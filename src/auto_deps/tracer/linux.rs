use crate::auto_deps::TraceOptions;
use crate::auto_deps::event::{PathEvent, PathEventKind, TraceReport, TraceStatsSnapshot};
use crate::auto_deps::tracer::mem_read::read_cstr;
#[cfg(target_arch = "x86_64")]
use crate::auto_deps::tracer::seccomp;
use crate::auto_deps::tracer::state::{FdEntry, PendingSyscall, Stage, TraceeState};
use crate::auto_deps::tracer::syscalls::{
    Effect, classify, effect_needs_exit, effect_to_event_kind, open_flags_is_cloexec,
    open_flags_is_directory, open_flags_is_write,
};

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::sync::Mutex;
use syscalls::Sysno;

const BASE_TRACE_OPTIONS: i32 = libc::PTRACE_O_TRACESYSGOOD
    | libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXEC;

/// Install `PTRACE_TRACEME` in `cmd`'s pre-exec hook. After the child is
/// spawned, the kernel will deliver a `SIGTRAP` on its first successful
/// `execve`. The caller observes that `SIGTRAP` via `waitpid` before handing
/// off to [`Tracer::attach`].
///
/// Note: do NOT also `raise(SIGSTOP)` here. `std::process::Command`
/// synchronizes with the child via a `CLOEXEC` pipe — `spawn` blocks reading
/// the pipe until the child execs (closing it) or writes an error. Stopping
/// the child before exec hangs `spawn` forever.
pub fn install_ptrace_traceme(cmd: &mut Command) {
    unsafe {
        cmd.pre_exec(|| {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Build a seccomp-BPF filter from `syscalls` and install it from `cmd`'s
/// pre-exec hook. The filter is built **before** the closure runs (in the
/// parent) and moved into the closure, so the post-fork child only does
/// syscalls — never an allocation.
///
/// Pair with [`install_ptrace_traceme`]. With `PTRACE_O_TRACESECCOMP` set on
/// the tracer side, every listed syscall raises a `PTRACE_EVENT_SECCOMP`
/// stop instead of a normal syscall-entry stop, and the kernel never wakes
/// the tracer for any other syscall.
#[cfg(target_arch = "x86_64")]
pub fn install_seccomp_filter(cmd: &mut Command, syscalls: &[Sysno]) {
    let prog = seccomp::build_filter(syscalls);
    unsafe {
        cmd.pre_exec(move || seccomp::install(&prog));
    }
}

/// State machine that converts ptrace stop notifications into [`PathEvent`]s.
///
/// The tracer does not call `waitpid` itself — the caller (a test driver or
/// the daemon's event loop) is the single `waitpid` consumer for the
/// process. After each `waitpid` returns a status for a known tracee, the
/// caller invokes [`Tracer::on_status`]; the tracer issues the appropriate
/// ptrace operations (`PTRACE_GET_SYSCALL_INFO`, `PTRACE_SYSCALL`, etc.) to
/// continue the trace. Splitting it this way avoids a `waitpid(-1)` race
/// between the tracer and any other reaper sharing the same process.
#[derive(Debug, Default, Clone, Copy)]
pub struct TraceStats {
    pub status_total: u64,
    pub syscall_stops: u64,
    pub event_stops: u64,
    pub signal_stops: u64,
    pub exit_stops: u64,
    pub get_syscall_info_calls: u64,
    pub resume_calls: u64,
    pub read_cstr_calls: u64,
    pub fork_clones: u64,
}

#[derive(Clone, Copy)]
enum ResumeMode {
    /// Stop on the next syscall entry/exit. Used as the default outside
    /// seccomp mode, and to bridge a SECCOMP entry through to its EXIT for
    /// effects that need the syscall return value.
    Syscall,
    /// Run free until the next event-stop (PTRACE_EVENT_*). Default in
    /// seccomp mode.
    Cont,
}

pub struct Tracer {
    root_pid: i32,
    max_events: usize,
    use_seccomp: bool,
    tracees: HashMap<i32, TraceeState>,
    events: Vec<PathEvent>,
    seq: u64,
    truncated: bool,
    root_exit: Option<ExitStatus>,
    stats: TraceStats,
    syscall_histogram: Vec<u64>,
}

impl Tracer {
    pub fn stats(&self) -> TraceStats {
        self.stats
    }
}

impl Tracer {
    /// Begin tracing a child that has already trapped on its initial
    /// `execve` (i.e., `waitpid` returned with `WSTOPSIG == SIGTRAP`).
    ///
    /// Sets `PTRACE_O_TRACESYSGOOD | TRACEFORK | TRACEVFORK | TRACECLONE |
    /// TRACEEXEC` and resumes the tracee with `PTRACE_SYSCALL`.
    pub fn attach(root_pid: i32, opts: TraceOptions) -> anyhow::Result<Self> {
        let use_seccomp = cfg!(target_arch = "x86_64") && opts.use_seccomp;
        let trace_opts =
            BASE_TRACE_OPTIONS | if use_seccomp { libc::PTRACE_O_TRACESECCOMP } else { 0 };
        if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, root_pid, 0i64, trace_opts as i64) }
            == -1
        {
            anyhow::bail!("PTRACE_SETOPTIONS: {}", io::Error::last_os_error());
        }

        let mut tracees: HashMap<i32, TraceeState> = HashMap::new();
        let initial_cwd = std::fs::read_link(format!("/proc/{}/cwd", root_pid))?;
        tracees.insert(root_pid, TraceeState::new(initial_cwd));

        let initial_resume = if use_seccomp { ResumeMode::Cont } else { ResumeMode::Syscall };
        resume(root_pid, 0, initial_resume)?;

        Ok(Self {
            root_pid,
            max_events: opts.max_events,
            use_seccomp,
            tracees,
            events: Vec::new(),
            seq: 0,
            truncated: false,
            root_exit: None,
            stats: TraceStats::default(),
            syscall_histogram: vec![0u64; 1024],
        })
    }

    pub fn syscall_histogram(&self) -> &[u64] {
        &self.syscall_histogram
    }

    /// Process a wait status for `pid`. Idempotent for unknown pids.
    pub fn on_status(&mut self, pid: i32, status: i32) {
        self.stats.status_total += 1;
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.stats.exit_stops += 1;
            self.tracees.remove(&pid);
            if pid == self.root_pid {
                self.root_exit = Some(ExitStatus::from_raw(status));
            }
            return;
        }
        if !libc::WIFSTOPPED(status) {
            return;
        }
        let default_mode = if self.use_seccomp { ResumeMode::Cont } else { ResumeMode::Syscall };
        let sig = libc::WSTOPSIG(status);
        if sig == (libc::SIGTRAP | 0x80) {
            self.stats.syscall_stops += 1;
            self.handle_syscall_stop(pid);
            if self.truncated {
                let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0i64, 0i64) };
                return;
            }
            self.stats.resume_calls += 1;
            let _ = resume(pid, 0, default_mode);
        } else if sig == libc::SIGTRAP {
            self.stats.event_stops += 1;
            let event = (status >> 16) & 0xffff;
            if event as i32 == libc::PTRACE_EVENT_SECCOMP {
                let mode = self.handle_seccomp_stop(pid);
                self.stats.resume_calls += 1;
                let _ = resume(pid, 0, mode);
                return;
            }
            self.handle_ptrace_event(pid, event as i32);
            self.stats.resume_calls += 1;
            let _ = resume(pid, 0, default_mode);
        } else if sig == libc::SIGSTOP {
            self.stats.signal_stops += 1;
            // The kernel emits an initial SIGSTOP for every tracee created via
            // PTRACE_O_TRACEFORK/VFORK/CLONE. It looks like a real signal but
            // it is the post-clone group-stop notification — must be resumed
            // with sig=0. Re-injecting SIGSTOP is catastrophic: SIGSTOP cannot
            // be blocked, the tracee re-enters stopped state, the kernel
            // re-notifies us, and we busy-loop on that pid. This race fires
            // whenever the parent's PTRACE_EVENT_CLONE is processed before
            // the child's SIGSTOP (the common order under heavy threading).
            //
            // We don't need to preserve real-SIGSTOP semantics for a build
            // tracer, so swallow all SIGSTOPs unconditionally.
            if !self.tracees.contains_key(&pid) {
                let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid)).unwrap_or_default();
                self.tracees.insert(pid, TraceeState::new(cwd));
            }
            self.stats.resume_calls += 1;
            let _ = resume(pid, 0, default_mode);
        } else {
            self.stats.signal_stops += 1;
            self.stats.resume_calls += 1;
            let _ = resume(pid, sig, default_mode);
        }
    }

    /// True once the root tracee has exited and all descendants are reaped.
    pub fn is_done(&self) -> bool {
        self.root_exit.is_some() && self.tracees.is_empty()
    }

    /// Live tracee pids — useful for callers that need to know which pids
    /// belong to this trace (e.g. to route incoming `waitpid` statuses to
    /// the right `Tracer`).
    pub fn tracees(&self) -> impl Iterator<Item = i32> + '_ {
        self.tracees.keys().copied()
    }

    pub fn finish(self) -> TraceReport {
        let (report, _) = self.finish_with_histogram();
        report
    }

    pub fn finish_with_histogram(self) -> (TraceReport, Vec<u64>) {
        let report = TraceReport {
            events: self.events,
            root_pid: self.root_pid,
            exit_status: self.root_exit.unwrap_or_else(|| ExitStatus::from_raw(0)),
            truncated: self.truncated,
            stats: TraceStatsSnapshot {
                status_total: self.stats.status_total,
                syscall_stops: self.stats.syscall_stops,
                event_stops: self.stats.event_stops,
                signal_stops: self.stats.signal_stops,
                exit_stops: self.stats.exit_stops,
                get_syscall_info_calls: self.stats.get_syscall_info_calls,
                resume_calls: self.stats.resume_calls,
                read_cstr_calls: self.stats.read_cstr_calls,
                fork_clones: self.stats.fork_clones,
            },
        };
        (report, self.syscall_histogram)
    }

    fn handle_ptrace_event(&mut self, pid: i32, event: i32) {
        match event {
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                self.stats.fork_clones += 1;
                let mut child_pid: u64 = 0;
                let r = unsafe {
                    libc::ptrace(libc::PTRACE_GETEVENTMSG, pid, 0i64, &mut child_pid as *mut u64)
                };
                if r == -1 {
                    return;
                }
                let child_pid = child_pid as i32;
                // Always copy parent state, even when CLONE_FS / CLONE_FILES
                // would have aliased it in the kernel. Pthread-style siblings
                // sharing fs/files will diverge after the clone — accepted
                // for simplicity, since the common fork+exec case is fine.
                let snapshot = self.tracees.get(&pid).cloned();
                if let Some(mut s) = snapshot {
                    s.pending = None;
                    self.tracees.insert(child_pid, s);
                } else {
                    let cwd =
                        std::fs::read_link(format!("/proc/{}/cwd", child_pid)).unwrap_or_default();
                    self.tracees.insert(child_pid, TraceeState::new(cwd));
                }
            }
            libc::PTRACE_EVENT_EXEC => {
                if let Some(state) = self.tracees.get_mut(&pid) {
                    state.fds.retain(|_, e| !e.cloexec);
                    state.pending = None;
                }
                // `execve` is excluded from the seccomp filter (see
                // `TRACED_SYSCALLS`), so this event is the only place we
                // observe an exec in seccomp mode. Emit it here so both
                // modes produce the same trace shape. /proc/<pid>/exe
                // resolves to the *new* binary because the kernel raises
                // PTRACE_EVENT_EXEC after the address-space swap.
                if self.use_seccomp {
                    if let Ok(path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                        push_event(
                            &mut self.events,
                            &mut self.seq,
                            self.max_events,
                            &mut self.truncated,
                            PathEventKind::Exec,
                            path,
                            pid,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_syscall_stop(&mut self, pid: i32) {
        // In non-seccomp mode we use `state.stage` to skip the
        // PTRACE_GET_SYSCALL_INFO call on the EXIT side of any uninteresting
        // syscall (the vast majority). In seccomp mode the only syscall_stops
        // we ever see are EXITs of effects we explicitly bridged with
        // PTRACE_SYSCALL — Stage tracking is redundant but harmless.
        let stage = self.tracees.get(&pid).map(|s| s.stage).unwrap_or(Stage::AwaitingEntry);

        if matches!(stage, Stage::InsideSyscall) {
            let state = match self.tracees.get_mut(&pid) {
                Some(s) => s,
                None => return,
            };
            state.stage = Stage::AwaitingEntry;
            let Some(pending) = state.pending.take() else { return };

            self.stats.get_syscall_info_calls += 1;
            let info = match get_syscall_info(pid) {
                Ok(info) => info,
                Err(_) => return,
            };
            if info.op != libc::PTRACE_SYSCALL_INFO_EXIT {
                return;
            }
            let exit = unsafe { info.u.exit };
            if exit.is_error != 0 {
                return;
            }
            let rval = exit.sval;
            self.handle_syscall_exit(pid, pending, rval);
            return;
        }

        self.stats.get_syscall_info_calls += 1;
        let info = match get_syscall_info(pid) {
            Ok(info) => info,
            Err(_) => return,
        };
        if info.op != libc::PTRACE_SYSCALL_INFO_ENTRY {
            return;
        }
        let nr = unsafe { info.u.entry.nr } as usize;
        let args = unsafe { info.u.entry.args };
        self.record_entry(pid, nr, args);
        if let Some(state) = self.tracees.get_mut(&pid) {
            state.stage = Stage::InsideSyscall;
        }
    }

    /// Handle a `PTRACE_EVENT_SECCOMP` stop — the seccomp filter promoted a
    /// classified syscall to a tracer-visible event. Mirrors the ENTRY half
    /// of `handle_syscall_stop` (fetches args via `PTRACE_GET_SYSCALL_INFO`
    /// with `op == SECCOMP`, runs `record_entry`) but then chooses how to
    /// resume per-effect: `PTRACE_SYSCALL` for effects that need the syscall
    /// return value (so the existing EXIT path runs unchanged), `PTRACE_CONT`
    /// for everything else (and the entry-side event is emitted now).
    fn handle_seccomp_stop(&mut self, pid: i32) -> ResumeMode {
        self.stats.get_syscall_info_calls += 1;
        let info = match get_syscall_info(pid) {
            Ok(info) => info,
            Err(_) => return ResumeMode::Cont,
        };
        if info.op != libc::PTRACE_SYSCALL_INFO_SECCOMP {
            return ResumeMode::Cont;
        }
        let nr = unsafe { info.u.seccomp.nr } as usize;
        let args = unsafe { info.u.seccomp.args };
        self.record_entry(pid, nr, args);

        let pending = match self.tracees.get_mut(&pid) {
            Some(s) => s.pending.clone(),
            None => return ResumeMode::Cont,
        };
        let Some(pending) = pending else { return ResumeMode::Cont };

        if effect_needs_exit(pending.effect) {
            if let Some(state) = self.tracees.get_mut(&pid) {
                state.stage = Stage::InsideSyscall;
            }
            ResumeMode::Syscall
        } else {
            if let Some(state) = self.tracees.get_mut(&pid) {
                state.pending = None;
            }
            self.process_entry_only_effect(pid, pending);
            ResumeMode::Cont
        }
    }

    fn record_entry(&mut self, pid: i32, nr: usize, args: [u64; 6]) {
        if let Some(slot) = self.syscall_histogram.get_mut(nr) {
            *slot += 1;
        }
        let state = self
            .tracees
            .entry(pid)
            .or_insert_with(|| TraceeState::new(PathBuf::new()));
        let read_cstr_calls = &mut self.stats.read_cstr_calls;
        state.pending = Sysno::new(nr).and_then(|sysno| {
            let shape = classify(sysno)?;
            let resolved_path = shape.path.and_then(|parg| {
                let path_addr = args[parg.path as usize];
                *read_cstr_calls += 1;
                let bytes = read_cstr(pid, path_addr).ok()?;
                let raw = PathBuf::from(OsString::from_vec(bytes));
                Some(resolve_path(state, &args, parg.dirfd, raw))
            });
            Some(PendingSyscall { effect: shape.effect, args, resolved_path })
        });
    }

    /// Emit events / update state for effects where we don't need the
    /// syscall return value: `Stat`, `ReadLink`, `Exec`, `Unlink`, `Mkdir`,
    /// `Chdir`, `Fchdir`. The `Open`/`ListDir`/`Rename`/`Read` arms are
    /// unreachable here — those effects are dispatched through
    /// `handle_syscall_exit` after a `PTRACE_SYSCALL` resume.
    fn process_entry_only_effect(&mut self, pid: i32, pending: PendingSyscall) {
        let state = match self.tracees.get_mut(&pid) {
            Some(s) => s,
            None => return,
        };
        let PendingSyscall { effect, args, resolved_path } = pending;
        match effect {
            Effect::Stat | Effect::ReadLink | Effect::Exec | Effect::Unlink | Effect::Mkdir => {
                let Some(path) = resolved_path else { return };
                let Some(kind) = effect_to_event_kind(effect, false) else { return };
                push_event(
                    &mut self.events,
                    &mut self.seq,
                    self.max_events,
                    &mut self.truncated,
                    kind,
                    path,
                    pid,
                );
            }
            Effect::Chdir => {
                if let Some(path) = resolved_path {
                    state.cwd = path;
                }
            }
            Effect::Fchdir { fd_arg } => {
                let fd = args[fd_arg as usize] as i32;
                if let Some(entry) = state.fds.get(&fd) {
                    state.cwd = entry.path.clone();
                }
            }
            Effect::Open { .. }
            | Effect::ListDir { .. }
            | Effect::Rename { .. }
            | Effect::Read => {}
        }
    }

    fn handle_syscall_exit(&mut self, pid: i32, pending: PendingSyscall, rval: i64) {
        let state = match self.tracees.get_mut(&pid) {
            Some(s) => s,
            None => return,
        };
        let PendingSyscall { effect, args, resolved_path } = pending;

        match effect {
            Effect::Open { flags_arg } => {
                let Some(path) = resolved_path else { return };
                let flags = args[flags_arg as usize];
                let opened_write = open_flags_is_write(flags);
                let opened_dir = open_flags_is_directory(flags);
                let cloexec = open_flags_is_cloexec(flags);
                let fd = rval as i32;
                if fd >= 0 {
                    state.fds.insert(
                        fd,
                        FdEntry { path: path.clone(), opened_write, cloexec },
                    );
                }
                // O_DIRECTORY opens are the prelude to `getdents64`. Don't
                // emit a Read event - the listing surfaces the dependency,
                // and recording a Read here pulls the directory itself
                // into `input_paths` and lets it collapse over its own
                // children.
                if opened_dir {
                    return;
                }
                let kind = if opened_write { PathEventKind::Write } else { PathEventKind::Read };
                push_event(&mut self.events, &mut self.seq, self.max_events, &mut self.truncated, kind, path, pid);
            }
            Effect::Stat | Effect::ReadLink | Effect::Exec | Effect::Unlink | Effect::Mkdir => {
                let Some(path) = resolved_path else { return };
                let Some(kind) = effect_to_event_kind(effect, false) else { return };
                push_event(&mut self.events, &mut self.seq, self.max_events, &mut self.truncated, kind, path, pid);
            }
            Effect::ListDir { fd_arg } => {
                let fd = args[fd_arg as usize] as i32;
                if let Some(entry) = state.fds.get(&fd) {
                    let path = entry.path.clone();
                    push_event(&mut self.events, &mut self.seq, self.max_events, &mut self.truncated, PathEventKind::ListDir, path, pid);
                }
            }
            Effect::Chdir => {
                if let Some(path) = resolved_path {
                    state.cwd = path;
                }
            }
            Effect::Fchdir { fd_arg } => {
                let fd = args[fd_arg as usize] as i32;
                if let Some(entry) = state.fds.get(&fd) {
                    state.cwd = entry.path.clone();
                }
            }
            Effect::Rename { dst_dirfd, dst_path } => {
                let src = resolved_path;
                let dst_addr = args[dst_path as usize];
                let dst = read_cstr(pid, dst_addr).ok().map(|bytes| {
                    let raw = PathBuf::from(OsString::from_vec(bytes));
                    resolve_path(state, &args, dst_dirfd, raw)
                });
                if let Some(p) = src {
                    push_event(&mut self.events, &mut self.seq, self.max_events, &mut self.truncated, PathEventKind::Unlink, p, pid);
                }
                if let Some(p) = dst {
                    push_event(&mut self.events, &mut self.seq, self.max_events, &mut self.truncated, PathEventKind::Write, p, pid);
                }
            }
            Effect::Read => {}
        }
    }
}

fn resume(pid: i32, signo: i32, mode: ResumeMode) -> anyhow::Result<()> {
    let (op, name) = match mode {
        ResumeMode::Syscall => (libc::PTRACE_SYSCALL, "PTRACE_SYSCALL"),
        ResumeMode::Cont => (libc::PTRACE_CONT, "PTRACE_CONT"),
    };
    let r = unsafe { libc::ptrace(op, pid, 0i64, signo as i64) };
    if r == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        anyhow::bail!("{} pid={} sig={}: {}", name, pid, signo, err);
    }
    Ok(())
}

fn get_syscall_info(pid: i32) -> anyhow::Result<libc::ptrace_syscall_info> {
    let mut info = MaybeUninit::<libc::ptrace_syscall_info>::zeroed();
    let size = std::mem::size_of::<libc::ptrace_syscall_info>() as libc::c_long;
    let r = unsafe { libc::ptrace(libc::PTRACE_GET_SYSCALL_INFO, pid, size, info.as_mut_ptr()) };
    if r == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) {
            anyhow::bail!("PTRACE_GET_SYSCALL_INFO unsupported (Linux 5.3 or newer required)");
        }
        anyhow::bail!("PTRACE_GET_SYSCALL_INFO: {}", err);
    }
    Ok(unsafe { info.assume_init() })
}

fn push_event(
    events: &mut Vec<PathEvent>,
    seq: &mut u64,
    max_events: usize,
    truncated: &mut bool,
    kind: PathEventKind,
    path: PathBuf,
    pid: i32,
) {
    if events.len() >= max_events {
        *truncated = true;
        return;
    }
    let s = *seq;
    *seq += 1;
    events.push(PathEvent { kind, path, pid, seq: s });
}

fn resolve_path(state: &TraceeState, args: &[u64; 6], dirfd_idx: Option<u8>, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    match dirfd_idx {
        None => state.cwd.join(path),
        Some(idx) => {
            let dirfd = args[idx as usize] as i32;
            if dirfd == libc::AT_FDCWD {
                state.cwd.join(path)
            } else if let Some(entry) = state.fds.get(&dirfd) {
                entry.path.join(path)
            } else {
                state.cwd.join(path)
            }
        }
    }
}

/// Driving `Tracer` from a private `waitpid(-1)` loop. Safe only when the
/// caller's process has no other `waitpid` consumer (tests, CLI). The
/// daemon must drive `Tracer` via its own event loop.
static BLOCKING_TRACE_LOCK: Mutex<()> = Mutex::new(());

/// Spawn `cmd` and drive a [`Tracer`] to completion using `waitpid(-1)` in
/// the calling thread. Convenience for tests and CLI; **not** safe to call
/// from the daemon process (it would race the event loop's reaper).
pub fn trace_command(cmd: Command, opts: TraceOptions) -> anyhow::Result<TraceReport> {
    trace_command_with_histogram(cmd, opts).map(|(r, _)| r)
}

pub fn trace_command_with_histogram(
    mut cmd: Command,
    opts: TraceOptions,
) -> anyhow::Result<(TraceReport, Vec<u64>)> {
    let _guard = BLOCKING_TRACE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    install_ptrace_traceme(&mut cmd);
    #[cfg(target_arch = "x86_64")]
    if opts.use_seccomp {
        install_seccomp_filter(&mut cmd, crate::auto_deps::tracer::syscalls::TRACED_SYSCALLS);
    }
    let child = cmd.spawn()?;
    let root_pid = child.id() as i32;
    // The wait loop below reaps the tracee; std's Child::wait would race.
    std::mem::forget(child);

    let mut status = 0i32;
    if unsafe { libc::waitpid(root_pid, &mut status, 0) } == -1 {
        anyhow::bail!("initial waitpid: {}", io::Error::last_os_error());
    }
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP {
        anyhow::bail!("expected initial SIGTRAP from execve auto-stop, got status {:#x}", status);
    }

    let mut tracer = Tracer::attach(root_pid, opts)?;

    while !tracer.is_done() {
        let mut status = 0i32;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid == -1 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => break,
                _ => anyhow::bail!("waitpid: {}", err),
            }
        }
        tracer.on_status(pid, status);
    }

    Ok(tracer.finish_with_histogram())
}
