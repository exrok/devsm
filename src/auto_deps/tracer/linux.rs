use crate::auto_deps::TraceOptions;
use crate::auto_deps::event::{PathEvent, PathEventKind, TraceReport, TraceStatsSnapshot};
use crate::auto_deps::tracer::mem_read::read_cstr;
use crate::auto_deps::tracer::state::{FdEntry, PendingSyscall, Stage, TraceeState};
use crate::auto_deps::tracer::syscalls::{
    Effect, classify, effect_to_event_kind, open_flags_is_cloexec, open_flags_is_write,
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

const TRACE_OPTIONS: i32 = libc::PTRACE_O_TRACESYSGOOD
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

pub struct Tracer {
    root_pid: i32,
    max_events: usize,
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
        if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, root_pid, 0i64, TRACE_OPTIONS as i64) }
            == -1
        {
            anyhow::bail!("PTRACE_SETOPTIONS: {}", io::Error::last_os_error());
        }

        let mut tracees: HashMap<i32, TraceeState> = HashMap::new();
        let initial_cwd = std::fs::read_link(format!("/proc/{}/cwd", root_pid))?;
        tracees.insert(root_pid, TraceeState::new(initial_cwd));

        resume_syscall(root_pid, 0)?;

        Ok(Self {
            root_pid,
            max_events: opts.max_events,
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
        let sig = libc::WSTOPSIG(status);
        if sig == (libc::SIGTRAP | 0x80) {
            self.stats.syscall_stops += 1;
            self.handle_syscall_stop(pid);
            if self.truncated {
                let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0i64, 0i64) };
                return;
            }
            self.stats.resume_calls += 1;
            let _ = resume_syscall(pid, 0);
        } else if sig == libc::SIGTRAP {
            self.stats.event_stops += 1;
            let event = (status >> 16) & 0xffff;
            self.handle_ptrace_event(pid, event as i32);
            self.stats.resume_calls += 1;
            let _ = resume_syscall(pid, 0);
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
            let _ = resume_syscall(pid, 0);
        } else {
            self.stats.signal_stops += 1;
            self.stats.resume_calls += 1;
            let _ = resume_syscall(pid, sig);
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
            }
            _ => {}
        }
    }

    fn handle_syscall_stop(&mut self, pid: i32) {
        // We track ENTRY vs EXIT in `state.stage` so that we can skip the
        // PTRACE_GET_SYSCALL_INFO syscall on the EXIT side of any uninteresting
        // syscall (i.e. when nothing was pending). Without seccomp filtering we
        // see two stops per tracee syscall, and the vast majority are syscalls
        // we don't classify — paying for an extra ptrace call on each of those
        // EXITs is the dominant per-stop cost.
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
        if let Some(slot) = self.syscall_histogram.get_mut(nr) {
            *slot += 1;
        }
        let state = self
            .tracees
            .entry(pid)
            .or_insert_with(|| TraceeState::new(PathBuf::new()));
        state.stage = Stage::InsideSyscall;
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
                let cloexec = open_flags_is_cloexec(flags);
                let fd = rval as i32;
                if fd >= 0 {
                    state.fds.insert(
                        fd,
                        FdEntry { path: path.clone(), opened_write, cloexec },
                    );
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

fn resume_syscall(pid: i32, signo: i32) -> anyhow::Result<()> {
    let r = unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0i64, signo as i64) };
    if r == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        anyhow::bail!("PTRACE_SYSCALL pid={} sig={}: {}", pid, signo, err);
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
