use crate::rpc;
use crate::rpc::{CommandBody, DecodingState, RpcMessageKind};
use crate::workspace::{self, ExitCause, JobIndex, JobStatus, Workspace, WorkspaceState};
use crate::{
    config::{Command, TaskConfigRc, TaskKind},
    line_width::{Segment, apply_raw_display_mode_vt_to_style},
    log_storage::{LogGroup, LogWriter},
};
use anyhow::{Context, bail};
use extui::Style;
use hashbrown::HashMap;
use jsony_value::ValueMap;
use mio::{Events, Interest, Poll, Token, Waker, unix::SourceFd};
use slab::Slab;
use std::io::Write;
use std::panic::UnwindSafe;
use std::{
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Stdio},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64},
    },
};
use unicode_width::UnicodeWidthStr;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Pipe {
    Stdout,
    Stderr,
}

mod rpc_handlers;

type WorkspaceIndex = u32;
/// Tracks ready condition checking for a service process.
pub(crate) struct ReadyChecker {
    /// String to search for in output (ANSI stripped).
    pub(crate) needle: String,
    /// When to timeout if ready condition not met.
    pub(crate) timeout_at: Option<std::time::Instant>,
}

/// Tracks timeout conditions for a process.
pub(crate) struct TimeoutTracker {
    /// String to search for in output that starts the conditional timeout (ANSI stripped).
    pub(crate) conditional_needle: Option<String>,
    /// Absolute timeout at this instant (max timeout).
    pub(crate) max_timeout_at: Option<std::time::Instant>,
    /// Timeout at this instant after conditional predicate matched.
    pub(crate) conditional_timeout_at: Option<std::time::Instant>,
    /// Duration for conditional timeout (stored to compute timeout_at when predicate matches).
    pub(crate) conditional_duration_secs: Option<f64>,
    /// Idle timeout duration in seconds.
    pub(crate) idle_duration_secs: Option<f64>,
    /// Last time output was received (for idle timeout).
    pub(crate) last_output_at: std::time::Instant,
}

pub(crate) struct ActiveProcess {
    pub(crate) log_group: LogGroup,
    pub(crate) job_index: JobIndex,
    pub(crate) workspace_index: WorkspaceIndex,
    pub(crate) alive: bool,
    pub(crate) stdout_buffer: Option<Buffer>,
    pub(crate) stderr_buffer: Option<Buffer>,
    pub(crate) style: Style,
    pub(crate) child: Child,
    pub(crate) pending_exit_cause: Option<ExitCause>,
    /// Ready condition checker. None if no ready condition or already ready.
    pub(crate) ready_checker: Option<ReadyChecker>,
    /// Timeout tracker. None if no timeout configured.
    pub(crate) timeout_tracker: Option<TimeoutTracker>,
    /// When SIGINT was sent (for SIGKILL escalation after timeout).
    pub(crate) kill_sent_at: Option<std::time::Instant>,
}

impl ActiveProcess {
    fn append_line(&mut self, text: &[u8], writer: &mut LogWriter) {
        if let Ok(text) = std::str::from_utf8(text) {
            let mut new_style = self.style;
            let mut width = 0;
            for segment in Segment::iterator(text) {
                match segment {
                    Segment::Ascii(text) => width += text.len(),
                    Segment::AnsiEscapes(escape) => apply_raw_display_mode_vt_to_style(&mut new_style, escape),
                    Segment::Utf8(text) => width += text.width(),
                }
            }

            writer.push_line(text, width as u32, self.log_group, self.style);
            self.style = new_style;
        }
    }
}

pub(crate) struct Buffer {
    pub(crate) data: Vec<u8>,
    pub(crate) read: usize,
}

pub(crate) type ProcessIndex = usize;

impl Buffer {
    pub(crate) fn is_empty(&self) -> bool {
        self.read >= self.data.len()
    }
    pub(crate) fn reset(&mut self) {
        self.data.clear();
        self.read = 0;
    }
    fn remaining_slice(&self) -> &[u8] {
        &self.data[self.read..]
    }
    pub(crate) fn readline(&mut self) -> Option<&[u8]> {
        if let Some(pos) = self.data[self.read..].iter().position(|&b| b == b'\n') {
            let line = &self.data[self.read..self.read + pos];
            self.read += pos + 1;
            Some(line)
        } else {
            None
        }
    }
}

#[derive(Default)]
struct RpcSubscriptions {
    job_status: bool,
    job_exits: bool,
}

enum ClientKind {
    Tui,
    Run { log_group: LogGroup },
    TestRun,
    Rpc { subscriptions: RpcSubscriptions },
    SelfLogs,
    Logs,
}

struct ClientEntry {
    workspace: WorkspaceIndex,
    channel: Arc<ClientChannel>,
    socket: UnixStream,
    kind: ClientKind,
    partial_rpc_read: Option<(DecodingState, Vec<u8>)>,
}

pub struct WorkspaceEntry {
    line_writer: LogWriter,
    handle: Arc<Workspace>,
}

struct State {
    poll: Poll,
    processes: slab::Slab<ActiveProcess>,

    workspaces: slab::Slab<WorkspaceEntry>,
    workspace_map: HashMap<Box<Path>, WorkspaceIndex>,

    request: Arc<MioChannel>,
    timed_ready_count: u32,
    timed_timeout_count: u32,
}

pub(crate) struct EventLoop {
    buffer_pool: Vec<Vec<u8>>,

    clients: Slab<ClientEntry>,

    state: State,
    // poll: Poll,
    // processes: slab::Slab<ActiveProcess>,

    // workspaces: slab::Slab<WorkspaceEntry>,
    // workspace_map: HashMap<Box<Path>, WorkspaceIndex>,

    // request: Arc<MioChannel>,
    // timed_ready_count: u32,
    // timed_timeout_count: u32,
    wait_thread: std::thread::JoinHandle<()>,
}

pub(crate) enum ReadResult {
    Done,
    More,
    EOF,
    WouldBlock,
    OtherError(std::io::ErrorKind),
}

#[derive(Clone, Copy, Debug)]
enum SocketTerminationReason {
    Eof,
    ReadError,
    ProtocolError,
    ClientRequestedTerminate,
}

impl SocketTerminationReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eof => "socket_eof",
            Self::ReadError => "socket_read_error",
            Self::ProtocolError => "protocol_error",
            Self::ClientRequestedTerminate => "client_requested_terminate",
        }
    }
}

pub(crate) fn try_read(fd: RawFd, buffer: &mut Vec<u8>) -> ReadResult {
    let mut target = buffer.spare_capacity_mut();
    if target.len() < 1024 {
        buffer.reserve(1024);
        target = buffer.spare_capacity_mut();
    }
    let read_len = target.len();
    loop {
        let result = unsafe { libc::read(fd, target.as_mut_ptr() as *mut libc::c_void, read_len) };
        if result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return ReadResult::WouldBlock;
            }
            return ReadResult::OtherError(err.kind());
        } else if result == 0 {
            return ReadResult::EOF;
        } else {
            unsafe {
                buffer.set_len(buffer.len() + result as usize);
            }
            if result as usize == read_len {
                return ReadResult::More;
            } else {
                return ReadResult::Done;
            }
        }
    }
}

impl EventLoop {
    pub(crate) fn read(&mut self, index: ProcessIndex, pipe: Pipe) -> anyhow::Result<()> {
        kvlog::debug!("Read process", index, pipe= ?pipe);
        let process = self.state.processes.get_mut(index).context("Invalid process index")?;
        let (fd, mut buffer) = match pipe {
            Pipe::Stdout => (
                process.child.stdout.as_ref().map(|s| s.as_raw_fd()).context("No stdout")?,
                process
                    .stdout_buffer
                    .take()
                    .unwrap_or_else(|| Buffer { data: self.buffer_pool.pop().unwrap_or_default(), read: 0 }),
            ),
            Pipe::Stderr => (
                process.child.stderr.as_ref().map(|s| s.as_raw_fd()).context("No stderr")?,
                process
                    .stderr_buffer
                    .take()
                    .unwrap_or_else(|| Buffer { data: self.buffer_pool.pop().unwrap_or_default(), read: 0 }),
            ),
        };
        let mut expecting_more = true;
        loop {
            match try_read(fd, &mut buffer.data) {
                ReadResult::Done | ReadResult::WouldBlock => break,
                ReadResult::More => continue,
                ReadResult::EOF => {
                    if let Err(err) = self.state.poll.registry().deregister(&mut SourceFd(&fd)) {
                        kvlog::error!("Failed to unregister fd", ?err, ?pipe, job_index = process.job_index);
                    }
                    match pipe {
                        Pipe::Stdout => {
                            process.child.stdout = None;
                            process.stdout_buffer = None;
                        }
                        Pipe::Stderr => {
                            process.child.stderr = None;
                            process.stderr_buffer = None;
                        }
                    }
                    kvlog::debug!("Process pipe EOF found, closing", ?pipe, job_index = process.job_index);
                    expecting_more = false;
                    break;
                }
                ReadResult::OtherError(err) => {
                    kvlog::warn!("Read failed with unexpected error", ?err, ?pipe, job_index = process.job_index);
                    break;
                }
            }
        }

        let mut ready_matched = false;
        while let Some(line) = buffer.readline() {
            if let Ok(text) = std::str::from_utf8(line) {
                let mut new_style = process.style;
                let mut width = 0;
                for segment in Segment::iterator(text) {
                    match segment {
                        Segment::Ascii(text) => width += text.len(),
                        Segment::AnsiEscapes(escape) => apply_raw_display_mode_vt_to_style(&mut new_style, escape),
                        Segment::Utf8(text) => width += text.width(),
                    }
                }

                if let Some(workspace) = self.state.workspaces.get_mut(process.workspace_index as usize) {
                    workspace.line_writer.push_line(text, width as u32, process.log_group, process.style);
                }

                if let Some(ref checker) = process.ready_checker {
                    if crate::line_width::strip_ansi_and_contains(text, &checker.needle) {
                        if checker.timeout_at.is_some() {
                            self.state.timed_ready_count -= 1;
                        }
                        ready_matched = true;
                        process.ready_checker = None;
                    }
                }

                if let Some(ref mut tracker) = process.timeout_tracker {
                    let now = std::time::Instant::now();
                    tracker.last_output_at = now;

                    if tracker.conditional_timeout_at.is_none()
                        && let Some(ref needle) = tracker.conditional_needle
                        && crate::line_width::strip_ansi_and_contains(text, needle)
                    {
                        if let Some(secs) = tracker.conditional_duration_secs {
                            tracker.conditional_timeout_at = Some(now + std::time::Duration::from_secs_f64(secs));
                        }
                        tracker.conditional_needle = None;
                    }
                }
                process.style = new_style;
            }
        }
        let ws_index = process.workspace_index;
        let job_index = process.job_index;
        if buffer.is_empty() || !expecting_more {
            buffer.reset();
            self.buffer_pool.push(buffer.data)
        } else {
            match pipe {
                Pipe::Stdout => process.stdout_buffer = Some(buffer),
                Pipe::Stderr => process.stderr_buffer = Some(buffer),
            }
        }

        if ready_matched {
            self.mark_service_ready(ws_index, job_index);
        }

        Ok(())
    }
    pub(crate) fn scheduled(&mut self) {
        const MAX_ITERATIONS: u32 = 10_000;
        let mut iteration_count = 0u32;
        'outer: loop {
            iteration_count += 1;
            if iteration_count > MAX_ITERATIONS {
                kvlog::error!(
                    "Scheduler exceeded maximum iterations",
                    iterations = MAX_ITERATIONS,
                    workspaces = self.state.workspaces.len()
                );
                break;
            }
            for (wsi, ws) in &self.state.workspaces {
                let state = ws.handle.state();

                if let Some(service_to_kill) = state.service_to_terminate_for_queue() {
                    let job = &state.jobs[service_to_kill.idx()];
                    let job_id = job.log_group;
                    let JobStatus::Running { process_index, .. } = job.process_status else {
                        drop(state);
                        continue;
                    };
                    drop(state);

                    if let Some(process) = self.state.processes.get_mut(process_index) {
                        if process.log_group == job_id && process.alive {
                            let child_pid = process.child.id();
                            let pgid_to_kill = -(child_pid as i32);
                            kvlog::info!(
                                "Sending SIGINT to process group",
                                job_index = service_to_kill,
                                base_task_index = job_id.base_task_index().0,
                                reason = ExitCause::ProfileConflict.name(),
                                pid = child_pid,
                                pgid = pgid_to_kill
                            );
                            process.pending_exit_cause = Some(ExitCause::ProfileConflict);
                            unsafe {
                                libc::kill(pgid_to_kill, libc::SIGINT);
                            }
                            process.alive = false;
                            process.kill_sent_at = Some(std::time::Instant::now());
                        }
                    }
                    break;
                }

                match state.next_scheduled() {
                    workspace::Scheduled::Ready(job_index) => {
                        let job = &state.jobs[job_index.idx()];
                        let job_correlation = job.log_group;
                        let job_task = job.task.clone();
                        drop(state);
                        let _ = self.spawn(wsi as WorkspaceIndex, job_correlation, job_index, job_task);
                        continue 'outer;
                    }
                    workspace::Scheduled::Never(job_index) => {
                        kvlog::info!("Scheduled task will never be ready cancelling", job_index);
                        drop(state);
                        let mut ws_state = ws.handle.state.write().unwrap();
                        ws_state.update_job_status(job_index, JobStatus::Cancelled);
                        continue 'outer;
                    }
                    workspace::Scheduled::None => (),
                }
            }
            break;
        }
    }

    fn mark_service_ready(&mut self, ws_index: WorkspaceIndex, job_index: JobIndex) {
        if let Some(ws) = self.state.workspaces.get(ws_index as usize) {
            let mut state = ws.handle.state.write().unwrap();
            if let JobStatus::Running { ready_state, .. } = &mut state[job_index].process_status {
                *ready_state = Some(true);
            }
            state.change_number = state.change_number.wrapping_add(1);
            drop(state);
        }
        self.scheduled();
    }

    fn check_ready_timeouts(&mut self) {
        let now = std::time::Instant::now();
        for (_, process) in &mut self.state.processes {
            if let Some(ref checker) = process.ready_checker {
                if checker.timeout_at.is_some_and(|t| now > t) {
                    self.state.timed_ready_count -= 1;
                    process.ready_checker = None;
                }
            }
        }
    }

    fn check_timeouts(&mut self) {
        let now = std::time::Instant::now();
        let mut to_kill: Vec<(usize, u32)> = Vec::new();

        for (index, process) in &self.state.processes {
            if !process.alive {
                continue;
            }
            let Some(ref tracker) = process.timeout_tracker else {
                continue;
            };

            let should_kill = tracker.max_timeout_at.is_some_and(|t| now > t)
                || tracker.conditional_timeout_at.is_some_and(|t| now > t)
                || tracker
                    .idle_duration_secs
                    .is_some_and(|secs| now.duration_since(tracker.last_output_at).as_secs_f64() > secs);

            if should_kill {
                to_kill.push((index, process.child.id()));
            }
        }

        for (index, child_pid) in to_kill {
            let Some(process) = self.state.processes.get_mut(index) else {
                continue;
            };
            if !process.alive {
                continue;
            }

            let pgid_to_kill = -(child_pid as i32);
            kvlog::info!(
                "Sending SIGINT to process group (timeout)",
                job_index = process.job_index,
                base_task_index = process.log_group.base_task_index().0,
                reason = ExitCause::Timeout.name(),
                pid = child_pid,
                pgid = pgid_to_kill
            );

            process.pending_exit_cause = Some(ExitCause::Timeout);
            unsafe {
                libc::kill(pgid_to_kill, libc::SIGINT);
            }
            process.alive = false;
            process.kill_sent_at = Some(now);
        }
    }

    fn check_kill_escalation(&mut self) {
        const SIGKILL_ESCALATION_SECS: u64 = 20;
        let now = std::time::Instant::now();

        for (_index, process) in &mut self.state.processes {
            let Some(kill_sent_at) = process.kill_sent_at else {
                continue;
            };

            if now.duration_since(kill_sent_at).as_secs() < SIGKILL_ESCALATION_SECS {
                continue;
            }

            let child_pid = process.child.id();
            let pgid_to_kill = -(child_pid as i32);

            kvlog::warn!(
                "Process did not terminate after SIGINT, escalating to SIGKILL",
                job_index = process.job_index,
                base_task_index = process.log_group.base_task_index().0,
                pid = child_pid,
                pgid = pgid_to_kill,
                elapsed_secs = now.duration_since(kill_sent_at).as_secs()
            );

            unsafe {
                if libc::kill(pgid_to_kill, libc::SIGKILL) == -1 {
                    let err = std::io::Error::last_os_error();
                    kvlog::error!("Failed to send SIGKILL", ?err, pid = child_pid, pgid = pgid_to_kill);
                }
            }

            process.kill_sent_at = None;
        }
    }

    pub(crate) fn spawn(
        &mut self,
        workspace_index: WorkspaceIndex,
        job_id: LogGroup,
        job_index: JobIndex,
        task: TaskConfigRc,
    ) -> anyhow::Result<()> {
        let index = self.state.processes.vacant_key();
        let tc = task.config();
        let workspace = &self.state.workspaces[workspace_index as usize];
        let path = {
            let ws = &mut *workspace.handle.state.write().unwrap();
            ws.change_number = ws.change_number.wrapping_add(1);
            match &ws[job_index].process_status {
                JobStatus::Scheduled { .. } => {
                    ws.update_job_status(job_index, JobStatus::Starting);
                }
                JobStatus::Starting => (),
                JobStatus::Running { .. } => bail!("Attempt start already running job"),
                JobStatus::Exited { .. } => bail!("Attempt start already exited job"),
                JobStatus::Cancelled => return Ok(()),
            }
            ws.config.current.base_path.join(tc.pwd)
        };

        let (mut command, sh_script) = match &tc.command {
            Command::Sh(script) => (std::process::Command::new("/bin/sh"), Some(*script)),
            Command::Cmd(cmd_args) => {
                if cmd_args.is_empty() {
                    bail!("Command must not be empty");
                }
                let [cmd, args @ ..] = *cmd_args else { panic!("Expected atleast one command") };
                let mut cmd = std::process::Command::new(cmd);
                cmd.args(args);
                (cmd, None)
            }
        };

        command.env("CARGO_TERM_COLOR", "always").current_dir(path).envs(tc.envvar.iter().copied());
        command.process_group(0);
        // PR_SET_PDEATHSIG is a nice fallback for auto termination, however pre_exec
        // causes spawn to use a custom spawn that has a bug that introduces a panic:
        // https://github.com/rust-lang/rust/issues/110317
        //
        // unsafe {
        //     command.pre_exec(|| {
        //         // Create process group to allow nested cleanup
        //         if libc::setpgid(0, 0) != 0 {
        //             return Err(std::io::Error::last_os_error());
        //         }
        //         #[cfg(target_os = "linux")]
        //         if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
        //             return Err(std::io::Error::last_os_error());
        //         }
        //         Ok(())
        //     });
        // }

        let stdin = if sh_script.is_some() { Stdio::piped() } else { Stdio::null() };
        command.stdin(stdin);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn().context("Failed to spawn process")?;

        if let (Some(mut stdin), Some(script)) = (child.stdin.take(), sh_script) {
            use std::io::Write;
            let _ = stdin.write_all(script.as_bytes());
            let _ = stdin.flush();
            drop(stdin);
        }
        self.wait_thread.thread().unpark();
        if let Some(stdout) = &mut child.stdout {
            unsafe {
                if libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == -1 {
                    panic!("Failed to set non-blocking");
                }
            }
            self.state.poll.registry().register(
                &mut SourceFd(&stdout.as_raw_fd()),
                Token(index << 1),
                Interest::READABLE,
            )?;
        };
        if let Some(stderr) = &mut child.stderr {
            unsafe {
                if libc::fcntl(stderr.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == -1 {
                    panic!("Failed to set non-blocking");
                }
            }
            self.state.poll.registry().register(
                &mut SourceFd(&stderr.as_raw_fd()),
                Token((index << 1) | 1),
                Interest::READABLE,
            )?;
        };
        let ready_checker = tc.ready.as_ref().map(|rc| {
            use crate::config::ReadyPredicate;
            ReadyChecker {
                needle: match &rc.when {
                    ReadyPredicate::OutputContains(s) => s.to_string(),
                },
                timeout_at: rc.timeout.map(|secs| std::time::Instant::now() + std::time::Duration::from_secs_f64(secs)),
            }
        });
        if ready_checker.as_ref().is_some_and(|rc| rc.timeout_at.is_some()) {
            self.state.timed_ready_count += 1;
        }
        let ready_state = ready_checker.as_ref().map(|_| false);

        let now = std::time::Instant::now();
        let timeout_tracker = tc.timeout.as_ref().map(|tc| {
            use crate::config::TimeoutPredicate;
            TimeoutTracker {
                conditional_needle: tc.when.as_ref().map(|w| match w {
                    TimeoutPredicate::OutputContains(s) => s.to_string(),
                }),
                max_timeout_at: tc.max.map(|secs| now + std::time::Duration::from_secs_f64(secs)),
                conditional_timeout_at: None,
                conditional_duration_secs: tc.conditional,
                idle_duration_secs: tc.idle,
                last_output_at: now,
            }
        });
        if timeout_tracker.is_some() {
            self.state.timed_timeout_count += 1;
        }
        let process_index = self.state.processes.insert(ActiveProcess {
            workspace_index,
            job_index,
            log_group: job_id,
            alive: true,
            stdout_buffer: None,
            stderr_buffer: None,
            style: Style::default(),
            child,
            pending_exit_cause: None,
            ready_checker,
            timeout_tracker,
            kill_sent_at: None,
        });
        {
            let mut ws = workspace.handle.state.write().unwrap();
            ws.update_job_status(job_index, JobStatus::Running { process_index, ready_state });
        }
        self.broadcast_job_status(workspace_index, job_index, crate::rpc::JobStatusKind::Running);
        Ok(())
    }
}

pub(crate) enum AttachKind {
    Tui,
    Run { task_name: Box<str>, params: Vec<u8>, as_test: bool },
    TestRun { filters: Vec<u8> },
    Rpc { subscribe: bool },
    Logs { query: Vec<u8> },
}

pub(crate) enum ReceivedFds {
    None,
    Pair([File; 2]),
    Single(File),
}

pub(crate) enum ProcessRequest {
    RpcMessage {
        socket: UnixStream,
        fds: ReceivedFds,
        kind: crate::rpc::RpcMessageKind,
        correlation: u16,
        one_shot: bool,
        ws_data: Vec<u8>,
        payload: Vec<u8>,
    },
    Spawn {
        task: TaskConfigRc,
        workspace_id: WorkspaceIndex,
        job_id: LogGroup,
        job_index: JobIndex,
    },
    AttachClient {
        stdin: Option<File>,
        stdout: Option<File>,
        socket: UnixStream,
        workspace_config: PathBuf,
        kind: AttachKind,
    },
    TerminateJob {
        job_id: LogGroup,
        process_index: usize,
        exit_cause: ExitCause,
    },
    ClientExited {
        index: usize,
    },
    ProcessExited {
        pid: u32,
        status: u32,
    },
    AttachSelfLogsClient {
        stdout: File,
        socket: UnixStream,
    },
    GlobalTermination,
}

/// Flag bit indicating the selection is a meta-group rather than a base task.
pub const SELECTED_META_GROUP_FLAG: u64 = 1 << 63;
/// Meta-group selection for tests (`@tests`).
pub const SELECTED_META_GROUP_TESTS: u64 = SELECTED_META_GROUP_FLAG | 0;
/// Meta-group selection for actions (`@actions`).
pub const SELECTED_META_GROUP_ACTIONS: u64 = SELECTED_META_GROUP_FLAG | 1;

/// Channel for communicating with a client thread (TUI or forwarder).
///
/// For TUI clients, all fields are used. For forwarder clients, only `waker`
/// and `state` are used; `selected` and `events` are ignored.
pub struct ClientChannel {
    pub waker: extui::event::polling::Waker,
    /// Encodes termination flag (high bits > u32::MAX) and resize counter (low bits).
    pub state: AtomicU64,
    /// Tracks selected item. Only used by TUI clients.
    /// - Values without `SELECTED_META_GROUP_FLAG` set: base task index
    /// - `SELECTED_META_GROUP_TESTS`: the @tests meta-group is selected
    /// - `SELECTED_META_GROUP_ACTIONS`: the @actions meta-group is selected
    pub selected: AtomicU64,
    /// Event queue. Only used by TUI clients.
    pub events: Mutex<Vec<()>>,
}

pub enum Action {
    Resized,
    Terminated,
}

impl ClientChannel {
    /// Wakes the client thread to check for new events or logs.
    pub fn wake(&self) -> std::io::Result<()> {
        self.waker.wake()
    }

    /// Returns true if the client should terminate.
    pub fn is_terminated(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Relaxed) > u32::MAX as u64
    }

    /// Signals the client to terminate.
    pub fn set_terminated(&self) {
        self.state.store(1u64 << 32, std::sync::atomic::Ordering::Relaxed);
    }

    #[expect(unused, reason = "No events added yet")]
    pub fn swap_recv(&self, buf: &mut Vec<()>) {
        let mut events = self.events.lock().unwrap();
        buf.clear();
        std::mem::swap(buf, &mut events);
    }

    pub fn try_send(&self, req: ()) -> anyhow::Result<()> {
        let mut events = self.events.lock().unwrap();
        events.push(req);
        self.waker.wake()?;
        Ok(())
    }

    pub fn actions(&self, previous: &mut u64) -> Option<Action> {
        let state = self.state.load(std::sync::atomic::Ordering::Relaxed);
        if state > u32::MAX as u64 {
            return Some(Action::Terminated);
        }
        if *previous != state {
            *previous = state;
            return Some(Action::Resized);
        }
        None
    }

    #[expect(unused, reason = "No events added yet")]
    pub fn send(&self, req: ()) {
        if let Err(err) = self.try_send(req) {
            kvlog::error!("Failed to send request", ?err);
        }
    }
}

pub(crate) struct MioChannel {
    pub(crate) waker: &'static mio::Waker,
    pub(crate) events: Mutex<Vec<ProcessRequest>>,
}

impl MioChannel {
    pub(crate) fn swap_recv(&self, buf: &mut Vec<ProcessRequest>) {
        let mut events = self.events.lock().unwrap();
        buf.clear();
        std::mem::swap(buf, &mut events);
    }
    pub(crate) fn try_send(&self, req: ProcessRequest) -> anyhow::Result<()> {
        let mut events = self.events.lock().unwrap();
        events.push(req);
        self.waker.wake()?;
        Ok(())
    }
    pub(crate) fn send(&self, req: ProcessRequest) {
        if let Err(err) = self.try_send(req) {
            kvlog::error!("Failed to send request", ?err);
        }
    }
}

pub(crate) struct ProcessManagerHandle {
    pub(crate) request: Arc<MioChannel>,
}
impl State {
    fn get_or_create_workspace_index(&mut self, workspace_config: PathBuf) -> anyhow::Result<WorkspaceIndex> {
        if let Some(index) = self.workspace_map.get(workspace_config.as_path()) {
            return Ok(*index);
        }
        let state = WorkspaceState::new(workspace_config.clone())?;
        let line_writer = LogWriter::new();
        let handle = Arc::new(Workspace {
            workspace_id: self.workspaces.vacant_key() as u32,
            logs: line_writer.reader(),
            state: RwLock::new(state),
            process_channel: self.request.clone(),
        });
        let entry = WorkspaceEntry { line_writer, handle: handle.clone() };
        let index = self.workspaces.insert(entry) as WorkspaceIndex;
        self.workspace_map.insert(workspace_config.to_path_buf().into_boxed_path(), index);
        Ok(index)
    }
}
impl EventLoop {
    fn handle_request(&mut self, req: ProcessRequest) -> bool {
        match req {
            ProcessRequest::TerminateJob { job_id, process_index, exit_cause } => {
                let Some(process) = self.state.processes.get_mut(process_index) else {
                    kvlog::warn!(
                        "TerminateJob: process not found in slab",
                        ?process_index,
                        ?job_id,
                        reason = exit_cause.name()
                    );
                    return false;
                };
                if process.log_group != job_id {
                    kvlog::error!(
                        "TerminateJob: mismatched job id",
                        ?job_id,
                        expected = ?process.log_group,
                        ?process_index
                    );
                    return false;
                }
                process.pending_exit_cause = Some(exit_cause);
                let child_pid = process.child.id();
                let pgid_to_kill = -(child_pid as i32);

                kvlog::info!(
                    "Sending SIGINT to process group",
                    job_index = process.job_index,
                    base_task_index = job_id.base_task_index().0,
                    reason = exit_cause.name(),
                    pid = child_pid,
                    pgid = pgid_to_kill
                );

                unsafe {
                    if libc::kill(pgid_to_kill, libc::SIGINT) == -1 {
                        let err = std::io::Error::last_os_error();
                        kvlog::error!("Failed to send SIGINT", ?err, pid = child_pid, pgid = pgid_to_kill);
                    }
                }
                process.alive = false;
                process.kill_sent_at = Some(std::time::Instant::now());
                false
            }
            ProcessRequest::AttachClient { stdin, stdout, socket, workspace_config, kind } => {
                let ws_index = match self.state.get_or_create_workspace_index(workspace_config) {
                    Ok(ws) => ws,
                    Err(err) => {
                        kvlog::info!("Error spawning workspace", %err);
                        if let Some(stdout) = stdout {
                            let mut file = unsafe { std::fs::File::from_raw_fd(stdout.into_raw_fd()) };
                            if let Some(config_err) = err.downcast_ref::<crate::config::ConfigError>() {
                                let _ = file.write_all(config_err.message.as_bytes());
                            } else {
                                let _ = file.write_all(format!("error: {}\n", err).as_bytes());
                            }
                        }
                        return false;
                    }
                };

                match kind {
                    AttachKind::Tui => {
                        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
                            kvlog::error!("TUI client requires stdin/stdout FDs");
                            return false;
                        };
                        self.attach_tui_client(stdin, stdout, socket, ws_index);
                    }
                    AttachKind::Run { task_name, params, as_test } => {
                        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
                            kvlog::error!("Run client requires stdin/stdout FDs");
                            return false;
                        };
                        self.attach_run_client(stdin, stdout, socket, ws_index, &task_name, params, as_test);
                    }
                    AttachKind::TestRun { filters } => {
                        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
                            kvlog::error!("Test client requires stdin/stdout FDs");
                            return false;
                        };
                        self.attach_test_run_client(stdin, stdout, socket, ws_index, filters);
                    }
                    AttachKind::Rpc { subscribe } => {
                        self.attach_rpc_client(socket, ws_index, subscribe);
                    }
                    AttachKind::Logs { query } => {
                        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
                            kvlog::error!("Logs client requires stdin/stdout FDs");
                            return false;
                        };
                        self.attach_logs_client(stdin, stdout, socket, ws_index, query);
                    }
                }

                false
            }
            ProcessRequest::ClientExited { index } => {
                self.client_exited(index as ClientIndex);
                false
            }
            ProcessRequest::AttachSelfLogsClient { stdout, socket } => {
                self.attach_self_logs_client(stdout, socket);
                false
            }
            ProcessRequest::GlobalTermination => {
                for (_, process) in &mut self.state.processes {
                    let child_pid = process.child.id();
                    let pgid_to_kill = -(child_pid as i32);

                    unsafe {
                        if libc::kill(pgid_to_kill, libc::SIGTERM) == -1 {
                            let err = std::io::Error::last_os_error();
                            kvlog::error!("Failed to send SIGTERM", ?err, ?child_pid);
                        }
                    }
                }
                true
            }
            ProcessRequest::ProcessExited { pid, status } => {
                for (index, process) in &mut self.state.processes {
                    if process.child.id() != pid {
                        continue;
                    }
                    kvlog::info!("Process Exited", pid, status, job_index = process.job_index);
                    if let Some(stdin) = process.child.stdout.take() {
                        let mut buffer = process
                            .stdout_buffer
                            .take()
                            .unwrap_or_else(|| Buffer { data: self.buffer_pool.pop().unwrap_or_default(), read: 0 });

                        loop {
                            match try_read(stdin.as_raw_fd(), &mut buffer.data) {
                                ReadResult::Done | ReadResult::WouldBlock | ReadResult::EOF => {
                                    break;
                                }
                                ReadResult::More => continue,
                                ReadResult::OtherError(err) => {
                                    kvlog::error!("Read failed with unexpected error", ?err);
                                    break;
                                }
                            }
                        }
                        if let Some(workspace) = self.state.workspaces.get_mut(process.workspace_index as usize) {
                            while let Some(line) = buffer.readline() {
                                process.append_line(line, &mut workspace.line_writer);
                            }
                            if !buffer.remaining_slice().is_empty() {
                                process.append_line(buffer.remaining_slice(), &mut workspace.line_writer);
                            }
                        }

                        buffer.reset();
                        self.buffer_pool.push(buffer.data);
                        if let Err(err) = self.state.poll.registry().deregister(&mut SourceFd(&stdin.as_raw_fd())) {
                            kvlog::error!("Failed to unregister fd", ?err);
                        }
                    }
                    if let Some(stderr) = process.child.stderr.take() {
                        let mut buffer = process
                            .stderr_buffer
                            .take()
                            .unwrap_or_else(|| Buffer { data: self.buffer_pool.pop().unwrap_or_default(), read: 0 });

                        loop {
                            match try_read(stderr.as_raw_fd(), &mut buffer.data) {
                                ReadResult::Done | ReadResult::WouldBlock | ReadResult::EOF => {
                                    break;
                                }
                                ReadResult::More => continue,
                                ReadResult::OtherError(err) => {
                                    kvlog::error!("Read failed with unexpected error", ?err);
                                    break;
                                }
                            }
                        }
                        if let Some(workspace) = self.state.workspaces.get_mut(process.workspace_index as usize) {
                            while let Some(line) = buffer.readline() {
                                process.append_line(line, &mut workspace.line_writer);
                            }
                            if !buffer.remaining_slice().is_empty() {
                                process.append_line(buffer.remaining_slice(), &mut workspace.line_writer);
                            }
                        }
                        buffer.reset();
                        self.buffer_pool.push(buffer.data);
                        if let Err(err) = self.state.poll.registry().deregister(&mut SourceFd(&stderr.as_raw_fd())) {
                            kvlog::error!("Failed to unregister fd", ?err);
                        }
                    }
                    let ws_idx = process.workspace_index;
                    let job_idx = process.job_index;
                    let cause = process.pending_exit_cause.unwrap_or(ExitCause::Unknown);
                    let exit_code =
                        if libc::WIFEXITED(status as i32) { libc::WEXITSTATUS(status as i32) as u32 } else { u32::MAX };
                    let rpc_cause = match cause {
                        ExitCause::Unknown => crate::rpc::ExitCause::Unknown,
                        ExitCause::Killed => crate::rpc::ExitCause::Killed,
                        ExitCause::Restarted => crate::rpc::ExitCause::Restarted,
                        ExitCause::SpawnFailed => crate::rpc::ExitCause::SpawnFailed,
                        ExitCause::ProfileConflict => crate::rpc::ExitCause::ProfileConflict,
                        ExitCause::Timeout => crate::rpc::ExitCause::Timeout,
                    };
                    if let Some(workspace) = self.state.workspaces.get(ws_idx as usize) {
                        let mut ws = workspace.handle.state.write().unwrap();
                        ws.update_job_status(
                            job_idx,
                            JobStatus::Exited {
                                finished_at: std::time::Instant::now(),
                                log_end: workspace.line_writer.tail(),
                                cause,
                                status: exit_code,
                            },
                        );
                    }
                    if process.ready_checker.as_ref().is_some_and(|rc| rc.timeout_at.is_some()) {
                        self.state.timed_ready_count -= 1;
                    }
                    if process.timeout_tracker.is_some() {
                        self.state.timed_timeout_count -= 1;
                    }
                    self.state.processes.remove(index);
                    self.broadcast_job_exited(ws_idx, job_idx, exit_code as i32, rpc_cause);
                    return false;
                }
                kvlog::info!("Didn't Find ProcessExited");
                false
            }
            ProcessRequest::Spawn { task, job_id, workspace_id, job_index } => {
                if let Err(err) = self.spawn(workspace_id, job_id, job_index, task) {
                    kvlog::error!("Failed to spawn process", ?err, ?job_id);
                    if let Some(workspace) = self.state.workspaces.get(workspace_id as usize) {
                        let log_end = workspace.line_writer.tail();
                        let mut ws = workspace.handle.state.write().unwrap();
                        ws.update_job_status(
                            job_index,
                            JobStatus::Exited {
                                finished_at: std::time::Instant::now(),
                                log_end,
                                cause: ExitCause::SpawnFailed,
                                status: 127,
                            },
                        );
                        drop(ws);
                        self.broadcast_job_exited(workspace_id, job_index, 127, crate::rpc::ExitCause::SpawnFailed);
                    }
                }
                false
            }
            ProcessRequest::RpcMessage { socket, fds, kind, correlation, one_shot, ws_data, payload } => {
                self.handle_rpc_request(socket, fds, kind, correlation, one_shot, &ws_data, &payload);
                false
            }
        }
    }

    fn register_client(
        &mut self,
        socket: UnixStream,
        ws_index: WorkspaceIndex,
        kind: ClientKind,
        partial_rpc_read: Option<(DecodingState, Vec<u8>)>,
    ) -> (usize, Arc<ClientChannel>) {
        let channel = Arc::new(ClientChannel {
            waker: extui::event::polling::Waker::new().unwrap(),
            events: Mutex::new(Vec::new()),
            selected: AtomicU64::new(0),
            state: AtomicU64::new(0),
        });
        let next = self.clients.vacant_key();
        let _ = self.state.poll.registry().register(
            &mut SourceFd(&socket.as_raw_fd()),
            TokenHandle::Client(next as u32).into(),
            Interest::READABLE,
        );
        let _ = socket.set_nonblocking(true);
        let client_entry =
            ClientEntry { channel: channel.clone(), workspace: ws_index, socket, kind, partial_rpc_read };
        let index = self.clients.insert(client_entry);
        (index, channel)
    }

    fn attach_tui_client(&mut self, stdin: File, stdout: File, socket: UnixStream, ws_index: WorkspaceIndex) {
        let (index, channel) = self.register_client(socket, ws_index, ClientKind::Tui, None);
        let ws = &mut self.state.workspaces[ws_index as usize];
        let ws_handle = ws.handle.clone();
        kvlog::info!("Client Attached");
        let keybinds = global_keybinds();

        let output_mode = if std::env::var("DEVSM_JSON_STATE_STREAM").is_ok() {
            crate::tui::OutputMode::JsonStateStream
        } else {
            crate::tui::OutputMode::Terminal
        };
        self.spawn_client_channel("tui", index, move || {
            crate::tui::run(stdin, stdout, &ws_handle, channel, keybinds, output_mode)
        });
    }

    fn attach_run_client(
        &mut self,
        stdin: File,
        mut stdout: File,
        socket: UnixStream,
        ws_index: WorkspaceIndex,
        task_name: &str,
        params: Vec<u8>,
        as_test: bool,
    ) {
        let params: ValueMap = jsony::from_binary(&params).unwrap_or_else(|_| ValueMap::new());
        let (name, profile) = task_name.rsplit_once(":").unwrap_or((&*task_name, ""));

        let ws = &self.state.workspaces[ws_index as usize];
        let job_id = {
            let mut state = ws.handle.state.write().unwrap();
            let Some(base_index) = state.base_index_by_name(name) else {
                drop(state);
                let _ = std::io::Write::write_all(&mut stdout, b"Task not found\n");
                return;
            };
            drop(state);
            ws.handle.restart_task(base_index, params, profile);

            let state = ws.handle.state.read().unwrap();
            let bt = &state.base_tasks[base_index.idx()];
            bt.jobs.all().last().map(|ji| (state[*ji].log_group, *ji, base_index))
        };

        let Some((job_id, job_index, base_index)) = job_id else {
            let _ = std::io::Write::write_all(&mut stdout, b"Failed to start task\n");
            return;
        };

        if as_test {
            let mut state = ws.handle.state.write().unwrap();
            let group_id = state.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
            state.last_test_group =
                Some(workspace::TestGroup { group_id, base_tasks: vec![base_index], job_indices: vec![job_index] });
        }
        let forwarder_socket = socket.try_clone().ok();
        let (index, channel) = self.register_client(socket, ws_index, ClientKind::Run { log_group: job_id }, None);
        let ws = &self.state.workspaces[ws_index as usize]; // require ws to allow register_client to run

        let ws_handle = ws.handle.clone();
        self.spawn_client_channel("run", index, move || {
            crate::log_fowarder_ui::run(stdin, stdout, forwarder_socket, &ws_handle, job_id, channel)
        });
    }

    fn attach_test_run_client(
        &mut self,
        stdin: File,
        stdout: File,
        mut socket: UnixStream,
        ws_index: WorkspaceIndex,
        filters: Vec<u8>,
    ) {
        let filters: crate::daemon::TestFilters =
            jsony::from_binary(&filters).unwrap_or_else(|_| crate::daemon::TestFilters::default());

        let test_filters: Vec<crate::cli::TestFilter> = {
            let mut v = Vec::new();
            for tag in &filters.exclude_tags {
                v.push(crate::cli::TestFilter::ExcludeTag(tag));
            }
            for tag in &filters.include_tags {
                v.push(crate::cli::TestFilter::IncludeTag(tag));
            }
            for name in &filters.include_names {
                v.push(crate::cli::TestFilter::IncludeName(name));
            }
            v
        };

        let ws = &self.state.workspaces[ws_index as usize];
        let test_run = match ws.handle.start_test_run(&test_filters) {
            Ok(run) => run,
            Err(err) => {
                let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
                let _ = std::io::Write::write_all(&mut file, format!("error: {}\n", err).as_bytes());
                std::mem::forget(file);
                return;
            }
        };

        if test_run.test_jobs.is_empty() {
            let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
            let _ = std::io::Write::write_all(&mut file, b"No tests matched the filters\n");
            std::mem::forget(file);
            // Send TerminateAck so client exits gracefully with success
            let mut encoder = crate::rpc::Encoder::new();
            encoder.encode_empty(RpcMessageKind::TerminateAck, 0);
            let _ = socket.write_all(encoder.output());
            return;
        }
        let forwarder_socket = socket.try_clone().ok();
        let (index, channel) = self.register_client(socket, ws_index, ClientKind::TestRun, None);
        let ws = &self.state.workspaces[ws_index as usize];

        let ws_handle = ws.handle.clone();
        self.spawn_client_channel("test-run", index, move || {
            crate::test_summary_ui::run(stdin, stdout, forwarder_socket, &ws_handle, test_run, channel)
        });
    }

    fn spawn_client_channel(
        &mut self,
        kind: &'static str,
        index: usize,
        func: impl (FnOnce() -> anyhow::Result<()>) + 'static + Send + UnwindSafe,
    ) {
        let request_channel = self.state.request.clone();
        let result = std::thread::Builder::new().name(format!("{kind}[{index}")).spawn(move || {
            let result = std::panic::catch_unwind(|| func());
            match result {
                Ok(Ok(())) => {
                    kvlog::info!("Client thread exiting", index, reason = "completed", kind);
                }
                Ok(Err(err)) => {
                    kvlog::error!("Client thread exiting with error", index, %err, kind);
                }
                Err(_) => {
                    kvlog::error!("Client thread panicked", index, kind);
                }
            }
            request_channel.send(ProcessRequest::ClientExited { index });
        });
        match result {
            Ok(_) => {}
            Err(err) => {
                kvlog::error!("Failed to spawn client thread", ?err, index, kind);
                self.state.request.send(ProcessRequest::ClientExited { index });
            }
        }
    }

    fn attach_rpc_client(&mut self, socket: UnixStream, ws_index: WorkspaceIndex, subscribe: bool) {
        let subscriptions = RpcSubscriptions { job_status: subscribe, job_exits: subscribe };

        let (client_index, _) = self.register_client(socket, ws_index, ClientKind::Rpc { subscriptions }, None);
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_response(
            crate::rpc::RpcMessageKind::OpenWorkspaceAck,
            0,
            &crate::rpc::OpenWorkspaceResponse { success: true, error: None },
        );
        let client = &mut self.clients[client_index];
        let _ = client.socket.write_all(encoder.output());

        kvlog::info!("RPC client attached", workspace = ws_index, subscribe);
    }

    fn attach_logs_client(
        &mut self,
        stdin: File,
        stdout: File,
        socket: UnixStream,
        ws_index: WorkspaceIndex,
        query: Vec<u8>,
    ) {
        let query: crate::daemon::LogsQuery =
            jsony::from_binary(&query).unwrap_or_else(|_| crate::daemon::LogsQuery::default());
        let forwarder_socket = socket.try_clone().ok();
        let (index, channel) = self.register_client(socket, ws_index, ClientKind::Logs, None);

        let ws = &self.state.workspaces[ws_index as usize];
        let ws_handle = ws.handle.clone();
        let config = crate::log_fowarder_ui::LogForwarderConfig::from_query(&query, &ws_handle);
        self.spawn_client_channel("logs", index, move || {
            crate::log_fowarder_ui::run_logs(stdin, stdout, forwarder_socket, &ws_handle, config, channel)
        });
    }

    fn attach_self_logs_client(&mut self, stdout: File, socket: UnixStream) {
        let (index, channel) = self.register_client(socket, 0, ClientKind::SelfLogs, None);
        let request_channel = self.state.request.clone();
        self.spawn_client_channel("self-logs", index, move || {
            run_self_logs_forwarder(stdout, channel, request_channel.clone(), index);
            Ok(())
        });
    }

    fn terminate_client(&mut self, client_index: ClientIndex, reason: SocketTerminationReason) {
        let Some(client) = self.clients.get(client_index as usize) else {
            return;
        };
        client.channel.set_terminated();
        let _ = client.channel.wake();
        let _ = self.state.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
        kvlog::info!("Client terminated", index = client_index as usize, reason = reason.as_str());
        match &client.kind {
            ClientKind::Rpc { .. } => {
                let Some(_) = self.clients.try_remove(client_index as usize) else {
                    kvlog::debug!("Client already removed", index = client_index as usize);
                    return;
                };
            }
            _ => (),
        }
    }

    fn client_exited(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.try_remove(client_index as usize) else {
            kvlog::debug!("Client already removed", index = client_index as usize);
            return;
        };
        client.channel.set_terminated();
        let _ = client.channel.wake();
        let _ = self.state.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
        kvlog::info!("Client exited", index = client_index as usize);
    }

    fn broadcast_job_status(
        &mut self,
        ws_index: WorkspaceIndex,
        job_index: JobIndex,
        status: crate::rpc::JobStatusKind,
    ) {
        let event = crate::rpc::JobStatusEvent { job_index: job_index.as_u32(), status };
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_push(RpcMessageKind::JobStatus, &event);
        let output = encoder.output();

        for (_, client) in &mut self.clients {
            if client.workspace != ws_index {
                continue;
            }
            let ClientKind::Rpc { subscriptions } = &client.kind else { continue };
            if !subscriptions.job_status {
                continue;
            }
            let _ = client.socket.write_all(output);
        }
    }

    fn broadcast_job_exited(
        &mut self,
        ws_index: WorkspaceIndex,
        job_index: JobIndex,
        exit_code: i32,
        cause: crate::rpc::ExitCause,
    ) {
        let event = crate::rpc::JobExitedEvent { job_index: job_index.as_u32(), exit_code, cause };
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_push(RpcMessageKind::JobExited, &event);
        let output = encoder.output();

        for (_, client) in &mut self.clients {
            if client.workspace != ws_index {
                continue;
            }
            let ClientKind::Rpc { subscriptions } = &client.kind else { continue };
            if !subscriptions.job_exits {
                continue;
            }
            let _ = client.socket.write_all(output);
        }
    }
}

pub(crate) fn process_worker(request: Arc<MioChannel>, wait_thread: std::thread::JoinHandle<()>, poll: Poll) {
    let mut events = Events::with_capacity(128);
    let mut job_manager = EventLoop {
        buffer_pool: Vec::new(),
        clients: Slab::new(),
        state: State {
            request,
            workspace_map: HashMap::new(),
            workspaces: slab::Slab::new(),
            processes: slab::Slab::new(),
            poll,
            timed_ready_count: 0,
            timed_timeout_count: 0,
        },
        wait_thread,
    };
    loop {
        if TERMINATED.load(std::sync::atomic::Ordering::Relaxed) {
            job_manager.handle_request(ProcessRequest::GlobalTermination);
            return;
        }

        let poll_timeout = if job_manager.state.timed_ready_count > 0 || job_manager.state.timed_timeout_count > 0 {
            Some(std::time::Duration::from_millis(500))
        } else {
            None
        };

        if let Err(err) = job_manager.state.poll.poll(&mut events, poll_timeout) {
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }

        if TERMINATED.load(std::sync::atomic::Ordering::Relaxed) {
            job_manager.handle_request(ProcessRequest::GlobalTermination);
            return;
        }

        for event in &events {
            match TokenHandle::from(event.token()) {
                TokenHandle::RequestChannel => {
                    let mut reqs = Vec::new();
                    job_manager.state.request.swap_recv(&mut reqs);
                    for req in reqs {
                        if job_manager.handle_request(req) {
                            return;
                        }
                    }
                }
                TokenHandle::Task(pipe) => {
                    if let Err(err) = job_manager.read(pipe.index(), pipe.pipe()) {
                        kvlog::error!("Failed to read from process", ?err, ?pipe);
                    }
                }
                TokenHandle::Client(index) => {
                    job_manager.handle_client_rpc_read(index);
                }
            }
        }

        job_manager.scheduled();
        if job_manager.state.timed_ready_count > 0 {
            job_manager.check_ready_timeouts();
        }
        if job_manager.state.timed_timeout_count > 0 {
            job_manager.check_timeouts();
        }
        job_manager.check_kill_escalation();

        for (_, client) in &job_manager.clients {
            let _ = client.channel.wake();
        }
    }
}

type ClientIndex = u32;

#[derive(Clone, Copy, Debug)]
struct TaskPipe(u32);

impl TaskPipe {
    pub fn index(self) -> usize {
        (self.0 >> 1) as usize
    }
    pub fn pipe(self) -> Pipe {
        if (self.0 & 1) == 0 { Pipe::Stdout } else { Pipe::Stderr }
    }
}

enum TokenHandle {
    RequestChannel,
    Task(TaskPipe),
    Client(ClientIndex),
}

impl From<Token> for TokenHandle {
    fn from(token: Token) -> Self {
        if token.0 == CHANNEL_TOKEN.0 {
            TokenHandle::RequestChannel
        } else if token.0 & (1 << 29) != 0 {
            let index = token.0 & !(1 << 29);
            TokenHandle::Client(index as ClientIndex)
        } else {
            let pipe = TaskPipe(token.0 as u32);
            TokenHandle::Task(pipe)
        }
    }
}

impl From<TokenHandle> for Token {
    fn from(handle: TokenHandle) -> Self {
        match handle {
            TokenHandle::RequestChannel => CHANNEL_TOKEN,
            TokenHandle::Client(index) => Token((1 << 29) | (index as usize)),
            TokenHandle::Task(pipe) => Token(pipe.0 as usize),
        }
    }
}

pub(crate) const CHANNEL_TOKEN: Token = Token(1 << 30);

fn wait_thread(req: Arc<MioChannel>) {
    loop {
        let mut status: libc::c_int = 0;
        unsafe {
            let pid = libc::wait(&mut status);
            if pid > 0 {
                req.send(ProcessRequest::ProcessExited { pid: pid as u32, status: status as u32 });
            } else if pid == -1 {
                // let errno = *libc::__errno_location();
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::ECHILD {
                    std::thread::park();
                } else {
                    kvlog::error!("Error calling wait", ?errno);
                }
            }
        }
    }
}

static TERMINATED: AtomicBool = AtomicBool::new(false);
extern "C" fn term_handler(_sig: i32) {
    TERMINATED.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(waker) = GLOBAL_WAKER.get() {
        let _ = waker.wake();
    }
}

fn setup_signal_handler(sig: i32, handler: unsafe extern "C" fn(i32)) -> anyhow::Result<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as libc::sighandler_t;
        // Do not set SA_RESTART, so that system calls are interrupted
        sa.sa_flags = 0;
        // Block all signals while the handler is running
        libc::sigfillset(&mut sa.sa_mask);

        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            bail!("Failed to set signal handler for signal {}: {}", sig, std::io::Error::last_os_error());
        }
    }
    Ok(())
}

static GLOBAL_WAKER: std::sync::OnceLock<&'static Waker> = std::sync::OnceLock::new();
static GLOBAL_KEYBINDS: std::sync::OnceLock<Mutex<Arc<crate::keybinds::Keybinds>>> = std::sync::OnceLock::new();
static GLOBAL_USER_CONFIG_LOADED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub(crate) fn global_keybinds() -> Arc<crate::keybinds::Keybinds> {
    GLOBAL_KEYBINDS
        .get_or_init(|| {
            let config = crate::user_config::UserConfig::load();
            GLOBAL_USER_CONFIG_LOADED.get_or_init(|| config.loaded_from_file);
            Mutex::new(Arc::new(config.keybinds))
        })
        .lock()
        .unwrap()
        .clone()
}

pub(crate) fn update_global_keybinds(keybinds: crate::keybinds::Keybinds) {
    if let Some(mutex) = GLOBAL_KEYBINDS.get() {
        *mutex.lock().unwrap() = Arc::new(keybinds);
    }
}

pub(crate) fn user_config_loaded() -> bool {
    let _ = global_keybinds();
    *GLOBAL_USER_CONFIG_LOADED.get().unwrap_or(&false)
}

impl ProcessManagerHandle {
    pub(crate) fn global_block_on(
        mut func: impl FnMut(ProcessManagerHandle) + Send + Sync + 'static,
    ) -> anyhow::Result<()> {
        // Load user config (keybinds) at startup
        let _ = global_keybinds();

        setup_signal_handler(libc::SIGTERM, term_handler)?;
        setup_signal_handler(libc::SIGINT, term_handler)?;
        let poll = Poll::new()?;
        let waker = Box::leak(Box::new(Waker::new(poll.registry(), CHANNEL_TOKEN)?));
        if GLOBAL_WAKER.set(waker).is_err() {
            bail!("Global Waker already initialized");
        }
        let request = Arc::new(MioChannel { waker, events: Mutex::new(Vec::new()) });
        let r = request.clone();
        let r2 = r.clone();
        let wait_thread = std::thread::Builder::new()
            .name("PID-Poller".into())
            .spawn(move || {
                wait_thread(r2);
            })
            .unwrap();

        let handle = ProcessManagerHandle { request };

        std::thread::Builder::new()
            .name("RPC-forwarder".into())
            .spawn(move || {
                func(handle);
            })
            .unwrap();
        process_worker(r, wait_thread, poll);
        Ok(())
    }
}

fn run_self_logs_forwarder(
    mut stdout: File,
    channel: Arc<ClientChannel>,
    request_channel: Arc<MioChannel>,
    index: usize,
) {
    kvlog::debug!("Self-logs forwarder thread started", index);

    let Some(log_state) = crate::self_log::daemon_log_state() else {
        kvlog::info!("Self-logs forwarder exiting", index, reason = "no_log_state");
        request_channel.send(ProcessRequest::ClientExited { index });
        return;
    };

    let mut last_offset = 0u64;
    let mut logs = Vec::new();
    let mut fmt_buf = Vec::new();
    let mut parents = kvlog::collector::ParentSpanSuffixCache::new_boxed();
    let mut exit_reason = "signaled_to_terminate";

    loop {
        if channel.is_terminated() {
            break;
        }

        let (new_offset, follower_id) = {
            let mut state = log_state.lock().unwrap();
            let new_offset = state.snapshot_from(last_offset, &mut logs);
            let follower_id = state.register_follower(std::thread::current());
            (new_offset, follower_id)
        };

        if !logs.is_empty() {
            fmt_buf.clear();
            for log in kvlog::encoding::decode(&logs) {
                if let Ok((ts, level, span, fields)) = log {
                    kvlog::collector::format_statement_with_colors(&mut fmt_buf, &mut parents, ts, level, span, fields);
                }
            }
            if stdout.write_all(&fmt_buf).is_err() {
                log_state.lock().unwrap().unregister_follower(follower_id);
                exit_reason = "stdout_write_error";
                break;
            }
        }
        last_offset = new_offset;

        if channel.is_terminated() {
            log_state.lock().unwrap().unregister_follower(follower_id);
            break;
        }

        std::thread::park();
        log_state.lock().unwrap().unregister_follower(follower_id);
    }

    kvlog::info!("Self-logs forwarder exiting", index, reason = exit_reason);
    request_channel.send(ProcessRequest::ClientExited { index });
}
