use crate::rpc;
use crate::rpc::{CommandBody, DecodingState, RpcMessageKind};
use crate::workspace::{self, ExitCause, JobIndex, JobStatus, ProcessOwner, Workspace, WorkspaceState};
use crate::{
    config::{Command, TaskConfigRc, TaskKind},
    line_width::{Segment, apply_raw_display_mode_vt_to_style, write_kept_bytes},
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
        unix::{ffi::OsStrExt, net::UnixStream, process::CommandExt},
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
pub(crate) const PROCESS_KILL_ESCALATION: std::time::Duration = std::time::Duration::from_secs(20);
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
    /// Active ptrace tracer when the job was spawned with `--derive-cache-key`.
    /// `None` if untraced or before the initial `SIGTRAP` is observed.
    #[cfg(target_os = "linux")]
    pub(crate) tracer: Option<Box<crate::auto_deps::Tracer>>,
    /// True if `install_ptrace_traceme` was applied to this child's command.
    #[cfg(target_os = "linux")]
    pub(crate) is_traced: bool,
}

struct UntrackedChildGuard {
    child: Option<Child>,
}

impl UntrackedChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("untracked child already disarmed")
    }

    fn disarm(mut self) -> Child {
        self.child.take().expect("untracked child already disarmed")
    }
}

impl Drop for UntrackedChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else { return };
        let pid = child.id() as i32;
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl ActiveProcess {
    fn append_line(&mut self, text: &[u8], writer: &mut LogWriter) {
        if let Ok(text) = std::str::from_utf8(text) {
            let mut iter = Segment::iterator(text);
            let mut new_style = self.style;
            let mut width = 0usize;
            for segment in &mut iter {
                match segment {
                    Segment::Ascii(s) => width += s.len(),
                    Segment::AnsiEscapes(escape) => apply_raw_display_mode_vt_to_style(&mut new_style, escape),
                    Segment::Utf8(s) => width += s.width(),
                }
            }

            if !iter.stripped {
                writer.push_line(text, width as u32, self.log_group, self.style);
            } else {
                writer.push_line_with(text.len(), width as u32, self.log_group, self.style, |dst| {
                    write_kept_bytes(text, dst)
                });
            }
            self.style = new_style;
        }
    }

    pub(crate) fn request_termination(&mut self, cause: ExitCause) {
        if !self.alive {
            return;
        }
        self.pending_exit_cause = Some(cause);
        let child_pid = self.child.id();
        let pgid = -(child_pid as i32);
        kvlog::info!(
            "Sending SIGINT to process group",
            job_index = self.job_index,
            base_task_index = self.log_group.base_task_index().0,
            reason = cause.name(),
            pid = child_pid,
            pgid
        );
        unsafe {
            if libc::kill(pgid, libc::SIGINT) == -1 {
                let err = std::io::Error::last_os_error();
                kvlog::error!("Failed to send SIGINT", ?err, pid = child_pid, pgid);
            }
        }
        self.alive = false;
        self.kill_sent_at = Some(crate::clock::now());
    }

    pub(crate) fn send_signal(&self, signal: i32) {
        let child_pid = self.child.id();
        let pgid = -(child_pid as i32);
        unsafe {
            if libc::kill(pgid, signal) == -1 {
                let err = std::io::Error::last_os_error();
                kvlog::error!("Failed to send signal", ?err, pid = child_pid, pgid, signal);
            }
        }
    }

    pub(crate) fn escalate_to_sigkill(&mut self) {
        let elapsed_secs = self.kill_sent_at.map(|t| crate::clock::now().duration_since(t).as_secs());
        kvlog::warn!(
            "Process did not terminate after SIGINT, escalating to SIGKILL",
            job_index = self.job_index,
            base_task_index = self.log_group.base_task_index().0,
            pid = self.child.id(),
            pgid = -(self.child.id() as i32),
            ?elapsed_secs
        );
        self.send_signal(libc::SIGKILL);
        self.kill_sent_at = None;
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
    Run {
        log_groups: Vec<LogGroup>,
    },
    TestRun,
    Rpc {
        subscriptions: RpcSubscriptions,
    },
    SelfLogs,
    Logs,
    /// A `devsm exec` client blocked until its task's `require` dependencies are
    /// satisfied. `job` is the remote scheduler entry standing in for the exec.
    Exec {
        job: JobIndex,
    },
    TerminalHarness {
        harness_id: workspace::HarnessId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalHarnessAvailability {
    Reserved,
    Starting,
    Running,
    Idle,
    Detaching,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalRunBinding {
    job: JobIndex,
    run_token: workspace::RunToken,
}

/// All mutable lifecycle facts for a terminal wrapper. Keeping them in one
/// value makes invalid cross-field combinations visible and ensures the event
/// loop is the sole authority for ownership transitions.
struct TerminalHarnessState {
    binding: Option<TerminalRunBinding>,
    phase: TerminalHarnessAvailability,
    replacement: Option<TerminalRunBinding>,
    pending_exit_cause: Option<ExitCause>,
    process_group: Option<libc::pid_t>,
}

struct TerminalHarness {
    workspace: WorkspaceIndex,
    client_index: ClientIndex,
    base_task: workspace::BaseTaskIndex,
    sticky: bool,
    wrapper_process_group: libc::pid_t,
    state: TerminalHarnessState,
}

struct ClientEntry {
    workspace: WorkspaceIndex,
    channel: Arc<ClientChannel>,
    socket: UnixStream,
    kind: ClientKind,
    partial_rpc_read: Option<(DecodingState, Vec<u8>)>,
    outbound: Vec<u8>,
    outbound_offset: usize,
    wake_process_group_after_flush: Option<libc::pid_t>,
}

/// State for a pending `devsm exec` gate. The socket lives in the [`ClientEntry`]
/// identified by `client_index`; this only tracks the warning deadline.
struct RemoteExec {
    client_index: ClientIndex,
    submitted_at: std::time::Instant,
    /// Whether the "waiting on …" stderr notice has already been sent.
    warned: bool,
    /// The daemon has handed execution to the client and is now holding this job
    /// active until the inherited socket closes.
    proceeded: bool,
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
    /// Pending `devsm exec` gates, keyed by the remote scheduler job standing in
    /// for the exec. Reconciled each loop iteration: once the job's requirements
    /// resolve, the client is told to proceed (or that they can never be met).
    remote_execs: HashMap<(WorkspaceIndex, JobIndex), RemoteExec>,
    terminal_harnesses: HashMap<workspace::HarnessId, TerminalHarness>,
    next_harness_id: workspace::HarnessId,
    next_run_token: workspace::RunToken,
    db: crate::db::Db,
    /// Pid → process_index for jobs spawned under ptrace. Empty in steady
    /// state — checked with `is_empty()` in the reap loop to keep the
    /// non-traced fast path identical to the un-modified version.
    #[cfg(target_os = "linux")]
    traced_root_pids: HashMap<i32, usize>,
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
}

pub(crate) enum ReadResult {
    Done,
    More,
    Eof,
    WouldBlock,
    OtherError(std::io::ErrorKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketTerminationReason {
    Eof,
    ReadError,
    WriteError,
    ProtocolError,
    ClientRequestedTerminate,
}

impl SocketTerminationReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eof => "socket_eof",
            Self::ReadError => "socket_read_error",
            Self::WriteError => "socket_write_error",
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
            return ReadResult::Eof;
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

fn drain_outbound_with(
    outbound: &[u8],
    offset: &mut usize,
    mut write: impl FnMut(&[u8]) -> std::io::Result<usize>,
) -> std::io::Result<bool> {
    while *offset < outbound.len() {
        match write(&outbound[*offset..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "socket write returned zero")),
            Ok(written) => *offset += written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

/// Which class of pending service termination [`EventLoop::request_service_termination`]
/// should look for: one freeing a queued service, or one freeing a resource.
enum TerminationKind {
    Queue,
    Resource,
}

/// One workspace's decision for a single scheduling pass, computed while holding
/// the workspace read lock and acted on after it is released.
enum SchedulingStep {
    Spawn {
        job_id: LogGroup,
        job_index: JobIndex,
        task: TaskConfigRc,
        target: workspace::ExecutionTarget,
    },
    Cancel { job_index: JobIndex },
    Idle,
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
                ReadResult::Eof => {
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
                let mut iter = Segment::iterator(text);
                let mut new_style = process.style;
                let mut width = 0usize;
                for segment in &mut iter {
                    match segment {
                        Segment::Ascii(s) => width += s.len(),
                        Segment::AnsiEscapes(escape) => apply_raw_display_mode_vt_to_style(&mut new_style, escape),
                        Segment::Utf8(s) => width += s.width(),
                    }
                }

                if let Some(workspace) = self.state.workspaces.get_mut(process.workspace_index as usize) {
                    if !iter.stripped {
                        workspace.line_writer.push_line(text, width as u32, process.log_group, process.style);
                    } else {
                        workspace.line_writer.push_line_with(
                            text.len(),
                            width as u32,
                            process.log_group,
                            process.style,
                            |dst| write_kept_bytes(text, dst),
                        );
                    }
                }

                if let Some(ref checker) = process.ready_checker
                    && crate::line_width::strip_ansi_and_contains(text, &checker.needle)
                {
                    if checker.timeout_at.is_some() {
                        self.state.timed_ready_count -= 1;
                    }
                    ready_matched = true;
                    process.ready_checker = None;
                }

                if let Some(ref mut tracker) = process.timeout_tracker {
                    let now = crate::clock::now();
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

        self.broadcast_debug_trace(ws_index, "output", job_index);

        if ready_matched {
            self.broadcast_debug_trace(ws_index, "ready_matched", job_index);
            self.mark_service_ready(ws_index, job_index);
        }

        Ok(())
    }
    /// Signal the one service a workspace wants stopped for the given reason, if
    /// any. The signal is asynchronous (SIGINT to the process group) and
    /// idempotent — [`ActiveProcess::request_termination`] no-ops once the
    /// process is already draining — so callers may invoke this every scheduling
    /// pass without re-signalling a service that is already on its way down.
    fn request_service_termination(&mut self, ws_index: WorkspaceIndex, kind: TerminationKind) {
        let Some(ws) = self.state.workspaces.get(ws_index as usize) else {
            return;
        };
        let state = ws.handle.state();
        let candidate = match kind {
            TerminationKind::Queue => state.service_to_terminate_for_queue(),
            TerminationKind::Resource => state.service_to_terminate_for_resource(),
        };
        let Some((service_to_kill, exit_cause)) = candidate else {
            return;
        };
        let job = &state.jobs[service_to_kill];
        let job_id = job.log_group;
        let JobStatus::Running { owner, .. } = job.process_status else {
            return;
        };
        drop(state);
        self.handle_request(ProcessRequest::TerminateJob { job_id, owner, exit_cause });
    }

    pub(crate) fn scheduled(&mut self) {
        const MAX_ITERATIONS: u32 = 10_000;

        // Snapshot the workspace keys once. The set is stable across this call
        // (the event loop is single-threaded and only mutates `workspaces` while
        // handling other events), and iterating an owned list frees the loop
        // body to call `&mut self` methods without holding a borrow on
        // `self.state.workspaces`.
        let ws_indices: Vec<usize> = self.state.workspaces.iter().map(|(i, _)| i).collect();

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
            for &wsi in &ws_indices {
                // Fire any pending service terminations needed to unblock a
                // queued service or free a contended resource. These are
                // asynchronous: the service stays Running until its process
                // exits, so we only signal and fall through to scheduling.
                // Independent ready jobs below must not wait out the drain.
                // Re-firing across passes is harmless (idempotent) and never
                // spins, because only an actual spawn/cancel `continue`s 'outer.
                self.request_service_termination(wsi as WorkspaceIndex, TerminationKind::Queue);
                self.request_service_termination(wsi as WorkspaceIndex, TerminationKind::Resource);

                let step = {
                    let Some(ws) = self.state.workspaces.get(wsi) else {
                        continue;
                    };
                    let state = ws.handle.state();
                    match state.next_scheduled() {
                        workspace::Scheduled::Ready(job_index) => {
                            let job = &state.jobs[job_index];
                            SchedulingStep::Spawn {
                                job_id: job.log_group,
                                job_index,
                                task: job.task().clone(),
                                target: job.execution_target,
                            }
                        }
                        workspace::Scheduled::Never(job_index) => SchedulingStep::Cancel { job_index },
                        workspace::Scheduled::None => SchedulingStep::Idle,
                    }
                };

                match step {
                    SchedulingStep::Spawn { job_id, job_index, task, target } => {
                        if self.state.remote_execs.contains_key(&(wsi as WorkspaceIndex, job_index)) {
                            self.start_remote_exec(wsi as WorkspaceIndex, job_index);
                        } else if let workspace::ExecutionTarget::Terminal { harness_id, run_token } = target {
                            if let Err(err) = self.start_terminal_job(
                                wsi as WorkspaceIndex,
                                job_id,
                                job_index,
                                task,
                                harness_id,
                                run_token,
                            ) {
                                let bound = self
                                    .state
                                    .terminal_harnesses
                                    .get(&harness_id)
                                    .and_then(|harness| harness.state.binding)
                                    .is_some_and(|binding| binding.job == job_index && binding.run_token == run_token);
                                if bound {
                                    if let Some(client_index) = self
                                        .state
                                        .terminal_harnesses
                                        .get(&harness_id)
                                        .map(|harness| harness.client_index)
                                    {
                                        let mut encoder = crate::rpc::Encoder::new();
                                        encoder.encode_push(
                                            RpcMessageKind::TerminalError,
                                            &crate::rpc::TerminalErrorEvent {
                                                message: format!("failed to deliver terminal launch: {err:#}").into(),
                                            },
                                        );
                                        let _ = self.queue_client_output(client_index, encoder.output());
                                    }
                                    self.terminal_spawn_failed(
                                        harness_id,
                                        crate::rpc::TerminalSpawnFailedEvent {
                                            run_token,
                                            message: format!("failed to deliver terminal launch: {err:#}").into(),
                                        },
                                    );
                                } else {
                                    self.handle_spawn_failure(wsi as WorkspaceIndex, job_id, job_index, err);
                                }
                            }
                        } else if let Err(err) = self.spawn(wsi as WorkspaceIndex, job_id, job_index, task) {
                            self.handle_spawn_failure(wsi as WorkspaceIndex, job_id, job_index, err);
                        }
                        continue 'outer;
                    }
                    SchedulingStep::Cancel { job_index } => {
                        kvlog::info!("Scheduled task will never be ready cancelling", job_index);
                        let terminal_cancellation = if let Some(ws) = self.state.workspaces.get(wsi) {
                            let mut state = ws.handle.state.write().unwrap();
                            let target = state.jobs.get(job_index).map(|job| job.execution_target);
                            let message = state
                                .record_dependency_failure_from_requirements(job_index)
                                .as_ref()
                                .map(Self::exec_dependency_failure_message)
                                .unwrap_or_else(|| {
                                    "Terminal task was cancelled because its requirements could not be satisfied"
                                        .to_string()
                                });
                            state.update_job_status(job_index, JobStatus::Cancelled);
                            match target {
                                Some(workspace::ExecutionTarget::Terminal { harness_id, run_token }) => {
                                    Some((harness_id, run_token, message))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };
                        if let Some((harness_id, run_token, message)) = terminal_cancellation {
                            self.cancel_terminal_reservation(harness_id, run_token, Some(message));
                        }
                        continue 'outer;
                    }
                    SchedulingStep::Idle => {}
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
        let now = crate::clock::now();
        let mut timed_out = Vec::new();
        for (_, process) in &mut self.state.processes {
            if let Some(ref checker) = process.ready_checker
                && checker.timeout_at.is_some_and(|t| now > t)
            {
                self.state.timed_ready_count -= 1;
                process.ready_checker = None;
                timed_out.push((process.workspace_index, process.job_index));
            }
        }
        for (ws_index, job_index) in timed_out {
            self.broadcast_debug_trace(ws_index, "ready_timeout", job_index);
            self.mark_service_ready(ws_index, job_index);
        }
    }

    fn check_timeouts(&mut self) {
        let now = crate::clock::now();
        let mut to_kill: Vec<usize> = Vec::new();

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
                to_kill.push(index);
            }
        }

        for index in to_kill {
            let Some(process) = self.state.processes.get_mut(index) else {
                continue;
            };
            process.request_termination(ExitCause::Timeout);
        }
    }

    fn check_kill_escalation(&mut self) {
        let now = crate::clock::now();

        for (_index, process) in &mut self.state.processes {
            let Some(kill_sent_at) = process.kill_sent_at else {
                continue;
            };

            if now.duration_since(kill_sent_at) < PROCESS_KILL_ESCALATION {
                continue;
            }

            process.escalate_to_sigkill();
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
        let (path, trace_requested) = {
            let ws = &mut *workspace.handle.state.write().unwrap();
            ws.change_number = ws.change_number.wrapping_add(1);
            match &ws[job_index].process_status {
                JobStatus::Scheduled { .. } => {
                    ws.update_job_status(job_index, JobStatus::Starting);
                }
                JobStatus::Starting => (),
                JobStatus::Running { .. } | JobStatus::RemoteRunning { .. } => {
                    bail!("Attempt start already running job")
                }
                JobStatus::Exited { .. } => bail!("Attempt start already exited job"),
                JobStatus::Cancelled => return Ok(()),
            }
            (ws.config.current.base_path().join(tc.pwd), ws[job_index].trace)
        };

        let mut command = match &tc.command {
            Command::Sh { script, args } => {
                let mut cmd = std::process::Command::new("/bin/sh");
                cmd.arg("-c").arg(*script);
                if !args.is_empty() {
                    cmd.arg("devsm").args(*args);
                }
                cmd
            }
            Command::Cmd(cmd_args) => {
                if cmd_args.is_empty() {
                    bail!("Command must not be empty");
                }
                let [cmd, args @ ..] = *cmd_args else { panic!("Expected atleast one command") };
                let mut cmd = std::process::Command::new(cmd);
                cmd.args(args);
                cmd
            }
        };

        command.env("CARGO_TERM_COLOR", "always").current_dir(path).envs(tc.envvar.iter().copied());
        command.process_group(0);

        // Set parent-death signal to SIGTERM so that if this manager process dies,
        // we automatically kill the managed processed. This is just a fallback,
        // devsm will already automatically kill managed processed when it can.
        #[cfg(target_os = "linux")]
        unsafe {
            command.pre_exec(|| {
                let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }

        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        #[cfg(target_os = "linux")]
        let installed_traceme = if trace_requested {
            crate::auto_deps::install_ptrace_traceme(&mut command);
            #[cfg(target_arch = "x86_64")]
            crate::auto_deps::install_seccomp_filter(&mut command, crate::auto_deps::TRACED_SYSCALLS);
            true
        } else {
            false
        };
        #[cfg(not(target_os = "linux"))]
        if trace_requested {
            bail!("--derive-cache-key is only supported on Linux");
        }

        let child = command.spawn().context("Failed to spawn process")?;
        let mut untracked_child = UntrackedChildGuard::new(child);
        if let Some(stdout) = &mut untracked_child.child_mut().stdout {
            unsafe {
                if libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == -1 {
                    bail!("Failed to set stdout non-blocking: {}", std::io::Error::last_os_error());
                }
            }
            self.state.poll.registry().register(
                &mut SourceFd(&stdout.as_raw_fd()),
                Token(index << 1),
                Interest::READABLE,
            )?;
        };
        if let Some(stderr) = &mut untracked_child.child_mut().stderr {
            unsafe {
                if libc::fcntl(stderr.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == -1 {
                    bail!("Failed to set stderr non-blocking: {}", std::io::Error::last_os_error());
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
                timeout_at: rc.timeout.map(|secs| crate::clock::now() + std::time::Duration::from_secs_f64(secs)),
            }
        });
        if ready_checker.as_ref().is_some_and(|rc| rc.timeout_at.is_some()) {
            self.state.timed_ready_count += 1;
        }
        let ready_state = ready_checker.as_ref().map(|_| false);

        let now = crate::clock::now();
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
        let child = untracked_child.disarm();
        // Record the traced root pid only after all fallible fd/poll setup has
        // succeeded. The slab vacant_key reserved as `index` is the slot this
        // process now occupies, so the entry matches the committed process. An
        // earlier insert would leak when registration failed and the guard
        // killed the child without it ever entering `state.processes`.
        #[cfg(target_os = "linux")]
        if installed_traceme {
            self.state.traced_root_pids.insert(child.id() as i32, index);
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
            #[cfg(target_os = "linux")]
            tracer: None,
            #[cfg(target_os = "linux")]
            is_traced: installed_traceme,
        });
        {
            let mut ws = workspace.handle.state.write().unwrap();
            ws.update_job_status(
                job_index,
                JobStatus::Running { owner: ProcessOwner::Daemon { process_index }, ready_state },
            );
        }
        self.broadcast_job_status(workspace_index, job_index, crate::rpc::JobStatusKind::Running);
        Ok(())
    }

    fn handle_spawn_failure(
        &mut self,
        workspace_id: WorkspaceIndex,
        job_id: LogGroup,
        job_index: JobIndex,
        err: anyhow::Error,
    ) {
        kvlog::error!("Failed to spawn process", ?err, ?job_id);
        let Some(workspace) = self.state.workspaces.get(workspace_id as usize) else {
            return;
        };
        let mut ws = workspace.handle.state.write().unwrap();
        let public_id = ws
            .update_job_status(
                job_index,
                JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::SpawnFailed, status: 127 },
            )
            .unwrap_or(0);
        drop(ws);
        self.broadcast_job_exited(workspace_id, public_id, 127, crate::rpc::ExitCause::SpawnFailed);
    }

    /// "Spawn" a remote exec job: its requirements are satisfied, so instead of
    /// launching a daemon child we acquire its resources and leave it in
    /// `Starting`. The reconciler tells the waiting client to `exec`, then marks
    /// it `RemoteRunning`; socket EOF later releases the held requirements.
    ///
    /// The daemon never sees the unmanaged command's real exit code: socket EOF
    /// always records `Exited { status: 0 }`. The job is marked `cache_synthetic`
    /// so that fabricated success is never written to the persistent cache and is
    /// never reused as an in-memory cache hit. `Terminated`-predicate dependents
    /// still treat it as satisfied, which is the documented limit of
    /// `managed = false`.
    fn start_remote_exec(&mut self, workspace_id: WorkspaceIndex, job_index: JobIndex) {
        let Some(workspace) = self.state.workspaces.get(workspace_id as usize) else {
            return;
        };
        let started = {
            let mut ws = workspace.handle.state.write().unwrap();
            let Some(job) = ws.jobs.get_mut(job_index) else {
                return;
            };
            if !matches!(job.process_status, JobStatus::Scheduled { .. }) {
                return;
            }
            // Suppress cache writes/reuse: the status:0 recorded on socket EOF is
            // fabricated, not an observed success. See the doc comment above.
            job.cache_synthetic = true;
            ws.update_job_status(job_index, JobStatus::Starting);
            true
        };
        if started {
            self.broadcast_job_status(workspace_id, job_index, crate::rpc::JobStatusKind::Starting);
        }
    }
}

pub(crate) enum AttachKind {
    Tui,
    Run { task_name: Box<str>, params: Vec<u8>, as_test: bool, derive_cache_key: bool },
    TestRun { filters: Vec<u8> },
    Rpc { subscribe: bool },
    Logs { query: Vec<u8> },
    Exec { task_name: Box<str>, params: Vec<u8> },
    Terminal { task_name: Box<str>, params: Vec<u8>, sticky: bool, wrapper_process_group: libc::pid_t },
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
        remaining: Vec<u8>,
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
        owner: ProcessOwner,
        exit_cause: ExitCause,
    },
    TerminalControl {
        workspace_id: WorkspaceIndex,
        task_name: Box<str>,
        profile: Box<str>,
        params: ValueMap<'static>,
        restart: bool,
        response: std::sync::mpsc::SyncSender<Result<(), String>>,
    },
    ReconcileTerminalHarnesses { workspace_id: WorkspaceIndex },
    ClientExited {
        index: usize,
    },
    AttachSelfLogsClient {
        stdout: File,
        socket: UnixStream,
    },
    ShellSpawn {
        script: Box<str>,
        env_vars: Vec<(Box<str>, Box<str>)>,
    },
    /// Run clipboard helper commands on the event-loop thread.
    ///
    /// `fork`/`spawn` must stay centralized here because this thread owns child
    /// process creation and wait/reap behavior. TUI/client threads may request
    /// a copy, but must not spawn clipboard helpers directly.
    ClipboardCopy {
        text: Box<str>,
        /// `Some(command)` runs that exact shell command; `None` tries platform defaults.
        command: Option<Box<str>>,
        response: std::sync::mpsc::SyncSender<std::io::Result<String>>,
    },
    GlobalTermination,
}

/// Flag bit indicating the selection is a meta-group rather than a base task.
pub const SELECTED_META_GROUP_FLAG: u64 = 1 << 63;
/// Meta-group selection for tests (`@tests`).
pub const SELECTED_META_GROUP_TESTS: u64 = SELECTED_META_GROUP_FLAG;
/// Meta-group selection for actions (`@actions`).
pub const SELECTED_META_GROUP_ACTIONS: u64 = SELECTED_META_GROUP_FLAG | 1;
/// Meta-group selection for services (`@services`).
pub const SELECTED_META_GROUP_SERVICES: u64 = SELECTED_META_GROUP_FLAG | 2;

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
    /// - `SELECTED_META_GROUP_SERVICES`: the @services meta-group is selected
    /// - `SELECTED_META_GROUP_ACTIONS`: the @actions meta-group is selected
    /// - `SELECTED_META_GROUP_TESTS`: the @tests meta-group is selected
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
    /// Wake the event loop without queuing a request. Used by paths that mutate
    /// workspace state and need the next `scheduled()` poll to run.
    pub(crate) fn wake(&self) {
        if let Err(err) = self.waker.wake() {
            kvlog::error!("Failed to wake event loop", ?err);
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
        self.db.record_workspace(&workspace_config);
        Ok(index)
    }
}

struct ClipboardCommand {
    program: &'static str,
    args: &'static [&'static str],
}

#[cfg(target_os = "macos")]
const CLIPBOARD_COMMANDS: &[ClipboardCommand] = &[ClipboardCommand { program: "pbcopy", args: &[] }];

#[cfg(target_os = "linux")]
const CLIPBOARD_COMMANDS: &[ClipboardCommand] = &[
    ClipboardCommand { program: "wl-copy", args: &[] },
    ClipboardCommand { program: "xsel", args: &["--clipboard", "--input"] },
    ClipboardCommand { program: "xclip", args: &["-selection", "clipboard"] },
];

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const CLIPBOARD_COMMANDS: &[ClipboardCommand] = &[];

fn run_clipboard_copy_command(text: &str, preferred_command: Option<&str>) -> std::io::Result<String> {
    let mut errors = Vec::new();

    if let Some(command) = preferred_command {
        run_shell_clipboard_command(command, text)?;
        return Ok(command.to_string());
    }

    for command in CLIPBOARD_COMMANDS {
        match run_named_clipboard_command(command, text) {
            Ok(()) => return Ok(command.program.to_string()),
            Err(err) => errors.push(format!("{}: {err}", command.program)),
        }
    }

    if errors.is_empty() {
        Err(std::io::Error::other("no clipboard commands configured for this OS"))
    } else {
        Err(std::io::Error::other(errors.join("; ")))
    }
}

fn configure_clipboard_command(cmd: &mut std::process::Command) {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

fn run_shell_clipboard_command(command: &str, text: &str) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c").arg(command);
    configure_clipboard_command(&mut cmd);
    let mut child = cmd.spawn()?;
    wait_for_clipboard_process(&mut child, text)
}

fn run_named_clipboard_command(command: &ClipboardCommand, text: &str) -> std::io::Result<()> {
    let mut cmd = std::process::Command::new(command.program);
    cmd.args(command.args);
    configure_clipboard_command(&mut cmd);
    let mut child = cmd.spawn()?;
    wait_for_clipboard_process(&mut child, text)
}

fn wait_for_clipboard_process(child: &mut Child, text: &str) -> std::io::Result<()> {
    {
        let mut stdin =
            child.stdin.take().ok_or_else(|| std::io::Error::other("clipboard command stdin unavailable"))?;
        stdin.write_all(text.as_bytes())?;
    }

    for _ in 0..30 {
        if let Some(status) = child.try_wait()? {
            return if status.success() { Ok(()) } else { Err(std::io::Error::other(format!("exited with {status}"))) };
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // xsel/xclip may stay alive to own the X selection. Once stdin has been
    // accepted and the process remains running briefly, treat that as success.
    Ok(())
}

impl EventLoop {
    fn handle_request(&mut self, req: ProcessRequest) -> bool {
        match req {
            ProcessRequest::TerminateJob { job_id, owner, exit_cause } => {
                if let ProcessOwner::Terminal { harness_id, run_token } = owner {
                    if self.cancel_terminal_reservation(harness_id, run_token, None) {
                        return false;
                    }
                    let Some(harness) = self.state.terminal_harnesses.get_mut(&harness_id) else {
                        kvlog::warn!("TerminateJob: terminal harness missing", harness_id, run_token);
                        return false;
                    };
                    let expected = harness.state.binding.map(|binding| binding.run_token);
                    if expected != Some(run_token) {
                        kvlog::warn!("TerminateJob: stale terminal run token", harness_id, run_token);
                        return false;
                    }
                    harness.state.pending_exit_cause = Some(exit_cause);
                    let client_index = harness.client_index;
                    let replacement_pending = harness.state.replacement.is_some();
                    let wrapper_process_group = harness.wrapper_process_group;
                    let mut encoder = crate::rpc::Encoder::new();
                    encoder.encode_push(
                        RpcMessageKind::TerminalStop,
                        &crate::rpc::TerminalStopEvent {
                            run_token,
                            cause: Self::rpc_exit_cause(exit_cause),
                            replacement_pending,
                        },
                    );
                    if let Err(error) =
                        self.queue_client_output_and_wake(client_index, encoder.output(), wrapper_process_group)
                    {
                        kvlog::warn!("Failed to queue terminal stop", harness_id, %error);
                        self.terminate_client(client_index, SocketTerminationReason::WriteError);
                    }
                    return false;
                }
                let ProcessOwner::Daemon { process_index } = owner else { unreachable!() };
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
                process.request_termination(exit_cause);
                false
            }
            ProcessRequest::TerminalControl { workspace_id, task_name, profile, params, restart, response } => {
                let params = jsony::to_binary(&params);
                let payload = jsony::to_binary(&crate::rpc::SpawnTaskRequest {
                    task_name: &task_name,
                    profile: &profile,
                    params: &params,
                    as_test: false,
                    cached: false,
                });
                let kind = if restart { RpcMessageKind::RestartTask } else { RpcMessageKind::StartTask };
                let result = match self.terminal_control_rpc(workspace_id, kind, &payload) {
                    Some(CommandBody::Empty | CommandBody::Message(_)) => Ok(()),
                    Some(CommandBody::Error(error)) => Err(error.into()),
                    None => Err(format!("Task '{}' is no longer configured with managed = \"terminal\"", task_name)),
                };
                let _ = response.send(result);
                false
            }
            ProcessRequest::ReconcileTerminalHarnesses { workspace_id } => {
                self.reconcile_idle_terminal_harnesses(workspace_id);
                false
            }
            ProcessRequest::AttachClient { stdin, stdout, socket, workspace_config, kind } => {
                // Fault injection for the crash-reporting tests: panic on the
                // event-loop thread (taking the daemon down) once a client has
                // attached. Debug-only so it cannot fire in release builds.
                #[cfg(debug_assertions)]
                if std::env::var_os("DEVSM_TEST_PANIC_ON_ATTACH").is_some() {
                    panic!("injected test panic on client attach");
                }
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
                    AttachKind::Run { task_name, params, as_test, derive_cache_key } => {
                        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
                            kvlog::error!("Run client requires stdin/stdout FDs");
                            return false;
                        };
                        self.attach_run_client(
                            stdin,
                            stdout,
                            socket,
                            ws_index,
                            &task_name,
                            params,
                            as_test,
                            derive_cache_key,
                        );
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
                    AttachKind::Exec { task_name, params } => {
                        self.attach_exec_client(socket, ws_index, &task_name, params);
                    }
                    AttachKind::Terminal { task_name, params, sticky, wrapper_process_group } => {
                        self.attach_terminal_client(
                            socket,
                            ws_index,
                            &task_name,
                            params,
                            sticky,
                            wrapper_process_group,
                        );
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
            ProcessRequest::ShellSpawn { script, env_vars } => {
                let mut cmd = std::process::Command::new("/bin/sh");
                cmd.arg("-c").arg(&*script);
                cmd.envs(env_vars.iter().map(|(k, v)| (&**k, &**v)));
                cmd.stdin(Stdio::null());
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
                unsafe {
                    cmd.pre_exec(|| {
                        libc::setsid();
                        Ok(())
                    });
                }
                match cmd.spawn() {
                    Ok(_child) => {
                        kvlog::info!("Shell command spawned", script = &*script);
                    }
                    Err(err) => {
                        kvlog::error!("Failed to spawn shell command", ?err, script = &*script);
                    }
                }
                false
            }
            ProcessRequest::ClipboardCopy { text, command, response } => {
                let result = run_clipboard_copy_command(&text, command.as_deref());
                let _ = response.send(result);
                false
            }
            ProcessRequest::GlobalTermination => {
                for (_, process) in &self.state.processes {
                    process.send_signal(libc::SIGTERM);
                }
                true
            }
            ProcessRequest::RpcMessage { socket, fds, kind, correlation, one_shot, ws_data, payload, remaining } => {
                use rpc_handlers::{RpcError, RpcOutcome};

                match self.handle_rpc_request(socket, fds, kind, correlation, one_shot, &ws_data, &payload, remaining) {
                    Ok(RpcOutcome::Attached) => {}
                    Ok(RpcOutcome::RawWrite { mut socket, data }) => {
                        if let Err(e) = socket.write_all(&data) {
                            kvlog::warn!("Failed to write RPC raw response", ?e);
                        }
                    }
                    Ok(RpcOutcome::Respond { mut socket, encoder, register }) => {
                        if let Err(e) = socket.write_all(encoder.output()) {
                            kvlog::warn!("Failed to write RPC response", ?e);
                        }
                        if let Some((ws_index, partial)) = register {
                            self.register_client(
                                socket,
                                ws_index,
                                ClientKind::Rpc { subscriptions: RpcSubscriptions::default() },
                                partial,
                            );
                        }
                    }
                    Err(RpcError { mut socket, error, correlation }) => {
                        let mut encoder = crate::rpc::Encoder::new();
                        crate::rpc::ResponseState::send_error(&mut encoder, correlation, &error);
                        if let Err(e) = socket.write_all(encoder.output()) {
                            kvlog::warn!("Failed to write RPC error response", ?e);
                        }
                    }
                }
                false
            }
        }
    }

    fn reap_children(&mut self) {
        // Fast path: when no traced jobs are active the loop is identical
        // to the un-modified version (single waitpid flag, no extra
        // dispatch). The HashMap probe is one branch on a cache-resident
        // pointer.
        #[cfg(target_os = "linux")]
        let any_traced = !self.state.traced_root_pids.is_empty();

        #[cfg(target_os = "linux")]
        let flags = libc::WNOHANG | if any_traced { libc::__WALL } else { 0 };
        #[cfg(not(target_os = "linux"))]
        let flags = libc::WNOHANG;

        loop {
            let mut status: i32 = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, flags) };
            if pid <= 0 {
                break;
            }

            #[cfg(target_os = "linux")]
            if any_traced && self.dispatch_traced_status(pid, status) {
                continue;
            }

            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.handle_process_exited(pid as u32, status as u32);
            }
        }
    }

    /// Routes a `waitpid` status to the appropriate `Tracer`.
    ///
    /// Returns `true` when the status was fully consumed by the trace
    /// machinery and the caller should skip the normal exit path. Returns
    /// `false` when the status corresponds to the root tracee's terminal
    /// exit and `handle_process_exited` should still run.
    ///
    /// Idempotent for unknown pids — see [`crate::auto_deps::Tracer::on_status`].
    #[cfg(target_os = "linux")]
    fn dispatch_traced_status(&mut self, pid: i32, status: i32) -> bool {
        // Initial SIGTRAP from `execve` for a freshly-spawned traced root:
        // construct the Tracer and resume.
        if let Some(&process_index) = self.state.traced_root_pids.get(&pid) {
            let needs_attach =
                self.state.processes.get(process_index).is_some_and(|p| p.is_traced && p.tracer.is_none());
            if needs_attach {
                if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP {
                    match crate::auto_deps::Tracer::attach(pid, crate::auto_deps::TraceOptions::default()) {
                        Ok(tracer) => {
                            if let Some(p) = self.state.processes.get_mut(process_index) {
                                p.tracer = Some(Box::new(tracer));
                            }
                            return true;
                        }
                        Err(err) => {
                            kvlog::error!("Tracer::attach failed", pid, ?err);
                            self.state.traced_root_pids.remove(&pid);
                            // Fall through; the child will continue running but
                            // without ptrace bookkeeping. No trace report is
                            // delivered.
                            return false;
                        }
                    }
                } else {
                    // Unexpected pre-attach status — let the standard path
                    // handle it (probably a spawn failure).
                    return false;
                }
            }
        }

        // Forward to every active tracer. With at most one traced root in
        // the typical case the iteration cost is negligible. The Tracer is
        // documented idempotent for unknown pids.
        let mut owning_index: Option<usize> = None;
        for (idx, process) in &mut self.state.processes {
            if let Some(tracer) = process.tracer.as_deref_mut() {
                tracer.on_status(pid, status);
                let is_root_exit =
                    self.state.traced_root_pids.get(&pid).copied().is_some_and(|root_idx| root_idx == idx)
                        && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status));
                if is_root_exit {
                    owning_index = Some(idx);
                }
            }
        }

        let Some(idx) = owning_index else {
            // Status fully consumed by a tracer (stop, fork notification,
            // non-root tracee exit, or unknown pid).
            return true;
        };

        // Root tracee exited: finalize the report and stash it on the job.
        // Returning `false` lets `handle_process_exited` run the normal
        // cleanup path (drain pipes, deliver `JobExited`, drop process).
        let (process_pid, ws_index, job_index) = {
            let p = &self.state.processes[idx];
            (p.child.id() as i32, p.workspace_index, p.job_index)
        };
        self.state.traced_root_pids.remove(&process_pid);
        let tracer = self.state.processes[idx].tracer.take();
        if let Some(tracer) = tracer {
            // The Tracer may still be waiting on descendant exits; drive
            // them out synchronously so the report is complete. Bounded
            // by `__WALL` waits on the same pid set the kernel still owns.
            let mut tracer = *tracer;
            while !tracer.is_done() {
                let mut s: i32 = 0;
                let p = unsafe { libc::waitpid(-1, &mut s, libc::__WALL) };
                if p <= 0 {
                    break;
                }
                tracer.on_status(p, s);
            }
            let report = tracer.finish();
            let exit_code = report.exit_status.code().unwrap_or(-1);
            let truncated = report.truncated;
            let workspace = &self.state.workspaces[ws_index as usize];
            let project_root = workspace.handle.state.read().unwrap().config.current.base_path().to_path_buf();
            let inferred = crate::auto_deps::infer(&report, &project_root);
            let payload = crate::auto_deps::TraceReportPayload::from_inferred(inferred, exit_code, truncated);
            workspace.handle.state.write().unwrap()[job_index].trace_report = Some(payload);
        }
        false
    }

    fn handle_process_exited(&mut self, pid: u32, status: u32) {
        for (index, process) in &mut self.state.processes {
            if process.child.id() != pid {
                continue;
            }
            kvlog::info!("Process Exited", pid, status, job_index = process.job_index);
            if let Some(stdout) = process.child.stdout.take() {
                let mut buffer = process
                    .stdout_buffer
                    .take()
                    .unwrap_or_else(|| Buffer { data: self.buffer_pool.pop().unwrap_or_default(), read: 0 });

                loop {
                    match try_read(stdout.as_raw_fd(), &mut buffer.data) {
                        ReadResult::Done | ReadResult::WouldBlock | ReadResult::Eof => {
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
                if let Err(err) = self.state.poll.registry().deregister(&mut SourceFd(&stdout.as_raw_fd())) {
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
                        ReadResult::Done | ReadResult::WouldBlock | ReadResult::Eof => {
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
            let public_id = if let Some(workspace) = self.state.workspaces.get(ws_idx as usize) {
                let mut ws = workspace.handle.state.write().unwrap();
                ws.update_job_status(
                    job_idx,
                    JobStatus::Exited { finished_at: crate::clock::now(), cause, status: exit_code },
                )
                .unwrap_or(0)
            } else {
                0
            };
            if process.ready_checker.as_ref().is_some_and(|rc| rc.timeout_at.is_some()) {
                self.state.timed_ready_count -= 1;
            }
            if process.timeout_tracker.is_some() {
                self.state.timed_timeout_count -= 1;
            }
            self.state.processes.remove(index);
            self.broadcast_job_exited(ws_idx, public_id, exit_code as i32, rpc_cause);
            return;
        }
        kvlog::info!("Didn't Find ProcessExited", pid);
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
        let client_entry = ClientEntry {
            channel: channel.clone(),
            workspace: ws_index,
            socket,
            kind,
            partial_rpc_read,
            outbound: Vec::new(),
            outbound_offset: 0,
            wake_process_group_after_flush: None,
        };
        let index = self.clients.insert(client_entry);
        (index, channel)
    }

    fn validate_outbound_frames(bytes: &[u8]) -> std::io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            if bytes.len() - offset < crate::rpc::HEAD_SIZE {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated RPC frame"));
            }
            let header: &[u8; crate::rpc::HEAD_SIZE] = bytes[offset..offset + crate::rpc::HEAD_SIZE]
                .try_into()
                .expect("header length checked");
            let head = crate::rpc::Head::from_bytes(header)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid RPC frame: {error:?}")))?;
            let payload = head.ws_len as usize + head.len as usize;
            if payload > crate::rpc::DEFAULT_MAX_PAYLOAD {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("RPC payload is {payload} bytes; maximum is {}", crate::rpc::DEFAULT_MAX_PAYLOAD),
                ));
            }
            let frame_len = crate::rpc::HEAD_SIZE + payload;
            if bytes.len() - offset < frame_len {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated RPC payload"));
            }
            offset += frame_len;
        }
        Ok(())
    }

    fn set_client_interest(&mut self, client_index: ClientIndex, writable: bool) -> std::io::Result<()> {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "client disconnected"));
        };
        let interest = if writable { Interest::READABLE.add(Interest::WRITABLE) } else { Interest::READABLE };
        self.state.poll.registry().reregister(
            &mut SourceFd(&client.socket.as_raw_fd()),
            TokenHandle::Client(client_index).into(),
            interest,
        )
    }

    fn queue_client_output(&mut self, client_index: ClientIndex, bytes: &[u8]) -> std::io::Result<()> {
        self.queue_client_output_inner(client_index, bytes, None)
    }

    fn queue_client_output_and_wake(
        &mut self,
        client_index: ClientIndex,
        bytes: &[u8],
        process_group: libc::pid_t,
    ) -> std::io::Result<()> {
        self.queue_client_output_inner(client_index, bytes, Some(process_group))
    }

    fn queue_client_output_inner(
        &mut self,
        client_index: ClientIndex,
        bytes: &[u8],
        wake_process_group_after_flush: Option<libc::pid_t>,
    ) -> std::io::Result<()> {
        Self::validate_outbound_frames(bytes)?;
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "client disconnected"));
        };
        if client.outbound_offset == client.outbound.len() {
            client.outbound.clear();
            client.outbound_offset = 0;
        }
        client.outbound.extend_from_slice(bytes);
        if wake_process_group_after_flush.is_some() {
            client.wake_process_group_after_flush = wake_process_group_after_flush;
        }
        self.set_client_interest(client_index, true)?;
        self.flush_client_output(client_index)
    }

    fn flush_client_output(&mut self, client_index: ClientIndex) -> std::io::Result<()> {
        let wake_process_group = {
            let Some(client) = self.clients.get_mut(client_index as usize) else {
                return Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "client disconnected"));
            };
            let fd = client.socket.as_raw_fd();
            if !drain_outbound_with(&client.outbound, &mut client.outbound_offset, |bytes| {
                let result = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
                if result < 0 { Err(std::io::Error::last_os_error()) } else { Ok(result as usize) }
            })? {
                return Ok(());
            }
            client.outbound.clear();
            client.outbound_offset = 0;
            client.wake_process_group_after_flush.take()
        };
        if let Some(process_group) = wake_process_group {
            unsafe { libc::kill(-process_group, libc::SIGCONT) };
        }
        self.set_client_interest(client_index, false)
    }

    fn attach_tui_client(&mut self, stdin: File, stdout: File, socket: UnixStream, ws_index: WorkspaceIndex) {
        let (index, channel) = self.register_client(socket, ws_index, ClientKind::Tui, None);
        let ws = &mut self.state.workspaces[ws_index as usize];
        let ws_handle = ws.handle.clone();
        kvlog::info!("Client Attached");
        let keybinds = global_keybinds();
        let clipboard_config = global_clipboard_config();

        let output_mode = if std::env::var("DEVSM_JSON_STATE_STREAM").is_ok() {
            crate::tui::OutputMode::JsonStateStream
        } else {
            crate::tui::OutputMode::Terminal
        };
        self.spawn_client_channel("tui", index, move || {
            crate::tui::run(stdin, stdout, &ws_handle, channel, keybinds, clipboard_config, output_mode)
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
        derive_cache_key: bool,
    ) {
        let params = jsony::from_binary::<ValueMap>(&params).unwrap_or_else(|_| ValueMap::new()).to_owned();
        let (name, profile) = task_name.rsplit_once(":").unwrap_or((task_name, ""));

        let ws = &self.state.workspaces[ws_index as usize];

        let mut spec = workspace::SpawnSpec::task(name, profile, params, false);
        spec.test_group = as_test;
        if derive_cache_key {
            if let Some(task) = spec.tasks.first_mut() {
                task.trace = true;
            }
        }
        let result = match ws.handle.submit(spec) {
            Ok(result) => result,
            Err(e) => {
                let _ = std::io::Write::write_all(&mut stdout, format!("{e}\n").as_bytes());
                return;
            }
        };
        let Some(_) = result.jobs.first() else {
            let _ = std::io::Write::write_all(&mut stdout, b"No job created\n");
            return;
        };
        let (job_indices, log_groups) = {
            let state = ws.handle.state.read().unwrap();
            let job_indices = result.jobs.iter().map(|(_, ji)| *ji).collect::<Vec<_>>();
            let log_groups = job_indices.iter().map(|ji| state[*ji].log_group).collect::<Vec<_>>();
            (job_indices, log_groups)
        };
        let forwarder_socket = socket.try_clone().ok();
        let (index, channel) =
            self.register_client(socket, ws_index, ClientKind::Run { log_groups: log_groups.clone() }, None);
        let ws = &self.state.workspaces[ws_index as usize]; // require ws to allow register_client to run

        let ws_handle = ws.handle.clone();
        if result.group_names.is_empty() && job_indices.len() == 1 {
            let job_id = log_groups[0];
            self.spawn_client_channel("run", index, move || {
                crate::log_fowarder_ui::run(stdin, stdout, forwarder_socket, &ws_handle, job_id, channel)
            });
        } else {
            self.spawn_client_channel("run", index, move || {
                crate::log_fowarder_ui::run_many(
                    stdin,
                    stdout,
                    forwarder_socket,
                    &ws_handle,
                    job_indices,
                    log_groups,
                    channel,
                )
            });
        }
    }

    /// Attach a `devsm exec` client. The task's `require` graph is scheduled like
    /// a normal run, but the leaf job is a *remote* entry: instead of spawning a
    /// process, it merely gates the client. Once its requirements resolve, the
    /// reconciler ([`Self::poll_remote_execs`]) tells the client to proceed.
    fn attach_exec_client(&mut self, socket: UnixStream, ws_index: WorkspaceIndex, task_name: &str, params: Vec<u8>) {
        let params = jsony::from_binary::<ValueMap>(&params).unwrap_or_else(|_| ValueMap::new()).to_owned();
        let (name, profile) = task_name.rsplit_once(':').unwrap_or((task_name, ""));

        let ws = &self.state.workspaces[ws_index as usize];
        let result = match ws.handle.submit_exec(name, profile, params) {
            Ok(result) => result,
            Err(e) => {
                Self::send_exec_error_message(&socket, &e);
                return;
            }
        };
        let Some((_, job_index)) = result.jobs.first().copied() else {
            Self::send_exec_error_message(&socket, "No job created");
            return;
        };

        let (client_index, _channel) =
            self.register_client(socket, ws_index, ClientKind::Exec { job: job_index }, None);
        self.state.remote_execs.insert(
            (ws_index, job_index),
            RemoteExec {
                client_index: client_index as ClientIndex,
                submitted_at: crate::clock::now(),
                warned: false,
                proceeded: false,
            },
        );
    }

    fn attach_terminal_client(
        &mut self,
        socket: UnixStream,
        ws_index: WorkspaceIndex,
        task_name: &str,
        params: Vec<u8>,
        sticky: bool,
        wrapper_process_group: libc::pid_t,
    ) {
        let params = jsony::from_binary::<ValueMap>(&params).unwrap_or_else(|_| ValueMap::new()).to_owned();
        let (name, profile) = task_name.rsplit_once(':').unwrap_or((task_name, ""));
        let harness_id = self.state.next_harness_id;
        self.state.next_harness_id = self.state.next_harness_id.wrapping_add(1).max(1);
        let run_token = self.state.next_run_token;
        self.state.next_run_token = self.state.next_run_token.wrapping_add(1).max(1);

        let (client_index, _) =
            self.register_client(socket, ws_index, ClientKind::TerminalHarness { harness_id }, None);
        if wrapper_process_group <= 0 {
            let mut encoder = crate::rpc::Encoder::new();
            encoder.encode_push(
                RpcMessageKind::TerminalError,
                &crate::rpc::TerminalErrorEvent { message: "terminal wrapper reported an invalid process group".into() },
            );
            let _ = self.queue_client_output(client_index as ClientIndex, encoder.output());
            return;
        }
        let ws = &self.state.workspaces[ws_index as usize];
        let result = match ws.handle.submit_terminal(name, profile, params, harness_id, run_token, false) {
            Ok(result) => result,
            Err(message) => {
                let mut encoder = crate::rpc::Encoder::new();
                encoder.encode_push(
                    RpcMessageKind::TerminalError,
                    &crate::rpc::TerminalErrorEvent { message: message.into() },
                );
                let _ = self.queue_client_output(client_index as ClientIndex, encoder.output());
                return;
            }
        };
        let Some((base_task, job)) = result.jobs.first().copied() else {
            return;
        };
        let waiting = ws.handle.state().pending_dep_names(job);
        self.state.terminal_harnesses.insert(
            harness_id,
            TerminalHarness {
                workspace: ws_index,
                client_index: client_index as ClientIndex,
                base_task,
                sticky,
                wrapper_process_group,
                state: TerminalHarnessState {
                    binding: Some(TerminalRunBinding { job, run_token }),
                    phase: TerminalHarnessAvailability::Reserved,
                    replacement: None,
                    pending_exit_cause: None,
                    process_group: None,
                },
            },
        );
        self.broadcast_job_status(ws_index, job, crate::rpc::JobStatusKind::Scheduled);
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_empty(RpcMessageKind::TerminalAttached, 0);
        if !waiting.is_empty() {
            encoder.encode_push(
                RpcMessageKind::TerminalWaiting,
                &crate::rpc::TerminalWaitingEvent { tasks: waiting },
            );
        }
        if let Err(error) = self.queue_client_output(client_index as ClientIndex, encoder.output()) {
            kvlog::warn!("Failed to queue terminal attachment", harness_id, %error);
            self.terminate_client(client_index as ClientIndex, SocketTerminationReason::WriteError);
        }
    }

    fn start_terminal_job(
        &mut self,
        workspace_id: WorkspaceIndex,
        job_id: LogGroup,
        job_index: JobIndex,
        task: TaskConfigRc,
        harness_id: workspace::HarnessId,
        run_token: workspace::RunToken,
    ) -> anyhow::Result<()> {
        let binding = TerminalRunBinding { job: job_index, run_token };
        let client_index = {
            let harness = self.state.terminal_harnesses.get_mut(&harness_id).context("terminal wrapper disconnected")?;
            if harness.workspace != workspace_id {
                bail!("terminal wrapper belongs to another workspace");
            }
            if harness.state.replacement == Some(binding) {
                harness.state.binding = Some(binding);
                harness.state.replacement = None;
                harness.state.pending_exit_cause = None;
                harness.state.process_group = None;
            } else if harness.state.binding != Some(binding) {
                bail!("terminal wrapper reservation no longer matches scheduled job");
            }
            harness.client_index
        };
        let workspace = &self.state.workspaces[workspace_id as usize];
        let tc = task.config();
        let pwd = {
            let mut ws = workspace.handle.state.write().unwrap();
            match ws.jobs.get(job_index).map(|job| &job.process_status) {
                Some(JobStatus::Scheduled { .. }) => {
                    ws.update_job_status(job_index, JobStatus::Starting);
                }
                Some(JobStatus::Starting) => {}
                Some(JobStatus::Cancelled) => return Ok(()),
                _ => bail!("attempted terminal start for non-scheduled job"),
            }
            ws.config.current.base_path().join(tc.pwd)
        };
        let command = match &tc.command {
            Command::Cmd(args) => crate::rpc::TerminalCommand::Cmd(args.iter().map(|arg| (*arg).into()).collect()),
            Command::Sh { script, args } => crate::rpc::TerminalCommand::Sh {
                script: (*script).into(),
                args: args.iter().map(|arg| (*arg).into()).collect(),
            },
        };
        let event = crate::rpc::TerminalStartEvent {
            run_token,
            pwd: pwd.as_os_str().as_bytes().to_vec(),
            command,
            env: tc.envvar.iter().map(|(key, value)| ((*key).into(), (*value).into())).collect(),
        };
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_push(RpcMessageKind::TerminalStart, &event);
        self.queue_client_output(client_index, encoder.output())?;
        let harness = self.state.terminal_harnesses.get_mut(&harness_id).context("terminal wrapper disconnected")?;
        if harness.state.binding != Some(binding) {
            bail!("terminal wrapper reservation changed while queuing launch");
        }
        harness.state.phase = TerminalHarnessAvailability::Starting;
        if let Some(workspace) = self.state.workspaces.get_mut(workspace_id as usize) {
            const NOTE: &str = "output is attached to its terminal";
            workspace.line_writer.push_line(NOTE, NOTE.len() as u32, job_id, Style::default());
        }
        self.broadcast_job_status(workspace_id, job_index, crate::rpc::JobStatusKind::Starting);
        Ok(())
    }

    fn terminal_started(&mut self, harness_id: workspace::HarnessId, event: crate::rpc::TerminalRunEvent) {
        let Some(harness) = self.state.terminal_harnesses.get_mut(&harness_id) else { return };
        let Some(binding) = harness.state.binding else { return };
        if binding.run_token != event.run_token || harness.state.phase != TerminalHarnessAvailability::Starting {
            kvlog::warn!("Ignoring stale TerminalStarted", harness_id, run_token = event.run_token);
            return;
        }
        if event.process_group <= 0 {
            let client_index = harness.client_index;
            kvlog::warn!("Terminal harness reported invalid process group", harness_id, process_group = event.process_group);
            self.terminate_client(client_index, SocketTerminationReason::ProtocolError);
            return;
        }
        let job_index = binding.job;
        let ws_index = harness.workspace;
        let Some(workspace) = self.state.workspaces.get(ws_index as usize) else { return };
        let mut state = workspace.handle.state.write().unwrap();
        if !matches!(state.jobs.get(job_index).map(|job| &job.process_status), Some(JobStatus::Starting)) {
            return;
        }
        state.update_job_status(
            job_index,
            JobStatus::Running {
                owner: ProcessOwner::Terminal { harness_id, run_token: event.run_token },
                ready_state: None,
            },
        );
        harness.state.phase = TerminalHarnessAvailability::Running;
        harness.state.process_group = Some(event.process_group);
        drop(state);
        self.broadcast_job_status(ws_index, job_index, crate::rpc::JobStatusKind::Running);
        self.scheduled();
    }

    fn terminal_spawn_failed(
        &mut self,
        harness_id: workspace::HarnessId,
        event: crate::rpc::TerminalSpawnFailedEvent,
    ) {
        let Some(harness) = self.state.terminal_harnesses.get_mut(&harness_id) else { return };
        let Some(binding) = harness.state.binding else { return };
        if binding.run_token != event.run_token {
            kvlog::warn!("Ignoring stale TerminalSpawnFailed", harness_id, run_token = event.run_token);
            return;
        }
        kvlog::error!("Terminal child failed to spawn", harness_id, error = &*event.message);
        harness.state.binding = None;
        let job_index = binding.job;
        let ws_index = harness.workspace;
        harness.state.pending_exit_cause = None;
        harness.state.process_group = None;
        harness.state.phase = if harness.state.replacement.is_some() {
            TerminalHarnessAvailability::Reserved
        } else {
            TerminalHarnessAvailability::Idle
        };
        let Some(workspace) = self.state.workspaces.get(ws_index as usize) else { return };
        let public_id = workspace
            .handle
            .state
            .write()
            .unwrap()
            .update_job_status(
                job_index,
                JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::SpawnFailed, status: 127 },
            )
            .unwrap_or(0);
        self.broadcast_job_exited(ws_index, public_id, 127, crate::rpc::ExitCause::SpawnFailed);
        self.reconcile_idle_terminal_harnesses(ws_index);
        self.finish_terminal_run(harness_id);
        self.scheduled();
    }

    fn terminal_exited(&mut self, harness_id: workspace::HarnessId, event: crate::rpc::TerminalExitedEvent) {
        let Some(harness) = self.state.terminal_harnesses.get_mut(&harness_id) else { return };
        let Some(binding) = harness.state.binding else { return };
        if binding.run_token != event.run_token {
            kvlog::warn!("Ignoring stale TerminalExited", harness_id, run_token = event.run_token);
            return;
        }
        harness.state.binding = None;
        let job_index = binding.job;
        let ws_index = harness.workspace;
        let cause = harness.state.pending_exit_cause.take().unwrap_or(ExitCause::Unknown);
        harness.state.process_group = None;
        harness.state.phase = if harness.state.replacement.is_some() {
            TerminalHarnessAvailability::Reserved
        } else {
            TerminalHarnessAvailability::Idle
        };
        let status = event.exit_code.max(0) as u32;
        let Some(workspace) = self.state.workspaces.get(ws_index as usize) else { return };
        let public_id = workspace
            .handle
            .state
            .write()
            .unwrap()
            .update_job_status(
                job_index,
                JobStatus::Exited { finished_at: crate::clock::now(), cause, status },
            )
            .unwrap_or(0);
        self.broadcast_job_exited(ws_index, public_id, event.exit_code, Self::rpc_exit_cause(cause));
        self.reconcile_idle_terminal_harnesses(ws_index);
        self.finish_terminal_run(harness_id);
        self.scheduled();
    }

    fn finish_terminal_run(&mut self, harness_id: workspace::HarnessId) {
        let Some(harness) = self.state.terminal_harnesses.get(&harness_id) else { return };
        if harness.state.phase != TerminalHarnessAvailability::Idle
            || harness.sticky
            || harness.state.replacement.is_some()
        {
            return;
        }
        let client_index = harness.client_index;
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_empty(RpcMessageKind::TerminalDetached, 0);
        if let Err(error) = self.queue_client_output(client_index, encoder.output()) {
            kvlog::warn!("Failed to queue terminal detach", harness_id, %error);
            self.terminate_client(client_index, SocketTerminationReason::WriteError);
        }
    }

    /// Release a terminal job that was cancelled before its child started.
    /// Reservations can live in either `binding` (the initial run) or
    /// `replacement` (a restart waiting for the prior run and dependencies).
    fn cancel_terminal_reservation(
        &mut self,
        harness_id: workspace::HarnessId,
        run_token: workspace::RunToken,
        error_message: Option<String>,
    ) -> bool {
        let (workspace_id, client_index, sticky, wrapper_process_group, became_idle) = {
            let Some(harness) = self.state.terminal_harnesses.get_mut(&harness_id) else {
                return false;
            };

            let replacement_matches = harness
                .state
                .replacement
                .is_some_and(|binding| binding.run_token == run_token);
            let reserved_binding_matches = harness.state.phase == TerminalHarnessAvailability::Reserved
                && harness.state.binding.is_some_and(|binding| binding.run_token == run_token);
            if replacement_matches {
                harness.state.replacement = None;
            } else if reserved_binding_matches {
                harness.state.binding = None;
                harness.state.pending_exit_cause = None;
                harness.state.process_group = None;
            } else {
                return false;
            }

            let became_idle = harness.state.binding.is_none() && harness.state.replacement.is_none();
            if became_idle {
                harness.state.phase = TerminalHarnessAvailability::Idle;
            } else if harness.state.binding.is_none() {
                harness.state.phase = TerminalHarnessAvailability::Reserved;
            }
            (
                harness.workspace,
                harness.client_index,
                harness.sticky,
                harness.wrapper_process_group,
                became_idle,
            )
        };

        if became_idle {
            let mut encoder = crate::rpc::Encoder::new();
            if let Some(message) = error_message {
                encoder.encode_push(
                    RpcMessageKind::TerminalError,
                    &crate::rpc::TerminalErrorEvent { message: message.into() },
                );
                encoder.encode_empty(RpcMessageKind::TerminalDetached, 0);
            } else if !sticky {
                encoder.encode_empty(RpcMessageKind::TerminalDetached, 0);
            }
            if encoder.output().is_empty() {
                unsafe { libc::kill(-wrapper_process_group, libc::SIGCONT) };
            } else if let Err(error) =
                self.queue_client_output_and_wake(client_index, encoder.output(), wrapper_process_group)
            {
                kvlog::warn!("Failed to queue terminal cancellation", harness_id, %error);
                self.terminate_client(client_index, SocketTerminationReason::WriteError);
            }
        }
        self.reconcile_idle_terminal_harnesses(workspace_id);
        true
    }

    fn terminal_detach(&mut self, harness_id: workspace::HarnessId) {
        let Some(harness) = self.state.terminal_harnesses.get(&harness_id) else { return };
        match harness.state.phase {
            TerminalHarnessAvailability::Reserved | TerminalHarnessAvailability::Starting => {
                let client_index = harness.client_index;
                self.terminate_client(client_index, SocketTerminationReason::ClientRequestedTerminate);
                return;
            }
            TerminalHarnessAvailability::Idle => {}
            TerminalHarnessAvailability::Running | TerminalHarnessAvailability::Detaching => {
                kvlog::warn!("Terminal harness attempted detach while active", harness_id);
                return;
            }
        }
        let client_index = harness.client_index;
        let harness = self.state.terminal_harnesses.remove(&harness_id).expect("terminal harness disappeared");
        self.rebuild_idle_terminal_cache(harness.workspace);
        self.terminate_client(client_index, SocketTerminationReason::ClientRequestedTerminate);
    }

    /// Refresh the workspace generation and detach idle wrappers whose task no
    /// longer has the same kind and terminal execution mode. Active jobs keep
    /// their resolved generation and are intentionally left alone.
    fn reconcile_idle_terminal_harnesses(&mut self, ws_index: WorkspaceIndex) {
        let Some(workspace) = self.state.workspaces.get(ws_index as usize) else { return };
        workspace.handle.refresh_config_if_changed();
        let invalid: Vec<_> = {
            let state = workspace.handle.state();
            self.state
                .terminal_harnesses
                .iter()
                .filter_map(|(&id, harness)| {
                    if harness.workspace != ws_index
                        || !harness.sticky
                        || harness.state.phase != TerminalHarnessAvailability::Idle
                    {
                        return None;
                    }
                    let task = state.base_tasks.get(harness.base_task.idx());
                    let compatible = task.is_some_and(|task| {
                        !task.removed && task.config.managed == crate::config::ExecutionMode::Terminal
                    });
                    (!compatible).then(|| {
                        let name = task.map_or_else(|| "<removed>".into(), |task| task.name.clone());
                        (id, harness.client_index, harness.wrapper_process_group, name)
                    })
                })
                .collect()
        };
        for (harness_id, client_index, wrapper_process_group, task_name) in invalid {
            if let Some(harness) = self.state.terminal_harnesses.get_mut(&harness_id) {
                harness.state.phase = TerminalHarnessAvailability::Detaching;
            }
            let mut encoder = crate::rpc::Encoder::new();
            encoder.encode_push(
                RpcMessageKind::TerminalError,
                &crate::rpc::TerminalErrorEvent {
                    message: format!(
                        "Terminal wrapper for '{}' detached because the task was removed or is no longer terminal-managed",
                        task_name
                    )
                    .into(),
                },
            );
            encoder.encode_empty(RpcMessageKind::TerminalDetached, 0);
            if let Err(error) =
                self.queue_client_output_and_wake(client_index, encoder.output(), wrapper_process_group)
            {
                kvlog::warn!("Failed to queue incompatible terminal detach", harness_id, %error);
                self.terminate_client(client_index, SocketTerminationReason::WriteError);
            }
            kvlog::info!("Detaching incompatible idle terminal harness after config reload", harness_id);
        }
        self.rebuild_idle_terminal_cache(ws_index);
    }

    fn rebuild_idle_terminal_cache(&self, ws_index: WorkspaceIndex) {
        let Some(workspace) = self.state.workspaces.get(ws_index as usize) else { return };
        let mut state = workspace.handle.state.write().unwrap();
        for task in &mut state.base_tasks {
            task.idle_terminal_harnesses = 0;
        }
        for harness in self.state.terminal_harnesses.values() {
            if harness.workspace != ws_index
                || !harness.sticky
                || harness.state.phase != TerminalHarnessAvailability::Idle
            {
                continue;
            }
            let Some(task) = state.base_tasks.get_mut(harness.base_task.idx()) else { continue };
            if !task.removed && task.config.managed == crate::config::ExecutionMode::Terminal {
                task.idle_terminal_harnesses += 1;
            }
        }
    }

    fn terminal_control_rpc(
        &mut self,
        ws_index: WorkspaceIndex,
        kind: RpcMessageKind,
        payload: &[u8],
    ) -> Option<CommandBody> {
        if !matches!(kind, RpcMessageKind::StartTask | RpcMessageKind::RestartTask) {
            return None;
        }
        let req = match jsony::from_binary::<crate::rpc::SpawnTaskRequest>(payload) {
            Ok(req) => req,
            Err(_) => return Some(CommandBody::Error("Invalid request payload".into())),
        };
        let params = jsony::from_binary::<ValueMap>(req.params).unwrap_or_else(|_| ValueMap::new()).to_owned();
        let workspace = &self.state.workspaces[ws_index as usize];
        workspace.handle.refresh_config_if_changed();
        let (base_task, profile, already_active, active_owner) = {
            let state = workspace.handle.state.write().unwrap();
            let Some(base_task) = state.lookup_name(req.task_name) else {
                return None;
            };
            if state.base_tasks[base_task.idx()].config.managed != crate::config::ExecutionMode::Terminal {
                return None;
            }
            if req.as_test || req.cached {
                return Some(CommandBody::Error(
                    "terminal tasks do not support --as-test or cached start/restart".into(),
                ));
            }
            let profile = if req.profile.is_empty() {
                state.base_tasks[base_task.idx()].config.profiles.first().copied().unwrap_or("").to_string()
            } else {
                req.profile.to_string()
            };
            let mut already_active = false;
            let mut active_owner = None;
            for &job_index in state.base_tasks[base_task.idx()].jobs.non_terminal().iter().rev() {
                let job = &state.jobs[job_index];
                if job.spawn_profile() != profile || job.spawn_params() != &params {
                    continue;
                }
                already_active = true;
                match (&job.process_status, job.execution_target) {
                    (JobStatus::Running { owner: owner @ ProcessOwner::Terminal { .. }, .. }, _) => {
                        active_owner = Some((job_index, *owner));
                    }
                    (
                        JobStatus::Scheduled { .. } | JobStatus::Starting,
                        workspace::ExecutionTarget::Terminal { harness_id, run_token },
                    ) => {
                        active_owner = Some((job_index, ProcessOwner::Terminal { harness_id, run_token }));
                    }
                    _ => {}
                }
                break;
            }
            (base_task, profile, already_active, active_owner)
        };

        if kind == RpcMessageKind::StartTask && already_active {
            return Some(CommandBody::Message(format!("Task '{}' is already active", req.task_name).into()));
        }

        let (harness_id, replacing) = if kind == RpcMessageKind::RestartTask {
            let Some((_, ProcessOwner::Terminal { harness_id, .. })) = active_owner else {
                return Some(CommandBody::Error(
                    format!(
                        "Cannot restart terminal task '{}': no compatible running terminal wrapper exists.\n\
                         Start it with: devsm run {}",
                        req.task_name, req.task_name
                    )
                    .into(),
                ));
            };
            (harness_id, true)
        } else {
            let candidate = self
                .state
                .terminal_harnesses
                .iter()
                .filter(|(_, harness)| {
                    harness.workspace == ws_index
                        && harness.base_task == base_task
                        && harness.sticky
                        && harness.state.phase == TerminalHarnessAvailability::Idle
                })
                .map(|(id, _)| *id)
                .min();
            let Some(harness_id) = candidate else {
                return Some(CommandBody::Error(
                    format!(
                        "Cannot start terminal task '{}': no compatible idle sticky wrapper exists.\n\
                         Attach one with: devsm run --sticky {}",
                        req.task_name, req.task_name
                    )
                    .into(),
                ));
            };
            (harness_id, false)
        };

        let run_token = self.state.next_run_token;
        self.state.next_run_token = self.state.next_run_token.wrapping_add(1).max(1);
        if replacing
            && self
                .state
                .terminal_harnesses
                .get(&harness_id)
                .is_some_and(|harness| harness.state.replacement.is_some())
        {
            return Some(CommandBody::Error(
                format!("Cannot restart terminal task '{}': a replacement is already pending", req.task_name).into(),
            ));
        }
        let result = workspace
            .handle
            .submit_terminal(req.task_name, &profile, params, harness_id, run_token, replacing);
        let result = match result {
            Ok(result) => result,
            Err(error) => return Some(CommandBody::Error(error.into())),
        };
        let Some((_, job_index)) = result.jobs.first().copied() else {
            return Some(CommandBody::Error("No terminal job was created".into()));
        };
        if let Some(harness) = self.state.terminal_harnesses.get_mut(&harness_id) {
            let binding = TerminalRunBinding { job: job_index, run_token };
            if replacing {
                harness.state.replacement = Some(binding);
            } else {
                harness.state.binding = Some(binding);
                harness.state.phase = TerminalHarnessAvailability::Reserved;
                harness.state.pending_exit_cause = None;
                harness.state.process_group = None;
            }
        }
        self.rebuild_idle_terminal_cache(ws_index);
        self.broadcast_job_status(ws_index, job_index, crate::rpc::JobStatusKind::Scheduled);
        Some(CommandBody::Empty)
    }

    fn send_exec_message(socket: &UnixStream, encoder: &crate::rpc::Encoder) {
        let mut s = socket;
        let _ = std::io::Write::write_all(&mut s, encoder.output());
    }

    fn send_exec_proceed(socket: &UnixStream) {
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_empty(RpcMessageKind::ExecProceed, 0);
        Self::send_exec_message(socket, &encoder);
    }

    fn send_exec_waiting(socket: &UnixStream, tasks: Vec<String>) {
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_push(RpcMessageKind::ExecWaiting, &crate::rpc::ExecWaitingEvent { tasks });
        Self::send_exec_message(socket, &encoder);
    }

    fn rpc_exit_cause(cause: ExitCause) -> crate::rpc::ExitCause {
        match cause {
            ExitCause::Unknown => crate::rpc::ExitCause::Unknown,
            ExitCause::Killed => crate::rpc::ExitCause::Killed,
            ExitCause::Restarted => crate::rpc::ExitCause::Restarted,
            ExitCause::SpawnFailed => crate::rpc::ExitCause::SpawnFailed,
            ExitCause::ProfileConflict => crate::rpc::ExitCause::ProfileConflict,
            ExitCause::Timeout => crate::rpc::ExitCause::Timeout,
        }
    }

    fn exec_dependency_failure_event(failure: &workspace::DependencyFailure) -> crate::rpc::ExecDependencyFailureEvent {
        crate::rpc::ExecDependencyFailureEvent {
            task_name: failure.task_name.clone(),
            job_index: failure.job_index,
            predicate: failure.predicate.name().to_string(),
            reason: failure.reason.clone(),
            exit_code: failure.exit_code,
            cause: failure.cause.map(Self::rpc_exit_cause),
            terminal: failure.terminal,
            suggested_invocation: failure.suggested_invocation.clone(),
        }
    }

    fn exec_dependency_failure_message(failure: &workspace::DependencyFailure) -> String {
        let job = failure.job_index.map(|id| format!(" (job #{id})")).unwrap_or_default();
        let mut message =
            format!("required dependency '{}'{} could not be satisfied: {}", failure.task_name, job, failure.reason);
        if let Some(command) = &failure.suggested_invocation {
            message.push_str("\n\nStart it in another terminal, then retry:\n    ");
            message.push_str(command);
        }
        message
    }

    fn exec_error_event_for_job(
        state: &WorkspaceState,
        job_index: JobIndex,
        fallback: &'static str,
    ) -> crate::rpc::ExecErrorEvent {
        if let Some(failure) = state
            .jobs
            .get(job_index)
            .and_then(|job| job.dependency_failure.clone())
            .or_else(|| state.dependency_failure(job_index))
        {
            return crate::rpc::ExecErrorEvent {
                message: Self::exec_dependency_failure_message(&failure),
                failed_dependency: Some(Self::exec_dependency_failure_event(&failure)),
            };
        }

        crate::rpc::ExecErrorEvent { message: fallback.to_string(), failed_dependency: None }
    }

    fn send_exec_error(socket: &UnixStream, event: &crate::rpc::ExecErrorEvent) {
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_push(RpcMessageKind::ExecError, event);
        Self::send_exec_message(socket, &encoder);
    }

    fn send_exec_error_message(socket: &UnixStream, message: &str) {
        Self::send_exec_error(
            socket,
            &crate::rpc::ExecErrorEvent { message: message.to_string(), failed_dependency: None },
        );
    }

    /// Reconcile pending exec gates against current job state. Run every loop
    /// iteration (cheap when there are none): a remote job that has reached a
    /// terminal/active state releases its client; one blocked past the warning
    /// threshold gets a one-time "waiting on …" notice.
    fn poll_remote_execs(&mut self) {
        if self.state.remote_execs.is_empty() {
            return;
        }
        const WARN_AFTER: std::time::Duration = std::time::Duration::from_millis(500);
        let now = crate::clock::now();
        let mut settled: Vec<(WorkspaceIndex, JobIndex)> = Vec::new();
        let mut running_broadcasts: Vec<(WorkspaceIndex, JobIndex)> = Vec::new();
        let mut wake_scheduler = false;

        for (&(ws_index, job_index), remote) in &mut self.state.remote_execs {
            let Some(workspace) = self.state.workspaces.get(ws_index as usize) else {
                settled.push((ws_index, job_index));
                continue;
            };
            let Some(client) = self.clients.get(remote.client_index as usize) else {
                settled.push((ws_index, job_index));
                continue;
            };
            let socket = &client.socket;

            enum Outcome {
                Pending(Vec<String>),
                Proceed,
                Failed(crate::rpc::ExecErrorEvent),
                Running,
            }
            let outcome = {
                let state = workspace.handle.state.read().unwrap();
                match state.jobs.get(job_index).map(|job| &job.process_status) {
                    None | Some(JobStatus::Cancelled) => Outcome::Failed(Self::exec_error_event_for_job(
                        &state,
                        job_index,
                        "a required dependency could not be satisfied",
                    )),
                    Some(JobStatus::Starting) if remote.proceeded => Outcome::Running,
                    Some(JobStatus::Starting) => Outcome::Proceed,
                    Some(JobStatus::RemoteRunning { .. }) if remote.proceeded => Outcome::Running,
                    Some(JobStatus::RemoteRunning { .. }) => Outcome::Proceed,
                    Some(JobStatus::Exited { status: 0, .. }) if remote.proceeded => Outcome::Running,
                    Some(JobStatus::Exited { status: 0, .. }) => Outcome::Proceed,
                    Some(JobStatus::Exited { .. }) => Outcome::Failed(Self::exec_error_event_for_job(
                        &state,
                        job_index,
                        "a required dependency could not be satisfied",
                    )),
                    // A remote job is gated before it can spawn, so it should
                    // never actually run; treat that defensively as "go ahead".
                    Some(JobStatus::Running { .. }) if remote.proceeded => Outcome::Running,
                    Some(JobStatus::Running { .. }) => Outcome::Proceed,
                    Some(JobStatus::Scheduled { .. }) => Outcome::Pending(state.pending_dep_names(job_index)),
                }
            };

            match outcome {
                Outcome::Pending(names) => {
                    if !remote.warned && now.duration_since(remote.submitted_at) >= WARN_AFTER {
                        remote.warned = true;
                        Self::send_exec_waiting(socket, names);
                    }
                }
                Outcome::Proceed => {
                    Self::send_exec_proceed(socket);
                    remote.proceeded = true;
                    let marked_running = {
                        let mut state = workspace.handle.state.write().unwrap();
                        let ready_state = match state.jobs.get(job_index) {
                            Some(job) if matches!(job.process_status, JobStatus::Starting) => {
                                job.task().config().ready.as_ref().map(|_| false)
                            }
                            _ => continue,
                        };
                        state.update_job_status(job_index, JobStatus::RemoteRunning { ready_state });
                        true
                    };
                    if marked_running {
                        running_broadcasts.push((ws_index, job_index));
                        wake_scheduler = true;
                    }
                }
                Outcome::Failed(event) => {
                    Self::send_exec_error(socket, &event);
                    settled.push((ws_index, job_index));
                }
                Outcome::Running => {}
            }
        }

        for key in settled {
            self.state.remote_execs.remove(&key);
        }
        for (ws_index, job_index) in running_broadcasts {
            self.broadcast_job_status(ws_index, job_index, crate::rpc::JobStatusKind::Running);
        }
        if wake_scheduler {
            self.state.request.wake();
        }
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
                v.push(crate::cli::TestFilter::ExcludeTag(std::borrow::Cow::Borrowed(*tag)));
            }
            for tag in &filters.include_tags {
                v.push(crate::cli::TestFilter::IncludeTag(std::borrow::Cow::Borrowed(*tag)));
            }
            for name in &filters.include_names {
                v.push(crate::cli::TestFilter::IncludeName(std::borrow::Cow::Borrowed(*name)));
            }
            v
        };

        let ws = &self.state.workspaces[ws_index as usize];
        let test_run = match ws.handle.start_test_run(&test_filters, filters.force) {
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
            let result = std::panic::catch_unwind(func);
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
        let terminal_harness = match self.clients.get(client_index as usize).map(|client| &client.kind) {
            Some(ClientKind::TerminalHarness { harness_id }) => Some(*harness_id),
            _ => None,
        };
        if let Some(harness_id) = terminal_harness {
            let Some(client) = self.clients.try_remove(client_index as usize) else { return };
            let _ = self.state.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
            client.channel.set_terminated();
            let harness = self.state.terminal_harnesses.remove(&harness_id);
            if let Some(harness) = harness {
                if reason != SocketTerminationReason::ClientRequestedTerminate
                    && let Some(process_group) = harness.state.process_group
                {
                    // Wrapper authority is gone. Kill the reported child group
                    // before releasing scheduler resources or publishing exit.
                    unsafe { libc::kill(-process_group, libc::SIGKILL) };
                }
                let bindings = [harness.state.binding, harness.state.replacement];
                for binding in bindings.into_iter().flatten() {
                    let Some(workspace) = self.state.workspaces.get(harness.workspace as usize) else { continue };
                    let transition = {
                    let mut state = workspace.handle.state.write().unwrap();
                    match state.jobs.get(binding.job).map(|job| &job.process_status) {
                        Some(JobStatus::Scheduled { .. }) => {
                            state.update_job_status(binding.job, JobStatus::Cancelled);
                            None
                        }
                        Some(JobStatus::Starting) => state
                            .update_job_status(
                                binding.job,
                                JobStatus::Exited {
                                    finished_at: crate::clock::now(),
                                    cause: ExitCause::SpawnFailed,
                                    status: 127,
                                },
                            )
                            .map(|id| (id, 127)),
                        Some(JobStatus::Running {
                            owner: ProcessOwner::Terminal { harness_id: owner_id, run_token },
                            ..
                        }) if *owner_id == harness_id && *run_token == binding.run_token => state
                            .update_job_status(
                                binding.job,
                                JobStatus::Exited {
                                    finished_at: crate::clock::now(),
                                    cause: ExitCause::SpawnFailed,
                                    status: 1,
                                },
                            )
                            .map(|id| (id, 1)),
                        _ => None,
                    }
                    };
                    if let Some((public_id, status)) = transition {
                        self.broadcast_job_exited(
                            harness.workspace,
                            public_id,
                            status,
                            crate::rpc::ExitCause::SpawnFailed,
                        );
                    }
                }
                self.rebuild_idle_terminal_cache(harness.workspace);
            }
            kvlog::info!("Terminal harness disconnected", harness_id, reason = reason.as_str());
            self.scheduled();
            return;
        }
        let Some(client) = self.clients.get(client_index as usize) else {
            return;
        };
        client.channel.set_terminated();
        let _ = client.channel.wake();
        let _ = self.state.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
        kvlog::info!("Client terminated", index = client_index as usize, reason = reason.as_str());
        if let ClientKind::Exec { job } = &client.kind {
            let (ws_index, job_index) = (client.workspace, *job);
            self.finish_or_cancel_remote_exec(ws_index, job_index);
            let _ = self.clients.try_remove(client_index as usize);
            return;
        }
        if let ClientKind::Rpc { .. } = &client.kind {
            let Some(_) = self.clients.try_remove(client_index as usize) else {
                kvlog::debug!("Client already removed", index = client_index as usize);
                return;
            };
        }
    }

    /// Drop an exec gate. If the client went away before `ExecProceed`, cancel
    /// the still-scheduled job. If the client already exec'd, socket EOF marks
    /// the remote job complete and releases the requirements it held active.
    fn finish_or_cancel_remote_exec(&mut self, ws_index: WorkspaceIndex, job_index: JobIndex) {
        let Some(remote) = self.state.remote_execs.remove(&(ws_index, job_index)) else {
            return;
        };
        let Some(workspace) = self.state.workspaces.get(ws_index as usize) else {
            return;
        };
        let public_id = {
            let mut ws = workspace.handle.state.write().unwrap();
            match ws.jobs.get(job_index).map(|j| &j.process_status) {
                Some(JobStatus::Scheduled { .. }) => {
                    ws.update_job_status(job_index, JobStatus::Cancelled);
                    None
                }
                Some(JobStatus::Starting) if remote.proceeded => ws.update_job_status(
                    job_index,
                    JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status: 0 },
                ),
                Some(JobStatus::Starting) => {
                    ws.update_job_status(job_index, JobStatus::Cancelled);
                    None
                }
                Some(JobStatus::RemoteRunning { .. }) if remote.proceeded => ws.update_job_status(
                    job_index,
                    JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status: 0 },
                ),
                // `RemoteRunning` is only reachable after `poll_remote_execs` has
                // set `proceeded` in the same loop iteration that started it, so
                // the socket cannot close in the `!proceeded` window. If the loop
                // ordering ever changes, leaving the job `RemoteRunning` here
                // would pin its resources and service dependents forever.
                Some(status @ JobStatus::RemoteRunning { .. }) => {
                    kvlog::error!(
                        "Exec socket closed on un-proceeded RemoteRunning job; resources may leak",
                        ws_index,
                        job_index,
                        status = status.name()
                    );
                    None
                }
                _ => None,
            }
        };
        if let Some(public_id) = public_id {
            self.broadcast_job_exited(ws_index, public_id, 0, crate::rpc::ExitCause::Unknown);
        }
        self.scheduled();
    }

    fn client_exited(&mut self, client_index: ClientIndex) {
        let Some(mut client) = self.clients.try_remove(client_index as usize) else {
            kvlog::debug!("Client already removed", index = client_index as usize);
            return;
        };
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_empty(RpcMessageKind::Disconnect, 0);
        let _ = client.socket.write_all(encoder.output());
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
        let Some(ws) = self.state.workspaces.get(ws_index as usize) else { return };
        let public_id = ws.handle.state.read().unwrap().jobs.public_id_of(job_index).unwrap_or(0);
        let event = crate::rpc::JobStatusEvent { job_index: public_id, status };
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
        public_id: u32,
        exit_code: i32,
        cause: crate::rpc::ExitCause,
    ) {
        let event = crate::rpc::JobExitedEvent { job_index: public_id, exit_code, cause };
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

    fn broadcast_debug_trace(&mut self, ws_index: WorkspaceIndex, tag: &str, job_index: JobIndex) {
        if !crate::clock::is_fuzz() {
            return;
        }
        let Some(ws) = self.state.workspaces.get(ws_index as usize) else { return };
        let public_id = ws.handle.state.read().unwrap().jobs.public_id_of(job_index).unwrap_or(0);
        let event = crate::rpc::DebugTraceEvent { tag, job_index: public_id };
        let mut encoder = crate::rpc::Encoder::new();
        encoder.encode_push(RpcMessageKind::DebugTrace, &event);
        let output = encoder.output();

        for (_, client) in &mut self.clients {
            if client.workspace != ws_index {
                continue;
            }
            let ClientKind::Rpc { .. } = &client.kind else { continue };
            let _ = client.socket.write_all(output);
        }
    }
}

pub(crate) fn process_worker(request: Arc<MioChannel>, poll: Poll) {
    let mut events = Events::with_capacity(128);
    let db = crate::db::Db::open();
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
            remote_execs: HashMap::new(),
            terminal_harnesses: HashMap::new(),
            next_harness_id: 1,
            next_run_token: 1,
            db,
            #[cfg(target_os = "linux")]
            traced_root_pids: HashMap::new(),
        },
    };
    loop {
        if TERMINATED.load(std::sync::atomic::Ordering::Relaxed) {
            job_manager.handle_request(ProcessRequest::GlobalTermination);
            return;
        }

        let has_waiting_remote_exec = job_manager.state.remote_execs.values().any(|remote| !remote.proceeded);
        let has_timed = job_manager.state.timed_ready_count > 0
            || job_manager.state.timed_timeout_count > 0
            || has_waiting_remote_exec;
        let poll_timeout = if crate::clock::is_fuzz() {
            crate::clock::set_wake_needed(has_timed);
            None
        } else if has_timed {
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

        if CHILD_EXITED.swap(false, std::sync::atomic::Ordering::Relaxed) {
            job_manager.reap_children();
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
                    if event.is_writable()
                        && let Err(error) = job_manager.flush_client_output(index)
                    {
                        kvlog::warn!("Client socket write failed", index, %error);
                        job_manager.terminate_client(index, SocketTerminationReason::WriteError);
                        continue;
                    }
                    if event.is_readable() && job_manager.clients.contains(index as usize) {
                        job_manager.handle_client_rpc_read(index);
                    }
                }
            }
        }

        job_manager.scheduled();
        job_manager.poll_remote_execs();
        if job_manager.state.timed_ready_count > 0 {
            job_manager.check_ready_timeouts();
        }
        if job_manager.state.timed_timeout_count > 0 {
            job_manager.check_timeouts();
        }
        job_manager.check_kill_escalation();

        if crate::clock::is_fuzz() {
            for ws_idx in 0..job_manager.state.workspaces.len() {
                job_manager.broadcast_debug_trace(ws_idx as WorkspaceIndex, "tick", JobIndex::from_usize(0));
            }
        }

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

static TERMINATED: AtomicBool = AtomicBool::new(false);
static CHILD_EXITED: AtomicBool = AtomicBool::new(false);

extern "C" fn term_handler(_sig: i32) {
    TERMINATED.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(waker) = GLOBAL_WAKER.get() {
        let _ = waker.wake();
    }
}

extern "C" fn sigchld_handler(_sig: i32) {
    CHILD_EXITED.store(true, std::sync::atomic::Ordering::Relaxed);
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

pub(crate) static GLOBAL_WAKER: std::sync::OnceLock<&'static Waker> = std::sync::OnceLock::new();
static GLOBAL_KEYBINDS: std::sync::OnceLock<Mutex<Arc<crate::keybinds::Keybinds>>> = std::sync::OnceLock::new();
static GLOBAL_CLIPBOARD_CONFIG: std::sync::OnceLock<Mutex<Arc<crate::clipboard::ClipboardConfig>>> =
    std::sync::OnceLock::new();
static GLOBAL_USER_CONFIG_LOADED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub(crate) fn global_keybinds() -> Arc<crate::keybinds::Keybinds> {
    GLOBAL_KEYBINDS
        .get_or_init(|| {
            let config = crate::user_config::UserConfig::load();
            GLOBAL_USER_CONFIG_LOADED.get_or_init(|| config.loaded_from_file);
            crate::user_config::set_global_max_job_history(config.max_job_history);
            GLOBAL_CLIPBOARD_CONFIG.get_or_init(|| Mutex::new(Arc::new(config.clipboard.clone())));
            Mutex::new(Arc::new(config.keybinds))
        })
        .lock()
        .unwrap()
        .clone()
}

pub(crate) fn global_clipboard_config() -> Arc<crate::clipboard::ClipboardConfig> {
    let _ = global_keybinds();
    GLOBAL_CLIPBOARD_CONFIG
        .get_or_init(|| Mutex::new(Arc::new(crate::clipboard::ClipboardConfig::default())))
        .lock()
        .unwrap()
        .clone()
}

pub(crate) fn update_global_keybinds(keybinds: crate::keybinds::Keybinds) {
    if let Some(mutex) = GLOBAL_KEYBINDS.get() {
        *mutex.lock().unwrap() = Arc::new(keybinds);
    }
}

pub(crate) fn update_global_clipboard_config(config: crate::clipboard::ClipboardConfig) {
    if let Some(mutex) = GLOBAL_CLIPBOARD_CONFIG.get() {
        *mutex.lock().unwrap() = Arc::new(config);
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
        setup_signal_handler(libc::SIGCHLD, sigchld_handler)?;
        let poll = Poll::new()?;
        let waker = Box::leak(Box::new(Waker::new(poll.registry(), CHANNEL_TOKEN)?));
        if GLOBAL_WAKER.set(waker).is_err() {
            bail!("Global Waker already initialized");
        }
        let request = Arc::new(MioChannel { waker, events: Mutex::new(Vec::new()) });
        let r = request.clone();

        let handle = ProcessManagerHandle { request };

        std::thread::Builder::new()
            .name("RPC-forwarder".into())
            .spawn(move || {
                func(handle);
            })
            .unwrap();
        process_worker(r, poll);
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
            for (ts, level, span, fields) in kvlog::encoding::decode(&logs).flatten() {
                kvlog::collector::format_statement_with_colors(&mut fmt_buf, &mut parents, ts, level, span, fields);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn untracked_child_guard_kills_and_reaps_child_on_drop() {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("trap '' TERM; sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command.process_group(0);

        let child = command.spawn().expect("spawn child");
        let pid = child.id() as i32;
        drop(UntrackedChildGuard::new(child));

        let still_alive = unsafe { libc::kill(pid, 0) == 0 };
        assert!(!still_alive, "untracked child process should have been killed and reaped");
    }

    #[test]
    fn outbound_writer_preserves_partial_progress_across_would_block() {
        let payload = b"abcdef";
        let mut offset = 0;
        let mut calls = 0;
        let drained = drain_outbound_with(payload, &mut offset, |bytes| {
            calls += 1;
            match calls {
                1 => {
                    assert_eq!(bytes, b"abcdef");
                    Ok(2)
                }
                2 => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                _ => unreachable!(),
            }
        })
        .unwrap();
        assert!(!drained);
        assert_eq!(offset, 2);

        let drained = drain_outbound_with(payload, &mut offset, |bytes| {
            assert_eq!(bytes, b"cdef");
            Ok(bytes.len())
        })
        .unwrap();
        assert!(drained);
        assert_eq!(offset, payload.len());
    }

    #[test]
    fn outbound_frame_validation_rejects_oversized_payloads() {
        let head = crate::rpc::Head {
            magic: crate::rpc::MAGIC,
            kind: RpcMessageKind::TerminalStart as u16,
            one_shot: false,
            correlation: 0,
            ws_len: 0,
            len: (crate::rpc::DEFAULT_MAX_PAYLOAD + 1) as u32,
        };
        assert!(EventLoop::validate_outbound_frames(&head.as_bytes()).is_err());
    }
}
