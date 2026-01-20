use crate::rpc::{DecodeResult, DecodingState, RpcMessageKind};
use crate::workspace::{self, ExitCause, JobIndex, JobStatus, Workspace, WorkspaceState};
use crate::{
    config::{Command, TaskConfigRc},
    daemon::WorkspaceCommand,
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
use std::{
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
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

type WorkspaceIndex = u32;
/// Tracks ready condition checking for a service process.
pub(crate) struct ReadyChecker {
    /// String to search for in output (ANSI stripped).
    pub(crate) needle: String,
    /// When to timeout if ready condition not met.
    pub(crate) timeout_at: Option<std::time::Instant>,
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

pub(crate) struct ProcessManager {
    clients: Slab<ClientEntry>,
    workspaces: slab::Slab<WorkspaceEntry>,
    workspace_map: HashMap<Box<Path>, WorkspaceIndex>,
    processes: slab::Slab<ActiveProcess>,
    buffer_pool: Vec<Vec<u8>>,
    wait_thread: std::thread::JoinHandle<()>,
    request: Arc<MioChannel>,
    poll: Poll,
    timed_ready_count: u32,
}

pub(crate) enum ReadResult {
    Done,
    More,
    EOF,
    WouldBlock,
    OtherError(std::io::ErrorKind),
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
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return ReadResult::OtherError(err.kind());
            }
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return ReadResult::WouldBlock;
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

impl ProcessManager {
    pub(crate) fn read(&mut self, index: ProcessIndex, pipe: Pipe) -> anyhow::Result<()> {
        kvlog::info!("Read");
        let process = self.processes.get_mut(index).context("Invalid process index")?;
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
                    .stdout_buffer
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
                    if let Err(err) = self.poll.registry().deregister(&mut SourceFd(&fd)) {
                        kvlog::error!("Failed to unregister fd", ?err);
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
                    kvlog::info!("EOF");
                    expecting_more = false;
                    break;
                }
                ReadResult::OtherError(err) => {
                    kvlog::error!("Read failed with unexpected error", ?err, ?pipe);
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

                if let Some(workspace) = self.workspaces.get_mut(process.workspace_index as usize) {
                    workspace.line_writer.push_line(text, width as u32, process.log_group, process.style);
                }

                if let Some(ref checker) = process.ready_checker {
                    if crate::line_width::strip_ansi_and_contains(text, &checker.needle) {
                        if checker.timeout_at.is_some() {
                            self.timed_ready_count -= 1;
                        }
                        ready_matched = true;
                        process.ready_checker = None;
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
        'outer: loop {
            for (wsi, ws) in &self.workspaces {
                let state = ws.handle.state();
                match state.next_scheduled() {
                    workspace::Scheduled::Ready(job_index) => {
                        kvlog::info!("Scheduled task is ready");
                        let job = &state.jobs[job_index.idx()];
                        let job_correlation = job.log_group;
                        let job_task = job.task.clone();
                        drop(state);
                        let _ = self.spawn(wsi as WorkspaceIndex, job_correlation, job_index, job_task);
                        continue 'outer;
                    }
                    workspace::Scheduled::Never(job_index) => {
                        kvlog::info!("Scheduled task is never");
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
        if let Some(ws) = self.workspaces.get(ws_index as usize) {
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
        for (_, process) in &mut self.processes {
            if let Some(ref checker) = process.ready_checker {
                if checker.timeout_at.is_some_and(|t| now > t) {
                    self.timed_ready_count -= 1;
                    process.ready_checker = None;
                }
            }
        }
    }

    pub(crate) fn spawn(
        &mut self,
        workspace_index: WorkspaceIndex,
        job_id: LogGroup,
        job_index: JobIndex,
        task: TaskConfigRc,
    ) -> anyhow::Result<()> {
        let index = self.processes.vacant_key();
        let tc = task.config();
        let workspace = &self.workspaces[workspace_index as usize];
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
        unsafe {
            command.pre_exec(|| {
                // Create process group to allow nested cleanup
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

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
            self.poll.registry().register(&mut SourceFd(&stdout.as_raw_fd()), Token(index << 1), Interest::READABLE)?;
        };
        if let Some(stderr) = &mut child.stderr {
            unsafe {
                if libc::fcntl(stderr.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == -1 {
                    panic!("Failed to set non-blocking");
                }
            }
            self.poll.registry().register(
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
            self.timed_ready_count += 1;
        }
        let ready_state = ready_checker.as_ref().map(|_| false);
        let process_index = self.processes.insert(ActiveProcess {
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
    Run { task_name: Box<str>, params: Vec<u8> },
    TestRun { filters: Vec<u8> },
    Rpc { subscribe: bool },
}

pub(crate) enum ProcessRequest {
    WorkspaceCommand {
        workspace_config: PathBuf,
        socket: UnixStream,
        command: Vec<u8>,
    },
    Spawn {
        task: TaskConfigRc,
        workspace_id: WorkspaceIndex,
        job_id: LogGroup,
        job_index: JobIndex,
    },
    AttachClient {
        stdin: Option<OwnedFd>,
        stdout: Option<OwnedFd>,
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
    GlobalTermination,
}

/// Channel for communicating with a client thread (TUI or forwarder).
///
/// For TUI clients, all fields are used. For forwarder clients, only `waker`
/// and `state` are used; `selected` and `events` are ignored.
pub struct ClientChannel {
    pub waker: extui::event::polling::Waker,
    /// Encodes termination flag (high bits > u32::MAX) and resize counter (low bits).
    pub state: AtomicU64,
    /// Tracks selected base task index. Only used by TUI clients.
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

impl ProcessManager {
    fn workspace_index(&mut self, workspace_config: PathBuf) -> anyhow::Result<WorkspaceIndex> {
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
    fn handle_workspace_command(&mut self, ws_index: u32, cmd: &[u8], mut socket: UnixStream) {
        match jsony::from_binary::<WorkspaceCommand>(cmd).unwrap() {
            WorkspaceCommand::RestartSelected => {
                let ws = &self.workspaces[ws_index as usize];
                for (_, client) in &self.clients {
                    if client.workspace != ws_index {
                        continue;
                    }
                    let base_index = client.channel.selected.load(std::sync::atomic::Ordering::Relaxed);
                    let bti = workspace::BaseTaskIndex(base_index as u32);
                    let ws_state = ws.handle.state();
                    if let Some(bt) = ws_state.base_tasks.get(bti.idx()) {
                        if let Some(&last_ji) = bt.jobs.all().last() {
                            let job = &ws_state[last_ji];
                            let params = job.spawn_params.clone();
                            let profile = job.spawn_profile.clone();
                            drop(ws_state);
                            ws.handle.restart_task(bti, params, &profile);
                        } else {
                            drop(ws_state);
                            ws.handle.restart_task(bti, ValueMap::new(), "");
                        }
                    }
                }
            }
            WorkspaceCommand::GetPanicLocation => {
                let response = jsony::to_json(&self.workspaces[ws_index as usize].handle.last_rust_panic());
                let _ = socket.write_all(response.as_bytes());
            }
            WorkspaceCommand::Run { name, params } => {
                let ws = &self.workspaces[ws_index as usize];
                let mut state = ws.handle.state.write().unwrap();
                let (name, profile) = name.rsplit_once(":").unwrap_or((&*name, ""));
                if let Some(index) = state.base_index_by_name(name) {
                    drop(state);
                    ws.handle.restart_task(index, params, profile);
                }
            }
        }
    }
    fn handle_request(&mut self, req: ProcessRequest) -> bool {
        match req {
            ProcessRequest::WorkspaceCommand { workspace_config, mut socket, command } => {
                let ws_index = match self.workspace_index(workspace_config) {
                    Ok(ws) => ws,
                    Err(err) => {
                        kvlog::info!("Error spawning workspace", %err);
                        if let Some(config_err) = err.downcast_ref::<crate::config::ConfigError>() {
                            let _ = socket.write_all(config_err.message.as_bytes());
                        } else {
                            let _ = socket.write_all(format!("error: {}\n", err).as_bytes());
                        }
                        return false;
                    }
                };
                self.handle_workspace_command(ws_index, &command, socket);
                false
            }
            ProcessRequest::TerminateJob { job_id, process_index, exit_cause } => {
                let Some(process) = self.processes.get_mut(process_index) else {
                    return false;
                };
                if process.log_group != job_id {
                    kvlog::error!(
                        "Mismatched job id for termination",
                        ?job_id,
                        expected = ?process.log_group
                    );
                    return false;
                }
                process.pending_exit_cause = Some(exit_cause);
                let child_pid = process.child.id();
                let pgid_to_kill = -(child_pid as i32);

                unsafe {
                    if libc::kill(pgid_to_kill, libc::SIGINT) == -1 {
                        let err = std::io::Error::last_os_error();
                        kvlog::error!("Failed to send SIGTERM", ?err, ?child_pid);
                    }
                }
                process.alive = false;
                // if let Some(workspace) = self.workspaces.get(workspace_id as usize) {
                //     let mut ws = workspace.handle.state.write().unwrap();
                //     // if let Some(task) = ws.get_job_mut(job_id) {
                //     //     task.status = JobStatus::Terminating;
                //     // }
                // }
                false
            }
            ProcessRequest::AttachClient { stdin, stdout, socket, workspace_config, kind } => {
                let ws_index = match self.workspace_index(workspace_config) {
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
                    AttachKind::Run { task_name, params } => {
                        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
                            kvlog::error!("Run client requires stdin/stdout FDs");
                            return false;
                        };
                        self.attach_run_client(stdin, stdout, socket, ws_index, &task_name, params);
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
                }

                false
            }
            ProcessRequest::ClientExited { index } => {
                self.terminate_client(index as ClientIndex);
                false
            }
            ProcessRequest::GlobalTermination => {
                for (_, process) in &mut self.processes {
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
                for (index, process) in &mut self.processes {
                    if process.child.id() != pid {
                        continue;
                    }
                    kvlog::info!("Found ProcessExited");
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
                        if let Some(workspace) = self.workspaces.get_mut(process.workspace_index as usize) {
                            while let Some(line) = buffer.readline() {
                                process.append_line(line, &mut workspace.line_writer);
                            }
                            if !buffer.remaining_slice().is_empty() {
                                process.append_line(buffer.remaining_slice(), &mut workspace.line_writer);
                            }
                        }

                        buffer.reset();
                        self.buffer_pool.push(buffer.data);
                        if let Err(err) = self.poll.registry().deregister(&mut SourceFd(&stdin.as_raw_fd())) {
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
                        if let Some(workspace) = self.workspaces.get_mut(process.workspace_index as usize) {
                            while let Some(line) = buffer.readline() {
                                process.append_line(line, &mut workspace.line_writer);
                            }
                            if !buffer.remaining_slice().is_empty() {
                                process.append_line(buffer.remaining_slice(), &mut workspace.line_writer);
                            }
                        }
                        buffer.reset();
                        self.buffer_pool.push(buffer.data);
                        if let Err(err) = self.poll.registry().deregister(&mut SourceFd(&stderr.as_raw_fd())) {
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
                    };
                    if let Some(workspace) = self.workspaces.get(ws_idx as usize) {
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
                        self.timed_ready_count -= 1;
                    }
                    self.processes.remove(index);
                    self.broadcast_job_exited(ws_idx, job_idx, exit_code as i32, rpc_cause);
                    return false;
                }
                kvlog::info!("Didn't Find ProcessExited");
                false
            }
            ProcessRequest::Spawn { task, job_id, workspace_id, job_index } => {
                if let Err(err) = self.spawn(workspace_id, job_id, job_index, task) {
                    kvlog::error!("Failed to spawn process", ?err, ?job_id);
                    if let Some(workspace) = self.workspaces.get(workspace_id as usize) {
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
        }
    }

    fn attach_tui_client(&mut self, stdin: OwnedFd, stdout: OwnedFd, socket: UnixStream, ws_index: WorkspaceIndex) {
        let ws = &mut self.workspaces[ws_index as usize];
        let ws_handle = ws.handle.clone();
        let channel = Arc::new(ClientChannel {
            waker: extui::event::polling::Waker::new().unwrap(),
            events: Mutex::new(Vec::new()),
            selected: AtomicU64::new(0),
            state: AtomicU64::new(0),
        });
        let next = self.clients.vacant_key();
        let _ = self.poll.registry().register(
            &mut SourceFd(&socket.as_raw_fd()),
            TokenHandle::Client(next as u32).into(),
            Interest::READABLE,
        );
        let _ = socket.set_nonblocking(true);
        let client_entry = ClientEntry {
            channel: channel.clone(),
            workspace: ws_index,
            socket,
            kind: ClientKind::Tui,
            partial_rpc_read: None,
        };
        let index = self.clients.insert(client_entry);
        kvlog::info!("Client Attached");
        let keybinds = global_keybinds();
        let channel_clone = channel.clone();
        let output_mode = if std::env::var("DEVSM_JSON_STATE_STREAM").is_ok() {
            crate::tui::OutputMode::JsonStateStream
        } else {
            crate::tui::OutputMode::Terminal
        };
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(|| {
                if let Err(err) = crate::tui::run(stdin, stdout, &ws_handle, channel_clone, keybinds, output_mode) {
                    kvlog::error!("TUI exited with error", %err);
                }
            });
            kvlog::info!("Terminating Client");
            ws_handle.process_channel.send(ProcessRequest::ClientExited { index });
        });
    }

    fn attach_run_client(
        &mut self,
        stdin: OwnedFd,
        stdout: OwnedFd,
        socket: UnixStream,
        ws_index: WorkspaceIndex,
        task_name: &str,
        params: Vec<u8>,
    ) {
        let params: ValueMap = jsony::from_binary(&params).unwrap_or_else(|_| ValueMap::new());
        let (name, profile) = task_name.rsplit_once(":").unwrap_or((&*task_name, ""));

        let ws = &self.workspaces[ws_index as usize];
        let job_id = {
            let mut state = ws.handle.state.write().unwrap();
            let Some(base_index) = state.base_index_by_name(name) else {
                drop(state);
                let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
                let _ = std::io::Write::write_all(&mut file, b"Task not found\n");
                std::mem::forget(file);
                return;
            };
            drop(state);
            ws.handle.restart_task(base_index, params, profile);

            let state = ws.handle.state.read().unwrap();
            let bt = &state.base_tasks[base_index.idx()];
            bt.jobs.all().last().map(|ji| state[*ji].log_group)
        };

        let Some(job_id) = job_id else {
            let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
            let _ = std::io::Write::write_all(&mut file, b"Failed to start task\n");
            std::mem::forget(file);
            return;
        };

        let channel = Arc::new(ClientChannel {
            waker: extui::event::polling::Waker::new().unwrap(),
            events: Mutex::new(Vec::new()),
            selected: AtomicU64::new(0),
            state: AtomicU64::new(0),
        });

        let next = self.clients.vacant_key();
        let _ = self.poll.registry().register(
            &mut SourceFd(&socket.as_raw_fd()),
            TokenHandle::Client(next as u32).into(),
            Interest::READABLE,
        );
        let _ = socket.set_nonblocking(true);

        let forwarder_socket = socket.try_clone().ok();

        let client_entry = ClientEntry {
            channel: channel.clone(),
            workspace: ws_index,
            socket,
            kind: ClientKind::Run { log_group: job_id },
            partial_rpc_read: None,
        };
        let index = self.clients.insert(client_entry);

        let ws_handle = ws.handle.clone();
        let request_channel = self.request.clone();
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(|| {
                if let Err(err) =
                    crate::log_fowarder_ui::run(stdin, stdout, forwarder_socket, &ws_handle, job_id, channel)
                {
                    kvlog::error!("Forwarder exited with error", %err);
                }
            });
            kvlog::info!("Terminating run client");
            request_channel.send(ProcessRequest::ClientExited { index });
        });
    }

    fn attach_test_run_client(
        &mut self,
        stdin: OwnedFd,
        stdout: OwnedFd,
        socket: UnixStream,
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

        let ws = &self.workspaces[ws_index as usize];
        let test_run = ws.handle.start_test_run(&test_filters);

        if test_run.test_jobs.is_empty() {
            let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
            let _ = std::io::Write::write_all(&mut file, b"No tests matched the filters\n");
            std::mem::forget(file);
            return;
        }

        let channel = Arc::new(ClientChannel {
            waker: extui::event::polling::Waker::new().unwrap(),
            events: Mutex::new(Vec::new()),
            selected: AtomicU64::new(0),
            state: AtomicU64::new(0),
        });

        let next = self.clients.vacant_key();
        let _ = self.poll.registry().register(
            &mut SourceFd(&socket.as_raw_fd()),
            TokenHandle::Client(next as u32).into(),
            Interest::READABLE,
        );
        let _ = socket.set_nonblocking(true);

        let forwarder_socket = socket.try_clone().ok();

        let client_entry = ClientEntry {
            channel: channel.clone(),
            workspace: ws_index,
            socket,
            kind: ClientKind::TestRun,
            partial_rpc_read: None,
        };
        let index = self.clients.insert(client_entry);

        let ws_handle = ws.handle.clone();
        let request_channel = self.request.clone();
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(|| {
                if let Err(err) =
                    crate::test_summary_ui::run(stdin, stdout, forwarder_socket, &ws_handle, test_run, channel)
                {
                    kvlog::error!("Test forwarder exited with error", %err);
                }
            });
            kvlog::info!("Terminating test run client");
            request_channel.send(ProcessRequest::ClientExited { index });
        });
    }

    fn attach_rpc_client(&mut self, socket: UnixStream, ws_index: WorkspaceIndex, subscribe: bool) {
        let subscriptions = RpcSubscriptions { job_status: subscribe, job_exits: subscribe };

        let channel = Arc::new(ClientChannel {
            waker: extui::event::polling::Waker::new().unwrap(),
            events: Mutex::new(Vec::new()),
            selected: AtomicU64::new(0),
            state: AtomicU64::new(0),
        });

        let next = self.clients.vacant_key();
        let _ = self.poll.registry().register(
            &mut SourceFd(&socket.as_raw_fd()),
            TokenHandle::Client(next as u32).into(),
            Interest::READABLE,
        );
        let _ = socket.set_nonblocking(true);

        let client_entry = ClientEntry {
            channel,
            workspace: ws_index,
            socket,
            kind: ClientKind::Rpc { subscriptions },
            partial_rpc_read: None,
        };
        let client_index = self.clients.insert(client_entry);

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

    fn handle_rpc_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let ws_index = client.workspace;

        let (mut state, mut buffer) = client
            .partial_rpc_read
            .take()
            .unwrap_or_else(|| (DecodingState::default(), self.buffer_pool.pop().unwrap_or_default()));

        let mut terminate = false;
        loop {
            match try_read(client.socket.as_raw_fd(), &mut buffer) {
                ReadResult::More => continue,
                ReadResult::EOF => {
                    terminate = true;
                    break;
                }
                ReadResult::Done | ReadResult::WouldBlock => break,
                ReadResult::OtherError(err) => {
                    kvlog::error!("RPC client read error", ?err);
                    terminate = true;
                    break;
                }
            }
        }

        let mut encoder = crate::rpc::Encoder::new();

        loop {
            match state.decode(&buffer) {
                DecodeResult::Message { kind, correlation, payload } => {
                    self.handle_rpc_message(client_index, ws_index, kind, correlation, payload, &mut encoder);
                }
                DecodeResult::MissingData { .. } => break,
                DecodeResult::Empty => {
                    buffer.clear();
                    break;
                }
                DecodeResult::Error(e) => {
                    kvlog::error!("RPC protocol decode error", ?e);
                    terminate = true;
                    break;
                }
            }
        }

        state.compact(&mut buffer, 4096);

        if !encoder.output().is_empty() {
            let Some(client) = self.clients.get_mut(client_index as usize) else {
                self.buffer_pool.push(buffer);
                return;
            };
            let _ = client.socket.write_all(encoder.output());
        }

        if terminate {
            self.buffer_pool.push(buffer);
            self.terminate_client(client_index);
        } else if buffer.is_empty() {
            self.buffer_pool.push(buffer);
        } else {
            let Some(client) = self.clients.get_mut(client_index as usize) else { return };
            client.partial_rpc_read = Some((state, buffer));
        }
    }

    fn handle_rpc_message(
        &mut self,
        client_index: ClientIndex,
        ws_index: WorkspaceIndex,
        kind: RpcMessageKind,
        correlation: u16,
        payload: &[u8],
        encoder: &mut crate::rpc::Encoder,
    ) {
        match kind {
            RpcMessageKind::Subscribe => {
                let Ok(filter) = jsony::from_binary::<crate::rpc::SubscriptionFilter>(payload) else {
                    encoder.encode_response(
                        RpcMessageKind::ErrorResponse,
                        correlation,
                        &crate::rpc::ErrorResponsePayload { code: 1, message: "Invalid subscription filter".into() },
                    );
                    return;
                };
                let Some(client) = self.clients.get_mut(client_index as usize) else { return };
                let ClientKind::Rpc { subscriptions } = &mut client.kind else { return };
                subscriptions.job_status = filter.job_status;
                subscriptions.job_exits = filter.job_exits;
                encoder.encode_response(
                    RpcMessageKind::SubscribeAck,
                    correlation,
                    &crate::rpc::SubscribeAck { success: true },
                );
            }
            RpcMessageKind::RunTask => {
                let Ok(req) = jsony::from_binary::<crate::rpc::RunTaskRequest>(payload) else {
                    encoder.encode_response(
                        RpcMessageKind::ErrorResponse,
                        correlation,
                        &crate::rpc::ErrorResponsePayload { code: 2, message: "Invalid run task request".into() },
                    );
                    return;
                };
                let params: ValueMap = jsony::from_binary(req.params).unwrap_or_else(|_| ValueMap::new());
                let ws = &self.workspaces[ws_index as usize];
                let mut state = ws.handle.state.write().unwrap();
                let Some(base_index) = state.base_index_by_name(req.task_name) else {
                    drop(state);
                    encoder.encode_response(
                        RpcMessageKind::RunTaskAck,
                        correlation,
                        &crate::rpc::RunTaskResponse {
                            success: false,
                            job_index: None,
                            error: Some(format!("Task '{}' not found", req.task_name).into()),
                        },
                    );
                    return;
                };
                drop(state);

                ws.handle.restart_task(base_index, params, req.profile);

                let ws_state = ws.handle.state.read().unwrap();
                let bt = &ws_state.base_tasks[base_index.idx()];
                let job_index = bt.jobs.all().last().map(|ji| ji.as_u32());

                encoder.encode_response(
                    RpcMessageKind::RunTaskAck,
                    correlation,
                    &crate::rpc::RunTaskResponse { success: true, job_index, error: None },
                );
            }
            RpcMessageKind::Terminate => {
                encoder.encode_empty(RpcMessageKind::TerminateAck, correlation);
            }
            RpcMessageKind::OpenWorkspace => {
                encoder.encode_response(
                    RpcMessageKind::OpenWorkspaceAck,
                    correlation,
                    &crate::rpc::OpenWorkspaceResponse { success: true, error: None },
                );
            }
            _ => {
                kvlog::warn!("Unexpected RPC message kind from client", ?kind);
            }
        }
    }

    fn terminate_client(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.try_remove(client_index as usize) else {
            kvlog::error!("Terminate for missing client", index = client_index as usize);
            return;
        };
        client.channel.set_terminated();
        let _ = client.channel.wake();
        let _ = self.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
    }

    fn handle_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get(client_index as usize) else {
            kvlog::error!("Read for missing client", index = client_index as usize);
            return;
        };

        match &client.kind {
            ClientKind::Tui => self.handle_tui_client_read(client_index),
            ClientKind::Run { log_group: job_id } => {
                let job_id = *job_id;
                self.handle_run_client_read(client_index, job_id);
            }
            ClientKind::TestRun => self.handle_test_run_client_read(client_index),
            ClientKind::Rpc { .. } => self.handle_rpc_client_read(client_index),
        }
    }

    fn handle_tui_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let (mut state, mut buffer) = client
            .partial_rpc_read
            .take()
            .unwrap_or_else(|| (DecodingState::default(), self.buffer_pool.pop().unwrap_or_default()));

        let mut terminate = false;
        loop {
            match try_read(client.socket.as_raw_fd(), &mut buffer) {
                ReadResult::More => continue,
                ReadResult::EOF => {
                    terminate = true;
                    break;
                }
                ReadResult::Done => break,
                ReadResult::WouldBlock => break,
                ReadResult::OtherError(err) => {
                    kvlog::error!("Read failed with unexpected error", ?err);
                    terminate = true;
                    break;
                }
            }
        }

        let mut wake = false;
        loop {
            match state.decode(&buffer) {
                DecodeResult::Message { kind, .. } => match kind {
                    RpcMessageKind::Resize => {
                        client.channel.state.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        wake = true;
                    }
                    RpcMessageKind::Terminate => {
                        terminate = true;
                    }
                    _ => {
                        kvlog::error!("Unexpected message kind from TUI client", ?kind);
                    }
                },
                DecodeResult::MissingData { .. } => break,
                DecodeResult::Empty => {
                    buffer.clear();
                    break;
                }
                DecodeResult::Error(e) => {
                    kvlog::error!("Protocol decode error", ?e);
                    terminate = true;
                    break;
                }
            }
        }

        state.compact(&mut buffer, 4096);

        if terminate {
            self.buffer_pool.push(buffer);
            self.terminate_client(client_index);
        } else {
            if buffer.is_empty() {
                self.buffer_pool.push(buffer);
            } else {
                let Some(client) = self.clients.get_mut(client_index as usize) else { return };
                client.partial_rpc_read = Some((state, buffer));
            }
            if wake {
                let Some(client) = self.clients.get_mut(client_index as usize) else { return };
                let _ = client.channel.wake();
            }
        }
    }

    fn handle_run_client_read(&mut self, client_index: ClientIndex, job_id: LogGroup) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let (mut state, mut buffer) = client
            .partial_rpc_read
            .take()
            .unwrap_or_else(|| (DecodingState::default(), self.buffer_pool.pop().unwrap_or_default()));

        let mut terminate = false;
        let mut kill_task = false;

        loop {
            match try_read(client.socket.as_raw_fd(), &mut buffer) {
                ReadResult::More => continue,
                ReadResult::EOF => {
                    terminate = true;
                    break;
                }
                ReadResult::Done => break,
                ReadResult::WouldBlock => break,
                ReadResult::OtherError(_) => {
                    terminate = true;
                    break;
                }
            }
        }

        loop {
            match state.decode(&buffer) {
                DecodeResult::Message { kind, .. } => match kind {
                    RpcMessageKind::Terminate => {
                        kill_task = true;
                        terminate = true;
                    }
                    _ => {
                        kvlog::error!("Unexpected message kind from run client", ?kind);
                    }
                },
                DecodeResult::MissingData { .. } => break,
                DecodeResult::Empty => {
                    buffer.clear();
                    break;
                }
                DecodeResult::Error(e) => {
                    kvlog::error!("Protocol decode error", ?e);
                    terminate = true;
                    break;
                }
            }
        }

        state.compact(&mut buffer, 4096);

        if kill_task {
            for (_, process) in &self.processes {
                if process.log_group == job_id {
                    let child_pid = process.child.id();
                    let pgid = -(child_pid as i32);
                    unsafe {
                        libc::kill(pgid, libc::SIGINT);
                    }
                    break;
                }
            }
        }

        if terminate {
            self.buffer_pool.push(buffer);
            self.terminate_client(client_index);
        } else if buffer.is_empty() {
            self.buffer_pool.push(buffer);
        } else {
            let Some(client) = self.clients.get_mut(client_index as usize) else { return };
            client.partial_rpc_read = Some((state, buffer));
        }
    }

    fn handle_test_run_client_read(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            return;
        };
        let (mut state, mut buffer) = client
            .partial_rpc_read
            .take()
            .unwrap_or_else(|| (DecodingState::default(), self.buffer_pool.pop().unwrap_or_default()));

        let mut terminate = false;

        loop {
            match try_read(client.socket.as_raw_fd(), &mut buffer) {
                ReadResult::More => continue,
                ReadResult::EOF => {
                    terminate = true;
                    break;
                }
                ReadResult::Done => break,
                ReadResult::WouldBlock => break,
                ReadResult::OtherError(_) => {
                    terminate = true;
                    break;
                }
            }
        }

        loop {
            match state.decode(&buffer) {
                DecodeResult::Message { kind, .. } => match kind {
                    RpcMessageKind::Terminate => {
                        terminate = true;
                    }
                    _ => {
                        kvlog::error!("Unexpected message kind from test client", ?kind);
                    }
                },
                DecodeResult::MissingData { .. } => break,
                DecodeResult::Empty => {
                    buffer.clear();
                    break;
                }
                DecodeResult::Error(e) => {
                    kvlog::error!("Protocol decode error", ?e);
                    terminate = true;
                    break;
                }
            }
        }

        state.compact(&mut buffer, 4096);

        if terminate {
            self.buffer_pool.push(buffer);
            self.terminate_client(client_index);
        } else if buffer.is_empty() {
            self.buffer_pool.push(buffer);
        } else {
            let Some(client) = self.clients.get_mut(client_index as usize) else { return };
            client.partial_rpc_read = Some((state, buffer));
        }
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
    let mut job_manager = ProcessManager {
        clients: Slab::new(),
        request,
        workspace_map: HashMap::new(),
        workspaces: slab::Slab::new(),
        processes: slab::Slab::new(),
        buffer_pool: Vec::new(),
        wait_thread,
        poll,
        timed_ready_count: 0,
    };
    loop {
        let poll_timeout =
            if job_manager.timed_ready_count > 0 { Some(std::time::Duration::from_millis(500)) } else { None };
        job_manager.poll.poll(&mut events, poll_timeout).unwrap();

        for event in &events {
            match TokenHandle::from(event.token()) {
                TokenHandle::RequestChannel => {
                    if TERMINATED.load(std::sync::atomic::Ordering::Relaxed) {
                        job_manager.handle_request(ProcessRequest::GlobalTermination);
                        return;
                    }
                    let mut reqs = Vec::new();
                    job_manager.request.swap_recv(&mut reqs);
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
                    job_manager.handle_client_read(index);
                }
            }
        }

        job_manager.scheduled();
        if job_manager.timed_ready_count > 0 {
            job_manager.check_ready_timeouts();
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

fn wait_thread(req: Arc<MioChannel>) {
    loop {
        let mut status: libc::c_int = 0;
        unsafe {
            let pid = libc::wait(&mut status);
            if pid > 0 {
                req.send(ProcessRequest::ProcessExited { pid: pid as u32, status: status as u32 });
            } else if pid == -1 {
                let errno = *libc::__errno_location();
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
static GLOBAL_USER_CONFIG: std::sync::OnceLock<crate::user_config::UserConfig> = std::sync::OnceLock::new();

fn global_user_config() -> &'static crate::user_config::UserConfig {
    GLOBAL_USER_CONFIG.get_or_init(crate::user_config::UserConfig::load)
}

pub(crate) fn global_keybinds() -> &'static crate::keybinds::Keybinds {
    &global_user_config().keybinds
}

pub(crate) fn user_config_loaded() -> bool {
    global_user_config().loaded_from_file
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
        let wait_thread = std::thread::spawn(move || {
            wait_thread(r2);
        });

        let handle = ProcessManagerHandle { request };

        std::thread::spawn(move || {
            func(handle);
        });
        process_worker(r, wait_thread, poll);
        Ok(())
    }
}
