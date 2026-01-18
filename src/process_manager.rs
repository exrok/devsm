use crate::workspace::{self, ExitCause, JobIndex, JobStatus, Workspace, WorkspaceState};
use crate::{
    config::{Command, TaskConfigRc},
    daemon::WorkspaceCommand,
    line_width::{Segment, apply_raw_display_mode_vt_to_style},
    log_storage::{JobLogCorrelation, LogWriter},
};
use anyhow::{Context, bail};
use jsony_value::ValueMap;
use mio::{Events, Interest, Poll, Token, Waker, unix::SourceFd};
use slab::Slab;
use std::io::Write;
use std::{
    collections::HashMap,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
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
use vtui::Style;

const RESIZE_CODE: u32 = 0x85_06_09_44;
const TERMINATION_CODE: u32 = 0xcf_04_43_58;
#[derive(Clone, Copy, Debug)]
pub(crate) enum Pipe {
    Stdout,
    Stderr,
}

type WorkspaceIndex = u32;
pub(crate) struct ActiveProcess {
    // active stdout
    pub(crate) job_id: JobLogCorrelation,
    pub(crate) job_index: JobIndex,
    pub(crate) workspace_index: WorkspaceIndex,
    pub(crate) alive: bool,
    pub(crate) stdout_buffer: Option<Buffer>,
    pub(crate) stderr_buffer: Option<Buffer>,
    pub(crate) style: Style,
    pub(crate) child: Child,
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

            writer.push_line(text, width as u32, self.job_id, self.style);
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

struct ClientEntry {
    workspace: WorkspaceIndex,
    channel: Arc<ClientChannel>,
    socket: UnixStream,
}

struct RunClientEntry {
    workspace: WorkspaceIndex,
    channel: Arc<ForwarderChannel>,
    socket: UnixStream,
    job_id: JobLogCorrelation,
}

struct TestRunClientEntry {
    workspace: WorkspaceIndex,
    channel: Arc<ForwarderChannel>,
    socket: UnixStream,
}

pub struct WorkspaceEntry {
    line_writer: LogWriter,
    handle: Arc<Workspace>,
}

pub(crate) struct ProcessManager {
    clients: Slab<ClientEntry>,
    run_clients: Slab<RunClientEntry>,
    test_run_clients: Slab<TestRunClientEntry>,
    workspaces: slab::Slab<WorkspaceEntry>,
    workspace_map: HashMap<Box<Path>, WorkspaceIndex>,
    processes: slab::Slab<ActiveProcess>,
    buffer_pool: Vec<Vec<u8>>,
    wait_thread: std::thread::JoinHandle<()>,
    request: Arc<MioChannel>,
    poll: Poll,
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
                    workspace.line_writer.push_line(text, width as u32, process.job_id, process.style);
                }
                process.style = new_style;
            }
        }
        if buffer.is_empty() || !expecting_more {
            buffer.reset();
            self.buffer_pool.push(buffer.data)
        } else {
            // todo should compact buffer it too much space left
            match pipe {
                Pipe::Stdout => process.stdout_buffer = Some(buffer),
                Pipe::Stderr => process.stderr_buffer = Some(buffer),
            }
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
                        let job_id = job.job_id;
                        let job_index = job_index;
                        let job_task = job.task.clone();
                        drop(state);
                        let _ = self.spawn(wsi as WorkspaceIndex, job_id, job_index, job_task);
                        continue 'outer;
                    }
                    workspace::Scheduled::Never(job_index) => {
                        kvlog::info!("Scheduled task is never");
                        drop(state);
                        let mut ws_state = ws.handle.state.write().unwrap();
                        ws_state.update_job_status(job_index, JobStatus::Cancelled);
                        continue 'outer;
                    }
                    workspace::Scheduled::None => {
                        kvlog::info!("no task is ready");
                    }
                }
            }
            break;
        }
    }
    pub(crate) fn spawn(
        &mut self,
        workspace_index: WorkspaceIndex,
        job_id: JobLogCorrelation,
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
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        // If using sh, pipe the script to stdin, otherwise use null stdin
        let stdin = if sh_script.is_some() { Stdio::piped() } else { Stdio::null() };
        command.stdin(stdin);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn().context("Failed to spawn process")?;

        // If using sh, write the script to stdin and close it
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
            self.poll.registry().register(
                &mut SourceFd(&stdout.as_raw_fd()),
                Token((index << 1) | 0),
                Interest::READABLE,
            )?;
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
        let process_index = self.processes.insert(ActiveProcess {
            workspace_index,
            job_index,
            job_id,
            alive: true,
            stdout_buffer: None,
            stderr_buffer: None,
            style: Style::default(),
            child,
        });
        {
            let mut ws = workspace.handle.state.write().unwrap();
            ws.update_job_status(job_index, JobStatus::Running { process_index });
        }
        Ok(())
    }
}

pub(crate) enum ProcessRequest {
    WorkspaceCommand { workspace_config: PathBuf, socket: UnixStream, command: Vec<u8> },
    Spawn { task: TaskConfigRc, workspace_id: WorkspaceIndex, job_id: JobLogCorrelation, job_index: JobIndex },
    AttachClient { stdin: OwnedFd, stdout: OwnedFd, socket: UnixStream, workspace_config: PathBuf },
    AttachRun {
        stdin: OwnedFd,
        stdout: OwnedFd,
        socket: UnixStream,
        workspace_config: PathBuf,
        task_name: Box<str>,
        params: Vec<u8>,
    },
    AttachTestRun {
        stdin: OwnedFd,
        stdout: OwnedFd,
        socket: UnixStream,
        workspace_config: PathBuf,
        filters: Vec<u8>,
    },
    TerminateJob { job_id: JobLogCorrelation, process_index: usize },
    ClientExited { index: usize },
    RunClientExited { index: usize },
    TestRunClientExited { index: usize },
    ProcessExited { pid: u32, status: u32 },
    GlobalTermination,
}

pub(crate) struct ClientChannel {
    pub(crate) waker: vtui::event::polling::Waker,
    pub(crate) state: AtomicU64,
    pub(crate) selected: AtomicU64,
    pub(crate) events: Mutex<Vec<()>>,
}

/// Channel for communicating with a log forwarder thread.
///
/// Allows the process manager to wake the forwarder when new logs arrive
/// and signal termination when the client disconnects.
pub struct ForwarderChannel {
    pub waker: vtui::event::polling::Waker,
    pub state: AtomicU64,
}

impl ForwarderChannel {
    /// Wakes the forwarder thread to check for new logs.
    pub fn wake(&self) -> std::io::Result<()> {
        self.waker.wake()
    }

    /// Returns true if the forwarder should terminate.
    pub fn is_terminated(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Relaxed) != 0
    }

    /// Signals the forwarder to terminate.
    pub fn set_terminated(&self) {
        self.state.store(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub enum Action {
    Resized,
    Terminated,
}
impl ClientChannel {
    pub(crate) fn wake(&self) -> std::io::Result<()> {
        self.waker.wake()
    }
    pub(crate) fn swap_recv(&self, buf: &mut Vec<()>) {
        let mut events = self.events.lock().unwrap();
        buf.clear();
        std::mem::swap(buf, &mut events);
    }
    pub(crate) fn try_send(&self, req: ()) -> anyhow::Result<()> {
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
    pub(crate) fn send(&self, req: ()) {
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
                    ws.handle.restart_task(workspace::BaseTaskIndex(base_index as u32), ValueMap::new(), "");
                }
            }
            WorkspaceCommand::GetPanicLocation => {
                let response = jsony::to_json(&self.workspaces[ws_index as usize].handle.last_rust_panic());
                let _ = socket.write_all(&response.as_bytes());
            }
            WorkspaceCommand::Run { name, params } => {
                let ws = &self.workspaces[ws_index as usize];
                let mut state = ws.handle.state.write().unwrap();
                let (name, profile) = name.rsplit_once(":").unwrap_or((&*name, ""));
                if let Some(index) = state.base_index_by_name(name) {
                    drop(state);
                    ws.handle.restart_task(workspace::BaseTaskIndex(index as u32), params, profile);
                }
            }
        }
    }
    fn handle_request(&mut self, req: ProcessRequest) -> bool {
        match req {
            ProcessRequest::WorkspaceCommand { workspace_config, socket, command } => {
                let ws_index = match self.workspace_index(workspace_config) {
                    Ok(ws) => ws,
                    Err(err) => {
                        kvlog::info!("Error spawning workspace", %err);
                        return false;
                    }
                };
                self.handle_workspace_command(ws_index, &command, socket);
                false
            }
            ProcessRequest::TerminateJob { job_id, process_index } => {
                if let Some(process) = self.processes.get_mut(process_index) {
                    if process.job_id != job_id {
                        kvlog::error!(
                            "Mismatched job id for termination",
                            ?job_id,
                            expected = ?process.job_id
                        );
                        return false;
                    }
                    let child_pid = process.child.id();
                    let pgid_to_kill = -(child_pid as i32);

                    unsafe {
                        if libc::kill(pgid_to_kill, libc::SIGINT) == -1 {
                            let err = std::io::Error::last_os_error();
                            kvlog::error!("Failed to send SIGTERM", ?err, ?child_pid);
                        }
                    }
                    process.alive = false;
                }
                // if let Some(workspace) = self.workspaces.get(workspace_id as usize) {
                //     let mut ws = workspace.handle.state.write().unwrap();
                //     // if let Some(task) = ws.get_job_mut(job_id) {
                //     //     task.status = JobStatus::Terminating;
                //     // }
                // }
                false
            }
            ProcessRequest::AttachClient { stdin, stdout, socket, workspace_config } => {
                let ws_index = match self.workspace_index(workspace_config) {
                    Ok(ws) => ws,
                    Err(err) => {
                        kvlog::info!("Error spawning workspace", %err);
                        return false;
                    }
                };
                let ws = &mut self.workspaces[ws_index as usize];
                let ws_handle = ws.handle.clone();
                let vtui_channel = Arc::new(ClientChannel {
                    waker: vtui::event::polling::Waker::new().unwrap(),
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
                let client_entry = ClientEntry { channel: vtui_channel.clone(), workspace: ws_index, socket };
                let index = self.clients.insert(client_entry);
                kvlog::info!("Client Attached");
                let keybinds = global_keybinds();
                std::thread::spawn(move || {
                    let _ = std::panic::catch_unwind(|| {
                        if let Err(err) = crate::tui::run(stdin, stdout, &ws_handle, vtui_channel, keybinds) {
                            kvlog::error!("TUI exited with error", %err);
                        }
                    });
                    kvlog::info!("Terminating Clinet");
                    ws_handle.process_channel.send(ProcessRequest::ClientExited { index });
                });

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
                return true;
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
                    if let Some(workspace) = self.workspaces.get(process.workspace_index as usize) {
                        let mut ws = workspace.handle.state.write().unwrap();
                        ws.update_job_status(
                            process.job_index,
                            JobStatus::Exited {
                                finished_at: std::time::Instant::now(),
                                log_end: workspace.line_writer.tail(),
                                cause: ExitCause::Unknown,
                                status: status,
                            },
                        );
                    }
                    self.processes.remove(index);
                    return false;
                }
                kvlog::info!("Didn't Find ProcessExited");
                return false;
            }
            ProcessRequest::Spawn { task, job_id, workspace_id, job_index } => {
                if let Err(err) = self.spawn(workspace_id, job_id, job_index, task) {
                    kvlog::error!("Failed to spawn process", ?err, ?job_id);
                }
                return false;
            }
            ProcessRequest::AttachRun {
                stdin,
                stdout,
                socket,
                workspace_config,
                task_name,
                params,
            } => {
                let ws_index = match self.workspace_index(workspace_config) {
                    Ok(ws) => ws,
                    Err(err) => {
                        kvlog::info!("Error spawning workspace", %err);
                        return false;
                    }
                };

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
                        return false;
                    };
                    drop(state);
                    ws.handle.restart_task(workspace::BaseTaskIndex(base_index as u32), params, profile);

                    let state = ws.handle.state.read().unwrap();
                    let bt = &state.base_tasks[base_index];
                    bt.jobs.all().last().map(|ji| state[*ji].job_id)
                };

                let Some(job_id) = job_id else {
                    let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
                    let _ = std::io::Write::write_all(&mut file, b"Failed to start task\n");
                    std::mem::forget(file);
                    return false;
                };

                let forwarder_channel = Arc::new(ForwarderChannel {
                    waker: vtui::event::polling::Waker::new().unwrap(),
                    state: AtomicU64::new(0),
                });

                let next = self.run_clients.vacant_key();
                let _ = self.poll.registry().register(
                    &mut SourceFd(&socket.as_raw_fd()),
                    TokenHandle::RunClient(next as u32).into(),
                    Interest::READABLE,
                );
                let _ = socket.set_nonblocking(true);

                let forwarder_socket = socket.try_clone().ok();

                let run_client_entry = RunClientEntry {
                    channel: forwarder_channel.clone(),
                    workspace: ws_index,
                    socket,
                    job_id,
                };
                let index = self.run_clients.insert(run_client_entry);

                let ws_handle = ws.handle.clone();
                let request_channel = self.request.clone();
                std::thread::spawn(move || {
                    let _ = std::panic::catch_unwind(|| {
                        if let Err(err) =
                            crate::forwarder::run(stdin, stdout, forwarder_socket, &ws_handle, job_id, forwarder_channel)
                        {
                            kvlog::error!("Forwarder exited with error", %err);
                        }
                    });
                    kvlog::info!("Terminating run client");
                    request_channel.send(ProcessRequest::RunClientExited { index });
                });

                false
            }
            ProcessRequest::RunClientExited { index } => {
                self.terminate_run_client(index as u32);
                false
            }
            ProcessRequest::AttachTestRun {
                stdin,
                stdout,
                socket,
                workspace_config,
                filters,
            } => {
                let ws_index = match self.workspace_index(workspace_config) {
                    Ok(ws) => ws,
                    Err(err) => {
                        kvlog::info!("Error spawning workspace", %err);
                        return false;
                    }
                };

                let filters: crate::daemon::TestFilters =
                    jsony::from_binary(&filters).unwrap_or_else(|_| crate::daemon::TestFilters::default());

                // Convert TestFilters to Vec<TestFilter>
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
                    return false;
                }

                let forwarder_channel = Arc::new(ForwarderChannel {
                    waker: vtui::event::polling::Waker::new().unwrap(),
                    state: AtomicU64::new(0),
                });

                let next = self.test_run_clients.vacant_key();
                let _ = self.poll.registry().register(
                    &mut SourceFd(&socket.as_raw_fd()),
                    TokenHandle::TestRunClient(next as u32).into(),
                    Interest::READABLE,
                );
                let _ = socket.set_nonblocking(true);

                let forwarder_socket = socket.try_clone().ok();

                let test_run_client_entry = TestRunClientEntry {
                    channel: forwarder_channel.clone(),
                    workspace: ws_index,
                    socket,
                };
                let index = self.test_run_clients.insert(test_run_client_entry);

                let ws_handle = ws.handle.clone();
                let request_channel = self.request.clone();
                std::thread::spawn(move || {
                    let _ = std::panic::catch_unwind(|| {
                        if let Err(err) = crate::test_forwarder::run(
                            stdin,
                            stdout,
                            forwarder_socket,
                            &ws_handle,
                            test_run,
                            forwarder_channel,
                        ) {
                            kvlog::error!("Test forwarder exited with error", %err);
                        }
                    });
                    kvlog::info!("Terminating test run client");
                    request_channel.send(ProcessRequest::TestRunClientExited { index });
                });

                false
            }
            ProcessRequest::TestRunClientExited { index } => {
                self.terminate_test_run_client(index as u32);
                false
            }
        }
    }
    fn terminate_client(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.try_remove(client_index as usize) else {
            kvlog::error!("Client ready index for missing client_index", index = client_index as usize);
            return;
        };
        client.channel.state.store(1 << 0u64, std::sync::atomic::Ordering::Relaxed);
        let _ = client.channel.wake();
        let _ = self.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
    }
    fn handle_client_read_ready(&mut self, client_index: ClientIndex) {
        let Some(client) = self.clients.get_mut(client_index as usize) else {
            kvlog::error!("Client ready index for missing client_index", index = client_index as usize);
            return;
        };
        let mut buffer = self.buffer_pool.pop().unwrap_or_default();
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
        let mut requests = &buffer[..];
        let mut wake = false;
        while let Some((a, remaining)) = requests.split_first_chunk() {
            let command = u32::from_le_bytes(*a);
            requests = remaining;
            if command == RESIZE_CODE {
                client.channel.state.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                wake = true;
            } else if command == TERMINATION_CODE {
                terminate = true;
            } else {
                kvlog::error!("Unknown command from client", ?command);
            }
        }

        if terminate {
            self.terminate_client(client_index);
        } else if wake {
            let _ = client.channel.wake();
        }
    }
    fn terminate_run_client(&mut self, client_index: u32) {
        let Some(client) = self.run_clients.try_remove(client_index as usize) else {
            return;
        };
        client.channel.set_terminated();
        let _ = client.channel.wake();
        let _ = self.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
    }
    fn handle_run_client_read(&mut self, client_index: u32) {
        let Some(client) = self.run_clients.get_mut(client_index as usize) else {
            return;
        };
        let mut buffer = [0u8; 4];
        let mut terminate = false;
        let mut kill_task = false;
        match std::io::Read::read(&mut &client.socket, &mut buffer) {
            Ok(4) => {
                let code = u32::from_le_bytes(buffer);
                if code == TERMINATION_CODE {
                    kill_task = true;
                    terminate = true;
                }
            }
            Ok(0) => {
                terminate = true;
            }
            Err(_) => {
                terminate = true;
            }
            _ => {}
        }

        if kill_task {
            let job_id = client.job_id;
            for (_, process) in &self.processes {
                if process.job_id == job_id {
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
            self.terminate_run_client(client_index);
        }
    }
    fn terminate_test_run_client(&mut self, client_index: u32) {
        let Some(client) = self.test_run_clients.try_remove(client_index as usize) else {
            return;
        };
        client.channel.set_terminated();
        let _ = client.channel.wake();
        let _ = self.poll.registry().deregister(&mut SourceFd(&client.socket.as_raw_fd()));
    }
    fn handle_test_run_client_read(&mut self, client_index: u32) {
        let Some(client) = self.test_run_clients.get_mut(client_index as usize) else {
            return;
        };
        let mut buffer = [0u8; 4];
        let mut terminate = false;
        match std::io::Read::read(&mut &client.socket, &mut buffer) {
            Ok(4) => {
                let code = u32::from_le_bytes(buffer);
                if code == TERMINATION_CODE {
                    terminate = true;
                }
            }
            Ok(0) => {
                terminate = true;
            }
            Err(_) => {
                terminate = true;
            }
            _ => {}
        }

        if terminate {
            self.terminate_test_run_client(client_index);
        }
    }
}

pub(crate) fn process_worker(request: Arc<MioChannel>, wait_thread: std::thread::JoinHandle<()>, poll: Poll) {
    let mut events = Events::with_capacity(128);
    let mut job_manager = ProcessManager {
        clients: Slab::new(),
        run_clients: Slab::new(),
        test_run_clients: Slab::new(),
        request,
        workspace_map: HashMap::new(),
        workspaces: slab::Slab::new(),
        processes: slab::Slab::new(),
        buffer_pool: Vec::new(),
        wait_thread,
        poll,
    };
    loop {
        job_manager.poll.poll(&mut events, None).unwrap();

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
                            // Termination requested
                            return;
                        }
                    }
                    job_manager.scheduled();
                }
                TokenHandle::Task(pipe) => {
                    if let Err(err) = job_manager.read(pipe.index(), pipe.pipe()) {
                        kvlog::error!("Failed to read from process", ?err, ?pipe);
                    }
                    job_manager.scheduled();
                }
                TokenHandle::Client(index) => {
                    job_manager.handle_client_read_ready(index);
                }
                TokenHandle::RunClient(index) => {
                    job_manager.handle_run_client_read(index);
                }
                TokenHandle::TestRunClient(index) => {
                    job_manager.handle_test_run_client_read(index);
                }
            }
        }
        for (_, client) in &job_manager.clients {
            let _ = client.channel.wake();
        }
        for (_, client) in &job_manager.run_clients {
            let _ = client.channel.wake();
        }
        for (_, client) in &job_manager.test_run_clients {
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
    pub fn token(self) -> Token {
        Token(self.0 as usize)
    }
}

enum TokenHandle {
    RequestChannel,
    Task(TaskPipe),
    Client(ClientIndex),
    RunClient(u32),
    TestRunClient(u32),
}

impl From<Token> for TokenHandle {
    fn from(token: Token) -> Self {
        if token.0 == CHANNEL_TOKEN.0 {
            TokenHandle::RequestChannel
        } else if token.0 & (1 << 29) != 0 {
            let index = token.0 & !(1 << 29);
            TokenHandle::Client(index as ClientIndex)
        } else if token.0 & (1 << 28) != 0 {
            let index = token.0 & !(1 << 28);
            TokenHandle::RunClient(index as u32)
        } else if token.0 & (1 << 27) != 0 {
            let index = token.0 & !(1 << 27);
            TokenHandle::TestRunClient(index as u32)
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
            TokenHandle::RunClient(index) => Token((1 << 28) | (index as usize)),
            TokenHandle::TestRunClient(index) => Token((1 << 27) | (index as usize)),
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
static GLOBAL_KEYBINDS: std::sync::OnceLock<crate::keybinds::Keybinds> = std::sync::OnceLock::new();

pub(crate) fn global_keybinds() -> &'static crate::keybinds::Keybinds {
    GLOBAL_KEYBINDS.get_or_init(|| crate::user_config::UserConfig::load().keybinds)
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
