use crate::config::TaskConfigRc;
use crate::line_width::Segment;
use crate::line_width::apply_raw_display_mode_vt_to_style;
use crate::log_storage;
use crate::log_storage::JobId;
use crate::log_storage::LogWriter;
use crate::log_storage::Logs;
use crate::workspace::Job;
use crate::workspace::Workspace;
use crate::workspace::WorkspaceState;
use anyhow::Context;
use mio::Events;
use mio::Interest;
use mio::Poll;
use mio::Token;
use mio::Waker;
use mio::unix::SourceFd;
use slab::Slab;
use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;
use unicode_width::UnicodeWidthStr;
use vtui::Style;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Pipe {
    Stdout,
    Stderr,
}
impl Pipe {
    fn of(task: ProcessIndex) -> TaskPipe {
        TaskPipe((task as u32) << 1)
    }
}

type WorkspaceIndex = u32;
pub(crate) struct ActiveProcess {
    // active stdout
    pub(crate) job_id: JobId,
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
                    Segment::AnsiEscapes(escape) => {
                        apply_raw_display_mode_vt_to_style(&mut new_style, escape)
                    }
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

struct ClientHandle {
    update: AtomicU64,
    pub waker: vtui::event::polling::Waker,
    stream: UnixStream,
}

impl ClientHandle {
    pub fn consume_update(&self) -> Option<ClientUpdate> {
        let update = self.update.swap(0, std::sync::atomic::Ordering::Relaxed);
        if update > u32::MAX as u64 {
            Some(ClientUpdate::Terminated)
        } else if update != 0 {
            Some(ClientUpdate::Resized)
        } else {
            None
        }
    }
}

pub enum ClientUpdate {
    Terminated,
    Resized,
}

struct ClientEntry {
    workspace: WorkspaceIndex,
    channel: Arc<VtuiChannel>,
    socket: UnixStream,
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
    let result = unsafe { libc::read(fd, target.as_mut_ptr() as *mut libc::c_void, read_len) };
    if result < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::WouldBlock {
            return ReadResult::OtherError(err.kind());
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

impl ProcessManager {
    pub(crate) fn read(
        &mut self,
        poll: &mut Poll,
        index: ProcessIndex,
        pipe: Pipe,
    ) -> anyhow::Result<()> {
        kvlog::info!("Read");
        let process = self
            .processes
            .get_mut(index)
            .context("Invalid process index")?;
        let (fd, mut buffer) = match pipe {
            Pipe::Stdout => (
                process
                    .child
                    .stdout
                    .as_ref()
                    .map(|s| s.as_raw_fd())
                    .context("No stdout")?,
                process.stdout_buffer.take().unwrap_or_else(|| Buffer {
                    data: self.buffer_pool.pop().unwrap_or_default(),
                    read: 0,
                }),
            ),
            Pipe::Stderr => (
                process
                    .child
                    .stderr
                    .as_ref()
                    .map(|s| s.as_raw_fd())
                    .context("No stderr")?,
                process.stdout_buffer.take().unwrap_or_else(|| Buffer {
                    data: self.buffer_pool.pop().unwrap_or_default(),
                    read: 0,
                }),
            ),
        };
        let mut expecting_more = true;
        loop {
            match try_read(fd, &mut buffer.data) {
                ReadResult::Done | ReadResult::WouldBlock => break,
                ReadResult::More => continue,
                ReadResult::EOF => {
                    if let Err(err) = poll.registry().deregister(&mut SourceFd(&fd)) {
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
                        Segment::AnsiEscapes(escape) => {
                            apply_raw_display_mode_vt_to_style(&mut new_style, escape)
                        }
                        Segment::Utf8(text) => width += text.width(),
                    }
                }

                if let Some(workspace) = self.workspaces.get_mut(process.workspace_index as usize) {
                    workspace.line_writer.push_line(
                        text,
                        width as u32,
                        process.job_id,
                        process.style,
                    );
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
    pub(crate) fn spawn(
        &mut self,
        poll: &mut Poll,
        workspace_index: WorkspaceIndex,
        job_id: JobId,
        task: TaskConfigRc,
    ) -> anyhow::Result<()> {
        let index = self.processes.vacant_key();
        let tc = task.config();
        let [cmd, args @ ..] = tc.cmd else {
            panic!("Expected atleast one command")
        };
        let workspace = &self.workspaces[workspace_index as usize];
        let mut command = std::process::Command::new(cmd);
        let path = {
            let ws = workspace.handle.state.read().unwrap();
            ws.config.current.base_path.join(tc.pwd)
        };
        command
            .args(args)
            .current_dir(path)
            .envs(tc.envvar.iter().copied());
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
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn().context("Failed to spawn process")?;
        self.wait_thread.thread().unpark();
        if let Some(stdout) = &mut child.stdout {
            unsafe {
                if libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) == -1 {
                    panic!("Failed to set non-blocking");
                }
            }
            poll.registry().register(
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
            poll.registry().register(
                &mut SourceFd(&stderr.as_raw_fd()),
                Token((index << 1) | 1),
                Interest::READABLE,
            )?;
        };
        let process_index = self.processes.insert(ActiveProcess {
            workspace_index,
            job_id,
            alive: true,
            stdout_buffer: None,
            stderr_buffer: None,
            style: Style::default(),
            child,
        });
        {
            let log_start = workspace.handle.logs.read().unwrap().head();
            let mut ws = workspace.handle.state.write().unwrap();
            ws.active_jobs.push(Job {
                job_id,
                process_index,
                task,
                started_at: std::time::Instant::now(),
                log_start,
            })
        }
        Ok(())
    }
}

pub(crate) enum ProcessRequest {
    Spawn {
        task: TaskConfigRc,
        workspace_id: WorkspaceIndex,
        job_id: JobId,
    },
    AttachClient {
        stdin: OwnedFd,
        stdout: OwnedFd,
        socket: UnixStream,
        workspace_config: PathBuf,
    },
    ProcessExited(u32),
    GlobalTermination,
}

pub(crate) struct VtuiChannel {
    pub(crate) waker: vtui::event::polling::Waker,
    pub(crate) events: Mutex<Vec<()>>,
}

impl VtuiChannel {
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
    pub(crate) fn send(&self, req: ()) {
        if let Err(err) = self.try_send(req) {
            kvlog::error!("Failed to send request", ?err);
        }
    }
}

pub(crate) struct MioChannel {
    pub(crate) waker: mio::Waker,
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
    pub(crate) worker_thread: Option<std::thread::JoinHandle<()>>,
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
        let entry = WorkspaceEntry {
            line_writer,
            handle: handle.clone(),
        };
        let index = self.workspaces.insert(entry) as WorkspaceIndex;
        self.workspace_map
            .insert(workspace_config.to_path_buf().into_boxed_path(), index);
        Ok(index)
    }
    fn handle_request(&mut self, poll: &mut Poll, req: ProcessRequest) -> bool {
        match req {
            ProcessRequest::AttachClient {
                stdin,
                stdout,
                socket,
                workspace_config,
            } => {
                let ws_index = match self.workspace_index(workspace_config) {
                    Ok(ws) => ws,
                    Err(err) => {
                        kvlog::info!("Error spawning workspace", %err);
                        return false;
                    }
                };
                let ws = &mut self.workspaces[ws_index as usize];
                let ws_handle = ws.handle.clone();
                let vtui_channel = Arc::new(VtuiChannel {
                    waker: vtui::event::polling::Waker::new().unwrap(),
                    events: Mutex::new(Vec::new()),
                });
                let next = self.clients.vacant_key();
                let _ = poll.registry().register(
                    &mut SourceFd(&socket.as_raw_fd()),
                    TokenHandle::Client(next as u32).into(),
                    Interest::READABLE,
                );
                let _ = socket.set_nonblocking(true);
                let client_entry = ClientEntry {
                    channel: vtui_channel.clone(),
                    workspace: ws_index,
                    socket,
                };
                let index = self.clients.insert(client_entry);
                kvlog::info!("Client Attached");
                std::thread::spawn(move || {
                    if let Err(err) = crate::tui::run(stdin, stdout, ws_handle, vtui_channel) {
                        kvlog::error!("TUI exited with error", %err);
                    }
                });

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
            ProcessRequest::ProcessExited(pid) => {
                for (index, process) in &mut self.processes {
                    if process.child.id() != pid {
                        continue;
                    }
                    kvlog::info!("Found ProcessExited");
                    if let Some(stdin) = process.child.stdout.take() {
                        let mut buffer = process.stdout_buffer.take().unwrap_or_else(|| Buffer {
                            data: self.buffer_pool.pop().unwrap_or_default(),
                            read: 0,
                        });

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
                        if let Some(workspace) =
                            self.workspaces.get_mut(process.workspace_index as usize)
                        {
                            while let Some(line) = buffer.readline() {
                                process.append_line(line, &mut workspace.line_writer);
                            }
                            if !buffer.remaining_slice().is_empty() {
                                process.append_line(
                                    buffer.remaining_slice(),
                                    &mut workspace.line_writer,
                                );
                            }
                        }

                        buffer.reset();
                        self.buffer_pool.push(buffer.data);
                        if let Err(err) = poll
                            .registry()
                            .deregister(&mut SourceFd(&stdin.as_raw_fd()))
                        {
                            kvlog::error!("Failed to unregister fd", ?err);
                        }
                    }
                    if let Some(stderr) = process.child.stderr.take() {
                        let mut buffer = process.stderr_buffer.take().unwrap_or_else(|| Buffer {
                            data: self.buffer_pool.pop().unwrap_or_default(),
                            read: 0,
                        });

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
                        if let Some(workspace) =
                            self.workspaces.get_mut(process.workspace_index as usize)
                        {
                            while let Some(line) = buffer.readline() {
                                process.append_line(line, &mut workspace.line_writer);
                            }
                            if !buffer.remaining_slice().is_empty() {
                                process.append_line(
                                    buffer.remaining_slice(),
                                    &mut workspace.line_writer,
                                );
                            }
                        }
                        buffer.reset();
                        self.buffer_pool.push(buffer.data);
                        if let Err(err) = poll
                            .registry()
                            .deregister(&mut SourceFd(&stderr.as_raw_fd()))
                        {
                            kvlog::error!("Failed to unregister fd", ?err);
                        }
                    }
                    self.processes.remove(index);
                    return false;
                }
                kvlog::info!("Didn't Find ProcessExited");
                return false;
            }
            ProcessRequest::Spawn {
                task,
                job_id,
                workspace_id,
            } => {
                if let Err(err) = self.spawn(poll, workspace_id, job_id, task) {
                    kvlog::error!("Failed to spawn process", ?err, ?job_id);
                }
                return false;
            }
        }
    }
}

pub(crate) fn process_worker(
    request: Arc<MioChannel>,
    wait_thread: std::thread::JoinHandle<()>,
    mut poll: Poll,
) {
    let mut events = Events::with_capacity(128);
    let mut job_manager = ProcessManager {
        clients: Slab::new(),
        request,
        workspace_map: HashMap::new(),
        workspaces: slab::Slab::new(),
        processes: slab::Slab::new(),
        buffer_pool: Vec::new(),
        wait_thread,
    };
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            match TokenHandle::from(event.token()) {
                TokenHandle::RequestChannel => {
                    let mut reqs = Vec::new();
                    job_manager.request.swap_recv(&mut reqs);
                    for req in reqs {
                        if job_manager.handle_request(&mut poll, req) {
                            // Termination requested
                            return;
                        }
                    }
                }
                TokenHandle::Task(pipe) => {
                    if let Err(err) = job_manager.read(&mut poll, pipe.index(), pipe.pipe()) {
                        kvlog::error!("Failed to read from process", ?err, ?pipe);
                    }
                }
                TokenHandle::Client(_) => {
                    kvlog::error!("Received unexpected client token");
                }
            }
        }
        // todo optimize
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
        if (self.0 & 1) == 0 {
            Pipe::Stdout
        } else {
            Pipe::Stderr
        }
    }
    pub fn token(self) -> Token {
        Token(self.0 as usize)
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

impl Drop for ProcessManagerHandle {
    fn drop(&mut self) {
        self.request.send(ProcessRequest::GlobalTermination);
        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

fn wait_thread(req: Arc<MioChannel>) {
    loop {
        let mut status: libc::c_int = 0;
        unsafe {
            let pid = libc::wait(&mut status);
            if pid > 0 {
                req.send(ProcessRequest::ProcessExited(pid as u32))
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

impl ProcessManagerHandle {
    pub(crate) fn spawn() -> std::io::Result<ProcessManagerHandle> {
        let poll = Poll::new()?;
        let request = Arc::new(MioChannel {
            waker: Waker::new(poll.registry(), CHANNEL_TOKEN)?,
            events: Mutex::new(Vec::new()),
        });
        let r = request.clone();
        let main_thread = std::thread::current();
        let worker_thread = std::thread::spawn(move || {
            unsafe {
                // Create a signal set
                let mut mask: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut mask);
                // Add the signals to block to the set
                libc::sigaddset(&mut mask, libc::SIGTERM);
                libc::sigaddset(&mut mask, libc::SIGINT);

                // 2. Block these signals for the calling thread (the spawned thread).
                // This does NOT affect the main thread.
                if libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) != 0 {
                    // In a real app, better error handling is needed here.
                    eprintln!("[Spawned Thread] Failed to set signal mask!");
                }
            }

            main_thread.unpark();
            let r2 = r.clone();
            let wait_thread = std::thread::spawn(move || {
                wait_thread(r2);
            });
            process_worker(r, wait_thread, poll);
        });

        std::thread::park();
        Ok(ProcessManagerHandle {
            request,
            worker_thread: Some(worker_thread),
        })
    }
}
