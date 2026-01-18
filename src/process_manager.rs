use crate::line_width::Segment;
use crate::line_width::apply_raw_display_mode_vt_to_style;
use crate::log_storage;
use crate::log_storage::JobId;
use crate::log_storage::LogWriter;
use crate::log_storage::Logs;
use anyhow::Context;
use mio::Events;
use mio::Interest;
use mio::Poll;
use mio::Token;
use mio::Waker;
use mio::unix::SourceFd;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use unicode_width::UnicodeWidthStr;
use vtui::Style;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Pipe {
    Stdout,
    Stderr,
}

pub(crate) struct ActiveProcess {
    // active stdout
    pub(crate) job_id: JobId,
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

pub(crate) fn process_from_token(token: Token) -> Option<(usize, Pipe)> {
    if token.0 >= 1 << 24 {
        return None;
    }
    let index = token.0 >> 1;
    let pipe = if (token.0 & 1) == 0 {
        Pipe::Stdout
    } else {
        Pipe::Stderr
    };
    Some((index as usize, pipe))
}

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

pub(crate) struct ProcessManager {
    line_writer: LogWriter,
    processes: slab::Slab<ActiveProcess>,
    buffer_pool: Vec<Vec<u8>>,
    wait_thread: std::thread::JoinHandle<()>,
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

                self.line_writer
                    .push_line(text, width as u32, process.job_id, process.style);
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
        job_id: JobId,
        mut command: Command,
    ) -> anyhow::Result<()> {
        let index = self.processes.vacant_key();
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
        self.processes.insert(ActiveProcess {
            job_id,
            alive: true,
            stdout_buffer: None,
            stderr_buffer: None,
            style: Style::default(),
            child,
        });
        Ok(())
    }
}

pub(crate) enum ProcessRequest {
    Spawn {
        command: Box<Command>,
        job_id: JobId,
    },
    ProcessExited(u32),
    GlobalTermination,
}

pub(crate) struct VtuiChannel {
    pub(crate) waker: &'static vtui::event::polling::Waker,
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
    pub(crate) logs: Arc<RwLock<Logs>>,
    pub(crate) request: Arc<MioChannel>,
    pub(crate) response: Arc<VtuiChannel>,
    pub(crate) worker_thread: Option<std::thread::JoinHandle<()>>,
}

impl ProcessManager {
    fn handle_request(&mut self, poll: &mut Poll, req: ProcessRequest) -> bool {
        match req {
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
                        while let Some(line) = buffer.readline() {
                            process.append_line(line, &mut self.line_writer);
                        }
                        if !buffer.remaining_slice().is_empty() {
                            process.append_line(buffer.remaining_slice(), &mut self.line_writer);
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
                        while let Some(line) = buffer.readline() {
                            process.append_line(line, &mut self.line_writer);
                        }
                        if !buffer.remaining_slice().is_empty() {
                            process.append_line(buffer.remaining_slice(), &mut self.line_writer);
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
            ProcessRequest::Spawn { command, job_id } => {
                if let Err(err) = self.spawn(poll, job_id, *command) {
                    kvlog::error!("Failed to spawn process", ?err, ?job_id);
                }
                return false;
            }
        }
    }
}

pub(crate) fn process_worker(
    line_writer: LogWriter,
    request: Arc<MioChannel>,
    resp: Arc<VtuiChannel>,
    wait_thread: std::thread::JoinHandle<()>,
    mut poll: Poll,
) {
    let mut events = Events::with_capacity(128);
    let mut job_manager = ProcessManager {
        line_writer,
        processes: slab::Slab::new(),
        buffer_pool: Vec::new(),
        wait_thread,
    };
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            let tok = event.token();
            if tok == CHANNEL_TOKEN {
                let mut reqs = Vec::new();
                request.swap_recv(&mut reqs);
                for req in reqs {
                    if job_manager.handle_request(&mut poll, req) {
                        // Termination requested
                        return;
                    }
                }
            } else if let Some((id, pipe)) = process_from_token(tok) {
                if let Err(err) = job_manager.read(&mut poll, id, pipe) {
                    kvlog::error!("Failed to read from process", ?err, ?id, ?pipe);
                }
            } else {
                kvlog::error!("Received invalid token", ?tok);
            }
        }
        let _ = resp.wake();
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
    pub(crate) fn spawn(
        waker: &'static vtui::event::polling::Waker,
    ) -> std::io::Result<ProcessManagerHandle> {
        let resp = Arc::new(VtuiChannel {
            waker,
            events: Mutex::new(Vec::new()),
        });
        let writer = log_storage::LogWriter::new();
        let lines = writer.reader();
        let poll = Poll::new()?;
        let request = Arc::new(MioChannel {
            waker: Waker::new(poll.registry(), CHANNEL_TOKEN)?,
            events: Mutex::new(Vec::new()),
        });
        let respx = resp.clone();
        let r = request.clone();
        let wait_thread = std::thread::spawn(move || {
            wait_thread(r);
        });
        let r = request.clone();
        let worker_thread = std::thread::spawn(move || {
            process_worker(writer, r, respx, wait_thread, poll);
        });
        Ok(ProcessManagerHandle {
            logs: lines,
            request,
            response: resp,
            worker_thread: Some(worker_thread),
        })
    }
}
