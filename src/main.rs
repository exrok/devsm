use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::Context;

use crate::line_buffer::{LineBuffer, LineBufferWriter};

mod line_buffer;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct JobId(pub u32);

#[derive(Clone, Copy, Debug)]
enum Pipe {
    Stdout,
    Stderr,
}

struct ActiveProcess {
    // active stdout
    job_id: JobId,
    alive: bool,
    stdout_buffer: Option<Buffer>,
    stderr_buffer: Option<Buffer>,
    child: Child,
}

struct Buffer {
    data: Vec<u8>,
    read: usize,
}

type ProcessIndex = usize;

fn process_from_token(token: Token) -> Option<(usize, Pipe)> {
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
    fn is_empty(&self) -> bool {
        self.read >= self.data.len()
    }
    fn reset(&mut self) {
        self.data.clear();
        self.read = 0;
    }
    fn readline(&mut self) -> Option<&[u8]> {
        if let Some(pos) = self.data[self.read..].iter().position(|&b| b == b'\n') {
            let line = &self.data[self.read..self.read + pos];
            self.read += pos + 1;
            Some(line)
        } else {
            None
        }
    }
}

struct ProcessManager {
    line_writer: LineBufferWriter,
    processes: slab::Slab<ActiveProcess>,
    buffer_pool: Vec<Vec<u8>>,
}

enum ReadResult {
    Done,
    More,
    EOF,
    WouldBlock,
    OtherError(std::io::ErrorKind),
}

fn try_read(fd: RawFd, buffer: &mut Vec<u8>) -> ReadResult {
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
    fn read(&mut self, poll: &mut Poll, index: ProcessIndex, pipe: Pipe) -> anyhow::Result<()> {
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
                    if let Err(err) = poll.registry().register(
                        &mut SourceFd(&fd),
                        Token((index << 1) | (pipe as usize)),
                        Interest::READABLE,
                    ) {
                        kvlog::error!("Failed to unregister fd", ?err);
                    }
                    match pipe {
                        Pipe::Stdout => process.stdout_buffer = None,
                        Pipe::Stderr => process.stderr_buffer = None,
                    }
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
                self.line_writer.push_line(text, 0, process.job_id);
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
    fn spawn(
        &mut self,
        poll: &mut Poll,
        job_id: JobId,
        mut command: Command,
    ) -> anyhow::Result<()> {
        let index = self.processes.vacant_key();
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let mut child = command.spawn().context("Failed to spawn process")?;

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
            child,
        });
        Ok(())
    }
}

enum ProcessRequest {
    Spawn {
        command: Box<Command>,
        job_id: JobId,
    },
}

struct MioChannel {
    waker: Waker,
    events: Mutex<Vec<ProcessRequest>>,
}
impl MioChannel {
    fn swap_recv(&self, buf: &mut Vec<ProcessRequest>) {
        let mut events = self.events.lock().unwrap();
        buf.clear();
        std::mem::swap(buf, &mut events);
    }
    fn try_send(&self, req: ProcessRequest) -> anyhow::Result<()> {
        let mut events = self.events.lock().unwrap();
        events.push(req);
        self.waker.wake()?;
        Ok(())
    }
    fn send(&self, req: ProcessRequest) {
        if let Err(err) = self.try_send(req) {
            kvlog::error!("Failed to send request", ?err);
        }
    }
}

struct ProcessManagerHandle {
    lines: Arc<RwLock<LineBuffer>>,
    request: Arc<MioChannel>,
}

fn process_worker(line_writer: LineBufferWriter, request: Arc<MioChannel>, mut poll: Poll) {
    let mut events = Events::with_capacity(128);
    let mut job_manager = ProcessManager {
        line_writer,
        processes: slab::Slab::new(),
        buffer_pool: Vec::new(),
    };
    loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            let tok = event.token();
            if tok == CHANNEL_TOKEN {
                let mut reqs = Vec::new();
                request.swap_recv(&mut reqs);
                for req in reqs {
                    match req {
                        ProcessRequest::Spawn { command, job_id } => {
                            if let Err(err) = job_manager.spawn(&mut poll, job_id, *command) {
                                kvlog::error!("Failed to spawn process", ?err, ?job_id);
                            }
                        }
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
    }
}

const CHANNEL_TOKEN: Token = Token(1 << 30);
impl ProcessManagerHandle {
    fn spawn() -> std::io::Result<ProcessManagerHandle> {
        let writer = line_buffer::LineBufferWriter::new();
        let lines = writer.reader();
        let poll = Poll::new()?;
        let request = Arc::new(MioChannel {
            waker: Waker::new(poll.registry(), CHANNEL_TOKEN)?,
            events: Mutex::new(Vec::new()),
        });
        let r = request.clone();
        std::thread::spawn(move || {
            process_worker(writer, r, poll);
        });
        Ok(ProcessManagerHandle { lines, request })
    }
}

fn main() -> anyhow::Result<()> {
    let manager = ProcessManagerHandle::spawn()?;
    let mut comm = Command::new("ping");
    comm.arg("127.0.0.1");
    manager.request.send(ProcessRequest::Spawn {
        command: Box::new(comm),
        job_id: JobId(32),
    });
    // let mut comm = Command::new("ping");
    // comm.arg("1.1.1.1");
    // manager.request.send(ProcessRequest::Spawn {
    //     command: Box::new(comm),
    //     job_id: JobId(54),
    // });
    for _ in 1..100 {
        std::thread::sleep(Duration::from_millis(500));
        let lines = manager.lines.read().unwrap();
        lines.for_each(|_, j, text, _| {
            println!("{j:?}: {text}");
            std::ops::ControlFlow::Continue(())
        });
    }

    Ok(())
}
