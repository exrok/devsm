use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::Write;
use std::mem::needs_drop;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use unicode_width::UnicodeWidthStr;
use vtui::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use vtui::vt::BufferWrite;
use vtui::{Rect, Style, TerminalFlags, vt};

use anyhow::Context;

use crate::line_buffer::{JobId, Line, LineId, LineTable, LineTableWriter};
use crate::line_width::{Segment, apply_raw_display_mode_vt_to_style};
use crate::scroll_view::{MultiView, TailView};

mod line_buffer;
mod line_width;
mod scroll_view;

// #[derive(Clone, Copy, PartialEq, Eq, Debug)]
// pub struct JobId(pub u32);

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
    style: Style,
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
    line_writer: LineTableWriter,
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

// let child_pid = child.id();
// let pgid_to_kill = -(child_pid as i32);

// unsafe {
//     // Send SIGTERM for a graceful shutdown. This allows processes
//     // to clean up resources.
//     if libc::kill(pgid_to_kill, libc::SIGTERM) == -1 {
//         // If libc::kill returns -1, an error occurred.
//         let err = std::io::Error::last_os_error();
//         eprintln!(
//             "Failed to send SIGTERM to process group {}: {}",
//             child_pid, err
//         );
//         // In a real-world scenario, you might fallback to SIGKILL here.
//     }
// }

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
                    if let Err(err) = poll.registry().deregister(&mut SourceFd(&fd)) {
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
    fn spawn(
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

enum ProcessRequest {
    Spawn {
        command: Box<Command>,
        job_id: JobId,
    },
}

struct CrosstermChannel {
    waker: &'static vtui::event::polling::Waker,
    events: Mutex<Vec<()>>,
}

impl CrosstermChannel {
    fn wake(&self) -> std::io::Result<()> {
        self.waker.wake()
    }
    fn swap_recv(&self, buf: &mut Vec<()>) {
        let mut events = self.events.lock().unwrap();
        buf.clear();
        std::mem::swap(buf, &mut events);
    }
    fn try_send(&self, req: ()) -> anyhow::Result<()> {
        let mut events = self.events.lock().unwrap();
        events.push(req);
        self.waker.wake()?;
        Ok(())
    }
    fn send(&self, req: ()) {
        if let Err(err) = self.try_send(req) {
            kvlog::error!("Failed to send request", ?err);
        }
    }
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
    lines: Arc<RwLock<LineTable>>,
    request: Arc<MioChannel>,
}

fn process_worker(
    line_writer: LineTableWriter,
    request: Arc<MioChannel>,
    resp: Arc<CrosstermChannel>,
    mut poll: Poll,
) {
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
        let _ = resp.wake();
    }
}

const CHANNEL_TOKEN: Token = Token(1 << 30);
impl ProcessManagerHandle {
    fn spawn(resp: Arc<CrosstermChannel>) -> std::io::Result<ProcessManagerHandle> {
        let writer = line_buffer::LineTableWriter::new();
        let lines = writer.reader();
        let poll = Poll::new()?;
        let request = Arc::new(MioChannel {
            waker: Waker::new(poll.registry(), CHANNEL_TOKEN)?,
            events: Mutex::new(Vec::new()),
        });
        let r = request.clone();
        std::thread::spawn(move || {
            process_worker(writer, r, resp, poll);
        });
        Ok(ProcessManagerHandle { lines, request })
    }
}

/// State for optimized VT list rendered directly to the terminal
/// Smartly using native VT scroll and the native line wrapping of
/// the terminal.
///
/// Assumes the list rendered to the full width of terminal, which
/// is a requirement to make use of the scrolling escape codes.
struct RawListRenderer {
    rect: Rect,
    sub_offset: i32,
    tail: i16,
    last_visible_item_index: usize,
}

fn main() -> anyhow::Result<()> {
    let _log_guard = kvlog::collector::init_file_logger("/tmp/.dfj.log");
    let resp = Arc::new(CrosstermChannel {
        waker: vtui::event::polling::resize_waker().unwrap(),
        events: Mutex::new(Vec::new()),
    });
    let mode = TerminalFlags::RAW_MODE
        | TerminalFlags::MOUSE_CAPTURE
        | TerminalFlags::ALT_SCREEN
        | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
    let mut terminal = vtui::Terminal::open(mode).expect("Valid TTY");
    let mut events = vtui::event::parse::Events::default();
    use std::io::Write;
    let mut buf = Vec::new();
    vt::move_cursor_to_origin(&mut buf);
    buf.extend_from_slice(vt::CLEAR_BELOW);

    terminal.write_all(&buf)?;
    let stdin = std::io::stdin();
    let mut line_buffer = line_buffer::LineTableWriter::new();
    let mut view = MultiView::Tail(TailView::default());
    for i in 0..10 {
        let text = format!("Initial line number {}", i);
        line_buffer.push_line(&text, text.len() as u32, JobId(1), Style::DEFAULT);
    }
    let reader = line_buffer.reader();
    let mut add_next = false;
    let mut scroll_request: Option<i32> = None;
    loop {
        let (w, h) = terminal.size()?;
        let dest = Rect {
            x: 0,
            y: 5,
            width: w,
            height: 5,
        };
        vt::move_cursor(&mut buf, 0, dest.y - 1);
        for i in 0..w {
            buf.push(b'=');
        }
        vt::move_cursor(&mut buf, 0, dest.y + dest.height);
        for i in 0..w {
            buf.push(b'=');
        }
        if let Some(scroll_request) = scroll_request.take() {
            let reader = reader.read().unwrap();
            if scroll_request < 0 {
                view.scroll_down(-scroll_request as u32, &mut buf, dest, reader.view_all());
            } else if scroll_request > 0 {
                view.scroll_up(scroll_request as u32, &mut buf, dest, reader.view_all());
            }
        }
        {
            let reader = reader.read().unwrap();
            if let MultiView::Tail(tail) = &mut view {
                tail.render(&mut buf, dest, reader.view_all());
            }
        }
        terminal.write_all(&buf)?;
        buf.clear();
        match vtui::event::poll(&stdin, None)? {
            vtui::event::Polled::ReadReady => {
                events.read_from(&stdin)?;
            }
            vtui::event::Polled::Woken => {
                // resize event
            }
            vtui::event::Polled::TimedOut => {}
        }
        while let Some(event) = events.next(terminal.is_raw()) {
            if add_next {
                add_next = false;
                let text = format!("{:?}", event);
                line_buffer.push_line(&text, text.len() as u32, JobId(3), Style::DEFAULT);
            }
            match event {
                Event::Key(key_event) => {
                    use KeyCode::*;
                    const CTRL: KeyModifiers = KeyModifiers::CONTROL;
                    // const NORM: KeyModifiers = KeyModifiers::empty();

                    match (key_event.modifiers, key_event.code) {
                        (CTRL, Char('c')) => return Ok(()),
                        (_, Char('n')) => add_next = true,
                        (_, Char('k')) => {
                            if let Some(value) = scroll_request {
                                scroll_request = Some(value + 1);
                            } else {
                                scroll_request = Some(1);
                            }
                        }
                        (_, Char('j')) => {
                            if let Some(value) = scroll_request {
                                scroll_request = Some(value - 1);
                            } else {
                                scroll_request = Some(-1);
                            }
                        }
                        _ => (),
                    }
                }
                Event::Resized => (),
                _ => (),
            }
        }
    }

    Ok(())
}
fn main2() -> anyhow::Result<()> {
    let _log_guard = kvlog::collector::init_file_logger("/tmp/.dfj.log");
    let resp = Arc::new(CrosstermChannel {
        waker: vtui::event::polling::resize_waker().unwrap(),
        events: Mutex::new(Vec::new()),
    });
    let manager = ProcessManagerHandle::spawn(resp)?;
    // let mut comm = Command::new("cargo");
    // comm.arg("run")
    //     .current_dir("/home/user/am/libra/backend")
    //     .env("CARGO_TERM_COLOR", "always");

    let mut comm = Command::new("cargo");
    comm.arg("run")
        .current_dir("/home/user/am/libra/backend")
        .env("CARGO_TERM_COLOR", "always");
    manager.request.send(ProcessRequest::Spawn {
        command: Box::new(comm),
        job_id: JobId(3),
    });
    let mut comm = Command::new("ping");
    comm.arg("127.0.0.1");
    comm.current_dir("/home/user/am/libra/frontend/app")
        .env("FORCE_COLOR", "2");

    manager.request.send(ProcessRequest::Spawn {
        command: Box::new(comm),
        job_id: JobId(2),
    });
    let mut start = LineId::default();

    let mode = TerminalFlags::RAW_MODE
        | TerminalFlags::MOUSE_CAPTURE
        | TerminalFlags::ALT_SCREEN
        | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
    let mut terminal = vtui::Terminal::open(mode).expect("Valid TTY");
    let mut events = vtui::event::parse::Events::default();
    use std::io::Write;
    let mut buf = Vec::new();
    vt::move_cursor_to_origin(&mut buf);
    buf.extend_from_slice(vt::CLEAR_BELOW);
    terminal.write_all(&buf)?;
    let stdin = std::io::stdin();
    loop {
        let lines = manager.lines.read().unwrap();
        // start = lines.for_each_from(start, |_, j, text, _| std::ops::ControlFlow::Continue(()));
        let (w, h) = terminal.size()?;
        buf.clear();
        let dest = Rect {
            x: 0,
            y: 5,
            width: w,
            height: 5,
        };
        vt::move_cursor(&mut buf, 0, dest.y - 1);
        for i in 0..w {
            buf.push(b'=');
        }
        vt::move_cursor(&mut buf, 0, dest.y + dest.height);
        for i in 0..w {
            buf.push(b'=');
        }
        std::fs::write("/tmp/output.txt", &buf);
        terminal.write_all(&buf)?;
        match vtui::event::poll(&stdin, None)? {
            vtui::event::Polled::ReadReady => {
                events.read_from(&stdin)?;
            }
            vtui::event::Polled::Woken => {}
            vtui::event::Polled::TimedOut => {}
        }
        while let Some(event) = events.next(terminal.is_raw()) {
            match event {
                Event::Key(key_event) => {
                    use KeyCode::*;
                    const CTRL: KeyModifiers = KeyModifiers::CONTROL;
                    // const NORM: KeyModifiers = KeyModifiers::empty();
                    match (key_event.modifiers, key_event.code) {
                        (CTRL, Char('c')) => return Ok(()),
                        (_, Char('n')) => return Ok(()),
                        _ => (),
                    }
                }
                Event::Resized => (),
                _ => (),
            }
        }
    }

    Ok(())
}
