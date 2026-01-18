use std::{
    io::{ErrorKind, Read, Write},
    os::{
        fd::RawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::bail;
use libc::sigwait;
use sendfd::SendWithFd;

use crate::{
    config::{BumpEval, TaskConfig, WorkspaceConfig, load_from_env},
    daemon::GLOBAL_SOCKET,
};

mod config;
mod daemon;
mod line_width;
mod log_storage;
mod process_manager;
mod scroll_view;
mod tui;
mod workspace;

fn unmanaged_exec(ws: &WorkspaceConfig, task: &TaskConfig) {
    let [cmd, args @ ..] = task.cmd else {
        panic!("Expected atleast one command")
    };
    let path = ws.base_path.join(task.pwd);
    println!("in {:?}", path);
    let _ = std::process::Command::new(cmd)
        .args(args)
        .current_dir(path)
        .envs(task.envvar.iter().copied())
        .exec();
    panic!()
}

fn main_simple_run() {
    let config = load_from_env().unwrap();
    let mut args = std::env::args();
    args.next();
    let arg = args.next().expect("Arg");
    let (task, profile) = arg.rsplit_once(":").unwrap_or((&arg, ""));
    let task = config.task_by_name(task).expect("Unknown task");
    let bump = bumpalo::Bump::new();
    let task = task
        .bump_eval(&config::Enviroment { profile }, &bump)
        .unwrap();
    unmanaged_exec(&config, &task);
}

fn main() {
    let mut args = std::env::args();
    args.next();
    let mode = args.next().expect("Arg");
    if mode == "client" {
        client().unwrap();
    }
    if mode == "server" {
        let _log_guard = kvlog::collector::init_file_logger("/tmp/.dfj.log");
        if let Err(err) = daemon::worker() {
            kvlog::error!("Daemon terminated with error", ?err);
        }
    }
}

const RESIZE_CODE: u32 = 0x85_06_09_44;
const TERMINATION_CODE: u32 = 0xcf_04_43_58;

// Bit 0 is for termination, Bit 1 is for resize
const TERMINATION_FLAG: u64 = 1 << 0;
const RESIZE_FLAG: u64 = 1 << 1;

static SIGNAL_FLAGS: AtomicU64 = AtomicU64::new(0);

// Signal handler for termination signals (SIGINT, SIGTERM)
extern "C" fn term_handler(_sig: i32) {
    SIGNAL_FLAGS.fetch_or(TERMINATION_FLAG, Ordering::Relaxed);
}

// Signal handler for window resize signal (SIGWINCH)
extern "C" fn winch_handler(_sig: i32) {
    SIGNAL_FLAGS.fetch_or(RESIZE_FLAG, Ordering::Relaxed);
}

// Helper function to set up a signal handler using libc::sigaction
fn setup_signal_handler(sig: i32, handler: unsafe extern "C" fn(i32)) -> anyhow::Result<()> {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as libc::sighandler_t;
        // Do not set SA_RESTART, so that system calls are interrupted
        sa.sa_flags = 0;
        // Block all signals while the handler is running
        libc::sigfillset(&mut sa.sa_mask);

        if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
            bail!(
                "Failed to set signal handler for signal {}: {}",
                sig,
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

fn connect_or_spawn_daemon() -> std::io::Result<UnixStream> {
    if let Ok(socket) = UnixStream::connect(GLOBAL_SOCKET) {
        return Ok(socket);
    }
    let current_exe = std::env::current_exe()?;
    let mut command = std::process::Command::new(current_exe);
    command.arg("server");
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    unsafe {
        command.pre_exec(|| {
            // setsid() creates a new session and detaches the process from
            // the controlling terminal of the parent (the client).
            // This prevents SIGTTOU when the daemon tries to configure the
            // client's TTY later.
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    command.spawn()?;
    for _ in 0..1000 {
        std::thread::sleep(Duration::from_millis(1));
        if let Ok(socket) = UnixStream::connect(GLOBAL_SOCKET) {
            return Ok(socket);
        }
    }
    Err(std::io::Error::new(
        ErrorKind::TimedOut,
        "Failed to connect to daemon",
    ))
}

fn client() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find dfj.js in current or parent directories"))?;

    // Register the signal handlers using libc directly
    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;
    setup_signal_handler(libc::SIGWINCH, winch_handler)?;

    let mut socket = connect_or_spawn_daemon()?;

    // socket.write_all()?;
    socket.send_with_fd(
        &jsony::to_binary(&daemon::RequestMessage {
            cwd: &cwd,
            request: daemon::Request::AttachTui { config: &config },
        }),
        &[0, 1],
    )?;

    let mut buf = [0; 4];

    loop {
        let flags = SIGNAL_FLAGS.swap(0, Ordering::Relaxed);

        if flags & TERMINATION_FLAG != 0 {
            socket.write_all(&TERMINATION_CODE.to_ne_bytes())?;
            return Ok(());
        }

        if flags & RESIZE_FLAG != 0 {
            socket.write_all(&RESIZE_CODE.to_ne_bytes())?;
        }
        match socket.read(&mut buf) {
            Ok(_) => {
                let received_code = u32::from_ne_bytes(buf);
                if received_code == TERMINATION_CODE {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                kvlog::info!("Interuped")
            }
            Err(e) => {
                bail!("Socket read failed: {}", e);
            }
        }
    }

    Ok(())
}

// fn server() -> anyhow::Result<()> {
//     let _ = std::fs::remove_file("/tmp/.dfj");
//     let listener = std::os::unix::net::UnixListener::bind("/tmp/.dfj")?;
//     loop {
//         let (mut socket, _) = listener.accept()?;
//         std::thread::spawn(move || {
//             handler(socket).unwrap();
//         });
//     }

//     Ok(())
// }

// fn handler(mut stream: UnixStream) -> anyhow::Result<()> {
//     let stdin_fd = stream.recv_fd()?;
//     let stdout_fd = stream.recv_fd()?;

//     use std::process::Command;

//     use vtui::event::polling::GlobalWakerConfig;
//     use vtui::event::{Event, KeyCode, KeyModifiers};
//     use vtui::vt::BufferWrite;
//     use vtui::{Color, Rect, Style, TerminalFlags, vt};

//     let mode = TerminalFlags::RAW_MODE
//         | TerminalFlags::HIDE_CURSOR
//         | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
//     let mut terminal = vtui::Terminal::new(stdout_fd, mode).expect("Valid TTY");
//     let (w, h) = terminal.size().unwrap();
//     let mut events = vtui::event::parse::Events::default();
//     let mut render_frame = vtui::DoubleBuffer::new(w, h);
//     loop {
//         match vtui::event::poll_with_custom_waker(&stdin_fd, None, None)? {
//             vtui::event::Polled::ReadReady => {
//                 events.read_from(&stdin_fd)?;
//             }
//             vtui::event::Polled::Woken => {}
//             vtui::event::Polled::TimedOut => {}
//         }
//         let (w, h) = terminal.size().unwrap();
//         render_frame.resize(w, h);
//         let rect = render_frame.rect();
//         while let Some(event) = events.next(terminal.is_raw()) {
//             rect.with(Color(2).as_fg())
//                 .text(&mut render_frame, &format!("{:?}", event));
//         }

//         render_frame.render(&mut terminal);
//     }
//     Ok(())
// }
