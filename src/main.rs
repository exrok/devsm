#![allow(unused, dead_code)]
use std::{
    io::{ErrorKind, Read, Write},
    os::unix::{net::UnixStream, process::CommandExt},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::bail;
use sendfd::SendWithFd;

use crate::daemon::{GLOBAL_SOCKET, WorkspaceCommand};

mod cli;
mod config;
mod daemon;
mod line_width;
mod log_storage;
mod process_manager;
mod scroll_view;
mod searcher;
mod tui;
mod workspace;

fn main() {
    let mut args = std::env::args();
    args.next();
    let args = args.collect::<Vec<_>>();
    let (_config, command) = cli::parse(&args).unwrap();
    match command {
        cli::Command::Cli => {
            let _log_guard = kvlog::collector::init_file_logger("/tmp/.client.devsm.log");
            client().unwrap();
            return;
        }
        cli::Command::Server => {
            let _log_guard = kvlog::collector::init_file_logger("/tmp/.devsm.log");
            if let Err(err) = daemon::worker() {
                kvlog::error!("Daemon terminated with error", ?err);
            }
        }
        cli::Command::RestartSelected => {
            workspace_command(WorkspaceCommand::RestartSelected).unwrap();
        }
        cli::Command::TriggerPrimary => todo!(),
        cli::Command::TriggerSecondary => todo!(),
        cli::Command::Run { job, value_map } => {
            workspace_command(WorkspaceCommand::Run { name: job.into(), params: value_map }).unwrap()
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
            bail!("Failed to set signal handler for signal {}: {}", sig, std::io::Error::last_os_error());
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
    Err(std::io::Error::new(ErrorKind::TimedOut, "Failed to connect to daemon"))
}

fn workspace_command(command: WorkspaceCommand) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

    let mut socket = connect_or_spawn_daemon()?;
    socket.write_all(&jsony::to_binary(&daemon::RequestMessage {
        cwd: &cwd,
        request: daemon::Request::WorkspaceCommand { config: &config, command },
    }))?;
    std::io::copy(&mut socket, &mut std::io::stdout())?;
    Ok(())
}

fn client() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let config = config::find_config_path_from(&cwd)
        .ok_or_else(|| anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))?;

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
            Ok(amount) => {
                if amount == 0 {
                    break;
                }
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
