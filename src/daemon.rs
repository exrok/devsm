use std::{
    io::{ErrorKind, Read},
    os::{
        fd::OwnedFd,
        unix::{
            io::{AsRawFd, FromRawFd},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};

use anyhow::{Context, bail};
use jsony::Jsony;
use mio::Poll;
use sendfd::RecvWithFd;

use crate::process_manager::{MioChannel, ProcessManagerHandle};

pub const GLOBAL_SOCKET: &str = "/tmp/.dfj.socket";

struct Workspace {
    manager: ProcessManagerHandle,
}

mod unix_path {
    use jsony::{BytesWriter, FromBinary, ToBinary};
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};
    pub fn encode_binary(value: &Path, output: &mut BytesWriter) {
        value.as_os_str().as_bytes().encode_binary(output);
    }
    pub fn decode_binary<'a>(decoder: &mut jsony::binary::Decoder<'a>) -> &'a Path {
        Path::new(OsStr::from_bytes(<&'a [u8]>::decode_binary(decoder)))
    }
}
#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub struct RequestMessage<'a> {
    #[jsony(with = unix_path)]
    pub cwd: &'a Path,
    pub request: Request<'a>,
}

#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub enum Request<'a> {
    AttachTui {
        #[jsony(with = unix_path)]
        config: &'a Path,
    },
}

static SIGNAL_FLAGS: AtomicU64 = AtomicU64::new(0);

// Signal handler for termination signals (SIGINT, SIGTERM)
extern "C" fn term_handler(_sig: i32) {
    SIGNAL_FLAGS.store(1, Ordering::Relaxed);
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

pub fn worker() -> anyhow::Result<()> {
    kvlog::info!("Daemon Starting");
    // Setup signal handlers for graceful termination
    setup_signal_handler(libc::SIGTERM, term_handler)?;
    setup_signal_handler(libc::SIGINT, term_handler)?;

    // Ensure the socket from a previous run is removed
    let _ = std::fs::remove_file(GLOBAL_SOCKET);
    let listener = UnixListener::bind(GLOBAL_SOCKET).context("Failed to bind daemon socket")?;
    kvlog::info!("RPC Socket bound", path = GLOBAL_SOCKET);
    let listener_fd = listener.as_raw_fd();

    let mut buffer = [0u8; 4096 * 16];

    let mut pm = ProcessManagerHandle::spawn()?;

    if SIGNAL_FLAGS.load(Ordering::Relaxed) != 0 {
        kvlog::warn!("Worker terminated.");
    }

    loop {
        // Check for termination signal before blocking
        if SIGNAL_FLAGS.load(Ordering::Relaxed) != 0 {
            kvlog::warn!("Worker terminated.");
            break;
        }

        #[cfg(target_os = "linux")]
        let new_fd = {
            unsafe {
                // Directly call the raw libc::accept function
                libc::accept4(
                    listener_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            }
        };

        #[cfg(not(target_os = "linux"))]
        let new_fd = {
            unsafe {
                let fd = libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut());
                if fd >= 0 {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                }
                fd
            }
        };
        let socket = match new_fd {
            // A new connection was successfully accepted
            fd if fd >= 0 => unsafe {
                // Safely convert the raw file descriptor back into a Rust UnixStream
                UnixStream::from_raw_fd(fd)
            },
            // The accept call returned an error
            _ => {
                let err = std::io::Error::last_os_error();
                // Check if the error was EINTR (Interrupted System Call)
                if err.kind() == ErrorKind::Interrupted {
                    // This is expected when a signal is received.
                    // The loop will continue, check the flag, and then exit.
                    continue;
                } else {
                    // For any other error, log it and continue listening
                    kvlog::error!("Error accepting connection", ?err);
                    continue;
                }
            }
        };
        let mut fds = [0; 2];
        // If we have a valid socket, process the incoming message
        match socket.recv_with_fd(&mut buffer, &mut fds) {
            Ok((amount, fd_count)) => match jsony::from_binary::<RequestMessage>(&buffer[..amount])
            {
                Ok(message) => {
                    kvlog::info!("Message Received", cwd=?message);
                    match message.request {
                        Request::AttachTui { config } => {
                            kvlog::info!("Receiving FD");
                            if fd_count != 2 {
                                return Err(anyhow::anyhow!(
                                    "Expected 2 FDs, received {}",
                                    fd_count
                                ));
                            }
                            unsafe {
                                libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                                libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                            }
                            pm.request
                                .send(crate::process_manager::ProcessRequest::AttachClient {
                                    stdin: unsafe { OwnedFd::from_raw_fd(fds[0]) },
                                    stdout: unsafe { OwnedFd::from_raw_fd(fds[1]) },
                                    socket,
                                    workspace_config: config.into(),
                                });
                        }
                    }
                }
                Err(err) => {
                    kvlog::error!("Failed to parse message", ?err)
                }
            },
            Err(err) => {
                kvlog::error!("Failed to read message", ?err)
            }
        }
    }

    kvlog::warn!("Worker terminated.");
    Ok(())
}
