use std::{
    io::ErrorKind,
    os::{
        fd::OwnedFd,
        unix::{
            io::{AsRawFd, FromRawFd},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
};

use anyhow::{Context, bail};
use jsony::Jsony;
use jsony_value::ValueMap;
use sendfd::RecvWithFd;

use crate::process_manager::ProcessManagerHandle;

pub const GLOBAL_SOCKET: &str = "/tmp/.devsm.socket";

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
pub enum WorkspaceCommand<'a> {
    RestartSelected,
    GetPanicLocation,
    Run { name: Box<str>, params: ValueMap<'a> },
}

#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub enum Request<'a> {
    WorkspaceCommand {
        #[jsony(with = unix_path)]
        config: &'a Path,
        command: WorkspaceCommand<'a>,
    },
    AttachTui {
        #[jsony(with = unix_path)]
        config: &'a Path,
    },
    AttachRun {
        #[jsony(with = unix_path)]
        config: &'a Path,
        name: Box<str>,
        params: ValueMap<'a>,
    },
}

struct FdSet<'a>(&'a [i32]);

impl<'a> FdSet<'a> {
    unsafe fn new(fds: &'a [i32]) -> Self {
        for fd in fds {
            let _ = unsafe { libc::fcntl(*fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        FdSet(fds)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn pop_front(&mut self) -> Option<OwnedFd> {
        if self.0.is_empty() {
            None
        } else {
            let fd = self.0[0];
            self.0 = &self.0[1..];
            Some(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
}

impl<'a> Drop for FdSet<'a> {
    fn drop(&mut self) {
        for &fd in self.0 {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

fn handle_request(
    pm: &ProcessManagerHandle,
    socket: UnixStream,
    message: RequestMessage,
    mut fds: FdSet,
) -> anyhow::Result<()> {
    match message.request {
        Request::WorkspaceCommand { config, command } => {
            kvlog::info!("Restarting selected processes");
            pm.request.send(crate::process_manager::ProcessRequest::WorkspaceCommand {
                socket,
                // hack for now.
                command: jsony::to_binary(&command),
                workspace_config: config.into(),
            });
        }
        Request::AttachTui { config } => {
            kvlog::info!("Receiving FD");
            if fds.len() != 2 {
                bail!("Expected 2 FD's found only one");
            }
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: fds.pop_front().unwrap(),
                stdout: fds.pop_front().unwrap(),
                socket,
                workspace_config: config.into(),
            });
        }
        Request::AttachRun { config, name, params } => {
            kvlog::info!("Receiving FD for run command");
            if fds.len() != 2 {
                bail!("Expected 2 FD's found only one");
            }
            pm.request.send(crate::process_manager::ProcessRequest::AttachRun {
                stdin: fds.pop_front().unwrap(),
                stdout: fds.pop_front().unwrap(),
                socket,
                workspace_config: config.into(),
                task_name: name,
                params: jsony::to_binary(&params),
            });
        }
    }
    Ok(())
}

pub fn worker() -> anyhow::Result<()> {
    kvlog::info!("Daemon Starting");
    // Setup signal handlers for graceful termination

    // Ensure the socket from a previous run is removed
    let _ = std::fs::remove_file(GLOBAL_SOCKET);
    let listener = UnixListener::bind(GLOBAL_SOCKET).context("Failed to bind daemon socket")?;
    kvlog::info!("RPC Socket bound", path = GLOBAL_SOCKET);
    let listener_fd = listener.as_raw_fd();

    let mut buffer = [0u8; 4096 * 16];

    let _ = ProcessManagerHandle::global_block_on(move |pm| {
        loop {
            #[cfg(target_os = "linux")]
            let new_fd = {
                unsafe {
                    // Directly call the raw libc::accept function
                    libc::accept4(listener_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC)
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
                Ok((amount, fd_count)) => {
                    let fds = unsafe { FdSet::new(&fds[..fd_count]) };
                    match jsony::from_binary::<RequestMessage>(&buffer[..amount]) {
                        Ok(message) => {
                            if let Err(err) = handle_request(&pm, socket, message, fds) {
                                kvlog::error!("Failed to handle message", ?err);
                            }
                        }
                        Err(err) => {
                            kvlog::error!("Failed to parse message", ?err);
                        }
                    };
                }
                Err(err) => {
                    kvlog::error!("Failed to read message", ?err)
                }
            }
        }
    });

    Ok(())
}
