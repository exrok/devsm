use std::{
    fs::File,
    io::{ErrorKind, Write},
    os::{
        fd::AsRawFd,
        unix::{
            io::FromRawFd,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::OnceLock,
};

use anyhow::{Context, bail};
use jsony::Jsony;
use jsony_value::ValueMap;
use sendfd::RecvWithFd;

use crate::process_manager::ProcessManagerHandle;

static SOCKET_PATH: OnceLock<String> = OnceLock::new();

/// Returns the path to the Unix domain socket for daemon communication.
///
/// Uses `DEVSM_SOCKET` environment variable if set, otherwise uses the
/// platform-appropriate per-user runtime directory:
/// - Linux: `$XDG_RUNTIME_DIR/devsm.socket`
/// - macOS: `$TMPDIR/devsm.socket`
///
/// Falls back to `/tmp/devsm-<uid>.socket` if the standard directories are unavailable.
pub fn socket_path() -> &'static str {
    SOCKET_PATH.get_or_init(|| {
        if let Ok(path) = std::env::var("DEVSM_SOCKET") {
            return path;
        }

        #[cfg(target_os = "linux")]
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            return format!("{runtime_dir}/devsm.socket");
        }

        #[cfg(target_os = "macos")]
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let tmpdir = tmpdir.trim_end_matches('/');
            return format!("{tmpdir}/devsm.socket");
        }

        let uid = unsafe { libc::getuid() };
        format!("/tmp/devsm-{uid}.socket")
    })
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
pub enum WorkspaceCommand<'a> {
    RestartSelected,
    GetPanicLocation,
    Run { name: Box<str>, params: ValueMap<'a> },
    CallFunction { name: Box<str> },
}

/// Filters for test selection (serializable for IPC).
#[derive(Jsony, Debug, Clone, Default)]
#[jsony(Binary)]
pub struct TestFilters<'a> {
    pub include_tags: Vec<&'a str>,
    pub exclude_tags: Vec<&'a str>,
    pub include_names: Vec<&'a str>,
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
    AttachTests {
        #[jsony(with = unix_path)]
        config: &'a Path,
        filters: TestFilters<'a>,
    },
    AttachRpc {
        #[jsony(with = unix_path)]
        config: &'a Path,
        subscribe: bool,
    },
    GetSelfLogs,
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
    pub fn pop_front(&mut self) -> Option<File> {
        if self.0.is_empty() {
            None
        } else {
            let fd = self.0[0];
            self.0 = &self.0[1..];
            Some(unsafe { File::from_raw_fd(fd) })
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
                stdin: Some(fds.pop_front().unwrap()),
                stdout: Some(fds.pop_front().unwrap()),
                socket,
                workspace_config: config.into(),
                kind: crate::process_manager::AttachKind::Tui,
            });
        }
        Request::AttachRun { config, name, params } => {
            kvlog::info!("Receiving FD for run command");
            if fds.len() != 2 {
                bail!("Expected 2 FD's found only one");
            }
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: Some(fds.pop_front().unwrap()),
                stdout: Some(fds.pop_front().unwrap()),
                socket,
                workspace_config: config.into(),
                kind: crate::process_manager::AttachKind::Run { task_name: name, params: jsony::to_binary(&params) },
            });
        }
        Request::AttachTests { config, filters } => {
            kvlog::info!("Receiving FD for test command");
            if fds.len() != 2 {
                bail!("Expected 2 FD's found only one");
            }
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: Some(fds.pop_front().unwrap()),
                stdout: Some(fds.pop_front().unwrap()),
                socket,
                workspace_config: config.into(),
                kind: crate::process_manager::AttachKind::TestRun { filters: jsony::to_binary(&filters) },
            });
        }
        Request::AttachRpc { config, subscribe } => {
            kvlog::info!("Attaching RPC client");
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: None,
                stdout: None,
                socket,
                workspace_config: config.into(),
                kind: crate::process_manager::AttachKind::Rpc { subscribe },
            });
        }
        Request::GetSelfLogs => {
            let logs = crate::self_log::get_daemon_logs().unwrap_or_default();
            let mut socket = socket;
            let _ = socket.write_all(&logs);
        }
    }
    Ok(())
}

pub fn worker() -> anyhow::Result<()> {
    kvlog::info!("Daemon Starting");

    let socket = socket_path();
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).context("Failed to bind daemon socket")?;
    kvlog::info!("RPC Socket bound", path = socket);
    let listener_fd = listener.as_raw_fd();

    let mut buffer = [0u8; 4096 * 16];

    let _ = ProcessManagerHandle::global_block_on(move |pm| {
        loop {
            #[cfg(target_os = "linux")]
            let new_fd = {
                unsafe { libc::accept4(listener_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) }
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
                fd if fd >= 0 => unsafe { UnixStream::from_raw_fd(fd) },
                _ => {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == ErrorKind::Interrupted {
                        continue;
                    } else {
                        kvlog::error!("Error accepting connection", ?err);
                        continue;
                    }
                }
            };
            let mut fds = [0; 2];
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
