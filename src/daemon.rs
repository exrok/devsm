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
use crate::rpc::{HEAD_SIZE, Head, MAGIC, RpcMessageKind};

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

/// Filters for test selection (serializable for IPC).
#[derive(Jsony, Debug, Clone, Default)]
#[jsony(Binary)]
pub struct TestFilters<'a> {
    pub include_tags: Vec<&'a str>,
    pub exclude_tags: Vec<&'a str>,
    pub include_names: Vec<&'a str>,
}

/// Query parameters for the logs command.
#[derive(Jsony, Debug, Clone, Default)]
#[jsony(Binary)]
pub struct LogsQuery<'a> {
    pub max_age_secs: Option<u32>,
    pub task_filters: Vec<TaskFilter<'a>>,
    pub job_index: Option<u32>,
    pub kind_filters: Vec<KindFilter<'a>>,
    pub pattern: &'a str,
    pub follow: bool,
    pub retry: bool,
    pub oldest: Option<u32>,
    pub newest: Option<u32>,
    pub without_taskname: bool,
    pub is_tty: bool,
}

#[derive(Jsony, Debug, Clone)]
#[jsony(Binary)]
pub struct TaskFilter<'a> {
    pub name: &'a str,
    pub latest: bool,
}

#[derive(Jsony, Debug, Clone)]
#[jsony(Binary)]
pub struct KindFilter<'a> {
    pub kind: &'a str,
    pub latest: bool,
}

#[derive(Jsony, Debug)]
#[jsony(Binary)]
pub enum Request<'a> {
    AttachTui {
        #[jsony(with = unix_path)]
        config: &'a Path,
    },
    AttachRun {
        #[jsony(with = unix_path)]
        config: &'a Path,
        name: Box<str>,
        params: ValueMap<'a>,
        as_test: bool,
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
    AttachLogs {
        #[jsony(with = unix_path)]
        config: &'a Path,
        query: LogsQuery<'a>,
    },
    GetSelfLogs {
        follow: bool,
    },
}

use crate::process_manager::ReceivedFds;

unsafe fn convert_received_fds(raw_fds: &[i32], fd_count: usize) -> Option<ReceivedFds> {
    for &fd in &raw_fds[..fd_count] {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }

    match fd_count {
        0 => Some(ReceivedFds::None),
        1 => Some(ReceivedFds::Single(unsafe { File::from_raw_fd(raw_fds[0]) })),
        2 => unsafe { Some(ReceivedFds::Pair([File::from_raw_fd(raw_fds[0]), File::from_raw_fd(raw_fds[1])])) },
        _ => {
            kvlog::error!("Unexpected FD count", fd_count);
            for &fd in &raw_fds[..fd_count] {
                unsafe { libc::close(fd) };
            }
            None
        }
    }
}

fn handle_request(
    pm: &ProcessManagerHandle,
    socket: UnixStream,
    message: RequestMessage,
    fds: ReceivedFds,
) -> anyhow::Result<()> {
    match message.request {
        Request::AttachTui { config } => {
            kvlog::info!("Receiving FD");
            let ReceivedFds::Pair([stdin, stdout]) = fds else {
                bail!("Expected 2 FDs");
            };
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: Some(stdin),
                stdout: Some(stdout),
                socket,
                workspace_config: config.into(),
                kind: crate::process_manager::AttachKind::Tui,
            });
        }
        Request::AttachRun { config, name, params, as_test } => {
            kvlog::info!("Receiving FD for run command", as_test);
            let ReceivedFds::Pair([stdin, stdout]) = fds else {
                bail!("Expected 2 FDs");
            };
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: Some(stdin),
                stdout: Some(stdout),
                socket,
                workspace_config: config.into(),
                kind: crate::process_manager::AttachKind::Run {
                    task_name: name,
                    params: jsony::to_binary(&params),
                    as_test,
                },
            });
        }
        Request::AttachTests { config, filters } => {
            kvlog::info!("Receiving FD for test command");
            let ReceivedFds::Pair([stdin, stdout]) = fds else {
                bail!("Expected 2 FDs");
            };
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: Some(stdin),
                stdout: Some(stdout),
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
        Request::AttachLogs { config, query } => {
            kvlog::info!("Receiving FD for logs command");
            let ReceivedFds::Pair([stdin, stdout]) = fds else {
                bail!("Expected 2 FDs for logs");
            };
            pm.request.send(crate::process_manager::ProcessRequest::AttachClient {
                stdin: Some(stdin),
                stdout: Some(stdout),
                socket,
                workspace_config: config.into(),
                kind: crate::process_manager::AttachKind::Logs { query: jsony::to_binary(&query) },
            });
        }
        Request::GetSelfLogs { follow } => {
            if follow {
                let ReceivedFds::Single(stdout) = fds else {
                    bail!("Expected 1 FD for self-logs follow");
                };
                pm.request.send(crate::process_manager::ProcessRequest::AttachSelfLogsClient { stdout, socket });
            } else {
                let logs = crate::self_log::get_daemon_logs().unwrap_or_default();
                let mut socket = socket;
                let _ = socket.write_all(&logs);
            }
        }
    }
    Ok(())
}

fn is_rpc_message(buffer: &[u8]) -> bool {
    if buffer.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    magic == MAGIC
}

fn handle_rpc_connection(pm: &ProcessManagerHandle, socket: UnixStream, buffer: &[u8], fds: ReceivedFds) {
    if buffer.len() < HEAD_SIZE {
        kvlog::error!("RPC message too short");
        return;
    }

    let header_bytes: &[u8; HEAD_SIZE] = buffer[..HEAD_SIZE].try_into().unwrap();
    let head = match Head::from_bytes(header_bytes) {
        Ok(h) => h,
        Err(e) => {
            kvlog::error!("Failed to parse RPC header", ?e);
            return;
        }
    };

    let Some(kind) = RpcMessageKind::from_u16(head.kind) else {
        kvlog::error!("Unknown RPC message kind", kind = head.kind);
        return;
    };

    let total_len = HEAD_SIZE + head.len as usize;
    if buffer.len() < total_len {
        kvlog::error!("RPC payload incomplete", expected = total_len, actual = buffer.len());
        return;
    }

    let payload = &buffer[HEAD_SIZE..total_len];

    pm.request.send(crate::process_manager::ProcessRequest::RpcMessage {
        socket,
        fds,
        kind,
        correlation: head.correlation,
        one_shot: head.one_shot,
        payload: payload.to_vec(),
    });
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
            let mut raw_fds = [0; 2];
            match socket.recv_with_fd(&mut buffer, &mut raw_fds) {
                Ok((amount, fd_count)) => {
                    // Safety - raw_fds are valid FDs received from recvmsg.
                    let fds = unsafe { convert_received_fds(&raw_fds, fd_count) };
                    let Some(fds) = fds else {
                        continue;
                    };

                    if is_rpc_message(&buffer[..amount]) {
                        handle_rpc_connection(&pm, socket, &buffer[..amount], fds);
                    } else {
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
                }
                Err(err) => {
                    kvlog::error!("Failed to read message", ?err)
                }
            }
        }
    });

    Ok(())
}
