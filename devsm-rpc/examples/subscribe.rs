//! Example demonstrating subscription to workspace events via RPC.
//!
//! Connects to the devsm daemon, opens a workspace, and prints all job status
//! and exit events to stdout.
//!
//! # Usage
//!
//! ```bash
//! cargo run -p devsm-rpc --example subscribe -- /path/to/devsm.toml
//! ```

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use devsm_rpc::{ClientProtocol, DecodeResult, JobExitedEvent, JobStatusEvent, RpcMessageKind};
use jsony::ToBinary;

const SOCKET_PATH: &str = "/tmp/.devsm.socket";

/// Encodes an AttachRpc request message in jsony binary format.
///
/// The format matches the daemon's RequestMessage struct:
/// - cwd: length-prefixed byte string (path)
/// - request: enum discriminant (4 for AttachRpc) + variant fields
///   - config: length-prefixed byte string (path)
///   - subscribe: bool as u8
fn encode_attach_rpc(cwd: &Path, config: &Path, subscribe: bool) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    let mut out = jsony::BytesWriter::new();

    // Encode cwd path (length-prefixed bytes)
    let cwd_bytes = cwd.as_os_str().as_bytes();
    cwd_bytes.encode_binary(&mut out);

    // Encode Request enum discriminant (AttachRpc = variant index 4)
    out.push(4);

    // Encode AttachRpc fields:
    // - config path (length-prefixed bytes)
    let config_bytes = config.as_os_str().as_bytes();
    config_bytes.encode_binary(&mut out);

    // - subscribe bool
    subscribe.encode_binary(&mut out);

    out.into_vec()
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("devsm.toml");

    if !Path::new(config_path).exists() {
        anyhow::bail!("Config file not found: {}", config_path);
    }

    let config_path = std::fs::canonicalize(config_path)?;
    let config_str = config_path.to_string_lossy();

    println!("Connecting to daemon at {}", SOCKET_PATH);
    let mut socket = UnixStream::connect(SOCKET_PATH)?;

    let cwd = std::env::current_dir()?;
    let encoded = encode_attach_rpc(&cwd, &config_path, true);
    socket.write_all(&encoded)?;

    println!("Opening workspace: {}", config_str);
    println!("Subscribed to all events. Waiting for events...\n");

    let mut protocol = ClientProtocol::new();
    let mut read_buf = Vec::with_capacity(4096);

    loop {
        let mut chunk = [0u8; 4096];
        let n = socket.read(&mut chunk)?;
        if n == 0 {
            println!("Connection closed by server");
            break;
        }
        read_buf.extend_from_slice(&chunk[..n]);

        loop {
            match protocol.decode(&read_buf) {
                DecodeResult::Message { kind, correlation, payload } => {
                    handle_message(kind, correlation, payload);
                }
                DecodeResult::MissingData { .. } => break,
                DecodeResult::Empty => {
                    read_buf.clear();
                    break;
                }
                DecodeResult::Error(e) => {
                    eprintln!("Protocol error: {e}");
                    return Ok(());
                }
            }
        }
        protocol.compact(&mut read_buf, 4096);
    }

    Ok(())
}

fn handle_message(kind: RpcMessageKind, correlation: u16, payload: &[u8]) {
    match kind {
        RpcMessageKind::OpenWorkspaceAck => {
            let response: devsm_rpc::OpenWorkspaceResponse =
                jsony::from_binary(payload).expect("invalid payload");
            if response.success {
                println!("[ACK] Workspace opened successfully");
            } else {
                let error = response.error.as_deref().unwrap_or("unknown error");
                eprintln!("[ACK] Failed to open workspace: {}", error);
            }
        }
        RpcMessageKind::JobStatus => {
            let event: JobStatusEvent = jsony::from_binary(payload).expect("invalid payload");
            println!(
                "[EVENT] JobStatus: job_index={}, status={:?}",
                event.job_index, event.status
            );
        }
        RpcMessageKind::JobExited => {
            let event: JobExitedEvent = jsony::from_binary(payload).expect("invalid payload");
            println!(
                "[EVENT] JobExited: job_index={}, exit_code={}, cause={:?}",
                event.job_index, event.exit_code, event.cause
            );
        }
        RpcMessageKind::Disconnect => {
            println!("[EVENT] Disconnect received");
        }
        _ => {
            println!(
                "[MSG] kind={:?}, correlation={}, payload_len={}",
                kind,
                correlation,
                payload.len()
            );
        }
    }
}
