use std::env;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::process;

/// Binary protocol for test-app <-> test harness communication.
///
/// Header: 10 bytes, little-endian
///   magic:  u32  (0x7E570001)
///   kind:   u16  (message type)
///   len:    u32  (payload length)
///
/// Message kinds:
///   0x01  Connect       (app -> server)  payload: u16 pwd_len + pwd_bytes
///                                                 + u16 argc + (u16 len + bytes) per arg
///   0x02  WriteStdout   (server -> app)  payload: raw bytes to write
///   0x03  WriteStderr   (server -> app)  payload: raw bytes to write
///   0x04  Exit          (server -> app)  payload: i32 exit code (LE)
const MAGIC: u32 = 0x7E57_0001;
const HEADER_SIZE: usize = 10;

const CONNECT: u16 = 0x01;
const WRITE_STDOUT: u16 = 0x02;
const WRITE_STDERR: u16 = 0x03;
const EXIT: u16 = 0x04;

fn main() {
    let socket_path = env::var_os("TEST_APP_SOCKET").unwrap_or_else(|| {
        eprintln!("TEST_APP_SOCKET environment variable not set");
        process::exit(1);
    });

    let mut stream = UnixStream::connect(&socket_path).unwrap_or_else(|e| {
        eprintln!("connect: {e}");
        process::exit(1);
    });

    send_connect(&mut stream);

    let mut hdr = [0u8; HEADER_SIZE];
    let mut payload = Vec::new();
    loop {
        if stream.read_exact(&mut hdr).is_err() {
            break;
        }

        let hdr: &[u8] = &hdr;
        let (magic, hdr) = hdr.split_first_chunk::<4>().unwrap();
        let (kind, hdr) = hdr.split_first_chunk::<2>().unwrap();
        let (len, _) = hdr.split_first_chunk::<4>().unwrap();

        let magic = u32::from_le_bytes(*magic);
        if magic != MAGIC {
            eprintln!("bad magic: {magic:#010x}");
            process::exit(1);
        }

        let kind = u16::from_le_bytes(*kind);
        let len = u32::from_le_bytes(*len) as usize;

        payload.resize(len, 0);
        if len > 0 && stream.read_exact(&mut payload).is_err() {
            eprintln!("truncated payload");
            process::exit(1);
        }

        match kind {
            WRITE_STDOUT => {
                let _ = std::io::stdout().write_all(&payload);
                let _ = std::io::stdout().flush();
            }
            WRITE_STDERR => {
                let _ = std::io::stderr().write_all(&payload);
                let _ = std::io::stderr().flush();
            }
            EXIT => {
                let code = if let Some((bytes, _)) = payload.split_first_chunk::<4>() {
                    i32::from_le_bytes(*bytes)
                } else {
                    0
                };
                process::exit(code);
            }
            other => {
                eprintln!("unknown kind: {other:#06x}");
            }
        }
    }
}

fn send_connect(stream: &mut UnixStream) {
    let pwd = env::current_dir().unwrap_or_default();
    let pwd_bytes = pwd.as_os_str().as_bytes();
    let args: Vec<String> = env::args().collect();

    let mut payload = Vec::new();
    push_u16_bytes(&mut payload, pwd_bytes);
    payload.extend_from_slice(&(args.len() as u16).to_le_bytes());
    for arg in &args {
        push_u16_bytes(&mut payload, arg.as_bytes());
    }

    let mut msg = Vec::with_capacity(HEADER_SIZE + payload.len());
    msg.extend_from_slice(&MAGIC.to_le_bytes());
    msg.extend_from_slice(&CONNECT.to_le_bytes());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(&payload);

    stream.write_all(&msg).unwrap_or_else(|e| {
        eprintln!("write connect: {e}");
        process::exit(1);
    });
}

fn push_u16_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buf.extend_from_slice(data);
}
