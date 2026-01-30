use std::io::{Read, Write};
use std::os::unix::net::UnixListener;

const CMD_ADVANCE: u8 = 0x01;
const CMD_GET_TIME: u8 = 0x02;

pub fn run(path: &str) {
    let _ = std::fs::remove_file(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(err) => {
            kvlog::error!("Failed to bind fuzz socket", ?err, path);
            return;
        }
    };
    kvlog::info!("Fuzz server listening", path);

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(err) => {
                kvlog::error!("Fuzz server accept error", ?err);
                continue;
            }
        };

        let mut buf = [0u8; 9];
        loop {
            if let Err(_) = read_exact(&mut stream, &mut buf) {
                break;
            }

            let cmd = buf[0];
            let value = u64::from_le_bytes(buf[1..9].try_into().unwrap());

            match cmd {
                CMD_ADVANCE => {
                    let was_needed = crate::clock::advance(value);
                    // Always wake so the event loop re-evaluates with the new time,
                    // even if it hasn't yet set WAKE_NEEDED for this iteration.
                    if let Some(waker) = crate::event_loop::GLOBAL_WAKER.get() {
                        let _ = waker.wake();
                    }
                    let response = [if was_needed { 0x01 } else { 0x00 }];
                    if stream.write_all(&response).is_err() {
                        break;
                    }
                }
                CMD_GET_TIME => {
                    let nanos = crate::clock::simulated_nanos();
                    if stream.write_all(&nanos.to_le_bytes()).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    }
}

fn read_exact(stream: &mut std::os::unix::net::UnixStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match stream.read(&mut buf[offset..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
