use std::env;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{self, Command, Stdio};

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
    let args: Vec<_> = env::args_os().collect();
    if args.get(1).is_some_and(|arg| arg == "--job-control-monitor") {
        job_control_monitor(args.into_iter().skip(2).collect());
    }

    if args.iter().any(|arg| arg == "--read-stdin-before-connect") {
        let mut byte = [0u8; 1];
        if let Err(error) = std::io::stdin().read_exact(&mut byte) {
            eprintln!("read stdin: {error}");
            process::exit(1);
        }
    }
    let args = args.into_iter().map(|arg| arg.to_string_lossy().into_owned()).collect();
    process::exit(run_controller(args));
}

fn job_control_monitor(command: Vec<std::ffi::OsString>) -> ! {
    let Some((program, args)) = command.split_first() else {
        eprintln!("--job-control-monitor requires a command");
        process::exit(2);
    };

    let mut child_command = Command::new(program);
    child_command.args(args).stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    unsafe {
        child_command.pre_exec(|| foreground_new_process_group(libc::STDIN_FILENO));
    }
    let mut child = child_command.spawn().unwrap_or_else(|error| {
        eprintln!("job-control monitor failed to spawn child: {error}");
        process::exit(1);
    });
    let pid = child.id() as libc::pid_t;

    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if result == pid && libc::WIFSTOPPED(status) {
            break;
        }
        if result == pid {
            eprintln!("job-control monitor child exited before stopping");
            process::exit(wait_status_exit_code(status));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            eprintln!("job-control monitor failed to wait for stopped child: {error}");
            process::exit(1);
        }
    }

    set_foreground_process_group(libc::STDIN_FILENO, unsafe { libc::getpgrp() }).unwrap_or_else(|error| {
        eprintln!("job-control monitor failed to reclaim terminal: {error}");
        process::exit(1);
    });

    let _ = run_controller(vec!["test-app".into(), "wrapper-stopped".into()]);
    let status = child.wait().unwrap_or_else(|error| {
        eprintln!("job-control monitor failed to reap child: {error}");
        process::exit(1);
    });
    process::exit(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
}

fn foreground_new_process_group(fd: libc::c_int) -> std::io::Result<()> {
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_foreground_process_group(fd, unsafe { libc::getpid() })
}

fn set_foreground_process_group(fd: libc::c_int, process_group: libc::pid_t) -> std::io::Result<()> {
    let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        libc::sigaddset(&mut blocked, libc::SIGTTIN);
    }
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = unsafe { libc::tcsetpgrp(fd, process_group) };
    let error = (result != 0).then(std::io::Error::last_os_error);
    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
    }
    error.map_or(Ok(()), Err)
}

fn wait_status_exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

fn run_controller(args: Vec<String>) -> i32 {
    let socket_path = env::var_os("TEST_APP_SOCKET").unwrap_or_else(|| {
        eprintln!("TEST_APP_SOCKET environment variable not set");
        process::exit(1);
    });

    let mut stream = UnixStream::connect(&socket_path).unwrap_or_else(|e| {
        eprintln!("connect: {e}");
        process::exit(1);
    });

    send_connect(&mut stream, &args);

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
                return payload
                    .split_first_chunk::<4>()
                    .map_or(0, |(bytes, _)| i32::from_le_bytes(*bytes));
            }
            other => {
                eprintln!("unknown kind: {other:#06x}");
            }
        }
    }
    0
}

fn send_connect(stream: &mut UnixStream, args: &[String]) {
    let pwd = env::current_dir().unwrap_or_default();
    let pwd_bytes = pwd.as_os_str().as_bytes();

    let mut payload = Vec::new();
    push_u16_bytes(&mut payload, pwd_bytes);
    payload.extend_from_slice(&(args.len() as u16).to_le_bytes());
    for arg in args {
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
