//! Test harness and utilities for E2E tests.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use std::os::unix::net::UnixListener;

use crate::rpc::{
    ClientProtocol, DebugTraceEvent, DecodeResult, ExitCause, JobExitedEvent, JobStatusEvent, JobStatusKind,
    RpcMessageKind, encode_attach_rpc,
};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Result of running a client command.
pub struct ClientResult {
    pub status: ExitStatus,
    #[allow(dead_code)]
    pub stdout: String,
    pub stderr: String,
}

impl ClientResult {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    #[allow(dead_code)]
    pub fn exit_code(&self) -> i32 {
        self.status.code().unwrap_or(-1)
    }
}

/// Test harness for isolated e2e tests.
///
/// Each test gets a unique temporary directory and socket path. The harness
/// manages server lifecycle and cleanup.
pub struct TestHarness {
    pub temp_dir: PathBuf,
    pub socket_path: PathBuf,
    #[cfg_attr(not(feature = "fuzz"), allow(dead_code))]
    pub fuzz_socket_path: PathBuf,
    pub server_log_path: PathBuf,
    pub server: Option<Child>,
}

impl TestHarness {
    /// Creates a new test harness with a unique temp directory.
    pub fn new(test_name: &str) -> Self {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!("devsm_e2e_{}_{}", test_name, counter));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        let socket_path = temp_dir.join("devsm.socket");
        let fuzz_socket_path = temp_dir.join("fuzz.socket");
        let server_log_path = temp_dir.join("server.log");

        Self { temp_dir, socket_path, fuzz_socket_path, server_log_path, server: None }
    }

    /// Writes a devsm.toml configuration file.
    pub fn write_config(&self, content: &str) -> &Self {
        let config_path = self.temp_dir.join("devsm.toml");
        fs::write(&config_path, content).expect("Failed to write config");
        self
    }

    /// Spawns the server with isolated socket path.
    ///
    /// Server output is captured to a log file for debugging on failure.
    pub fn spawn_server(&mut self) -> &mut Self {
        let log_file = fs::File::create(&self.server_log_path).expect("Failed to create server log");
        let log_file_err = log_file.try_clone().expect("Failed to clone log file");

        let server = Command::new(cargo_bin_path())
            .arg("server")
            .current_dir(&self.temp_dir)
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_LOG_STDOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("Failed to spawn server");

        self.server = Some(server);
        self
    }

    /// Spawns the server from a specific directory (not the config directory).
    pub fn spawn_server_from(&mut self, cwd: &PathBuf) -> &mut Self {
        let log_file = fs::File::create(&self.server_log_path).expect("Failed to create server log");
        let log_file_err = log_file.try_clone().expect("Failed to clone log file");

        let server = Command::new(cargo_bin_path())
            .arg("server")
            .current_dir(cwd)
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_LOG_STDOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("Failed to spawn server");

        self.server = Some(server);
        self
    }

    /// Spawns the server with fuzz time enabled.
    ///
    /// Sets `DEVSM_FUZZ_SOCKET` so the daemon uses simulated time controlled
    /// via the fuzz socket.
    #[cfg(feature = "fuzz")]
    pub fn spawn_fuzz_server(&mut self) -> &mut Self {
        let log_file = fs::File::create(&self.server_log_path).expect("Failed to create server log");
        let log_file_err = log_file.try_clone().expect("Failed to clone log file");

        let server = Command::new(cargo_bin_path())
            .arg("server")
            .current_dir(&self.temp_dir)
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_FUZZ_SOCKET", &self.fuzz_socket_path)
            .env("DEVSM_LOG_STDOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("Failed to spawn server");

        self.server = Some(server);
        self
    }

    /// Waits for the fuzz socket file to exist, with timeout.
    #[cfg(feature = "fuzz")]
    pub fn wait_for_fuzz_socket(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.fuzz_socket_path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    /// Runs a client command with isolated configuration.
    ///
    /// Uses `DEVSM_NO_AUTO_SPAWN=1` to rely on the test-spawned server and
    /// `DEVSM_CONNECT_TIMEOUT_MS=5000` for event-driven waiting.
    ///
    /// Uses piped stdin (not null) to prevent the server from detaching early.
    /// The server polls on stdin and detaches if it gets EOF.
    pub fn run_client(&self, args: &[&str]) -> ClientResult {
        let mut cmd = Command::new(cargo_bin_path());
        cmd.args(args)
            .current_dir(&self.temp_dir)
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_NO_AUTO_SPAWN", "1")
            .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("Failed to spawn client");
        let stdin_handle = child.stdin.take();
        let status = child.wait().expect("Failed to wait for client");
        drop(stdin_handle);

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut out) = child.stdout.take() {
            out.read_to_string(&mut stdout).ok();
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut stderr).ok();
        }

        ClientResult { status, stdout, stderr }
    }

    /// Waits for the socket file to exist, with timeout.
    pub fn wait_for_socket(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.socket_path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    /// Returns the server log contents for debugging.
    pub fn server_log(&self) -> String {
        fs::read_to_string(&self.server_log_path).unwrap_or_else(|_| "<no server log>".to_string())
    }

    /// Waits for a file to exist with timeout, useful for checking task completion.
    pub fn wait_for_file(&self, path: &Path, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        if let Some(ref mut server) = self.server {
            let pid = server.id() as i32;
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            for _ in 0..50 {
                if let Ok(Some(_)) = server.try_wait() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = server.kill();
            let _ = server.wait();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

/// Observed event from RPC subscription.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RpcEvent {
    JobStatus { job_index: u32, status: JobStatusKind },
    JobExited { job_index: u32, exit_code: i32, cause: ExitCause },
    DebugTrace { tag: String, job_index: u32 },
    WorkspaceOpened,
    Disconnect,
    Other { kind: RpcMessageKind },
}

/// RPC subscriber for observing workspace events.
pub struct RpcSubscriber {
    socket: UnixStream,
    protocol: ClientProtocol,
    buffer: Vec<u8>,
}

impl RpcSubscriber {
    /// Connects via RPC and subscribes to workspace events.
    pub fn connect(harness: &TestHarness) -> Self {
        let config_path = harness.temp_dir.join("devsm.toml");
        let mut socket = UnixStream::connect(&harness.socket_path).expect("Failed to connect for RPC");

        let msg = encode_attach_rpc(&harness.temp_dir, &config_path, true);
        socket.write_all(&msg).expect("Failed to send AttachRpc");
        socket.set_read_timeout(Some(Duration::from_secs(10))).ok();

        Self { socket, protocol: ClientProtocol::new(), buffer: Vec::with_capacity(4096) }
    }

    /// Collects events until predicate returns true or timeout expires.
    pub fn collect_until<F>(&mut self, predicate: F, timeout: Duration) -> Vec<RpcEvent>
    where
        F: Fn(&[RpcEvent]) -> bool,
    {
        let start = Instant::now();
        let mut events = Vec::new();

        while start.elapsed() < timeout {
            if predicate(&events) {
                break;
            }

            let mut chunk = [0u8; 4096];
            self.socket.set_read_timeout(Some(Duration::from_millis(100))).ok();

            let n = match self.socket.read(&mut chunk) {
                Ok(0) => {
                    events.push(RpcEvent::Disconnect);
                    break;
                }
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(_) => break,
            };
            self.buffer.extend_from_slice(&chunk[..n]);

            loop {
                match self.protocol.decode(&self.buffer) {
                    DecodeResult::Message { kind, payload, .. } => {
                        let event = match kind {
                            RpcMessageKind::OpenWorkspaceAck => RpcEvent::WorkspaceOpened,
                            RpcMessageKind::JobStatus => {
                                let e: JobStatusEvent = jsony::from_binary(payload).expect("invalid JobStatusEvent");
                                RpcEvent::JobStatus { job_index: e.job_index, status: e.status }
                            }
                            RpcMessageKind::JobExited => {
                                let e: JobExitedEvent = jsony::from_binary(payload).expect("invalid JobExitedEvent");
                                RpcEvent::JobExited { job_index: e.job_index, exit_code: e.exit_code, cause: e.cause }
                            }
                            RpcMessageKind::DebugTrace => {
                                let e: DebugTraceEvent =
                                    jsony::from_binary(payload).expect("invalid DebugTraceEvent");
                                RpcEvent::DebugTrace { tag: e.tag.to_string(), job_index: e.job_index }
                            }
                            RpcMessageKind::Disconnect => RpcEvent::Disconnect,
                            _ => RpcEvent::Other { kind },
                        };
                        events.push(event);
                    }
                    DecodeResult::MissingData { .. } => break,
                    DecodeResult::Empty => {
                        self.buffer.clear();
                        break;
                    }
                    DecodeResult::Error(_) => break,
                }
            }
            self.protocol.compact(&mut self.buffer, 4096);
        }
        events
    }

    /// Waits for a specific job to exit and returns its exit code.
    #[allow(dead_code)]
    pub fn wait_for_exit(&mut self, job_index: u32, timeout: Duration) -> Option<i32> {
        let events = self.collect_until(
            |evs| evs.iter().any(|e| matches!(e, RpcEvent::JobExited { job_index: j, .. } if *j == job_index)),
            timeout,
        );
        events.into_iter().find_map(|e| match e {
            RpcEvent::JobExited { job_index: j, exit_code, .. } if j == job_index => Some(exit_code),
            _ => None,
        })
    }

    /// Collects status transitions for a job until it exits.
    pub fn collect_job_statuses(&mut self, job_index: u32, timeout: Duration) -> Vec<JobStatusKind> {
        let events = self.collect_until(
            |evs| evs.iter().any(|e| matches!(e, RpcEvent::JobExited { job_index: j, .. } if *j == job_index)),
            timeout,
        );
        events
            .into_iter()
            .filter_map(|e| match e {
                RpcEvent::JobStatus { job_index: j, status } if j == job_index => Some(status),
                _ => None,
            })
            .collect()
    }

    /// Collects events until a debug trace with the given tag and job_index arrives.
    #[cfg(feature = "fuzz")]
    pub fn wait_for_trace(&mut self, tag: &str, job_index: u32, timeout: Duration) -> Vec<RpcEvent> {
        self.collect_until(
            |evs| {
                evs.iter().any(|e| {
                    matches!(e, RpcEvent::DebugTrace { tag: t, job_index: j } if t == tag && *j == job_index)
                })
            },
            timeout,
        )
    }
}

/// Returns the path to the compiled binary.
pub fn cargo_bin_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("Failed to get current exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("devsm");
    path
}

// ── test-app protocol ──────────────────────────────────────────────────────

const MAGIC: u32 = 0x7E57_0001;
const HEADER_SIZE: usize = 10;

const CONNECT: u16 = 0x01;
const WRITE_STDOUT: u16 = 0x02;
const EXIT: u16 = 0x04;

pub struct TestAppServer {
    pub listener: UnixListener,
    pub path: PathBuf,
}

impl TestAppServer {
    pub fn new(dir: &Path) -> Self {
        let path = dir.join("ctrl.socket");
        let listener = UnixListener::bind(&path).expect("Failed to bind controller socket");
        listener.set_nonblocking(false).unwrap();
        Self { listener, path }
    }

    pub fn accept(&self, timeout: Duration) -> TestAppConn {
        self.listener.set_nonblocking(true).unwrap();
        let start = Instant::now();
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut conn = TestAppConn { stream, args: Vec::new() };
                    conn.read_connect();
                    return conn;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("accept error: {e}"),
            }
            if start.elapsed() >= timeout {
                panic!("Timed out waiting for test-app connection");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub struct TestAppConn {
    stream: UnixStream,
    pub args: Vec<String>,
}

impl TestAppConn {
    fn read_connect(&mut self) {
        let mut hdr = [0u8; HEADER_SIZE];
        self.stream.read_exact(&mut hdr).expect("Failed to read connect header");

        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let kind = u16::from_le_bytes(hdr[4..6].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[6..10].try_into().unwrap()) as usize;

        assert_eq!(magic, MAGIC, "bad magic in connect message");
        assert_eq!(kind, CONNECT, "expected CONNECT message");

        let mut payload = vec![0u8; len];
        if len > 0 {
            self.stream.read_exact(&mut payload).expect("Failed to read connect payload");
        }

        let mut pos = 0;
        let pwd_len = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2 + pwd_len;

        let argc = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;

        self.args.clear();
        for _ in 0..argc {
            let arg_len = u16::from_le_bytes(payload[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            let arg = String::from_utf8_lossy(&payload[pos..pos + arg_len]).to_string();
            pos += arg_len;
            self.args.push(arg);
        }
    }

    pub fn write_stdout(&mut self, data: &[u8]) {
        let mut msg = Vec::with_capacity(HEADER_SIZE + data.len());
        msg.extend_from_slice(&MAGIC.to_le_bytes());
        msg.extend_from_slice(&WRITE_STDOUT.to_le_bytes());
        msg.extend_from_slice(&(data.len() as u32).to_le_bytes());
        msg.extend_from_slice(data);
        self.stream.write_all(&msg).expect("Failed to write stdout message");
    }

    pub fn exit(&mut self, code: i32) {
        let payload = code.to_le_bytes();
        let mut msg = Vec::with_capacity(HEADER_SIZE + payload.len());
        msg.extend_from_slice(&MAGIC.to_le_bytes());
        msg.extend_from_slice(&EXIT.to_le_bytes());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        self.stream.write_all(&msg).expect("Failed to write exit message");
    }

    pub fn name(&self) -> &str {
        self.args.get(1).map(|s| s.as_str()).unwrap_or("<unknown>")
    }
}

// ── fuzz clock client ──────────────────────────────────────────────────────

#[cfg(feature = "fuzz")]
const CMD_ADVANCE: u8 = 0x01;

#[cfg(feature = "fuzz")]
pub struct FuzzClock {
    stream: UnixStream,
}

#[cfg(feature = "fuzz")]
impl FuzzClock {
    pub fn connect(harness: &TestHarness) -> Self {
        assert!(harness.wait_for_fuzz_socket(Duration::from_secs(5)), "Fuzz socket not created");
        let stream = UnixStream::connect(&harness.fuzz_socket_path).expect("Failed to connect fuzz socket");
        Self { stream }
    }

    pub fn advance_secs(&mut self, secs: f64) {
        let nanos = (secs * 1_000_000_000.0) as u64;
        let mut msg = [0u8; 9];
        msg[0] = CMD_ADVANCE;
        msg[1..9].copy_from_slice(&nanos.to_le_bytes());
        self.stream.write_all(&msg).expect("Failed to send advance");
        let mut resp = [0u8; 1];
        self.stream.read_exact(&mut resp).expect("Failed to read advance response");
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

#[cfg(feature = "fuzz")]
pub fn find_exit_event(events: &[RpcEvent], job_index: u32) -> Option<(i32, ExitCause)> {
    events.iter().find_map(|e| match e {
        RpcEvent::JobExited { job_index: j, exit_code, cause } if *j == job_index => {
            Some((*exit_code, cause.clone()))
        }
        _ => None,
    })
}

#[cfg(feature = "fuzz")]
pub fn has_job_exit(events: &[RpcEvent], job_index: u32) -> bool {
    events.iter().any(|e| matches!(e, RpcEvent::JobExited { job_index: j, .. } if *j == job_index))
}
