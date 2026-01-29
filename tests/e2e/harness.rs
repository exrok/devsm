//! Test harness and utilities for E2E tests.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::rpc::{
    ClientProtocol, DecodeResult, ExitCause, JobExitedEvent, JobStatusEvent, JobStatusKind, RpcMessageKind,
    encode_attach_rpc,
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
        let server_log_path = temp_dir.join("server.log");

        Self { temp_dir, socket_path, server_log_path, server: None }
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
