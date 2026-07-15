//! Test harness and utilities for E2E tests.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};

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

pub struct PtyClientResult {
    pub exit_code: u32,
    pub output: String,
    pub echo_enabled: bool,
    pub newline_processing_enabled: bool,
}

pub struct PtyClient {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    writer: Box<dyn Write + Send>,
    master: Box<dyn portable_pty::MasterPty + Send>,
    output_rx: std::sync::mpsc::Receiver<String>,
}

impl PtyClient {
    pub fn newline_processing_enabled(&self) -> Option<bool> {
        self.master.as_raw_fd().and_then(|fd| {
            let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
            (unsafe { libc::tcgetattr(fd, &mut termios) } == 0)
                .then_some(termios.c_oflag & libc::OPOST != 0 && termios.c_oflag & libc::ONLCR != 0)
        })
    }

    pub fn send_input(&mut self, input: &[u8]) {
        self.writer.write_all(input).expect("failed to send PTY input");
        self.writer.flush().expect("failed to flush PTY input");
    }

    pub fn send_ctrl_c(&mut self) {
        self.send_input(&[3]);
    }

    pub fn send_ctrl_z(&mut self) {
        self.send_input(&[26]);
    }

    pub fn kill_wrapper(&mut self) {
        self.child.kill().expect("failed to kill PTY wrapper");
    }

    pub fn signal_wrapper(&self, signal: i32) {
        let pid = self.child.process_id().expect("PTY wrapper has no process id") as i32;
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0, "failed to signal PTY wrapper");
    }

    pub fn wait_wrapper_stopped(&self, timeout: Duration) {
        let pid = self.child.process_id().expect("PTY wrapper has no process id") as i32;
        let (status_tx, status_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
            let _ = status_tx.send((result, status));
        });
        let (result, status) = status_rx.recv_timeout(timeout).expect("PTY wrapper did not stop before timeout");
        assert!(result >= 0, "failed to inspect PTY wrapper state: {}", std::io::Error::last_os_error());
        assert!(result == pid && libc::WIFSTOPPED(status), "PTY wrapper changed to an unexpected state");
    }

    pub fn wait(self, timeout: Duration, server_log: impl FnOnce() -> String) -> PtyClientResult {
        let PtyClient { mut child, writer, master, output_rx } = self;
        let mut killer = child.clone_killer();
        let (status_tx, status_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = status_tx.send(child.wait());
        });
        let status = match status_rx.recv_timeout(timeout) {
            Ok(status) => status.expect("failed to wait for PTY client"),
            Err(_) => {
                let _ = killer.kill();
                let _ = status_rx.recv_timeout(Duration::from_secs(2));
                panic!("PTY client timed out after {timeout:?}; server log:\n{}", server_log());
            }
        };
        let terminal_flags = master
            .as_raw_fd()
            .and_then(|fd| {
                let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
                (unsafe { libc::tcgetattr(fd, &mut termios) } == 0).then_some((
                    termios.c_lflag & libc::ECHO != 0,
                    termios.c_oflag & libc::OPOST != 0 && termios.c_oflag & libc::ONLCR != 0,
                ))
            })
            .unwrap_or((false, false));
        drop(writer);
        drop(master);
        let output = output_rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
        PtyClientResult {
            exit_code: status.exit_code(),
            output,
            echo_enabled: terminal_flags.0,
            newline_processing_enabled: terminal_flags.1,
        }
    }
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
    pub sock_dir: PathBuf,
    pub socket_path: PathBuf,
    #[cfg_attr(not(feature = "fuzz"), allow(dead_code))]
    pub fuzz_socket_path: PathBuf,
    pub server_log_path: PathBuf,
    pub server: Option<Child>,
}

impl TestHarness {
    /// Creates a new test harness with a unique temp directory.
    ///
    /// The path includes the host pid so that two concurrent `cargo test`
    /// runs (e.g. a dev loop and a CI shell invoking the same suite) do not
    /// collide on `/tmp/devsm_e2e_<name>_<counter>` and corrupt each other's
    /// sockets — previously the local `TEST_COUNTER` restarted at zero in
    /// every process, so parallel runs wiped each other's directories and
    /// fought over the same `devsm.socket`, which would stall the daemon.
    pub fn new(test_name: &str) -> Self {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let temp_dir = std::env::temp_dir().join(format!("devsm_e2e_{}_p{}_{}", test_name, pid, counter));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");
        // On macOS temp_dir() sits behind the /var -> /private/var symlink while the
        // daemon and clients key workspaces by getcwd(), which resolves it. Canonicalize
        // so paths written into configs and AttachRpc match what the daemon sees.
        let temp_dir = temp_dir.canonicalize().expect("Failed to canonicalize temp dir");

        // Sockets live in a separate directory without the test name: macOS caps
        // sockaddr_un paths at 104 bytes and its $TMPDIR alone is ~50, so
        // temp_dir-based socket paths overflow SUN_LEN for longer test names.
        let sock_dir = std::env::temp_dir().join(format!("devsm_s{}_{}", pid, counter));
        let _ = fs::remove_dir_all(&sock_dir);
        fs::create_dir_all(&sock_dir).expect("Failed to create socket dir");

        let socket_path = sock_dir.join("devsm.socket");
        let fuzz_socket_path = sock_dir.join("fuzz.socket");
        let server_log_path = temp_dir.join("server.log");

        Self { temp_dir, sock_dir, socket_path, fuzz_socket_path, server_log_path, server: None }
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
        self.spawn_server_with_db_path(Path::new("/dev/null"))
    }

    /// Spawns the server with a specific DB path.
    pub fn spawn_server_with_db(&mut self, db_path: &Path) -> &mut Self {
        self.spawn_server_with_db_path(db_path)
    }

    fn spawn_server_with_db_path(&mut self, db_path: &Path) -> &mut Self {
        let log_file = fs::File::create(&self.server_log_path).expect("Failed to create server log");
        let log_file_err = log_file.try_clone().expect("Failed to clone log file");
        let (mut ready_reader, ready_writer) = readiness_pipe();

        let server = Command::new(cargo_bin_path())
            .args(["self", "server"])
            .current_dir(&self.temp_dir)
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_DB", db_path)
            .env("DEVSM_LOG_STDOUT", "1")
            .env("DEVSM_TEST_READY_FD", ready_writer.as_raw_fd().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("Failed to spawn server");
        drop(ready_writer);
        let mut ready = [0u8; 1];
        ready_reader.read_exact(&mut ready).expect("daemon exited before binding its socket");

        self.server = Some(server);
        self
    }

    /// Stops the test server if it is running.
    pub fn stop_server(&mut self) {
        terminate_server(&mut self.server);
        let _ = fs::remove_file(&self.socket_path);
    }

    /// Spawns the server from a specific directory (not the config directory).
    pub fn spawn_server_from(&mut self, cwd: &PathBuf) -> &mut Self {
        let log_file = fs::File::create(&self.server_log_path).expect("Failed to create server log");
        let log_file_err = log_file.try_clone().expect("Failed to clone log file");
        let (mut ready_reader, ready_writer) = readiness_pipe();

        let server = Command::new(cargo_bin_path())
            .args(["self", "server"])
            .current_dir(cwd)
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_DB", "/dev/null")
            .env("DEVSM_LOG_STDOUT", "1")
            .env("DEVSM_TEST_READY_FD", ready_writer.as_raw_fd().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("Failed to spawn server");
        drop(ready_writer);
        let mut ready = [0u8; 1];
        ready_reader.read_exact(&mut ready).expect("daemon exited before binding its socket");

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
            .args(["self", "server"])
            .current_dir(&self.temp_dir)
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_DB", "/dev/null")
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
            .env("DEVSM_DB", "/dev/null")
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

    /// Runs a client as the session leader of a real PTY. This is used for
    /// terminal-harness tests; ordinary pipe-based helpers cannot exercise
    /// controlling-terminal foreground groups or termios restoration.
    pub fn spawn_pty_client(&self, args: &[&str]) -> PtyClient {
        let mut command = CommandBuilder::new(cargo_bin_path());
        command.args(args);
        command.cwd(&self.temp_dir);
        command.env("DEVSM_SOCKET", &self.socket_path);
        command.env("DEVSM_DB", "/dev/null");
        command.env("DEVSM_NO_AUTO_SPAWN", "1");
        command.env("DEVSM_CONNECT_TIMEOUT_MS", "5000");

        self.spawn_pty_command(command)
    }

    /// Spawn devsm beneath a monitor-mode shell. Unlike the ordinary PTY
    /// helper, this keeps a parent process group in the PTY session so Ctrl-Z
    /// exercises real, non-orphaned shell job control.
    pub fn spawn_job_controlled_pty_client(&self, control_socket: &Path, args: &[&str]) -> PtyClient {
        fn shell_quote(value: &str) -> String {
            format!("'{}'", value.replace('\'', "'\"'\"'"))
        }

        let mut invocation = shell_quote(cargo_bin_path().to_string_lossy().as_ref());
        for arg in args {
            invocation.push(' ');
            invocation.push_str(&shell_quote(arg));
        }
        let script = format!(
            "set -m\n{invocation}\nwrapper=$(jobs -p %1)\ntest-app wrapper-stopped\nwait -f \"$wrapper\" 2>/dev/null\nexit $?"
        );
        let mut command = CommandBuilder::new("/bin/bash");
        command.args(["--noprofile", "--norc", "-c", &script]);
        command.cwd(&self.temp_dir);
        command.env("TEST_APP_SOCKET", control_socket);
        command.env("DEVSM_SOCKET", &self.socket_path);
        command.env("DEVSM_DB", "/dev/null");
        command.env("DEVSM_NO_AUTO_SPAWN", "1");
        command.env("DEVSM_CONNECT_TIMEOUT_MS", "5000");

        self.spawn_pty_command(command)
    }

    fn spawn_pty_command(&self, command: CommandBuilder) -> PtyClient {
        let pair = NativePtySystem::default()
            .openpty(PtySize { rows: 24, cols: 100, pixel_width: 0, pixel_height: 0 })
            .expect("failed to open PTY");

        let child = pair.slave.spawn_command(command).expect("failed to spawn PTY client");
        drop(pair.slave);
        let writer = pair.master.take_writer().expect("failed to open PTY writer");
        let mut reader = pair.master.try_clone_reader().expect("failed to clone PTY reader");
        let (output_tx, output_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut output = String::new();
            let _ = reader.read_to_string(&mut output);
            let _ = output_tx.send(output);
        });

        PtyClient { child, writer, master: pair.master, output_rx }
    }

    pub fn run_pty_client(&self, args: &[&str], timeout: Duration) -> PtyClientResult {
        self.spawn_pty_client(args).wait(timeout, || self.server_log())
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

fn readiness_pipe() -> (fs::File, fs::File) {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "failed to create daemon readiness pipe");
    unsafe { (fs::File::from_raw_fd(fds[0]), fs::File::from_raw_fd(fds[1])) }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        terminate_server(&mut self.server);
        let _ = fs::remove_dir_all(&self.temp_dir);
        let _ = fs::remove_dir_all(&self.sock_dir);
    }
}

fn terminate_server(server: &mut Option<Child>) {
    if let Some(mut server) = server.take() {
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
                                let e: DebugTraceEvent = jsony::from_binary(payload).expect("invalid DebugTraceEvent");
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
                evs.iter()
                    .any(|e| matches!(e, RpcEvent::DebugTrace { tag: t, job_index: j } if t == tag && *j == job_index))
            },
            timeout,
        )
    }
}

/// Returns the path to the compiled binary.
///
/// Uses `CARGO_BIN_EXE_devsm` so the path matches the binary cargo built for
/// this test invocation's feature set. Resolving via `current_exe()` instead
/// returns `target/debug/devsm`, which a concurrent `cargo run` (e.g. another
/// devsm test action) can overwrite with a non-fuzz build.
pub fn cargo_bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_devsm"))
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
        assert!(wait_readable(self.listener.as_raw_fd(), timeout), "Timed out waiting for test-app connection");
        let (stream, _) = self.listener.accept().unwrap_or_else(|error| panic!("accept error: {error}"));
        stream.set_nonblocking(false).expect("set accepted test-app connection blocking");
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut conn = TestAppConn { stream, args: Vec::new() };
        conn.read_connect();
        conn
    }

    /// Accepts one connection per entry in `names`, returning them in the
    /// order of `names` regardless of arrival order. Tasks spawned around the
    /// same scheduling instant connect in scheduler-dependent order, so
    /// consecutive `accept` calls asserting fixed names are racy.
    pub fn accept_named<const N: usize>(&self, names: [&str; N], timeout: Duration) -> [TestAppConn; N] {
        let start = Instant::now();
        let mut slots: [Option<TestAppConn>; N] = std::array::from_fn(|_| None);
        for _ in 0..N {
            let conn = self.accept(timeout.saturating_sub(start.elapsed()));
            let Some(slot) = (0..N).find(|&i| slots[i].is_none() && names[i] == conn.name()) else {
                panic!("unexpected test-app connection '{}' while waiting for {:?}", conn.name(), names);
            };
            slots[slot] = Some(conn);
        }
        slots.map(|conn| conn.unwrap())
    }

    pub fn try_accept(&self, timeout: Duration) -> Option<TestAppConn> {
        if !wait_readable(self.listener.as_raw_fd(), timeout) {
            return None;
        }
        Some(self.accept(Duration::ZERO))
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

    pub fn wait_disconnected(&mut self, timeout: Duration) -> bool {
        wait_readable(self.stream.as_raw_fd(), timeout) && self.is_disconnected()
    }

    pub fn is_disconnected(&mut self) -> bool {
        let mut byte = [0u8; 1];
        let n = unsafe {
            libc::recv(
                self.stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                byte.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n == 0 {
            return true;
        }
        if n > 0 {
            return false;
        }

        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => false,
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => true,
            _ => true,
        }
    }
}

fn wait_readable(fd: std::os::fd::RawFd, timeout: Duration) -> bool {
    let mut descriptor = libc::pollfd { fd, events: libc::POLLIN | libc::POLLHUP | libc::POLLERR, revents: 0 };
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result >= 0 {
            return result > 0;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return false;
        }
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
        RpcEvent::JobExited { job_index: j, exit_code, cause } if *j == job_index => Some((*exit_code, cause.clone())),
        _ => None,
    })
}

#[cfg(feature = "fuzz")]
pub fn has_job_exit(events: &[RpcEvent], job_index: u32) -> bool {
    events.iter().any(|e| matches!(e, RpcEvent::JobExited { job_index: j, .. } if *j == job_index))
}
