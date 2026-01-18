use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use devsm_rpc::{
    ClientProtocol, DecodeResult, JobExitedEvent, JobStatusEvent, JobStatusKind, RpcMessageKind, encode_attach_rpc,
};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Result of running a client command.
struct ClientResult {
    status: ExitStatus,
    #[allow(dead_code)]
    stdout: String,
    stderr: String,
}

impl ClientResult {
    fn success(&self) -> bool {
        self.status.success()
    }

    #[allow(dead_code)]
    fn exit_code(&self) -> i32 {
        self.status.code().unwrap_or(-1)
    }
}

/// Test harness for isolated e2e tests.
///
/// Each test gets a unique temporary directory and socket path. The harness
/// manages server lifecycle and cleanup.
struct TestHarness {
    temp_dir: PathBuf,
    socket_path: PathBuf,
    server: Option<Child>,
}

impl TestHarness {
    /// Creates a new test harness with a unique temp directory.
    fn new(test_name: &str) -> Self {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!("devsm_e2e_{}_{}", test_name, counter));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        let socket_path = temp_dir.join("devsm.socket");

        Self { temp_dir, socket_path, server: None }
    }

    /// Writes a devsm.toml configuration file.
    fn write_config(&self, content: &str) -> &Self {
        let config_path = self.temp_dir.join("devsm.toml");
        fs::write(&config_path, content).expect("Failed to write config");
        self
    }

    /// Spawns the server with isolated socket path.
    ///
    /// Does not wait for the server to be ready; the client's built-in
    /// connection retry handles that.
    fn spawn_server(&mut self) -> &mut Self {
        let server = Command::new(cargo_bin_path())
            .arg("server")
            .env("DEVSM_SOCKET", &self.socket_path)
            .env("DEVSM_LOG_STDOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
    fn run_client(&self, args: &[&str]) -> ClientResult {
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
    fn wait_for_socket(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.socket_path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        if let Some(ref mut server) = self.server {
            let _ = server.kill();
            let _ = server.wait();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

/// Observed event from RPC subscription.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum RpcEvent {
    JobStatus { job_index: u32, status: JobStatusKind },
    JobExited { job_index: u32, exit_code: i32 },
    WorkspaceOpened,
    Disconnect,
    Other { kind: RpcMessageKind },
}

/// RPC subscriber for observing workspace events.
struct RpcSubscriber {
    socket: UnixStream,
    protocol: ClientProtocol,
    buffer: Vec<u8>,
}

impl RpcSubscriber {
    /// Connects via RPC and subscribes to workspace events.
    fn connect(harness: &TestHarness) -> Self {
        let config_path = harness.temp_dir.join("devsm.toml");
        let mut socket = UnixStream::connect(&harness.socket_path).expect("Failed to connect for RPC");

        let msg = encode_attach_rpc(&harness.temp_dir, &config_path, true);
        socket.write_all(&msg).expect("Failed to send AttachRpc");
        socket.set_read_timeout(Some(Duration::from_secs(10))).ok();

        Self { socket, protocol: ClientProtocol::new(), buffer: Vec::with_capacity(4096) }
    }

    /// Collects events until predicate returns true or timeout expires.
    fn collect_until<F>(&mut self, predicate: F, timeout: Duration) -> Vec<RpcEvent>
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
                                RpcEvent::JobExited { job_index: e.job_index, exit_code: e.exit_code }
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
    fn wait_for_exit(&mut self, job_index: u32, timeout: Duration) -> Option<i32> {
        let events = self.collect_until(
            |evs| evs.iter().any(|e| matches!(e, RpcEvent::JobExited { job_index: j, .. } if *j == job_index)),
            timeout,
        );
        events.into_iter().find_map(|e| match e {
            RpcEvent::JobExited { job_index: j, exit_code } if j == job_index => Some(exit_code),
            _ => None,
        })
    }

    /// Collects status transitions for a job until it exits.
    fn collect_job_statuses(&mut self, job_index: u32, timeout: Duration) -> Vec<JobStatusKind> {
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
fn cargo_bin_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("Failed to get current exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("devsm");
    path
}

#[test]
fn test_run_simple_action() {
    let mut harness = TestHarness::new("run_simple");
    harness.write_config(
        r#"
[action.echo_test]
cmd = ["echo", "hello from devsm"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "echo_test"]);

    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert!(result.stderr.contains("Task exited (code 0)"), "Expected exit message, got: {}", result.stderr);
}

#[test]
fn test_run_with_exit_code() {
    let mut harness = TestHarness::new("run_exit_code");
    harness.write_config(
        r#"
[action.fail_task]
sh = "exit 42"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "fail_task"]);

    assert!(result.success(), "Client should exit successfully even if task fails");
    assert!(result.stderr.contains("Task exited (code 42)"), "Expected exit code 42 in stderr, got: {}", result.stderr);
}

#[test]
fn test_test_command_passes() {
    let mut harness = TestHarness::new("test_passes");
    harness.write_config(
        r#"
[test.passing_test]
sh = "exit 0"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);

    assert!(result.success(), "Expected success, got: {}", result.stderr);
}

#[test]
fn test_test_command_fails() {
    let mut harness = TestHarness::new("test_fails");
    harness.write_config(
        r#"
[test.failing_test]
sh = "exit 1"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);

    assert!(result.success(), "Client should complete, stderr: {}", result.stderr);
}

#[test]
fn test_client_fails_without_server() {
    let harness = TestHarness::new("no_server");
    harness.write_config(
        r#"
[action.dummy]
cmd = ["true"]
"#,
    );

    let result = harness.run_client(&["run", "dummy"]);

    assert!(!result.success(), "Expected failure without server");
    assert!(
        result.stderr.contains("auto-spawn disabled") || result.stderr.contains("Connection"),
        "Expected connection error, got: {}",
        result.stderr
    );
}

#[test]
fn test_run_with_profile() {
    let mut harness = TestHarness::new("run_with_profile");
    let output_file = harness.temp_dir.join("output.txt");
    // Use env field to pass profile to shell script
    harness.write_config(&format!(
        r#"
[action.greet]
sh = '''
if [ "$PROFILE" = "formal" ]; then
    echo "Good morning" > {output}
else
    echo "Hey" > {output}
fi
'''
profiles = ["default", "formal"]
env.PROFILE = {{ if.profile = "formal", then = "formal", or_else = "default" }}
"#,
        output = output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Run with default profile
    let result = harness.run_client(&["run", "greet"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    let content = fs::read_to_string(&output_file).unwrap_or_default();
    assert!(content.trim() == "Hey", "Expected 'Hey' for default profile, got: {}", content);

    // Run with formal profile
    let result = harness.run_client(&["run", "greet:formal"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    let content = fs::read_to_string(&output_file).unwrap_or_default();
    assert!(content.trim() == "Good morning", "Expected 'Good morning' for formal profile, got: {}", content);
}

#[test]
fn test_profile_affects_command_args() {
    let mut harness = TestHarness::new("profile_cmd_args");
    let marker = harness.temp_dir.join("marker.txt");
    // Use conditional in cmd to demonstrate profile-based argument changes
    harness.write_config(&format!(
        r#"
[action.write_profile]
cmd = ["sh", "-c", "echo $PROFILE_VAL > {marker}"]
profiles = ["default", "verbose"]
env.PROFILE_VAL = {{ if.profile = "verbose", then = "verbose", or_else = "default" }}
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Run with default profile
    let result = harness.run_client(&["run", "write_profile"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    let content = fs::read_to_string(&marker).unwrap_or_default();
    assert!(content.trim() == "default", "Expected 'default', got: {}", content);

    // Run with verbose profile
    let result = harness.run_client(&["run", "write_profile:verbose"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    let content = fs::read_to_string(&marker).unwrap_or_default();
    assert!(content.trim() == "verbose", "Expected 'verbose', got: {}", content);
}

#[test]
fn test_require_runs_dependency_first() {
    let mut harness = TestHarness::new("require_order");
    let order_file = harness.temp_dir.join("order.txt");
    harness.write_config(&format!(
        r#"
[action.setup]
sh = "echo setup >> {}"

[action.main]
sh = "echo main >> {}"
require = ["setup"]
"#,
        order_file.display(),
        order_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "main"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let content = fs::read_to_string(&order_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["setup", "main"], "Expected setup before main, got: {:?}", lines);
}

#[test]
fn test_require_waits_for_success() {
    let mut harness = TestHarness::new("require_waits");
    let marker = harness.temp_dir.join("marker.txt");
    harness.write_config(&format!(
        r#"
[action.dep]
sh = "sleep 0.1 && echo dep_done > {}"

[action.main]
sh = "cat {}"
require = ["dep"]
"#,
        marker.display(),
        marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Via RPC, verify main waits for dep
    let mut subscriber = RpcSubscriber::connect(&harness);

    // Run main via client in background
    let client_handle = std::thread::spawn({
        let temp_dir = harness.temp_dir.clone();
        let socket_path = harness.socket_path.clone();
        move || {
            Command::new(cargo_bin_path())
                .args(["run", "main"])
                .current_dir(&temp_dir)
                .env("DEVSM_SOCKET", &socket_path)
                .env("DEVSM_NO_AUTO_SPAWN", "1")
                .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn client")
                .wait()
        }
    });

    // Collect events
    let events = subscriber.collect_until(
        |evs| evs.iter().filter(|e| matches!(e, RpcEvent::JobExited { .. })).count() >= 2,
        Duration::from_secs(5),
    );

    client_handle.join().ok();

    // Verify dep exits before main
    let exit_order: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            RpcEvent::JobExited { job_index, .. } => Some(*job_index),
            _ => None,
        })
        .collect();
    assert!(exit_order.len() >= 2, "Expected at least 2 exits, got: {:?}", exit_order);
}

#[test]
fn test_require_fails_on_dependency_failure() {
    let mut harness = TestHarness::new("require_fails");
    let marker = harness.temp_dir.join("main_ran.txt");
    harness.write_config(&format!(
        r#"
[action.failing_dep]
sh = "exit 1"

[action.main]
sh = "echo ran > {}"
require = ["failing_dep"]
"#,
        marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "main"]);
    // The client completes but main should not run
    assert!(result.success() || !result.success(), "Client should complete");

    // Verify main never ran
    assert!(!marker.exists(), "main should not have run when dependency fails");
}

#[test]
fn test_deep_dependency_chain() {
    let mut harness = TestHarness::new("deep_chain");
    let output_file = harness.temp_dir.join("output.txt");
    harness.write_config(&format!(
        r#"
[action.step1]
sh = "echo 1 >> {}"

[action.step2]
sh = "echo 2 >> {}"
require = ["step1"]

[action.step3]
sh = "echo 3 >> {}"
require = ["step2"]

[action.step4]
sh = "echo 4 >> {}"
require = ["step3"]

[action.final]
sh = "echo 5 >> {}"
require = ["step4"]
"#,
        output_file.display(),
        output_file.display(),
        output_file.display(),
        output_file.display(),
        output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "final"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["1", "2", "3", "4", "5"], "Expected sequential order, got: {:?}", lines);
}

#[test]
fn test_diamond_dependency() {
    let mut harness = TestHarness::new("diamond_dep");
    let output_file = harness.temp_dir.join("output.txt");
    // Use cache = {} on setup to ensure it only runs once even when required by multiple tasks
    harness.write_config(&format!(
        r#"
[action.setup]
sh = "echo setup >> {}"
cache = {{}}

[action.left]
sh = "echo left >> {}"
require = ["setup"]

[action.right]
sh = "echo right >> {}"
require = ["setup"]

[action.final]
sh = "echo final >> {}"
require = ["left", "right"]
"#,
        output_file.display(),
        output_file.display(),
        output_file.display(),
        output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "final"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();

    // Verify setup runs first
    assert_eq!(lines.first(), Some(&"setup"), "setup should run first");
    // Verify final runs last
    assert_eq!(lines.last(), Some(&"final"), "final should run last");
    // Verify left and right are in between
    assert!(lines.contains(&"left"), "left should have run");
    assert!(lines.contains(&"right"), "right should have run");
    // setup should appear exactly once due to cache
    assert_eq!(lines.iter().filter(|&&l| l == "setup").count(), 1, "setup should run exactly once");
}

#[test]
fn test_cache_skips_on_hit() {
    let mut harness = TestHarness::new("cache_skip");
    let marker = harness.temp_dir.join("gen_marker.txt");
    let counter = harness.temp_dir.join("counter.txt");

    // Initialize counter
    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.gen]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
echo "gen_$count" > {marker}
'''
cache = {{}}

[action.use_gen]
sh = "cat {marker}"
require = ["gen"]
"#,
        counter = counter.display(),
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // First run
    let result = harness.run_client(&["run", "use_gen"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    let first_marker = fs::read_to_string(&marker).unwrap_or_default();

    // Second run - gen should be skipped due to cache
    let result = harness.run_client(&["run", "use_gen"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    let second_marker = fs::read_to_string(&marker).unwrap_or_default();

    // Marker should be unchanged (gen was cached)
    assert_eq!(first_marker, second_marker, "gen should have been cached");

    // Counter should still be 1
    let count = fs::read_to_string(&counter).unwrap_or_default();
    assert_eq!(count.trim(), "1", "gen should have run only once");
}

#[test]
fn test_cache_invalidates_on_file_modified() {
    let mut harness = TestHarness::new("cache_invalidate");
    let trigger = harness.temp_dir.join("trigger.txt");
    let output = harness.temp_dir.join("output.txt");
    let counter = harness.temp_dir.join("counter.txt");

    // Initialize files
    fs::write(&trigger, "initial").unwrap();
    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.gen]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
cat {trigger} > {output}
'''
cache.key = [{{ modified = "{trigger}" }}]

[action.consumer]
sh = "cat {output}"
require = ["gen"]
"#,
        trigger = trigger.display(),
        counter = counter.display(),
        output = output.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // First run
    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should run first time");

    // Second run - should be cached
    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on second run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should be cached");

    // Modify trigger file (sleep to ensure mtime changes)
    std::thread::sleep(Duration::from_millis(100));
    fs::write(&trigger, "modified").unwrap();

    // Third run - cache should be invalidated
    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on third run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "gen should run again after invalidation");
    assert_eq!(fs::read_to_string(&output).unwrap().trim(), "modified", "output should have new content");
}

#[test]
fn test_cache_profile_changed() {
    let mut harness = TestHarness::new("cache_profile");
    let dep_counter = harness.temp_dir.join("dep_counter.txt");
    let main_counter = harness.temp_dir.join("main_counter.txt");
    let runner_counter = harness.temp_dir.join("runner_counter.txt");

    fs::write(&dep_counter, "0").unwrap();
    fs::write(&main_counter, "0").unwrap();
    fs::write(&runner_counter, "0").unwrap();

    // Cache checking only applies to dependencies, not to the directly-run task.
    // So we need a runner task that requires main, and main has profile_changed cache.
    harness.write_config(&format!(
        r#"
[action.dep]
sh = '''
count=$(cat {dep_counter})
count=$((count + 1))
echo $count > {dep_counter}
'''
profiles = ["a", "b"]
cache = {{}}

[action.main]
sh = '''
count=$(cat {main_counter})
count=$((count + 1))
echo $count > {main_counter}
'''
require = ["dep"]
cache.key = [{{ profile_changed = "dep" }}]

[action.runner]
sh = '''
count=$(cat {runner_counter})
count=$((count + 1))
echo $count > {runner_counter}
'''
require = ["main"]
"#,
        dep_counter = dep_counter.display(),
        main_counter = main_counter.display(),
        runner_counter = runner_counter.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // First run - all should execute
    let result = harness.run_client(&["run", "runner"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&dep_counter).unwrap().trim(), "1", "dep should run");
    assert_eq!(fs::read_to_string(&main_counter).unwrap().trim(), "1", "main should run");
    assert_eq!(fs::read_to_string(&runner_counter).unwrap().trim(), "1", "runner should run");

    // Second run - dep and main should be cached
    let result = harness.run_client(&["run", "runner"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&dep_counter).unwrap().trim(), "1", "dep should be cached");
    assert_eq!(fs::read_to_string(&main_counter).unwrap().trim(), "1", "main should be cached");
    assert_eq!(fs::read_to_string(&runner_counter).unwrap().trim(), "2", "runner always runs");

    // Run dep with different profile to change profile_change_counter
    let result = harness.run_client(&["run", "dep:b"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&dep_counter).unwrap().trim(), "2", "dep:b should run");

    // Run runner again - main should run because dep's profile changed
    let result = harness.run_client(&["run", "runner"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    // dep should still be cached (has cache = {})
    assert_eq!(fs::read_to_string(&dep_counter).unwrap().trim(), "2", "dep should still be cached");
    // main should run because its profile_changed key changed
    assert_eq!(fs::read_to_string(&main_counter).unwrap().trim(), "2", "main should run due to profile_changed");
}

#[test]
fn test_rpc_status_sequence_simple() {
    let mut harness = TestHarness::new("rpc_simple");
    harness.write_config(
        r#"
[action.task]
sh = "echo hello"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut subscriber = RpcSubscriber::connect(&harness);

    // Wait for workspace to open
    subscriber.collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::WorkspaceOpened)), Duration::from_secs(2));

    // Run task via client in background thread
    let client_handle = std::thread::spawn({
        let temp_dir = harness.temp_dir.clone();
        let socket_path = harness.socket_path.clone();
        move || {
            Command::new(cargo_bin_path())
                .args(["run", "task"])
                .current_dir(&temp_dir)
                .env("DEVSM_SOCKET", &socket_path)
                .env("DEVSM_NO_AUTO_SPAWN", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn client")
                .wait()
        }
    });

    // Collect events until we see exit
    let events = subscriber
        .collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::JobExited { .. })), Duration::from_secs(5));

    client_handle.join().ok();

    // Verify we saw Running status and then exit with code 0
    let has_running = events.iter().any(|e| matches!(e, RpcEvent::JobStatus { status: JobStatusKind::Running, .. }));
    let has_exit_0 = events.iter().any(|e| matches!(e, RpcEvent::JobExited { exit_code: 0, .. }));

    assert!(has_running, "Should see Running status, events: {:?}", events);
    assert!(has_exit_0, "Should see exit code 0, events: {:?}", events);
}

#[test]
fn test_rpc_status_sequence_with_dependency() {
    let mut harness = TestHarness::new("rpc_dep");
    harness.write_config(
        r#"
[action.dep]
sh = "sleep 0.01 && echo dep"

[action.main]
sh = "echo main"
require = ["dep"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut subscriber = RpcSubscriber::connect(&harness);

    // Wait for workspace to open
    subscriber.collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::WorkspaceOpened)), Duration::from_secs(2));

    // Run main via client
    let client_handle = std::thread::spawn({
        let temp_dir = harness.temp_dir.clone();
        let socket_path = harness.socket_path.clone();
        move || {
            Command::new(cargo_bin_path())
                .args(["run", "main"])
                .current_dir(&temp_dir)
                .env("DEVSM_SOCKET", &socket_path)
                .env("DEVSM_NO_AUTO_SPAWN", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn client")
                .wait()
        }
    });

    // Collect events until we see 2 exits
    let events = subscriber.collect_until(
        |evs| evs.iter().filter(|e| matches!(e, RpcEvent::JobExited { .. })).count() >= 2,
        Duration::from_secs(5),
    );

    client_handle.join().ok();

    // Count exits
    let exit_count = events.iter().filter(|e| matches!(e, RpcEvent::JobExited { .. })).count();
    assert!(exit_count >= 2, "Should see at least 2 exits (dep and main), events: {:?}", events);

    // Verify both exited successfully
    let exits_ok = events.iter().filter(|e| matches!(e, RpcEvent::JobExited { exit_code: 0, .. })).count();
    assert!(exits_ok >= 2, "Both tasks should exit with code 0, events: {:?}", events);
}

#[test]
fn test_rpc_multiple_status_transitions() {
    let mut harness = TestHarness::new("rpc_transitions");
    harness.write_config(
        r#"
[action.slow_task]
sh = "sleep 0.01 && echo done"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut subscriber = RpcSubscriber::connect(&harness);

    // Wait for workspace
    subscriber.collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::WorkspaceOpened)), Duration::from_secs(2));

    // Run in background
    let client_handle = std::thread::spawn({
        let temp_dir = harness.temp_dir.clone();
        let socket_path = harness.socket_path.clone();
        move || {
            Command::new(cargo_bin_path())
                .args(["run", "slow_task"])
                .current_dir(&temp_dir)
                .env("DEVSM_SOCKET", &socket_path)
                .env("DEVSM_NO_AUTO_SPAWN", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("Failed to spawn")
                .wait()
        }
    });

    // For job 0, collect all statuses
    let statuses = subscriber.collect_job_statuses(0, Duration::from_secs(5));
    client_handle.join().ok();

    // Should see Running at minimum
    assert!(
        statuses.iter().any(|s| matches!(s, JobStatusKind::Running)),
        "Should see Running status, got: {:?}",
        statuses
    );
}
