//! TUI E2E tests for devsm.

use crate::harness;

use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;

use harness::{TestHarness, cargo_bin_path};
use jsony::Jsony;

/// State parsed from TUI JSON output stream.
#[derive(Debug, Clone, Jsony, Default)]
struct TuiState {
    #[allow(dead_code)]
    collapsed: bool,
    #[allow(dead_code)]
    selection: Option<TuiSelection>,
    #[allow(dead_code)]
    overlay: Option<TuiOverlay>,
    base_tasks: Vec<TuiBaseTask>,
    #[allow(dead_code)]
    meta_groups: Option<TuiMetaGroups>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
struct TuiSelection {
    base_task: Option<usize>,
    job: Option<usize>,
    meta_group: Option<String>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
struct TuiMetaGroups {
    tests: TuiMetaGroup,
    actions: TuiMetaGroup,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
struct TuiMetaGroup {
    job_count: usize,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
struct TuiOverlay {
    kind: Option<String>,
    input: Option<String>,
    mode: Option<String>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
struct TuiBaseTask {
    index: usize,
    name: String,
    jobs: Vec<TuiJob>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
struct TuiJob {
    index: usize,
    status: String,
    exit_code: Option<u32>,
}

impl TuiState {
    fn from_json(json: &str) -> Option<Self> {
        jsony::from_json(json).ok()
    }

    fn find_task_by_name(&self, name: &str) -> Option<&TuiBaseTask> {
        self.base_tasks.iter().find(|t| t.name == name)
    }
}

#[test]
fn tui_restart_selected_restarts_service() {
    let mut harness = TestHarness::new("tui_restart_selected");
    let service_log = harness.temp_dir.join("service.log");

    harness.write_config(&format!(
        r#"
[service.my_service]
sh = '''
echo "started $(date +%s%N)" >> {service_log}
while true; do sleep 1; done
'''
"#,
        service_log = service_log.display()
    ));

    // Spawn server with JSON state stream mode enabled
    let log_file = fs::File::create(&harness.server_log_path).expect("Failed to create server log");
    let log_file_err = log_file.try_clone().expect("Failed to clone log file");

    let server = Command::new(cargo_bin_path())
        .arg("server")
        .env("DEVSM_SOCKET", &harness.socket_path)
        .env("DEVSM_LOG_STDOUT", "1")
        .env("DEVSM_JSON_STATE_STREAM", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()
        .expect("Failed to spawn server");

    harness.server = Some(server);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Start the service in a background thread (it runs forever)
    // We keep the stdin handle open to prevent the client from detaching
    let temp_dir = harness.temp_dir.clone();
    let socket_path = harness.socket_path.clone();
    let mut service_child = Command::new(cargo_bin_path())
        .args(["run", "my_service"])
        .current_dir(&temp_dir)
        .env("DEVSM_SOCKET", &socket_path)
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn service client");
    // Take the stdin handle to keep the pipe open
    let _stdin_handle = service_child.stdin.take();

    // Wait for the service to start
    let service_started = harness.wait_for_file(&service_log, Duration::from_secs(5));
    assert!(service_started, "Service should have started, server_log: {}", harness.server_log());

    // Verify service started exactly once
    let initial_log = fs::read_to_string(&service_log).unwrap_or_default();
    let initial_starts = initial_log.lines().filter(|l| l.contains("started")).count();
    assert_eq!(initial_starts, 1, "Service should have started once, log: {}", initial_log);

    // Now trigger restart-selected (this restarts the first task since selection defaults to 0)
    let _ws_result = harness.run_client(&["restart-selected"]);
    // Note: restart-selected doesn't wait for completion, it just sends the command

    // Wait for restart to complete
    std::thread::sleep(Duration::from_millis(500));

    // Verify service was restarted (should have 2 "started" entries now)
    let final_log = fs::read_to_string(&service_log).unwrap_or_default();
    let final_starts = final_log.lines().filter(|l| l.contains("started")).count();
    assert_eq!(
        final_starts,
        2,
        "Service should have been restarted (2 starts total), log: {}\nserver_log: {}",
        final_log,
        harness.server_log()
    );
}

#[test]
fn tui_json_state_stream_outputs_valid_json() {
    let mut harness = TestHarness::new("tui_json_output");

    harness.write_config(
        r#"
[action.task_one]
sh = "echo one"

[action.task_two]
sh = "echo two"

[service.my_service]
sh = "while true; do sleep 1; done"
"#,
    );

    // Spawn server with JSON state stream mode
    let log_file = fs::File::create(&harness.server_log_path).expect("Failed to create server log");
    let log_file_err = log_file.try_clone().expect("Failed to clone log file");

    let server = Command::new(cargo_bin_path())
        .arg("server")
        .env("DEVSM_SOCKET", &harness.socket_path)
        .env("DEVSM_LOG_STDOUT", "1")
        .env("DEVSM_JSON_STATE_STREAM", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()
        .expect("Failed to spawn server");

    harness.server = Some(server);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Spawn TUI client to get JSON output in background
    let temp_dir = harness.temp_dir.clone();
    let socket_path = harness.socket_path.clone();
    let mut tui_child = Command::new(cargo_bin_path())
        .current_dir(&temp_dir)
        .env("DEVSM_SOCKET", &socket_path)
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn TUI client");

    let stdout = tui_child.stdout.take().expect("No stdout");

    // Read with timeout using a separate thread
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                if tx.send(line).is_err() {
                    break;
                }
            }
        }
    });

    // Wait for initial JSON state with timeout
    let state = rx.recv_timeout(Duration::from_secs(3)).ok().and_then(|line| TuiState::from_json(&line));

    // Kill TUI client
    let _ = tui_child.kill();
    let _ = tui_child.wait();

    assert!(state.is_some(), "Should receive initial JSON state, server_log: {}", harness.server_log());

    let state = state.unwrap();

    // Verify base tasks are present
    assert!(state.base_tasks.len() >= 3, "Should have at least 3 tasks, got: {:?}", state.base_tasks);

    // Verify selection is present
    assert!(state.selection.is_some(), "Should have a selection");

    // Verify task names
    assert!(state.find_task_by_name("task_one").is_some(), "Should find task_one: {:?}", state.base_tasks);
    assert!(state.find_task_by_name("task_two").is_some(), "Should find task_two: {:?}", state.base_tasks);
    assert!(state.find_task_by_name("my_service").is_some(), "Should find my_service: {:?}", state.base_tasks);
}

#[test]
fn tui_task_launcher_overlay_opens_on_space() {
    use std::io::Write;

    let mut harness = TestHarness::new("tui_task_launcher");

    harness.write_config(
        r#"
[action.my_action]
profiles = ["default", "release"]
sh = "echo hello"
"#,
    );

    // Spawn server with JSON state stream mode
    let log_file = fs::File::create(&harness.server_log_path).expect("Failed to create server log");
    let log_file_err = log_file.try_clone().expect("Failed to clone log file");

    let server = Command::new(cargo_bin_path())
        .arg("server")
        .env("DEVSM_SOCKET", &harness.socket_path)
        .env("DEVSM_LOG_STDOUT", "1")
        .env("DEVSM_JSON_STATE_STREAM", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()
        .expect("Failed to spawn server");

    harness.server = Some(server);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Spawn TUI client with piped stdin/stdout
    let temp_dir = harness.temp_dir.clone();
    let socket_path = harness.socket_path.clone();
    let mut tui_child = Command::new(cargo_bin_path())
        .current_dir(&temp_dir)
        .env("DEVSM_SOCKET", &socket_path)
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn TUI client");

    let mut stdin = tui_child.stdin.take().expect("No stdin");
    let stdout = tui_child.stdout.take().expect("No stdout");

    // Read JSON states in background
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                if tx.send(line).is_err() {
                    break;
                }
            }
        }
    });

    // Wait for initial state
    let initial_state = rx.recv_timeout(Duration::from_secs(3)).ok().and_then(|line| TuiState::from_json(&line));
    assert!(initial_state.is_some(), "Should receive initial state, server_log: {}", harness.server_log());

    // Send Space to open task launcher
    stdin.write_all(b" ").expect("Failed to send space");
    stdin.flush().expect("Failed to flush");

    // Wait for launcher overlay to appear
    let mut launcher_opened = false;
    for _ in 0..20 {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(state) = TuiState::from_json(&line) {
                if let Some(ref overlay) = state.overlay {
                    if overlay.kind.as_deref() == Some("TaskLauncher") {
                        launcher_opened = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(launcher_opened, "TaskLauncher overlay should open, server_log: {}", harness.server_log());

    // Send Escape to close launcher
    stdin.write_all(b"\x1b").expect("Failed to send escape");
    stdin.flush().expect("Failed to flush");

    // Wait for overlay to close
    let mut launcher_closed = false;
    for _ in 0..20 {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(state) = TuiState::from_json(&line) {
                if state.overlay.is_none() {
                    launcher_closed = true;
                    break;
                }
            }
        }
    }
    assert!(launcher_closed, "TaskLauncher overlay should close on Escape, server_log: {}", harness.server_log());

    // Kill TUI client
    let _ = tui_child.kill();
    let _ = tui_child.wait();
}
