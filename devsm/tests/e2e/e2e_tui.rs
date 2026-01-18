//! TUI E2E tests for devsm.

use crate::harness;

use std::fs;
use std::io::Write;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
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

struct TuiTestClient {
    child: Child,
    stdin: ChildStdin,
    state_rx: Receiver<TuiState>,
}

impl TuiTestClient {
    fn spawn(harness: &TestHarness) -> Self {
        let mut child = Command::new(cargo_bin_path())
            .current_dir(&harness.temp_dir)
            .env("DEVSM_SOCKET", &harness.socket_path)
            .env("DEVSM_NO_AUTO_SPAWN", "1")
            .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn TUI client");

        let stdin = child.stdin.take().expect("No stdin");
        let stdout = child.stdout.take().expect("No stdout");

        let (tx, state_rx) = mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let Some(state) = TuiState::from_json(&line) else { continue };
                if tx.send(state).is_err() {
                    break;
                }
            }
        });

        Self { child, stdin, state_rx }
    }

    fn wait_until<F>(&self, predicate: F, timeout: Duration) -> Option<TuiState>
    where
        F: Fn(&TuiState) -> bool,
    {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            let recv_timeout = remaining.min(Duration::from_millis(100));
            if let Ok(state) = self.state_rx.recv_timeout(recv_timeout) {
                if predicate(&state) {
                    return Some(state);
                }
            }
        }
        None
    }

    fn send_key(&mut self, key: &[u8]) {
        self.stdin.write_all(key).expect("Failed to send key");
        self.stdin.flush().expect("Failed to flush");
    }
}

impl Drop for TuiTestClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn tui_restart_selected_restarts_service() {
    let mut harness = TestHarness::new("tui_restart_selected");

    harness.write_config(
        r#"
[service.my_service]
sh = "while true; do sleep 1; done"
"#,
    );

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

    let mut tui = TuiTestClient::spawn(&harness);
    let timeout = Duration::from_secs(5);

    let state = tui.wait_until(|s| s.find_task_by_name("my_service").is_some(), timeout);
    assert!(state.is_some(), "Should see my_service task, server_log: {}", harness.server_log());

    tui.send_key(b" ");
    let state = tui.wait_until(|s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false), timeout);
    assert!(state.is_some(), "Task launcher should open, server_log: {}", harness.server_log());

    tui.send_key(b"\r");

    let state = tui.wait_until(
        |s| {
            s.find_task_by_name("my_service")
                .map(|t| t.jobs.iter().any(|j| j.status == "Running"))
                .unwrap_or(false)
        },
        timeout,
    );
    assert!(state.is_some(), "Service should be running, server_log: {}", harness.server_log());
    let first_job_index = state.unwrap().find_task_by_name("my_service").unwrap().jobs[0].index;

    tui.send_key(b"r");

    let state = tui.wait_until(
        |s| {
            s.find_task_by_name("my_service")
                .map(|t| t.jobs.iter().any(|j| j.status == "Running" && j.index != first_job_index))
                .unwrap_or(false)
        },
        timeout,
    );
    assert!(state.is_some(), "Service should have restarted with new job, server_log: {}", harness.server_log());
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

    let tui = TuiTestClient::spawn(&harness);
    let timeout = Duration::from_secs(3);

    let state = tui.wait_until(
        |s| s.base_tasks.len() >= 3 && s.selection.is_some(),
        timeout,
    );
    assert!(state.is_some(), "Should receive initial JSON state, server_log: {}", harness.server_log());

    let state = state.unwrap();
    assert!(state.find_task_by_name("task_one").is_some(), "Should find task_one: {:?}", state.base_tasks);
    assert!(state.find_task_by_name("task_two").is_some(), "Should find task_two: {:?}", state.base_tasks);
    assert!(state.find_task_by_name("my_service").is_some(), "Should find my_service: {:?}", state.base_tasks);
}

#[test]
fn tui_task_launcher_overlay_opens_on_space() {
    let mut harness = TestHarness::new("tui_task_launcher");

    harness.write_config(
        r#"
[action.my_action]
profiles = ["default", "release"]
sh = "echo hello"
"#,
    );

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

    let mut tui = TuiTestClient::spawn(&harness);
    let timeout = Duration::from_secs(3);

    let state = tui.wait_until(|s| s.find_task_by_name("my_action").is_some(), timeout);
    assert!(state.is_some(), "Should receive initial state, server_log: {}", harness.server_log());

    tui.send_key(b" ");

    let state = tui.wait_until(
        |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
        timeout,
    );
    assert!(state.is_some(), "TaskLauncher overlay should open, server_log: {}", harness.server_log());

    tui.send_key(b"\x1b");

    let state = tui.wait_until(|s| s.overlay.is_none(), timeout);
    assert!(state.is_some(), "TaskLauncher overlay should close on Escape, server_log: {}", harness.server_log());
}
