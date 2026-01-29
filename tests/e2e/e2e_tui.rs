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
pub struct TuiState {
    pub tty_render_byte_count: usize,
    #[allow(dead_code)]
    collapsed: bool,
    #[allow(dead_code)]
    pub scroll: Option<TuiScrollState>,
    #[allow(dead_code)]
    selection: Option<TuiSelection>,
    #[allow(dead_code)]
    pub overlay: Option<TuiOverlay>,
    pub base_tasks: Vec<TuiBaseTask>,
    #[allow(dead_code)]
    meta_groups: Option<TuiMetaGroups>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
pub struct TuiScrollState {
    pub top: TuiScrollInfo,
    pub bottom: Option<TuiScrollInfo>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
pub struct TuiScrollInfo {
    pub is_scrolled: bool,
    pub can_scroll_up: bool,
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
pub struct TuiOverlay {
    pub kind: Option<String>,
    pub input: Option<String>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
pub struct TuiBaseTask {
    pub index: usize,
    pub name: String,
    pub jobs: Vec<TuiJob>,
}

#[derive(Debug, Clone, Jsony, Default)]
#[allow(dead_code)]
pub struct TuiJob {
    pub index: usize,
    pub status: String,
    pub exit_code: Option<u32>,
}

pub struct BenchMetrics {
    pub samples: Vec<usize>,
}

impl BenchMetrics {
    pub fn new() -> Self {
        Self { samples: Vec::new() }
    }

    pub fn push(&mut self, v: usize) {
        self.samples.push(v);
    }

    pub fn total(&self) -> usize {
        self.samples.iter().sum()
    }

    pub fn avg(&self) -> f64 {
        self.total() as f64 / self.samples.len().max(1) as f64
    }

    pub fn max(&self) -> usize {
        self.samples.iter().copied().max().unwrap_or(0)
    }

    pub fn median(&self) -> usize {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) { (sorted[mid - 1] + sorted[mid]) / 2 } else { sorted[mid] }
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }
}

impl TuiState {
    fn from_json(json: &str) -> Option<Self> {
        jsony::from_json(json).ok()
    }

    pub fn find_task_by_name(&self, name: &str) -> Option<&TuiBaseTask> {
        self.base_tasks.iter().find(|t| t.name == name)
    }
}

pub struct TuiTestClient {
    child: Child,
    stdin: ChildStdin,
    pub state_rx: Receiver<TuiState>,
}

/// Kitty keyboard protocol helper functions.
/// Encodes keys using CSI u format: ESC [ codepoint ; modifiers u
mod kitty {
    /// Modifier bits for Kitty keyboard protocol.
    const SHIFT: u8 = 1;
    const ALT: u8 = 2;
    const CTRL: u8 = 4;

    /// Encodes a key with modifiers using Kitty keyboard protocol.
    /// Returns bytes in CSI u format: ESC [ codepoint ; (modifiers + 1) u
    pub fn encode_key(key: char, ctrl: bool, alt: bool, shift: bool) -> Vec<u8> {
        let codepoint = key as u32;
        let mut modifier_mask: u8 = 0;
        if shift {
            modifier_mask |= SHIFT;
        }
        if alt {
            modifier_mask |= ALT;
        }
        if ctrl {
            modifier_mask |= CTRL;
        }
        format!("\x1b[{};{}u", codepoint, modifier_mask + 1).into_bytes()
    }

    /// Encodes Ctrl+key using Kitty keyboard protocol.
    pub fn ctrl(key: char) -> Vec<u8> {
        encode_key(key, true, false, false)
    }
}

impl TuiTestClient {
    pub fn spawn(harness: &TestHarness) -> Self {
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

    pub fn wait_until<F>(&self, predicate: F, timeout: Duration) -> Option<TuiState>
    where
        F: Fn(&TuiState) -> bool,
    {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            let recv_timeout = remaining.min(Duration::from_millis(100));
            if let Ok(state) = self.state_rx.recv_timeout(recv_timeout) {
                println!("{:#?}", state);
                if predicate(&state) {
                    return Some(state);
                }
            }
        }
        None
    }

    pub fn send_key(&mut self, key: &[u8]) {
        self.stdin.write_all(key).expect("Failed to send key");
        self.stdin.flush().expect("Failed to flush");
    }

    /// Sends a Ctrl+key using Kitty keyboard protocol encoding.
    pub fn send_ctrl_key(&mut self, key: char) {
        let bytes = kitty::ctrl(key);
        self.stdin.write_all(&bytes).expect("Failed to send key");
        self.stdin.flush().expect("Failed to flush");
    }

    pub fn drain_states(&self, timeout: Duration) {
        while self.state_rx.recv_timeout(timeout).is_ok() {}
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

    tui.send_key(b"s");
    let state = tui.wait_until(
        |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
        timeout,
    );
    assert!(state.is_some(), "Task launcher should open, server_log: {}", harness.server_log());

    tui.send_key(b"\r");

    let state = tui.wait_until(
        |s| s.find_task_by_name("my_service").map(|t| t.jobs.iter().any(|j| j.status == "Running")).unwrap_or(false),
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

    let state = tui.wait_until(|s| s.base_tasks.len() >= 3 && s.selection.is_some(), timeout);
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

    tui.send_key(b"s");

    let state = tui.wait_until(
        |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
        timeout,
    );
    assert!(state.is_some(), "TaskLauncher overlay should open, server_log: {}", harness.server_log());

    tui.send_key(b"\x1b");

    let state = tui.wait_until(|s| s.overlay.is_none(), timeout);
    assert!(state.is_some(), "TaskLauncher overlay should close on Escape, server_log: {}", harness.server_log());
}

#[test]
fn tui_scroll_state_prevents_scroll_when_logs_fit() {
    let mut harness = TestHarness::new("tui_scroll_state");

    harness.write_config(
        r#"
[action.many_logs]
sh = "for i in $(seq 1 200); do echo \"log line $i\"; done"
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

    let state = tui.wait_until(|s| s.scroll.is_some(), timeout);
    assert!(state.is_some(), "Should receive initial state with scroll info, server_log: {}", harness.server_log());

    let state = state.unwrap();
    let scroll = state.scroll.as_ref().unwrap();
    assert!(!scroll.top.is_scrolled, "Should not be scrolled initially");
    assert!(!scroll.top.can_scroll_up, "Should not be able to scroll with no logs");

    tui.send_ctrl_key('k');

    tui.send_key(b"s");
    let state = tui.wait_until(
        |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
        timeout,
    );
    assert!(state.is_some(), "TaskLauncher should open");
    let scroll = state.unwrap().scroll.unwrap();
    assert!(!scroll.top.is_scrolled, "Should NOT have entered scroll mode when logs fit on screen");

    tui.send_key(b"\x1b");
    let _ = tui.wait_until(|s| s.overlay.is_none(), timeout);

    tui.send_key(b"s");
    let _ = tui.wait_until(
        |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
        timeout,
    );
    tui.send_key(b"\r");

    let state = tui.wait_until(
        |s| {
            let task_exited = s
                .find_task_by_name("many_logs")
                .map(|t| t.jobs.iter().any(|j| j.status == "Exited" && j.exit_code == Some(0)))
                .unwrap_or(false);
            let can_scroll = s.scroll.as_ref().map(|sc| sc.top.can_scroll_up).unwrap_or(false);
            task_exited && can_scroll
        },
        timeout,
    );
    assert!(
        state.is_some(),
        "many_logs should complete and can_scroll_up should be true, server_log: {}",
        harness.server_log()
    );

    tui.send_ctrl_key('k');

    let state =
        tui.wait_until(|s| s.scroll.as_ref().map(|sc| sc.top.is_scrolled).unwrap_or(false), Duration::from_secs(2));
    assert!(state.is_some(), "Should enter scroll mode when there are enough logs");
}
