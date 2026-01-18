//! Render performance benchmarks for scroll view optimization.
//!
//! These tests measure `tty_render_byte_count` to establish baseline metrics
//! for scroll view rendering before optimization work.
//!
//! Note: Log view scrolling is mouse-only (no keyboard bindings in Global mode).
//! These benchmarks focus on search navigation and mode changes which do trigger
//! log view re-renders.

use crate::e2e_tui::{BenchMetrics, TuiState, TuiTestClient};
use crate::harness::{TestHarness, cargo_bin_path};

use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;

const PLAIN_LOG_GEN: &str =
    r#"for i in $(seq 1 500); do echo "Line $i: plain text output for baseline benchmarking"; done"#;

// const LONG_LOG_GEN: &str = r#"for i in $(seq 1 200); do printf "Line %04d: %s\n" "$i" "ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ"; done"#;

// const COLORED_LOG_GEN: &str = r#"for i in $(seq 1 300); do
//   case $((i % 4)) in
//     0) printf "\033[31m[ERROR]\033[0m Line %04d: Error message content here\n" $i;;
//     1) printf "\033[32m[INFO]\033[0m Line %04d: Info message content here\n" $i;;
//     2) printf "\033[33m[WARN]\033[0m Line %04d: Warning message content here\n" $i;;
//     3) printf "\033[34m[DEBUG]\033[0m Line %04d: Debug message content here\n" $i;;
//   esac
// done"#;

const TIMEOUT_MS: u64 = 500;

struct BenchHarness {
    harness: TestHarness,
    tui: TuiTestClient,
}

impl BenchHarness {
    fn new(name: &str, config: &str) -> Self {
        let mut harness = TestHarness::new(name);
        harness.write_config(config);

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
        assert!(harness.wait_for_socket(Duration::from_millis(TIMEOUT_MS)), "Server socket not created");

        let tui = TuiTestClient::spawn(&harness);

        Self { harness, tui }
    }

    fn wait_for_task(&self, task_name: &str) -> Option<TuiState> {
        self.tui.wait_until(|s| s.find_task_by_name(task_name).is_some(), Duration::from_millis(TIMEOUT_MS))
    }

    fn wait_for_task_exit(&self, task_name: &str) -> Option<TuiState> {
        self.tui.wait_until(
            |s| s.find_task_by_name(task_name).map(|t| t.jobs.iter().any(|j| j.status == "Exited")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        )
    }

    fn run_task_to_completion(&mut self) {
        self.tui.send_key(b" ");
        let state = self.tui.wait_until(
            |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        assert!(state.is_some(), "TaskLauncher should open, server_log: {}", self.harness.server_log());

        self.tui.send_key(b"\r");
    }

    fn measure_repeated(&mut self, key: &[u8], count: usize) -> BenchMetrics {
        let mut metrics = BenchMetrics::new();
        for _ in 0..count {
            self.tui.drain_states(Duration::from_millis(5));
            self.tui.send_key(key);
            if let Some(state) = self.tui.wait_until(|_| true, Duration::from_millis(100)) {
                metrics.push(state.tty_render_byte_count);
            }
        }
        metrics
    }

    fn measure_ctrl_key_repeated(&mut self, key: char, count: usize) -> BenchMetrics {
        let mut metrics = BenchMetrics::new();
        for _ in 0..count {
            self.tui.drain_states(Duration::from_millis(5));
            self.tui.send_ctrl_key(key);
            if let Some(state) = self.tui.wait_until(|_| true, Duration::from_millis(100)) {
                metrics.push(state.tty_render_byte_count);
            }
        }
        metrics
    }
}

fn print_bench_result(name: &str, log_type: &str, action: &str, key: &str, metrics: &BenchMetrics) {
    println!("\n=== {} ===", name);
    println!("  Log type: {}", log_type);
    println!("  Action: {} ({})", action, key);
    println!("  Repetitions: {}", metrics.len());
    println!("  Total bytes: {}", metrics.total());
    println!("  Avg bytes/action: {:.0}", metrics.avg());
    println!("  Median bytes: {}", metrics.median());
    println!("  Max bytes: {}", metrics.max());
}

#[test]
fn bench_search_next_plain() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_search_next_plain", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"2");
    bench.tui.drain_states(Duration::from_millis(10));

    bench.tui.send_key(b"/");
    bench.tui.drain_states(Duration::from_millis(10));
    bench.tui.send_key(b"Line");
    bench.tui.send_key(b"\r");
    bench.tui.drain_states(Duration::from_millis(10));

    let metrics = bench.measure_repeated(b"n", 20);
    print_bench_result("bench_search_next_plain", "plain (500 lines)", "search_next", "n", &metrics);

    assert!(metrics.len() >= 15, "Should have collected at least 15 samples, got {}", metrics.len());
}

#[test]
fn bench_search_prev_plain() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_search_prev_plain", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"2");
    bench.tui.drain_states(Duration::from_millis(10));

    bench.tui.send_key(b"/");
    bench.tui.drain_states(Duration::from_millis(10));
    bench.tui.send_key(b"Line");
    bench.tui.send_key(b"\r");
    bench.tui.drain_states(Duration::from_millis(10));

    for _ in 0..30 {
        bench.tui.send_key(b"n");
    }
    bench.tui.drain_states(Duration::from_millis(20));

    let metrics = bench.measure_repeated(b"N", 20);
    print_bench_result("bench_search_prev_plain", "plain (500 lines)", "search_prev", "N", &metrics);

    assert!(metrics.len() >= 15, "Should have collected at least 15 samples, got {}", metrics.len());
}

#[test]
fn bench_log_scroll_up_plain() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_log_scroll_up_plain", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"2");
    bench.tui.drain_states(Duration::from_millis(10));

    let metrics = bench.measure_ctrl_key_repeated('k', 20);
    print_bench_result("bench_log_scroll_up_plain", "plain (500 lines)", "log_scroll_up", "Ctrl-k", &metrics);

    assert!(metrics.len() >= 15, "Should have collected at least 15 samples, got {}", metrics.len());
}

#[test]
fn bench_log_scroll_down_plain() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_log_scroll_down_plain", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"2");
    bench.tui.drain_states(Duration::from_millis(10));

    for _ in 0..30 {
        bench.tui.send_ctrl_key('k');
    }
    bench.tui.drain_states(Duration::from_millis(20));

    let metrics = bench.measure_ctrl_key_repeated('j', 20);
    print_bench_result("bench_log_scroll_down_plain", "plain (500 lines)", "log_scroll_down", "Ctrl-j", &metrics);

    assert!(metrics.len() >= 15, "Should have collected at least 15 samples, got {}", metrics.len());
}

#[test]
fn bench_log_scroll_at_boundary() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_log_scroll_at_boundary", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"2");
    bench.tui.drain_states(Duration::from_millis(10));

    for _ in 0..200 {
        bench.tui.send_ctrl_key('k');
    }
    bench.tui.drain_states(Duration::from_millis(50));

    let metrics = bench.measure_ctrl_key_repeated('k', 10);
    print_bench_result(
        "bench_log_scroll_at_boundary",
        "plain (500 lines)",
        "Ctrl-k at scroll boundary (no more history to show)",
        "Ctrl-k",
        &metrics,
    );

    if metrics.len() > 0 {
        println!("  Note: At boundary, each action should emit minimal or zero bytes");
        if metrics.median() > 100 {
            println!("  WARNING: High byte count at boundary - scroll boundary optimization may not be working");
        }
    }
}
