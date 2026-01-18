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

const LONG_LOG_GEN: &str = r#"for i in $(seq 1 200); do printf "Line %04d: %s\n" "$i" "ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJ"; done"#;

const COLORED_LOG_GEN: &str = r#"for i in $(seq 1 300); do
  case $((i % 4)) in
    0) printf "\033[31m[ERROR]\033[0m Line %04d: Error message content here\n" $i;;
    1) printf "\033[32m[INFO]\033[0m Line %04d: Info message content here\n" $i;;
    2) printf "\033[33m[WARN]\033[0m Line %04d: Warning message content here\n" $i;;
    3) printf "\033[34m[DEBUG]\033[0m Line %04d: Debug message content here\n" $i;;
  esac
done"#;

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
fn bench_search_next_long() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        LONG_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_search_next_long", &config);

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
    print_bench_result("bench_search_next_long", "long (200 lines, 200+ chars)", "search_next", "n", &metrics);

    assert!(metrics.len() >= 15, "Should have collected at least 15 samples, got {}", metrics.len());
}

#[test]
fn bench_search_next_colored() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '''
{}
'''
"#,
        COLORED_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_search_next_colored", &config);

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
    print_bench_result("bench_search_next_colored", "colored (300 lines)", "search_next", "n", &metrics);

    assert!(metrics.len() >= 15, "Should have collected at least 15 samples, got {}", metrics.len());
}

#[test]
fn bench_mode_change_cycle() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_mode_change_cycle", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    let metrics = bench.measure_repeated(b"v", 9);
    print_bench_result(
        "bench_mode_change_cycle",
        "plain (500 lines)",
        "mode_change",
        "v (cycles All->OnlySelected->Hybrid)",
        &metrics,
    );

    assert!(metrics.len() >= 6, "Should have collected at least 6 samples, got {}", metrics.len());
}

#[test]
fn bench_mode_1_repeated() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_mode_1_repeated", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"2");
    bench.tui.drain_states(Duration::from_millis(10));

    let metrics = bench.measure_repeated(b"1", 10);
    print_bench_result("bench_mode_1_repeated", "plain (500 lines)", "set_mode_all", "1", &metrics);

    assert!(metrics.len() >= 8, "Should have collected at least 8 samples, got {}", metrics.len());
}

#[test]
fn bench_mode_2_repeated() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_mode_2_repeated", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"1");
    bench.tui.drain_states(Duration::from_millis(10));

    let metrics = bench.measure_repeated(b"2", 10);
    print_bench_result("bench_mode_2_repeated", "plain (500 lines)", "set_mode_selected", "2", &metrics);

    assert!(metrics.len() >= 8, "Should have collected at least 8 samples, got {}", metrics.len());
}

#[test]
fn bench_mode_3_repeated() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_mode_3_repeated", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"1");
    bench.tui.drain_states(Duration::from_millis(10));

    let metrics = bench.measure_repeated(b"3", 10);
    print_bench_result("bench_mode_3_repeated", "plain (500 lines)", "set_mode_hybrid", "3", &metrics);

    assert!(metrics.len() >= 8, "Should have collected at least 8 samples, got {}", metrics.len());
}

fn multi_service_config(count: usize) -> String {
    // Use services (not actions) because only services are shown in default view mode
    let mut config = String::new();
    for i in 1..=count {
        config.push_str(&format!(
            r#"
[service.svc{i}]
sh = 'for j in $(seq 1 100); do echo "Svc{i} Line $j"; done; sleep 3600'
"#,
            i = i
        ));
    }
    config
}

#[test]
fn bench_task_selection_mode1() {
    // Use 20 services so we have plenty of room for 15 selection changes
    let config = multi_service_config(20);

    let mut bench = BenchHarness::new("bench_task_selection_mode1", &config);

    let state = bench.wait_for_task("svc1");
    assert!(state.is_some(), "Should see svc1");

    // Start first 5 services to generate logs (they'll keep running due to sleep)
    for i in 1..=5 {
        let svc_name = format!("svc{}", i);
        bench.tui.send_key(b" ");
        let _ = bench.tui.wait_until(
            |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        bench.tui.send_key(b"\r");
        // Wait for the service to start running and produce logs
        let _ = bench.tui.wait_until(
            |s| s.find_task_by_name(&svc_name).map(|t| t.jobs.iter().any(|j| j.status == "Running")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        bench.tui.send_key(b"j");
    }

    bench.tui.send_key(b"1");
    bench.tui.drain_states(Duration::from_millis(10));

    // Move cursor back to top
    for _ in 0..10 {
        bench.tui.send_key(b"k");
    }
    bench.tui.drain_states(Duration::from_millis(10));

    // Now measure 'j' presses
    let metrics = bench.measure_repeated(b"j", 15);
    print_bench_result(
        "bench_task_selection_mode1",
        "multi-service (5x100 lines + 15 more services)",
        "select_next in Mode::All (no log redraw)",
        "j",
        &metrics,
    );

    assert!(metrics.len() >= 10, "Should have collected at least 10 samples, got {}", metrics.len());
}

#[test]
fn bench_task_selection_mode2() {
    // Use 20 services so we have plenty of room for 15 selection changes
    let config = multi_service_config(20);

    let mut bench = BenchHarness::new("bench_task_selection_mode2", &config);

    let state = bench.wait_for_task("svc1");
    assert!(state.is_some(), "Should see svc1");

    // Start first 5 services to generate logs
    for i in 1..=5 {
        let svc_name = format!("svc{}", i);
        bench.tui.send_key(b" ");
        let _ = bench.tui.wait_until(
            |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        bench.tui.send_key(b"\r");
        let _ = bench.tui.wait_until(
            |s| s.find_task_by_name(&svc_name).map(|t| t.jobs.iter().any(|j| j.status == "Running")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        bench.tui.send_key(b"j");
    }

    bench.tui.send_key(b"2");
    bench.tui.drain_states(Duration::from_millis(10));

    // Move cursor back to top
    for _ in 0..10 {
        bench.tui.send_key(b"k");
    }
    bench.tui.drain_states(Duration::from_millis(10));

    // Now measure 'j' presses - Mode2 should show log redraws
    let metrics = bench.measure_repeated(b"j", 15);
    print_bench_result(
        "bench_task_selection_mode2",
        "multi-service (5x100 lines + 15 more services)",
        "select_next in Mode::OnlySelected (log redraw expected)",
        "j",
        &metrics,
    );

    assert!(metrics.len() >= 10, "Should have collected at least 10 samples, got {}", metrics.len());
}

#[test]
fn bench_task_selection_mode3() {
    // Use 20 services so we have plenty of room for 15 selection changes
    let config = multi_service_config(20);

    let mut bench = BenchHarness::new("bench_task_selection_mode3", &config);

    let state = bench.wait_for_task("svc1");
    assert!(state.is_some(), "Should see svc1");

    // Start first 5 services to generate logs
    for i in 1..=5 {
        let svc_name = format!("svc{}", i);
        bench.tui.send_key(b" ");
        let _ = bench.tui.wait_until(
            |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        bench.tui.send_key(b"\r");
        let _ = bench.tui.wait_until(
            |s| s.find_task_by_name(&svc_name).map(|t| t.jobs.iter().any(|j| j.status == "Running")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        bench.tui.send_key(b"j");
    }

    bench.tui.send_key(b"3");
    bench.tui.drain_states(Duration::from_millis(10));

    // Move cursor back to top
    for _ in 0..10 {
        bench.tui.send_key(b"k");
    }
    bench.tui.drain_states(Duration::from_millis(10));

    // Now measure 'j' presses - Mode3 should show partial log redraws
    let metrics = bench.measure_repeated(b"j", 15);
    print_bench_result(
        "bench_task_selection_mode3",
        "multi-service (5x100 lines + 15 more services)",
        "select_next in Mode::Hybrid (log redraw expected)",
        "j",
        &metrics,
    );

    assert!(metrics.len() >= 10, "Should have collected at least 10 samples, got {}", metrics.len());
}

#[test]
fn bench_mode_2_long_lines() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        LONG_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_mode_2_long_lines", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"1");
    bench.tui.drain_states(Duration::from_millis(10));

    let metrics = bench.measure_repeated(b"2", 10);
    print_bench_result("bench_mode_2_long_lines", "long (200 lines, 200+ chars)", "set_mode_selected", "2", &metrics);

    assert!(metrics.len() >= 8, "Should have collected at least 8 samples, got {}", metrics.len());
}

#[test]
fn bench_mode_2_colored() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '''
{}
'''
"#,
        COLORED_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_mode_2_colored", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    bench.tui.send_key(b"1");
    bench.tui.drain_states(Duration::from_millis(10));

    let metrics = bench.measure_repeated(b"2", 10);
    print_bench_result("bench_mode_2_colored", "colored (300 lines)", "set_mode_selected", "2", &metrics);

    assert!(metrics.len() >= 8, "Should have collected at least 8 samples, got {}", metrics.len());
}

#[test]
fn bench_workflow_debug_error() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '''
{}
'''
"#,
        COLORED_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_workflow_debug_error", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    let mut metrics = BenchMetrics::new();

    bench.tui.send_key(b"2");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    bench.tui.send_key(b"/");
    bench.tui.drain_states(Duration::from_millis(10));
    bench.tui.send_key(b"ERROR");
    bench.tui.send_key(b"\r");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    for _ in 0..5 {
        bench.tui.drain_states(Duration::from_millis(5));
        bench.tui.send_key(b"n");
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }
    }

    bench.tui.send_key(b"3");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    for _ in 0..3 {
        bench.tui.drain_states(Duration::from_millis(5));
        bench.tui.send_key(b"n");
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }
    }

    print_bench_result(
        "bench_workflow_debug_error",
        "colored (300 lines)",
        "workflow: mode2 -> search ERROR -> 5x next -> mode3 -> 3x next",
        "mixed",
        &metrics,
    );

    assert!(metrics.len() >= 8, "Should have collected at least 8 samples, got {}", metrics.len());
}

#[test]
fn bench_workflow_multi_task_review() {
    let config = r#"
[action.build]
sh = 'for i in $(seq 1 50); do echo "[BUILD] Compiling module $i..."; done; echo "[BUILD] Done"'

[action.test]
sh = 'for i in $(seq 1 30); do echo "[TEST] Running test_$i... ok"; done; echo "[TEST] 30 passed"'

[action.lint]
sh = 'for i in $(seq 1 20); do echo "[LINT] Checking file_$i.rs... clean"; done; echo "[LINT] No issues"'
"#;

    let mut bench = BenchHarness::new("bench_workflow_multi_task_review", config);

    let state = bench.wait_for_task("build");
    assert!(state.is_some(), "Should see build task");

    for task in &["build", "test", "lint"] {
        bench.tui.send_key(b" ");
        let _ = bench.tui.wait_until(
            |s| s.overlay.as_ref().map(|o| o.kind.as_deref() == Some("TaskLauncher")).unwrap_or(false),
            Duration::from_millis(TIMEOUT_MS),
        );
        bench.tui.send_key(b"\r");
        let _ = bench.wait_for_task_exit(task);
        bench.tui.send_key(b"j");
    }

    let mut metrics = BenchMetrics::new();

    bench.tui.send_key(b"2");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    for _ in 0..3 {
        bench.tui.drain_states(Duration::from_millis(5));
        bench.tui.send_key(b"j");
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }

        bench.tui.send_key(b"/");
        bench.tui.drain_states(Duration::from_millis(10));
        bench.tui.send_key(b"Done\\|passed\\|issues");
        bench.tui.send_key(b"\r");
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }

        bench.tui.send_key(b"\x1b");
        bench.tui.drain_states(Duration::from_millis(10));
    }

    print_bench_result(
        "bench_workflow_multi_task_review",
        "multi-task (build/test/lint)",
        "workflow: 3x (select task -> mode2 -> search summary)",
        "mixed",
        &metrics,
    );

    assert!(metrics.len() >= 6, "Should have collected at least 6 samples, got {}", metrics.len());
}

#[test]
fn bench_workflow_rapid_mode_switch() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_workflow_rapid_mode_switch", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    let mut metrics = BenchMetrics::new();

    let sequence = [b"1", b"2", b"3", b"2", b"1", b"3", b"1", b"2", b"3", b"1"];
    for key in sequence {
        bench.tui.drain_states(Duration::from_millis(5));
        bench.tui.send_key(key);
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }
    }

    print_bench_result(
        "bench_workflow_rapid_mode_switch",
        "plain (500 lines)",
        "workflow: rapid 1-2-3-2-1-3-1-2-3-1 mode switching",
        "1/2/3",
        &metrics,
    );

    assert!(metrics.len() >= 8, "Should have collected at least 8 samples, got {}", metrics.len());
}

#[test]
fn bench_workflow_search_and_browse() {
    let config = format!(
        r#"
[action.gen_logs]
sh = '{}'
"#,
        PLAIN_LOG_GEN
    );

    let mut bench = BenchHarness::new("bench_workflow_search_and_browse", &config);

    let state = bench.wait_for_task("gen_logs");
    assert!(state.is_some(), "Should see gen_logs task");

    bench.run_task_to_completion();

    let state = bench.wait_for_task_exit("gen_logs");
    assert!(state.is_some(), "gen_logs should complete");

    let mut metrics = BenchMetrics::new();

    bench.tui.send_key(b"2");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    bench.tui.send_key(b"/");
    bench.tui.drain_states(Duration::from_millis(10));
    bench.tui.send_key(b"100");
    bench.tui.send_key(b"\r");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    for _ in 0..3 {
        bench.tui.drain_states(Duration::from_millis(5));
        bench.tui.send_key(b"n");
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }
    }

    bench.tui.send_key(b"/");
    bench.tui.drain_states(Duration::from_millis(10));
    bench.tui.send_key(b"200");
    bench.tui.send_key(b"\r");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    for _ in 0..3 {
        bench.tui.drain_states(Duration::from_millis(5));
        bench.tui.send_key(b"n");
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }
    }

    bench.tui.send_key(b"/");
    bench.tui.drain_states(Duration::from_millis(10));
    bench.tui.send_key(b"400");
    bench.tui.send_key(b"\r");
    if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
        metrics.push(s.tty_render_byte_count);
    }

    for _ in 0..2 {
        bench.tui.drain_states(Duration::from_millis(5));
        bench.tui.send_key(b"N");
        if let Some(s) = bench.tui.wait_until(|_| true, Duration::from_millis(100)) {
            metrics.push(s.tty_render_byte_count);
        }
    }

    print_bench_result(
        "bench_workflow_search_and_browse",
        "plain (500 lines)",
        "workflow: search '100' -> 3n -> search '200' -> 3n -> search '400' -> 2N",
        "mixed",
        &metrics,
    );

    assert!(metrics.len() >= 10, "Should have collected at least 10 samples, got {}", metrics.len());
}
