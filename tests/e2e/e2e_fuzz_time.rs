//! Fuzz-time e2e tests for ready timeouts, max timeouts, idle timeouts, and conditional timeouts.
//!
//! These tests use simulated time via `DEVSM_FUZZ_SOCKET` so they never sleep to
//! wait for timeouts. Instead, the test advances the daemon's clock and observes
//! the resulting behaviour via RPC events.

use std::time::Duration;

use crate::harness::{
    FuzzClock, RpcSubscriber, TestAppServer, TestHarness, find_exit_event, has_job_exit,
};
use crate::rpc::ExitCause;

// ── helpers ────────────────────────────────────────────────────────────────

fn setup_fuzz(test_name: &str) -> (TestHarness, TestAppServer) {
    let harness = TestHarness::new(test_name);
    let ctrl = TestAppServer::new(&harness.temp_dir);
    (harness, ctrl)
}

fn spawn_and_connect(harness: &mut TestHarness) -> (FuzzClock, RpcSubscriber) {
    harness.spawn_fuzz_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");
    let clock = FuzzClock::connect(harness);
    let subscriber = RpcSubscriber::connect(harness);
    (clock, subscriber)
}

// ── tests ──────────────────────────────────────────────────────────────────

/// Ready condition has a timeout. Service never outputs the ready string.
/// After advancing past the timeout, the dependent action should start because
/// the ready checker is removed.
#[test]
fn ready_timeout_unblocks_dependent() {
    let (mut harness, ctrl) = setup_fuzz("ready_timeout_unblocks");

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "READY" }}, timeout = 5 }}

[action.task]
cmd = ["test-app", "task"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc"]
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let (mut clock, _subscriber) = spawn_and_connect(&mut harness);

    let client_result = std::thread::scope(|s| {
        let handle = s.spawn(|| harness.run_client(&["run", "task"]));

        let _svc = ctrl.accept(Duration::from_secs(10));

        // Service started but never outputs "READY".
        // Advance past the 5s ready timeout.
        clock.advance_secs(6.0);

        // Dependent task should now start because ready checker timed out.
        let mut task = ctrl.accept(Duration::from_secs(10));
        assert_eq!(task.name(), "task");
        task.exit(0);

        handle.join().expect("client thread panicked")
    });

    assert!(
        client_result.success(),
        "run should succeed: stdout={}, stderr={}, server_log={}",
        client_result.stdout,
        client_result.stderr,
        harness.server_log()
    );
}

/// Action with `timeout = 10` (max). Process starts but never exits.
/// Advancing time past 10s should kill it with ExitCause::Timeout.
#[test]
fn max_timeout_kills_process() {
    let (mut harness, ctrl) = setup_fuzz("max_timeout_kills");

    harness.write_config(&format!(
        r#"
[action.slow]
cmd = ["test-app", "slow"]
env.TEST_APP_SOCKET = "{ctrl_path}"
timeout = 10
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let (mut clock, mut subscriber) = spawn_and_connect(&mut harness);

    std::thread::scope(|s| {
        let _client = s.spawn(|| harness.run_client(&["run", "slow"]));

        let _proc = ctrl.accept(Duration::from_secs(10));

        // Advance past the 10s max timeout.
        clock.advance_secs(11.0);

        // Collect the exit event.
        let events = subscriber.collect_until(|evs| has_job_exit(evs, 0), Duration::from_secs(5));
        let (_, cause) = find_exit_event(&events, 0).expect("expected job exit event");
        assert_eq!(cause, ExitCause::Timeout, "expected Timeout cause, got {cause:?}");
    });
}

/// Action with idle timeout. Process outputs something then goes silent.
/// Advancing past the idle duration should kill it.
#[test]
fn idle_timeout_kills_process() {
    let (mut harness, ctrl) = setup_fuzz("idle_timeout_kills");

    harness.write_config(&format!(
        r#"
[action.idle]
cmd = ["test-app", "idle"]
env.TEST_APP_SOCKET = "{ctrl_path}"
timeout = {{ idle = 5 }}
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let (mut clock, mut subscriber) = spawn_and_connect(&mut harness);

    std::thread::scope(|s| {
        let _client = s.spawn(|| harness.run_client(&["run", "idle"]));

        let _proc = ctrl.accept(Duration::from_secs(10));

        // last_output_at is set to base time at process start.
        // Advance past the 5s idle timeout without any output.
        clock.advance_secs(6.0);

        let events = subscriber.collect_until(|evs| has_job_exit(evs, 0), Duration::from_secs(5));
        let (_, cause) = find_exit_event(&events, 0).expect("expected job exit event");
        assert_eq!(cause, ExitCause::Timeout, "expected Timeout cause, got {cause:?}");
    });
}

/// Action with conditional timeout. Process outputs the predicate string, then
/// stays alive. Advancing past the conditional duration should kill it.
#[test]
fn conditional_timeout_kills_process() {
    let (mut harness, ctrl) = setup_fuzz("cond_timeout_kills");

    harness.write_config(&format!(
        r#"
[action.cond]
cmd = ["test-app", "cond"]
env.TEST_APP_SOCKET = "{ctrl_path}"
timeout = {{ when = {{ output_contains = "BUILD_DONE" }}, conditional = 5 }}
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let (mut clock, mut subscriber) = spawn_and_connect(&mut harness);

    std::thread::scope(|s| {
        let _client = s.spawn(|| harness.run_client(&["run", "cond"]));

        let mut proc = ctrl.accept(Duration::from_secs(10));

        // Output the predicate to start the conditional timeout.
        proc.write_stdout(b"BUILD_DONE\n");

        // Wait for the daemon to confirm it processed the output.
        subscriber.wait_for_trace("output", 0, Duration::from_secs(5));

        // Advance past conditional timeout (timeout_at ~ base + 5).
        clock.advance_secs(6.0);

        let events = subscriber.collect_until(|evs| has_job_exit(evs, 0), Duration::from_secs(5));
        let (_, cause) = find_exit_event(&events, 0).expect("expected job exit event");
        assert_eq!(cause, ExitCause::Timeout, "expected Timeout cause, got {cause:?}");
    });
}

/// Both max and conditional timeouts configured. Max is shorter than conditional.
/// Process outputs the conditional predicate, but max fires first.
#[test]
fn max_fires_before_conditional() {
    let (mut harness, ctrl) = setup_fuzz("max_before_cond");

    harness.write_config(&format!(
        r#"
[action.task]
cmd = ["test-app", "task"]
env.TEST_APP_SOCKET = "{ctrl_path}"
timeout = {{ max = 8, when = {{ output_contains = "MARKER" }}, conditional = 20 }}
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let (mut clock, mut subscriber) = spawn_and_connect(&mut harness);

    std::thread::scope(|s| {
        let _client = s.spawn(|| harness.run_client(&["run", "task"]));

        let mut proc = ctrl.accept(Duration::from_secs(10));

        // Output the conditional predicate early. Conditional timeout would be at ~20s.
        proc.write_stdout(b"MARKER\n");

        // Advance to 9s: past max(8) but before conditional(~20).
        clock.advance_secs(9.0);

        let events = subscriber.collect_until(|evs| has_job_exit(evs, 0), Duration::from_secs(5));
        let (_, cause) = find_exit_event(&events, 0).expect("expected job exit event");
        assert_eq!(cause, ExitCause::Timeout, "expected Timeout cause, got {cause:?}");
    });
}

/// Both max and conditional timeouts configured. Conditional is shorter than max.
/// Process outputs the conditional predicate, conditional fires first.
#[test]
fn conditional_fires_before_max() {
    let (mut harness, ctrl) = setup_fuzz("cond_before_max");

    harness.write_config(&format!(
        r#"
[action.task]
cmd = ["test-app", "task"]
env.TEST_APP_SOCKET = "{ctrl_path}"
timeout = {{ max = 30, when = {{ output_contains = "MARKER" }}, conditional = 5 }}
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let (mut clock, mut subscriber) = spawn_and_connect(&mut harness);

    std::thread::scope(|s| {
        let _client = s.spawn(|| harness.run_client(&["run", "task"]));

        let mut proc = ctrl.accept(Duration::from_secs(10));

        // Output predicate to start the conditional timeout.
        proc.write_stdout(b"MARKER\n");

        // Wait for the daemon to confirm it processed the output.
        subscriber.wait_for_trace("output", 0, Duration::from_secs(5));

        // Advance past conditional(5) but before max(30).
        clock.advance_secs(6.0);

        let events = subscriber.collect_until(|evs| has_job_exit(evs, 0), Duration::from_secs(5));
        let (_, cause) = find_exit_event(&events, 0).expect("expected job exit event");
        assert_eq!(cause, ExitCause::Timeout, "expected Timeout cause, got {cause:?}");
    });
}

/// Idle timeout resets when new output arrives. Process outputs at intervals
/// shorter than the idle timeout, then goes silent. The timeout only fires
/// after sufficient silence.
#[test]
fn idle_timeout_resets_on_output() {
    let (mut harness, ctrl) = setup_fuzz("idle_reset");

    harness.write_config(&format!(
        r#"
[action.task]
cmd = ["test-app", "task"]
env.TEST_APP_SOCKET = "{ctrl_path}"
timeout = {{ idle = 5 }}
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let (mut clock, mut subscriber) = spawn_and_connect(&mut harness);

    std::thread::scope(|s| {
        let _client = s.spawn(|| harness.run_client(&["run", "task"]));

        let mut proc = ctrl.accept(Duration::from_secs(10));

        // Output, advance 3s (under idle=5), output again (resets idle timer).
        proc.write_stdout(b"step 1\n");
        subscriber.wait_for_trace("output", 0, Duration::from_secs(5));
        clock.advance_secs(3.0);

        proc.write_stdout(b"step 2\n");
        subscriber.wait_for_trace("output", 0, Duration::from_secs(5));
        clock.advance_secs(3.0);

        // Total time is 6s, but only 3s since last output — should still be alive.
        // Verify no exit yet by collecting with a short real-time timeout.
        let events = subscriber.collect_until(|evs| has_job_exit(evs, 0), Duration::from_millis(500));
        assert!(
            find_exit_event(&events, 0).is_none(),
            "process should NOT have been killed yet: {events:?}"
        );

        // Now advance another 6s without output (total 6s since last output > idle=5).
        clock.advance_secs(6.0);

        let events = subscriber.collect_until(|evs| has_job_exit(evs, 0), Duration::from_secs(5));
        let (_, cause) = find_exit_event(&events, 0).expect("expected job exit event");
        assert_eq!(cause, ExitCause::Timeout, "expected Timeout cause, got {cause:?}");
    });
}
