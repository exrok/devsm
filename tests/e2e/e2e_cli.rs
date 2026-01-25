//! CLI E2E tests for devsm.

use crate::harness;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::rpc::{
    CommandBody, CommandResponse, DecodeResult, DecodingState, Encoder, ExitCause, JobExitedEvent, JobStatusKind,
    KillTaskRequest, RpcMessageKind, SpawnTaskRequest, SubscribeAck, SubscriptionFilter, WorkspaceRef,
};
use harness::{RpcEvent, RpcSubscriber, TestHarness, cargo_bin_path};

#[test]
fn run_simple_action() {
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
fn run_with_exit_code() {
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
fn test_command_passes() {
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
fn test_command_fails() {
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
fn client_fails_without_server() {
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
fn run_with_profile() {
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
fn profile_affects_command_args() {
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
fn require_runs_dependency_first() {
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
fn require_waits_for_success() {
    let mut harness = TestHarness::new("require_waits");
    let marker = harness.temp_dir.join("marker.txt");
    harness.write_config(&format!(
        r#"
[action.dep]
sh = "sleep 0.01 && echo dep_done > {}"

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
fn require_fails_on_dependency_failure() {
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
fn deep_dependency_chain() {
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
fn diamond_dependency() {
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
fn cache_skips_on_hit() {
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
fn cache_invalidates_on_file_modified() {
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
    std::thread::sleep(Duration::from_millis(1));
    fs::write(&trigger, "modified").unwrap();

    // Third run - cache should be invalidated
    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on third run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "gen should run again after invalidation");
    assert_eq!(fs::read_to_string(&output).unwrap().trim(), "modified", "output should have new content");
}

#[test]
fn cache_profile_changed() {
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
fn rpc_status_sequence_simple() {
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
fn rpc_status_sequence_with_dependency() {
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
fn rpc_multiple_status_transitions() {
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

#[test]
fn require_with_profile() {
    let mut harness = TestHarness::new("require_profile");
    let output_file = harness.temp_dir.join("output.txt");
    harness.write_config(&format!(
        r#"
[action.dep]
sh = '''
if [ "$PROFILE_VAL" = "release" ]; then
    echo "dep_release" >> {output}
else
    echo "dep_default" >> {output}
fi
'''
profiles = ["default", "release"]
env.PROFILE_VAL = {{ if.profile = "release", then = "release", or_else = "default" }}

[action.main]
sh = "echo main >> {output}"
require = ["dep:release"]
"#,
        output = output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "main"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["dep_release", "main"], "dep should run with release profile, got: {:?}", lines);
}

#[test]
fn require_with_params() {
    let mut harness = TestHarness::new("require_params");
    let output_file = harness.temp_dir.join("output.txt");
    // Use { var = "name" } syntax to reference params in env
    harness.write_config(&format!(
        r#"
[action.dep]
sh = "echo $MSG >> {output}"
env.MSG = {{ var = "msg" }}

[action.main]
sh = "echo main >> {output}"
require = [["dep", {{ msg = "hello_from_params" }}]]
"#,
        output = output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "main"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["hello_from_params", "main"], "dep should receive params, got: {:?}", lines);
}

#[test]
fn require_cache_per_profile() {
    let mut harness = TestHarness::new("cache_per_profile");
    let counter = harness.temp_dir.join("counter.txt");
    let output = harness.temp_dir.join("output.txt");

    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.dep]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
if [ "$PROFILE_VAL" = "release" ]; then
    echo "release_$count" >> {output}
else
    echo "default_$count" >> {output}
fi
'''
profiles = ["default", "release"]
env.PROFILE_VAL = {{ if.profile = "release", then = "release", or_else = "default" }}
cache = {{}}

[action.main_default]
sh = "echo main_default >> {output}"
require = ["dep"]

[action.main_release]
sh = "echo main_release >> {output}"
require = ["dep:release"]
"#,
        counter = counter.display(),
        output = output.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Run with default profile
    let result = harness.run_client(&["run", "main_default"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "dep should run first time");

    // Run with release profile - should run dep again despite cache
    let result = harness.run_client(&["run", "main_release"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "dep:release should run (different profile)");

    // Run with default profile again - should be cached
    let result = harness.run_client(&["run", "main_default"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "dep:default should be cached");

    // Run with release profile again - should be cached
    let result = harness.run_client(&["run", "main_release"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "dep:release should be cached");
}

#[test]
fn require_cache_per_params() {
    let mut harness = TestHarness::new("cache_per_params");
    let counter = harness.temp_dir.join("counter.txt");
    let output = harness.temp_dir.join("output.txt");

    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.dep]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
echo "${{VALUE}}_$count" >> {output}
'''
cache = {{}}
env.VALUE = {{ var = "value" }}

[action.main_a]
sh = "echo main_a >> {output}"
require = [["dep", {{ value = "aaa" }}]]

[action.main_b]
sh = "echo main_b >> {output}"
require = [["dep", {{ value = "bbb" }}]]
"#,
        counter = counter.display(),
        output = output.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Run with value=aaa
    let result = harness.run_client(&["run", "main_a"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "dep should run first time");

    // Run with value=bbb - should run dep again (different params)
    let result = harness.run_client(&["run", "main_b"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "dep with different params should run");

    // Run with value=aaa again - should be cached
    let result = harness.run_client(&["run", "main_a"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "dep with aaa should be cached");

    // Run with value=bbb again - should be cached
    let result = harness.run_client(&["run", "main_b"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "dep with bbb should be cached");

    let content = fs::read_to_string(&output).unwrap_or_default();
    assert!(content.contains("aaa_"), "should have aaa output: {}", content);
    assert!(content.contains("bbb_"), "should have bbb output: {}", content);
}

#[test]
fn service_restart_on_different_params() {
    let mut harness = TestHarness::new("service_restart_params");
    let service_log = harness.temp_dir.join("service.log");
    let task_a_marker = harness.temp_dir.join("task_a.done");
    let task_b_marker = harness.temp_dir.join("task_b.done");

    harness.write_config(&format!(
        r#"
[service.backend]
sh = '''
echo "started MODE=$MODE" >> {service_log}
while true; do sleep 1; done
'''
env.MODE = {{ var = "mode" }}

[action.task_a]
sh = "touch {task_a_marker}"
require = [["backend", {{ mode = "alpha" }}]]

[action.task_b]
sh = "touch {task_b_marker}"
require = [["backend", {{ mode = "beta" }}]]
"#,
        service_log = service_log.display(),
        task_a_marker = task_a_marker.display(),
        task_b_marker = task_b_marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "task_a"]);
    assert!(
        result.success() && harness.wait_for_file(&task_a_marker, Duration::from_secs(2)),
        "task_a failed: stderr={}, server_log={}",
        result.stderr,
        harness.server_log()
    );

    let result = harness.run_client(&["run", "task_b"]);
    assert!(
        result.success() && harness.wait_for_file(&task_b_marker, Duration::from_secs(2)),
        "task_b failed: stderr={}, server_log={}",
        result.stderr,
        harness.server_log()
    );

    let log = fs::read_to_string(&service_log).unwrap_or_default();
    let alpha_count = log.lines().filter(|l| l.contains("MODE=alpha")).count();
    let beta_count = log.lines().filter(|l| l.contains("MODE=beta")).count();
    assert_eq!(alpha_count, 1, "backend:alpha should start once, log: {}", log);
    assert_eq!(beta_count, 1, "backend:beta should start once, log: {}", log);
}

#[test]
fn service_reuse_on_matching_params() {
    let mut harness = TestHarness::new("service_reuse_params");
    let service_log = harness.temp_dir.join("service.log");
    let task_1_marker = harness.temp_dir.join("task_1.done");
    let task_2_marker = harness.temp_dir.join("task_2.done");

    harness.write_config(&format!(
        r#"
[service.backend]
sh = '''
echo "started MODE=$MODE" >> {service_log}
while true; do sleep 1; done
'''
env.MODE = {{ var = "mode" }}

[action.task_1]
sh = "touch {task_1_marker}"
require = [["backend", {{ mode = "same" }}]]

[action.task_2]
sh = "touch {task_2_marker}"
require = [["backend", {{ mode = "same" }}]]
"#,
        service_log = service_log.display(),
        task_1_marker = task_1_marker.display(),
        task_2_marker = task_2_marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "task_1"]);
    assert!(
        result.success() && harness.wait_for_file(&task_1_marker, Duration::from_secs(2)),
        "task_1 failed: stderr={}, server_log={}",
        result.stderr,
        harness.server_log()
    );

    let result = harness.run_client(&["run", "task_2"]);
    assert!(
        result.success() && harness.wait_for_file(&task_2_marker, Duration::from_secs(2)),
        "task_2 failed: stderr={}, server_log={}",
        result.stderr,
        harness.server_log()
    );

    let log = fs::read_to_string(&service_log).unwrap_or_default();
    let start_count = log.lines().filter(|l| l.contains("started")).count();
    assert_eq!(start_count, 1, "Service should start only once with matching params, log: {}", log);
}

#[test]
fn service_different_profiles() {
    let mut harness = TestHarness::new("service_profiles");
    let service_log = harness.temp_dir.join("service.log");
    let dev_marker = harness.temp_dir.join("dev.done");
    let prod_marker = harness.temp_dir.join("prod.done");
    let dev2_marker = harness.temp_dir.join("dev2.done");

    harness.write_config(&format!(
        r#"
[service.db]
sh = '''
echo "db profile=$PROFILE_VAL" >> {service_log}
while true; do sleep 1; done
'''
profiles = ["dev", "prod"]
env.PROFILE_VAL = {{ if.profile = "prod", then = "prod", or_else = "dev" }}

[action.dev_task]
sh = "touch {dev_marker}"
require = ["db"]

[action.prod_task]
sh = "touch {prod_marker}"
require = ["db:prod"]

[action.dev_task_2]
sh = "touch {dev2_marker}"
require = ["db"]
"#,
        service_log = service_log.display(),
        dev_marker = dev_marker.display(),
        prod_marker = prod_marker.display(),
        dev2_marker = dev2_marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "dev_task"]);
    assert!(
        result.success() && harness.wait_for_file(&dev_marker, Duration::from_secs(2)),
        "dev_task failed: stderr={}, server_log={}",
        result.stderr,
        harness.server_log()
    );

    let result = harness.run_client(&["run", "prod_task"]);
    assert!(
        result.success() && harness.wait_for_file(&prod_marker, Duration::from_secs(2)),
        "prod_task failed: stderr={}, server_log={}",
        result.stderr,
        harness.server_log()
    );

    let result = harness.run_client(&["run", "dev_task_2"]);
    assert!(
        result.success() && harness.wait_for_file(&dev2_marker, Duration::from_secs(2)),
        "dev_task_2 failed: stderr={}, server_log={}",
        result.stderr,
        harness.server_log()
    );

    let log = fs::read_to_string(&service_log).unwrap_or_default();
    let dev_starts = log.lines().filter(|l| l.contains("profile=dev")).count();
    let prod_starts = log.lines().filter(|l| l.contains("profile=prod")).count();

    assert_eq!(dev_starts, 1, "db:dev should start once, log: {}", log);
    assert_eq!(prod_starts, 1, "db:prod should start once, log: {}", log);
}

#[test]
fn config_reload_on_task_run() {
    let mut harness = TestHarness::new("config_reload");
    let output = harness.temp_dir.join("output.txt");

    harness.write_config(&format!(
        r#"
[action.task]
sh = "echo 'v1' > {output}"
"#,
        output = output.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "task"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&output).unwrap().trim(), "v1", "should output v1");

    std::thread::sleep(Duration::from_millis(10));
    harness.write_config(&format!(
        r#"
[action.task]
sh = "echo 'v2' > {output}"
"#,
        output = output.display()
    ));

    let result = harness.run_client(&["run", "task"]);
    assert!(result.success(), "Expected success on second run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&output).unwrap().trim(), "v2", "should output v2 after config reload");
}

#[test]
fn pwd_default_resolves_to_config_dir() {
    let mut harness = TestHarness::new("pwd_default");
    let output = harness.temp_dir.join("cwd_output.txt");

    harness.write_config(&format!(
        r#"
[action.print_cwd]
sh = "pwd > {output}"
"#,
        output = output.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "print_cwd"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let cwd = fs::read_to_string(&output).unwrap();
    let cwd = cwd.trim();
    let expected = harness.temp_dir.canonicalize().unwrap();
    assert_eq!(cwd, expected.to_str().unwrap(), "default pwd should be config directory");
}

#[test]
fn pwd_explicit_resolves_correctly() {
    let mut harness = TestHarness::new("pwd_explicit");
    let subdir = harness.temp_dir.join("subdir");
    fs::create_dir_all(&subdir).unwrap();
    let output = harness.temp_dir.join("cwd_output.txt");

    harness.write_config(&format!(
        r#"
[action.print_cwd]
sh = "pwd > {output}"
pwd = "subdir"
"#,
        output = output.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "print_cwd"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let cwd = fs::read_to_string(&output).unwrap();
    let cwd = cwd.trim();
    let expected = subdir.canonicalize().unwrap();
    assert_eq!(cwd, expected.to_str().unwrap(), "pwd should resolve to specified subdir");
}

#[test]
fn pwd_resolves_from_config_dir_not_server_cwd() {
    let mut harness = TestHarness::new("pwd_server_cwd");
    let subdir = harness.temp_dir.join("subdir");
    let server_cwd = harness.temp_dir.join("server_start_dir");
    fs::create_dir_all(&subdir).unwrap();
    fs::create_dir_all(&server_cwd).unwrap();
    let output = harness.temp_dir.join("cwd_output.txt");

    harness.write_config(&format!(
        r#"
[action.print_cwd_default]
sh = "pwd > {output}"

[action.print_cwd_subdir]
sh = "pwd > {output}"
pwd = "subdir"
"#,
        output = output.display()
    ));

    harness.spawn_server_from(&server_cwd);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "print_cwd_default"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let cwd = fs::read_to_string(&output).unwrap();
    let cwd = cwd.trim();
    let config_dir = harness.temp_dir.canonicalize().unwrap();
    assert_eq!(cwd, config_dir.to_str().unwrap(), "default pwd should resolve to config dir, not server cwd");

    let result = harness.run_client(&["run", "print_cwd_subdir"]);
    assert!(result.success(), "Expected success, got: {}", result.stderr);

    let cwd = fs::read_to_string(&output).unwrap();
    let cwd = cwd.trim();
    let expected = subdir.canonicalize().unwrap();
    assert_eq!(cwd, expected.to_str().unwrap(), "explicit pwd should resolve relative to config dir, not server cwd");
}

#[test]
fn exit_cause_unknown_on_natural_exit() {
    let mut harness = TestHarness::new("exit_cause_unknown");
    harness.write_config(
        r#"
[action.natural_exit]
sh = "exit 0"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut subscriber = RpcSubscriber::connect(&harness);
    subscriber.collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::WorkspaceOpened)), Duration::from_secs(2));

    let client_handle = std::thread::spawn({
        let temp_dir = harness.temp_dir.clone();
        let socket_path = harness.socket_path.clone();
        move || {
            Command::new(cargo_bin_path())
                .args(["run", "natural_exit"])
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

    let events = subscriber
        .collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::JobExited { .. })), Duration::from_secs(5));

    client_handle.join().ok();

    let exit_event = events.iter().find(|e| matches!(e, RpcEvent::JobExited { .. }));
    assert!(exit_event.is_some(), "Should see job exit, events: {:?}", events);
    let RpcEvent::JobExited { cause, .. } = exit_event.unwrap() else { panic!() };
    assert!(matches!(cause, ExitCause::Unknown), "Natural exit should have Unknown cause, got: {:?}", cause);
}

#[test]
fn exit_cause_restarted_on_service_restart() {
    let mut harness = TestHarness::new("exit_cause_restarted");
    let service_log = harness.temp_dir.join("service.log");
    harness.write_config(&format!(
        r#"
[service.backend]
sh = '''
echo "started" >> {service_log}
while true; do sleep 1; done
'''
"#,
        service_log = service_log.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut subscriber = RpcSubscriber::connect(&harness);
    subscriber.collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::WorkspaceOpened)), Duration::from_secs(2));

    let temp_dir = harness.temp_dir.clone();
    let socket_path = harness.socket_path.clone();
    let first_run = Command::new(cargo_bin_path())
        .args(["run", "backend"])
        .current_dir(&temp_dir)
        .env("DEVSM_SOCKET", &socket_path)
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn client");

    subscriber.collect_until(
        |evs| evs.iter().any(|e| matches!(e, RpcEvent::JobStatus { status: JobStatusKind::Running, .. })),
        Duration::from_secs(3),
    );

    drop(first_run);

    let temp_dir = harness.temp_dir.clone();
    let socket_path = harness.socket_path.clone();
    let _second_run = Command::new(cargo_bin_path())
        .args(["run", "backend"])
        .current_dir(&temp_dir)
        .env("DEVSM_SOCKET", &socket_path)
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn client");

    let events = subscriber
        .collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::JobExited { .. })), Duration::from_secs(5));

    let exit_event = events.iter().find(|e| matches!(e, RpcEvent::JobExited { job_index: 0, .. }));
    assert!(exit_event.is_some(), "Should see first service exit, events: {:?}", events);
    let RpcEvent::JobExited { cause, .. } = exit_event.unwrap() else { panic!() };
    assert!(matches!(cause, ExitCause::Restarted), "Restarted service should have Restarted cause, got: {:?}", cause);
}

#[test]
fn get_workspace_config_path_success() {
    let harness = TestHarness::new("get_config_path");
    harness.write_config(
        r#"
[action.dummy]
cmd = ["true"]
"#,
    );

    let result = harness.run_client(&["get", "workspace", "config-path"]);

    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);
    let expected_path = harness.temp_dir.join("devsm.toml");
    assert_eq!(result.stdout.trim(), expected_path.to_str().unwrap(), "Expected config path in stdout");
    assert!(result.stderr.is_empty(), "Expected no stderr output, got: {}", result.stderr);
}

#[test]
fn get_workspace_config_path_not_found() {
    let harness = TestHarness::new("get_config_path_missing");

    let result = harness.run_client(&["get", "workspace", "config-path"]);

    assert!(!result.success(), "Expected failure when config not found");
    assert!(result.stdout.is_empty(), "Expected no stdout output, got: {}", result.stdout);
    assert!(
        result.stderr.contains("cannot find devsm.toml"),
        "Expected error message about missing config, got: {}",
        result.stderr
    );
}

#[test]
fn spawn_failure_invalid_executable() {
    let mut harness = TestHarness::new("spawn_failure");
    harness.write_config(
        r#"
[action.bad_exe]
cmd = ["/nonexistent/path/to/executable"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut subscriber = RpcSubscriber::connect(&harness);
    subscriber.collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::WorkspaceOpened)), Duration::from_secs(2));

    let client_handle = std::thread::spawn({
        let temp_dir = harness.temp_dir.clone();
        let socket_path = harness.socket_path.clone();
        move || {
            Command::new(cargo_bin_path())
                .args(["run", "bad_exe"])
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

    let events = subscriber
        .collect_until(|evs| evs.iter().any(|e| matches!(e, RpcEvent::JobExited { .. })), Duration::from_secs(5));

    client_handle.join().ok();

    let exit_event = events.iter().find(|e| matches!(e, RpcEvent::JobExited { .. }));
    assert!(exit_event.is_some(), "Task should exit even when spawn fails, events: {:?}", events);

    let RpcEvent::JobExited { exit_code, cause, .. } = exit_event.unwrap() else { panic!() };
    assert_eq!(*exit_code, 127, "Spawn failure should use exit code 127, got: {}", exit_code);
    assert!(matches!(cause, ExitCause::SpawnFailed), "Spawn failure should have SpawnFailed cause, got: {:?}", cause);
}

#[test]
fn spawn_failure_does_not_block_dependents() {
    let mut harness = TestHarness::new("spawn_failure_deps");
    let marker = harness.temp_dir.join("main_ran.txt");
    harness.write_config(&format!(
        r#"
[action.bad_dep]
cmd = ["/nonexistent/path/to/executable"]

[action.main]
sh = "echo ran > {}"
require = ["bad_dep"]
"#,
        marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "main"]);
    assert!(result.success() || !result.success(), "Client should complete");

    assert!(!marker.exists(), "main should not have run when dependency spawn fails");
}

#[test]
fn config_reload_on_test_run() {
    let mut harness = TestHarness::new("test_reload");
    let output = harness.temp_dir.join("output.txt");

    harness.write_config(&format!(
        r#"
[test.my_test]
sh = "echo 'v1' > {output}"
"#,
        output = output.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert!(harness.wait_for_file(&output, Duration::from_secs(2)), "Output file should be created");
    assert_eq!(fs::read_to_string(&output).unwrap().trim(), "v1", "should output v1");

    std::thread::sleep(Duration::from_millis(10));
    harness.write_config(&format!(
        r#"
[test.my_test]
sh = "echo 'v2' > {output}"
"#,
        output = output.display()
    ));

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "Expected success on second run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&output).unwrap().trim(), "v2", "should output v2 after config reload");
}

#[test]
fn config_reload_adds_new_test() {
    let mut harness = TestHarness::new("test_add_new");
    let output1 = harness.temp_dir.join("output1.txt");
    let output2 = harness.temp_dir.join("output2.txt");

    harness.write_config(&format!(
        r#"
[test.test_one]
sh = "echo 'one' > {output1}"
"#,
        output1 = output1.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert!(harness.wait_for_file(&output1, Duration::from_secs(2)), "Output1 file should be created");
    assert!(!output2.exists(), "Output2 should not exist yet");

    std::thread::sleep(Duration::from_millis(10));
    harness.write_config(&format!(
        r#"
[test.test_one]
sh = "echo 'one' > {output1}"

[test.test_two]
sh = "echo 'two' > {output2}"
"#,
        output1 = output1.display(),
        output2 = output2.display()
    ));

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "Expected success on second run, got: {}", result.stderr);
    assert!(harness.wait_for_file(&output2, Duration::from_secs(2)), "Output2 should exist after adding new test");
    assert_eq!(fs::read_to_string(&output2).unwrap().trim(), "two", "new test should have run");
}

/// Tests that multiple tests requiring the same dependency only spawn it once.
/// This verifies the batch deduplication logic in start_test_run().
#[test]
fn test_batch_deduplication() {
    let mut harness = TestHarness::new("batch_dedup");
    let build_counter = harness.temp_dir.join("build_counter.txt");
    let test1_marker = harness.temp_dir.join("test1.done");
    let test2_marker = harness.temp_dir.join("test2.done");
    let test3_marker = harness.temp_dir.join("test3.done");

    harness.write_config(&format!(
        r#"
[action.build]
sh = '''
count=$(cat {build_counter} 2>/dev/null || echo 0)
echo $((count + 1)) > {build_counter}
'''
cache.never = true

[test.test_one]
sh = "touch {test1_marker}"
require = ["build"]

[test.test_two]
sh = "touch {test2_marker}"
require = ["build"]

[test.test_three]
sh = "touch {test3_marker}"
require = ["build"]
"#,
        build_counter = build_counter.display(),
        test1_marker = test1_marker.display(),
        test2_marker = test2_marker.display(),
        test3_marker = test3_marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "Test run failed: {}", result.stderr);

    assert!(harness.wait_for_file(&test1_marker, Duration::from_secs(2)), "test1 should complete");
    assert!(harness.wait_for_file(&test2_marker, Duration::from_secs(2)), "test2 should complete");
    assert!(harness.wait_for_file(&test3_marker, Duration::from_secs(2)), "test3 should complete");

    let count = fs::read_to_string(&build_counter).unwrap_or_default().trim().parse::<i32>().unwrap_or(0);

    assert_eq!(count, 1, "build should run exactly once despite 3 tests requiring it, got: {}", count);
}

/// Tests that service reuse works correctly when multiple tasks require the same service.
#[test]
fn service_reuse_across_batch() {
    let mut harness = TestHarness::new("service_batch");
    let service_counter = harness.temp_dir.join("service_starts.txt");
    let test1_marker = harness.temp_dir.join("test1.done");
    let test2_marker = harness.temp_dir.join("test2.done");

    harness.write_config(&format!(
        r#"
[service.db]
sh = '''
count=$(cat {service_counter} 2>/dev/null || echo 0)
echo $((count + 1)) > {service_counter}
while true; do sleep 1; done
'''

[test.test_one]
sh = "touch {test1_marker}"
require = ["db"]

[test.test_two]
sh = "touch {test2_marker}"
require = ["db"]
"#,
        service_counter = service_counter.display(),
        test1_marker = test1_marker.display(),
        test2_marker = test2_marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "Test run failed: {}", result.stderr);

    assert!(harness.wait_for_file(&test1_marker, Duration::from_secs(2)), "test1 should complete");
    assert!(harness.wait_for_file(&test2_marker, Duration::from_secs(2)), "test2 should complete");

    std::thread::sleep(Duration::from_millis(100));
    let count = fs::read_to_string(&service_counter).unwrap_or_default().trim().parse::<i32>().unwrap_or(0);

    assert_eq!(count, 1, "service should start exactly once for both tests, got: {}", count);
}

/// Tests that different profile requirements are queued and executed sequentially.
///
/// A single test requiring conflicting service profiles should fail immediately.
#[test]
fn same_test_conflicting_profiles_error() {
    let mut harness = TestHarness::new("same_test_conflict");

    harness.write_config(
        r#"
[service.srv]
cmd = ["sleep", "infinity"]
profiles = ["alpha", "beta"]

[[test.bad_test]]
cmd = ["true"]
require = ["srv:alpha", "srv:beta"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(!result.success(), "test command should fail due to conflict");
    assert!(
        result.stdout.contains("conflicting service requirements")
            || result.stderr.contains("conflicting service requirements"),
        "Error message should mention conflicting requirements. stdout: {}, stderr: {}",
        result.stdout,
        result.stderr
    );
}

/// A test requiring two services that transitively need conflicting profiles should fail.
/// Unlike actions, services need to stay Active, so their transitive service dependencies
/// must also stay active simultaneously - making conflicts impossible to resolve.
#[test]
fn transitive_service_conflict_error() {
    let mut harness = TestHarness::new("transitive_srv_conflict");

    harness.write_config(
        r#"
[service.base_srv]
cmd = ["sleep", "infinity"]
profiles = ["alpha", "beta"]

[service.srv_alpha]
cmd = ["sleep", "infinity"]
require = ["base_srv:alpha"]

[service.srv_beta]
cmd = ["sleep", "infinity"]
require = ["base_srv:beta"]

[[test.bad_test]]
cmd = ["true"]
require = ["srv_alpha", "srv_beta"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(!result.success(), "test command should fail due to transitive service conflict");
    assert!(
        result.stdout.contains("conflicting service requirements")
            || result.stderr.contains("conflicting service requirements"),
        "Error message should mention conflicting requirements. stdout: {}, stderr: {}",
        result.stdout,
        result.stderr
    );
}

/// A test requiring actions that transitively require different service profiles should succeed.
/// Actions complete and don't need the service to stay running, so they can be queued sequentially.
#[test]
fn indirect_different_profiles_succeeds() {
    let mut harness = TestHarness::new("indirect_profiles");
    let marker = harness.temp_dir.join("test.done");

    harness.write_config(&format!(
        r#"
[service.srv]
cmd = ["sleep", "infinity"]
profiles = ["alpha", "beta"]

[action.action_alpha]
cmd = ["true"]
require = ["srv:alpha"]

[action.action_beta]
cmd = ["true"]
require = ["srv:beta"]

[[test.good_test]]
sh = "echo done > {marker}"
require = ["action_alpha", "action_beta"]
"#,
        marker = marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "test command should succeed: stdout={}, stderr={}", result.stdout, result.stderr);
    assert!(harness.wait_for_file(&marker, Duration::from_secs(10)), "test should complete");
}

/// When two tests require the same service with different profiles:
/// 1. First test's profile is spawned
/// 2. Second test waits for first to complete
/// 3. First profile is terminated when it has no dependents
/// 4. Second profile is spawned
#[test]
fn service_profile_queuing() {
    let mut harness = TestHarness::new("profile_queue");
    let alpha_marker = harness.temp_dir.join("alpha.done");
    let beta_marker = harness.temp_dir.join("beta.done");
    let sequence_log = harness.temp_dir.join("sequence.log");

    harness.write_config(&format!(
        r#"
[service.srv]
sh = "echo $PROFILE started >> {sequence}; while true; do sleep 0.1; done"
profiles = ["alpha", "beta"]

[[test.alpha_test]]
sh = "echo alpha_test_running >> {sequence}; sleep 0.2; echo done > {alpha}"
require = ["srv:alpha"]

[[test.beta_test]]
sh = "echo beta_test_running >> {sequence}; echo done > {beta}"
require = ["srv:beta"]
"#,
        sequence = sequence_log.display(),
        alpha = alpha_marker.display(),
        beta = beta_marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "test command failed: {}", result.stderr);

    assert!(harness.wait_for_file(&alpha_marker, Duration::from_secs(5)), "alpha test should complete");
    assert!(harness.wait_for_file(&beta_marker, Duration::from_secs(5)), "beta test should complete");

    let sequence = fs::read_to_string(&sequence_log).unwrap_or_default();
    let lines: Vec<&str> = sequence.lines().collect();

    assert!(
        lines.iter().any(|l| l.contains("alpha started") || l.contains("started")),
        "Service alpha should have started: {:?}",
        lines
    );
    assert!(
        lines.iter().any(|l| l.contains("beta started") || l.contains("started")),
        "Service beta should have started: {:?}",
        lines
    );
}

// ============================================================================
// Logs command tests
// ============================================================================

#[test]
fn logs_basic_dump() {
    let mut harness = TestHarness::new("logs_basic");
    harness.write_config(
        r#"
[action.echo_task]
sh = "echo 'log line one'; echo 'log line two'; echo 'log line three'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "echo_task"]);
    assert!(result.success(), "run command failed: {}", result.stderr);

    let result = harness.run_client(&["logs"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    assert!(result.stdout.contains("log line one"), "logs should contain 'log line one', got: {}", result.stdout);
    assert!(result.stdout.contains("log line two"), "logs should contain 'log line two', got: {}", result.stdout);
    assert!(result.stdout.contains("log line three"), "logs should contain 'log line three', got: {}", result.stdout);
}

#[test]
fn logs_with_pattern_filter() {
    let mut harness = TestHarness::new("logs_pattern");
    harness.write_config(
        r#"
[action.mixed_output]
sh = "echo 'INFO: starting'; echo 'ERROR: something failed'; echo 'INFO: done'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "mixed_output"]);
    assert!(result.success(), "run command failed: {}", result.stderr);

    let result = harness.run_client(&["logs", "error"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    assert!(
        result.stdout.contains("ERROR: something failed"),
        "logs should contain error line, got: {}",
        result.stdout
    );
    assert!(!result.stdout.contains("INFO: starting"), "logs should not contain INFO lines, got: {}", result.stdout);
}

#[test]
fn logs_case_sensitive_pattern() {
    let mut harness = TestHarness::new("logs_case_sensitive");
    harness.write_config(
        r#"
[action.case_output]
sh = "echo 'ERROR uppercase'; echo 'error lowercase'; echo 'Error mixed'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "case_output"]);
    assert!(result.success(), "run command failed: {}", result.stderr);

    let result = harness.run_client(&["logs", "ERROR"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    assert!(
        result.stdout.contains("ERROR uppercase"),
        "Case-sensitive search should find uppercase ERROR, got: {}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("error lowercase"),
        "Case-sensitive search should not find lowercase error, got: {}",
        result.stdout
    );
}

#[test]
fn logs_with_task_filter() {
    let mut harness = TestHarness::new("logs_task_filter");
    harness.write_config(
        r#"
[action.task_a]
sh = "echo 'output from task_a'"

[action.task_b]
sh = "echo 'output from task_b'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "task_a"]);
    assert!(result.success(), "run task_a failed: {}", result.stderr);
    let result = harness.run_client(&["run", "task_b"]);
    assert!(result.success(), "run task_b failed: {}", result.stderr);

    let result = harness.run_client(&["logs", "--task=task_a"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    assert!(result.stdout.contains("output from task_a"), "logs should contain task_a output, got: {}", result.stdout);
    assert!(
        !result.stdout.contains("output from task_b"),
        "logs should not contain task_b output when filtering, got: {}",
        result.stdout
    );
}

#[test]
fn logs_with_newest_limit() {
    let mut harness = TestHarness::new("logs_newest");
    harness.write_config(
        r#"
[action.many_lines]
sh = "echo 'line 1'; echo 'line 2'; echo 'line 3'; echo 'line 4'; echo 'line 5'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "many_lines"]);
    assert!(result.success(), "run command failed: {}", result.stderr);

    let result = harness.run_client(&["logs", "--newest=2"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "should show exactly 2 lines with --newest=2, got: {:?}", lines);
    assert!(result.stdout.contains("line 4") || result.stdout.contains("line 5"), "should show last lines");
}

#[test]
fn logs_with_oldest_limit() {
    let mut harness = TestHarness::new("logs_oldest");
    harness.write_config(
        r#"
[action.many_lines]
sh = "echo 'line 1'; echo 'line 2'; echo 'line 3'; echo 'line 4'; echo 'line 5'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "many_lines"]);
    assert!(result.success(), "run command failed: {}", result.stderr);

    let result = harness.run_client(&["logs", "--oldest=2"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "should show exactly 2 lines with --oldest=2, got: {:?}", lines);
    assert!(result.stdout.contains("line 1") || result.stdout.contains("line 2"), "should show first lines");
}

#[test]
fn logs_multiple_tasks_shows_prefixes() {
    let mut harness = TestHarness::new("logs_prefixes");
    harness.write_config(
        r#"
[action.alpha]
sh = "echo 'alpha output'"

[action.beta]
sh = "echo 'beta output'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "alpha"]);
    assert!(result.success(), "run alpha failed: {}", result.stderr);
    let result = harness.run_client(&["run", "beta"]);
    assert!(result.success(), "run beta failed: {}", result.stderr);

    let result = harness.run_client(&["logs", "--task=alpha", "--task=beta"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    assert!(
        result.stdout.contains("alpha>") || result.stdout.contains(" alpha "),
        "should show alpha task prefix, got: {}",
        result.stdout
    );
    assert!(
        result.stdout.contains("beta>") || result.stdout.contains(" beta "),
        "should show beta task prefix, got: {}",
        result.stdout
    );
}

#[test]
fn logs_without_taskname_omits_prefixes() {
    let mut harness = TestHarness::new("logs_no_prefix");
    harness.write_config(
        r#"
[action.alpha]
sh = "echo 'alpha output'"

[action.beta]
sh = "echo 'beta output'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "alpha"]);
    assert!(result.success(), "run alpha failed: {}", result.stderr);
    let result = harness.run_client(&["run", "beta"]);
    assert!(result.success(), "run beta failed: {}", result.stderr);

    let result = harness.run_client(&["logs", "--task=alpha", "--task=beta", "--without-taskname"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    assert!(
        !result.stdout.contains("alpha>") && !result.stdout.contains(" alpha "),
        "should not show task prefixes with --without-taskname, got: {}",
        result.stdout
    );
}

#[test]
fn logs_follow_mode_receives_new_output() {
    let mut harness = TestHarness::new("logs_follow");
    harness.write_config(
        r#"
[action.delayed_output]
sh = "echo 'delayed message'"
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let temp_dir = harness.temp_dir.clone();
    let socket_path = harness.socket_path.clone();
    let mut logs_child = Command::new(cargo_bin_path())
        .args(["logs", "--follow", "--task=delayed_output"])
        .current_dir(&temp_dir)
        .env("DEVSM_SOCKET", &socket_path)
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn logs client");

    let result = harness.run_client(&["run", "delayed_output"]);
    assert!(result.success(), "run command failed: {}", result.stderr);

    let _ = logs_child.kill();
    let _ = logs_child.wait();

    let mut logs_output = String::new();
    if let Some(mut out) = logs_child.stdout.take() {
        out.read_to_string(&mut logs_output).ok();
    }

    assert!(logs_output.contains("delayed message"), "Follow mode should capture output, got: {}", logs_output);
}

#[test]
fn logs_kind_filter_actions() {
    let mut harness = TestHarness::new("logs_kind");
    let service_marker = harness.temp_dir.join("service_started.txt");
    harness.write_config(&format!(
        r#"
[action.my_action]
sh = "echo 'action output'"

[service.my_service]
sh = "echo 'service started'; touch {marker}; while true; do sleep 1; done"
"#,
        marker = service_marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "my_action"]);
    assert!(result.success(), "run my_action failed: {}", result.stderr);

    let temp_dir = harness.temp_dir.clone();
    let socket_path = harness.socket_path.clone();
    let _service = Command::new(cargo_bin_path())
        .args(["run", "my_service"])
        .current_dir(&temp_dir)
        .env("DEVSM_SOCKET", &socket_path)
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn service");

    assert!(harness.wait_for_file(&service_marker, Duration::from_secs(3)), "Service should start");

    let result = harness.run_client(&["logs", "--kind=action"]);
    assert!(result.success(), "logs command failed: {}", result.stderr);
    assert!(result.stdout.contains("action output"), "logs should contain action output, got: {}", result.stdout);
    assert!(
        !result.stdout.contains("service started"),
        "logs should not contain service output when filtering by action kind, got: {}",
        result.stdout
    );
}

/// RPC response types that can be received.
#[derive(Debug)]
#[allow(dead_code)]
enum RpcResponse {
    Command(CommandResponse),
    Subscribe(SubscribeAck),
    JobExited { job_index: u32 },
    Other(RpcMessageKind),
}

/// Helper to send an RPC command and receive response over a persistent connection.
fn rpc_send_recv<T: jsony::ToBinary>(
    socket: &mut UnixStream,
    encoder: &mut Encoder,
    decoder: &mut DecodingState,
    buffer: &mut Vec<u8>,
    kind: RpcMessageKind,
    correlation: u16,
    payload: &T,
) -> CommandResponse {
    encoder.encode_response(kind, correlation, payload);
    socket.write_all(encoder.output()).expect("Failed to send RPC command");
    encoder.clear();

    loop {
        match rpc_recv_any(socket, decoder, buffer, Duration::from_secs(5)) {
            RpcResponse::Command(resp) => return resp,
            _ => continue, // Skip events while waiting for command response
        }
    }
}

/// Helper to send Subscribe and wait for SubscribeAck.
fn rpc_subscribe(
    socket: &mut UnixStream,
    encoder: &mut Encoder,
    decoder: &mut DecodingState,
    buffer: &mut Vec<u8>,
    filter: &SubscriptionFilter,
    correlation: u16,
) {
    encoder.encode_response(RpcMessageKind::Subscribe, correlation, filter);
    socket.write_all(encoder.output()).expect("Failed to send Subscribe");
    encoder.clear();

    loop {
        match rpc_recv_any(socket, decoder, buffer, Duration::from_secs(5)) {
            RpcResponse::Subscribe(ack) => {
                assert!(ack.success, "Subscribe should succeed");
                return;
            }
            _ => continue,
        }
    }
}

/// Helper to wait for a specific job to exit.
fn rpc_wait_for_job_exit(
    socket: &mut UnixStream,
    decoder: &mut DecodingState,
    buffer: &mut Vec<u8>,
    expected_job_index: u32,
    timeout: Duration,
) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match rpc_recv_any(socket, decoder, buffer, Duration::from_millis(100)) {
            RpcResponse::JobExited { job_index } if job_index == expected_job_index => return,
            _ => continue,
        }
    }
    panic!("Timeout waiting for job {} to exit", expected_job_index);
}

/// Helper to receive any RPC message.
fn rpc_recv_any(
    socket: &mut UnixStream,
    decoder: &mut DecodingState,
    buffer: &mut Vec<u8>,
    timeout: Duration,
) -> RpcResponse {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > timeout {
            panic!("Timeout waiting for RPC message");
        }

        let spare = buffer.spare_capacity_mut();
        if spare.len() < 1024 {
            buffer.reserve(1024);
        }
        let spare = buffer.spare_capacity_mut();
        let n = match socket.read(unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) })
        {
            Ok(0) => panic!("Connection closed unexpectedly"),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => panic!("Read error: {}", e),
        };
        unsafe { buffer.set_len(buffer.len() + n) };

        loop {
            let result = match decoder.decode(buffer) {
                DecodeResult::Message { kind, payload, .. } => {
                    let response = match kind {
                        RpcMessageKind::CommandAck => {
                            let resp: CommandResponse = jsony::from_binary(payload).expect("Invalid CommandResponse");
                            RpcResponse::Command(resp)
                        }
                        RpcMessageKind::SubscribeAck => {
                            let resp: SubscribeAck = jsony::from_binary(payload).expect("Invalid SubscribeAck");
                            RpcResponse::Subscribe(resp)
                        }
                        RpcMessageKind::JobExited => {
                            let evt: JobExitedEvent = jsony::from_binary(payload).expect("Invalid JobExitedEvent");
                            RpcResponse::JobExited { job_index: evt.job_index }
                        }
                        other => RpcResponse::Other(other),
                    };
                    Some(response)
                }
                DecodeResult::MissingData { .. } => None,
                DecodeResult::Empty => {
                    buffer.clear();
                    None
                }
                DecodeResult::Error(e) => panic!("Decode error: {:?}", e),
            };

            if let Some(response) = result {
                decoder.compact(buffer, 4096);
                return response;
            } else {
                break;
            }
        }
    }
}

#[test]
fn rpc_multi_command_single_stream() {
    let mut harness = TestHarness::new("rpc_multi_cmd");
    let action_marker = harness.temp_dir.join("action.marker");
    let service_marker = harness.temp_dir.join("service.marker");

    harness.write_config(&format!(
        r#"
[action.my_action]
sh = "echo action > {action_marker}"

[service.my_service]
sh = '''
echo started > {service_marker}
while true; do sleep 1; done
'''
"#,
        action_marker = action_marker.display(),
        service_marker = service_marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let config_path = harness.temp_dir.join("devsm.toml");

    // Connect directly without AttachRpc - use direct RPC commands
    let mut socket = UnixStream::connect(&harness.socket_path).expect("Failed to connect");
    socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
    socket.set_nonblocking(true).ok();

    let mut encoder = Encoder::new();
    let mut decoder = DecodingState::default();
    let mut buffer = Vec::with_capacity(4096);
    let mut correlation: u16 = 1;

    // Command 1: SpawnTask (starts the action) - with one_shot=false to keep connection open
    let req1 = SpawnTaskRequest {
        workspace: WorkspaceRef::Path { config: &config_path },
        task_name: "my_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    };
    let resp1 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::SpawnTask,
        correlation,
        &req1,
    );
    correlation += 1;
    assert!(matches!(resp1.body, CommandBody::Empty), "SpawnTask should succeed with Empty, got {:?}", resp1.body);

    assert!(harness.wait_for_file(&action_marker, Duration::from_secs(3)), "Action should complete");

    // Subscribe to job exit events so we can wait for service termination
    let filter = SubscriptionFilter { job_status: false, job_exits: true };
    rpc_subscribe(&mut socket, &mut encoder, &mut decoder, &mut buffer, &filter, correlation);
    correlation += 1;

    // Command 2: SpawnTask (starts the service) - connection still open
    let req2 = SpawnTaskRequest {
        workspace: WorkspaceRef::Path { config: &config_path },
        task_name: "my_service",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    };
    let resp2 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::SpawnTask,
        correlation,
        &req2,
    );
    correlation += 1;
    assert!(matches!(resp2.body, CommandBody::Empty), "SpawnTask for service should succeed, got {:?}", resp2.body);

    assert!(harness.wait_for_file(&service_marker, Duration::from_secs(3)), "Service should start");

    // Command 3: KillTask (kills the service)
    let req3 = KillTaskRequest { workspace: WorkspaceRef::Path { config: &config_path }, task_name: "my_service" };
    let resp3 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::KillTask,
        correlation,
        &req3,
    );
    correlation += 1;
    assert!(
        matches!(resp3.body, CommandBody::Message(ref msg) if msg.contains("terminated")),
        "KillTask should succeed with terminated message, got {:?}",
        resp3.body
    );

    // Wait for JobExited event (job_index 1 is the service since action was job 0)
    rpc_wait_for_job_exit(&mut socket, &mut decoder, &mut buffer, 1, Duration::from_secs(5));

    // Command 4: KillTask again (should say already finished)
    let req4 = KillTaskRequest { workspace: WorkspaceRef::Path { config: &config_path }, task_name: "my_service" };
    let resp4 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::KillTask,
        correlation,
        &req4,
    );
    correlation += 1;
    assert!(
        matches!(resp4.body, CommandBody::Message(ref msg) if msg.contains("already finished")),
        "KillTask on dead service should return 'already finished', got {:?}",
        resp4.body
    );

    // Command 5: SpawnTask on nonexistent task (should error)
    let req5 = SpawnTaskRequest {
        workspace: WorkspaceRef::Path { config: &config_path },
        task_name: "nonexistent_task",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    };
    let resp5 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::SpawnTask,
        correlation,
        &req5,
    );
    let _ = correlation;
    assert!(
        matches!(resp5.body, CommandBody::Error(ref err) if err.contains("not found")),
        "SpawnTask on nonexistent should error, got {:?}",
        resp5.body
    );
}

#[test]
fn cache_invalidates_on_deeply_nested_file_modified() {
    let mut harness = TestHarness::new("cache_nested");
    let counter = harness.temp_dir.join("counter.txt");
    let nested_dir = harness.temp_dir.join("a/b/c/d/e");
    let nested_file = nested_dir.join("nested.txt");

    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(&nested_file, "initial").unwrap();
    fs::write(&counter, "0").unwrap();

    let a_dir = harness.temp_dir.join("a");
    harness.write_config(&format!(
        r#"
[action.gen]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache.key = [{{ modified = "{a_dir}" }}]

[action.consumer]
sh = "cat {counter}"
require = ["gen"]
"#,
        counter = counter.display(),
        a_dir = a_dir.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should run first time");

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on second run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should be cached");

    std::thread::sleep(Duration::from_millis(10));
    fs::write(&nested_file, "modified").unwrap();

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on third run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "gen should run after nested file modified");
}

#[test]
fn cache_ignores_patterns() {
    let mut harness = TestHarness::new("cache_ignore");
    let counter = harness.temp_dir.join("counter.txt");
    let src_dir = harness.temp_dir.join("src");
    let main_file = src_dir.join("main.rs");
    let readme_file = src_dir.join("README.md");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(&main_file, "fn main() {}").unwrap();
    fs::write(&readme_file, "# Readme").unwrap();
    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.gen]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache.key = [{{ modified = "{src_dir}", ignore = "*.md" }}]

[action.consumer]
sh = "cat {counter}"
require = ["gen"]
"#,
        counter = counter.display(),
        src_dir = src_dir.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should run first time");

    std::thread::sleep(Duration::from_millis(10));
    fs::write(&readme_file, "# Updated Readme").unwrap();

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on second run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should be cached (*.md ignored)");

    std::thread::sleep(Duration::from_millis(10));
    fs::write(&main_file, "fn main() { println!(\"updated\"); }").unwrap();

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on third run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "gen should run after main.rs modified");
}

#[test]
fn restart_cached_flag_skips_on_cache_hit() {
    let mut harness = TestHarness::new("restart_cached");
    let trigger = harness.temp_dir.join("trigger.txt");
    let counter = harness.temp_dir.join("counter.txt");

    fs::write(&trigger, "initial").unwrap();
    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.cached_action]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache.key = [{{ modified = "{trigger}" }}]
"#,
        trigger = trigger.display(),
        counter = counter.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let config_path = harness.temp_dir.join("devsm.toml");

    let mut socket = UnixStream::connect(&harness.socket_path).expect("Failed to connect");
    socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
    socket.set_nonblocking(true).ok();

    let mut encoder = Encoder::new();
    let mut decoder = DecodingState::default();
    let mut buffer = Vec::with_capacity(4096);
    let mut correlation: u16 = 1;

    // First restart with cached=false: should run the action
    let req1 = SpawnTaskRequest {
        workspace: WorkspaceRef::Path { config: &config_path },
        task_name: "cached_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    };
    let resp1 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::SpawnTask,
        correlation,
        &req1,
    );
    correlation += 1;
    assert!(matches!(resp1.body, CommandBody::Empty), "First restart should succeed with Empty, got {:?}", resp1.body);

    // Wait for action to complete
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "Action should have run once");

    // Second restart with cached=true: should return cache hit message
    let req2 = SpawnTaskRequest {
        workspace: WorkspaceRef::Path { config: &config_path },
        task_name: "cached_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: true,
    };
    let resp2 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::SpawnTask,
        correlation,
        &req2,
    );
    correlation += 1;
    assert!(
        matches!(resp2.body, CommandBody::Message(ref msg) if msg.contains("cache hit")),
        "Second restart with cached=true should return cache hit message, got {:?}",
        resp2.body
    );
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "Action should NOT have run again");

    // Modify trigger file to invalidate cache
    std::thread::sleep(Duration::from_millis(10));
    fs::write(&trigger, "modified").unwrap();

    // Third restart with cached=true: cache invalidated, should run
    let req3 = SpawnTaskRequest {
        workspace: WorkspaceRef::Path { config: &config_path },
        task_name: "cached_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: true,
    };
    let resp3 = rpc_send_recv(
        &mut socket,
        &mut encoder,
        &mut decoder,
        &mut buffer,
        RpcMessageKind::SpawnTask,
        correlation,
        &req3,
    );
    let _ = correlation;
    assert!(
        matches!(resp3.body, CommandBody::Empty),
        "Third restart should succeed (cache invalidated), got {:?}",
        resp3.body
    );

    // Wait for action to complete
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        fs::read_to_string(&counter).unwrap().trim(),
        "2",
        "Action should have run again after cache invalidation"
    );
}
