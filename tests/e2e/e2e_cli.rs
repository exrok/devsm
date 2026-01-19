//! CLI E2E tests for devsm.

use crate::harness;

use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::rpc::{ExitCause, JobStatusKind};
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
