//! E2E tests using test-app for deterministic ready-condition and service-conflict scenarios.

use std::time::Duration;

use crate::harness::{TestAppServer, TestHarness};
use crate::rpc::{CommandBody, SpawnTaskRequest, WorkspaceClient};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Service has `ready = { when = { output_contains = "READY" } }`, action depends on it.
/// The action should only start after the service outputs "READY\n".
#[test]
fn ready_blocks_dependent() {
    let mut harness = TestHarness::new("ready_blocks_dep");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "READY" }} }}

[action.task]
cmd = ["test-app", "task"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let client_result = std::thread::scope(|s| {
        let handle = s.spawn(|| harness.run_client(&["run", "task"]));

        let mut svc = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc.name(), "svc");

        svc.write_stdout(b"starting up...\n");
        std::thread::sleep(Duration::from_millis(200));
        svc.write_stdout(b"READY\n");

        let mut task = ctrl.accept(Duration::from_secs(10));
        assert_eq!(task.name(), "task");
        task.exit(0);

        handle.join().expect("client thread panicked")
    });

    assert!(
        client_result.success(),
        "run command should succeed: stdout={}, stderr={}, server_log={}",
        client_result.stdout,
        client_result.stderr,
        harness.server_log()
    );
}

/// Chain: service.db (ready) → service.api (ready, requires db) → action.migrate (requires api)
/// Verifies multi-level dependency resolution with ready conditions.
#[test]
fn ready_deep_dependency_chain() {
    let mut harness = TestHarness::new("ready_deep_chain");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.db]
cmd = ["test-app", "db"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "DB_READY" }} }}

[service.api]
cmd = ["test-app", "api"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "API_READY" }} }}
require = ["db"]

[action.migrate]
cmd = ["test-app", "migrate"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["api"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let client_result = std::thread::scope(|s| {
        let handle = s.spawn(|| harness.run_client(&["run", "migrate"]));

        let mut db = ctrl.accept(Duration::from_secs(10));
        assert_eq!(db.name(), "db");
        db.write_stdout(b"DB_READY\n");

        let mut api = ctrl.accept(Duration::from_secs(10));
        assert_eq!(api.name(), "api");
        api.write_stdout(b"API_READY\n");

        let mut migrate = ctrl.accept(Duration::from_secs(10));
        assert_eq!(migrate.name(), "migrate");
        migrate.exit(0);

        handle.join().expect("client thread panicked")
    });

    assert!(
        client_result.success(),
        "run command should succeed: stdout={}, stderr={}, server_log={}",
        client_result.stdout,
        client_result.stderr,
        harness.server_log()
    );
}

/// Two [[test.*]] entries requiring different profiles of the same service, both with ready.
/// Verifies profile conflict resolution works end-to-end with ready conditions.
#[test]
fn ready_conflict_sequential_profiles() {
    let mut harness = TestHarness::new("ready_conflict_seq");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
ready = {{ when = {{ output_contains = "SVC_READY" }} }}

[test.alpha_test]
cmd = ["test-app", "alpha_test"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:alpha"]

[test.beta_test]
cmd = ["test-app", "beta_test"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let client_result = std::thread::scope(|s| {
        let handle = s.spawn(|| harness.run_client(&["test"]));

        let mut svc1 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc1.name(), "svc");
        svc1.write_stdout(b"SVC_READY\n");

        let mut test1 = ctrl.accept(Duration::from_secs(10));
        assert!(
            test1.name() == "alpha_test" || test1.name() == "beta_test",
            "expected alpha_test or beta_test, got {}",
            test1.name()
        );
        test1.exit(0);

        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");
        svc2.write_stdout(b"SVC_READY\n");

        let mut test2 = ctrl.accept(Duration::from_secs(10));
        assert!(
            test2.name() == "alpha_test" || test2.name() == "beta_test",
            "expected alpha_test or beta_test, got {}",
            test2.name()
        );
        test2.exit(0);

        handle.join().expect("client thread panicked")
    });

    assert!(
        client_result.success(),
        "test command should succeed: stdout={}, stderr={}, server_log={}",
        client_result.stdout,
        client_result.stderr,
        harness.server_log()
    );
}

/// Two [[test.*]] entries requiring the same service (same profile) with ready.
/// Verifies the service is started once and reused, not restarted.
#[test]
fn ready_service_reuse_across_tests() {
    let mut harness = TestHarness::new("ready_svc_reuse");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "SVC_READY" }} }}

[test.first]
cmd = ["test-app", "first"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc"]

[test.second]
cmd = ["test-app", "second"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let client_result = std::thread::scope(|s| {
        let handle = s.spawn(|| harness.run_client(&["test"]));

        let mut svc = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc.name(), "svc");
        svc.write_stdout(b"SVC_READY\n");

        let mut t1 = ctrl.accept(Duration::from_secs(10));
        let mut t2 = ctrl.accept(Duration::from_secs(10));
        assert!(
            (t1.name() == "first" && t2.name() == "second") || (t1.name() == "second" && t2.name() == "first"),
            "expected first and second tests, got {} and {}",
            t1.name(),
            t2.name()
        );
        t1.exit(0);
        t2.exit(0);

        handle.join().expect("client thread panicked")
    });

    assert!(
        client_result.success(),
        "test command should succeed: stdout={}, stderr={}, server_log={}",
        client_result.stdout,
        client_result.stderr,
        harness.server_log()
    );
}

// ---------------------------------------------------------------------------
// allow_multiple tests
// ---------------------------------------------------------------------------

/// allow_multiple = true: two instances of the same service run concurrently.
#[test]
fn allow_multiple_true_concurrent() {
    let mut harness = TestHarness::new("allow_multi_true");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
allow_multiple = true
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let h1 = s.spawn(|| harness.run_client(&["run", "svc"]));

        let mut svc1 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc1.name(), "svc");

        let h2 = s.spawn(|| harness.run_client(&["run", "svc"]));

        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");

        svc1.exit(0);
        svc2.exit(0);

        let r1 = h1.join().expect("client 1 panicked");
        let r2 = h2.join().expect("client 2 panicked");
        assert!(r1.success(), "client 1: stdout={}, stderr={}", r1.stdout, r1.stderr);
        assert!(r2.success(), "client 2: stdout={}, stderr={}", r2.stdout, r2.stderr);
    });
}

#[test]
fn queued_profile_conflict_service_keeps_resource_requirements() {
    let mut harness = TestHarness::new("queued_service_resource_require");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
require = [{{ resource = "shared" }}]

[action.need_beta]
cmd = ["test-app", "need_beta"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]

[action.uses_resource]
cmd = ["test-app", "uses_resource"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = [{{ resource = "shared" }}]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["spawn", "svc:alpha"]);
    assert!(result.success(), "spawn svc:alpha: stdout={}, stderr={}", result.stdout, result.stderr);
    let mut alpha = ctrl.accept(Duration::from_secs(10));
    assert_eq!(alpha.name(), "svc");

    std::thread::scope(|s| {
        let beta_action = s.spawn(|| harness.run_client(&["run", "need_beta"]));

        assert!(
            alpha.wait_disconnected(Duration::from_secs(10)),
            "svc:alpha should be stopped before svc:beta starts; server_log={}",
            harness.server_log()
        );

        let mut beta = ctrl.accept(Duration::from_secs(10));
        assert_eq!(beta.name(), "svc");

        let mut need_beta = ctrl.accept(Duration::from_secs(10));
        assert_eq!(need_beta.name(), "need_beta");

        let resource_action = s.spawn(|| harness.run_client(&["run", "uses_resource"]));
        if let Some(mut early) = ctrl.try_accept(Duration::from_millis(300)) {
            let name = early.name().to_string();
            early.exit(1);
            panic!(
                "{name} started while svc:beta's dependent was still running; queued svc:beta did not hold resource"
            );
        }

        need_beta.exit(0);
        let beta_result = beta_action.join().expect("need_beta client panicked");
        assert!(beta_result.success(), "need_beta: stdout={}, stderr={}", beta_result.stdout, beta_result.stderr);

        assert!(
            beta.wait_disconnected(Duration::from_secs(10)),
            "svc:beta should be stopped to free the resource; server_log={}",
            harness.server_log()
        );
        let mut uses_resource = ctrl.accept(Duration::from_secs(10));
        assert_eq!(uses_resource.name(), "uses_resource");
        uses_resource.exit(0);

        let resource_result = resource_action.join().expect("uses_resource client panicked");
        assert!(
            resource_result.success(),
            "uses_resource: stdout={}, stderr={}",
            resource_result.stdout,
            resource_result.stderr
        );
    });
}

#[test]
fn single_profile_queued_requirement_waits_for_all_incompatible_instances() {
    let mut harness = TestHarness::new("single_profile_waits_all");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc", {{ var = "id" }}]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
allow_multiple = "single_profile"
var.id = {{ default = "default" }}

[action.need_beta]
cmd = ["test-app", "need_beta"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["spawn", "svc:alpha", "--id=one"]);
    assert!(result.success(), "spawn alpha one: stdout={}, stderr={}", result.stdout, result.stderr);
    let mut alpha_one = ctrl.accept(Duration::from_secs(10));
    assert_eq!(alpha_one.name(), "svc");

    let result = harness.run_client(&["spawn", "svc:alpha", "--id=two"]);
    assert!(result.success(), "spawn alpha two: stdout={}, stderr={}", result.stdout, result.stderr);
    let mut alpha_two = ctrl.accept(Duration::from_secs(10));
    assert_eq!(alpha_two.name(), "svc");

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "need_beta",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "need_beta spawn rejected: {:?}", resp.body);

    let mut beta = ctrl.accept(Duration::from_secs(10));
    assert_eq!(beta.name(), "svc");
    assert!(
        alpha_one.wait_disconnected(Duration::from_secs(1)) && alpha_two.wait_disconnected(Duration::from_secs(1)),
        "svc:beta must not run while any svc:alpha instance is still alive; server_log={}",
        harness.server_log()
    );

    let mut action = ctrl.accept(Duration::from_secs(10));
    assert_eq!(action.name(), "need_beta");
    action.exit(0);
    beta.exit(0);
}

#[test]
fn test_batch_allows_schedulable_distinct_profile_service_requirements() {
    let mut harness = TestHarness::new("test_batch_distinct_profiles");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
allow_multiple = "distinct_profiles"

[test.needs_both]
cmd = ["test-app", "needs_both"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:alpha", "svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let client = s.spawn(|| harness.run_client(&["test"]));

        let mut svc1 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc1.name(), "svc");
        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");
        let mut test = ctrl.accept(Duration::from_secs(10));
        assert_eq!(test.name(), "needs_both");
        test.exit(0);

        let result = client.join().expect("test client panicked");
        assert!(result.success(), "test command: stdout={}, stderr={}", result.stdout, result.stderr);
        svc1.exit(0);
        svc2.exit(0);
    });
}

#[test]
fn test_batch_rejects_unschedulable_same_profile_service_params() {
    let mut harness = TestHarness::new("test_batch_params_conflict");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc", {{ var = "id" }}]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha"]
allow_multiple = false

[test.bad]
cmd = ["test-app", "bad"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = [["svc:alpha", {{ id = "one" }}], ["svc:alpha", {{ id = "two" }}]]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "bad",
        profile: "",
        params: &[],
        as_test: true,
        cached: false,
    });

    assert!(
        matches!(resp.body, CommandBody::Error(_)),
        "test batch should reject impossible duplicate service params, got {:?}",
        resp.body
    );
}

/// allow_multiple = false (default): spawning same service kills old instance.
#[test]
fn allow_multiple_false_kills_old() {
    let mut harness = TestHarness::new("allow_multi_false");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
allow_multiple = false
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let _h1 = s.spawn(|| harness.run_client(&["run", "svc"]));
        let _svc1 = ctrl.accept(Duration::from_secs(10));

        let h2 = s.spawn(|| harness.run_client(&["run", "svc"]));

        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");
        svc2.exit(0);

        let r2 = h2.join().expect("client 2 panicked");
        assert!(r2.success(), "client 2: stdout={}, stderr={}", r2.stdout, r2.stderr);
    });
}

/// allow_multiple = "distinct_profiles": different profiles run concurrently.
#[test]
fn allow_multiple_distinct_profiles_different_keeps() {
    let mut harness = TestHarness::new("allow_multi_dp_diff");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
allow_multiple = "distinct_profiles"
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let h1 = s.spawn(|| harness.run_client(&["run", "svc:alpha"]));

        let mut svc1 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc1.name(), "svc");

        let h2 = s.spawn(|| harness.run_client(&["run", "svc:beta"]));

        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");

        svc1.exit(0);
        svc2.exit(0);

        let r1 = h1.join().expect("client 1 panicked");
        let r2 = h2.join().expect("client 2 panicked");
        assert!(r1.success(), "client 1: stdout={}, stderr={}", r1.stdout, r1.stderr);
        assert!(r2.success(), "client 2: stdout={}, stderr={}", r2.stdout, r2.stderr);
    });
}

/// allow_multiple = "distinct_profiles": same profile kills old instance.
#[test]
fn allow_multiple_distinct_profiles_same_kills() {
    let mut harness = TestHarness::new("allow_multi_dp_same");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
allow_multiple = "distinct_profiles"
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let _h1 = s.spawn(|| harness.run_client(&["run", "svc:alpha"]));
        let _svc1 = ctrl.accept(Duration::from_secs(10));

        let h2 = s.spawn(|| harness.run_client(&["run", "svc:alpha"]));

        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");
        svc2.exit(0);

        let r2 = h2.join().expect("client 2 panicked");
        assert!(r2.success(), "client 2: stdout={}, stderr={}", r2.stdout, r2.stderr);
    });
}

/// allow_multiple = "single_profile": same profile runs concurrently.
#[test]
fn allow_multiple_single_profile_same_coexists() {
    let mut harness = TestHarness::new("allow_multi_sp_same");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
allow_multiple = "single_profile"
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let h1 = s.spawn(|| harness.run_client(&["run", "svc:alpha"]));

        let mut svc1 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc1.name(), "svc");

        let h2 = s.spawn(|| harness.run_client(&["run", "svc:alpha"]));

        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");

        svc1.exit(0);
        svc2.exit(0);

        let r1 = h1.join().expect("client 1 panicked");
        let r2 = h2.join().expect("client 2 panicked");
        assert!(r1.success(), "client 1: stdout={}, stderr={}", r1.stdout, r1.stderr);
        assert!(r2.success(), "client 2: stdout={}, stderr={}", r2.stdout, r2.stderr);
    });
}

/// allow_multiple = "single_profile": different profile kills old instance.
#[test]
fn allow_multiple_single_profile_different_kills() {
    let mut harness = TestHarness::new("allow_multi_sp_diff");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
allow_multiple = "single_profile"
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let _h1 = s.spawn(|| harness.run_client(&["run", "svc:alpha"]));
        let _svc1 = ctrl.accept(Duration::from_secs(10));

        let h2 = s.spawn(|| harness.run_client(&["run", "svc:beta"]));

        let mut svc2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(svc2.name(), "svc");
        svc2.exit(0);

        let r2 = h2.join().expect("client 2 panicked");
        assert!(r2.success(), "client 2: stdout={}, stderr={}", r2.stdout, r2.stderr);
    });
}

/// allow_multiple = true with actions: concurrent action instances.
#[test]
fn allow_multiple_true_action_concurrent() {
    let mut harness = TestHarness::new("allow_multi_action");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.task]
cmd = ["test-app", "task"]
env.TEST_APP_SOCKET = "{ctrl_path}"
allow_multiple = true
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    std::thread::scope(|s| {
        let h1 = s.spawn(|| harness.run_client(&["run", "task"]));
        let mut t1 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(t1.name(), "task");

        let h2 = s.spawn(|| harness.run_client(&["run", "task"]));
        let mut t2 = ctrl.accept(Duration::from_secs(10));
        assert_eq!(t2.name(), "task");

        t1.exit(0);
        t2.exit(0);

        let r1 = h1.join().expect("client 1 panicked");
        let r2 = h2.join().expect("client 2 panicked");
        assert!(r1.success(), "client 1: stdout={}, stderr={}", r1.stdout, r1.stderr);
        assert!(r2.success(), "client 2: stdout={}, stderr={}", r2.stdout, r2.stderr);
    });
}
