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

    let result = harness.run_client(&["restart", "svc:alpha"]);
    assert!(result.success(), "restart svc:alpha: stdout={}, stderr={}", result.stdout, result.stderr);
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
fn queued_replacement_waits_for_new_resource_requirements_before_stopping_current_profile() {
    let mut harness = TestHarness::new("queued_service_waits_new_resource");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]

[action.holder]
cmd = ["test-app", "holder"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = [{{ resource = "R" }}]

[action.need_beta]
cmd = ["test-app", "need_beta"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "svc:alpha"]);
    assert!(result.success(), "start svc:alpha: stdout={}, stderr={}", result.stdout, result.stderr);
    let mut alpha = ctrl.accept(Duration::from_secs(10));
    assert_eq!(alpha.name(), "svc");

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
require = [{{ resource = "R" }}]

[action.holder]
cmd = ["test-app", "holder"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = [{{ resource = "R" }}]

[action.need_beta]
cmd = ["test-app", "need_beta"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "holder",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "holder spawn rejected: {:?}", resp.body);
    let mut holder = ctrl.accept(Duration::from_secs(10));
    assert_eq!(holder.name(), "holder");

    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "need_beta",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "need_beta spawn rejected: {:?}", resp.body);

    assert!(
        !alpha.wait_disconnected(Duration::from_millis(500)),
        "svc:alpha must stay running while svc:beta is blocked by holder's resource; server_log={}",
        harness.server_log()
    );

    holder.exit(0);
    assert!(
        alpha.wait_disconnected(Duration::from_secs(10)),
        "svc:alpha should stop once svc:beta's new resource requirement is available; server_log={}",
        harness.server_log()
    );

    let mut beta = ctrl.accept(Duration::from_secs(10));
    assert_eq!(beta.name(), "svc");
    let mut need_beta = ctrl.accept(Duration::from_secs(10));
    assert_eq!(need_beta.name(), "need_beta");
    need_beta.exit(0);
    beta.exit(0);
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

    let result = harness.run_client(&["restart", "svc:alpha", "--id=one"]);
    assert!(result.success(), "restart alpha one: stdout={}, stderr={}", result.stdout, result.stderr);
    let mut alpha_one = ctrl.accept(Duration::from_secs(10));
    assert_eq!(alpha_one.name(), "svc");

    let result = harness.run_client(&["restart", "svc:alpha", "--id=two"]);
    assert!(result.success(), "restart alpha two: stdout={}, stderr={}", result.stdout, result.stderr);
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
require = [
  {{ name = "svc:alpha", vars = {{ id = "one" }} }},
  {{ name = "svc:alpha", vars = {{ id = "two" }} }},
]
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

/// Submitting a service explicitly while it is already scheduled as a dependency
/// of another submitted task must not orphan dependents already wired to that
/// scheduled job. Models the production pattern from a config like:
///
/// ```toml
/// [service.frontend]   require = ["init"]
/// [service.portal]     require = ["init", "frontend"]
/// [service.child]      require = ["init", "frontend", "portal"]
/// ```
///
/// invoked as a group `["portal", "child", "frontend"]`. Before the fix the
/// explicit `frontend` spawn cancelled the dependency-spawned `frontend` job,
/// which left `portal`/`child` waiting on a now-`Cancelled` `Active` predicate
/// and cascaded both into "will never be ready" cancellation.
#[test]
fn group_explicit_service_reuses_scheduled_dependency_job() {
    let mut harness = TestHarness::new("group_reuses_scheduled_dep");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.init]
cmd = ["test-app", "init"]
env.TEST_APP_SOCKET = "{ctrl_path}"
cache = {{}}

[service.frontend]
cmd = ["test-app", "frontend"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["init"]

[service.portal]
cmd = ["test-app", "portal"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["init", "frontend"]

[service.child]
cmd = ["test-app", "child"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["init", "frontend", "portal"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");

    // Spawn the dependent first so `frontend` is scheduled as a dependency of `portal`.
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "portal",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "spawn portal rejected: {:?}", resp.body);

    // Anchor `init` in `Running` state. Action `init` is now `Running`, so the
    // dependency-spawned `frontend` job stays `Scheduled` until we tell `init`
    // to exit. This is what reproduces the original bug: the explicit `frontend`
    // submission below races a still-`Scheduled` dependency job.
    let mut init = ctrl.accept(Duration::from_secs(10));
    assert_eq!(init.name(), "init");

    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "child",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "spawn child rejected: {:?}", resp.body);

    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "frontend",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "spawn frontend rejected: {:?}", resp.body);

    init.exit(0);

    let mut frontend = ctrl.accept(Duration::from_secs(10));
    assert_eq!(
        frontend.name(),
        "frontend",
        "frontend must start after init exits; server_log={}",
        harness.server_log()
    );

    let mut portal = ctrl.accept(Duration::from_secs(10));
    assert_eq!(
        portal.name(),
        "portal",
        "portal must not be cancelled when frontend is re-submitted; server_log={}",
        harness.server_log()
    );

    let mut child = ctrl.accept(Duration::from_secs(10));
    assert_eq!(
        child.name(),
        "child",
        "child must not be cancelled when frontend is re-submitted; server_log={}",
        harness.server_log()
    );

    child.exit(0);
    portal.exit(0);
    frontend.exit(0);
}

#[test]
fn group_uncached_action_requirement_runs_per_service_until_ready() {
    let mut harness = TestHarness::new("group_uncached_action_sequenced");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{ctrl_path}"

[service.a]
cmd = ["test-app", "a"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "A_READY" }} }}
require = ["setup"]

[service.b]
cmd = ["test-app", "b"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "B_READY" }} }}
require = ["setup"]

[group]
sequenced = ["a", "b"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "group.sequenced"]);
    assert!(result.success(), "uncached group should start: stdout={}, stderr={}", result.stdout, result.stderr);

    let mut setup_a = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_a.name(), "setup");
    setup_a.exit(0);

    let mut a = ctrl.accept(Duration::from_secs(10));
    assert_eq!(a.name(), "a");
    assert!(
        ctrl.try_accept(Duration::from_millis(300)).is_none(),
        "second setup must wait until service a is ready; server_log={}",
        harness.server_log()
    );

    a.write_stdout(b"A_READY\n");

    let mut setup_b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_b.name(), "setup");
    setup_b.exit(0);

    let mut b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(b.name(), "b");
    b.write_stdout(b"B_READY\n");

    assert!(
        ctrl.try_accept(Duration::from_millis(300)).is_none(),
        "uncached setup should run once per service, not more; server_log={}",
        harness.server_log()
    );

    b.exit(0);
    a.exit(0);
}

#[test]
fn ready_barrier_prevents_resource_eviction_before_service_ready() {
    let mut harness = TestHarness::new("ready_barrier_resource_eviction");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = [{{ resource = "R" }}]

[service.a]
cmd = ["test-app", "a"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "A_READY" }} }}
require = ["setup", {{ resource = "R" }}]

[service.b]
cmd = ["test-app", "b"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "B_READY" }} }}
require = ["setup"]

[group]
sequenced = ["a", "b"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "group.sequenced"]);
    assert!(
        result.success(),
        "uncached resource group should start: stdout={}, stderr={}",
        result.stdout,
        result.stderr
    );

    let mut setup_a = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_a.name(), "setup");
    setup_a.exit(0);

    let mut a = ctrl.accept(Duration::from_secs(10));
    assert_eq!(a.name(), "a");
    assert!(
        !a.wait_disconnected(Duration::from_millis(500)),
        "service a must not be evicted for setup_b's resource while setup_b is still waiting on a's ready barrier; server_log={}",
        harness.server_log()
    );

    a.write_stdout(b"A_READY\n");
    assert!(
        a.wait_disconnected(Duration::from_secs(10)),
        "service a should become evictable after ready so setup_b can acquire the resource; server_log={}",
        harness.server_log()
    );

    let mut setup_b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_b.name(), "setup");
    setup_b.exit(0);

    let mut b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(b.name(), "b");
    b.write_stdout(b"B_READY\n");
    b.exit(0);
}

#[test]
fn group_uncached_action_requirement_continues_after_service_exits_before_ready() {
    let mut harness = TestHarness::new("group_uncached_action_service_exits");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{ctrl_path}"

[service.a]
cmd = ["test-app", "a"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "A_READY" }} }}
require = ["setup"]

[service.b]
cmd = ["test-app", "b"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "B_READY" }} }}
require = ["setup"]

[group]
sequenced = ["a", "b"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "group.sequenced"]);
    assert!(result.success(), "uncached group should start: stdout={}, stderr={}", result.stdout, result.stderr);

    let mut setup_a = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_a.name(), "setup");
    setup_a.exit(0);

    let mut a = ctrl.accept(Duration::from_secs(10));
    assert_eq!(a.name(), "a");
    assert!(
        ctrl.try_accept(Duration::from_millis(300)).is_none(),
        "second setup must wait while service a is not ready; server_log={}",
        harness.server_log()
    );

    a.exit(0);

    let mut setup_b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(
        setup_b.name(),
        "setup",
        "second setup must run after service a exits before ready; server_log={}",
        harness.server_log()
    );
    setup_b.exit(0);

    let mut b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(b.name(), "b");
    b.write_stdout(b"B_READY\n");
    b.exit(0);
}

#[test]
fn group_uncached_action_requirement_continues_after_first_action_failure() {
    let mut harness = TestHarness::new("group_uncached_action_failure_continues");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{ctrl_path}"

[service.a]
cmd = ["test-app", "a"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "A_READY" }} }}
require = ["setup"]

[service.b]
cmd = ["test-app", "b"]
env.TEST_APP_SOCKET = "{ctrl_path}"
ready = {{ when = {{ output_contains = "B_READY" }} }}
require = ["setup"]

[group]
sequenced = ["a", "b"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "group.sequenced"]);
    assert!(result.success(), "uncached group should start: stdout={}, stderr={}", result.stdout, result.stderr);

    let mut setup_a = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_a.name(), "setup");
    setup_a.exit(1);

    let mut setup_b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(
        setup_b.name(),
        "setup",
        "second setup must run after failed first setup cancels service a; server_log={}",
        harness.server_log()
    );
    setup_b.exit(0);

    let mut b = ctrl.accept(Duration::from_secs(10));
    assert_eq!(b.name(), "b");
    b.write_stdout(b"B_READY\n");
    b.exit(0);
}

#[test]
fn group_cached_action_requirement_coalesces_services() {
    let mut harness = TestHarness::new("group_cached_action_coalesces");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{ctrl_path}"
cache = {{}}

[service.a]
cmd = ["test-app", "a"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["setup"]

[service.b]
cmd = ["test-app", "b"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["setup"]

[group]
good = ["a", "b"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "group.good"]);
    assert!(result.success(), "cached group should start: stderr={}", result.stderr);

    let mut setup = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup.name(), "setup");
    setup.exit(0);

    let mut first = ctrl.accept(Duration::from_secs(10));
    let mut second = ctrl.accept(Duration::from_secs(10));
    let mut names = vec![first.name().to_string(), second.name().to_string()];
    names.sort();
    assert_eq!(names, ["a", "b"]);
    assert!(
        ctrl.try_accept(Duration::from_millis(300)).is_none(),
        "cacheable setup should be shared and only run once; server_log={}",
        harness.server_log()
    );

    first.exit(0);
    second.exit(0);
}

#[test]
fn restart_eval_failure_keeps_existing_service_running() {
    let mut harness = TestHarness::new("restart_eval_failure_keeps_service");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "svc"]);
    assert!(result.success(), "svc should start: stdout={}, stderr={}", result.stdout, result.stderr);

    let mut svc = ctrl.accept(Duration::from_secs(10));
    assert_eq!(svc.name(), "svc");

    std::thread::sleep(Duration::from_millis(10));
    harness.write_config(&format!(
        r#"
[action.bad]
pwd = {{ var = "missing" }}
cmd = ["true"]

[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["bad"]
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let result = harness.run_client(&["restart", "svc"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("Failed to evaluate task 'bad'"),
        "expected bad dependency eval error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
    assert!(
        !svc.wait_disconnected(Duration::from_millis(500)),
        "existing svc must keep running after replacement dependency eval fails; server_log={}",
        harness.server_log()
    );
    svc.exit(0);
}

#[test]
fn queued_service_waits_for_dependencies_before_killing_current_profile() {
    let mut harness = TestHarness::new("queued_service_waits_deps");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{ctrl_path}"

[service.svc]
cmd = ["test-app", "svc"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
require = ["setup"]

[action.user]
cmd = ["test-app", "user"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "svc:alpha"]);
    assert!(result.success(), "svc:alpha should submit: stdout={}, stderr={}", result.stdout, result.stderr);

    let mut setup_alpha = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_alpha.name(), "setup");
    setup_alpha.exit(0);

    let mut alpha = ctrl.accept(Duration::from_secs(10));
    assert_eq!(alpha.name(), "svc");

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "user",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "spawn user rejected: {:?}", resp.body);

    let alpha_disconnected_before_setup = alpha.wait_disconnected(Duration::from_millis(500));

    let mut setup_beta = ctrl.accept(Duration::from_secs(10));
    assert_eq!(setup_beta.name(), "setup");
    setup_beta.exit(1);

    assert!(
        ctrl.try_accept(Duration::from_millis(300)).is_none(),
        "svc:beta or user must not start after setup failure; server_log={}",
        harness.server_log()
    );

    assert!(
        !alpha_disconnected_before_setup,
        "svc:alpha must not be killed while svc:beta setup is still pending; server_log={}",
        harness.server_log()
    );

    assert!(
        !alpha.wait_disconnected(Duration::from_millis(300)),
        "svc:alpha must still be running after svc:beta setup fails; server_log={}",
        harness.server_log()
    );
    alpha.exit(0);
}

#[test]
fn queued_service_rejects_own_conflicting_service_requirements() {
    let mut harness = TestHarness::new("queued_service_rejects_own_conflicts");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.dep]
cmd = ["test-app", "dep"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["one", "two"]

[service.svc]
sh = "trap '' TERM; exec test-app svc \"$PROFILE\""
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]

[action.user]
cmd = ["test-app", "user"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "svc:alpha"]);
    assert!(result.success(), "svc:alpha should submit: stdout={}, stderr={}", result.stdout, result.stderr);

    let mut alpha = ctrl.accept(Duration::from_secs(10));
    assert_eq!(alpha.name(), "svc");

    harness.write_config(&format!(
        r#"
[service.dep]
cmd = ["test-app", "dep"]
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["one", "two"]

[service.svc]
sh = "trap '' TERM; exec test-app svc \"$PROFILE\""
env.TEST_APP_SOCKET = "{ctrl_path}"
profiles = ["alpha", "beta"]
require = ["dep:one", "dep:two"]

[action.user]
cmd = ["test-app", "user"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:beta"]
"#,
        ctrl_path = ctrl.path.display(),
    ));

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "user",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    match resp.body {
        CommandBody::Error(err) => {
            assert!(err.contains("conflicting service requirements"), "unexpected queued service error: {err}")
        }
        other => panic!("queued service with conflicting own requirements must be rejected, got {other:?}"),
    }

    assert!(
        ctrl.try_accept(Duration::from_millis(300)).is_none(),
        "dependency, queued service, or user action must not start after rejection; server_log={}",
        harness.server_log()
    );
    assert!(
        !alpha.wait_disconnected(Duration::from_millis(300)),
        "existing alpha service must remain running after queued-service rejection; server_log={}",
        harness.server_log()
    );
    alpha.exit(0);
}

/// Regression: a pending service termination must not starve independent ready
/// jobs. `blocker` holds resource `R` and ignores SIGINT (via `trap '' INT`),
/// so once the scheduler decides to stop it to free `R` for the blocked
/// `wants_r`, it keeps draining indefinitely. While it drains, the independent
/// `independent` action (no requirements) must still start instead of waiting
/// the drain out. Before the fix, `scheduled()` short-circuited on the pending
/// termination and never reached independent ready work, so `independent` only
/// ran after `blocker` was SIGKILL-escalated ~20s later.
#[test]
fn pending_service_termination_does_not_starve_independent_jobs() {
    let mut harness = TestHarness::new("pending_term_independent");
    let ctrl = TestAppServer::new(&harness.temp_dir);

    harness.write_config(&format!(
        r#"
[service.blocker]
cmd = ["sh", "-c", "trap '' INT; exec test-app blocker"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = [{{ resource = "R" }}]

[action.wants_r]
cmd = ["test-app", "wants_r"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = [{{ resource = "R" }}]

[action.independent]
cmd = ["test-app", "independent"]
env.TEST_APP_SOCKET = "{ctrl_path}"
"#,
        ctrl_path = ctrl.path.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    // Non-blocking RPC submits so a failure never hangs on a `run` client that
    // is itself waiting on the starved job.
    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");
    let spawn = |client: &mut WorkspaceClient, name: &'static str| {
        let resp = client.send_unwrap(&SpawnTaskRequest {
            task_name: name,
            profile: "",
            params: &[],
            as_test: false,
            cached: false,
        });
        assert!(matches!(resp.body, CommandBody::Empty), "{name} spawn rejected: {:?}", resp.body);
    };

    // Start the resource holder and wait until its process is running, which
    // means it has acquired `R`.
    spawn(&mut client, "blocker");
    let mut blocker = ctrl.accept(Duration::from_secs(10));
    assert_eq!(blocker.name(), "blocker");

    // `wants_r` blocks on `R`. The scheduler SIGINTs `blocker` to free it, but
    // `blocker` ignores SIGINT and keeps holding `R`, so `wants_r` stays
    // scheduled and the termination stays pending.
    spawn(&mut client, "wants_r");
    assert!(
        ctrl.try_accept(Duration::from_millis(500)).is_none(),
        "wants_r must stay blocked while blocker holds R; server_log={}",
        harness.server_log()
    );

    // With `blocker`'s stop now pending, an independent action must still start
    // promptly rather than waiting for `blocker` to exit.
    spawn(&mut client, "independent");
    let mut independent = ctrl.try_accept(Duration::from_secs(5)).unwrap_or_else(|| {
        panic!("independent action starved by pending blocker termination; server_log={}", harness.server_log())
    });
    assert_eq!(independent.name(), "independent");
    independent.exit(0);

    // Cleanup: stop the holder so `R` frees and the queued `wants_r` runs.
    blocker.exit(0);
    let mut wants_r = ctrl.accept(Duration::from_secs(10));
    assert_eq!(wants_r.name(), "wants_r");
    wants_r.exit(0);
}
