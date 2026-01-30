//! E2E tests using test-app for deterministic ready-condition and service-conflict scenarios.

use std::time::Duration;

use crate::harness::{TestAppServer, TestHarness};

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

[[test.alpha_test]]
cmd = ["test-app", "alpha_test"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc:alpha"]

[[test.beta_test]]
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

[[test.first]]
cmd = ["test-app", "first"]
env.TEST_APP_SOCKET = "{ctrl_path}"
require = ["svc"]

[[test.second]]
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
            (t1.name() == "first" && t2.name() == "second")
                || (t1.name() == "second" && t2.name() == "first"),
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
