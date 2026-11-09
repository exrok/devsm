use std::fs;
use std::time::{Duration, UNIX_EPOCH};

use crate::harness::{TestAppServer, TestHarness};
use crate::rpc::{CommandBody, SpawnTaskRequest, WorkspaceClient};

const WAIT: Duration = Duration::from_secs(10);

fn write_local(harness: &TestHarness, text: &str, version: u64) {
    let path = harness.temp_dir.join("devsm.local.toml");
    fs::write(&path, text).unwrap();
    // Control the watched timestamp instead of sleeping between writes.
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1_700_000_000 + version)))
        .unwrap();
}

fn run_chain(harness: &TestHarness, ctrl: &TestAppServer, names: &[&str]) {
    std::thread::scope(|scope| {
        let client = scope.spawn(|| harness.run_client(&["run", "consumer"]));
        for name in names {
            ctrl.accept_expected(name, WAIT).exit(0);
        }
        let result = client.join().unwrap();
        assert!(result.success(), "{}\n{}", result.stderr, harness.server_log());
    });
}

fn cached_setup(client: &mut WorkspaceClient) -> CommandBody {
    client
        .send_unwrap(&SpawnTaskRequest { task_name: "setup", profile: "", params: &[], as_test: false, cached: true })
        .body
}

#[test]
fn local_options_reload_and_invalidate_only_referenced_cache_inputs() {
    let mut harness = TestHarness::new("options_cache");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[option.infra]
choices = ["docker", "native"]
default = "docker"
[option.unused]
choices = ["a", "b"]
default = "a"
[action.setup]
cmd = {{ if.option.infra = "docker", then = ["test-app", "setup-docker"], else = ["test-app", "setup-native"] }}
env.TEST_APP_SOCKET = "{socket}"
cache.persistent = true
[action.consumer]
cmd = ["test-app", "consumer"]
env.TEST_APP_SOCKET = "{socket}"
require = ["setup"]
"#,
        socket = ctrl.path.display()
    ));
    let db_path = harness.temp_dir.join("devsm.db");
    harness.spawn_server_with_db(&db_path);
    run_chain(&harness, &ctrl, &["setup-docker", "consumer"]);
    run_chain(&harness, &ctrl, &["consumer"]);

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).unwrap();
    assert!(matches!(cached_setup(&mut client), CommandBody::Message(message) if message.contains("cache hit")));
    write_local(&harness, "[option]\nunused = 'b'\n", 1);
    run_chain(&harness, &ctrl, &["consumer"]);
    assert!(matches!(cached_setup(&mut client), CommandBody::Message(message) if message.contains("cache hit")));

    write_local(&harness, "[option]\ninfra = 'native'\n", 2);
    assert!(matches!(cached_setup(&mut client), CommandBody::Empty));
    let mut setup = ctrl.accept_expected("setup-native", WAIT);
    std::thread::scope(|scope| {
        let consumer = scope.spawn(|| harness.run_client(&["run", "consumer"]));
        setup.exit(0);
        ctrl.accept_expected("consumer", WAIT).exit(0);
        let result = consumer.join().unwrap();
        assert!(result.success(), "{}", result.stderr);
    });

    for (version, invalid) in [(3, "[option]\ninfra = 'typo'\n"), (4, "[option")] {
        write_local(&harness, invalid, version);
        let body = cached_setup(&mut client);
        assert!(matches!(&body, CommandBody::Error(message) if message.contains("devsm.local.toml")), "{body:?}");
    }
    write_local(&harness, "[option]\ninfra = 'native'\nold_branch = 'gone'\n", 5);
    run_chain(&harness, &ctrl, &["consumer"]);
    assert!(harness.server_log().contains("unknown option 'old_branch'"));

    // Changing the option also changes persistent keys across daemon sessions.
    drop(client);
    harness.stop_server();
    harness.spawn_server_with_db(&db_path);
    run_chain(&harness, &ctrl, &["consumer"]);
    fs::remove_file(harness.temp_dir.join("devsm.local.toml")).unwrap();
    // The earlier docker result is still cached under its own key.
    run_chain(&harness, &ctrl, &["consumer"]);
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).unwrap();
    assert!(matches!(cached_setup(&mut client), CommandBody::Message(message) if message.contains("persistent")));
}

#[test]
fn local_options_switch_services_on_explicit_restart() {
    let mut harness = TestHarness::new("options_services");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[option.infra]
choices = ["docker", "native"]
default = "docker"
[service.postgres]
cmd = {{ if.option.infra = "docker", then = ["test-app", "postgres-docker"], else = ["test-app", "postgres-native"] }}
env.TEST_APP_SOCKET = "{socket}"
[service.mqtt]
cmd = {{ if.option.infra = "docker", then = ["test-app", "mqtt-docker"], else = ["test-app", "mqtt-native"] }}
env.TEST_APP_SOCKET = "{socket}"
[action.consumer]
cmd = ["test-app", "consumer"]
env.TEST_APP_SOCKET = "{socket}"
require = ["postgres", "mqtt"]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let (mut postgres, mut mqtt) = std::thread::scope(|scope| {
        let consumer = scope.spawn(|| harness.run_client(&["run", "consumer"]));
        let [pg, mqtt] = ctrl.accept_named(["postgres-docker", "mqtt-docker"], WAIT);
        ctrl.accept_expected("consumer", WAIT).exit(0);
        assert!(consumer.join().unwrap().success());
        (pg, mqtt)
    });
    write_local(&harness, "[option]\ninfra = 'native'\n", 1);
    run_chain(&harness, &ctrl, &["consumer"]);
    // Reloading leaves both existing service instances alive.
    postgres.write_stdout(b"still docker postgres\n");
    mqtt.write_stdout(b"still docker mqtt\n");
    for name in ["postgres", "mqtt"] {
        let result = harness.run_client(&["restart", name]);
        assert!(result.success(), "{}", result.stderr);
        let mut service = ctrl.accept_expected(&format!("{name}-native"), WAIT);
        service.exit(0);
    }
}

#[test]
fn local_options_control_requirement_graph_validation() {
    let mut harness = TestHarness::new("options_require_graph");
    harness.write_config(
        r#"
[option.infra]
choices = ["docker", "native"]
default = "native"
[action.setup]
cmd = "true"
cache = {}
require = [{ if.option.infra = "docker", then = "dependent" }]
[action.dependent]
cmd = "true"
require = ["setup"]
"#,
    );
    harness.spawn_server();
    assert!(harness.run_client(&["run", "setup"]).success());
    write_local(&harness, "[option]\ninfra = 'docker'\n", 1);
    let mut client = WorkspaceClient::connect(&harness.socket_path, &harness.temp_dir.join("devsm.toml")).unwrap();
    assert!(matches!(cached_setup(&mut client), CommandBody::Error(message) if message.contains("cycle")));
    let result = harness.run_client(&["self", "validate", "--skip-path-checks", "devsm.toml"]);
    assert!(!result.success());
    fs::remove_file(harness.temp_dir.join("devsm.local.toml")).unwrap();
    assert!(harness.run_client(&["run", "setup"]).success());
}
