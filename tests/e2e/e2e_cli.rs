//! CLI E2E tests for devsm.

use crate::harness;

use std::fs;
use std::io::{Read, Write};
use std::os::unix::{fs::PermissionsExt, net::UnixListener, net::UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::rpc::{
    CommandBody, CommandResponse, DecodeResult, DecodingState, Encoder, ExitCause, GetStatusRequest, JobStatusKind,
    KillTaskRequest, RpcMessageKind, RunnableStatus, SpawnTaskRequest, StatusResponse, SubscribeAck,
    SubscriptionFilter, WorkspaceClient,
};
use harness::{RpcEvent, RpcSubscriber, TestHarness, cargo_bin_path};

fn spawn_client_process(harness: &TestHarness, args: &[&str]) -> Child {
    Command::new(cargo_bin_path())
        .args(args)
        .current_dir(&harness.temp_dir)
        .env("DEVSM_SOCKET", &harness.socket_path)
        .env("DEVSM_DB", "/dev/null")
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn client")
}

fn run_client_with_timeout(harness: &TestHarness, args: &[&str], timeout: Duration) -> Option<harness::ClientResult> {
    let mut cmd = Command::new(cargo_bin_path());
    cmd.args(args)
        .current_dir(&harness.temp_dir)
        .env("DEVSM_SOCKET", &harness.socket_path)
        .env("DEVSM_DB", "/dev/null")
        .env("DEVSM_NO_AUTO_SPAWN", "1")
        .env("DEVSM_CONNECT_TIMEOUT_MS", "5000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn client");
    let stdin_handle = child.stdin.take();
    let start = Instant::now();
    let status = loop {
        match child.try_wait().expect("Failed to poll client") {
            Some(status) => break status,
            None if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                drop(stdin_handle);
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    drop(stdin_handle);

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout).ok();
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr).ok();
    }

    Some(harness::ClientResult { status, stdout, stderr })
}

fn wait_for_line_count(path: &Path, needle: &str, expected: usize, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let count = fs::read_to_string(path).unwrap_or_default().lines().filter(|line| line.contains(needle)).count();
        if count >= expected {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn wait_child_with_timeout(mut child: Child, timeout: Duration) -> (Option<harness::ClientResult>, Option<Child>) {
    let start = Instant::now();
    let status = loop {
        match child.try_wait().expect("failed to poll child") {
            Some(status) => break status,
            None if start.elapsed() >= timeout => return (None, Some(child)),
            None => thread::sleep(Duration::from_millis(10)),
        }
    };

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut stdout).ok();
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_string(&mut stderr).ok();
    }

    (Some(harness::ClientResult { status, stdout, stderr }), None)
}

mod exec_await_wire {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use jsony::Jsony;
    use jsony_value::ValueMap;

    mod unix_path {
        use super::*;
        use jsony::{BytesWriter, FromBinary, ToBinary};

        pub fn encode_binary(value: &Path, output: &mut BytesWriter) {
            value.as_os_str().as_bytes().encode_binary(output);
        }

        pub fn decode_binary<'a>(decoder: &mut jsony::binary::Decoder<'a>) -> &'a Path {
            Path::new(OsStr::from_bytes(<&'a [u8]>::decode_binary(decoder)))
        }
    }

    #[derive(Jsony, Debug)]
    #[jsony(Binary)]
    pub struct RequestMessage<'a> {
        #[jsony(with = unix_path)]
        pub cwd: &'a Path,
        pub request: Request<'a>,
    }

    #[allow(dead_code)]
    #[derive(Jsony, Debug)]
    #[jsony(Binary)]
    pub enum Request<'a> {
        AttachTui {
            #[jsony(with = unix_path)]
            config: &'a Path,
        },
        AttachRun {
            #[jsony(with = unix_path)]
            config: &'a Path,
            name: Box<str>,
            params: ValueMap<'a>,
            as_test: bool,
            derive_cache_key: bool,
        },
        AttachTests {
            #[jsony(with = unix_path)]
            config: &'a Path,
            filters: bool,
        },
        AttachRpc {
            #[jsony(with = unix_path)]
            config: &'a Path,
            subscribe: bool,
        },
        AttachLogs {
            #[jsony(with = unix_path)]
            config: &'a Path,
            query: bool,
        },
        GetSelfLogs {
            follow: bool,
        },
        ExecAwait {
            #[jsony(with = unix_path)]
            config: &'a Path,
            name: Box<str>,
            params: ValueMap<'a>,
        },
    }
}

fn connect_exec_await(harness: &TestHarness, task: &str) -> UnixStream {
    let mut socket = UnixStream::connect(&harness.socket_path).expect("connect exec-await socket");
    let config = harness.temp_dir.join("devsm.toml");
    let message = exec_await_wire::RequestMessage {
        cwd: &harness.temp_dir,
        request: exec_await_wire::Request::ExecAwait {
            config: &config,
            name: task.into(),
            params: jsony_value::ValueMap::new(),
        },
    };
    socket.write_all(&jsony::to_binary(&message)).expect("send exec-await request");
    socket
}

fn wait_for_exec_proceed(socket: &mut UnixStream, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut state = DecodingState::default();
    let mut buffer = Vec::with_capacity(256);
    while start.elapsed() < timeout {
        socket.set_read_timeout(Some(Duration::from_millis(50))).ok();
        let mut chunk = [0u8; 256];
        match socket.read(&mut chunk) {
            Ok(0) => return Err("daemon closed exec-await socket".to_string()),
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(format!("failed reading exec-await socket: {e}")),
        }

        loop {
            match state.decode(&buffer) {
                DecodeResult::Message { kind: RpcMessageKind::ExecProceed, .. } => return Ok(()),
                DecodeResult::Message { kind: RpcMessageKind::ExecWaiting, .. } => {}
                DecodeResult::Message { kind: RpcMessageKind::ExecError, payload, .. } => {
                    let message = jsony::from_binary::<crate::rpc::ExecErrorEvent>(payload)
                        .map(|event| event.message)
                        .unwrap_or_else(|_| "requirements could not be satisfied".to_string());
                    return Err(message);
                }
                DecodeResult::Message { kind, .. } => return Err(format!("unexpected exec-await message: {kind:?}")),
                DecodeResult::MissingData { .. } => break,
                DecodeResult::Empty => {
                    buffer.clear();
                    break;
                }
                DecodeResult::Error(err) => return Err(format!("invalid exec-await response: {err:?}")),
            }
        }
        state.compact(&mut buffer, 4096);
    }
    Err("timed out waiting for ExecProceed".to_string())
}

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
    assert!(result.stdout.contains("hello from devsm"), "Expected task output, got: {}", result.stdout);
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

    assert_eq!(result.exit_code(), 42, "Client should forward task exit code, stderr: {}", result.stderr);
}

#[test]
fn run_group_bare_and_explicit_namespace() {
    let mut harness = TestHarness::new("run_group_cli");
    harness.write_config(
        r#"
[action.alpha]
sh = "echo alpha-run"

[action.beta]
sh = "echo beta-run"

[group]
combo = [{ action = "alpha" }, { name = "beta" }]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["combo"]);
    assert!(result.success(), "bare group failed: {}", result.stderr);
    assert!(result.stdout.contains("alpha-run"), "missing alpha output: {}", result.stdout);
    assert!(result.stdout.contains("beta-run"), "missing beta output: {}", result.stdout);

    let result = harness.run_client(&["run", "group.combo"]);
    assert!(result.success(), "explicit group failed: {}", result.stderr);
    assert!(result.stdout.contains("alpha-run"), "missing alpha output: {}", result.stdout);
    assert!(result.stdout.contains("beta-run"), "missing beta output: {}", result.stdout);
}

#[test]
fn large_sh_script_group_spawn_keeps_daemon_responsive() {
    let mut harness = TestHarness::new("large_sh_script_group");
    let marker = harness.temp_dir.join("after.started");

    let mut script = String::from("sleep 10\n");
    for _ in 0..10_000 {
        script.push_str("# filler line to fill the shell stdin pipe before the shell resumes reading\n");
    }

    harness.write_config(&format!(
        r#"
[action.blocking]
sh = '''
{script}'''

[action.after]
sh = "touch {marker}"

[group]
freeze = ["blocking", "after"]
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let started = run_client_with_timeout(&harness, &["start", "group.freeze"], Duration::from_secs(5))
        .expect("start group.freeze timed out");
    assert!(started.success(), "group start failed: {}", started.stderr);

    let status = run_client_with_timeout(&harness, &["status", "after"], Duration::from_secs(2));
    assert!(
        status.is_some(),
        "daemon stopped responding after scheduling group.freeze; server log:\n{}",
        harness.server_log()
    );
    let status = status.unwrap();
    assert!(status.success(), "status after failed: {}", status.stderr);
    assert!(
        harness.wait_for_file(&marker, Duration::from_secs(2)),
        "after task did not run; status output:\n{}",
        status.stdout
    );
}

#[test]
fn group_is_lowest_priority_for_bare_names() {
    let mut harness = TestHarness::new("group_lowest_priority");
    harness.write_config(
        r#"
[action.combo]
sh = "echo task-wins"

[action.alpha]
sh = "echo group-ran"

[group]
combo = ["alpha"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "combo"]);
    assert!(result.success(), "task run failed: {}", result.stderr);
    assert!(result.stdout.contains("task-wins"), "bare name should run task: {}", result.stdout);
    assert!(!result.stdout.contains("group-ran"), "bare name should not fall through to group: {}", result.stdout);

    let result = harness.run_client(&["run", "group.combo"]);
    assert!(result.success(), "group run failed: {}", result.stderr);
    assert!(result.stdout.contains("group-ran"), "explicit group should run group: {}", result.stdout);
}

#[test]
fn exec_group_errors() {
    let mut harness = TestHarness::new("exec_group_errors");
    harness.write_config(
        r#"
[action.alpha]
sh = "echo alpha"

[group]
combo = ["alpha"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["exec", "combo"]);
    assert!(!result.success(), "exec group should fail");
    assert!(result.stderr.contains("exec is not supported for groups"), "unexpected stderr: {}", result.stderr);
}

#[test]
fn start_restart_stop_group_services() {
    let mut harness = TestHarness::new("group_state_actions");
    let starts = harness.temp_dir.join("starts.txt");
    let stopped_a = harness.temp_dir.join("a.stopped");
    let stopped_b = harness.temp_dir.join("b.stopped");
    harness.write_config(&format!(
        r#"
[service.a]
sh = "echo a >> {starts}; trap 'echo a > {stopped_a}; exit 0' INT; while true; do sleep 0.1; done"

[service.b]
sh = "echo b >> {starts}; trap 'echo b > {stopped_b}; exit 0' INT; while true; do sleep 0.1; done"

[group]
dev = [{{ service = "a" }}, {{ name = "service.b" }}]
"#,
        starts = starts.display(),
        stopped_a = stopped_a.display(),
        stopped_b = stopped_b.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "dev"]);
    assert!(result.success(), "start group failed: {}", result.stderr);
    assert!(wait_for_line_count(&starts, "a", 1, Duration::from_secs(3)), "service a did not start");
    assert!(wait_for_line_count(&starts, "b", 1, Duration::from_secs(3)), "service b did not start");

    let result = harness.run_client(&["restart", "group.dev"]);
    assert!(result.success(), "restart group failed: {}", result.stderr);
    assert!(wait_for_line_count(&starts, "a", 2, Duration::from_secs(3)), "service a did not restart");
    assert!(wait_for_line_count(&starts, "b", 2, Duration::from_secs(3)), "service b did not restart");

    let result = harness.run_client(&["stop", "dev"]);
    assert!(result.success(), "stop group failed: {}", result.stderr);
    assert!(harness.wait_for_file(&stopped_a, Duration::from_secs(3)), "service a was not stopped");
    assert!(harness.wait_for_file(&stopped_b, Duration::from_secs(3)), "service b was not stopped");
}

#[test]
fn status_without_name_lists_active_tasks() {
    let mut harness = TestHarness::new("status_active_tasks");
    let started_a = harness.temp_dir.join("a.started");
    let started_b = harness.temp_dir.join("b.started");
    harness.write_config(&format!(
        r#"
[service.a]
sh = "touch {started_a}; while true; do sleep 0.1; done"

[service.b]
sh = "touch {started_b}; while true; do sleep 0.1; done"

[group]
dev = ["a", "b"]
"#,
        started_a = started_a.display(),
        started_b = started_b.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "dev"]);
    assert!(result.success(), "start group failed: {}", result.stderr);
    assert!(harness.wait_for_file(&started_a, Duration::from_secs(3)), "service a did not start");
    assert!(harness.wait_for_file(&started_b, Duration::from_secs(3)), "service b did not start");

    let result = harness.run_client(&["status"]);
    assert!(result.success(), "status failed: {}", result.stderr);
    assert!(result.stdout.contains("2 active task(s)"), "unexpected status output:\n{}", result.stdout);
    assert!(result.stdout.contains("service.a: running"), "missing service a:\n{}", result.stdout);
    assert!(result.stdout.contains("service.b: running"), "missing service b:\n{}", result.stdout);
    assert!(result.stdout.contains("Last job: #"), "missing job ids:\n{}", result.stdout);

    let result = harness.run_client(&["stop", "dev"]);
    assert!(result.success(), "stop group failed: {}", result.stderr);
}

#[test]
fn status_for_job_shows_evaluated_profile_requirements() {
    let mut harness = TestHarness::new("status_profile_requirements");
    harness.write_config(
        r#"
[action.setup]
cmd = ["true"]

[action.live_dep]
cmd = ["true"]

[action.backend]
profiles = ["default", "live"]
cmd = ["true"]
require = [
  "setup",
  { if.profile = "live", then = "live_dep" },
]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "backend"]);
    assert!(result.success(), "default backend run failed: {}", result.stderr);

    let result = harness.run_client(&["status", "backend"]);
    assert!(result.success(), "status failed: {}", result.stderr);
    assert!(
        result.stdout.contains("task setup"),
        "status should include evaluated setup requirement:\n{}",
        result.stdout
    );
    assert!(
        !result.stdout.contains("live_dep"),
        "status must not include requirements from non-selected profile branches:\n{}",
        result.stdout
    );
}

fn fake_status(name: &str, kind: &str, state: &str, job_id: Option<u32>) -> RunnableStatus {
    RunnableStatus {
        name: name.into(),
        kind: kind.into(),
        state: state.into(),
        last_job_id: job_id,
        last_run_started_secs_ago: job_id.map(|_| 1),
        last_run_duration_ms: job_id.map(|_| 1000),
        exit_code: None,
        exit_cause: None,
        ready: None,
        blocked_on: Vec::new(),
        profile: None,
        spawn_params: None,
        config_generation_id: None,
        config_is_current: true,
        pwd: None,
        command: None,
        envvars: Vec::new(),
        require: Vec::new(),
    }
}

fn read_fake_get_status_name(stream: &mut UnixStream) -> String {
    let mut state = DecodingState::new();
    let mut buffer = Vec::new();
    loop {
        let mut chunk = [0; 4096];
        let n = stream.read(&mut chunk).expect("read fake status request");
        assert_ne!(n, 0, "client closed fake status connection before request");
        buffer.extend_from_slice(&chunk[..n]);

        match state.decode(&buffer) {
            DecodeResult::Message { kind: RpcMessageKind::GetStatus, payload, .. } => {
                let req: GetStatusRequest = jsony::from_binary(payload).expect("decode fake status request");
                return req.name.to_string();
            }
            DecodeResult::Message { kind, .. } => panic!("unexpected fake status request kind: {kind:?}"),
            DecodeResult::MissingData { .. } => continue,
            DecodeResult::Empty => continue,
            DecodeResult::Error(err) => panic!("fake status protocol error: {err:?}"),
        }
    }
}

fn write_fake_command_response(stream: &mut UnixStream, body: CommandBody) {
    let mut encoder = Encoder::new();
    encoder.encode_push(RpcMessageKind::CommandAck, &CommandResponse { workspace_id: 0, body });
    stream.write_all(encoder.output()).expect("write fake status response");
}

#[test]
fn status_without_name_falls_back_for_old_daemon() {
    let harness = TestHarness::new("status_old_daemon_fallback");
    harness.write_config(
        r#"
[action.idle]
cmd = ["true"]

[service.active]
cmd = ["true"]
"#,
    );

    let listener = UnixListener::bind(&harness.socket_path).expect("bind fake daemon socket");
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let started = Instant::now();
        let mut accepted = 0;
        while accepted < 3 && started.elapsed() < Duration::from_secs(5) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    accepted += 1;
                    let name = read_fake_get_status_name(&mut stream);
                    let body = match name.as_str() {
                        "" => CommandBody::Error("'' is not a known task or group".into()),
                        "action.idle" => {
                            let resp = StatusResponse::Task(fake_status("idle", "action", "exited (success)", Some(0)));
                            CommandBody::Message(jsony::to_json(&resp).into())
                        }
                        "service.active" => {
                            let resp = StatusResponse::Task(fake_status("active", "service", "running", Some(1)));
                            CommandBody::Message(jsony::to_json(&resp).into())
                        }
                        other => panic!("unexpected fake status query: {other}"),
                    };
                    write_fake_command_response(&mut stream, body);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("fake daemon accept failed: {err}"),
            }
        }
        assert_eq!(accepted, 3, "fake daemon did not receive all fallback status requests");
    });

    let result = harness.run_client(&["status"]);
    assert!(result.success(), "status fallback failed: {}", result.stderr);
    assert!(result.stdout.contains("1 active task(s)"), "unexpected status output:\n{}", result.stdout);
    assert!(result.stdout.contains("service.active: running"), "missing active service:\n{}", result.stdout);
    assert!(!result.stdout.contains("action.idle"), "inactive task should be filtered:\n{}", result.stdout);

    server.join().unwrap();
}

#[test]
fn subcommand_help_does_not_require_daemon() {
    let harness = TestHarness::new("subcommand_help");
    harness.write_config(
        r#"
[action.dummy]
cmd = ["true"]
"#,
    );

    for args in [
        &["logs", "--help"][..],
        &["status", "--help"][..],
        &["self", "logs", "--help"][..],
        &["get", "workspaces", "--help"][..],
    ] {
        let result = harness.run_client(args);
        assert!(result.success(), "{args:?} should print help: {}", result.stderr);
        assert!(result.stderr.is_empty(), "{args:?} should not warn: {}", result.stderr);
        assert!(result.stdout.contains("Usage: devsm"), "{args:?} did not print usage:\n{}", result.stdout);
    }
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
fn failed_spawn_does_not_leak_stale_service_dependent() {
    // Reproduces the "stuck in waiting" behavior the user observed when transitioning a
    // service from a working profile to one whose conditional cmd evaluates to an empty
    // list. The Starting → Exited(SpawnFailed) transition (for the failing profile) must
    // clean up the global job lists and ServiceDependents — otherwise dep:a retains a
    // stale dependent and can_stop returns false, so a subsequent action that needs
    // dep:b can never get dep:a auto-terminated and stays in Wait forever.
    let mut harness = TestHarness::new("failed_spawn_no_leak_dep");
    let consumer_marker = harness.temp_dir.join("consumer.marker");

    harness.write_config(&format!(
        r#"
[service.dep]
sh = "while true; do sleep 1; done"
profiles = ["a", "b"]

[service.broken]
cmd = {{ if.profile = "good", then = ["sh", "-c", "while true; do sleep 1; done"] }}
require = ["dep"]
profiles = ["good", "bad"]

[action.consumer]
sh = "echo done > {marker}"
require = ["dep:b"]
"#,
        marker = consumer_marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");

    // Bring up broken:good; this transitively spawns dep:a.
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "broken",
        profile: "good",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "broken:good spawn rejected: {:?}", resp.body);
    std::thread::sleep(Duration::from_millis(300));

    // Switch to broken:bad. broken:good is killed, broken:bad is queued, eventually it
    // transitions Starting → Exited(SpawnFailed) when spawn() finds an empty cmd.
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "broken",
        profile: "bad",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "broken:bad spawn rejected: {:?}", resp.body);
    std::thread::sleep(Duration::from_millis(500));

    // Now ask for an action that needs dep:b. dep is currently running with profile a,
    // so dep:b must be queued and dep:a auto-terminated to make room. With the bug this
    // hangs.
    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "consumer",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "consumer spawn rejected: {:?}", resp.body);

    assert!(
        harness.wait_for_file(&consumer_marker, Duration::from_secs(5)),
        "consumer should run after the failed broken:bad spawn cleared its stale dependent;\nserver log:\n{}",
        harness.server_log(),
    );
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
fn persistent_cache_survives_daemon_restart() {
    let mut harness = TestHarness::new("cache_persistent_restart");
    let db_path = harness.temp_dir.join("devsm.db");
    let counter = harness.temp_dir.join("counter.txt");

    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.gen]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache.persistent = true

[action.consumer]
sh = "true"
require = ["gen"]
"#,
        counter = counter.display()
    ));

    harness.spawn_server_with_db(&db_path);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should run first time");

    harness.stop_server();
    harness.spawn_server_with_db(&db_path);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created after restart");

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success after restart, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should be cached after restart");
}

#[test]
fn persistent_cache_expires_after_max_age() {
    let mut harness = TestHarness::new("cache_persistent_max_age");
    let db_path = harness.temp_dir.join("devsm.db");
    let counter = harness.temp_dir.join("counter.txt");

    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.gen]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache.persistent = true
cache.max-age = "1ms"

[action.consumer]
sh = "true"
require = ["gen"]
"#,
        counter = counter.display()
    ));

    harness.spawn_server_with_db(&db_path);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success on first run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "gen should run first time");

    harness.stop_server();
    std::thread::sleep(Duration::from_millis(25));
    harness.spawn_server_with_db(&db_path);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created after restart");

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success after restart, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "gen should rerun after cache expiry");
}

#[test]
fn test_persistent_cache_survives_daemon_restart() {
    let mut harness = TestHarness::new("test_cache_persistent_restart");
    let db_path = harness.temp_dir.join("devsm.db");
    let counter = harness.temp_dir.join("counter.txt");

    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[test.foo]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache.persistent = true
"#,
        counter = counter.display()
    ));

    harness.spawn_server_with_db(&db_path);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test", "foo"]);
    assert!(result.success(), "Expected success on first test run, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "test should run first time");

    harness.stop_server();
    harness.spawn_server_with_db(&db_path);
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created after restart");

    let result = harness.run_client(&["test", "foo"]);
    assert!(result.success(), "Expected success after restart, got: {}", result.stderr);
    assert!(
        result.stdout.contains("1 test skipped via cache"),
        "Expected cache skip summary, got stdout:\n{}",
        result.stdout
    );
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "test should be cached after restart");

    let result = harness.run_client(&["test", "--force", "foo"]);
    assert!(result.success(), "Expected success with --force, got: {}", result.stderr);
    assert!(
        !result.stdout.contains("skipped via cache"),
        "--force should not report a cache skip, got stdout:\n{}",
        result.stdout
    );
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "--force should rerun cached test");
}

#[test]
fn failed_test_batch_does_not_create_cached_partial_job() {
    let mut harness = TestHarness::new("failed_test_batch_no_cached_partial");
    let counter = harness.temp_dir.join("counter.txt");

    fn last_job_id(status: &str) -> String {
        status
            .lines()
            .find_map(|line| line.trim().strip_prefix("Last job: #"))
            .expect("status should include a last job id")
            .to_string()
    }

    fs::write(&counter, "0").unwrap();
    harness.write_config(&format!(
        r#"
[test.foo]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache = {{}}
"#,
        counter = counter.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test", "foo"]);
    assert!(result.success(), "foo should pass: stdout={}, stderr={}", result.stdout, result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "foo should run once");

    let before = harness.run_client(&["status", "test.foo"]);
    assert!(before.success(), "status before failed batch should succeed: {}", before.stderr);
    let before_job = last_job_id(&before.stdout);

    harness.write_config(&format!(
        r#"
[service.svc]
cmd = ["true"]
var.port = {{ default = "8080" }}

[test.foo]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache = {{}}

[test.bad]
cmd = ["true"]
require = [
  {{ name = "svc", vars = {{ port = "a" }} }},
  {{ name = "svc", vars = {{ port = "b" }} }},
]
"#,
        counter = counter.display()
    ));

    let result = harness.run_client(&["test"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("conflicting service requirements"),
        "expected conflict error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "cached foo must not rerun");

    let after = harness.run_client(&["status", "test.foo"]);
    assert!(after.success(), "status after failed batch should succeed: {}", after.stderr);
    assert_eq!(
        last_job_id(&after.stdout),
        before_job,
        "failed batch must not create a new cached synthetic job for foo"
    );
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
fn failed_spawn_does_not_invalidate_profile_changed_cache() {
    let mut harness = TestHarness::new("failed_spawn_profile_cache");
    let dep_counter = harness.temp_dir.join("dep_counter.txt");
    let main_counter = harness.temp_dir.join("main_counter.txt");

    fs::write(&dep_counter, "0").unwrap();
    fs::write(&main_counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.dep]
sh = '''
count=$(cat {dep_counter})
count=$((count + 1))
echo $count > {dep_counter}
'''
profiles = ["default", "bad"]
pwd = {{ if.profile = "bad", then = {{ var = "missing" }}, or_else = "./" }}

[action.main]
sh = '''
count=$(cat {main_counter})
count=$((count + 1))
echo $count > {main_counter}
'''
cache.key = [{{ profile_changed = "dep" }}]

[action.runner]
cmd = ["true"]
require = ["main"]
"#,
        dep_counter = dep_counter.display(),
        main_counter = main_counter.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "dep"]);
    assert!(result.success(), "dep default should run: stdout={}, stderr={}", result.stdout, result.stderr);
    assert_eq!(fs::read_to_string(&dep_counter).unwrap().trim(), "1", "dep should run once");

    let result = harness.run_client(&["run", "runner"]);
    assert!(result.success(), "main should run: stdout={}, stderr={}", result.stdout, result.stderr);
    assert_eq!(fs::read_to_string(&main_counter).unwrap().trim(), "1", "main should run once");

    let result = harness.run_client(&["run", "runner"]);
    assert!(result.success(), "cached main should skip: stdout={}, stderr={}", result.stdout, result.stderr);
    assert_eq!(fs::read_to_string(&main_counter).unwrap().trim(), "1", "main should remain cached");

    let result = harness.run_client(&["run", "dep:bad"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("Failed to evaluate task 'dep'"),
        "expected dep:bad eval error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
    assert_eq!(fs::read_to_string(&dep_counter).unwrap().trim(), "1", "failed dep spawn must not run");

    let result = harness.run_client(&["run", "runner"]);
    assert!(result.success(), "cached main should still skip: stdout={}, stderr={}", result.stdout, result.stderr);
    assert_eq!(
        fs::read_to_string(&main_counter).unwrap().trim(),
        "1",
        "failed dep spawn must not invalidate profile_changed cache"
    );
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
fn profile_dependent_require_runs_only_matching_branch() {
    let mut harness = TestHarness::new("profile_dependent_require");
    let output_file = harness.temp_dir.join("output.txt");
    let live_marker = harness.temp_dir.join("live_dep.txt");
    harness.write_config(&format!(
        r#"
[action.setup]
sh = "echo setup >> {output}"

[action.live_dep]
sh = "echo live > {live_marker}"

[action.backend]
profiles = ["default", "traffic-live"]
sh = "echo backend >> {output}"
require = [
  "setup",
  {{ if.profile = "traffic-live", then = "live_dep" }},
]
"#,
        output = output_file.display(),
        live_marker = live_marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "backend"]);
    assert!(result.success(), "default profile should succeed: {}", result.stderr);
    assert!(!live_marker.exists(), "traffic-live-only dependency must not run for default profile");

    let result = harness.run_client(&["run", "backend:traffic-live"]);
    assert!(result.success(), "traffic-live profile should succeed: {}", result.stderr);
    assert!(harness.wait_for_file(&live_marker, Duration::from_secs(2)), "traffic-live dependency should run");
}

#[test]
fn profile_dependent_require_cycle_only_blocks_matching_profile() {
    let mut harness = TestHarness::new("profile_dependent_cycle");
    let marker = harness.temp_dir.join("default.txt");
    harness.write_config(&format!(
        r#"
[action.backend]
profiles = ["default", "bad"]
sh = "echo default > {marker}"
require = [
  {{ if.profile = "bad", then = "backend:bad" }},
]
"#,
        marker = marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "backend"]);
    assert!(result.success(), "default profile should not see bad-profile cycle: {}", result.stderr);
    assert!(harness.wait_for_file(&marker, Duration::from_secs(2)), "default profile should run");

    let result = harness.run_client(&["run", "backend:bad"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(!result.success(), "bad profile should fail due to profile-specific cycle");
    assert!(combined.contains("require cycle"), "expected require cycle error, got: {combined}");
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
require = [{{ name = "dep", vars = {{ msg = "hello_from_params" }} }}]
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
fn run_forwards_task_arguments() {
    let mut harness = TestHarness::new("run_forward_args");
    let output_file = harness.temp_dir.join("forwarded.txt");
    harness.write_config(&format!(
        r#"
[action.capture]
cmd = ["sh", "-c", '''printf '%s\n' "$@" > {output}''', "capture", {{ var = "args" }}]
cli.forward-arguments = true
"#,
        output = output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "capture", "-al", "/tmp", "--color=auto"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["-al", "/tmp", "--color=auto"], "forwarded args mismatch: {:?}", lines);
}

#[test]
fn run_forwards_shell_task_arguments_as_positional_params() {
    let mut harness = TestHarness::new("run_forward_sh_args");
    let output_file = harness.temp_dir.join("forwarded.txt");
    harness.write_config(&format!(
        r#"
[action.capture]
sh = '''printf '%s\n' "$@" > {output}'''
cli.forward-arguments = true
"#,
        output = output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "capture", "-al", "/tmp/two words", "--color=auto", "semi;colon"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec!["-al", "/tmp/two words", "--color=auto", "semi;colon"],
        "forwarded shell args mismatch: {:?}",
        lines
    );
}

#[test]
fn exec_forwards_task_arguments() {
    let harness = TestHarness::new("exec_forward_args");
    let output_file = harness.temp_dir.join("forwarded.txt");
    harness.write_config(&format!(
        r#"
[action.capture]
cmd = ["sh", "-c", '''printf '%s\n' "$@" > {output}''', "capture", {{ var = "args" }}]
cli.forward-arguments = true
"#,
        output = output_file.display()
    ));

    let result = harness.run_client(&["exec", "capture", "-al", "/tmp", "--color=auto"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines, vec!["-al", "/tmp", "--color=auto"], "forwarded args mismatch: {:?}", lines);
}

#[test]
fn exec_forwards_shell_task_arguments_as_positional_params() {
    let harness = TestHarness::new("exec_forward_sh_args");
    let output_file = harness.temp_dir.join("forwarded.txt");
    harness.write_config(&format!(
        r#"
[action.capture]
sh = '''printf '%s\n' "$@" > {output}'''
cli.forward-arguments = true
"#,
        output = output_file.display()
    ));

    let result = harness.run_client(&["exec", "capture", "-al", "/tmp/two words", "--color=auto", "semi;colon"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec!["-al", "/tmp/two words", "--color=auto", "semi;colon"],
        "forwarded shell args mismatch: {:?}",
        lines
    );
}

#[test]
fn exec_requirements_hold_resources_until_exec_process_exits() {
    let mut harness = TestHarness::new("exec_requirements_hold_resources");
    let order = harness.temp_dir.join("order.txt");
    harness.write_config(&format!(
        r#"
[action.hold]
managed = false
sh = """
printf 'hold-start\n' >> {order}
sleep 0.5
printf 'hold-end\n' >> {order}
"""
require = [{{ resource = "serial" }}]

[action.contender]
sh = "printf 'contender\n' >> {order}"
require = [{{ resource = "serial" }}]
"#,
        order = order.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut holder = spawn_client_process(&harness, &["exec", "hold"]);
    assert!(wait_for_line_count(&order, "hold-start", 1, Duration::from_secs(5)), "exec task did not start");

    let result = harness.run_client(&["run", "contender"]);
    assert!(result.success(), "contender failed: stdout={}, stderr={}", result.stdout, result.stderr);

    let status = holder.wait().expect("failed waiting for exec holder");
    let mut holder_stderr = String::new();
    if let Some(mut stderr) = holder.stderr.take() {
        stderr.read_to_string(&mut holder_stderr).ok();
    }
    assert!(status.success(), "exec holder failed: {holder_stderr}");

    let content = fs::read_to_string(&order).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines,
        vec!["hold-start", "hold-end", "contender"],
        "resource contender ran while exec process was still active:\n{content}\nserver log:\n{}",
        harness.server_log()
    );
}

#[test]
fn exec_requirement_service_dependent_is_released_after_exec_process_exits() {
    let mut harness = TestHarness::new("exec_requirement_service_released");
    let starts = harness.temp_dir.join("starts.txt");
    harness.write_config(&format!(
        r#"
[service.svc]
profiles = ["alpha", "beta"]
sh = """
printf '%s\n' "$PROFILE_VAL" >> {starts}
trap 'exit 0' INT TERM
while true; do sleep 1; done
"""
env.PROFILE_VAL = {{ if.profile = "beta", then = "beta", or_else = "alpha" }}

[action.use]
managed = false
sh = "sleep 0.2"
require = ["svc:alpha"]
"#,
        starts = starts.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut user = spawn_client_process(&harness, &["exec", "use"]);
    assert!(wait_for_line_count(&starts, "alpha", 1, Duration::from_secs(5)), "alpha service did not start");

    let status = user.wait().expect("failed waiting for exec user");
    let mut user_stderr = String::new();
    if let Some(mut stderr) = user.stderr.take() {
        stderr.read_to_string(&mut user_stderr).ok();
    }
    assert!(status.success(), "exec user failed: {user_stderr}");

    let result = harness.run_client(&["start", "svc:beta"]);
    assert!(result.success(), "svc:beta submit failed: stdout={}, stderr={}", result.stdout, result.stderr);
    assert!(
        wait_for_line_count(&starts, "beta", 1, Duration::from_secs(5)),
        "beta service did not start after exec process exited; starts:\n{}\nserver log:\n{}",
        fs::read_to_string(&starts).unwrap_or_default(),
        harness.server_log()
    );
}

#[test]
fn exec_requirement_duplicate_service_clients_do_not_share_scheduler_gate() {
    let mut harness = TestHarness::new("exec_requirement_duplicate_service_clients");
    let release = harness.temp_dir.join("release");
    let gate_started = harness.temp_dir.join("gate-started");
    harness.write_config(&format!(
        r#"
[action.gate]
sh = """
touch {gate_started}
while [ ! -f {release} ]; do sleep 0.02; done
"""

[service.remote]
managed = false
sh = "sleep 10"
require = ["gate"]
"#,
        gate_started = gate_started.display(),
        release = release.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut first = connect_exec_await(&harness, "remote");
    assert!(harness.wait_for_file(&gate_started, Duration::from_secs(5)), "gate dependency did not start");
    let mut second = connect_exec_await(&harness, "remote");

    fs::write(&release, "").expect("release gate");

    wait_for_exec_proceed(&mut first, Duration::from_secs(5)).unwrap_or_else(|err| {
        panic!("first exec client should proceed first, got {err}; server log:\n{}", harness.server_log())
    });

    let second_early = wait_for_exec_proceed(&mut second, Duration::from_millis(200));
    assert!(
        second_early.is_err(),
        "second exec client should wait for the first remote exec to finish before proceeding"
    );

    drop(first);
    wait_for_exec_proceed(&mut second, Duration::from_secs(5)).unwrap_or_else(|err| {
        panic!(
            "second exec client should proceed after first socket closes, got {err}; server log:\n{}",
            harness.server_log()
        )
    });
}

#[test]
fn exec_requirement_duplicate_action_clients_do_not_wait_for_previous_exec() {
    let mut harness = TestHarness::new("exec_requirement_duplicate_action_clients");
    let release = harness.temp_dir.join("release");
    let gate_started = harness.temp_dir.join("gate-started");
    harness.write_config(&format!(
        r#"
[action.gate]
sh = """
touch {gate_started}
while [ ! -f {release} ]; do sleep 0.02; done
"""

[action.remote]
managed = false
sh = "sleep 10"
require = ["gate"]
"#,
        gate_started = gate_started.display(),
        release = release.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut first = connect_exec_await(&harness, "remote");
    assert!(harness.wait_for_file(&gate_started, Duration::from_secs(5)), "gate dependency did not start");
    fs::write(&release, "").expect("release gate");

    wait_for_exec_proceed(&mut first, Duration::from_secs(5)).unwrap_or_else(|err| {
        panic!("first exec client should proceed, got {err}; server log:\n{}", harness.server_log())
    });

    let mut second = connect_exec_await(&harness, "remote");
    wait_for_exec_proceed(&mut second, Duration::from_secs(1)).unwrap_or_else(|err| {
        panic!(
            "unmanaged actions should not wait for an older same-action exec, got {err}; server log:\n{}",
            harness.server_log()
        )
    });
}

#[test]
fn exec_requirement_dependents_wait_until_exec_gate_proceeds() {
    let mut harness = TestHarness::new("exec_requirement_dependent_after_proceed");
    let release = harness.temp_dir.join("release");
    let gate_started = harness.temp_dir.join("gate-started");
    let proceed_marker = harness.temp_dir.join("proceeded");
    let order = harness.temp_dir.join("order.txt");
    harness.write_config(&format!(
        r#"
[action.gate]
sh = """
touch {gate_started}
while [ ! -f {release} ]; do sleep 0.02; done
"""

[service.remote]
managed = false
sh = "sleep 10"
require = ["gate"]

[action.dependent]
sh = """
if [ -f {proceed_marker} ]; then
  printf 'after-proceed\n' > {order}
else
  printf 'before-proceed\n' > {order}
fi
"""
require = ["remote"]
"#,
        gate_started = gate_started.display(),
        release = release.display(),
        proceed_marker = proceed_marker.display(),
        order = order.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut exec_socket = connect_exec_await(&harness, "remote");
    assert!(harness.wait_for_file(&gate_started, Duration::from_secs(5)), "gate dependency did not start");
    let marker_for_thread = proceed_marker.clone();
    let proceed_reader = thread::spawn(move || {
        wait_for_exec_proceed(&mut exec_socket, Duration::from_secs(5)).expect("exec should proceed");
        fs::write(marker_for_thread, "").expect("write proceed marker");
    });

    let dependent = spawn_client_process(&harness, &["run", "dependent"]);
    thread::sleep(Duration::from_millis(100));
    fs::write(&release, "").expect("release gate");

    let (dependent_result, mut timed_out) = wait_child_with_timeout(dependent, Duration::from_secs(5));
    if let Some(mut child) = timed_out.take() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("dependent did not finish; server log:\n{}", harness.server_log());
    }
    let dependent_result = dependent_result.expect("dependent result");
    assert!(dependent_result.success(), "dependent failed: {}", dependent_result.stderr);
    proceed_reader.join().expect("proceed reader thread panicked");

    let order = fs::read_to_string(&order).unwrap_or_default();
    assert_eq!(
        order.trim(),
        "after-proceed",
        "dependent ran before daemon released the exec gate; server log:\n{}",
        harness.server_log()
    );
}

#[test]
fn stop_reports_active_remote_exec_instead_of_already_finished() {
    let mut harness = TestHarness::new("stop_reports_remote_exec");
    harness.write_config(
        r#"
[action.gate]
sh = "true"

[action.remote]
managed = false
sh = "sleep 10"
require = ["gate"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let mut exec_socket = connect_exec_await(&harness, "remote");
    wait_for_exec_proceed(&mut exec_socket, Duration::from_secs(5))
        .unwrap_or_else(|err| panic!("remote exec should proceed, got {err}; server log:\n{}", harness.server_log()));

    let result = harness.run_client(&["stop", "remote"]);
    assert!(result.success(), "stop failed: {}", result.stderr);
    assert!(
        !result.stdout.contains("already finished"),
        "active remote exec was reported as already finished:\n{}",
        result.stdout
    );
    assert!(
        result.stdout.contains("unmanaged exec"),
        "stop should explain that active remote execs cannot be terminated by the daemon, got:\n{}",
        result.stdout
    );
}

#[test]
fn remote_exec_service_does_not_starve_managed_resource_termination() {
    let mut harness = TestHarness::new("remote_exec_no_starve_managed_resource");
    let order = harness.temp_dir.join("order.txt");
    let remote_gate_done = harness.temp_dir.join("remote-gate-done");
    harness.write_config(&format!(
        r#"
[service.remote]
managed = false
sh = "sleep 10"
require = [{{ resource = "R1" }}]

[service.holder]
sh = """
printf 'holder-start\n' >> {order}
trap "printf 'holder-stop\n' >> {order}; exit 0" INT TERM
while true; do sleep 0.05; done
"""
require = [{{ resource = "R2" }}]

[action.remote_gate]
sh = "touch {remote_gate_done}"

[action.blocked_remote]
sh = "printf 'remote-action\n' >> {order}"
require = ["remote_gate", {{ resource = "R1" }}]

[action.needs_holder_resource]
sh = "printf 'managed-action\n' >> {order}"
require = [{{ resource = "R2" }}]
"#,
        order = order.display(),
        remote_gate_done = remote_gate_done.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let start_holder = harness.run_client(&["start", "holder"]);
    assert!(
        start_holder.success(),
        "holder service failed to start: stdout={}, stderr={}",
        start_holder.stdout,
        start_holder.stderr
    );
    assert!(
        wait_for_line_count(&order, "holder-start", 1, Duration::from_secs(5)),
        "holder service did not start; server log:\n{}",
        harness.server_log()
    );

    let mut remote_socket = connect_exec_await(&harness, "remote");
    wait_for_exec_proceed(&mut remote_socket, Duration::from_secs(5)).unwrap_or_else(|err| {
        panic!("remote exec service should proceed, got {err}; server log:\n{}", harness.server_log())
    });

    let blocked_remote = spawn_client_process(&harness, &["run", "blocked_remote"]);
    assert!(
        harness.wait_for_file(&remote_gate_done, Duration::from_secs(5)),
        "remote blocker was not scheduled before managed waiter; server log:\n{}",
        harness.server_log()
    );

    let managed_waiter = spawn_client_process(&harness, &["run", "needs_holder_resource"]);
    let (managed_result, mut timed_out) = wait_child_with_timeout(managed_waiter, Duration::from_secs(5));
    if let Some(mut child) = timed_out.take() {
        let _ = child.kill();
        let _ = child.wait();
        drop(remote_socket);
        let (_, mut blocked_timed_out) = wait_child_with_timeout(blocked_remote, Duration::from_secs(1));
        if let Some(mut child) = blocked_timed_out.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!(
            "managed resource waiter starved behind unkillable remote exec holder; order:\n{}\nserver log:\n{}",
            fs::read_to_string(&order).unwrap_or_default(),
            harness.server_log()
        );
    }
    let managed_result = managed_result.expect("managed waiter result");
    assert!(
        managed_result.success(),
        "managed resource waiter failed: stdout={}, stderr={}\nserver log:\n{}",
        managed_result.stdout,
        managed_result.stderr,
        harness.server_log()
    );

    let content = fs::read_to_string(&order).unwrap_or_default();
    assert!(
        content.lines().any(|line| line == "managed-action"),
        "managed waiter did not run after holder termination; order:\n{content}\nserver log:\n{}",
        harness.server_log()
    );

    drop(remote_socket);
    let (remote_result, mut remote_timed_out) = wait_child_with_timeout(blocked_remote, Duration::from_secs(5));
    if let Some(mut child) = remote_timed_out.take() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("remote-blocked client did not exit after remote socket closed; server log:\n{}", harness.server_log());
    }
    assert!(
        remote_result.expect("remote blocker result").success(),
        "remote-blocked client failed; server log:\n{}",
        harness.server_log()
    );
}

#[test]
fn exec_rejects_unmanaged_service_with_ready_condition() {
    let harness = TestHarness::new("exec_rejects_unmanaged_ready");
    let ran = harness.temp_dir.join("ran");
    harness.write_config(&format!(
        r#"
[service.remote]
managed = false
ready = {{ when = {{ output_contains = "READY" }} }}
sh = "touch {ran}"
"#,
        ran = ran.display(),
    ));

    let result = harness.run_client(&["exec", "remote"]);
    assert!(
        !result.success(),
        "exec should reject unmanaged service ready config; stdout={}, stderr={}",
        result.stdout,
        result.stderr
    );
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    assert!(
        combined.contains("ready") && combined.contains("managed = false"),
        "error should explain ready/managed=false incompatibility, got:\n{combined}"
    );
    assert!(!ran.exists(), "unmanaged task command ran despite rejected ready config");
}

#[test]
fn complete_forward_prefix_returns_static_command_prefix() {
    let harness = TestHarness::new("complete_forward_prefix");
    harness.write_config(
        r#"
[action.git_checkout]
cmd = ["git", "checkout", { var = "args" }]
cli.forward-arguments = true
cli.autocomplete = "forward"

[action.no_forward_completion]
cmd = ["git", "status", { var = "args" }]
cli.forward-arguments = true
"#,
    );

    let result = harness.run_client(&["self", "complete", "forward-prefix", "--task=git_checkout"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines, vec!["git", "checkout"]);

    let result = harness.run_client(&["self", "complete", "forward-prefix", "--task=git_checkout:debug"]);
    assert!(result.success(), "Expected success for task profile, got stderr: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines, vec!["git", "checkout"]);

    let result = harness.run_client(&["self", "complete", "forward-prefix", "--task=no_forward_completion"]);
    assert!(result.success(), "Expected success with empty output, got stderr: {}", result.stderr);
    assert!(result.stdout.is_empty(), "Expected no prefix, got stdout: {:?}", result.stdout);
}

#[test]
fn complete_task_args_returns_forward_pwd_and_legacy_vars() {
    let harness = TestHarness::new("complete_task_args");
    let work_dir = harness.temp_dir.join("work dir");
    fs::create_dir_all(&work_dir).expect("create task pwd");
    harness.write_config(&format!(
        r#"
[action.list]
pwd = "{work_dir}"
cmd = ["ls", {{ var = "args" }}]
cli.forward-arguments = true
cli.autocomplete = "forward"

[action.echo]
cmd = ["echo", {{ var = "name" }}]
var.name = {{ description = "Name to print" }}
"#,
        work_dir = work_dir.display()
    ));

    let result = harness.run_client(&["self", "complete", "task-args", "--task=list"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines, vec!["forward", work_dir.to_str().unwrap(), "ls"]);

    let result = harness.run_client(&["self", "complete", "task-args", "--task=echo"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines, vec!["vars", "name\tName to print"]);
}

#[test]
fn fish_runnable_completions_do_not_duplicate_group_namespace() {
    let completion_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("completions/devsm.fish");
    let script = format!(
        r#"
function devsm
    set -l joined (string join ' ' -- $argv)
    switch $joined
        case 'self complete runnables'
            printf '%s\n' build serve dev ci
    end
end

source {}
__fish_devsm_runnables
"#,
        completion_path.display()
    );

    let Ok(output) = Command::new("fish").arg("-c").arg(script).output() else {
        return;
    };
    assert!(output.status.success(), "fish failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines, vec!["build", "serve", "dev", "ci"]);
}

#[test]
fn complete_task_args_returns_schema_items() {
    let harness = TestHarness::new("complete_schema_items");
    let work_dir = harness.temp_dir.join("work");
    fs::create_dir_all(&work_dir).expect("create task pwd");
    let schema_script = harness.temp_dir.join("schema.sh");
    fs::write(
        &schema_script,
        format!(
            r#"#!/bin/sh
if [ "$SCHEMA_ENV" != "schema-env" ]; then
    exit 2
fi
if [ "$PWD" != "{}" ]; then
    exit 3
fi
printf '%s\n' '{{"version":1,"options":[{{"name":"env","short":"e","description":"Target environment","value":{{"name":"ENV","candidates":["xo",{{"value":"demo","description":"Demo env"}}]}}}},{{"name":"deploy","description":"Deploy build"}},{{"name":"component","repeatable":true,"value":{{"candidates":["libra_webserver"]}}}}]}}'
"#,
            work_dir.display()
        ),
    )
    .expect("write schema script");
    let mut permissions = fs::metadata(&schema_script).expect("schema metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&schema_script, permissions).expect("chmod schema script");

    harness.write_config(&format!(
        r#"
[action.make]
pwd = "{work_dir}"
cmd = ["true", {{ var = "args" }}]
env.SCHEMA_ENV = "schema-env"
cli.forward-arguments = true
cli.autocomplete = {{ command = ["{schema_script}"] }}
"#,
        work_dir = work_dir.display(),
        schema_script = schema_script.display()
    ));

    let result = harness.run_client(&["self", "complete", "task-args", "--task=make", "--", ""]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines, vec!["items", "--env\tTarget environment", "--deploy\tDeploy build", "--component"]);

    let result = harness.run_client(&["self", "complete", "task-args", "--task=make", "--", "--env", "d"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines, vec!["items", "demo\tDemo env"]);

    let result = harness.run_client(&["self", "complete", "task-args", "--task=make", "--", "--deploy", ""]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);
    let lines: Vec<&str> = result.stdout.lines().collect();
    assert_eq!(lines, vec!["items", "--env\tTarget environment", "--component"]);
}

#[test]
fn run_non_forward_task_still_parses_vars_after_task_name() {
    let mut harness = TestHarness::new("run_legacy_vars");
    let output_file = harness.temp_dir.join("value.txt");
    harness.write_config(&format!(
        r#"
[action.capture]
sh = "printf '%s' \"$VALUE\" > {output}"
env.VALUE = {{ var = "value" }}
"#,
        output = output_file.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "capture", "--value=hello"]);
    assert!(result.success(), "Expected success, got stderr: {}", result.stderr);

    let content = fs::read_to_string(&output_file).unwrap_or_default();
    assert_eq!(content, "hello");
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
require = [{{ name = "dep", vars = {{ value = "aaa" }} }}]

[action.main_b]
sh = "echo main_b >> {output}"
require = [{{ name = "dep", vars = {{ value = "bbb" }} }}]
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
require = [{{ name = "backend", vars = {{ mode = "alpha" }} }}]

[action.task_b]
sh = "touch {task_b_marker}"
require = [{{ name = "backend", vars = {{ mode = "beta" }} }}]
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
require = [{{ name = "backend", vars = {{ mode = "same" }} }}]

[action.task_2]
sh = "touch {task_2_marker}"
require = [{{ name = "backend", vars = {{ mode = "same" }} }}]
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
fn start_does_not_restart_running_service() {
    let mut harness = TestHarness::new("start_no_restart");
    let service_log = harness.temp_dir.join("service.log");

    harness.write_config(&format!(
        r#"
[service.web]
sh = '''
echo "started" >> {service_log}
while true; do sleep 1; done
'''
"#,
        service_log = service_log.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "web"]);
    assert!(result.success(), "start web failed: stderr={}, server_log={}", result.stderr, harness.server_log());
    assert!(
        wait_for_line_count(&service_log, "started", 1, Duration::from_secs(2)),
        "web should start once; log={}, server_log={}",
        fs::read_to_string(&service_log).unwrap_or_default(),
        harness.server_log()
    );

    let result = harness.run_client(&["start", "web"]);
    assert!(result.success(), "second start web failed: stderr={}, server_log={}", result.stderr, harness.server_log());
    std::thread::sleep(Duration::from_millis(100));
    let log = fs::read_to_string(&service_log).unwrap_or_default();
    let start_count = log.lines().filter(|line| line.contains("started")).count();
    assert_eq!(start_count, 1, "second start should not restart service, log: {}", log);

    let result = harness.run_client(&["restart", "web"]);
    assert!(result.success(), "restart web failed: stderr={}, server_log={}", result.stderr, harness.server_log());
    assert!(
        wait_for_line_count(&service_log, "started", 2, Duration::from_secs(2)),
        "restart should start a second process; log={}, server_log={}",
        fs::read_to_string(&service_log).unwrap_or_default(),
        harness.server_log()
    );
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
fn failed_dependency_resolution_rolls_back_earlier_dependencies() {
    let mut harness = TestHarness::new("dep_resolution_rollback");
    let marker = harness.temp_dir.join("ok_ran.txt");

    harness.write_config(&format!(
        r#"
[action.ok]
sh = "echo ok > {marker}"

[action.bad]
pwd = {{ var = "missing" }}
cmd = ["true"]

[action.main]
cmd = ["true"]
require = ["ok", "bad"]
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "main"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("Failed to evaluate task 'bad'"),
        "expected bad dependency eval error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "earlier dependency must not run after later dependency resolution fails");
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

[test.bad_test]
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

[test.bad_test]
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

[test.good_test]
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

[test.alpha_test]
sh = "echo alpha_test_running >> {sequence}; sleep 0.2; echo done > {alpha}"
require = ["srv:alpha"]

[test.beta_test]
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
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("Failed to connect");

    // Command 1: SpawnTask (starts the action)
    let resp1 = client.send_unwrap(&SpawnTaskRequest {
        task_name: "my_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp1.body, CommandBody::Empty), "SpawnTask should succeed with Empty, got {:?}", resp1.body);

    assert!(harness.wait_for_file(&action_marker, Duration::from_secs(3)), "Action should complete");

    // Subscribe to job exit events so we can wait for service termination
    let filter = SubscriptionFilter { job_status: false, job_exits: true };
    let sub_ack: SubscribeAck = client.subscribe(&filter).expect("subscribe failed").decode().expect("decode failed");
    assert!(sub_ack.success, "Subscribe should succeed");

    // Command 2: SpawnTask (starts the service)
    let resp2 = client.send_unwrap(&SpawnTaskRequest {
        task_name: "my_service",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp2.body, CommandBody::Empty), "SpawnTask for service should succeed, got {:?}", resp2.body);

    assert!(harness.wait_for_file(&service_marker, Duration::from_secs(3)), "Service should start");

    // Command 3: KillTask (kills the service)
    let resp3 = client.send_unwrap(&KillTaskRequest { task_name: "my_service" });
    assert!(
        matches!(resp3.body, CommandBody::Message(ref msg) if msg.contains("terminated")),
        "KillTask should succeed with terminated message, got {:?}",
        resp3.body
    );

    // Wait for JobExited event (job_index 1 is the service since action was job 0)
    client.wait_for_job_exit(1).expect("wait_for_job_exit failed");

    // Command 4: KillTask again (should say already finished)
    let resp4 = client.send_unwrap(&KillTaskRequest { task_name: "my_service" });
    assert!(
        matches!(resp4.body, CommandBody::Message(ref msg) if msg.contains("already finished")),
        "KillTask on dead service should return 'already finished', got {:?}",
        resp4.body
    );

    // Command 5: SpawnTask on nonexistent task (should error)
    let resp5 = client.send_unwrap(&SpawnTaskRequest {
        task_name: "nonexistent_task",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
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
fn cache_modified_supports_brace_expansion() {
    let mut harness = TestHarness::new("cache_brace_modified");
    let counter = harness.temp_dir.join("counter.txt");
    let pkg = harness.temp_dir.join("pkg");
    let cargo_toml = pkg.join("Cargo.toml");
    let lib_rs = pkg.join("src/lib.rs");

    fs::create_dir_all(pkg.join("src")).unwrap();
    fs::write(&cargo_toml, "[package]\nname = \"pkg\"\n").unwrap();
    fs::write(&lib_rs, "pub fn f() {}\n").unwrap();
    fs::write(&counter, "0").unwrap();

    harness.write_config(&format!(
        r#"
[action.gen]
sh = '''
count=$(cat {counter})
count=$((count + 1))
echo $count > {counter}
'''
cache.key = [{{ modified = "pkg/{{Cargo.toml,src/lib.rs}}" }}]

[action.consumer]
sh = "cat {counter}"
require = ["gen"]
"#,
        counter = counter.display()
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
    fs::write(&cargo_toml, "[package]\nname = \"pkg2\"\n").unwrap();

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success after Cargo.toml update, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "2", "gen should run after Cargo.toml modified");

    std::thread::sleep(Duration::from_millis(10));
    fs::write(&lib_rs, "pub fn f() { println!(\"updated\"); }\n").unwrap();

    let result = harness.run_client(&["run", "consumer"]);
    assert!(result.success(), "Expected success after lib.rs update, got: {}", result.stderr);
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "3", "gen should run after lib.rs modified");
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
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("Failed to connect");

    // First restart with cached=false: should run the action
    let resp1 = client.send_unwrap(&SpawnTaskRequest {
        task_name: "cached_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp1.body, CommandBody::Empty), "First restart should succeed with Empty, got {:?}", resp1.body);

    // Wait for action to complete
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fs::read_to_string(&counter).unwrap().trim(), "1", "Action should have run once");

    // Second restart with cached=true: should return cache hit message
    let resp2 = client.send_unwrap(&SpawnTaskRequest {
        task_name: "cached_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: true,
    });
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
    let resp3 = client.send_unwrap(&SpawnTaskRequest {
        task_name: "cached_action",
        profile: "",
        params: &[],
        as_test: false,
        cached: true,
    });
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

#[test]
fn function_call_with_config_override() {
    let mut harness = TestHarness::new("function_call_override");
    let marker = harness.temp_dir.join("fn1_ran.txt");
    harness.write_config(&format!(
        r#"
[action.my_task]
sh = "echo ran > {marker}"

[function]
fn1 = {{ restart = "my_task" }}
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["function", "call", "fn1"]);

    assert!(result.success(), "Expected success, got: {}", result.stderr);
    std::thread::sleep(Duration::from_millis(100));
    assert!(marker.exists(), "fn1 should have restarted my_task which creates the marker file");
}

#[test]
fn function_spawn_uses_object_vars() {
    let mut harness = TestHarness::new("function_spawn_object_vars");
    let marker = harness.temp_dir.join("function_spawn.txt");
    harness.write_config(&format!(
        r#"
[action.target]
sh = "echo $MSG > {marker}"
env.MSG = {{ var = "msg" }}

[function]
fn1 = {{ spawn = {{ name = "target", vars = {{ msg = "from_function" }} }} }}
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["function", "call", "fn1"]);

    assert!(result.success(), "Expected success, got: {}", result.stderr);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fs::read_to_string(marker).unwrap(), "from_function\n");
}

#[test]
fn function_call_default_restart_selected() {
    let mut harness = TestHarness::new("function_call_default");
    harness.write_config(
        r#"
[action.dummy]
cmd = ["true"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["function", "call", "fn2"]);

    assert!(
        result.stderr.contains("no active TUI session")
            || result.stderr.contains("no jobs in selected meta-group")
            || result.stderr.contains("selected task no longer exists"),
        "fn2 should default to restart-selected which fails without a TUI/selection, got: {}",
        result.stderr
    );
}

#[test]
fn config_hot_reload_new_task() {
    let mut harness = TestHarness::new("config_hot_reload");
    harness.write_config(
        r#"
[action.existing_task]
cmd = ["echo", "existing"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "existing_task"]);
    assert!(result.success(), "existing_task should succeed: {}", result.stderr);

    std::thread::sleep(Duration::from_millis(100));

    let config_path = harness.temp_dir.join("devsm.toml");
    fs::write(
        &config_path,
        r#"
[action.existing_task]
cmd = ["echo", "existing"]

[action.new_task]
cmd = ["echo", "hot reloaded"]
"#,
    )
    .expect("Failed to write updated config");

    let result = harness.run_client(&["run", "new_task"]);
    assert!(result.success(), "new_task should be found after config reload: {}", result.stderr);
    assert!(result.stdout.contains("hot reloaded"), "new_task should run updated task, got: {}", result.stdout);
}

// ============================================================================
// Resource lock tests
// ============================================================================

/// Two tasks declaring the same resource must run sequentially even if both are
/// scheduled in the same batch.
#[test]
fn resource_two_tasks_serialize() {
    let mut harness = TestHarness::new("resource_serialize");
    let sequence = harness.temp_dir.join("seq.log");

    harness.write_config(&format!(
        r#"
[test.first]
sh = "echo first_start >> {seq}; sleep 0.3; echo first_end >> {seq}"
require = [{{ resource = "R" }}]

[test.second]
sh = "echo second_start >> {seq}; echo second_end >> {seq}"
require = [{{ resource = "R" }}]
"#,
        seq = sequence.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "test command failed: {}", result.stderr);

    let log = fs::read_to_string(&sequence).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let pos_first_end = lines.iter().position(|l| l.contains("first_end")).expect("first_end missing");
    let pos_second_start = lines.iter().position(|l| l.contains("second_start")).expect("second_start missing");
    assert!(pos_first_end < pos_second_start, "second must start AFTER first ends; got: {:?}", lines);
}

/// A task without the resource overlaps freely with the holder.
#[test]
fn resource_third_runs_concurrent() {
    let mut harness = TestHarness::new("resource_concurrent");
    let sequence = harness.temp_dir.join("seq.log");

    harness.write_config(&format!(
        r#"
[test.holder]
sh = "echo holder_start >> {seq}; sleep 0.4; echo holder_end >> {seq}"
require = [{{ resource = "R" }}]

[test.unrelated]
sh = "sleep 0.1; echo unrelated_mid >> {seq}"
"#,
        seq = sequence.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "test command failed: {}", result.stderr);

    let log = fs::read_to_string(&sequence).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let pos_holder_end = lines.iter().position(|l| l.contains("holder_end")).expect("holder_end missing");
    let pos_unrelated = lines.iter().position(|l| l.contains("unrelated_mid")).expect("unrelated_mid missing");
    assert!(
        pos_unrelated < pos_holder_end,
        "unrelated must finish BEFORE holder ends (running concurrently); got: {:?}",
        lines
    );
}

/// Three contenders with priorities 2, 1, 0 must execute in priority order.
#[test]
fn resource_priority_order() {
    let mut harness = TestHarness::new("resource_priority");
    let sequence = harness.temp_dir.join("seq.log");

    harness.write_config(&format!(
        r#"
[test.low]
sh = "echo low >> {seq}; sleep 0.05"
require = [{{ resource = "R", priority = 0 }}]

[test.mid]
sh = "echo mid >> {seq}; sleep 0.05"
require = [{{ resource = "R", priority = 1 }}]

[test.high]
sh = "echo high >> {seq}; sleep 0.05"
require = [{{ resource = "R", priority = 2 }}]
"#,
        seq = sequence.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "test command failed: {}", result.stderr);

    let log = fs::read_to_string(&sequence).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let pos_high = lines.iter().position(|l| l.contains("high")).expect("high missing");
    let pos_mid = lines.iter().position(|l| l.contains("mid")).expect("mid missing");
    let pos_low = lines.iter().position(|l| l.contains("low")).expect("low missing");
    assert!(pos_high < pos_mid && pos_mid < pos_low, "expected high < mid < low, got: {:?}", lines);
}

/// A task with two resources only starts when both are free.
#[test]
fn resource_multi_atomic() {
    let mut harness = TestHarness::new("resource_multi");
    let sequence = harness.temp_dir.join("seq.log");

    harness.write_config(&format!(
        r#"
[test.holder_a]
sh = "echo holder_a_start >> {seq}; sleep 0.4; echo holder_a_end >> {seq}"
require = [{{ resource = "A" }}]

[test.needs_a_and_b]
sh = "echo combo_start >> {seq}; echo combo_end >> {seq}"
require = [{{ resource = "A" }}, {{ resource = "B" }}]
"#,
        seq = sequence.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["test"]);
    assert!(result.success(), "test command failed: {}", result.stderr);

    let log = fs::read_to_string(&sequence).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let pos_holder_end = lines.iter().position(|l| l.contains("holder_a_end")).expect("holder_a_end missing");
    let pos_combo_start = lines.iter().position(|l| l.contains("combo_start")).expect("combo_start missing");
    assert!(pos_holder_end < pos_combo_start, "combo must start AFTER A is released; got: {:?}", lines);
}

/// A failed spawn (bogus executable) releases the resource so the next waiter unblocks.
#[test]
fn resource_release_on_spawn_fail() {
    let mut harness = TestHarness::new("resource_spawn_fail");
    let success_marker = harness.temp_dir.join("ok.txt");

    harness.write_config(&format!(
        r#"
[test.broken]
cmd = ["/nonexistent/bin/devsm-test-binary"]
require = [{{ resource = "R", priority = 1 }}]

[test.ok]
sh = "echo ok > {marker}"
require = [{{ resource = "R", priority = 0 }}]
"#,
        marker = success_marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let _ = harness.run_client(&["test"]);

    assert!(
        harness.wait_for_file(&success_marker, Duration::from_secs(5)),
        "ok task must run after broken's spawn failure released the resource"
    );
}

/// A service holding a resource is evicted when another task requires the resource.
/// Mirrors the eviction behaviour for `require` on a service with no active dependents.
#[test]
fn resource_evicts_service_holder() {
    let mut harness = TestHarness::new("resource_evict_service");
    let service_started = harness.temp_dir.join("service.started");
    let action_done = harness.temp_dir.join("action.done");

    harness.write_config(&format!(
        r#"
[service.holder]
sh = """
echo running > {service_started}
while true; do sleep 1; done
"""
require = [{{ resource = "R" }}]

[action.contender]
sh = "echo done > {action_done}"
require = [{{ resource = "R" }}]
"#,
        service_started = service_started.display(),
        action_done = action_done.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

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
    assert!(harness.wait_for_file(&service_started, Duration::from_secs(3)), "service holder must start");

    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "contender",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "contender spawn rejected: {:?}", resp.body);

    assert!(
        harness.wait_for_file(&action_done, Duration::from_secs(5)),
        "contender must run after service is evicted; server log:\n{}",
        harness.server_log(),
    );
}

/// A service holding a resource is NOT evicted while it has active dependents.
/// Once the dependent action finishes, the service can then be evicted for the
/// queued resource contender.
#[test]
fn resource_waits_for_holder_dependents() {
    let mut harness = TestHarness::new("resource_wait_deps");
    let sequence = harness.temp_dir.join("seq.log");
    let dep_started = harness.temp_dir.join("dep.started");

    harness.write_config(&format!(
        r#"
[service.holder]
sh = """
echo holder_start >> {seq}
while true; do sleep 1; done
"""
require = [{{ resource = "R" }}]

[action.dependent]
sh = "echo dep_started > {dep_started}; sleep 0.6; echo dep_end >> {seq}"
require = ["holder"]

[action.contender]
sh = "echo contender >> {seq}"
require = [{{ resource = "R" }}]
"#,
        seq = sequence.display(),
        dep_started = dep_started.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let config_path = harness.temp_dir.join("devsm.toml");
    let mut client = WorkspaceClient::connect(&harness.socket_path, &config_path).expect("connect");

    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "dependent",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "dependent spawn rejected: {:?}", resp.body);
    assert!(harness.wait_for_file(&dep_started, Duration::from_secs(3)), "dependent must start");

    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "contender",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "contender spawn rejected: {:?}", resp.body);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let log = fs::read_to_string(&sequence).unwrap_or_default();
        if log.contains("contender") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let log = fs::read_to_string(&sequence).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let pos_dep_end = lines.iter().position(|l| l.contains("dep_end"));
    let pos_contender = lines.iter().position(|l| l.contains("contender"));
    assert!(
        pos_dep_end.is_some() && pos_contender.is_some(),
        "expected both dep_end and contender in log; got: {:?}\nserver log:\n{}",
        lines,
        harness.server_log(),
    );
    assert!(
        pos_dep_end.unwrap() < pos_contender.unwrap(),
        "contender must run AFTER dependent finishes (so service was kept alive while dependent was active); got: {:?}",
        lines,
    );
}

/// An action holding a resource is NEVER evicted: the contender waits for the
/// action to terminate naturally.
#[test]
fn resource_does_not_evict_action_holder() {
    let mut harness = TestHarness::new("resource_no_evict_action");
    let sequence = harness.temp_dir.join("seq.log");
    let holder_started = harness.temp_dir.join("holder.started");

    harness.write_config(&format!(
        r#"
[action.holder]
sh = "echo holder_start > {holder_started}; sleep 0.6; echo holder_end >> {seq}"
require = [{{ resource = "R" }}]

[action.contender]
sh = "echo contender >> {seq}"
require = [{{ resource = "R" }}]
"#,
        seq = sequence.display(),
        holder_started = holder_started.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

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
    assert!(harness.wait_for_file(&holder_started, Duration::from_secs(3)), "holder must start");

    let resp = client.send_unwrap(&SpawnTaskRequest {
        task_name: "contender",
        profile: "",
        params: &[],
        as_test: false,
        cached: false,
    });
    assert!(matches!(resp.body, CommandBody::Empty), "contender spawn rejected: {:?}", resp.body);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let log = fs::read_to_string(&sequence).unwrap_or_default();
        if log.contains("contender") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let log = fs::read_to_string(&sequence).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    let pos_holder_end = lines.iter().position(|l| l.contains("holder_end"));
    let pos_contender = lines.iter().position(|l| l.contains("contender"));
    assert!(
        pos_holder_end.is_some() && pos_contender.is_some(),
        "expected both holder_end and contender in log (holder must finish naturally, not be killed); got: {:?}\nserver log:\n{}",
        lines,
        harness.server_log(),
    );
    assert!(
        pos_holder_end.unwrap() < pos_contender.unwrap(),
        "contender must run AFTER holder action terminates naturally; got: {:?}",
        lines,
    );
}

/// A plain require cycle (A → B → A) errors at spawn time with the cycle path.
#[test]
fn plain_require_cycle_error() {
    let mut harness = TestHarness::new("require_cycle");

    harness.write_config(
        r#"
[action.a]
cmd = ["true"]
require = ["b"]

[action.b]
cmd = ["true"]
require = ["a"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "a"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("require cycle"),
        "expected `require cycle` error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
}

/// A task declaring resource R that transitively requires (Active) a service
/// also declaring R is a deadlock.
#[test]
fn resource_service_deadlock_error() {
    let mut harness = TestHarness::new("resource_deadlock");

    harness.write_config(
        r#"
[service.svc]
cmd = ["sleep", "infinity"]
require = [{ resource = "R" }]

[action.user]
cmd = ["true"]
require = ["svc", { resource = "R" }]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "user"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("resource deadlock"),
        "expected `resource deadlock` error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
}

#[test]
fn group_static_error_prevents_partial_spawn() {
    let mut harness = TestHarness::new("group_static_error_no_partial");
    let marker = harness.temp_dir.join("ok.ran");

    harness.write_config(&format!(
        r#"
[action.ok]
sh = "echo ok > {marker}"

[action.bad]
cmd = ["true"]
require = ["loop"]

[action.loop]
cmd = ["true"]
require = ["bad"]

[group]
bad = ["ok", "bad"]
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "group.bad"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("require cycle"),
        "expected static require-cycle error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "group submit must fail before spawning earlier valid entries");
}

#[test]
fn group_dynamic_eval_error_prevents_partial_spawn() {
    let mut harness = TestHarness::new("group_dynamic_error_no_partial");
    let marker = harness.temp_dir.join("ok.ran");

    harness.write_config(&format!(
        r#"
[action.ok]
sh = "echo ok > {marker}"

[action.bad]
pwd = {{ var = "missing" }}
cmd = ["true"]

[group]
bad = ["ok", "bad"]
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["start", "group.bad"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("Failed to evaluate task 'bad'"),
        "expected dynamic eval error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "group submit must roll back earlier valid entries after dynamic eval failure");
}

#[test]
fn direct_and_nested_uncached_action_requirements_both_run() {
    let mut harness = TestHarness::new("direct_nested_uncached_action");
    let order = harness.temp_dir.join("order.log");

    harness.write_config(&format!(
        r#"
[action.setup]
sh = "echo setup >> {order}"

[service.a]
sh = "echo a >> {order}; sleep 30"
require = ["setup"]

[action.user]
sh = "echo user >> {order}"
require = ["a", "setup"]
"#,
        order = order.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "user"]);
    assert!(result.success(), "user should run: stdout={}, stderr={}", result.stdout, result.stderr);

    let written = fs::read_to_string(&order).expect("order log should exist");
    let setup_count = written.lines().filter(|line| *line == "setup").count();
    assert_eq!(setup_count, 2, "direct and nested setup requirements must run separately:\n{written}");
    assert!(written.lines().any(|line| line == "a"), "service should have run:\n{written}");
    assert!(written.lines().any(|line| line == "user"), "dependent action should have run:\n{written}");
}

/// Sharing a resource via an Action chain (predicate
/// TerminatedNaturallyAndSuccessfully) is *not* a deadlock — the action
/// releases its hold before the requirer runs.
#[test]
fn resource_action_chain_not_flagged() {
    let mut harness = TestHarness::new("resource_action_chain");
    let marker = harness.temp_dir.join("done.txt");

    harness.write_config(&format!(
        r#"
[action.dep]
cmd = ["true"]
require = [{{ resource = "R" }}]

[action.user]
sh = "echo done > {marker}"
require = ["dep", {{ resource = "R" }}]
"#,
        marker = marker.display(),
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "user"]);
    assert!(result.success(), "action chain should not be flagged as deadlock: {}", result.stderr);
    assert!(harness.wait_for_file(&marker, Duration::from_secs(5)), "user task should complete");
}

/// `devsm self validate` must accept the `action.`, `service.`, and `test.`
/// kind-qualified require prefixes that the daemon's lookup already supports.
#[test]
fn validate_accepts_kind_qualified_require_names() {
    let harness = TestHarness::new("validate_kind_qualified");
    harness.write_config(
        r#"
[action.dep]
cmd = ["echo", "dep"]

[service.svc]
cmd = ["./svc"]

[test.t]
cmd = ["echo", "t"]

[action.user]
cmd = ["echo", "user"]
require = ["action.dep", "service.svc"]
"#,
    );

    let config_path = harness.temp_dir.join("devsm.toml");
    let result = Command::new(cargo_bin_path())
        .args(["self", "validate"])
        .arg(&config_path)
        .arg("--skip-path-checks")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("validate should run");

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success(),
        "validate must accept kind-qualified require names; status: {:?}\nstdout: {}\nstderr: {}",
        result.status,
        stdout,
        stderr,
    );
}

#[test]
fn validate_checks_conditional_require_branches() {
    let harness = TestHarness::new("validate_conditional_require");
    harness.write_config(
        r#"
[action.user]
cmd = ["echo", "user"]
profiles = ["default", "live"]
require = [
  { if.profile = "live", then = "missing_dep" },
]
"#,
    );

    let config_path = harness.temp_dir.join("devsm.toml");
    let result = Command::new(cargo_bin_path())
        .args(["self", "validate"])
        .arg(&config_path)
        .arg("--skip-path-checks")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("validate should run");

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "validate should fail for conditional missing dep");
    assert!(
        stdout.contains("missing_dep") || stderr.contains("missing_dep"),
        "validate should mention missing conditional dep; stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn validate_accepts_implicitly_profiled_conditional_require() {
    let harness = TestHarness::new("validate_inferred_conditional_profile");
    harness.write_config(
        r#"
[action.setup]
cmd = ["echo", "setup"]

[action.backend]
cmd = ["echo", "backend"]
require = [
  { if.profile = "live", then = "setup" },
]

[action.user]
cmd = ["echo", "user"]
require = ["backend:live"]
"#,
    );

    let config_path = harness.temp_dir.join("devsm.toml");
    let result = Command::new(cargo_bin_path())
        .args(["self", "validate"])
        .arg(&config_path)
        .arg("--skip-path-checks")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("validate should run");

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success(),
        "validate should accept inferred profile from conditional require; stdout: {stdout}\nstderr: {stderr}"
    );
}

#[test]
fn validate_rejects_explicit_profiles_missing_conditional_require_profile() {
    let harness = TestHarness::new("validate_incomplete_explicit_profiles");
    harness.write_config(
        r#"
[action.setup]
cmd = ["echo", "setup"]

[action.backend]
profiles = ["default"]
cmd = ["echo", "backend"]
require = [
  { if.profile = "live", then = "setup" },
]
"#,
    );

    let config_path = harness.temp_dir.join("devsm.toml");
    let result = Command::new(cargo_bin_path())
        .args(["self", "validate"])
        .arg(&config_path)
        .arg("--skip-path-checks")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("validate should run");

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!result.status.success(), "validate should reject incomplete explicit profiles");
    assert!(
        stdout.contains("not listed in `profiles`") || stderr.contains("not listed in `profiles`"),
        "validate should explain missing explicit profile; stdout: {stdout}\nstderr: {stderr}"
    );
}

/// A task whose `require` list pins the same `allow_multiple = false` service
/// to two different variants (different params or different profiles) cannot
/// be satisfied. The daemon must reject the spawn up front rather than
/// scheduling jobs that deadlock or silently get cancelled.
#[test]
fn task_with_incompatible_service_requirements_errors_up_front() {
    let mut harness = TestHarness::new("incompat_svc_reqs");
    harness.write_config(
        r#"
[service.svc]
sh = "while true; do sleep 1; done"
var.port = { default = "8080" }

[action.user]
cmd = ["true"]
require = [
  { name = "svc", vars = { port = "a" } },
  { name = "svc", vars = { port = "b" } },
]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["run", "user"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("conflicting") || combined.contains("incompatible"),
        "spawn must reject incompatible service requirements up front, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
}

#[test]
fn action_with_transitive_incompatible_service_requirements_errors_up_front() {
    let mut harness = TestHarness::new("transitive_incompat_action_svc_reqs");
    harness.write_config(
        r#"
[service.base]
cmd = ["sleep", "infinity"]
profiles = ["alpha", "beta"]

[service.svc_alpha]
cmd = ["sleep", "infinity"]
require = ["base:alpha"]

[service.svc_beta]
cmd = ["sleep", "infinity"]
require = ["base:beta"]

[action.user]
cmd = ["true"]
require = ["svc_alpha", "svc_beta"]
"#,
    );
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

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
            assert!(err.contains("conflicting service requirements"), "unexpected error: {err}");
        }
        other => panic!("spawn must reject transitive incompatible service requirements up front, got {other:?}"),
    }
}

/// A `function call` sends the spawn request straight to the daemon without
/// the CLI's client-side `resolve_name_in_config` check. After a reload that
/// removes the target task, the daemon must report it gone instead of silently
/// reusing the stale v1 expression.
#[test]
fn function_call_to_removed_task_errors_after_reload() {
    let mut harness = TestHarness::new("fn_removed_task");
    let marker = harness.temp_dir.join("target_ran.txt");

    harness.write_config(&format!(
        r#"
[action.target]
sh = "echo ran > {marker}"

[function]
fn1 = {{ restart = "target" }}
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["function", "call", "fn1"]);
    assert!(result.success(), "fn1 must run target before reload: {}", result.stderr);
    assert!(harness.wait_for_file(&marker, Duration::from_secs(5)), "target should have produced marker");
    std::fs::remove_file(&marker).expect("clear marker before reload");

    std::thread::sleep(Duration::from_millis(100));
    harness.write_config(
        r#"
[action.placeholder]
cmd = ["true"]

[function]
fn1 = { restart = "target" }
"#,
    );

    let result = harness.run_client(&["function", "call", "fn1"]);
    std::thread::sleep(Duration::from_millis(200));
    let combined = format!("{}{}", result.stdout, result.stderr);

    assert!(
        !marker.exists(),
        "stale target config must not run after reload removes it (combined output: {})",
        combined
    );
    assert!(
        combined.contains("not found"),
        "daemon should reject the removed task, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
}

#[test]
fn function_spawn_dynamic_eval_error_prevents_partial_spawn() {
    let mut harness = TestHarness::new("function_spawn_dynamic_error_no_partial");
    let marker = harness.temp_dir.join("ok.ran");

    harness.write_config(&format!(
        r#"
[action.ok]
sh = "echo ok > {marker}"

[action.bad]
pwd = {{ var = "missing" }}
cmd = ["true"]

[function]
fn1 = {{ spawn = ["ok", "bad"] }}
"#,
        marker = marker.display()
    ));
    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let result = harness.run_client(&["function", "call", "fn1"]);
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("Failed to evaluate task 'bad'"),
        "expected dynamic eval error, got stdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "function spawn must roll back earlier entries after dynamic eval failure");
}
