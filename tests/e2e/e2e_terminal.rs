use crate::harness::{RpcEvent, RpcSubscriber, TestAppServer, TestHarness};
use crate::rpc::{ClientProtocol, DecodeResult, Encoder, ExitCause, JobStatusKind, RpcMessageKind, TerminalExitedEvent, TerminalRunEvent, TerminalStartEvent};
use jsony::ToBinary;
use std::io::{Read, Write};
use std::os::unix::{ffi::OsStrExt, net::UnixStream};
use std::time::Duration;

struct RawTerminalHarness {
    socket: UnixStream,
    protocol: ClientProtocol,
    buffer: Vec<u8>,
}

impl RawTerminalHarness {
    fn attach(harness: &TestHarness, sticky: bool) -> Self {
        let ready = harness.run_client(&["status"]);
        assert!(ready.success(), "server was not ready: {}; server log:\n{}", ready.stderr, harness.server_log());
        let mut socket = UnixStream::connect(&harness.socket_path).expect("raw terminal connect failed");
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = jsony::BytesWriter::new();
        harness.temp_dir.as_os_str().as_bytes().encode_binary(&mut request);
        // daemon::Request::AttachTerminal is appended to preserve all legacy discriminants.
        request.push(7);
        harness.temp_dir.join("devsm.toml").as_os_str().as_bytes().encode_binary(&mut request);
        "editor".encode_binary(&mut request);
        jsony_value::ValueMap::new().encode_binary(&mut request);
        sticky.encode_binary(&mut request);
        (unsafe { libc::getpgrp() }).encode_binary(&mut request);
        socket.write_all(&request.into_vec()).unwrap();
        Self { socket, protocol: ClientProtocol::new(), buffer: Vec::new() }
    }

    fn next_start(&mut self) -> TerminalStartEvent {
        loop {
            match self.protocol.decode(&self.buffer) {
                DecodeResult::Message { kind, payload, .. } => {
                    let start = (kind == RpcMessageKind::TerminalStart)
                        .then(|| jsony::from_binary(payload).expect("invalid TerminalStart"));
                    self.protocol.compact(&mut self.buffer, 4096);
                    if let Some(start) = start {
                        return start;
                    }
                }
                DecodeResult::MissingData { .. } | DecodeResult::Empty => {
                    self.protocol.compact(&mut self.buffer, 4096);
                    let mut chunk = [0u8; 4096];
                    let count = self.socket.read(&mut chunk).expect("raw terminal socket read failed");
                    assert_ne!(count, 0, "daemon disconnected from raw terminal harness");
                    self.buffer.extend_from_slice(&chunk[..count]);
                }
                DecodeResult::Error(error) => panic!("terminal protocol error: {error:?}"),
            }
        }
    }

    fn send<T: jsony::ToBinary>(&mut self, kind: RpcMessageKind, event: &T) {
        let mut encoder = Encoder::new();
        encoder.encode_push(kind, event);
        self.socket.write_all(encoder.output()).unwrap();
    }

    fn disconnect(mut self) {
        self.socket.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buffer = [0u8; 4096];
        while self.socket.read(&mut buffer).unwrap_or(0) != 0 {}
    }
}

fn subscribe(harness: &TestHarness) -> RpcSubscriber {
    let ready = harness.run_client(&["status"]);
    assert!(ready.success(), "server was not ready: {}", ready.stderr);
    let mut subscriber = RpcSubscriber::connect(harness);
    let events = subscriber.collect_until(
        |events| events.iter().any(|event| matches!(event, RpcEvent::WorkspaceOpened)),
        Duration::from_secs(5),
    );
    assert!(events.iter().any(|event| matches!(event, RpcEvent::WorkspaceOpened)));
    subscriber
}

fn wait_for_exit(subscriber: &mut RpcSubscriber, job_index: u32) -> Vec<RpcEvent> {
    let events = subscriber.collect_until(
        |events| events.iter().any(|event| matches!(event, RpcEvent::JobExited { job_index: index, .. } if *index == job_index)),
        Duration::from_secs(5),
    );
    assert!(
        events.iter().any(|event| matches!(event, RpcEvent::JobExited { job_index: index, .. } if *index == job_index)),
        "job {job_index} did not exit: {events:?}"
    );
    events
}

#[test]
fn terminal_run_inherits_pty_and_reports_real_exit() {
    let mut harness = TestHarness::new("terminal_run_inherits_pty");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();

    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));
    editor.write_stdout(b"terminal-child-output\n");
    editor.exit(7);
    let result = wrapper.wait(Duration::from_secs(10), || harness.server_log());
    assert_eq!(result.exit_code, 7, "PTY output:\n{}\nserver log:\n{}", result.output, harness.server_log());
    assert!(result.output.contains("terminal-child-output"), "PTY output:\n{}", result.output);

    let logs = harness.run_client(&["logs", "--task=editor"]);
    assert!(logs.success(), "logs failed: {}", logs.stderr);
    assert!(
        !logs.stdout.contains("terminal-child-output"),
        "terminal child output leaked into daemon logs: {}",
        logs.stdout
    );
    assert!(logs.stdout.contains("output is attached to its terminal"), "logs output: {}", logs.stdout);
}

#[test]
fn terminal_child_can_read_before_the_wrapper_spawn_returns() {
    let mut harness = TestHarness::new("terminal_immediate_stdin");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
cmd = ["test-app", "editor", "--read-stdin-before-connect"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();

    let mut wrapper = harness.spawn_pty_client(&["run", "editor"]);
    wrapper.send_input(b"ready\n");
    let mut editor = ctrl.accept(Duration::from_secs(5));
    assert_eq!(editor.name(), "editor");
    editor.exit(0);
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "PTY output:\n{}\nserver log:\n{}", result.output, harness.server_log());
}

#[test]
fn terminal_job_reports_scheduled_starting_running_and_exact_exit() {
    let mut harness = TestHarness::new("terminal_lifecycle_events");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);

    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));
    editor.exit(9);
    let events = wait_for_exit(&mut subscriber, 0);
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 9, "PTY output:\n{}", result.output);
    for expected in [JobStatusKind::Scheduled, JobStatusKind::Starting, JobStatusKind::Running] {
        assert!(
            events.iter().any(|event| {
                matches!(event, RpcEvent::JobStatus { job_index: 0, status } if std::mem::discriminant(status) == std::mem::discriminant(&expected))
            }),
            "missing {expected:?} in {events:?}; server log:\n{}",
            harness.server_log()
        );
    }
    assert!(
        events.iter().any(|event| matches!(
            event,
            RpcEvent::JobExited { job_index: 0, exit_code: 9, cause: ExitCause::Unknown }
        )),
        "incorrect exit event: {events:?}"
    );
}

#[test]
fn stale_terminal_exit_token_is_ignored_after_relaunch() {
    let mut harness = TestHarness::new("terminal_stale_token");
    harness.write_config(
        r#"
[action.editor]
managed = "terminal"
cmd = ["true"]
"#,
    );
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);
    let mut wrapper = RawTerminalHarness::attach(&harness, true);
    let first = wrapper.next_start();
    wrapper.send(
        RpcMessageKind::TerminalStarted,
        &TerminalRunEvent {
            run_token: first.run_token,
            process_group: unsafe { libc::getpid() },
        },
    );
    wrapper.send(
        RpcMessageKind::TerminalExited,
        &TerminalExitedEvent { run_token: first.run_token, exit_code: 0 },
    );
    wait_for_exit(&mut subscriber, 0);

    let started = harness.run_client(&["start", "editor"]);
    assert!(started.success(), "relaunch failed: {}", started.stderr);
    let second = wrapper.next_start();
    assert_ne!(first.run_token, second.run_token);
    wrapper.send(
        RpcMessageKind::TerminalExited,
        &TerminalExitedEvent { run_token: first.run_token, exit_code: 99 },
    );
    let status = harness.run_client(&["status", "editor"]);
    assert!(!status.stdout.contains("code 99"), "stale exit mutated replacement job: {}", status.stdout);

    wrapper.send(
        RpcMessageKind::TerminalStarted,
        &TerminalRunEvent {
            run_token: second.run_token,
            process_group: unsafe { libc::getpid() },
        },
    );
    let events = subscriber.collect_until(
        |events| events.iter().any(|event| matches!(event, RpcEvent::JobStatus { job_index: 1, status: JobStatusKind::Running })),
        Duration::from_secs(5),
    );
    assert!(events.iter().any(|event| matches!(event, RpcEvent::JobStatus { job_index: 1, status: JobStatusKind::Running })));
    wrapper.send(
        RpcMessageKind::TerminalExited,
        &TerminalExitedEvent { run_token: second.run_token, exit_code: 0 },
    );
    wait_for_exit(&mut subscriber, 1);
    let mut encoder = Encoder::new();
    encoder.encode_empty(RpcMessageKind::TerminalDetach, 0);
    wrapper.socket.write_all(encoder.output()).unwrap();
}

#[test]
fn disconnect_during_terminal_starting_records_spawn_failure_and_releases_resources() {
    let mut harness = TestHarness::new("terminal_starting_disconnect");
    harness.write_config(
        r#"
[service.editor]
managed = "terminal"
cmd = ["true"]
require = [{ resource = "serial" }]

[action.contender]
cmd = ["true"]
require = [{ resource = "serial" }]
"#,
    );
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);
    let mut wrapper = RawTerminalHarness::attach(&harness, false);
    let _start = wrapper.next_start();
    drop(wrapper);
    wait_for_exit(&mut subscriber, 0);
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("spawn_failed"), "starting disconnect cause: {}", status.stdout);
    assert!(status.stdout.contains("127"), "starting disconnect exit code: {}", status.stdout);

    let contender = harness.run_client(&["run", "contender"]);
    assert!(contender.success(), "starting disconnect pinned resource: {}", contender.stderr);
}

#[test]
fn disconnect_while_terminal_job_is_scheduled_cancels_it() {
    let mut harness = TestHarness::new("terminal_scheduled_disconnect");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{socket}"

[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"
require = ["setup"]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let mut wrapper = RawTerminalHarness::attach(&harness, false);
    let mut attached = [0u8; 4096];
    assert!(wrapper.socket.read(&mut attached).unwrap() > 0);
    let mut setup = ctrl.accept(Duration::from_secs(5));
    assert_eq!(setup.name(), "setup");
    wrapper.disconnect();
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("cancelled"), "scheduled disconnect status: {}", status.stdout);
    setup.exit(0);
    assert!(ctrl.try_accept(Duration::from_millis(100)).is_none(), "cancelled editor was spawned");
}

#[test]
fn terminal_restart_reuses_non_sticky_wrapper() {
    let mut harness = TestHarness::new("terminal_restart_same_wrapper");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
sh = "exec test-app editor $$"
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let client = harness.spawn_pty_client(&["run", "editor"]);
    let mut first = ctrl.accept(Duration::from_secs(5));

    let restarted = harness.run_client(&["restart", "editor"]);
    assert!(restarted.success(), "restart failed: {}\n{}", restarted.stderr, harness.server_log());
    assert!(first.wait_disconnected(Duration::from_secs(5)), "restarted child did not exit");
    let mut second = ctrl.accept(Duration::from_secs(5));
    assert_ne!(first.args[2], second.args[2], "restart did not create a replacement child");

    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}", stopped.stderr);
    assert!(second.wait_disconnected(Duration::from_secs(5)), "replacement child did not stop");
    let result = client.wait(Duration::from_secs(10), || harness.server_log());
    assert_eq!(result.exit_code, 143, "PTY output:\n{}\nserver log:\n{}", result.output, harness.server_log());
}

#[test]
fn stop_resumes_a_suspended_terminal_wrapper() {
    let mut harness = TestHarness::new("terminal_stop_suspended_wrapper");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    wrapper.signal_wrapper(libc::SIGSTOP);
    wrapper.wait_wrapper_stopped(Duration::from_secs(5));
    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}\n{}", stopped.stderr, harness.server_log());
    assert!(editor.wait_disconnected(Duration::from_secs(5)), "suspended wrapper did not stop its child");
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 143, "PTY output:\n{}", result.output);
}

#[test]
fn stop_recovers_a_ctrl_z_suspended_terminal_job() {
    let mut harness = TestHarness::new("terminal_stop_ctrl_z_job");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let mut wrapper = harness.spawn_job_controlled_pty_client(&ctrl.path, &["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    wrapper.send_ctrl_z();
    let mut stopped_event = ctrl.accept(Duration::from_secs(5));
    assert_eq!(stopped_event.name(), "wrapper-stopped");
    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}\n{}", stopped.stderr, harness.server_log());
    assert!(editor.wait_disconnected(Duration::from_secs(5)), "Ctrl-Z-stopped child was not terminated");
    stopped_event.exit(0);
    let _result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
}

#[test]
fn restart_resumes_a_suspended_terminal_wrapper() {
    let mut harness = TestHarness::new("terminal_restart_suspended_wrapper");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut first = ctrl.accept(Duration::from_secs(5));

    wrapper.signal_wrapper(libc::SIGSTOP);
    wrapper.wait_wrapper_stopped(Duration::from_secs(5));
    let restarted = harness.run_client(&["restart", "editor"]);
    assert!(restarted.success(), "restart failed: {}\n{}", restarted.stderr, harness.server_log());
    assert!(first.wait_disconnected(Duration::from_secs(5)), "suspended wrapper did not stop its old child");
    let mut second = ctrl.accept(Duration::from_secs(5));

    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "replacement stop failed: {}", stopped.stderr);
    assert!(second.wait_disconnected(Duration::from_secs(5)), "replacement child did not stop");
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 143, "PTY output:\n{}", result.output);
}

#[test]
fn explicit_run_in_a_new_terminal_supersedes_the_old_wrapper() {
    let mut harness = TestHarness::new("terminal_explicit_supersede");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
sh = "exec test-app editor $$"
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let old_wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut first = ctrl.accept(Duration::from_secs(5));

    let new_wrapper = harness.spawn_pty_client(&["run", "editor"]);
    assert!(first.wait_disconnected(Duration::from_secs(5)), "superseded child did not exit");
    let mut second = ctrl.accept(Duration::from_secs(5));
    assert_ne!(first.args[2], second.args[2]);
    let old = old_wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(old.exit_code, 143, "old PTY output:\n{}", old.output);

    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}", stopped.stderr);
    assert!(second.wait_disconnected(Duration::from_secs(5)), "replacement child did not stop");
    let new = new_wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(new.exit_code, 143, "new PTY output:\n{}", new.output);
}

#[test]
fn sticky_action_config_keeps_terminal_wrapper_attached() {
    let mut harness = TestHarness::new("sticky_action_config");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
sticky = true
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);
    let mut client = harness.spawn_pty_client(&["run", "editor"]);
    let mut first = ctrl.accept(Duration::from_secs(5));
    first.exit(0);
    wait_for_exit(&mut subscriber, 0);
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("idle wrapper attached"), "idle wrapper missing from status: {}", status.stdout);

    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop of idle wrapper failed: {}", stopped.stderr);

    let started = harness.run_client(&["start", "editor"]);
    assert!(started.success(), "start failed: {}\n{}", started.stderr, harness.server_log());
    let mut second = ctrl.accept(Duration::from_secs(5));
    second.exit(0);
    wait_for_exit(&mut subscriber, 1);

    client.send_ctrl_c();
    let result = client.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "PTY output:\n{}", result.output);
    assert!(result.output.contains("Terminal task is idle"), "PTY output:\n{}", result.output);
}

#[test]
fn sticky_wrapper_survives_stop_and_can_be_started_again() {
    let mut harness = TestHarness::new("sticky_terminal_stop_relaunch");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);
    let mut wrapper = harness.spawn_pty_client(&["run", "--sticky", "editor"]);
    let mut first = ctrl.accept(Duration::from_secs(5));

    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "first stop failed: {}", stopped.stderr);
    assert!(first.wait_disconnected(Duration::from_secs(5)));
    wait_for_exit(&mut subscriber, 0);
    let started = harness.run_client(&["start", "editor"]);
    assert!(started.success(), "relaunch failed: {}\n{}", started.stderr, harness.server_log());
    let mut second = ctrl.accept(Duration::from_secs(5));
    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "second stop failed: {}", stopped.stderr);
    assert!(second.wait_disconnected(Duration::from_secs(5)));
    wait_for_exit(&mut subscriber, 1);

    wrapper.send_ctrl_c();
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 143, "PTY output:\n{}", result.output);
}

#[test]
fn missing_terminal_requirement_is_transactional_and_actionable() {
    let mut harness = TestHarness::new("missing_terminal_requirement");
    harness.write_config(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]

[action.consumer]
require = ["editor"]
cmd = ["sh", "-c", "touch consumer-ran"]
"#,
    );
    harness.spawn_server();

    let result = harness.run_client(&["run", "consumer"]);
    assert!(!result.success(), "consumer unexpectedly ran");
    let message = format!("{}{}", result.stdout, result.stderr);
    assert!(message.contains("required terminal task 'editor' is not running"), "message:\n{message}");
    assert!(message.contains("devsm editor"), "message:\n{message}");
    assert!(!harness.temp_dir.join("consumer-ran").exists());

    let status = harness.run_client(&["status"]);
    assert!(!status.stdout.contains("scheduled"), "partial jobs were left behind: {}", status.stdout);
}

#[test]
fn active_terminal_service_satisfies_managed_requirement() {
    let mut harness = TestHarness::new("active_terminal_requirement");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"

[action.consumer]
require = ["editor"]
cmd = ["test-app", "consumer"]
env.TEST_APP_SOCKET = "{socket}"
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    let consumer = std::thread::scope(|scope| {
        let run = scope.spawn(|| harness.run_client(&["run", "consumer"]));
        let mut consumer = ctrl.accept(Duration::from_secs(5));
        consumer.exit(0);
        run.join().unwrap()
    });
    assert!(consumer.success(), "consumer failed: {}\n{}", consumer.stderr, harness.server_log());

    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}", stopped.stderr);
    assert!(editor.wait_disconnected(Duration::from_secs(5)));
    let _ = wrapper.wait(Duration::from_secs(5), || harness.server_log());
}

#[test]
fn terminal_signal_exit_is_reported_as_128_plus_signal() {
    let mut harness = TestHarness::new("terminal_signal_exit");
    harness.write_config(
        r#"
[action.editor]
managed = "terminal"
sh = "kill -TERM $$"
"#,
    );
    harness.spawn_server();
    let result = harness.run_pty_client(&["editor"], Duration::from_secs(5));
    assert_eq!(result.exit_code, 143, "PTY output:\n{}\nserver log:\n{}", result.output, harness.server_log());
}

#[test]
fn terminal_resources_remain_held_until_the_reported_exit() {
    let mut harness = TestHarness::new("terminal_resources_held");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"
require = [{{ resource = "serial" }}]

[action.contender]
cmd = ["test-app", "contender"]
env.TEST_APP_SOCKET = "{socket}"
require = [{{ resource = "serial" }}]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    let contender = std::thread::scope(|scope| {
        let run = scope.spawn(|| harness.run_client(&["run", "contender"]));
        assert!(ctrl.try_accept(Duration::from_millis(100)).is_none(), "contender started before resource release");
        editor.exit(0);
        let mut contender = ctrl.accept(Duration::from_secs(5));
        assert_eq!(contender.name(), "contender");
        contender.exit(0);
        run.join().unwrap()
    });
    assert!(contender.success(), "contender failed: {}\n{}", contender.stderr, harness.server_log());
    let wrapper = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(wrapper.exit_code, 0, "PTY output:\n{}", wrapper.output);
}

#[test]
fn resource_contention_terminates_a_terminal_owned_service() {
    let mut harness = TestHarness::new("terminal_resource_service_eviction");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"
require = [{{ resource = "serial" }}]

[action.contender]
cmd = ["test-app", "contender"]
env.TEST_APP_SOCKET = "{socket}"
require = [{{ resource = "serial" }}]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    let contender = std::thread::scope(|scope| {
        let run = scope.spawn(|| harness.run_client(&["run", "contender"]));
        assert!(editor.wait_disconnected(Duration::from_secs(5)), "editor was not evicted");
        let mut contender = ctrl.accept(Duration::from_secs(5));
        contender.exit(0);
        run.join().unwrap()
    });
    assert!(contender.success(), "contender failed: {}\n{}", contender.stderr, harness.server_log());
    let wrapper = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(wrapper.exit_code, 143, "PTY output:\n{}", wrapper.output);
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("killed"), "eviction cause: {}", status.stdout);
}

#[test]
fn managed_requirements_complete_before_terminal_child_launch() {
    let mut harness = TestHarness::new("terminal_managed_requirement_order");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{socket}"

[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"
require = ["setup"]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut setup = ctrl.accept(Duration::from_secs(5));
    assert_eq!(setup.name(), "setup");
    assert!(ctrl.try_accept(Duration::from_millis(100)).is_none(), "terminal task started before its requirement");
    setup.exit(0);
    let mut editor = ctrl.accept(Duration::from_secs(5));
    assert_eq!(editor.name(), "editor");
    editor.write_stdout(b"terminal-after-setup\n");
    editor.exit(0);
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "PTY output:\n{}\n{}", result.output, harness.server_log());
    assert!(result.output.contains("Waiting for: setup"), "wrapper did not report scheduler wait: {}", result.output);
    assert!(result.output.contains("terminal-after-setup"), "terminal child ran before setup: {}", result.output);
}

#[test]
fn failed_requirement_releases_the_waiting_terminal_wrapper() {
    let mut harness = TestHarness::new("terminal_failed_requirement_releases_wrapper");
    harness.write_config(
        r#"
[action.setup]
sh = "exit 7"

[action.editor]
managed = "terminal"
cmd = ["true"]
require = ["setup"]
"#,
    );
    harness.spawn_server();

    let result = harness.run_pty_client(&["run", "editor"], Duration::from_secs(5));
    assert_ne!(result.exit_code, 0, "failed dependency unexpectedly succeeded: {}", result.output);
    assert!(
        result.output.contains("required dependency 'setup'"),
        "missing dependency failure diagnostic: {}\n{}",
        result.output,
        harness.server_log()
    );
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("cancelled"), "terminal root was not cancelled: {}", status.stdout);
}

#[test]
fn stopping_a_scheduled_terminal_job_detaches_without_spawning_it() {
    let mut harness = TestHarness::new("terminal_stop_while_scheduled");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{socket}"

[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"
require = ["setup"]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut setup = ctrl.accept(Duration::from_secs(5));
    wrapper.signal_wrapper(libc::SIGSTOP);
    wrapper.wait_wrapper_stopped(Duration::from_secs(5));
    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}", stopped.stderr);
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "PTY output:\n{}", result.output);
    setup.exit(0);
    assert!(ctrl.try_accept(Duration::from_millis(100)).is_none(), "stopped terminal task was spawned");
}

#[test]
fn ctrl_c_cancels_a_non_sticky_terminal_wrapper_waiting_on_requirements() {
    let mut harness = TestHarness::new("terminal_waiting_ctrl_c");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{socket}"

[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"
require = ["setup"]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let mut wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let _setup = ctrl.accept(Duration::from_secs(5));

    wrapper.send_ctrl_c();
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "Ctrl-C did not detach the waiting wrapper: {}", result.output);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let status = loop {
        let status = harness.run_client(&["status", "editor"]);
        if status.stdout.contains("cancelled") || std::time::Instant::now() >= deadline {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.stdout.contains("cancelled"), "waiting terminal job remained active: {}", status.stdout);
    assert!(ctrl.try_accept(Duration::from_millis(100)).is_none(), "terminal child spawned after Ctrl-C");
}

#[test]
fn restart_while_scheduled_keeps_the_same_non_sticky_wrapper_for_replacement() {
    let mut harness = TestHarness::new("terminal_restart_while_scheduled");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{socket}"

[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{socket}"
require = ["setup"]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut setup = ctrl.accept(Duration::from_secs(5));
    let restarted = harness.run_client(&["restart", "editor"]);
    assert!(restarted.success(), "restart failed: {}\n{}", restarted.stderr, harness.server_log());
    setup.exit(0);
    let mut editor = ctrl.accept(Duration::from_secs(5));
    if editor.name() == "setup" {
        editor.exit(0);
        editor = ctrl.accept(Duration::from_secs(5));
    }
    assert_eq!(editor.name(), "editor");
    editor.exit(0);
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "PTY output:\n{}", result.output);
}

#[test]
fn stopping_a_scheduled_restart_replacement_releases_the_wrapper() {
    let mut harness = TestHarness::new("terminal_stop_scheduled_replacement");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.setup]
cmd = ["test-app", "setup"]
env.TEST_APP_SOCKET = "{socket}"

[service.editor]
managed = "terminal"
cmd = ["true"]
require = ["setup"]
"#,
        socket = ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let _setup = ctrl.accept(Duration::from_secs(5));

    let restarted = harness.run_client(&["restart", "editor"]);
    assert!(restarted.success(), "restart failed: {}\n{}", restarted.stderr, harness.server_log());
    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}\n{}", stopped.stderr, harness.server_log());

    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "scheduled replacement retained the wrapper: {}", result.output);
    let status = harness.run_client(&["status", "editor"]);
    assert!(!status.stdout.contains("scheduled"), "replacement remained scheduled: {}", status.stdout);
}

#[test]
fn repeated_restart_while_two_terminal_jobs_are_scheduled_is_rejected_and_keeps_newest_owner() {
    let mut harness = TestHarness::new("terminal_restart_two_scheduled");
    harness.write_config(
        r#"
[action.setup]
sh = "sleep 1"
cache.never = true

[service.editor]
managed = "terminal"
allow_multiple = true
cmd = ["true"]
require = ["setup"]
"#,
    );
    harness.spawn_server();
    let mut first = RawTerminalHarness::attach(&harness, true);
    let mut second = RawTerminalHarness::attach(&harness, true);

    let restarted = harness.run_client(&["restart", "editor"]);
    assert!(restarted.success(), "restart failed: {}\n{}", restarted.stderr, harness.server_log());
    let repeated = harness.run_client(&["restart", "editor"]);
    assert!(!repeated.success(), "second restart unexpectedly replaced a pending replacement");
    assert!(
        repeated.stderr.contains("replacement is already pending"),
        "unexpected repeated-restart diagnostic: {}",
        repeated.stderr
    );

    let replacement = second.next_start();
    second.send(
        RpcMessageKind::TerminalStarted,
        &TerminalRunEvent {
            run_token: replacement.run_token,
            process_group: unsafe { libc::getpid() },
        },
    );
    second.send(
        RpcMessageKind::TerminalExited,
        &TerminalExitedEvent { run_token: replacement.run_token, exit_code: 0 },
    );

    let mut detach = Encoder::new();
    detach.encode_empty(RpcMessageKind::TerminalDetach, 0);
    first.socket.write_all(detach.output()).unwrap();
    second.socket.write_all(detach.output()).unwrap();
}

#[test]
fn stop_signals_the_entire_terminal_process_group() {
    let mut harness = TestHarness::new("terminal_stop_process_group");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
sh = "test-app parent & test-app grandchild & wait"
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let [mut parent, mut grandchild] = ctrl.accept_named(["parent", "grandchild"], Duration::from_secs(5));

    let result = harness.run_client(&["stop", "editor"]);
    assert!(result.success(), "stop failed: {}", result.stderr);
    assert!(parent.wait_disconnected(Duration::from_secs(5)), "parent process did not receive TERM");
    assert!(grandchild.wait_disconnected(Duration::from_secs(5)), "grandchild process did not receive TERM");
    let wrapper = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(wrapper.exit_code, 143, "PTY output:\n{}", wrapper.output);
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("killed"), "status did not retain killed cause: {}", status.stdout);
}

#[test]
fn daemon_disconnect_kills_the_child_and_restores_termios() {
    let mut harness = TestHarness::new("terminal_daemon_disconnect");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
sh = "stty -echo; exec test-app editor"
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    harness.stop_server();
    assert!(editor.wait_disconnected(Duration::from_secs(5)), "child process survived daemon disconnect");
    let wrapper = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_ne!(wrapper.exit_code, 0, "wrapper must fail when daemon authority disappears");
    assert!(wrapper.echo_enabled, "wrapper did not restore the terminal's echo setting");
}

#[test]
fn wrapper_disconnect_fails_the_job_and_releases_its_resource() {
    let mut harness = TestHarness::new("terminal_wrapper_disconnect");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
require = [{{ resource = "serial" }}]

[action.contender]
cmd = ["true"]
require = [{{ resource = "serial" }}]
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);
    let mut wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));
    wrapper.kill_wrapper();
    let _ = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert!(editor.wait_disconnected(Duration::from_secs(5)), "child survived wrapper disconnect");
    wait_for_exit(&mut subscriber, 0);

    let contender = harness.run_client(&["run", "contender"]);
    assert!(contender.success(), "resource remained pinned: {}\n{}", contender.stderr, harness.server_log());
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("spawn_failed"), "disconnect cause was not recorded: {}", status.stdout);
}

#[test]
fn sigterm_to_wrapper_kills_and_reaps_the_terminal_child_group() {
    let mut harness = TestHarness::new("terminal_wrapper_sigterm");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
sh = "test-app parent & test-app grandchild & wait"
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor"]);
    let [mut parent, mut grandchild] = ctrl.accept_named(["parent", "grandchild"], Duration::from_secs(5));

    wrapper.signal_wrapper(libc::SIGTERM);
    assert!(parent.wait_disconnected(Duration::from_secs(5)), "parent survived wrapper SIGTERM");
    assert!(grandchild.wait_disconnected(Duration::from_secs(5)), "grandchild survived wrapper SIGTERM");
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_ne!(result.exit_code, 0, "wrapper SIGTERM unexpectedly succeeded");
}

#[test]
fn oversized_terminal_launch_fails_without_hanging_the_wrapper() {
    let mut harness = TestHarness::new("terminal_oversized_launch");
    let oversized = "x".repeat(crate::rpc::DEFAULT_MAX_PAYLOAD + 1024);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
cmd = ["true"]
env.OVERSIZED = "{oversized}"
"#
    ));
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);

    let result = harness.run_pty_client(&["run", "editor"], Duration::from_secs(5));
    assert_ne!(result.exit_code, 0, "oversized terminal launch unexpectedly succeeded");
    assert!(result.output.contains("maximum is"), "unexpected PTY output: {}", result.output);
    let events = wait_for_exit(&mut subscriber, 0);
    assert!(
        events.iter().any(|event| matches!(event, RpcEvent::JobExited { cause: ExitCause::SpawnFailed, .. })),
        "oversized launch did not fail its job: {events:?}"
    );
}

#[test]
fn terminal_run_rejects_a_non_terminal_client_before_submission() {
    let mut harness = TestHarness::new("terminal_requires_tty");
    harness.write_config(
        r#"
[action.editor]
managed = "terminal"
sh = "touch should-not-run"
"#,
    );
    harness.spawn_server();

    let result = harness.run_client(&["run", "editor"]);
    assert!(!result.success());
    assert!(result.stderr.contains("stdin to be a terminal"), "unexpected diagnostic: {}", result.stderr);
    assert!(!harness.temp_dir.join("should-not-run").exists());
    let status = harness.run_client(&["status"]);
    assert!(status.stdout.contains("No active tasks"), "terminal job was submitted without a PTY: {}", status.stdout);
}

#[test]
fn sticky_wrapper_survives_spawn_failure_and_uses_reloaded_command() {
    let mut harness = TestHarness::new("terminal_sticky_spawn_failure");
    harness.write_config(
        r#"
[action.editor]
managed = "terminal"
cmd = ["devsm-command-that-does-not-exist"]
"#,
    );
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);
    let mut wrapper = harness.spawn_pty_client(&["run", "--sticky", "editor"]);
    wait_for_exit(&mut subscriber, 0);
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("spawn_failed"), "spawn failure was not recorded: {}", status.stdout);
    assert!(status.stdout.contains("127"), "spawn failure exit code was not recorded: {}", status.stdout);
    assert!(status.stdout.contains("idle wrapper attached"), "failed sticky wrapper was not idle: {}", status.stdout);

    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    let started = harness.run_client(&["start", "editor"]);
    assert!(started.success(), "start after reload failed: {}\n{}", started.stderr, harness.server_log());
    let mut editor = ctrl.accept(Duration::from_secs(5));
    editor.exit(0);
    wait_for_exit(&mut subscriber, 1);
    wrapper.send_ctrl_c();
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(result.exit_code, 0, "PTY output:\n{}", result.output);
}

#[test]
fn incompatible_reload_detaches_an_idle_sticky_wrapper() {
    let mut harness = TestHarness::new("terminal_idle_reload_detach");
    harness.write_config(
        r#"
[action.editor]
managed = "terminal"
cmd = ["true"]
"#,
    );
    harness.spawn_server();
    let mut subscriber = subscribe(&harness);
    let wrapper = harness.spawn_pty_client(&["run", "--sticky", "editor"]);
    wait_for_exit(&mut subscriber, 0);

    harness.write_config(
        r#"
[action.editor]
managed = true
cmd = ["true"]
"#,
    );
    let _ = harness.run_client(&["status", "editor"]);
    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_ne!(result.exit_code, 0, "incompatible idle wrapper remained attached");
    assert!(result.output.contains("no longer terminal-managed"), "PTY output:\n{}", result.output);
}

#[test]
fn incompatible_reload_detaches_sticky_wrapper_as_soon_as_active_run_exits() {
    let mut harness = TestHarness::new("terminal_active_reload_detach");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.editor]
managed = "terminal"
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "--sticky", "editor"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    harness.write_config(
        r#"
[action.editor]
managed = true
cmd = ["true"]
"#,
    );
    let active = harness.run_client(&["status", "editor"]);
    assert!(active.stdout.contains("running"), "active terminal generation was not retained: {}", active.stdout);
    editor.exit(0);

    let result = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_ne!(result.exit_code, 0, "incompatible wrapper remained attached after active exit");
    assert!(result.output.contains("no longer terminal-managed"), "PTY output:\n{}", result.output);
    let status = harness.run_client(&["status", "editor"]);
    assert!(!status.stdout.contains("idle wrapper attached"), "derived idle cache retained detached wrapper: {}", status.stdout);
}

#[test]
fn terminal_cli_rejects_unsupported_routes_and_sticky_combinations() {
    let mut harness = TestHarness::new("terminal_cli_validation");
    harness.write_config(
        r#"
[action.editor]
managed = "terminal"
cmd = ["true"]

[action.build]
cmd = ["true"]

[group]
combo = ["build"]
terminal_group = ["editor"]
"#,
    );
    harness.spawn_server();

    for (args, needle) in [
        (&["run", "--sticky", "group.combo"][..], "cannot be run with --sticky"),
        (&["run", "--sticky", "build"][..], "only supported for tasks"),
        (&["run", "--derive-cache-key", "editor"][..], "not supported for terminal"),
        (&["run", "--as-test", "editor"][..], "cannot be run as tests"),
        (&["exec", "editor"][..], "devsm run"),
        (&["run", "group.terminal_group"][..], "contains terminal task"),
    ] {
        let result = harness.run_client(args);
        assert!(!result.success(), "{:?} unexpectedly succeeded", args);
        assert!(
            result.stderr.contains(needle),
            "{:?}: expected {needle:?}, got {}; server log:\n{}",
            args,
            result.stderr,
            harness.server_log()
        );
    }
}

#[test]
fn terminal_start_and_restart_without_a_wrapper_are_actionable() {
    let mut harness = TestHarness::new("terminal_control_without_wrapper");
    harness.write_config(
        r#"
[service.editor]
managed = "terminal"
cmd = ["true"]
"#,
    );
    harness.spawn_server();

    let start = harness.run_client(&["start", "editor"]);
    assert!(!start.success());
    assert!(start.stderr.contains("devsm run --sticky editor"), "start diagnostic: {}", start.stderr);
    let restart = harness.run_client(&["restart", "editor"]);
    assert!(!restart.success());
    assert!(restart.stderr.contains("devsm run editor"), "restart diagnostic: {}", restart.stderr);
}

#[test]
fn cached_terminal_action_satisfies_a_later_requirement_without_a_wrapper() {
    let mut harness = TestHarness::new("terminal_cached_requirement");
    harness.write_config(
        r#"
[action.prepare]
managed = "terminal"
cmd = ["true"]
cache = {}

[action.consumer]
sh = "touch consumer-ran"
require = ["prepare"]
"#,
    );
    harness.spawn_server();
    let prepared = harness.run_pty_client(&["run", "prepare"], Duration::from_secs(5));
    assert_eq!(prepared.exit_code, 0, "PTY output:\n{}", prepared.output);

    let consumer = harness.run_client(&["run", "consumer"]);
    assert!(consumer.success(), "cached requirement was rejected: {}\n{}", consumer.stderr, harness.server_log());
    assert!(harness.temp_dir.join("consumer-ran").exists());
}

#[test]
fn successful_terminal_action_is_eligible_for_persistent_cache() {
    let mut harness = TestHarness::new("terminal_persistent_cache");
    let database = harness.temp_dir.join("devsm.db");
    harness.write_config(
        r#"
[action.prepare]
managed = "terminal"
sh = "touch prepared"
cache.persistent = true

[action.consumer]
sh = "touch consumer-ran"
require = ["prepare"]
"#,
    );
    harness.spawn_server_with_db(&database);
    let prepared = harness.run_pty_client(&["run", "prepare"], Duration::from_secs(5));
    assert_eq!(prepared.exit_code, 0, "PTY output:\n{}", prepared.output);

    harness.stop_server();
    harness.spawn_server_with_db(&database);
    let consumer = harness.run_client(&["run", "consumer"]);
    assert!(consumer.success(), "persistent terminal cache was not reused: {}", consumer.stderr);
    assert!(harness.temp_dir.join("consumer-ran").exists());
}

#[test]
fn conflicting_terminal_requirement_keeps_the_active_variant_and_suggests_the_exact_one() {
    let mut harness = TestHarness::new("terminal_conflicting_requirement");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[service.editor]
managed = "terminal"
profiles = ["dev", "prod"]
cmd = ["test-app", "editor"]
env.TEST_APP_SOCKET = "{}"

[action.consumer]
cmd = ["true"]
require = [{{ name = "editor:prod", vars = {{ theme = "dark mode" }} }}]
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "editor:dev"]);
    let mut editor = ctrl.accept(Duration::from_secs(5));

    let consumer = harness.run_client(&["run", "consumer"]);
    assert!(!consumer.success(), "conflicting requirement unexpectedly ran");
    let message = format!("{}{}", consumer.stdout, consumer.stderr);
    assert!(message.contains("devsm run --theme='\"dark mode\"' editor:prod"), "diagnostic:\n{message}");
    let status = harness.run_client(&["status", "editor"]);
    assert!(status.stdout.contains("running"), "active terminal variant was terminated: {}", status.stdout);

    let stopped = harness.run_client(&["stop", "editor"]);
    assert!(stopped.success(), "stop failed: {}", stopped.stderr);
    assert!(editor.wait_disconnected(Duration::from_secs(5)));
    let _ = wrapper.wait(Duration::from_secs(5), || harness.server_log());
}

#[test]
fn failed_running_terminal_dependency_has_a_restart_hint_without_a_log_tail() {
    let mut harness = TestHarness::new("terminal_dependency_failure_hint");
    let ctrl = TestAppServer::new(&harness.sock_dir);
    harness.write_config(&format!(
        r#"
[action.prepare]
managed = "terminal"
cmd = ["test-app", "prepare"]
env.TEST_APP_SOCKET = "{}"

[action.consumer]
managed = false
cmd = ["true"]
require = ["prepare"]
"#,
        ctrl.path.display()
    ));
    harness.spawn_server();
    let wrapper = harness.spawn_pty_client(&["run", "prepare"]);
    let mut prepare = ctrl.accept(Duration::from_secs(5));

    let consumer = std::thread::scope(|scope| {
        let run = scope.spawn(|| harness.run_client(&["exec", "consumer"]));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let status = harness.run_client(&["status", "consumer"]);
            if status.stdout.contains("scheduled") || status.stdout.contains("waiting") {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "consumer was not scheduled: {}", status.stdout);
            std::thread::sleep(Duration::from_millis(25));
        }
        harness.write_config(&format!(
            r#"
[action.prepare]
managed = false
cmd = ["test-app", "prepare"]
env.TEST_APP_SOCKET = "{}"

[action.consumer]
managed = false
cmd = ["true"]
require = ["prepare"]
"#,
            ctrl.path.display()
        ));
        let reloaded = harness.run_client(&["status", "prepare"]);
        assert!(reloaded.success(), "reload failed: {}", reloaded.stderr);
        prepare.exit(6);
        run.join().unwrap()
    });
    assert!(!consumer.success(), "consumer ran after failed terminal dependency");
    assert!(consumer.stderr.contains("devsm prepare"), "missing terminal restart hint: {}", consumer.stderr);
    assert!(
        !consumer.stderr.contains("output is attached to its terminal"),
        "terminal lifecycle placeholder was incorrectly used as a dependency log tail: {}",
        consumer.stderr
    );
    let wrapper = wrapper.wait(Duration::from_secs(5), || harness.server_log());
    assert_eq!(wrapper.exit_code, 6, "PTY output:\n{}", wrapper.output);
}
