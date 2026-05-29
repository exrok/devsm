//! Tests for error reporting when the daemon dies unexpectedly.

use crate::harness;

use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use harness::{TestHarness, cargo_bin_path};

/// Spawns a client (detached from any controlling terminal) that attaches to the
/// test daemon. `extra_env` lets a test inject e.g. the crash-report path.
fn spawn_detached_client(
    harness: &TestHarness,
    args: &[&str],
    extra_env: &[(&str, &std::path::Path)],
) -> std::process::Child {
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
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    // Detach from the controlling terminal so the crash-time terminal restore
    // targets a fresh session's /dev/tty (a no-op) instead of the terminal
    // running the test suite.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().expect("Failed to spawn client")
}

/// When the daemon dies abruptly (here: SIGKILL) while a client is attached, the
/// client must notice, exit non-zero, and print a diagnostic pointing at the
/// crash report and the issue tracker — rather than silently leaving the
/// terminal in raw mode.
#[test]
fn unexpected_daemon_death_reports_and_exits_nonzero() {
    let mut harness = TestHarness::new("crash_disconnect");
    let marker = harness.temp_dir.join("started.marker");
    let crash_path = harness.temp_dir.join("crash.log");

    harness.write_config(&format!(
        "[action.sleeper]\nsh = \"echo started > {marker}; while true; do sleep 0.1; done\"\n",
        marker = marker.display()
    ));

    harness.spawn_server();
    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let server_pid = harness.server.as_ref().expect("server running").id() as i32;

    let mut client = spawn_detached_client(&harness, &["run", "sleeper"], &[("DEVSM_CRASH_REPORT", &crash_path)]);

    assert!(
        harness.wait_for_file(&marker, Duration::from_secs(5)),
        "client never attached / task never started; server log:\n{}",
        harness.server_log()
    );

    unsafe {
        libc::kill(server_pid, libc::SIGKILL);
    }

    let status = client.wait().expect("Failed to wait for client");
    let mut stderr = String::new();
    if let Some(mut err) = client.stderr.take() {
        err.read_to_string(&mut stderr).ok();
    }

    assert!(!status.success(), "client should exit non-zero on unexpected daemon death; stderr:\n{stderr}");
    assert!(stderr.contains("unreachable"), "missing daemon-unreachable diagnostic; stderr was:\n{stderr}");
    assert!(stderr.contains("github.com/exrok/devsm"), "missing issue-reporting link; stderr was:\n{stderr}");
}

/// When the daemon panics, it must write a plain-text crash report containing the
/// panic details and the recent (decoded, ANSI-free) self-logs, so the user can
/// review and prune it before attaching it to a bug report.
#[test]
fn daemon_panic_writes_plain_text_crash_report() {
    let mut harness = TestHarness::new("crash_report_file");
    let crash_path = harness.temp_dir.join("crash.log");

    harness.write_config("[action.noop]\ncmd = [\"true\"]\n");

    // Spawn the daemon with the crash-report path and panic injection. Note we
    // deliberately do NOT set DEVSM_LOG_STDOUT, so the in-memory self-log ring
    // buffer is active and its decoded contents land in the report.
    let log_file = fs::File::create(&harness.server_log_path).expect("create server log");
    let log_err = log_file.try_clone().expect("clone server log");
    let server = Command::new(cargo_bin_path())
        .args(["self", "server"])
        .current_dir(&harness.temp_dir)
        .env("DEVSM_SOCKET", &harness.socket_path)
        .env("DEVSM_DB", "/dev/null")
        .env("DEVSM_CRASH_REPORT", &crash_path)
        .env("DEVSM_TEST_PANIC_ON_ATTACH", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("Failed to spawn server");
    harness.server = Some(server);

    assert!(harness.wait_for_socket(Duration::from_secs(5)), "Server socket not created");

    let client = spawn_detached_client(&harness, &["run", "noop"], &[("DEVSM_CRASH_REPORT", &crash_path)]);
    let output = client.wait_with_output().expect("Failed to wait for client");
    assert!(!output.status.success(), "client should exit non-zero when the daemon panics");

    assert!(
        harness.wait_for_file(&crash_path, Duration::from_secs(5)),
        "no crash report written; server log:\n{}",
        harness.server_log()
    );

    let report = fs::read_to_string(&crash_path).expect("crash report must be valid UTF-8 text");
    assert!(report.contains("devsm daemon crash report"), "report:\n{report}");
    assert!(report.contains("injected test panic on client attach"), "report:\n{report}");
    assert!(report.contains("--- recent daemon logs ---"), "report:\n{report}");
    assert!(report.contains("Daemon Starting"), "self-logs not captured in report:\n{report}");
    assert!(!report.contains('\x1b'), "crash report must be ANSI-free:\n{report}");
}
