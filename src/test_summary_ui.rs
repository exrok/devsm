//! Test run forwarder for the `test` command.
//!
//! Monitors and displays the status of test jobs during a test run.
//! Shows progress as tests execute and prints a summary when complete.

use std::{
    collections::VecDeque,
    io::{IsTerminal, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    sync::Arc,
    time::Instant,
};

use extui::{
    Color, TerminalFlags, splat,
    vt::{self, BufferWrite},
};

use crate::config::Command;
use crate::log_storage::LogGroup;
use crate::rpc::{Encoder, RpcMessageKind};
use crate::{
    process_manager::ClientChannel,
    workspace::{BaseTask, BaseTaskIndex, Job, JobIndex, JobStatus, TestJob, TestJobStatus, TestRun, Workspace},
};

fn format_command(cmd: &Command) -> String {
    match cmd {
        Command::Cmd(args) => args.join(" "),
        Command::Sh(script) => format!("sh -c '{}'", script),
    }
}

fn relative_path(pwd: &str, base_path: &Path) -> String {
    Path::new(pwd)
        .strip_prefix(base_path)
        .map(|p| {
            let s = p.display().to_string();
            if s.is_empty() { ".".to_string() } else { format!("./{}", s) }
        })
        .unwrap_or_else(|_| pwd.to_string())
}

fn format_job_details(job: &Job, job_index: usize, base_path: &Path) -> String {
    let config = job.task.config();
    let rel_path = relative_path(config.pwd, base_path);
    let cmd = format_command(&config.command);
    format!("# {:04} @ {} \n     {}", job_index, rel_path, cmd)
}

fn send_termination(encoder: &mut Encoder, socket: &mut Option<UnixStream>) {
    let Some(socket) = socket.as_mut() else { return };
    encoder.encode_empty(RpcMessageKind::TerminateAck, 0);
    let _ = socket.write_all(encoder.output());
    encoder.clear();
}

const MAX_RECENT_LOGS: usize = 3;
const MAX_SUMMARY_LOGS: usize = 12;

struct TestDisplay {
    #[expect(unused, reason = "May be useful for future features")]
    base_task_index: BaseTaskIndex,
    #[expect(unused, reason = "May be useful for future features")]
    job_index: JobIndex,
    log_group: LogGroup,
    status: TestJobStatus,
    name: String,
    command: String,
    started_at: Option<Instant>,
    finished_at: Option<Instant>,
    recent_logs: VecDeque<String>,
}

struct TuiState {
    tests: Vec<TestDisplay>,
    started_at: Instant,
    width: u16,
    height: u16,
}

/// Monitors test jobs and displays their progress and results.
///
/// # Errors
///
/// Returns an error if polling fails.
pub fn run(
    stdin: OwnedFd,
    stdout: OwnedFd,
    socket: Option<UnixStream>,
    workspace: &Workspace,
    test_run: TestRun,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let is_tty = stdout.is_terminal();
    if is_tty {
        run_tui_mode(stdin, stdout, socket, workspace, test_run, channel)
    } else {
        run_simple_mode(stdin, stdout, socket, workspace, test_run, channel)
    }
}

fn run_simple_mode(
    stdin: OwnedFd,
    stdout: OwnedFd,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    mut test_run: TestRun,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
    std::mem::forget(stdout);

    let mut encoder = Encoder::new();

    let _ = writeln!(file, "Running {} test(s)...\n", test_run.test_jobs.len());

    loop {
        if channel.is_terminated() {
            send_termination(&mut encoder, &mut socket);
            break;
        }

        let all_done = update_test_statuses(&mut file, workspace, &mut test_run)?;

        if all_done {
            let state = workspace.state.read().unwrap();
            print_summary(&mut file, &test_run, &state.base_tasks);
            drop(state);
            send_termination(&mut encoder, &mut socket);
            break;
        }

        match extui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), None) {
            Ok(extui::event::Polled::ReadReady) => {
                let mut buf = [0u8; 64];
                let n = unsafe { libc::read(stdin.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
                if n == 0 {
                    let _ = writeln!(file, "\nDetached. Tests will continue running in background.");
                    send_termination(&mut encoder, &mut socket);
                    break;
                }
            }
            Ok(extui::event::Polled::Woken) | Ok(extui::event::Polled::TimedOut) | Err(_) => {}
        }
    }

    Ok(())
}

enum ExitReason {
    Completed,
    Cancelled,
    Detached,
    Terminated,
}

fn run_tui_mode(
    stdin: OwnedFd,
    stdout: OwnedFd,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    test_run: TestRun,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mode = TerminalFlags::RAW_MODE | TerminalFlags::HIDE_CURSOR | TerminalFlags::ALT_SCREEN;
    let mut terminal = extui::Terminal::new(stdout.as_raw_fd(), mode)?;

    let (width, height) = terminal.size()?;
    let mut tui_state = init_tui_state(&test_run, workspace, width, height);

    let mut encoder = Encoder::new();
    let mut buf = Vec::with_capacity(4096);

    render_tui(&mut buf, &tui_state);
    terminal.write_all(&buf)?;

    let exit_reason = loop {
        if channel.is_terminated() {
            break ExitReason::Terminated;
        }

        let (all_done, changed) = update_tui_state(&mut tui_state, workspace, &test_run);

        if changed {
            buf.clear();
            render_tui(&mut buf, &tui_state);
            terminal.write_all(&buf)?;
        }

        if all_done {
            break ExitReason::Completed;
        }

        match extui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), None) {
            Ok(extui::event::Polled::ReadReady) => {
                let mut input_buf = [0u8; 64];
                let n = unsafe { libc::read(stdin.as_raw_fd(), input_buf.as_mut_ptr() as *mut _, input_buf.len()) };
                if n == 0 {
                    break ExitReason::Detached;
                }
                if n > 0 && input_buf[..n as usize].contains(&0x03) {
                    break ExitReason::Cancelled;
                }
            }
            Ok(extui::event::Polled::Woken) | Ok(extui::event::Polled::TimedOut) | Err(_) => {}
        }

        let (new_width, new_height) = terminal.size()?;
        if new_width != tui_state.width || new_height != tui_state.height {
            tui_state.width = new_width;
            tui_state.height = new_height;
            buf.clear();
            buf.extend_from_slice(vt::MOVE_CURSOR_TO_ORIGIN);
            buf.extend_from_slice(vt::CLEAR_BELOW);
            render_tui(&mut buf, &tui_state);
            terminal.write_all(&buf)?;
        }
    };

    drop(terminal);

    buf.clear();
    match exit_reason {
        ExitReason::Completed => {
            write_color_summary(&mut buf, &tui_state, workspace);
        }
        ExitReason::Cancelled => {
            write_cancelled_summary(&mut buf, &tui_state);
        }
        ExitReason::Detached => {
            let _ = writeln!(buf, "\nDetached. Tests will continue running in background.");
        }
        ExitReason::Terminated => {}
    }

    let _ = unsafe { libc::write(stdout.as_raw_fd(), buf.as_ptr() as *const _, buf.len()) };

    send_termination(&mut encoder, &mut socket);
    Ok(())
}

fn init_tui_state(test_run: &TestRun, workspace: &Workspace, width: u16, height: u16) -> TuiState {
    let state = workspace.state.read().unwrap();
    let tests: Vec<TestDisplay> = test_run
        .test_jobs
        .iter()
        .map(|tj| {
            let job = &state.jobs[tj.job_index.idx()];
            let command = format_command(&job.task.config().command);
            TestDisplay {
                base_task_index: tj.base_task_index,
                job_index: tj.job_index,
                log_group: job.log_group,
                status: tj.status,
                name: format_test_name(tj, &state.base_tasks),
                command,
                started_at: None,
                finished_at: None,
                recent_logs: VecDeque::new(),
            }
        })
        .collect();

    TuiState { tests, started_at: test_run.started_at, width, height }
}

fn update_tui_state(tui_state: &mut TuiState, workspace: &Workspace, test_run: &TestRun) -> (bool, bool) {
    let ws_state = workspace.state.read().unwrap();
    let logs = workspace.logs.read().unwrap();
    let mut all_done = true;
    let mut changed = false;

    for (i, test_job) in test_run.test_jobs.iter().enumerate() {
        let display = &mut tui_state.tests[i];

        if matches!(display.status, TestJobStatus::Passed | TestJobStatus::Failed(_)) {
            continue;
        }

        let job = &ws_state.jobs[test_job.job_index.idx()];
        let new_status = match &job.process_status {
            JobStatus::Scheduled { .. } | JobStatus::Starting => {
                all_done = false;
                TestJobStatus::Pending
            }
            JobStatus::Running { .. } => {
                all_done = false;
                TestJobStatus::Running
            }
            JobStatus::Exited { status, .. } => {
                if *status == 0 {
                    TestJobStatus::Passed
                } else {
                    TestJobStatus::Failed(*status as i32)
                }
            }
            JobStatus::Cancelled => TestJobStatus::Failed(-1),
        };

        if new_status != display.status {
            if new_status == TestJobStatus::Running && display.started_at.is_none() {
                display.started_at = Some(Instant::now());
            }
            if matches!(new_status, TestJobStatus::Passed | TestJobStatus::Failed(_)) {
                display.finished_at = Some(Instant::now());
            }
            display.status = new_status;
            changed = true;
        }

        let new_logs = collect_recent_logs(&logs, display.log_group, MAX_RECENT_LOGS);
        if new_logs != display.recent_logs.make_contiguous() {
            display.recent_logs = new_logs.into_iter().collect();
            changed = true;
        }
    }

    (all_done, changed)
}

fn collect_recent_logs(logs: &crate::log_storage::Logs, log_group: LogGroup, max_lines: usize) -> Vec<String> {
    let (a, b) = logs.slices();
    let mut recent = VecDeque::with_capacity(max_lines);

    for slice in [a, b] {
        for entry in slice {
            if entry.log_group != log_group {
                continue;
            }
            let text = unsafe { entry.text(logs) };
            if recent.len() >= max_lines {
                recent.pop_front();
            }
            recent.push_back(text.to_string());
        }
    }

    recent.into_iter().collect()
}

fn status_color(status: TestJobStatus) -> Color {
    match status {
        TestJobStatus::Pending => Color::Grey[17],
        TestJobStatus::Running => Color::DarkOliveGreen,
        TestJobStatus::Passed => Color::SpringGreen,
        TestJobStatus::Failed(_) => Color::NeonRed,
    }
}

fn render_tui(buf: &mut Vec<u8>, state: &TuiState) {
    vt::MoveCursor(0, 0).write_to_buffer(buf);

    let available_lines = state.height.saturating_sub(2) as usize;

    let running: Vec<_> = state.tests.iter().filter(|t| t.status == TestJobStatus::Running).collect();
    let failed: Vec<_> = state.tests.iter().filter(|t| matches!(t.status, TestJobStatus::Failed(_))).collect();
    let pending: Vec<_> = state.tests.iter().filter(|t| t.status == TestJobStatus::Pending).collect();
    let passed: Vec<_> = state.tests.iter().filter(|t| t.status == TestJobStatus::Passed).collect();

    let lines_per_test_with_logs = 1 + MAX_RECENT_LOGS;
    let tests_with_logs = running.len() + failed.len() + pending.len();
    let total_lines_needed = tests_with_logs * lines_per_test_with_logs + passed.len();
    let show_logs = total_lines_needed <= available_lines;

    let mut row: u16 = 0;

    for test in running.iter().chain(failed.iter()).chain(pending.iter()).chain(passed.iter()) {
        if row as usize >= available_lines {
            break;
        }

        render_test_header(buf, test, state.width, row);
        row += 1;

        let dominated = test.status != TestJobStatus::Passed;
        if show_logs && dominated && !test.recent_logs.is_empty() {
            for log_line in &test.recent_logs {
                if row as usize >= available_lines {
                    break;
                }
                render_log_line(buf, log_line, state.width, row);
                row += 1;
            }
        }
    }

    while row < state.height.saturating_sub(1) {
        vt::MoveCursor(0, row).write_to_buffer(buf);
        buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
        row += 1;
    }

    render_status_line(buf, state, state.height.saturating_sub(1));
}

fn render_test_header(buf: &mut Vec<u8>, test: &TestDisplay, _width: u16, row: u16) {
    vt::MoveCursor(0, row).write_to_buffer(buf);
    buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);

    let color = status_color(test.status);
    let status_str = match test.status {
        TestJobStatus::Pending => "WAIT",
        TestJobStatus::Running => "RUN ",
        TestJobStatus::Passed => "PASS",
        TestJobStatus::Failed(_) => "FAIL",
    };

    color.with_fg(Color::Black).write_to_buffer(buf);
    write!(buf, " {} ", status_str).ok();
    buf.extend_from_slice(vt::CLEAR_STYLE);

    write!(buf, " {}", test.name).ok();

    if let Some(started) = test.started_at {
        let elapsed = test.finished_at.unwrap_or_else(Instant::now).duration_since(started);
        Color::Grey[14].as_fg().write_to_buffer(buf);
        write!(buf, " ({:.1}s)", elapsed.as_secs_f64()).ok();
        buf.extend_from_slice(vt::CLEAR_STYLE);
    }

    if let TestJobStatus::Failed(code) = test.status {
        Color::Grey[14].as_fg().write_to_buffer(buf);
        write!(buf, " exit {}", code).ok();
        buf.extend_from_slice(vt::CLEAR_STYLE);
    }

    Color::Grey[14].as_fg().write_to_buffer(buf);
    write!(buf, " $ {}", test.command).ok();
    buf.extend_from_slice(vt::CLEAR_STYLE);
}

fn render_log_line(buf: &mut Vec<u8>, line: &str, _width: u16, row: u16) {
    vt::MoveCursor(0, row).write_to_buffer(buf);
    buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);
    write!(buf, "    {}", line).ok();
    buf.extend_from_slice(vt::CLEAR_STYLE);
}

fn render_status_line(buf: &mut Vec<u8>, state: &TuiState, row: u16) {
    vt::MoveCursor(0, row).write_to_buffer(buf);
    buf.extend_from_slice(vt::CLEAR_LINE_TO_RIGHT);

    let passed = state.tests.iter().filter(|t| t.status == TestJobStatus::Passed).count();
    let failed = state.tests.iter().filter(|t| matches!(t.status, TestJobStatus::Failed(_))).count();
    let running = state.tests.iter().filter(|t| t.status == TestJobStatus::Running).count();
    let pending = state.tests.iter().filter(|t| t.status == TestJobStatus::Pending).count();
    let total = state.tests.len();

    Color::Grey[4].with_fg(Color::Grey[25]).write_to_buffer(buf);
    write!(buf, " Tests: {}/{} ", passed + failed, total).ok();

    if running > 0 {
        Color::DarkOliveGreen.with_fg(Color::Black).write_to_buffer(buf);
        write!(buf, " {} running ", running).ok();
    }
    if pending > 0 {
        Color::Grey[17].with_fg(Color::Black).write_to_buffer(buf);
        write!(buf, " {} pending ", pending).ok();
    }
    if passed > 0 {
        Color::SpringGreen.with_fg(Color::Black).write_to_buffer(buf);
        write!(buf, " {} passed ", passed).ok();
    }
    if failed > 0 {
        Color::NeonRed.with_fg(Color::Black).write_to_buffer(buf);
        write!(buf, " {} failed ", failed).ok();
    }

    buf.extend_from_slice(vt::CLEAR_STYLE);
}

fn write_color_summary(buf: &mut Vec<u8>, state: &TuiState, workspace: &Workspace) {
    let logs = workspace.logs.read().unwrap();
    let elapsed = state.started_at.elapsed();

    let passed = state.tests.iter().filter(|t| t.status == TestJobStatus::Passed).count();
    let failed: Vec<_> = state.tests.iter().filter(|t| matches!(t.status, TestJobStatus::Failed(_))).collect();

    splat!(buf, "\n", "Tests: ", Color(2).as_fg(), passed, " passed", vt::CLEAR_STYLE);
    if !failed.is_empty() {
        splat!(buf, ", ", Color(1).as_fg(), failed.len(), " failed", vt::CLEAR_STYLE);
    }
    write!(buf, " ({:.1}s)\n", elapsed.as_secs_f64()).ok();

    for test in &failed {
        splat!(buf, "\n", Color(1).as_fg(), "FAIL ", test.name, vt::CLEAR_STYLE, "\n");
        splat!(buf, "  Command: ", test.command, "\n");
        if let TestJobStatus::Failed(code) = test.status {
            splat!(buf, "  Exit code: ", code, "\n");
        }

        let recent = collect_recent_logs(&logs, test.log_group, MAX_SUMMARY_LOGS);
        if !recent.is_empty() {
            splat!(buf, "  Last ", recent.len(), " log lines:\n");
            for line in &recent {
                splat!(buf, "", line, "\n");
            }
        }
    }
}

fn write_cancelled_summary(buf: &mut Vec<u8>, state: &TuiState) {
    let elapsed = state.started_at.elapsed();

    let passed = state.tests.iter().filter(|t| t.status == TestJobStatus::Passed).count();
    let failed = state.tests.iter().filter(|t| matches!(t.status, TestJobStatus::Failed(_))).count();
    let running = state.tests.iter().filter(|t| t.status == TestJobStatus::Running).count();
    let pending = state.tests.iter().filter(|t| t.status == TestJobStatus::Pending).count();

    splat!(buf, b'\n', Color(3).as_fg(), "Tests cancelled.", vt::CLEAR_STYLE);
    write!(buf, " ({:.1}s)\n", elapsed.as_secs_f64()).ok();
    buf.extend_from_slice(b"  ");
    if passed > 0 {
        splat!(buf, Color(2).as_fg(), passed, " passed", vt::CLEAR_STYLE);
    }
    if failed > 0 {
        if passed > 0 {
            buf.extend_from_slice(b", ");
        }
        splat!(buf, Color(1).as_fg(), failed, " failed", vt::CLEAR_STYLE);
    }
    if running > 0 {
        if passed > 0 || failed > 0 {
            buf.extend_from_slice(b", ");
        }
        splat!(buf, running, " cancelled while running");
    }
    if pending > 0 {
        if passed > 0 || failed > 0 || running > 0 {
            buf.extend_from_slice(b", ");
        }
        splat!(buf, pending, " not started");
    }
    buf.push(b'\n');
}

fn update_test_statuses(
    file: &mut std::fs::File,
    workspace: &Workspace,
    test_run: &mut TestRun,
) -> anyhow::Result<bool> {
    let state = workspace.state.read().unwrap();
    let mut all_done = true;

    for test_job in &mut test_run.test_jobs {
        if matches!(test_job.status, TestJobStatus::Passed | TestJobStatus::Failed(_)) {
            continue;
        }

        let job = &state.jobs[test_job.job_index.idx()];
        let new_status = match &job.process_status {
            JobStatus::Scheduled { .. } | JobStatus::Starting => {
                all_done = false;
                TestJobStatus::Pending
            }
            JobStatus::Running { .. } => {
                all_done = false;
                TestJobStatus::Running
            }
            JobStatus::Exited { status, .. } => {
                if *status == 0 {
                    TestJobStatus::Passed
                } else {
                    TestJobStatus::Failed(*status as i32)
                }
            }
            JobStatus::Cancelled => TestJobStatus::Failed(-1),
        };

        if new_status != test_job.status {
            test_job.status = new_status;

            let display_name = format_test_name(test_job, &state.base_tasks);
            let base_path = state.config.current.base_path;
            let details = format_job_details(job, test_job.job_index.idx(), base_path);
            match new_status {
                TestJobStatus::Passed => {
                    let _ = writeln!(file, "PASS {} {}", display_name, details);
                }
                TestJobStatus::Failed(code) => {
                    let _ = writeln!(file, "FAIL {} {} (exit code {})", display_name, details, code);
                }
                _ => {}
            }
        }
    }

    Ok(all_done)
}

fn format_test_name(test_job: &TestJob, base_tasks: &[BaseTask]) -> String {
    let base_task = &base_tasks[test_job.base_task_index.idx()];
    let Some(test_info) = &base_task.test_info else {
        return base_task.name.to_string();
    };
    let is_single = !base_tasks.iter().any(|bt| {
        bt.test_info
            .as_ref()
            .is_some_and(|ti| ti.base_name == test_info.base_name && ti.variant_index != test_info.variant_index)
    });
    if is_single {
        test_info.base_name.to_string()
    } else {
        format!("{}[{}]", test_info.base_name, test_info.variant_index)
    }
}

fn print_summary(file: &mut std::fs::File, test_run: &TestRun, base_tasks: &[BaseTask]) {
    let elapsed = test_run.started_at.elapsed();
    let passed = test_run.test_jobs.iter().filter(|j| matches!(j.status, TestJobStatus::Passed)).count();
    let failed: Vec<&TestJob> =
        test_run.test_jobs.iter().filter(|j| matches!(j.status, TestJobStatus::Failed(_))).collect();

    let _ = writeln!(file);
    let _ = writeln!(file, "Tests: {} passed, {} failed ({:.1}s)", passed, failed.len(), elapsed.as_secs_f64());

    if !failed.is_empty() {
        let _ = writeln!(file, "\nFailed:");
        for test_job in &failed {
            let name = format_test_name(test_job, base_tasks);
            if let TestJobStatus::Failed(code) = test_job.status {
                let _ = writeln!(file, "  {} (exit code {})", name, code);
            }
        }
    }
}
