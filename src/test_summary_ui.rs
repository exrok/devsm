//! Test run forwarder for the `test` command.
//!
//! Monitors and displays the status of test jobs during a test run.
//! Shows progress as tests execute and prints a summary when complete.

use std::{
    collections::VecDeque,
    fs::File,
    io::{IsTerminal, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::Arc,
    time::{Duration, Instant},
};

use extui::{
    AnsiColor, DoubleBuffer, Rect, Rgb, Style, TerminalFlags, splat, vt,
    vt::{BufferWrite, Modifier, MoveCursorUp},
};

use crate::config::Command;
use crate::line_width::strip_ansi_to_buffer_preserve_case;
use crate::log_storage::LogGroup;
use crate::rpc::{Encoder, RpcMessageKind};
use crate::workspace::ExitCause;
use crate::{
    event_loop::ClientChannel,
    workspace::{BaseTask, BaseTaskIndex, JobIndex, JobStatus, TestJob, TestJobStatus, TestRun, Workspace},
};

fn format_command(cmd: &Command) -> String {
    match cmd {
        Command::Cmd(args) => args.join(" "),
        Command::Sh { script, .. } => format!("sh -c '{}'", script.trim()),
    }
}

fn format_duration(secs: f64) -> String {
    if secs >= 86400.0 {
        format!("{}d", secs / 86400.0)
    } else if secs >= 3600.0 {
        format!("{}h", secs / 3600.0)
    } else if secs >= 60.0 {
        format!("{}m", secs / 60.0)
    } else {
        format!("{}s", secs)
    }
}

fn skipped_via_cache_text(count: usize) -> String {
    if count == 1 { "1 test skipped via cache".to_string() } else { format!("{count} tests skipped via cache") }
}

fn is_terminal_status(status: TestJobStatus) -> bool {
    matches!(status, TestJobStatus::Passed | TestJobStatus::Cached | TestJobStatus::Failed(_))
}

fn send_termination(encoder: &mut Encoder, socket: &mut Option<UnixStream>) {
    let Some(socket) = socket.as_mut() else { return };
    encoder.encode_empty(RpcMessageKind::TerminateAck, 0);
    let _ = socket.write_all(encoder.output());
    encoder.clear();
}

const MAX_RECENT_LOGS: usize = 3;
const MAX_SUMMARY_LOGS: usize = 24;

struct TestDisplay {
    #[expect(unused, reason = "May be useful for future features")]
    base_task_index: BaseTaskIndex,
    #[expect(unused, reason = "May be useful for future features")]
    job_index: Option<JobIndex>,
    log_group: Option<LogGroup>,
    status: TestJobStatus,
    name: String,
    command: String,
    started_at: Option<Instant>,
    finished_at: Option<Instant>,
    recent_logs: VecDeque<String>,
    timeout_info: Option<f64>,
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
    stdin: File,
    stdout: File,
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
    _stdin: File,
    mut stdout: File,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    mut test_run: TestRun,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mut encoder = Encoder::new();
    let strip_ansi = std::env::var("FORCE_COLOR").is_err();
    let mut buf = Vec::with_capacity(4096);

    writeln!(buf, "Running {} test(s)...\n", test_run.test_jobs.len()).ok();
    stdout.write_all(&buf)?;
    buf.clear();

    loop {
        if channel.is_terminated() {
            send_termination(&mut encoder, &mut socket);
            break;
        }

        let all_done = update_test_statuses(&mut buf, workspace, &mut test_run, strip_ansi)?;
        if !buf.is_empty() {
            stdout.write_all(&buf)?;
            buf.clear();
        }

        if all_done {
            let state = workspace.state.read().unwrap();
            print_summary(&mut buf, &test_run, &state.base_tasks);
            stdout.write_all(&buf)?;
            drop(state);
            send_termination(&mut encoder, &mut socket);
            break;
        }

        let _ = channel.waker.wait();
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
    stdin: File,
    stdout: File,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    test_run: TestRun,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mode = TerminalFlags::RAW_MODE | TerminalFlags::HIDE_CURSOR;
    let mut terminal = extui::Terminal::new(stdout.as_raw_fd(), mode)?;

    let (width, height) = terminal.size()?;
    let mut tui_state = init_tui_state(&test_run, workspace, width, height);

    let mut encoder = Encoder::new();
    let mut db = DoubleBuffer::new(width, 1);
    let mut prev_inline_height: u16 = 0;

    prev_inline_height = paint_frame(&mut db, &mut terminal, &tui_state, prev_inline_height, false)?;

    let exit_reason = loop {
        if channel.is_terminated() {
            break ExitReason::Terminated;
        }

        let (all_done, changed) = update_tui_state(&mut tui_state, workspace, &test_run);
        let has_running = tui_state.tests.iter().any(|t| t.status == TestJobStatus::Running);

        let (new_width, new_height) = terminal.size()?;
        let old_width = tui_state.width;
        let resized = new_width != tui_state.width || new_height != tui_state.height;
        tui_state.width = new_width;
        tui_state.height = new_height;

        if resized {
            cleanup_inline_region(&mut terminal, prev_inline_height, old_width, new_width)?;
            prev_inline_height = 0;
        }

        if changed || has_running || resized {
            prev_inline_height = paint_frame(&mut db, &mut terminal, &tui_state, prev_inline_height, false)?;
        }

        if all_done {
            break ExitReason::Completed;
        }

        let timeout = if has_running { Duration::from_millis(200) } else { Duration::from_secs(60) };
        match extui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), Some(timeout)) {
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
    };

    let _ = paint_frame(&mut db, &mut terminal, &tui_state, prev_inline_height, true)?;

    drop(db);
    drop(terminal);

    let mut buf = Vec::with_capacity(4096);
    match exit_reason {
        ExitReason::Completed => write_color_summary(&mut buf, &tui_state, workspace),
        ExitReason::Cancelled => write_cancelled_summary(&mut buf, &tui_state),
        ExitReason::Detached => {
            let _ = writeln!(buf, "\nDetached. Tests will continue running in background.");
        }
        ExitReason::Terminated => {}
    }
    if !buf.is_empty() {
        let _ = unsafe { libc::write(stdout.as_raw_fd(), buf.as_ptr() as *const _, buf.len()) };
    }

    send_termination(&mut encoder, &mut socket);
    Ok(())
}

fn init_tui_state(test_run: &TestRun, workspace: &Workspace, width: u16, height: u16) -> TuiState {
    let state = workspace.state.read().unwrap();
    let tests: Vec<TestDisplay> = test_run
        .test_jobs
        .iter()
        .map(|tj| {
            let (job_index, log_group, command) = tj
                .job_index
                .and_then(|ji| {
                    let job = state.jobs.get(ji)?;
                    Some((Some(ji), Some(job.log_group), format_command(&job.task().config().command)))
                })
                .unwrap_or((None, None, String::new()));
            TestDisplay {
                base_task_index: tj.base_task_index,
                job_index,
                log_group,
                status: tj.status,
                name: format_test_name(tj, &state.base_tasks),
                command,
                started_at: None,
                finished_at: None,
                recent_logs: VecDeque::new(),
                timeout_info: None,
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

        if is_terminal_status(display.status) {
            continue;
        }

        let Some(job_index) = test_job.job_index else {
            continue;
        };
        let Some(job) = ws_state.jobs.get(job_index) else {
            display.status = TestJobStatus::Failed(-1);
            display.finished_at = Some(crate::clock::now());
            changed = true;
            continue;
        };
        let (new_status, timeout_info) = match &job.process_status {
            JobStatus::Scheduled { .. } | JobStatus::Starting => {
                all_done = false;
                (TestJobStatus::Pending, None)
            }
            JobStatus::Running { .. } => {
                all_done = false;
                (TestJobStatus::Running, None)
            }
            JobStatus::Exited { status, cause, .. } => {
                if job.cache_synthetic {
                    (TestJobStatus::Cached, None)
                } else if *status == 0 {
                    (TestJobStatus::Passed, None)
                } else {
                    let timeout = if *cause == ExitCause::Timeout {
                        job.task().config().timeout.as_ref().and_then(|t| t.max.or(t.idle).or(t.conditional))
                    } else {
                        None
                    };
                    (TestJobStatus::Failed(*status as i32), timeout)
                }
            }
            JobStatus::Cancelled => (TestJobStatus::Failed(-1), None),
        };

        if new_status != display.status {
            if new_status == TestJobStatus::Running && display.started_at.is_none() {
                display.started_at = Some(crate::clock::now());
            }
            if is_terminal_status(new_status) {
                display.finished_at = Some(crate::clock::now());
                display.timeout_info = timeout_info;
            }
            display.status = new_status;
            changed = true;
        }

        if let Some(log_group) = display.log_group {
            let new_logs = collect_recent_logs(&logs, log_group, MAX_RECENT_LOGS);
            if new_logs != display.recent_logs.make_contiguous() {
                display.recent_logs = new_logs.into_iter().collect();
                changed = true;
            }
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

fn status_color(status: TestJobStatus) -> AnsiColor {
    match status {
        TestJobStatus::Pending => AnsiColor::Grey[17],
        TestJobStatus::Running => AnsiColor::DarkOliveGreen,
        TestJobStatus::Passed => AnsiColor::SpringGreen,
        TestJobStatus::Cached => AnsiColor::Cyan1,
        TestJobStatus::Failed(_) => AnsiColor::NeonRed,
    }
}

/// Render-time layout decision: how many log lines each test shows. Tests
/// render in their original order. Headers are always rendered. Each test
/// reserves `MAX_RECENT_LOGS` log rows even when it has fewer log lines, so
/// the layout stays vertically stable as logs arrive. Log allocations are
/// dropped to fit the budget when one is supplied.
struct Layout {
    /// Indices into `TuiState::tests`, in render order.
    order: Vec<usize>,
    /// Parallel to `order`; how many log rows each test reserves (0..=3).
    log_lines: Vec<u16>,
    /// Total painted height: headers + reserved log rows + 1 status line.
    height: u16,
}

fn drop_priority(status: TestJobStatus) -> u8 {
    match status {
        TestJobStatus::Passed => 0,
        TestJobStatus::Cached => 1,
        TestJobStatus::Pending => 2,
        TestJobStatus::Running => 3,
        TestJobStatus::Failed(_) => 4,
    }
}

fn compute_layout(state: &TuiState, budget: Option<u16>) -> Layout {
    let mut order: Vec<usize> = (0..state.tests.len()).collect();
    let mut log_lines: Vec<u16> = vec![MAX_RECENT_LOGS as u16; order.len()];

    let total = |log_lines: &[u16]| -> u16 {
        let header = log_lines.len() as u16;
        let logs: u16 = log_lines.iter().copied().sum();
        header + logs + 1
    };

    if let Some(budget) = budget {
        let mut drop_order: Vec<usize> = (0..order.len()).collect();
        drop_order.sort_by_key(|&i| drop_priority(state.tests[order[i]].status));

        for idx in drop_order {
            if total(&log_lines) <= budget {
                break;
            }
            log_lines[idx] = 0;
        }

        if total(&log_lines) > budget {
            let max_tests = budget.saturating_sub(1) as usize;
            if max_tests < order.len() {
                order.truncate(max_tests);
                log_lines.truncate(max_tests);
            }
        }
    }

    let height = total(&log_lines);
    Layout { order, log_lines, height }
}

/// Erases the previously painted inline region after a terminal resize.
///
/// `extui::DoubleBuffer::render_inline` assumes the cursor is one row below a
/// region with exactly `prev_height` terminal rows. A width shrink causes the
/// terminal to re-wrap previously emitted rows, which inflates the actual
/// footprint and breaks that assumption. Move up by the worst-case wrapped
/// row count and clear from there to the bottom of the screen, so the next
/// `render_inline` call can start fresh from the current cursor position with
/// `prev_height = 0`.
fn cleanup_inline_region(
    terminal: &mut extui::Terminal,
    prev_height: u16,
    old_width: u16,
    new_width: u16,
) -> std::io::Result<()> {
    if prev_height == 0 {
        return Ok(());
    }
    let wrap_factor: u32 =
        if new_width == 0 || old_width <= new_width { 1 } else { (old_width as u32).div_ceil(new_width as u32) };
    let rows_up = (prev_height as u32).saturating_mul(wrap_factor).min(u16::MAX as u32) as u16;
    let mut buf = Vec::with_capacity(16);
    buf.push(b'\r');
    if rows_up > 0 {
        MoveCursorUp(rows_up).write_to_buffer(&mut buf);
    }
    buf.extend_from_slice(vt::CLEAR_BELOW);
    terminal.write_all(&buf)
}

fn paint_frame(
    db: &mut DoubleBuffer,
    terminal: &mut extui::Terminal,
    state: &TuiState,
    prev_inline_height: u16,
    unbounded: bool,
) -> std::io::Result<u16> {
    let budget = if unbounded { None } else { Some(state.height.saturating_sub(1).max(1)) };
    let layout = compute_layout(state, budget);

    db.resize(state.width, layout.height.max(1));

    let mut row: u16 = 0;
    for (slot, &test_idx) in layout.order.iter().enumerate() {
        let test = &state.tests[test_idx];
        render_test_header(row_rect(db, row), db, test);
        row += 1;
        let log_count = layout.log_lines[slot] as usize;
        let actual = test.recent_logs.len().min(log_count);
        let skip = test.recent_logs.len() - actual;
        for log in test.recent_logs.iter().skip(skip) {
            render_log_line(row_rect(db, row), db, log);
            row += 1;
        }
        row += (log_count - actual) as u16;
    }

    render_status_line(row_rect(db, row), db, state);

    db.render_inline(terminal, prev_inline_height)
}

fn row_rect(db: &DoubleBuffer, row: u16) -> Rect {
    Rect { x: 0, y: row, w: db.width(), h: 1 }
}

const HEADER_BG: AnsiColor = AnsiColor::Grey[3];

fn render_test_header(rect: Rect, db: &mut DoubleBuffer, test: &TestDisplay) {
    let badge_style = status_color(test.status).with_fg(AnsiColor::Black);
    let status_str = match test.status {
        TestJobStatus::Pending => "WAIT",
        TestJobStatus::Running => "RUN ",
        TestJobStatus::Passed => "PASS",
        TestJobStatus::Cached => "SKIP",
        TestJobStatus::Failed(_) => "FAIL",
    };

    let header_bg = HEADER_BG.as_bg();
    let name_style = header_bg;
    let grey = AnsiColor::Grey[14].with_bg(HEADER_BG);

    let r = rect.display().with(header_bg).fill(db);
    let r = r.with(badge_style).fmt(db, format_args!(" {} ", status_str));
    let mut r = r.with(name_style).fmt(db, format_args!(" {}", test.name));

    if let Some(started) = test.started_at {
        let elapsed = test.finished_at.unwrap_or_else(Instant::now).duration_since(started);
        r = r.with(grey).fmt(db, format_args!(" ({:.1}s)", elapsed.as_secs_f64()));
    }

    if let TestJobStatus::Failed(code) = test.status {
        r = if let Some(timeout_secs) = test.timeout_info {
            r.with(grey).fmt(db, format_args!(" terminated: exceeded timeout of {}", format_duration(timeout_secs)))
        } else {
            r.with(grey).fmt(db, format_args!(" exit {}", code))
        };
    }

    r.with(grey).fmt(db, format_args!(" $ {}", test.command));
}

fn render_log_line(rect: Rect, db: &mut DoubleBuffer, line: &str) {
    let bytes = line.as_bytes();
    let mut r = rect.display().skip(4);
    let mut style = Style::DEFAULT;
    let mut chunk_start = 0usize;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'[') {
            if i > chunk_start {
                r = r.with(style).text(db, &line[chunk_start..i]);
            }
            let csi_start = i + 2;
            let mut j = csi_start;
            while j < bytes.len() && !bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j < bytes.len() {
                if bytes[j] == b'm'
                    && let Ok(params) = std::str::from_utf8(&bytes[csi_start..j])
                {
                    style = apply_sgr(style, params);
                }
                i = j + 1;
            } else {
                i = bytes.len();
            }
            chunk_start = i;
        } else {
            i += 1;
        }
    }
    if chunk_start < bytes.len() {
        r.with(style).text(db, &line[chunk_start..]);
    }
}

fn parse_sgr_param<'a, I: Iterator<Item = &'a str>>(parts: &mut std::iter::Peekable<I>) -> Option<u32> {
    let raw = parts.next()?;
    if raw.is_empty() { Some(0) } else { raw.parse().ok() }
}

fn apply_sgr(mut style: Style, params: &str) -> Style {
    let mut parts = params.split(';').peekable();
    while let Some(n) = parse_sgr_param(&mut parts) {
        match n {
            0 => style = Style::DEFAULT,
            1 => style = style.with_modifier(Modifier::BOLD),
            2 => style = style.with_modifier(Modifier::DIM),
            3 => style = style.with_modifier(Modifier::ITALIC),
            4 => style = style.with_modifier(Modifier::UNDERLINED),
            7 => style = style.with_modifier(Modifier::REVERSED),
            22 => style = style.without_modifier(Modifier::BOLD).without_modifier(Modifier::DIM),
            23 => style = style.without_modifier(Modifier::ITALIC),
            24 => style = style.without_modifier(Modifier::UNDERLINED),
            27 => style = style.without_modifier(Modifier::REVERSED),
            30..=37 => style = style.with_fg(AnsiColor((n - 30) as u8)),
            38 => match parse_sgr_param(&mut parts) {
                Some(5) => {
                    if let Some(idx) = parse_sgr_param(&mut parts) {
                        style = style.with_fg(AnsiColor(idx as u8));
                    }
                }
                Some(2) => {
                    let r = parse_sgr_param(&mut parts).unwrap_or(0) as u8;
                    let g = parse_sgr_param(&mut parts).unwrap_or(0) as u8;
                    let b = parse_sgr_param(&mut parts).unwrap_or(0) as u8;
                    style = style.with_fg(Rgb(r, g, b));
                }
                _ => {}
            },
            39 => style = style.without_fg(),
            40..=47 => style = style.with_bg(AnsiColor((n - 40) as u8)),
            48 => match parse_sgr_param(&mut parts) {
                Some(5) => {
                    if let Some(idx) = parse_sgr_param(&mut parts) {
                        style = style.with_bg(AnsiColor(idx as u8));
                    }
                }
                Some(2) => {
                    let r = parse_sgr_param(&mut parts).unwrap_or(0) as u8;
                    let g = parse_sgr_param(&mut parts).unwrap_or(0) as u8;
                    let b = parse_sgr_param(&mut parts).unwrap_or(0) as u8;
                    style = style.with_bg(Rgb(r, g, b));
                }
                _ => {}
            },
            49 => style = style.without_bg(),
            90..=97 => style = style.with_fg(AnsiColor((n - 90 + 8) as u8)),
            100..=107 => style = style.with_bg(AnsiColor((n - 100 + 8) as u8)),
            _ => {}
        }
    }
    style
}

fn render_status_line(rect: Rect, db: &mut DoubleBuffer, state: &TuiState) {
    let counts = status_counts(state);
    let total = state.tests.len();
    let done = counts.passed + counts.cached + counts.failed;

    let r = rect.display();
    let r = r.with(Style::DEFAULT).fmt(db, format_args!(" Tests: {}/{} ", done, total));

    let chip_styles = [
        (counts.running, "running", AnsiColor::DarkOliveGreen.with_fg(AnsiColor::Black)),
        (counts.pending, "pending", AnsiColor::Grey[17].with_fg(AnsiColor::Black)),
        (counts.passed, "passed", AnsiColor::SpringGreen.with_fg(AnsiColor::Black)),
        (counts.cached, "cached", AnsiColor::Cyan1.with_fg(AnsiColor::Black)),
        (counts.failed, "failed", AnsiColor::NeonRed.with_fg(AnsiColor::Black)),
    ];
    let mut r = r;
    for (count, label, style) in chip_styles {
        if count > 0 {
            r = r.with(style).fmt(db, format_args!(" {} {} ", count, label));
        }
    }
}

#[derive(Default)]
struct StatusCounts {
    passed: usize,
    cached: usize,
    failed: usize,
    running: usize,
    pending: usize,
}

fn status_counts(state: &TuiState) -> StatusCounts {
    let mut counts = StatusCounts::default();
    for test in &state.tests {
        match test.status {
            TestJobStatus::Passed => counts.passed += 1,
            TestJobStatus::Cached => counts.cached += 1,
            TestJobStatus::Failed(_) => counts.failed += 1,
            TestJobStatus::Running => counts.running += 1,
            TestJobStatus::Pending => counts.pending += 1,
        }
    }
    counts
}

fn write_color_summary(buf: &mut Vec<u8>, state: &TuiState, workspace: &Workspace) {
    let logs = workspace.logs.read().unwrap();
    let elapsed = state.started_at.elapsed();

    let passed = state.tests.iter().filter(|t| t.status == TestJobStatus::Passed).count();
    let cached = state.tests.iter().filter(|t| t.status == TestJobStatus::Cached).count();
    let failed: Vec<_> = state.tests.iter().filter(|t| matches!(t.status, TestJobStatus::Failed(_))).collect();

    splat!(buf, "\n", "Tests: ", AnsiColor(2).as_fg(), passed, " passed", vt::CLEAR_STYLE);
    if cached > 0 {
        splat!(buf, ", ", AnsiColor::Cyan1.as_fg(), skipped_via_cache_text(cached), vt::CLEAR_STYLE);
    }
    if !failed.is_empty() {
        splat!(buf, ", ", AnsiColor(1).as_fg(), failed.len(), " failed", vt::CLEAR_STYLE);
    }
    writeln!(buf, " ({:.1}s)", elapsed.as_secs_f64()).ok();

    for test in &failed {
        splat!(buf, "\n", AnsiColor(1).as_fg(), "FAIL ", test.name, vt::CLEAR_STYLE, "\n");
        splat!(buf, "  Command: ", test.command, "\n");
        if let TestJobStatus::Failed(code) = test.status {
            if let Some(timeout_secs) = test.timeout_info {
                splat!(buf, "  Terminated: exceeded timeout of ", format_duration(timeout_secs), "\n");
            } else {
                splat!(buf, "  Exit code: ", code, "\n");
            }
        }

        if let Some(log_group) = test.log_group {
            let recent = collect_recent_logs(&logs, log_group, MAX_SUMMARY_LOGS);
            if !recent.is_empty() {
                splat!(buf, "  Last ", recent.len(), " log lines:\n");
                for line in &recent {
                    splat!(buf, "", line, "\n");
                }
            }
        }
    }
}

fn write_cancelled_summary(buf: &mut Vec<u8>, state: &TuiState) {
    let elapsed = state.started_at.elapsed();

    let passed = state.tests.iter().filter(|t| t.status == TestJobStatus::Passed).count();
    let cached = state.tests.iter().filter(|t| t.status == TestJobStatus::Cached).count();
    let failed = state.tests.iter().filter(|t| matches!(t.status, TestJobStatus::Failed(_))).count();
    let running = state.tests.iter().filter(|t| t.status == TestJobStatus::Running).count();
    let pending = state.tests.iter().filter(|t| t.status == TestJobStatus::Pending).count();

    splat!(buf, b'\n', AnsiColor(3).as_fg(), "Tests cancelled.", vt::CLEAR_STYLE);
    writeln!(buf, " ({:.1}s)", elapsed.as_secs_f64()).ok();
    buf.extend_from_slice(b"  ");
    if passed > 0 {
        splat!(buf, AnsiColor(2).as_fg(), passed, " passed", vt::CLEAR_STYLE);
    }
    if cached > 0 {
        if passed > 0 {
            buf.extend_from_slice(b", ");
        }
        splat!(buf, AnsiColor::Cyan1.as_fg(), skipped_via_cache_text(cached), vt::CLEAR_STYLE);
    }
    if failed > 0 {
        if passed > 0 || cached > 0 {
            buf.extend_from_slice(b", ");
        }
        splat!(buf, AnsiColor(1).as_fg(), failed, " failed", vt::CLEAR_STYLE);
    }
    if running > 0 {
        if passed > 0 || cached > 0 || failed > 0 {
            buf.extend_from_slice(b", ");
        }
        splat!(buf, running, " cancelled while running");
    }
    if pending > 0 {
        if passed > 0 || cached > 0 || failed > 0 || running > 0 {
            buf.extend_from_slice(b", ");
        }
        splat!(buf, pending, " not started");
    }
    buf.push(b'\n');
}

fn update_test_statuses(
    buf: &mut Vec<u8>,
    workspace: &Workspace,
    test_run: &mut TestRun,
    strip_ansi: bool,
) -> anyhow::Result<bool> {
    let state = workspace.state.read().unwrap();
    let logs = workspace.logs.read().unwrap();
    let mut all_done = true;

    for test_job in &mut test_run.test_jobs {
        if is_terminal_status(test_job.status) {
            continue;
        }

        let Some(job_index) = test_job.job_index else {
            continue;
        };
        let Some(job) = state.jobs.get(job_index) else {
            test_job.status = TestJobStatus::Failed(-1);
            continue;
        };
        let (new_status, timeout_info) = match &job.process_status {
            JobStatus::Scheduled { .. } | JobStatus::Starting => {
                all_done = false;
                (TestJobStatus::Pending, None)
            }
            JobStatus::Running { .. } => {
                all_done = false;
                (TestJobStatus::Running, None)
            }
            JobStatus::Exited { status, cause, .. } => {
                if job.cache_synthetic {
                    (TestJobStatus::Cached, None)
                } else if *status == 0 {
                    (TestJobStatus::Passed, None)
                } else {
                    let timeout = if *cause == ExitCause::Timeout {
                        job.task().config().timeout.as_ref().and_then(|t| t.max.or(t.idle).or(t.conditional))
                    } else {
                        None
                    };
                    (TestJobStatus::Failed(*status as i32), timeout)
                }
            }
            JobStatus::Cancelled => (TestJobStatus::Failed(-1), None),
        };

        if new_status != test_job.status {
            test_job.status = new_status;

            let display_name = format_test_name(test_job, &state.base_tasks);
            match new_status {
                TestJobStatus::Passed => {
                    writeln!(buf, "=== PASS {}", display_name).ok();
                }
                TestJobStatus::Cached => {
                    writeln!(buf, "=== CACHE {}", display_name).ok();
                }
                TestJobStatus::Failed(code) => {
                    let base_path = state.config.current.base_path();
                    let config = job.task().config();
                    let mut path = base_path.join(config.pwd);
                    if let Ok(rel_path) = path.canonicalize() {
                        path = rel_path;
                    }

                    writeln!(buf, "=== FAIL {}", display_name).ok();
                    if let Some(timeout_secs) = timeout_info {
                        writeln!(buf, "terminated: exceeded timeout of {}", format_duration(timeout_secs)).ok();
                    } else {
                        writeln!(buf, "exit_code: {}", code).ok();
                    }
                    writeln!(buf, "pwd: {}", path.display()).ok();
                    match &config.command {
                        Command::Cmd(items) => {
                            writeln!(buf, "command: {}", items.join(" ")).ok();
                        }
                        Command::Sh { script, .. } => {
                            writeln!(buf, "sh: {}", script.trim()).ok();
                        }
                    }

                    let recent = collect_recent_logs(&logs, job.log_group, MAX_SUMMARY_LOGS);
                    if !recent.is_empty() {
                        let mut first = true;
                        writeln!(buf, "<logs>").ok();
                        for line in &recent {
                            if first && line.trim().is_empty() {
                                continue;
                            }
                            first = false;
                            if strip_ansi {
                                strip_ansi_to_buffer_preserve_case(line, buf);
                                buf.push(b'\n')
                            } else {
                                writeln!(buf, "{}", line).ok();
                            }
                        }
                        writeln!(buf, "</logs>").ok();

                        let public_id = state.jobs.public_id_of(job_index).unwrap_or(0);
                        writeln!(buf, "hint: `devsm logs --job={}` for full logs", public_id).ok();
                    }
                    writeln!(buf).ok();
                }
                _ => {}
            }
        }
    }

    Ok(all_done)
}

fn format_test_name(test_job: &TestJob, base_tasks: &[BaseTask]) -> String {
    let base_task = &base_tasks[test_job.base_task_index.idx()];
    base_task.name.to_string()
}

fn print_summary(buf: &mut Vec<u8>, test_run: &TestRun, _base_tasks: &[BaseTask]) {
    let elapsed = test_run.started_at.elapsed();
    let passed = test_run.test_jobs.iter().filter(|j| matches!(j.status, TestJobStatus::Passed)).count();
    let cached = test_run.test_jobs.iter().filter(|j| matches!(j.status, TestJobStatus::Cached)).count();
    let failed = test_run.test_jobs.iter().filter(|j| matches!(j.status, TestJobStatus::Failed(_))).count();

    writeln!(buf).ok();
    write!(buf, "Tests: {} passed, {} failed", passed, failed).ok();
    if cached > 0 {
        write!(buf, ", {}", skipped_via_cache_text(cached)).ok();
    }
    writeln!(buf, " ({:.1}s)", elapsed.as_secs_f64()).ok();
}
