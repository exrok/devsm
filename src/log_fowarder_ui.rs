//! Log forwarder for the `run` and `logs` commands.
//!
//! Forwards log output from managed tasks directly to the client's terminal
//! without using the TUI. Runs in a separate thread and exits when the task
//! completes or the client disconnects.

use std::{
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::Arc,
};

use crate::config::TaskKind;
use crate::daemon::LogsQuery;
use crate::line_width::{strip_ansi_to_buffer, strip_ansi_to_buffer_preserve_case};
use crate::log_storage::{BaseTaskSet, LogEntry, LogFilter, LogGroup, LogId, Logs};
use crate::process_manager::ClientChannel;
use crate::rpc::{Encoder, ExitCause as RpcExitCause, JobExitedEvent, JobStatusEvent, JobStatusKind, RpcMessageKind};
use crate::workspace::{BaseTaskIndex, ExitCause, JobIndex, JobStatus, Workspace};

const SPAN_COLORS: &[&str] = &[
    "\x1b[48;5;235;38;5;195m",
    "\x1b[48;5;16;38;5;189m",
    "\x1b[48;5;235;38;5;183m",
    "\x1b[48;5;16;38;5;149m",
    "\x1b[48;5;235;38;5;157m",
    "\x1b[48;5;16;38;5;110m",
    "\x1b[48;5;235;38;5;229m",
    "\x1b[48;5;16;38;5;182m",
    "\x1b[48;5;235;38;5;151m",
];

pub struct LogForwarderConfig {
    pub filter: LogForwarderFilter,
    pub pattern: String,
    pub case_sensitive: bool,
    pub max_age_secs: Option<u32>,
    pub strip_ansi: bool,
    pub with_taskname: bool,
    pub task_names: Vec<String>,
    pub follow: bool,
    pub oldest: Option<u32>,
    pub newest: Option<u32>,
}

pub enum LogForwarderFilter {
    All,
    BaseTasks(BaseTaskSet),
}

impl LogForwarderConfig {
    pub fn from_query(query: &LogsQuery, workspace: &Workspace) -> Self {
        let mut state = workspace.state.write().unwrap();

        let pattern = query.pattern.to_string();
        let case_sensitive = pattern.chars().any(|c| c.is_uppercase());
        let pattern_lower = if case_sensitive { pattern.clone() } else { pattern.to_lowercase() };

        let strip_ansi = !query.is_tty;

        let mut base_tasks = BaseTaskSet::new();
        let mut task_names = Vec::new();
        let mut task_count = 0usize;

        if !query.task_filters.is_empty() {
            for tf in &query.task_filters {
                if let Some(bti) = state.base_index_by_name(tf.name) {
                    base_tasks.insert(bti);
                    task_count += 1;
                    while task_names.len() <= bti.idx() {
                        task_names.push(String::new());
                    }
                    task_names[bti.idx()] = tf.name.to_string();
                }
            }
        } else if !query.kind_filters.is_empty() {
            for kf in &query.kind_filters {
                let kind = match kf.kind {
                    "service" => TaskKind::Service,
                    "action" => TaskKind::Action,
                    "test" => TaskKind::Test,
                    _ => continue,
                };
                for (bti, bt) in state.base_tasks.iter().enumerate() {
                    if bt.config.kind == kind {
                        let bti = BaseTaskIndex(bti as u32);
                        base_tasks.insert(bti);
                        task_count += 1;
                        while task_names.len() <= bti.idx() {
                            task_names.push(String::new());
                        }
                        task_names[bti.idx()] = bt.name.to_string();
                    }
                }
            }
        } else {
            for (bti, bt) in state.base_tasks.iter().enumerate() {
                let bti = BaseTaskIndex(bti as u32);
                base_tasks.insert(bti);
                task_count += 1;
                while task_names.len() <= bti.idx() {
                    task_names.push(String::new());
                }
                task_names[bti.idx()] = bt.name.to_string();
            }
        }

        let filter = if task_count == state.base_tasks.len() {
            LogForwarderFilter::All
        } else {
            LogForwarderFilter::BaseTasks(base_tasks)
        };

        let with_taskname = task_count > 1 && !query.without_taskname;

        Self {
            filter,
            pattern: pattern_lower,
            case_sensitive,
            max_age_secs: query.max_age_secs,
            strip_ansi,
            with_taskname,
            task_names,
            follow: query.follow,
            oldest: query.oldest,
            newest: query.newest,
        }
    }
}

fn matches_pattern(text: &str, pattern: &str, case_sensitive: bool, buffer: &mut Vec<u8>) -> bool {
    if pattern.is_empty() {
        return true;
    }
    buffer.clear();
    if case_sensitive {
        strip_ansi_to_buffer_preserve_case(text, buffer);
    } else {
        strip_ansi_to_buffer(text, buffer);
    }
    let haystack = std::str::from_utf8(buffer).unwrap_or("");
    haystack.contains(pattern)
}

fn write_log_entry(
    file: &mut File,
    entry: &LogEntry,
    logs: &Logs,
    config: &LogForwarderConfig,
    ansi_buffer: &mut Vec<u8>,
) -> std::io::Result<()> {
    let text = unsafe { entry.text(logs) };

    if !matches_pattern(text, &config.pattern, config.case_sensitive, ansi_buffer) {
        return Ok(());
    }

    if config.with_taskname {
        let bti = entry.log_group.base_task_index();
        let task_name = config.task_names.get(bti.idx()).map(|s| s.as_str()).unwrap_or("?");
        if config.strip_ansi {
            write!(file, "{}> ", task_name)?;
        } else {
            let color = SPAN_COLORS[bti.idx() % SPAN_COLORS.len()];
            write!(file, "{} {} \x1b[m ", color, task_name)?;
        }
    }

    if config.strip_ansi {
        ansi_buffer.clear();
        strip_ansi_to_buffer_preserve_case(text, ansi_buffer);
        file.write_all(ansi_buffer)?;
    } else {
        file.write_all(text.as_bytes())?;
    }
    file.write_all(b"\n")?;

    Ok(())
}

pub fn run_logs(
    stdin: File,
    mut stdout: File,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    config: LogForwarderConfig,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mut encoder = Encoder::new();
    let mut ansi_buffer = Vec::with_capacity(1024);

    if !config.follow {
        dump_logs(&mut stdout, workspace, &config, &mut ansi_buffer)?;
        send_termination(&mut encoder, &mut socket);
        return Ok(());
    }

    dump_logs(&mut stdout, workspace, &config, &mut ansi_buffer)?;

    let mut last_log_id = workspace.logs.read().unwrap().tail();

    loop {
        if channel.is_terminated() {
            forward_logs_filtered(&mut stdout, workspace, &config, &mut last_log_id, &mut ansi_buffer)?;
            send_termination(&mut encoder, &mut socket);
            break;
        }

        forward_logs_filtered(&mut stdout, workspace, &config, &mut last_log_id, &mut ansi_buffer)?;

        match extui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), None) {
            Ok(extui::event::Polled::ReadReady) => {
                let mut buf = [0u8; 64];
                let n = unsafe { libc::read(stdin.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
                if n == 0 {
                    forward_logs_filtered(&mut stdout, workspace, &config, &mut last_log_id, &mut ansi_buffer)?;
                    send_termination(&mut encoder, &mut socket);
                    break;
                }
            }
            Ok(extui::event::Polled::Woken) | Ok(extui::event::Polled::TimedOut) | Err(_) => {}
        }
    }

    Ok(())
}

fn dump_logs(
    file: &mut File,
    workspace: &Workspace,
    config: &LogForwarderConfig,
    ansi_buffer: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let logs = workspace.logs.read().unwrap();
    let elapsed_secs = logs.elapsed_secs();

    let filter = match &config.filter {
        LogForwarderFilter::All => LogFilter::All,
        LogForwarderFilter::BaseTasks(set) => LogFilter::IsInSet(set.clone()),
    };

    let view = logs.view(filter);
    let (a, b) = logs.slices();

    let mut matching_entries: Vec<&LogEntry> = Vec::new();

    for slice in [a, b] {
        for entry in slice {
            if !view.contains(entry) {
                continue;
            }

            if let Some(max_age) = config.max_age_secs {
                if entry.time + max_age < elapsed_secs {
                    continue;
                }
            }

            let text = unsafe { entry.text(&logs) };
            if !matches_pattern(text, &config.pattern, config.case_sensitive, ansi_buffer) {
                continue;
            }

            matching_entries.push(entry);
        }
    }

    let entries_to_print: &[&LogEntry] = if let Some(oldest) = config.oldest {
        let n = (oldest as usize).min(matching_entries.len());
        &matching_entries[..n]
    } else if let Some(newest) = config.newest {
        let n = (newest as usize).min(matching_entries.len());
        &matching_entries[matching_entries.len() - n..]
    } else {
        &matching_entries
    };

    for entry in entries_to_print {
        let text = unsafe { entry.text(&logs) };

        if config.with_taskname {
            let bti = entry.log_group.base_task_index();
            let task_name = config.task_names.get(bti.idx()).map(|s| s.as_str()).unwrap_or("?");
            if config.strip_ansi {
                write!(file, "{}> ", task_name)?;
            } else {
                let color = SPAN_COLORS[bti.idx() % SPAN_COLORS.len()];
                write!(file, "{} {} \x1b[m ", color, task_name)?;
            }
        }

        if config.strip_ansi {
            ansi_buffer.clear();
            strip_ansi_to_buffer_preserve_case(text, ansi_buffer);
            file.write_all(ansi_buffer)?;
        } else {
            file.write_all(text.as_bytes())?;
        }
        file.write_all(b"\n")?;
    }

    let _ = file.flush();
    Ok(())
}

fn forward_logs_filtered(
    file: &mut File,
    workspace: &Workspace,
    config: &LogForwarderConfig,
    last_log_id: &mut LogId,
    ansi_buffer: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let logs = workspace.logs.read().unwrap();
    let current_tail = logs.tail();

    if *last_log_id >= current_tail {
        return Ok(());
    }

    let elapsed_secs = logs.elapsed_secs();

    let filter = match &config.filter {
        LogForwarderFilter::All => LogFilter::All,
        LogForwarderFilter::BaseTasks(set) => LogFilter::IsInSet(set.clone()),
    };

    let view = logs.view(filter);
    let (a, b) = logs.slices_range(*last_log_id, LogId(current_tail.0.saturating_sub(1)));

    for slice in [a, b] {
        for entry in slice {
            if !view.contains(entry) {
                continue;
            }

            if let Some(max_age) = config.max_age_secs {
                if entry.time + max_age < elapsed_secs {
                    continue;
                }
            }

            let _ = write_log_entry(file, entry, &logs, config, ansi_buffer);
        }
    }
    let _ = file.flush();

    *last_log_id = current_tail;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initial,
    Restarting,
    Waiting,
    Running,
}

fn send_status(encoder: &mut Encoder, socket: &mut Option<UnixStream>, status: JobStatusKind, job_index: JobIndex) {
    let Some(socket) = socket.as_mut() else { return };
    encoder.encode_push(RpcMessageKind::JobStatus, &JobStatusEvent { job_index: job_index.as_u32(), status });
    let _ = socket.write_all(encoder.output());
    encoder.clear();
}

fn send_exit_status(
    encoder: &mut Encoder,
    socket: &mut Option<UnixStream>,
    exit_code: i32,
    job_index: JobIndex,
    cause: RpcExitCause,
) {
    let Some(socket) = socket.as_mut() else { return };
    encoder.encode_push(RpcMessageKind::JobExited, &JobExitedEvent { job_index: job_index.as_u32(), exit_code, cause });
    let _ = socket.write_all(encoder.output());
    encoder.clear();
}

fn send_termination(encoder: &mut Encoder, socket: &mut Option<UnixStream>) {
    let Some(socket) = socket.as_mut() else { return };
    encoder.encode_empty(RpcMessageKind::TerminateAck, 0);
    let _ = socket.write_all(encoder.output());
    encoder.clear();
}

/// Forwards log output for a specific job to the client's stdout.
///
/// Runs in a loop, blocking on the waker until new logs arrive or termination
/// is signaled. Exits when the job completes or the client disconnects.
///
/// # Errors
///
/// Returns an error if polling fails.
pub fn run(
    stdin: File,
    mut stdout: File,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    log_group: LogGroup,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mut last_log_id = workspace.logs.read().unwrap().head();
    let mut phase = Phase::Initial;
    let mut encoder = Encoder::new();
    let mut current_job: Option<JobIndex> = None;

    loop {
        if channel.is_terminated() {
            forward_new_logs(
                &mut encoder,
                &mut stdout,
                &mut socket,
                workspace,
                log_group,
                &mut last_log_id,
                &mut phase,
                &mut current_job,
            )?;
            send_termination(&mut encoder, &mut socket);
            break;
        }

        let (job_exited, exit_code, cause) = forward_new_logs(
            &mut encoder,
            &mut stdout,
            &mut socket,
            workspace,
            log_group,
            &mut last_log_id,
            &mut phase,
            &mut current_job,
        )?;

        if job_exited {
            if let (Some(code), Some(job_index)) = (exit_code, current_job) {
                send_exit_status(&mut encoder, &mut socket, code, job_index, cause.unwrap_or(RpcExitCause::Unknown));
            }
            send_termination(&mut encoder, &mut socket);
            break;
        }

        match extui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), None) {
            Ok(extui::event::Polled::ReadReady) => {
                let mut buf = [0u8; 64];
                let n = unsafe { libc::read(stdin.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
                if n == 0 {
                    forward_new_logs(
                        &mut encoder,
                        &mut stdout,
                        &mut socket,
                        workspace,
                        log_group,
                        &mut last_log_id,
                        &mut phase,
                        &mut current_job,
                    )?;
                    let _ = stdout.write_all(b"Detached. Task will continue running in background.\n");
                    send_termination(&mut encoder, &mut socket);
                    break;
                }
            }
            Ok(extui::event::Polled::Woken) | Ok(extui::event::Polled::TimedOut) | Err(_) => {}
        }
    }

    Ok(())
}

fn forward_new_logs(
    encoder: &mut Encoder,
    file: &mut std::fs::File,
    socket: &mut Option<UnixStream>,
    workspace: &Workspace,
    log_group: LogGroup,
    last_log_id: &mut LogId,
    phase: &mut Phase,
    current_job: &mut Option<JobIndex>,
) -> anyhow::Result<(bool, Option<i32>, Option<RpcExitCause>)> {
    let logs = workspace.logs.read().unwrap();
    let current_tail = logs.tail();

    if *last_log_id >= current_tail {
        let state = workspace.state.read().unwrap();
        for (idx, job) in state.jobs.iter().enumerate() {
            if job.log_group != log_group {
                continue;
            }
            let job_index = JobIndex::from_usize(idx);
            *current_job = Some(job_index);
            match &job.process_status {
                JobStatus::Scheduled { after } if !after.is_empty() => {
                    let has_terminating =
                        after.iter().any(|req| matches!(req.predicate, crate::workspace::JobPredicate::Terminated));
                    if has_terminating && *phase != Phase::Restarting {
                        *phase = Phase::Restarting;
                        send_status(encoder, socket, JobStatusKind::Restarting, job_index);
                    } else if !has_terminating && *phase != Phase::Waiting {
                        *phase = Phase::Waiting;
                        send_status(encoder, socket, JobStatusKind::Waiting, job_index);
                    }
                }
                JobStatus::Starting | JobStatus::Running { .. } => {
                    if *phase != Phase::Running {
                        *phase = Phase::Running;
                        send_status(encoder, socket, JobStatusKind::Running, job_index);
                    }
                }
                JobStatus::Exited { status, cause, .. } => {
                    let (code, rpc_cause) = match cause {
                        ExitCause::Killed => (-1, RpcExitCause::Killed),
                        ExitCause::Restarted => (-1, RpcExitCause::Restarted),
                        ExitCause::Unknown => (*status as i32, RpcExitCause::Unknown),
                        ExitCause::SpawnFailed => (*status as i32, RpcExitCause::SpawnFailed),
                        ExitCause::ProfileConflict => (-1, RpcExitCause::ProfileConflict),
                    };
                    return Ok((true, Some(code), Some(rpc_cause)));
                }
                JobStatus::Cancelled => {
                    return Ok((true, Some(-1), Some(RpcExitCause::Killed)));
                }
                _ => {}
            }
            break;
        }
        return Ok((false, None, None));
    }

    let view = logs.view(LogFilter::IsGroup(log_group));
    let (a, b) = logs.slices_range(*last_log_id, LogId(current_tail.0.saturating_sub(1)));

    for slice in [a, b] {
        for entry in slice {
            if !view.contains(entry) {
                continue;
            }
            let text = unsafe { entry.text(&logs) };
            let _ = file.write_all(text.as_bytes());
            let _ = file.write_all(b"\n");
        }
    }
    let _ = file.flush();

    *last_log_id = current_tail;

    let state = workspace.state.read().unwrap();
    for (idx, job) in state.jobs.iter().enumerate() {
        if job.log_group != log_group {
            continue;
        }
        let job_index = JobIndex::from_usize(idx);
        *current_job = Some(job_index);
        match &job.process_status {
            JobStatus::Starting | JobStatus::Running { .. } => {
                if *phase != Phase::Running {
                    *phase = Phase::Running;
                    send_status(encoder, socket, JobStatusKind::Running, job_index);
                }
            }
            JobStatus::Exited { status, cause, .. } => {
                let (code, rpc_cause) = match cause {
                    ExitCause::Killed => (-1, RpcExitCause::Killed),
                    ExitCause::Restarted => (-1, RpcExitCause::Restarted),
                    ExitCause::Unknown => (*status as i32, RpcExitCause::Unknown),
                    ExitCause::SpawnFailed => (*status as i32, RpcExitCause::SpawnFailed),
                    ExitCause::ProfileConflict => (-1, RpcExitCause::ProfileConflict),
                };
                return Ok((true, Some(code), Some(rpc_cause)));
            }
            JobStatus::Cancelled => {
                return Ok((true, Some(-1), Some(RpcExitCause::Killed)));
            }
            _ => {}
        }
        break;
    }

    Ok((false, None, None))
}
