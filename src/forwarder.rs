//! Log forwarder for the `run` command.
//!
//! Forwards log output from a managed task directly to the client's terminal
//! without using the TUI. Runs in a separate thread and exits when the task
//! completes or the client disconnects.

use std::{
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::Arc,
};

use crate::{
    log_storage::{JobLogCorrelation, LogFilter, LogId},
    process_manager::ForwarderChannel,
    workspace::{ExitCause, JobStatus, Workspace},
};

const STATUS_RESTARTING: u32 = 0x01_52_53_54;
const STATUS_WAITING: u32 = 0x02_57_41_54;
const STATUS_RUNNING: u32 = 0x03_52_55_4e;
const STATUS_EXITED: u32 = 0x04_45_58_54;
const TERMINATION_CODE: u32 = 0xcf_04_43_58;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initial,
    Restarting,
    Waiting,
    Running,
}

fn send_status(socket: &mut Option<UnixStream>, code: u32) {
    let Some(socket) = socket.as_mut() else { return };
    let _ = socket.write_all(&code.to_ne_bytes());
}

fn send_exit_status(socket: &mut Option<UnixStream>, exit_code: i32) {
    let Some(socket) = socket.as_mut() else { return };
    let _ = socket.write_all(&STATUS_EXITED.to_ne_bytes());
    let _ = socket.write_all(&exit_code.to_ne_bytes());
}

fn send_termination(socket: &mut Option<UnixStream>) {
    let Some(socket) = socket.as_mut() else { return };
    let _ = socket.write_all(&TERMINATION_CODE.to_ne_bytes());
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
    stdin: OwnedFd,
    stdout: OwnedFd,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    job_id: JobLogCorrelation,
    channel: Arc<ForwarderChannel>,
) -> anyhow::Result<()> {
    let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
    std::mem::forget(stdout);

    let mut last_log_id = workspace.logs.read().unwrap().head();
    let mut phase = Phase::Initial;

    loop {
        if channel.is_terminated() {
            forward_new_logs(&mut file, &mut socket, workspace, job_id, &mut last_log_id, &mut phase)?;
            send_termination(&mut socket);
            break;
        }

        let (job_exited, exit_code) =
            forward_new_logs(&mut file, &mut socket, workspace, job_id, &mut last_log_id, &mut phase)?;

        if job_exited {
            if let Some(code) = exit_code {
                send_exit_status(&mut socket, code);
            }
            send_termination(&mut socket);
            break;
        }

        match vtui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), None) {
            Ok(vtui::event::Polled::ReadReady) => {
                let mut buf = [0u8; 64];
                let n = unsafe { libc::read(stdin.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
                if n == 0 {
                    forward_new_logs(&mut file, &mut socket, workspace, job_id, &mut last_log_id, &mut phase)?;
                    let _ = file.write_all(b"Detached. Task will continue running in background.\n");
                    send_termination(&mut socket);
                    break;
                }
            }
            Ok(vtui::event::Polled::Woken) | Ok(vtui::event::Polled::TimedOut) | Err(_) => {}
        }
    }

    Ok(())
}

fn forward_new_logs(
    file: &mut std::fs::File,
    socket: &mut Option<UnixStream>,
    workspace: &Workspace,
    job_id: JobLogCorrelation,
    last_log_id: &mut LogId,
    phase: &mut Phase,
) -> anyhow::Result<(bool, Option<i32>)> {
    let logs = workspace.logs.read().unwrap();
    let current_tail = logs.tail();

    if *last_log_id >= current_tail {
        let state = workspace.state.read().unwrap();
        for job in &state.jobs {
            if job.job_id != job_id {
                continue;
            }
            match &job.process_status {
                JobStatus::Scheduled { after } if !after.is_empty() => {
                    let has_terminating =
                        after.iter().any(|req| matches!(req.predicate, crate::workspace::JobPredicate::Terminated));
                    if has_terminating && *phase != Phase::Restarting {
                        *phase = Phase::Restarting;
                        send_status(socket, STATUS_RESTARTING);
                    } else if !has_terminating && *phase != Phase::Waiting {
                        *phase = Phase::Waiting;
                        send_status(socket, STATUS_WAITING);
                    }
                }
                JobStatus::Starting | JobStatus::Running { .. } => {
                    if *phase != Phase::Running {
                        *phase = Phase::Running;
                        send_status(socket, STATUS_RUNNING);
                    }
                }
                JobStatus::Exited { status, cause, .. } => {
                    let code = match cause {
                        ExitCause::Killed | ExitCause::Replaced | ExitCause::Reloaded => -1,
                        ExitCause::Unknown => *status as i32,
                    };
                    return Ok((true, Some(code)));
                }
                JobStatus::Cancelled => {
                    return Ok((true, Some(-1)));
                }
                _ => {}
            }
            break;
        }
        return Ok((false, None));
    }

    let view = logs.view(LogFilter::IsJob(job_id));
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
    for job in &state.jobs {
        if job.job_id != job_id {
            continue;
        }
        match &job.process_status {
            JobStatus::Starting | JobStatus::Running { .. } => {
                if *phase != Phase::Running {
                    *phase = Phase::Running;
                    send_status(socket, STATUS_RUNNING);
                }
            }
            JobStatus::Exited { status, cause, .. } => {
                let code = match cause {
                    ExitCause::Killed | ExitCause::Replaced | ExitCause::Reloaded => -1,
                    ExitCause::Unknown => *status as i32,
                };
                return Ok((true, Some(code)));
            }
            JobStatus::Cancelled => {
                return Ok((true, Some(-1)));
            }
            _ => {}
        }
        break;
    }

    Ok((false, None))
}
