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
    log_storage::{LogFilter, LogGroup, LogId},
    process_manager::ClientChannel,
    workspace::{ExitCause, JobIndex, JobStatus, Workspace},
};
use devsm_rpc::{Encoder, ExitCause as RpcExitCause, JobExitedEvent, JobStatusEvent, JobStatusKind, RpcMessageKind};

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
    stdin: OwnedFd,
    stdout: OwnedFd,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    log_group: LogGroup,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
    std::mem::forget(stdout);

    let mut last_log_id = workspace.logs.read().unwrap().head();
    let mut phase = Phase::Initial;
    let mut encoder = Encoder::new();
    let mut current_job: Option<JobIndex> = None;

    loop {
        if channel.is_terminated() {
            forward_new_logs(
                &mut encoder,
                &mut file,
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
            &mut file,
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

        match vtui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), None) {
            Ok(vtui::event::Polled::ReadReady) => {
                let mut buf = [0u8; 64];
                let n = unsafe { libc::read(stdin.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
                if n == 0 {
                    forward_new_logs(
                        &mut encoder,
                        &mut file,
                        &mut socket,
                        workspace,
                        log_group,
                        &mut last_log_id,
                        &mut phase,
                        &mut current_job,
                    )?;
                    let _ = file.write_all(b"Detached. Task will continue running in background.\n");
                    send_termination(&mut encoder, &mut socket);
                    break;
                }
            }
            Ok(vtui::event::Polled::Woken) | Ok(vtui::event::Polled::TimedOut) | Err(_) => {}
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
