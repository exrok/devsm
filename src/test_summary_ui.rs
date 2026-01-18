//! Test run forwarder for the `test` command.
//!
//! Monitors and displays the status of test jobs during a test run.
//! Shows progress as tests execute and prints a summary when complete.

use std::{
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::Arc,
};

use crate::{
    process_manager::ClientChannel,
    workspace::{BaseTask, JobStatus, TestJob, TestJobStatus, TestRun, Workspace},
};

const TERMINATION_CODE: u32 = 0xcf_04_43_58;

fn send_termination(socket: &mut Option<UnixStream>) {
    let Some(socket) = socket.as_mut() else { return };
    let _ = socket.write_all(&TERMINATION_CODE.to_ne_bytes());
}

/// Monitors test jobs and displays their progress and results.
///
/// # Errors
///
/// Returns an error if polling fails.
pub fn run(
    stdin: OwnedFd,
    stdout: OwnedFd,
    mut socket: Option<UnixStream>,
    workspace: &Workspace,
    mut test_run: TestRun,
    channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mut file = unsafe { std::fs::File::from_raw_fd(stdout.as_raw_fd()) };
    std::mem::forget(stdout);

    let _ = writeln!(file, "Running {} test(s)...\n", test_run.test_jobs.len());

    loop {
        if channel.is_terminated() {
            send_termination(&mut socket);
            break;
        }

        let all_done = update_test_statuses(&mut file, workspace, &mut test_run)?;

        if all_done {
            let state = workspace.state.read().unwrap();
            print_summary(&mut file, &test_run, &state.base_tasks);
            drop(state);
            send_termination(&mut socket);
            break;
        }

        match vtui::event::poll_with_custom_waker(&stdin, Some(&channel.waker), None) {
            Ok(vtui::event::Polled::ReadReady) => {
                let mut buf = [0u8; 64];
                let n = unsafe { libc::read(stdin.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
                if n == 0 {
                    let _ = writeln!(file, "\nDetached. Tests will continue running in background.");
                    send_termination(&mut socket);
                    break;
                }
            }
            Ok(vtui::event::Polled::Woken) | Ok(vtui::event::Polled::TimedOut) | Err(_) => {}
        }
    }

    Ok(())
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
            let prev_status = test_job.status;
            test_job.status = new_status;

            let display_name = format_test_name(test_job, &state.base_tasks);
            match new_status {
                TestJobStatus::Running if !matches!(prev_status, TestJobStatus::Running) => {
                    let _ = writeln!(file, "RUN  {}", display_name);
                }
                TestJobStatus::Passed => {
                    let _ = writeln!(file, "PASS {}", display_name);
                }
                TestJobStatus::Failed(code) => {
                    let _ = writeln!(file, "FAIL {} (exit code {})", display_name, code);
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
