use crate::config::TaskConfigRc;
use crate::log_storage::LogGroup;
use crate::event_loop::MioChannel;
use crate::workspace::JobIndex;

pub fn spawn_job(channel: &MioChannel, job_index: JobIndex, task: TaskConfigRc, workspace_id: u32, job_id: LogGroup) {
    channel.send(crate::event_loop::ProcessRequest::Spawn { task, job_index, workspace_id, job_id });
}
