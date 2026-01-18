use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Instant, SystemTime},
};

use crate::{
    config::{Enviroment, TaskConfigExpr, TaskConfigRc, WorkspaceConfig},
    log_storage::{JobId, LogId, Logs},
    process_manager::{MioChannel, ProcessIndex},
};

enum TerminatedCause {
    Unknown,
    Killed,
    Replaced,
    Reloaded,
}

pub struct Job {
    pub job_id: JobId,
    pub process_index: ProcessIndex,
    pub task: TaskConfigRc,
    pub started_at: Instant,
    pub log_start: LogId,
}

struct FinishedJob {
    job: Job,
    finished_at: Instant,
    log_end: LogId,
    termination_cause: TerminatedCause,
}

pub struct LatestConfig {
    modified_time: SystemTime,
    path: PathBuf,
    pub current: WorkspaceConfig<'static>,
}

impl LatestConfig {
    fn new(path: PathBuf) -> anyhow::Result<Self> {
        let metadata = path.metadata()?;
        let modified_time = metadata.modified()?;
        let content = std::fs::read_to_string(&path)?.leak();
        let current =
            crate::config::load_workspace_config_leaking(path.parent().unwrap(), content)?;
        Ok(Self {
            modified_time,
            path,
            current,
        })
    }
    fn refresh(&mut self) -> anyhow::Result<bool> {
        let metadata = self.path.metadata()?;
        let modified = metadata.modified()?;
        if self.modified_time == modified {
            return Ok(false);
        }
        let content = std::fs::read_to_string(&self.path)?.leak();
        let new_config =
            crate::config::load_workspace_config_leaking(self.current.base_path, content)?;
        self.current = new_config;
        self.modified_time = modified;
        return Ok(true);
    }

    fn update_base_tasks(&self, base_tasks: &mut Vec<BaseTask>) {
        for base_task in base_tasks.iter_mut() {
            base_task.removed = true;
        }
        for (name, task_index) in &self.current.map {
            let config = &self.current.tasks[*task_index];
            if let Some(base_task) = base_tasks.iter_mut().find(|task| task.name == *name) {
                base_task.removed = false;
                base_task.config = config;
            } else {
                base_tasks.push(BaseTask {
                    name,
                    config,
                    removed: false,
                    last_spawn: None,
                    finished_jobs: Vec::new(),
                    process_count: 0,
                });
            }
        }
    }
}

pub struct BaseTask {
    pub name: &'static str,
    pub config: &'static TaskConfigExpr<'static>,
    pub removed: bool,
    pub last_spawn: Option<Instant>,
    pub finished_jobs: Vec<usize>,
    pub process_count: u32,
}

/// Stores that state of the current workspace including:
/// - Past running tasks
/// - Current running tasks
/// - Scheduled Tasks
pub struct WorkspaceState {
    pub config: LatestConfig,
    pub base_tasks: Vec<BaseTask>,
    pub active_jobs: Vec<Job>,
    pub finished_jobs: Vec<Job>,
}

impl WorkspaceState {
    pub fn new(config_path: PathBuf) -> anyhow::Result<WorkspaceState> {
        let config = LatestConfig::new(config_path)?;
        let mut base_tasks = Vec::new();
        config.update_base_tasks(&mut base_tasks);
        Ok(WorkspaceState {
            config,
            base_tasks,
            active_jobs: Vec::new(),
            finished_jobs: Vec::new(),
        })
    }
}

pub struct Workspace {
    pub workspace_id: u32,
    pub logs: Arc<RwLock<Logs>>,
    pub state: RwLock<WorkspaceState>,
    pub process_channel: Arc<MioChannel>,
}
impl Workspace {
    pub fn state(&self) -> std::sync::RwLockReadGuard<'_, WorkspaceState> {
        self.state.read().unwrap()
    }
    pub fn spawn_task_simple_from_base_task(&self, base_task: usize) {
        let state = &mut *self.state.write().unwrap();
        let bs = &mut state.base_tasks[base_task];
        bs.process_count += 1;
        let job_id = JobId((bs.process_count.wrapping_shl(12)) | base_task as u32);
        let task = state.base_tasks[base_task]
            .config
            .eval(&Enviroment { profile: "" })
            .unwrap();
        self.process_channel
            .send(crate::process_manager::ProcessRequest::Spawn {
                task,
                workspace_id: self.workspace_id,
                job_id,
            });
    }
}
