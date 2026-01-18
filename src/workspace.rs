use crate::{
    config::{CARGO_AUTO_EXPR, Enviroment, TaskConfigExpr, TaskConfigRc, TaskKind, WorkspaceConfig},
    log_storage::{JobLogCorrelation, LogId, Logs},
    process_manager::MioChannel,
};
pub use job_index_list::JobIndexList;
use jsony_value::ValueMap;
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Instant, SystemTime},
};
mod job_index_list;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct BaseTaskIndex(pub u32);

impl BaseTaskIndex {
    pub fn idx(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct JobIndex(u32);

impl JobIndex {
    pub fn idx(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug)]
#[allow(unused)]
pub enum ExitCause {
    Unknown,
    Killed,
    Replaced,
    Reloaded,
}

pub struct Job {
    pub process_status: JobStatus,
    pub job_id: JobLogCorrelation,
    pub task: TaskConfigRc,
    pub started_at: Instant,
    pub log_start: LogId,
}

#[derive(Debug)]
pub enum JobPredicate {
    Terminated,
    TerminatedNaturallyAndSucessfully,
    Active,
}

#[derive(Debug)]
pub struct ScheduleRequirement {
    pub job: JobIndex,
    pub predicate: JobPredicate,
}

enum RequirementStatus {
    Pending,
    Met,
    Never,
}

impl ScheduleRequirement {
    fn status(&self, ws: &WorkspaceState) -> RequirementStatus {
        let job = &ws[self.job];
        match self.predicate {
            JobPredicate::Terminated => match &job.process_status {
                JobStatus::Scheduled { .. } => RequirementStatus::Pending,
                JobStatus::Starting => RequirementStatus::Pending,
                JobStatus::Running { .. } => RequirementStatus::Pending,
                JobStatus::Exited { .. } => RequirementStatus::Met,
                JobStatus::Cancelled => RequirementStatus::Met,
            },
            JobPredicate::TerminatedNaturallyAndSucessfully => match &job.process_status {
                JobStatus::Scheduled { .. } => RequirementStatus::Pending,
                JobStatus::Starting => RequirementStatus::Pending,
                JobStatus::Running { .. } => RequirementStatus::Pending,
                JobStatus::Cancelled => RequirementStatus::Never,
                JobStatus::Exited { cause: ExitCause::Killed, .. } => RequirementStatus::Never,
                JobStatus::Exited { status, .. } => {
                    if *status == 0 {
                        RequirementStatus::Met
                    } else {
                        RequirementStatus::Never
                    }
                }
            },
            JobPredicate::Active => match &job.process_status {
                JobStatus::Scheduled { .. } => RequirementStatus::Pending,
                JobStatus::Starting => RequirementStatus::Never,
                JobStatus::Cancelled => RequirementStatus::Never,
                JobStatus::Running { .. } => RequirementStatus::Met,
                JobStatus::Exited { .. } => RequirementStatus::Never,
            },
        }
    }
}

#[derive(Debug)]
pub enum JobStatus {
    Scheduled { after: Vec<ScheduleRequirement> },
    Starting,
    Running { process_index: usize },
    Exited { finished_at: Instant, log_end: LogId, cause: ExitCause, status: u32 },
    Cancelled,
}

impl JobStatus {
    pub fn is_pending_completion(&self) -> bool {
        match self {
            JobStatus::Scheduled { .. } => true,
            JobStatus::Starting => true,
            JobStatus::Running { .. } => true,
            JobStatus::Exited { .. } => false,
            JobStatus::Cancelled => false,
        }
    }
    pub fn is_successful_completion(&self) -> bool {
        match self {
            JobStatus::Exited { status, .. } => *status == 0,
            _ => false,
        }
    }
}

struct FinishedJob {
    job: Job,
    finished_at: Instant,
    log_end: LogId,
    termination_cause: ExitCause,
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
        let current = crate::config::load_workspace_config_leaking(path.parent().unwrap(), content)?;
        Ok(Self { modified_time, path, current })
    }
    fn refresh(&mut self) -> anyhow::Result<bool> {
        let metadata = self.path.metadata()?;
        let modified = metadata.modified()?;
        if self.modified_time == modified {
            return Ok(false);
        }
        let content = std::fs::read_to_string(&self.path)?.leak();
        let new_config = crate::config::load_workspace_config_leaking(self.current.base_path, content)?;
        self.current = new_config;
        self.modified_time = modified;
        return Ok(true);
    }

    fn update_base_tasks(
        &self,
        base_tasks: &mut Vec<BaseTask>,
        name_map: &mut std::collections::HashMap<&'static str, usize>,
    ) {
        for base_task in base_tasks.iter_mut() {
            base_task.removed = true;
        }
        for (name, config) in self.current.tasks {
            match name_map.entry(name) {
                std::collections::hash_map::Entry::Occupied(occupied_entry) => {
                    let base_task = &mut base_tasks[*occupied_entry.get()];
                    base_task.removed = false;
                    base_task.config = config;
                }
                std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(base_tasks.len());
                    base_tasks.push(BaseTask {
                        name,
                        config,
                        removed: false,
                        last_spawn: None,
                        jobs: JobIndexList::default(),
                    });
                }
            }
        }
    }
}

pub struct BaseTask {
    pub name: &'static str,
    pub config: &'static TaskConfigExpr<'static>,
    pub removed: bool,
    pub last_spawn: Option<Instant>,
    pub jobs: JobIndexList,
}

/// Stores that state of the current workspace including:
/// - Past running tasks
/// - Current running tasks
/// - Scheduled Tasks
pub struct WorkspaceState {
    pub config: LatestConfig,
    pub base_tasks: Vec<BaseTask>,
    pub change_number: u32,
    pub name_map: std::collections::HashMap<&'static str, usize>,
    pub jobs: Vec<Job>,
}

impl WorkspaceState {
    pub fn base_index_by_name(&mut self, name: &str) -> Option<usize> {
        if let Some(index) = self.name_map.get(name) {
            return Some(*index);
        }
        if name == "~cargo" {
            let index = self.base_tasks.len();
            self.base_tasks.push(BaseTask {
                name: "~cargo",
                config: &CARGO_AUTO_EXPR,
                removed: false,
                last_spawn: None,
                jobs: JobIndexList::default(),
            });
            self.name_map.insert("~cargo", index);
            return Some(index);
        }
        None
    }
    fn spawn_task(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        base_task: usize,
        log_start: LogId,
        params: ValueMap,
        profile: &str,
    ) -> JobIndex {
        let bt = &mut self.base_tasks[base_task];
        let mut pred = Vec::new();

        for job_index in bt.jobs.terminate_scheduled() {
            let job = &mut self.jobs[job_index.idx()];
            // todo should handle scheuild
            match &job.process_status {
                JobStatus::Scheduled { .. } => {
                    job.process_status = JobStatus::Cancelled;
                }
                unexpected => panic!("Unexpected job status when terminating scheduled job: {:?}", unexpected),
            }
        }

        for job_index in bt.jobs.running() {
            let job = &mut self.jobs[job_index.idx()];
            // todo should handle scheuild
            match &job.process_status {
                JobStatus::Running { process_index } => {
                    pred.push(ScheduleRequirement { job: *job_index, predicate: JobPredicate::Terminated });
                    channel.send(crate::process_manager::ProcessRequest::TerminateJob {
                        job_id: job.job_id,
                        process_index: *process_index,
                    })
                }
                _ => (),
            }
        }
        let task = self.base_tasks[base_task].config.eval(&Enviroment { profile, param: params }).unwrap();

        'outer: for dep_alias in task.config().require {
            let Some(&dep_base_task) = self.name_map.get(&**dep_alias) else {
                kvlog::error!("unknown alias", dep_alias);
                continue;
            };
            let dep_config = self.base_tasks[dep_base_task].config;

            match dep_config.kind {
                TaskKind::Action => {
                    if dep_config.cache.is_some() {
                        let spawner = &self.base_tasks[dep_base_task];
                        for ji in spawner.jobs.all().iter().rev() {
                            let job = &self[*ji];
                            if matches!(job.process_status, JobStatus::Cancelled) {
                                continue;
                            }
                            if job.process_status.is_successful_completion() {
                                continue 'outer;
                            }
                            if job.process_status.is_pending_completion() {
                                pred.push(ScheduleRequirement {
                                    job: *ji,
                                    predicate: JobPredicate::TerminatedNaturallyAndSucessfully,
                                });
                                continue 'outer;
                            }
                            break;
                        }
                        let new_job =
                            self.spawn_task(workspace_id, channel, dep_base_task, log_start, ValueMap::new(), "");
                        pred.push(ScheduleRequirement {
                            job: new_job,
                            predicate: JobPredicate::TerminatedNaturallyAndSucessfully,
                        });
                    } else {
                        let new_job =
                            self.spawn_task(workspace_id, channel, dep_base_task, log_start, ValueMap::new(), "");
                        pred.push(ScheduleRequirement {
                            job: new_job,
                            predicate: JobPredicate::TerminatedNaturallyAndSucessfully,
                        });
                    }
                }
                TaskKind::Service => {
                    let spawner = &self.base_tasks[dep_base_task];
                    for &ji in spawner.jobs.running() {
                        pred.push(ScheduleRequirement { job: ji, predicate: JobPredicate::Active });
                        continue 'outer;
                    }
                    let new_job =
                        self.spawn_task(workspace_id, channel, dep_base_task, log_start, ValueMap::new(), "");
                    pred.push(ScheduleRequirement { job: new_job, predicate: JobPredicate::Active });
                }
            }
        }

        let job_index = JobIndex(self.jobs.len() as u32);
        let bt = &mut self.base_tasks[base_task];
        let pc = bt.jobs.len();
        let job_id = JobLogCorrelation((pc.wrapping_shl(12) as u32) | base_task as u32);

        let spawn = pred.is_empty();
        if spawn {
            bt.jobs.push_active(job_index);
        } else {
            bt.jobs.push_scheduled(job_index);
        }

        self.jobs.push(Job {
            process_status: if !spawn { JobStatus::Scheduled { after: pred } } else { JobStatus::Starting },
            job_id,
            task: task.clone(),
            started_at: Instant::now(),
            log_start,
        });
        if spawn {
            channel.send(crate::process_manager::ProcessRequest::Spawn { task, job_index, workspace_id, job_id });
        }
        job_index
    }
}

impl std::ops::Index<JobIndex> for WorkspaceState {
    type Output = Job;
    fn index(&self, index: JobIndex) -> &Self::Output {
        &self.jobs[index.idx()]
    }
}
impl std::ops::IndexMut<JobIndex> for WorkspaceState {
    fn index_mut(&mut self, index: JobIndex) -> &mut Self::Output {
        &mut self.jobs[index.idx()]
    }
}

pub enum Scheduled {
    Ready(JobIndex),
    Never(JobIndex),
    None,
}

impl WorkspaceState {
    #[track_caller]
    pub fn update_job_status(&mut self, job_index: JobIndex, status: JobStatus) {
        let job = &mut self.jobs[job_index.idx()];
        let bt = &mut self.base_tasks[job.job_id.base_task_index() as usize];

        use JobStatus as S;
        match (&job.process_status, &status) {
            (S::Scheduled { .. }, S::Cancelled) => {
                bt.jobs.set_terminal(job_index);
            }
            (S::Starting, S::Cancelled) => {
                // todo maybe we need to do something here
                bt.jobs.set_terminal(job_index);
            }
            (S::Running { .. }, S::Cancelled) => {
                bt.jobs.set_terminal(job_index);
            }
            (S::Scheduled { .. }, S::Starting {}) => {
                bt.jobs.set_active(job_index);
            }
            (S::Running { .. }, S::Exited { .. }) => {
                bt.jobs.set_terminal(job_index);
            }
            (S::Starting, S::Running { .. }) => {}
            (prev, to) => {
                let caller = std::panic::Location::caller();
                kvlog::error!(
                    "Attempted change task with invalid self transition",
                    ?job_index,
                    ?prev,
                    ?to,
                    from = format!("{}:{}", caller.file(), caller.line())
                );
            }
        }
        job.process_status = status;
    }
    pub fn new(config_path: PathBuf) -> anyhow::Result<WorkspaceState> {
        let config = LatestConfig::new(config_path)?;
        let mut base_tasks = Vec::new();
        let mut name_map = std::collections::HashMap::new();
        config.update_base_tasks(&mut base_tasks, &mut name_map);
        Ok(WorkspaceState { change_number: 0, config, name_map, base_tasks, jobs: Vec::new() })
    }

    /// Brute force scheduling useful testing will provided an optimized alternative later
    pub fn next_scheduled(&self) -> Scheduled {
        for bs in &self.base_tasks {
            'pending: for &job_index in bs.jobs.scheduled() {
                let JobStatus::Scheduled { after } = &self[job_index].process_status else {
                    kvlog::error!("Inconsistent JobStatus in WorkspaceState::next_ready_task",
                     status = ?&self[job_index].process_status, ?job_index);
                    continue;
                };
                kvlog::info!("checking req", ?after);
                for req in after {
                    match req.status(&self) {
                        RequirementStatus::Pending => continue 'pending,
                        RequirementStatus::Never => return Scheduled::Never(job_index),
                        RequirementStatus::Met => (),
                    }
                }
                return Scheduled::Ready(job_index);
            }
        }
        Scheduled::None
    }
}

pub struct Workspace {
    pub workspace_id: u32,
    pub logs: Arc<RwLock<Logs>>,
    pub state: RwLock<WorkspaceState>,
    pub process_channel: Arc<MioChannel>,
}

pub fn extract_rust_panic_from_line(line: &str) -> Option<(&str, u64)> {
    let (file, nums) = line.strip_prefix("thread")?.split_once(") panicked at ")?.1.split_once(":")?;
    let (line_str, _) = nums.split_once(":")?;
    let line = line_str.parse::<u64>().ok()?;
    Some((file, line))
}
impl Workspace {
    pub fn last_rust_panic(&self) -> Option<(String, u64)> {
        let logs = self.logs.read().unwrap();
        let (a, b) = logs.slices();
        for s in [b, a] {
            for entry in s {
                let text = unsafe { entry.text(&logs) };
                if let Some((file, line)) = extract_rust_panic_from_line(&text) {
                    return Some((file.to_string(), line));
                }
            }
        }
        None
    }
    pub fn state(&self) -> std::sync::RwLockReadGuard<'_, WorkspaceState> {
        self.state.read().unwrap()
    }
    pub fn restart_task(&self, base_task: BaseTaskIndex, params: ValueMap, profile: &str) {
        let state = &mut *self.state.write().unwrap();
        state.change_number = state.change_number.wrapping_add(1);
        state.spawn_task(
            self.workspace_id,
            &self.process_channel,
            base_task.idx(),
            self.logs.read().unwrap().tail(),
            params,
            profile,
        );
    }

    pub fn terminate_tasks(&self, base_task: BaseTaskIndex) {
        let state = &mut *self.state.write().unwrap();
        state.change_number = state.change_number.wrapping_add(1);
        let bt = &mut state.base_tasks[base_task.idx()];
        for job_index in bt.jobs.non_terminal() {
            let job = &state.jobs[job_index.idx()];
            if let JobStatus::Running { process_index } = &job.process_status {
                self.process_channel.send(crate::process_manager::ProcessRequest::TerminateJob {
                    job_id: job.job_id,
                    process_index: *process_index,
                })
            }
        }
    }
    pub fn spawn_task_simple_from_base_task(&self, base_task: usize) {
        let state = &mut *self.state.write().unwrap();
        let job_index = JobIndex(state.jobs.len() as u32);
        state.change_number = state.change_number.wrapping_add(1);
        let bt = &mut state.base_tasks[base_task];
        let pc = bt.jobs.len();
        let job_id = JobLogCorrelation((pc.wrapping_shl(12) as u32) | base_task as u32);
        bt.jobs.push_active(job_index);

        let task =
            state.base_tasks[base_task].config.eval(&Enviroment { profile: "", param: ValueMap::new() }).unwrap();

        state.jobs.push(Job {
            process_status: JobStatus::Starting,
            job_id,
            task: task.clone(),
            started_at: Instant::now(),
            log_start: self.logs.write().unwrap().tail(),
        });

        self.process_channel.send(crate::process_manager::ProcessRequest::Spawn {
            task,
            job_index,
            workspace_id: self.workspace_id,
            job_id,
        });
    }
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;

    #[test]
    fn test_job_status_is_pending_completion() {
        assert!(JobStatus::Scheduled { after: vec![] }.is_pending_completion());
        assert!(JobStatus::Starting.is_pending_completion());
        assert!(JobStatus::Running { process_index: 0 }.is_pending_completion());
        assert!(!JobStatus::Exited {
            finished_at: Instant::now(),
            log_end: LogId(0),
            cause: ExitCause::Unknown,
            status: 0
        }
        .is_pending_completion());
        assert!(!JobStatus::Cancelled.is_pending_completion());
    }

    #[test]
    fn test_job_status_is_successful_completion() {
        assert!(!JobStatus::Scheduled { after: vec![] }.is_successful_completion());
        assert!(!JobStatus::Starting.is_successful_completion());
        assert!(!JobStatus::Running { process_index: 0 }.is_successful_completion());
        assert!(!JobStatus::Cancelled.is_successful_completion());

        assert!(JobStatus::Exited {
            finished_at: Instant::now(),
            log_end: LogId(0),
            cause: ExitCause::Unknown,
            status: 0
        }
        .is_successful_completion());

        assert!(!JobStatus::Exited {
            finished_at: Instant::now(),
            log_end: LogId(0),
            cause: ExitCause::Unknown,
            status: 1
        }
        .is_successful_completion());

        // Note: is_successful_completion only checks status code, not exit cause.
        // The ScheduleRequirement::status method does check for Killed separately
        // when evaluating the TerminatedNaturallyAndSucessfully predicate.
        assert!(JobStatus::Exited {
            finished_at: Instant::now(),
            log_end: LogId(0),
            cause: ExitCause::Killed,
            status: 0
        }
        .is_successful_completion());
    }

    #[test]
    fn panic_split_line_tests() {
        let line = "thread 'log_storage::tests::test_rotation_on_max_lines' (143789) panicked at src/log_storage.rs:639:9:";
        let extracted = extract_rust_panic_from_line(line);
        assert_eq!(extracted, Some(("src/log_storage.rs", 639)));
    }
}
