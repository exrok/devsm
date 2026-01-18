use crate::{
    cli::TestFilter,
    config::{CARGO_AUTO_EXPR, CacheKeyInput, Enviroment, TaskConfigExpr, TaskConfigRc, TaskKind, WorkspaceConfig},
    log_storage::{LogGroup, LogId, Logs},
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
    pub fn new_or_panic(index: usize) -> BaseTaskIndex {
        if index > 0xfff_usize {
            panic!("BaseTaskIndex overflow for index {}", index);
        }
        BaseTaskIndex(index as u32)
    }
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

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn from_usize(idx: usize) -> Self {
        Self(idx as u32)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExitCause {
    Unknown,
    Killed,
    Restarted,
}

pub struct Job {
    pub process_status: JobStatus,
    pub log_group: LogGroup,
    pub task: TaskConfigRc,
    pub started_at: Instant,
    #[expect(unused, reason = "TODO use an optimization for log filtering")]
    pub log_start: LogId,
    /// Computed cache key for cache invalidation. Empty string means no key-based caching.
    pub cache_key: String,
    /// Profile used when spawning this job.
    pub spawn_profile: String,
    /// Parameters used when spawning this job.
    pub spawn_params: ValueMap<'static>,
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
                JobStatus::Starting => RequirementStatus::Pending,
                JobStatus::Cancelled => RequirementStatus::Never,
                JobStatus::Running { .. } => RequirementStatus::Met,
                JobStatus::Exited { .. } => RequirementStatus::Never,
            },
        }
    }
}

#[derive(Debug)]
pub enum JobStatus {
    Scheduled {
        after: Vec<ScheduleRequirement>,
    },
    Starting,
    Running {
        process_index: usize,
    },
    Exited {
        finished_at: Instant,
        #[expect(unused, reason = "TODO optimization in log filtering")]
        log_end: LogId,
        cause: ExitCause,
        status: u32,
    },
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

pub struct LatestConfig {
    modified_time: SystemTime,
    path: PathBuf,
    pub current: WorkspaceConfig<'static>,
}

impl LatestConfig {
    fn new(path: PathBuf) -> Result<Self, crate::config::ConfigError> {
        let metadata = path.metadata().map_err(|e| crate::config::ConfigError {
            message: format!("error: failed to read {}: {}\n", path.display(), e),
        })?;
        let modified_time = metadata.modified().map_err(|e| crate::config::ConfigError {
            message: format!("error: failed to get modification time for {}: {}\n", path.display(), e),
        })?;
        let content = std::fs::read_to_string(&path)
            .map_err(|e| crate::config::ConfigError {
                message: format!("error: failed to read {}: {}\n", path.display(), e),
            })?
            .leak();
        let current = crate::config::load_workspace_config_capturing(&path, content)?;
        Ok(Self { modified_time, path, current })
    }
    fn refresh(&mut self) -> anyhow::Result<bool> {
        let metadata = self.path.metadata()?;
        let modified = metadata.modified()?;
        if self.modified_time == modified {
            return Ok(false);
        }
        let content = std::fs::read_to_string(&self.path)?.leak();
        let config_path = self.current.base_path.join("devsm.toml");
        let new_config = crate::config::load_workspace_config_capturing(&config_path, content)
            .map_err(|e| anyhow::anyhow!("{}", e.message))?;
        self.current = new_config;
        self.modified_time = modified;
        Ok(true)
    }

    fn update_base_tasks(
        &self,
        base_tasks: &mut Vec<BaseTask>,
        name_map: &mut hashbrown::HashMap<&'static str, BaseTaskIndex>,
    ) {
        for base_task in base_tasks.iter_mut() {
            base_task.removed = true;
        }
        for (name, config) in self.current.tasks {
            match name_map.entry(name) {
                hashbrown::hash_map::Entry::Occupied(occupied_entry) => {
                    let base_task = &mut base_tasks[occupied_entry.get().idx()];
                    base_task.removed = false;
                    base_task.config = config;
                }
                hashbrown::hash_map::Entry::Vacant(vacant_entry) => {
                    if base_tasks.len() > u32::MAX as usize {
                        panic!("Too many base tasks");
                    }
                    vacant_entry.insert(BaseTaskIndex(base_tasks.len() as u32));
                    base_tasks.push(BaseTask {
                        name,
                        config,
                        removed: false,
                        jobs: JobIndexList::default(),
                        profile_change_counter: 0,
                        last_profile: None,
                        test_info: None,
                    });
                }
            }
        }
        for (base_name, variants) in self.current.tests {
            for (variant_index, config) in variants.iter().enumerate() {
                let task_name: &'static str = if variants.len() == 1 {
                    format!("~test:{}", base_name).leak()
                } else {
                    format!("~test:{}:{}", base_name, variant_index).leak()
                };
                let task_config = config.to_task_config_expr();
                let test_info = Some(TestInfo { base_name, variant_index: variant_index as u32 });

                match name_map.entry(task_name) {
                    hashbrown::hash_map::Entry::Occupied(occupied_entry) => {
                        let base_task = &mut base_tasks[occupied_entry.get().idx()];
                        base_task.removed = false;
                        base_task.config = task_config;
                        base_task.test_info = test_info;
                    }
                    hashbrown::hash_map::Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(BaseTaskIndex::new_or_panic(base_tasks.len()));
                        base_tasks.push(BaseTask {
                            name: task_name,
                            config: task_config,
                            removed: false,
                            jobs: JobIndexList::default(),
                            profile_change_counter: 0,
                            last_profile: None,
                            test_info,
                        });
                    }
                }
            }
        }
    }
}

/// Test-specific metadata for base tasks that are tests.
pub struct TestInfo {
    /// The test group name (e.g., "frontend" for test variant "frontend:0").
    pub base_name: &'static str,
    pub variant_index: u32,
}

pub struct BaseTask {
    pub name: &'static str,
    pub config: &'static TaskConfigExpr<'static>,
    pub removed: bool,
    pub jobs: JobIndexList,
    /// Counter incremented when the task's profile changes (not on first run).
    /// Used as cache key input for `profile_changed` invalidation.
    pub profile_change_counter: u32,
    /// The profile used for the last spawn (for tracking profile changes).
    pub last_profile: Option<String>,
    /// Test-specific metadata. Present only for tests (kind == Test).
    pub test_info: Option<TestInfo>,
}

impl BaseTask {
    /// Updates the profile change counter for a task if the profile changed.
    ///
    /// Does not increment on first run (when `last_profile` is `None`).
    /// Returns the new profile as a leaked static string.
    fn update_profile_tracking(&mut self, profile: &str) {
        if let Some(last) = &self.last_profile {
            if last != profile {
                self.profile_change_counter += 1;
            } else {
                return;
            }
        }
        self.last_profile = Some(profile.into());
    }
}

/// Status of a test job execution.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TestJobStatus {
    Pending,
    Running,
    Passed,
    Failed(i32),
}

/// A single test job within a test run.
pub struct TestJob {
    /// Index into base_tasks for this test.
    pub base_task_index: BaseTaskIndex,
    pub job_index: JobIndex,
    pub status: TestJobStatus,
}

/// Tracks the state of a test run (multiple tests executed together).
pub struct TestRun {
    pub run_id: u32,
    pub started_at: Instant,
    pub test_jobs: Vec<TestJob>,
}

/// Checks if a running service job matches the required profile and parameters.
fn service_matches_require(job: &Job, require_profile: &str, require_params: &ValueMap) -> bool {
    if !require_profile.is_empty() && job.spawn_profile != require_profile {
        return false;
    }
    require_params == &job.spawn_params
}

/// Stores that state of the current workspace including:
/// - Past running tasks
/// - Current running tasks
/// - Scheduled Tasks
pub struct WorkspaceState {
    pub config: LatestConfig,
    pub base_tasks: Vec<BaseTask>,
    pub change_number: u32,
    pub name_map: hashbrown::HashMap<&'static str, BaseTaskIndex>,
    pub jobs: Vec<Job>,
    pub active_test_run: Option<TestRun>,
    pub action_jobs: JobIndexList,
    pub test_jobs: JobIndexList,
}

impl WorkspaceState {
    /// Computes a cache key from the cache configuration.
    ///
    /// The key is a concatenation of all key inputs, formatted as:
    /// - `modified:<path>=<mtime_nanos>;` for file modification times
    /// - `profile_changed:<task>=<counter>;` for profile change counters
    ///
    /// Returns an empty string if there are no key inputs.
    fn compute_cache_key(&self, cache_key_inputs: &[CacheKeyInput]) -> String {
        if cache_key_inputs.is_empty() {
            return String::new();
        }
        let mut key = String::new();
        for input in cache_key_inputs {
            match input {
                CacheKeyInput::Modified(path) => {
                    let full_path = self.config.current.base_path.join(path);
                    let mtime = match std::fs::metadata(&full_path).and_then(|m| m.modified()) {
                        Ok(time) => time.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_nanos()),
                        Err(_) => 0,
                    };
                    key.push_str("modified:");
                    key.push_str(path);
                    key.push('=');
                    key.push_str(&mtime.to_string());
                    key.push(';');
                }
                CacheKeyInput::ProfileChanged(task_name) => {
                    let counter = self
                        .name_map
                        .get(*task_name)
                        .map_or(0, |&bti| self.base_tasks[bti.idx()].profile_change_counter);
                    key.push_str("profile_changed:");
                    key.push_str(task_name);
                    key.push('=');
                    key.push_str(&counter.to_string());
                    key.push(';');
                }
            }
        }
        key
    }

    /// Computes a cache key that includes profile and parameters from require.
    ///
    /// Extends [`compute_cache_key`] by appending the profile and parameters
    /// used to spawn this dependency, ensuring different profile/param
    /// combinations result in different cache keys.
    fn compute_cache_key_with_require(
        &self,
        cache_key_inputs: &[CacheKeyInput],
        profile: &str,
        params: &ValueMap,
    ) -> String {
        let mut key = self.compute_cache_key(cache_key_inputs);
        if !profile.is_empty() {
            key.push_str("require_profile:");
            key.push_str(profile);
            key.push(';');
        }
        if !params.entries().is_empty() {
            key.push_str("require_params:");
            for (k, v) in params.entries() {
                key.push_str(k);
                key.push('=');
                key.push_str(&v.to_string());
                key.push(',');
            }
            key.push(';');
        }
        key
    }

    pub fn base_index_by_name(&mut self, name: &str) -> Option<BaseTaskIndex> {
        if let Some(index) = self.name_map.get(name) {
            return Some(*index);
        }
        if name == "~cargo" {
            let index = self.base_tasks.len();
            self.base_tasks.push(BaseTask {
                name: "~cargo",
                config: &CARGO_AUTO_EXPR,
                removed: false,
                jobs: JobIndexList::default(),
                profile_change_counter: 0,
                last_profile: None,
                test_info: None,
            });
            if index > u32::MAX as usize {
                panic!("Too many base tasks");
            }
            let index = BaseTaskIndex(index as u32);
            self.name_map.insert("~cargo", index);
            return Some(index);
        }
        None
    }

    fn refresh_config(&mut self) {
        let Ok(changed) = self.config.refresh() else {
            return;
        };
        if changed {
            self.config.update_base_tasks(&mut self.base_tasks, &mut self.name_map);
        }
    }

    fn spawn_task(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        base_task: BaseTaskIndex,
        log_start: LogId,
        params: ValueMap,
        profile: &str,
    ) -> JobIndex {
        let bt = &mut self.base_tasks[base_task.idx()];
        bt.update_profile_tracking(profile);
        let mut pred = Vec::new();

        for job_index in bt.jobs.terminate_scheduled() {
            let job = &mut self.jobs[job_index.idx()];
            match &job.process_status {
                JobStatus::Scheduled { .. } => {
                    job.process_status = JobStatus::Cancelled;
                }
                unexpected => panic!("Unexpected job status when terminating scheduled job: {:?}", unexpected),
            }
        }

        for job_index in bt.jobs.running() {
            let job = &mut self.jobs[job_index.idx()];
            let JobStatus::Running { process_index } = &job.process_status else {
                continue;
            };
            pred.push(ScheduleRequirement { job: *job_index, predicate: JobPredicate::Terminated });
            channel.send(crate::process_manager::ProcessRequest::TerminateJob {
                job_id: job.log_group,
                process_index: *process_index,
                exit_cause: ExitCause::Restarted,
            });
        }
        let task = bt.config.eval(&Enviroment { profile, param: params.clone() }).unwrap();

        'outer: for dep_call in task.config().require {
            let dep_name = &*dep_call.name;
            let dep_profile = dep_call.profile.unwrap_or("");
            let dep_params = dep_call.vars.clone();

            let Some(&dep_base_task) = self.name_map.get(dep_name) else {
                kvlog::error!("unknown alias", dep_name);
                continue;
            };
            let dep_config = &self.base_tasks[dep_base_task.idx()].config;

            match dep_config.kind {
                TaskKind::Action => {
                    let Some(cache_config) = dep_config.cache.as_ref() else {
                        let new_job = self.spawn_task(
                            workspace_id,
                            channel,
                            dep_base_task,
                            log_start,
                            dep_params.clone(),
                            dep_profile,
                        );
                        pred.push(ScheduleRequirement {
                            job: new_job,
                            predicate: JobPredicate::TerminatedNaturallyAndSucessfully,
                        });
                        continue;
                    };

                    let expected_cache_key =
                        self.compute_cache_key_with_require(cache_config.key, dep_profile, &dep_params);
                    let spawner = &self.base_tasks[dep_base_task.idx()];

                    // When require specifies profile/params, we need to find a job with matching
                    // cache key. Don't break early on non-matching keys since different param
                    // combinations create different "cache buckets".
                    let mut found_pending = None;
                    for ji in spawner.jobs.all().iter().rev() {
                        let job = &self[*ji];
                        if matches!(job.process_status, JobStatus::Cancelled) {
                            continue;
                        }
                        if job.process_status.is_successful_completion() {
                            if expected_cache_key.is_empty() || job.cache_key == expected_cache_key {
                                continue 'outer;
                            }
                            continue;
                        }
                        if job.process_status.is_pending_completion() {
                            if expected_cache_key.is_empty() || job.cache_key == expected_cache_key {
                                found_pending = Some(*ji);
                                break;
                            }
                            continue;
                        }
                    }
                    if let Some(pending_job) = found_pending {
                        pred.push(ScheduleRequirement {
                            job: pending_job,
                            predicate: JobPredicate::TerminatedNaturallyAndSucessfully,
                        });
                        continue 'outer;
                    }
                    let new_job =
                        self.spawn_task(workspace_id, channel, dep_base_task, log_start, dep_params, dep_profile);
                    pred.push(ScheduleRequirement {
                        job: new_job,
                        predicate: JobPredicate::TerminatedNaturallyAndSucessfully,
                    });
                }
                TaskKind::Service => {
                    let spawner = &self.base_tasks[dep_base_task.idx()];
                    for &ji in spawner.jobs.running() {
                        let job = &self[ji];
                        if service_matches_require(job, dep_profile, &dep_params) {
                            pred.push(ScheduleRequirement { job: ji, predicate: JobPredicate::Active });
                            continue 'outer;
                        }
                    }
                    let new_job =
                        self.spawn_task(workspace_id, channel, dep_base_task, log_start, dep_params, dep_profile);
                    pred.push(ScheduleRequirement { job: new_job, predicate: JobPredicate::Active });
                }
                TaskKind::Test => {}
            }
        }

        let cache_key = task
            .config()
            .cache
            .as_ref()
            .map_or(String::new(), |c| self.compute_cache_key_with_require(c.key, profile, &params));

        let job_index = JobIndex(self.jobs.len() as u32);
        let bt = &mut self.base_tasks[base_task.idx()];
        let pc = bt.jobs.len();
        let job_id = LogGroup::new(base_task, pc);

        let spawn = pred.is_empty();
        let task_kind = bt.config.kind;
        if spawn {
            bt.jobs.push_active(job_index);
        } else {
            bt.jobs.push_scheduled(job_index);
        }

        let global_list = match task_kind {
            TaskKind::Action => Some(&mut self.action_jobs),
            TaskKind::Test => Some(&mut self.test_jobs),
            TaskKind::Service => None,
        };
        if let Some(list) = global_list {
            if spawn {
                list.push_active(job_index);
            } else {
                list.push_scheduled(job_index);
            }
        }

        self.jobs.push(Job {
            process_status: if !spawn { JobStatus::Scheduled { after: pred } } else { JobStatus::Starting },
            log_group: job_id,
            task: task.clone(),
            started_at: Instant::now(),
            log_start,
            cache_key,
            spawn_profile: profile.to_string(),
            spawn_params: params.to_owned(),
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

impl WorkspaceState {
    /// Returns all job indices for tasks of the given kind.
    pub fn jobs_by_kind(&self, kind: TaskKind) -> &[JobIndex] {
        match kind {
            TaskKind::Action => self.action_jobs.all(),
            TaskKind::Test => self.test_jobs.all(),
            TaskKind::Service => &[],
        }
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
        let job_id = job.log_group;
        let base_task = &mut self.base_tasks[job_id.base_task_index().idx()];
        let task_kind = base_task.config.kind;
        let jobs_list = &mut base_task.jobs;

        use JobStatus as S;
        match (&job.process_status, &status) {
            (S::Scheduled { .. }, S::Cancelled) => {
                jobs_list.set_terminal(job_index);
            }
            (S::Starting, S::Cancelled) => {
                jobs_list.set_terminal(job_index);
            }
            (S::Running { .. }, S::Cancelled) => {
                jobs_list.set_terminal(job_index);
            }
            (S::Scheduled { .. }, S::Starting) => {
                jobs_list.set_active(job_index);
            }
            (S::Running { .. }, S::Exited { .. }) => {
                jobs_list.set_terminal(job_index);
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

        let global_list = match task_kind {
            TaskKind::Action => Some(&mut self.action_jobs),
            TaskKind::Test => Some(&mut self.test_jobs),
            TaskKind::Service => None,
        };
        if let Some(list) = global_list {
            match (&job.process_status, &status) {
                (S::Scheduled { .. }, S::Cancelled)
                | (S::Starting, S::Cancelled)
                | (S::Running { .. }, S::Cancelled)
                | (S::Running { .. }, S::Exited { .. }) => {
                    list.set_terminal(job_index);
                }
                (S::Scheduled { .. }, S::Starting) => {
                    list.set_active(job_index);
                }
                _ => {}
            }
        }

        job.process_status = status;
    }
    pub fn new(config_path: PathBuf) -> Result<WorkspaceState, crate::config::ConfigError> {
        let config = LatestConfig::new(config_path)?;
        let mut base_tasks = Vec::new();
        let mut name_map = hashbrown::HashMap::new();
        config.update_base_tasks(&mut base_tasks, &mut name_map);
        Ok(WorkspaceState {
            change_number: 0,
            config,
            name_map,
            base_tasks,
            jobs: Vec::new(),
            active_test_run: None,
            action_jobs: JobIndexList::default(),
            test_jobs: JobIndexList::default(),
        })
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
                    match req.status(self) {
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
                if let Some((file, line)) = extract_rust_panic_from_line(text) {
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
        state.refresh_config();
        state.spawn_task(
            self.workspace_id,
            &self.process_channel,
            base_task,
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
            let JobStatus::Running { process_index } = &job.process_status else {
                continue;
            };
            self.process_channel.send(crate::process_manager::ProcessRequest::TerminateJob {
                job_id: job.log_group,
                process_index: *process_index,
                exit_cause: ExitCause::Killed,
            });
        }
    }

    /// Starts a test run with the given filters.
    /// Returns the test run containing all scheduled test jobs.
    pub fn start_test_run(&self, filters: &[TestFilter]) -> TestRun {
        let state = &mut *self.state.write().unwrap();
        state.change_number = state.change_number.wrapping_add(1);
        state.refresh_config();
        let log_start = self.logs.read().unwrap().tail();

        let run_id = state.active_test_run.as_ref().map_or(0, |r| r.run_id + 1);

        struct MatchedTest {
            base_task_idx: BaseTaskIndex,
            task_config: TaskConfigRc,
        }
        let mut matched_tests = Vec::new();
        for (base_task_idx, base_task) in state.base_tasks.iter().enumerate() {
            if base_task.removed {
                continue;
            }
            let Some(test_info) = &base_task.test_info else {
                continue;
            };
            let tags = base_task.config.tags;
            if !matches_test_filters(test_info.base_name, tags, filters) {
                continue;
            }
            let env = Enviroment { profile: "", param: ValueMap::new() };
            let Ok(task_config) = base_task.config.eval(&env) else {
                kvlog::error!("Failed to evaluate test config", name = base_task.name);
                continue;
            };
            matched_tests.push(MatchedTest { base_task_idx: BaseTaskIndex::new_or_panic(base_task_idx), task_config });
        }

        let mut test_jobs = Vec::new();
        for matched in matched_tests {
            let task_config = matched.task_config;

            // Collect require calls to avoid borrow issues
            struct RequireInfo {
                name: String,
                profile: String,
                params: ValueMap<'static>,
            }
            let requires: Vec<RequireInfo> = task_config
                .config()
                .require
                .iter()
                .map(|tc| RequireInfo {
                    name: (*tc.name).to_string(),
                    profile: tc.profile.unwrap_or("").to_string(),
                    params: tc.vars.clone().to_owned(),
                })
                .collect();

            let mut pred = Vec::new();
            for req in &requires {
                let Some(&dep_base_task) = state.name_map.get(req.name.as_str()) else {
                    continue;
                };
                let dep_config = &state.base_tasks[dep_base_task.idx()].config;
                match dep_config.kind {
                    TaskKind::Action => {
                        if let Some(cache_config) = dep_config.cache.as_ref() {
                            let expected_cache_key =
                                state.compute_cache_key_with_require(cache_config.key, &req.profile, &req.params);
                            let spawner = &state.base_tasks[dep_base_task.idx()];
                            let mut found_cached = false;
                            for ji in spawner.jobs.all().iter().rev() {
                                let job = &state.jobs[ji.idx()];
                                if matches!(job.process_status, JobStatus::Cancelled) {
                                    continue;
                                }
                                if job.process_status.is_successful_completion() {
                                    if expected_cache_key.is_empty() || job.cache_key == expected_cache_key {
                                        found_cached = true;
                                        break;
                                    }
                                    continue;
                                }
                            }
                            if found_cached {
                                continue;
                            }
                        }
                        let new_job = state.spawn_task(
                            self.workspace_id,
                            &self.process_channel,
                            dep_base_task,
                            log_start,
                            req.params.clone(),
                            &req.profile,
                        );
                        pred.push(ScheduleRequirement {
                            job: new_job,
                            predicate: JobPredicate::TerminatedNaturallyAndSucessfully,
                        });
                    }
                    TaskKind::Service => {
                        let spawner = &state.base_tasks[dep_base_task.idx()];
                        let mut found_running = false;
                        for &ji in spawner.jobs.running() {
                            let job = &state.jobs[ji.idx()];
                            if service_matches_require(job, &req.profile, &req.params) {
                                pred.push(ScheduleRequirement { job: ji, predicate: JobPredicate::Active });
                                found_running = true;
                                break;
                            }
                        }
                        if !found_running {
                            let new_job = state.spawn_task(
                                self.workspace_id,
                                &self.process_channel,
                                dep_base_task,
                                log_start,
                                req.params.clone(),
                                &req.profile,
                            );
                            pred.push(ScheduleRequirement { job: new_job, predicate: JobPredicate::Active });
                        }
                    }
                    TaskKind::Test => {}
                }
            }

            let cache_key =
                task_config.config().cache.as_ref().map_or(String::new(), |c| state.compute_cache_key(c.key));

            let job_index = JobIndex(state.jobs.len() as u32);
            let base_task = &mut state.base_tasks[matched.base_task_idx.idx()];
            let pc = base_task.jobs.len();
            let job_id = LogGroup::new(matched.base_task_idx, pc);

            let spawn = pred.is_empty();
            if spawn {
                base_task.jobs.push_active(job_index);
                state.test_jobs.push_active(job_index);
            } else {
                base_task.jobs.push_scheduled(job_index);
                state.test_jobs.push_scheduled(job_index);
            }

            state.jobs.push(Job {
                process_status: if !spawn { JobStatus::Scheduled { after: pred } } else { JobStatus::Starting },
                log_group: job_id,
                task: task_config.clone(),
                started_at: Instant::now(),
                log_start,
                cache_key,
                spawn_profile: String::new(),
                spawn_params: ValueMap::new(),
            });

            test_jobs.push(TestJob {
                base_task_index: matched.base_task_idx,
                job_index,
                status: TestJobStatus::Pending,
            });

            if spawn {
                self.process_channel.send(crate::process_manager::ProcessRequest::Spawn {
                    task: task_config,
                    job_index,
                    workspace_id: self.workspace_id,
                    job_id,
                });
            }
        }

        let test_run = TestRun { run_id, started_at: Instant::now(), test_jobs };
        state.active_test_run =
            Some(TestRun { run_id: test_run.run_id, started_at: test_run.started_at, test_jobs: Vec::new() });

        test_run
    }
}

/// Checks if a test matches the given filters.
/// Filter logic:
/// - `-tag`: Absolute exclusion (applied first)
/// - `+tag`: Include tests with this tag (OR combined)
/// - `name`: Include tests with this name (OR combined)
/// - If no inclusion filters, include all (minus exclusions)
fn matches_test_filters(name: &str, tags: &[&str], filters: &[TestFilter]) -> bool {
    let mut has_include_filters = false;
    let mut included = false;

    for filter in filters {
        if let TestFilter::ExcludeTag(exclude_tag) = filter
            && tags.contains(exclude_tag)
        {
            return false;
        }
    }

    for filter in filters {
        match filter {
            TestFilter::IncludeName(include_name) => {
                has_include_filters = true;
                if name == *include_name {
                    included = true;
                }
            }
            TestFilter::IncludeTag(include_tag) => {
                has_include_filters = true;
                if tags.contains(include_tag) {
                    included = true;
                }
            }
            TestFilter::ExcludeTag(_) => {}
        }
    }

    if !has_include_filters {
        return true;
    }

    included
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;

    #[test]
    fn test_job_status_is_pending_completion() {
        assert!(JobStatus::Scheduled { after: vec![] }.is_pending_completion());
        assert!(JobStatus::Starting.is_pending_completion());
        assert!(JobStatus::Running { process_index: 0 }.is_pending_completion());
        assert!(
            !JobStatus::Exited { finished_at: Instant::now(), log_end: LogId(0), cause: ExitCause::Unknown, status: 0 }
                .is_pending_completion()
        );
        assert!(!JobStatus::Cancelled.is_pending_completion());
    }

    #[test]
    fn test_job_status_is_successful_completion() {
        assert!(!JobStatus::Scheduled { after: vec![] }.is_successful_completion());
        assert!(!JobStatus::Starting.is_successful_completion());
        assert!(!JobStatus::Running { process_index: 0 }.is_successful_completion());
        assert!(!JobStatus::Cancelled.is_successful_completion());

        assert!(
            JobStatus::Exited { finished_at: Instant::now(), log_end: LogId(0), cause: ExitCause::Unknown, status: 0 }
                .is_successful_completion()
        );

        assert!(
            !JobStatus::Exited { finished_at: Instant::now(), log_end: LogId(0), cause: ExitCause::Unknown, status: 1 }
                .is_successful_completion()
        );

        // Note: is_successful_completion only checks status code, not exit cause.
        // The ScheduleRequirement::status method does check for Killed separately
        // when evaluating the TerminatedNaturallyAndSucessfully predicate.
        assert!(
            JobStatus::Exited { finished_at: Instant::now(), log_end: LogId(0), cause: ExitCause::Killed, status: 0 }
                .is_successful_completion()
        );
    }

    #[test]
    fn panic_split_line_tests() {
        let line =
            "thread 'log_storage::tests::test_rotation_on_max_lines' (143789) panicked at src/log_storage.rs:639:9:";
        let extracted = extract_rust_panic_from_line(line);
        assert_eq!(extracted, Some(("src/log_storage.rs", 639)));
    }
}
