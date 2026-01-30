use crate::{
    cache_key::CacheKeyHasher,
    cli::TestFilter,
    config::{
        CARGO_AUTO_EXPR, CacheKeyInput, Command, Environment, TaskConfigExpr, TaskConfigRc, TaskKind, WorkspaceConfig,
    },
    event_loop::MioChannel,
    function::FunctionAction,
    log_storage::{LogGroup, LogId, Logs},
};
pub use job_index_list::JobIndexList;
use jsony_value::ValueMap;
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Instant, SystemTime},
};
mod job_index_list;

/// Info needed to compute a cache key outside the workspace lock.
enum CacheKeyInfoItem {
    Modified { paths: Vec<PathBuf>, ignore: &'static [&'static str] },
    ProfileChanged { task_name: String, counter: u32 },
}

struct CacheKeyInfo {
    base_index: BaseTaskIndex,
    cache_key_inputs: Vec<CacheKeyInfoItem>,
}

/// Compute cache key without holding the workspace lock.
/// This allows filesystem I/O to happen without blocking other operations.
fn compute_cache_key_standalone(inputs: &[CacheKeyInfoItem], profile: &str, params: &ValueMap) -> String {
    if inputs.is_empty() && profile.is_empty() && params.entries().is_empty() {
        return String::new();
    }

    let mut hasher = CacheKeyHasher::new();

    for input in inputs {
        match input {
            CacheKeyInfoItem::Modified { paths, ignore } => {
                hasher.update(b"modified:");
                for path in paths {
                    hasher.hash_path(path, ignore);
                }
            }
            CacheKeyInfoItem::ProfileChanged { task_name, counter } => {
                hasher.update(b"profile_changed:");
                hasher.update(task_name.as_bytes());
                hasher.update(b"=");
                hasher.update_u32(*counter);
            }
        }
    }

    if !profile.is_empty() {
        hasher.update(b"require_profile:");
        hasher.update(profile.as_bytes());
    }
    if !params.entries().is_empty() {
        hasher.update(b"require_params:");
        for (k, v) in params.entries() {
            hasher.update(k.as_bytes());
            hasher.update(b"=");
            hasher.update(v.to_string().as_bytes());
        }
    }
    hasher.finalize_hex()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
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

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(transparent)]
pub struct JobIndex(u32);

impl kvlog::Encode for JobIndex {
    fn encode_log_value_into(&self, output: kvlog::ValueEncoder<'_>) {
        self.0.encode_log_value_into(output);
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCause {
    Unknown,
    Killed,
    Restarted,
    SpawnFailed,
    ProfileConflict,
    Timeout,
}

impl ExitCause {
    pub fn name(&self) -> &'static str {
        match self {
            ExitCause::Unknown => "unknown",
            ExitCause::Killed => "killed",
            ExitCause::Restarted => "restarted",
            ExitCause::SpawnFailed => "spawn_failed",
            ExitCause::ProfileConflict => "profile_conflict",
            ExitCause::Timeout => "timeout",
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobPredicate {
    Terminated,
    TerminatedNaturallyAndSuccessfully,
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
            JobPredicate::TerminatedNaturallyAndSuccessfully => match &job.process_status {
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
                JobStatus::Running { ready_state, .. } => match ready_state {
                    None => RequirementStatus::Met,
                    Some(true) => RequirementStatus::Met,
                    Some(false) => RequirementStatus::Pending,
                },
                JobStatus::Exited { .. } => RequirementStatus::Never,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ScheduleReason {
    Requested,
    Dependency,
    ProfileConflict,
    TestRun,
}

impl ScheduleReason {
    pub fn name(&self) -> &'static str {
        match self {
            ScheduleReason::Requested => "requested",
            ScheduleReason::Dependency => "dependency",
            ScheduleReason::ProfileConflict => "profile_conflict",
            ScheduleReason::TestRun => "test_run",
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
        /// None = no ready config (always ready)
        /// Some(false) = waiting for ready condition
        /// Some(true) = ready condition met
        ready_state: Option<bool>,
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
    pub fn name(&self) -> &'static str {
        match self {
            JobStatus::Scheduled { .. } => "Scheduled",
            JobStatus::Starting => "Starting",
            JobStatus::Running { .. } => "Running",
            JobStatus::Exited { .. } => "Exited",
            JobStatus::Cancelled => "Cancelled",
        }
    }

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
    pub fn is_running(&self) -> bool {
        matches!(self, JobStatus::Running { .. })
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

    pub fn refresh_capturing(&mut self) -> Result<bool, String> {
        let metadata = self.path.metadata().map_err(|e| format!("Failed to read {}: {}", self.path.display(), e))?;
        let modified = metadata.modified().map_err(|e| format!("Failed to get mtime: {}", e))?;

        if self.modified_time == modified {
            return Ok(false);
        }

        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("Failed to read {}: {}", self.path.display(), e))?;
        let content: &'static str = content.leak();

        let config_path = self.current.base_path.join("devsm.toml");
        let new_config =
            crate::config::load_workspace_config_capturing(&config_path, content).map_err(|e| e.message)?;

        self.current = new_config;
        self.modified_time = modified;
        Ok(true)
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn update_base_tasks(
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
                        has_run_this_session: false,
                    });
                }
            }
        }
        for (base_name, variants) in self.current.tests {
            for (variant_index, config) in variants.iter().enumerate() {
                let task_name: &'static str =
                    if variants.len() == 1 { base_name } else { format!("{}.{}", base_name, variant_index).leak() };

                let entry_task_name: &'static str = if variants.len() == 1 {
                    format!("~test/{}", base_name).leak()
                } else {
                    format!("~test/{}.{}", base_name, variant_index).leak()
                };
                let task_config = config.to_task_config_expr();

                match name_map.entry(entry_task_name) {
                    hashbrown::hash_map::Entry::Occupied(occupied_entry) => {
                        let base_task = &mut base_tasks[occupied_entry.get().idx()];
                        base_task.removed = false;
                        base_task.config = task_config;
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
                            has_run_this_session: false,
                        });
                    }
                }
            }
        }
    }
}

#[derive(jsony::Jsony)]
#[jsony(ToJson)]
pub struct LoggedPanic {
    pub age: u32,
    pub line: u64,
    pub column: u64,
    pub file: String,
    pub thread: String,
    pub task: String,
    pub pwd: String,
    pub cmd: Vec<String>,
    #[jsony(skip_if = Option::is_none)]
    pub next_line: Option<String>,
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
    //pub test_info: Option<TestInfo>,
    /// Whether this service has been run at least once this session.
    /// Used for `hidden = "until_ran"` visibility.
    pub has_run_this_session: bool,
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

/// Tracks which jobs depend on each service (reverse dependency tracking).
/// Used to determine when a service can be safely stopped.
#[derive(Default)]
pub struct ServiceDependents {
    dependents: hashbrown::HashMap<JobIndex, hashbrown::HashSet<JobIndex>>,
}

impl ServiceDependents {
    pub fn add_dependent(&mut self, service: JobIndex, dependent: JobIndex) {
        self.dependents.entry(service).or_default().insert(dependent);
    }

    #[cfg(test)]
    pub fn remove_dependent(&mut self, service: JobIndex, dependent: JobIndex) {
        if let Some(deps) = self.dependents.get_mut(&service) {
            deps.remove(&dependent);
        }
    }

    pub fn remove_from_all(&mut self, dependent: JobIndex) {
        for deps in self.dependents.values_mut() {
            deps.remove(&dependent);
        }
    }

    pub fn can_stop(&self, service: JobIndex) -> bool {
        self.dependents.get(&service).is_none_or(|deps| deps.is_empty())
    }

    #[cfg(test)]
    pub fn dependent_count(&self, service: JobIndex) -> usize {
        self.dependents.get(&service).map_or(0, |deps| deps.len())
    }
}

/// Result of checking service compatibility with a request.
pub enum ServiceCompatibility {
    /// A matching service is already running.
    Compatible(JobIndex),
    /// No service is currently running.
    Available,
    /// A service is running with a different profile than requested.
    Conflict { running_job: JobIndex, running_profile: String, requested_profile: String },
}

/// Key for deduplicating requirements across a batch of spawns.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RequirementKey {
    pub base_task: BaseTaskIndex,
    pub profile: String,
    pub params_hash: u64,
}

impl RequirementKey {
    pub fn new(base_task: BaseTaskIndex, profile: &str, params: &ValueMap) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (k, v) in params.entries() {
            k.hash(&mut hasher);
            v.to_string().hash(&mut hasher);
        }
        Self { base_task, profile: profile.to_string(), params_hash: hasher.finish() }
    }
}

/// A pending requirement collected during batch spawning.
pub struct PendingRequirement {
    pub base_task: BaseTaskIndex,
    pub profile: String,
    pub params: ValueMap<'static>,
}

/// A pending task collected during batch spawning.
pub struct PendingTask<T> {
    pub task_data: T,
}

/// Result of resolving a requirement during batch spawning.
pub enum ResolvedRequirement {
    Cached,
    Pending(JobIndex),
    Spawned(JobIndex),
}

/// A detected profile conflict within a batch.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct ProfileConflict {
    pub base_task: BaseTaskIndex,
    pub profiles: Vec<String>,
}

/// Batch spawning context for deduplicating requirements across multiple tasks.
pub struct SpawnBatch<T> {
    pending_requirements: hashbrown::HashMap<RequirementKey, PendingRequirement>,
    resolved_requirements: hashbrown::HashMap<RequirementKey, ResolvedRequirement>,
    pending_tasks: Vec<PendingTask<T>>,
}

impl<T> Default for SpawnBatch<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SpawnBatch<T> {
    pub fn new() -> Self {
        Self {
            pending_requirements: hashbrown::HashMap::new(),
            resolved_requirements: hashbrown::HashMap::new(),
            pending_tasks: Vec::new(),
        }
    }

    pub fn add_requirement(
        &mut self,
        base_task: BaseTaskIndex,
        profile: &str,
        params: ValueMap<'static>,
        _predicate: JobPredicate,
    ) -> RequirementKey {
        let key = RequirementKey::new(base_task, profile, &params);
        self.pending_requirements.entry(key.clone()).or_insert_with(|| PendingRequirement {
            base_task,
            profile: profile.to_string(),
            params,
        });
        key
    }

    pub fn add_task(&mut self, task_data: T) {
        self.pending_tasks.push(PendingTask { task_data });
    }

    #[cfg(test)]
    pub fn pending_requirements(&self) -> impl Iterator<Item = (&RequirementKey, &PendingRequirement)> {
        self.pending_requirements.iter()
    }

    pub fn mark_resolved(&mut self, key: RequirementKey, result: ResolvedRequirement) {
        self.resolved_requirements.insert(key, result);
    }

    pub fn get_resolved(&self, key: &RequirementKey) -> Option<&ResolvedRequirement> {
        self.resolved_requirements.get(key)
    }

    pub fn take_tasks(&mut self) -> Vec<PendingTask<T>> {
        std::mem::take(&mut self.pending_tasks)
    }

    #[cfg(test)]
    pub fn requirement_count(&self) -> usize {
        self.pending_requirements.len()
    }

    /// Detects profile conflicts within the batch.
    ///
    /// A conflict occurs when the same base task is requested with different profiles
    /// at the same level (e.g., `group = ["srv:alpha", "srv:beta"]`). These conflicts
    /// cannot be resolved by sequencing and should cause an immediate error.
    #[cfg(test)]
    pub fn detect_profile_conflicts(&self) -> Vec<ProfileConflict> {
        let mut by_base: hashbrown::HashMap<BaseTaskIndex, Vec<&str>> = hashbrown::HashMap::new();
        for (key, _) in &self.pending_requirements {
            by_base.entry(key.base_task).or_default().push(&key.profile);
        }

        let mut conflicts = Vec::new();
        for (base_task, profiles) in by_base {
            if profiles.len() > 1 {
                let mut unique_profiles: Vec<String> = profiles.iter().map(|s| s.to_string()).collect();
                unique_profiles.sort();
                unique_profiles.dedup();
                if unique_profiles.len() > 1 {
                    conflicts.push(ProfileConflict { base_task, profiles: unique_profiles });
                }
            }
        }
        conflicts
    }
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
    pub service_jobs: JobIndexList,
    pub service_dependents: ServiceDependents,
    /// Session-level function overrides (fn1, fn2).
    /// These are set by keybindings and persist for the daemon's lifetime.
    pub session_functions: hashbrown::HashMap<String, FunctionAction>,
    /// The most recent test group (persists across runs for rerun functionality).
    pub last_test_group: Option<TestGroup>,
    cache_key_hasher: CacheKeyHasher,
}

impl WorkspaceState {
    /// Quickly determine if a scheduled task is pending
    pub fn has_scheduled_task(&self) -> bool {
        let mut non_scheduled = 0;
        let mut total = 0;
        non_scheduled += self.action_jobs.terminal_count();
        non_scheduled += self.action_jobs.active_count();
        total += self.action_jobs.len();

        non_scheduled += self.test_jobs.terminal_count();
        non_scheduled += self.test_jobs.active_count();
        total += self.test_jobs.len();

        non_scheduled += self.service_jobs.terminal_count();
        non_scheduled += self.service_jobs.active_count();
        total += self.service_jobs.len();

        total != non_scheduled
    }
    fn compute_cache_key(&mut self, cache_key_inputs: &[CacheKeyInput]) -> String {
        if cache_key_inputs.is_empty() {
            return String::new();
        }
        self.cache_key_hasher.reset();

        for input in cache_key_inputs {
            match input {
                CacheKeyInput::Modified { paths, ignore } => {
                    self.cache_key_hasher.update(b"modified:");
                    for path in *paths {
                        let full_path = self.config.current.base_path.join(path);
                        self.cache_key_hasher.hash_path(&full_path, ignore);
                    }
                }
                CacheKeyInput::ProfileChanged(task_name) => {
                    let counter = self
                        .name_map
                        .get(*task_name)
                        .map_or(0, |&bti| self.base_tasks[bti.idx()].profile_change_counter);
                    self.cache_key_hasher.update(b"profile_changed:");
                    self.cache_key_hasher.update(task_name.as_bytes());
                    self.cache_key_hasher.update(b"=");
                    self.cache_key_hasher.update_u32(counter);
                }
            }
        }
        self.cache_key_hasher.finalize_hex()
    }

    fn compute_cache_key_with_require(
        &mut self,
        cache_key_inputs: &[CacheKeyInput],
        profile: &str,
        params: &ValueMap,
    ) -> String {
        if cache_key_inputs.is_empty() && profile.is_empty() && params.entries().is_empty() {
            return String::new();
        }

        self.cache_key_hasher.reset();

        for input in cache_key_inputs {
            match input {
                CacheKeyInput::Modified { paths, ignore } => {
                    self.cache_key_hasher.update(b"modified:");
                    for path in *paths {
                        let full_path = self.config.current.base_path.join(path);
                        self.cache_key_hasher.hash_path(&full_path, ignore);
                    }
                }
                CacheKeyInput::ProfileChanged(task_name) => {
                    let counter = self
                        .name_map
                        .get(*task_name)
                        .map_or(0, |&bti| self.base_tasks[bti.idx()].profile_change_counter);
                    self.cache_key_hasher.update(b"profile_changed:");
                    self.cache_key_hasher.update(task_name.as_bytes());
                    self.cache_key_hasher.update(b"=");
                    self.cache_key_hasher.update_u32(counter);
                }
            }
        }

        if !profile.is_empty() {
            self.cache_key_hasher.update(b"require_profile:");
            self.cache_key_hasher.update(profile.as_bytes());
        }
        if !params.entries().is_empty() {
            self.cache_key_hasher.update(b"require_params:");
            for (k, v) in params.entries() {
                self.cache_key_hasher.update(k.as_bytes());
                self.cache_key_hasher.update(b"=");
                self.cache_key_hasher.update(v.to_string().as_bytes());
            }
        }
        self.cache_key_hasher.finalize_hex()
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
                has_run_this_session: false,
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
        reason: ScheduleReason,
    ) -> JobIndex {
        let bt = &mut self.base_tasks[base_task.idx()];
        bt.update_profile_tracking(profile);
        let mut pred = Vec::new();

        let task_kind = bt.config.kind;
        let task_name = bt.name;

        for &job_index in bt.jobs.terminate_scheduled() {
            self.jobs[job_index.idx()].process_status = JobStatus::Cancelled;
            match task_kind {
                TaskKind::Action => self.action_jobs.set_terminal(job_index),
                TaskKind::Test => self.test_jobs.set_terminal(job_index),
                TaskKind::Service => self.service_jobs.set_terminal(job_index),
            }
            self.service_dependents.remove_from_all(job_index);
        }

        for &job_index in bt.jobs.running() {
            let job = &mut self.jobs[job_index.idx()];
            let JobStatus::Running { process_index, .. } = &job.process_status else {
                continue;
            };
            pred.push(ScheduleRequirement { job: job_index, predicate: JobPredicate::Terminated });
            channel.send(crate::event_loop::ProcessRequest::TerminateJob {
                job_id: job.log_group,
                process_index: *process_index,
                exit_cause: ExitCause::Restarted,
            });
        }

        let bt = &mut self.base_tasks[base_task.idx()];
        let task = bt.config.eval(&Environment { profile, param: params.clone(), vars: bt.config.vars }).unwrap();

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
                            ScheduleReason::Dependency,
                        );
                        pred.push(ScheduleRequirement {
                            job: new_job,
                            predicate: JobPredicate::TerminatedNaturallyAndSuccessfully,
                        });
                        continue;
                    };

                    if cache_config.never {
                        let new_job = self.spawn_task(
                            workspace_id,
                            channel,
                            dep_base_task,
                            log_start,
                            dep_params,
                            dep_profile,
                            ScheduleReason::Dependency,
                        );
                        pred.push(ScheduleRequirement {
                            job: new_job,
                            predicate: JobPredicate::TerminatedNaturallyAndSuccessfully,
                        });
                        continue;
                    }

                    let expected_cache_key =
                        self.compute_cache_key_with_require(cache_config.key, dep_profile, &dep_params);
                    let spawner = &self.base_tasks[dep_base_task.idx()];

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
                            predicate: JobPredicate::TerminatedNaturallyAndSuccessfully,
                        });
                        continue 'outer;
                    }
                    let new_job = self.spawn_task(
                        workspace_id,
                        channel,
                        dep_base_task,
                        log_start,
                        dep_params,
                        dep_profile,
                        ScheduleReason::Dependency,
                    );
                    pred.push(ScheduleRequirement {
                        job: new_job,
                        predicate: JobPredicate::TerminatedNaturallyAndSuccessfully,
                    });
                }
                TaskKind::Service => {
                    let cache_never = dep_config.cache.as_ref().is_some_and(|c| c.never);
                    if !cache_never {
                        let spawner = &self.base_tasks[dep_base_task.idx()];
                        for &ji in spawner.jobs.running() {
                            let job = &self[ji];
                            if service_matches_require(job, dep_profile, &dep_params) {
                                pred.push(ScheduleRequirement { job: ji, predicate: JobPredicate::Active });
                                continue 'outer;
                            }
                        }
                    }
                    let new_job = self.spawn_task(
                        workspace_id,
                        channel,
                        dep_base_task,
                        log_start,
                        dep_params,
                        dep_profile,
                        ScheduleReason::Dependency,
                    );
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
        if task_kind == TaskKind::Service {
            bt.has_run_this_session = true;
        }
        if spawn {
            bt.jobs.push_active(job_index);
        } else {
            bt.jobs.push_scheduled(job_index);
        }

        let global_list = match task_kind {
            TaskKind::Action => Some(&mut self.action_jobs),
            TaskKind::Test => Some(&mut self.test_jobs),
            TaskKind::Service => Some(&mut self.service_jobs),
        };
        if let Some(list) = global_list {
            if spawn {
                list.push_active(job_index);
            } else {
                list.push_scheduled(job_index);
            }
        }

        for req in &pred {
            if matches!(req.predicate, JobPredicate::Active) {
                self.service_dependents.add_dependent(req.job, job_index);
            }
        }

        self.jobs.push(Job {
            process_status: if !spawn { JobStatus::Scheduled { after: pred } } else { JobStatus::Starting },
            log_group: job_id,
            task: task.clone(),
            started_at: crate::clock::now(),
            log_start,
            cache_key,
            spawn_profile: profile.to_string(),
            spawn_params: params.to_owned(),
        });
        if spawn {
            channel.send(crate::event_loop::ProcessRequest::Spawn { task, job_index, workspace_id, job_id });
        } else {
            kvlog::info!("Job scheduled", task_name, job_index, reason = reason.name());
        }
        job_index
    }

    /// Schedule a queued service that waits for a blocking service to terminate.
    ///
    /// Creates a job in Scheduled state that will be spawned when the blocking
    /// service terminates. This is used when a service with a different profile
    /// is requested while another profile is still running.
    fn schedule_queued_service(
        &mut self,
        base_task: BaseTaskIndex,
        log_start: LogId,
        params: ValueMap,
        profile: &str,
        blocked_by: JobIndex,
    ) -> JobIndex {
        let (task_name, task, pc) = {
            let spawner = &self.base_tasks[base_task.idx()];
            let env = Environment { profile, param: params.clone(), vars: spawner.config.vars };
            let task = spawner.config.eval(&env).expect("Failed to eval queued service config");
            (spawner.name, task, spawner.jobs.len())
        };

        let cache_key = task.config().cache.as_ref().map_or(String::new(), |c| self.compute_cache_key(c.key));

        let job_index = JobIndex(self.jobs.len() as u32);
        let job_id = LogGroup::new(base_task, pc);

        let after = vec![ScheduleRequirement { job: blocked_by, predicate: JobPredicate::Terminated }];

        let base_task_mut = &mut self.base_tasks[base_task.idx()];
        base_task_mut.jobs.push_scheduled(job_index);
        self.service_jobs.push_scheduled(job_index);

        self.jobs.push(Job {
            process_status: JobStatus::Scheduled { after },
            log_group: job_id,
            task,
            started_at: crate::clock::now(),
            log_start,
            cache_key,
            spawn_profile: profile.to_string(),
            spawn_params: params.to_owned(),
        });

        kvlog::info!("Job scheduled", task_name, job_index, reason = ScheduleReason::ProfileConflict.name());

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

    /// Computes a summary of the current test group for status bar display.
    pub fn compute_test_group_summary(&self) -> Option<TestGroupSummary> {
        let test_group = self.last_test_group.as_ref()?;

        let mut summary = TestGroupSummary { total: test_group.job_indices.len() as u32, ..Default::default() };

        for &job_index in &test_group.job_indices {
            let Some(job) = self.jobs.get(job_index.idx()) else { continue };
            match &job.process_status {
                JobStatus::Scheduled { .. } | JobStatus::Starting => summary.pending += 1,
                JobStatus::Running { .. } => summary.running += 1,
                JobStatus::Exited { status, .. } => {
                    if *status == 0 {
                        summary.passed += 1;
                    } else {
                        summary.failed += 1;
                    }
                }
                JobStatus::Cancelled => summary.failed += 1,
            }
        }

        Some(summary)
    }

    /// Layer 2: Lookup task by name and spawn it in one operation.
    ///
    /// Refreshes config, increments change_number, and spawns the task.
    /// Returns the base task index and job index on success.
    pub fn lookup_and_spawn_task(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        name: &str,
        log_start: LogId,
        params: ValueMap,
        profile: &str,
    ) -> Result<(BaseTaskIndex, JobIndex), String> {
        let Some(base_index) = self.base_index_by_name(name) else {
            return Err(format!("Task '{}' not found", name));
        };
        self.change_number = self.change_number.wrapping_add(1);
        self.refresh_config();
        let job_index =
            self.spawn_task(workspace_id, channel, base_index, log_start, params, profile, ScheduleReason::Requested);
        Ok((base_index, job_index))
    }

    /// Check if a task has a cache hit using a pre-computed cache key.
    ///
    /// Returns `Some(message)` if cache hit, `None` otherwise.
    /// The cache key should be computed outside the lock to avoid blocking during filesystem I/O.
    pub fn check_cache_hit_with_key(
        &self,
        name: &str,
        base_index: BaseTaskIndex,
        expected_cache_key: &str,
    ) -> Option<String> {
        if expected_cache_key.is_empty() {
            return None;
        }

        let bt = &self.base_tasks[base_index.idx()];
        let task_kind = bt.config.kind;

        for ji in bt.jobs.all().iter().rev() {
            let job = &self[*ji];
            if matches!(job.process_status, JobStatus::Cancelled) {
                continue;
            }

            if job.cache_key != expected_cache_key {
                continue;
            }

            match task_kind {
                TaskKind::Action => {
                    if job.process_status.is_successful_completion() {
                        return Some(format!("Task '{}' cache hit (already completed)", name));
                    }
                    if job.process_status.is_pending_completion() {
                        return Some(format!("Task '{}' cache hit (already in progress)", name));
                    }
                }
                TaskKind::Service => {
                    if job.process_status.is_running() {
                        return Some(format!("Task '{}' cache hit (already running)", name));
                    }
                    if job.process_status.is_pending_completion() && !job.process_status.is_running() {
                        return Some(format!("Task '{}' cache hit (already scheduled)", name));
                    }
                }
                TaskKind::Test => {}
            }
        }

        None
    }

    /// Layer 2: Find task by name and terminate all running instances.
    ///
    /// Accepts task name or numeric index. Returns a message describing the result.
    pub fn lookup_and_terminate_task(&mut self, channel: &MioChannel, name: &str) -> Result<String, String> {
        let index = if let Ok(idx) = name.parse::<u32>() {
            let bti = BaseTaskIndex(idx);
            if self.base_tasks.get(bti.idx()).is_some() { Some(bti) } else { None }
        } else {
            self.base_index_by_name(name)
        };

        let Some(index) = index else {
            return Err(format!("Task '{}' not found", name));
        };

        let bt = &self.base_tasks[index.idx()];

        let has_non_terminal = !bt.jobs.non_terminal().is_empty();

        if !has_non_terminal {
            return Ok(format!("Task '{}' was already finished", bt.name));
        }

        let task_name = bt.name.to_string();
        self.change_number = self.change_number.wrapping_add(1);

        let mut jobs_to_cancel = Vec::new();
        let mut killed_count = 0u32;
        let mut cancelled_count = 0u32;

        for job_index in bt.jobs.non_terminal() {
            let job = &self.jobs[job_index.idx()];
            match &job.process_status {
                JobStatus::Running { process_index, .. } => {
                    kvlog::info!("Terminating running job", task_name, job_index, process_index);
                    channel.send(crate::event_loop::ProcessRequest::TerminateJob {
                        job_id: job.log_group,
                        process_index: *process_index,
                        exit_cause: ExitCause::Killed,
                    });
                    killed_count += 1;
                }
                JobStatus::Starting => {
                    kvlog::warn!("Job is in Starting state during termination", task_name, job_index);
                }
                JobStatus::Scheduled { .. } => {
                    kvlog::info!("Cancelling scheduled job", task_name, job_index);
                    jobs_to_cancel.push(*job_index);
                    cancelled_count += 1;
                }
                JobStatus::Exited { .. } | JobStatus::Cancelled => {}
            }
        }

        for job_index in jobs_to_cancel {
            self.update_job_status(job_index, JobStatus::Cancelled);
        }

        let msg = match (killed_count, cancelled_count) {
            (0, 0) => format!("Task '{}' was already finished", task_name),
            (k, 0) => format!("Task '{}' terminated ({} killed)", task_name, k),
            (0, c) => format!("Task '{}' cancelled ({} scheduled)", task_name, c),
            (k, c) => format!("Task '{}' terminated ({} killed, {} cancelled)", task_name, k, c),
        };

        Ok(msg)
    }

    /// Layer 2: Record a single task spawn as a test group.
    pub fn record_test_group(&mut self, base_index: BaseTaskIndex, job_index: JobIndex) {
        let group_id = self.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
        self.last_test_group = Some(TestGroup { group_id, base_tasks: vec![base_index], job_indices: vec![job_index] });
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
        let task_name = base_task.name;
        let task_kind = base_task.config.kind;
        let jobs_list = &mut base_task.jobs;

        kvlog::info!("Job status changed", job_index, task_name, status = status.name());

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
            (S::Starting, S::Exited { .. }) => {
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
            TaskKind::Service => Some(&mut self.service_jobs),
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

        match (&job.process_status, &status) {
            (S::Scheduled { .. }, S::Cancelled)
            | (S::Starting, S::Cancelled)
            | (S::Running { .. }, S::Cancelled)
            | (S::Running { .. }, S::Exited { .. }) => {
                self.service_dependents.remove_from_all(job_index);
            }
            _ => {}
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
            service_jobs: JobIndexList::default(),
            service_dependents: ServiceDependents::default(),
            session_functions: hashbrown::HashMap::new(),
            last_test_group: None,
            cache_key_hasher: CacheKeyHasher::new(),
        })
    }

    /// Brute force scheduling useful testing will provided an optimized alternative later
    pub fn next_scheduled(&self) -> Scheduled {
        if !self.has_scheduled_task() {
            return Scheduled::None;
        }
        for job_set in [&self.action_jobs, &self.service_jobs, &self.test_jobs] {
            'pending: for &job_index in job_set.scheduled() {
                let JobStatus::Scheduled { after } = &self[job_index].process_status else {
                    kvlog::error!("Inconsistent JobStatus in WorkspaceState::next_ready_task",
                     status = ?&self[job_index].process_status, ?job_index);
                    continue;
                };
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

    /// Find services that should be terminated to allow queued services to proceed.
    ///
    /// Returns the job index of a service that:
    /// 1. Has no more dependents (can_stop returns true)
    /// 2. Has a scheduled service waiting for it to terminate
    ///
    /// The caller should terminate this service to allow the queued service to start.
    pub fn service_to_terminate_for_queue(&self) -> Option<JobIndex> {
        for &job_index in self.service_jobs.scheduled() {
            let JobStatus::Scheduled { after } = &self[job_index].process_status else {
                continue;
            };
            for req in after {
                if req.predicate == JobPredicate::Terminated {
                    let blocking_job = &self.jobs[req.job.idx()];
                    if blocking_job.process_status.is_running() && self.service_dependents.can_stop(req.job) {
                        return Some(req.job);
                    }
                }
            }
        }
        None
    }

    /// Check compatibility of a service request with running instances.
    ///
    /// Returns:
    /// - `Compatible(job_index)` if a matching service is running
    /// - `Available` if no instance is running
    /// - `Conflict { ... }` if a service is running with a different profile
    pub fn check_service_compatibility(
        &self,
        base_task: BaseTaskIndex,
        requested_profile: &str,
        requested_params: &ValueMap,
    ) -> ServiceCompatibility {
        let spawner = &self.base_tasks[base_task.idx()];

        if let Some(&ji) = spawner.jobs.running().iter().next() {
            let job = &self.jobs[ji.idx()];
            if service_matches_require(job, requested_profile, requested_params) {
                return ServiceCompatibility::Compatible(ji);
            }
            return ServiceCompatibility::Conflict {
                running_job: ji,
                running_profile: job.spawn_profile.clone(),
                requested_profile: requested_profile.to_string(),
            };
        }

        ServiceCompatibility::Available
    }

    /// Resolves a batch of requirements with deduplication.
    ///
    /// Takes a SpawnBatch and resolves all pending requirements, spawning each unique
    /// requirement at most once.
    pub fn resolve_batch_requirements<T>(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        batch: &mut SpawnBatch<T>,
        log_start: LogId,
    ) {
        let reqs: Vec<_> = batch
            .pending_requirements
            .iter()
            .map(|(k, r)| (k.clone(), r.base_task, r.profile.clone(), r.params.clone()))
            .collect();

        for (key, base_task, profile, params) in reqs {
            if batch.resolved_requirements.contains_key(&key) {
                continue;
            }

            let dep_config = &self.base_tasks[base_task.idx()].config;

            match dep_config.kind {
                TaskKind::Action => {
                    let mut resolved = None;

                    if let Some(cache_config) = dep_config.cache.as_ref()
                        && !cache_config.never
                    {
                        let expected_cache_key =
                            self.compute_cache_key_with_require(cache_config.key, &profile, &params);
                        let spawner = &self.base_tasks[base_task.idx()];

                        for ji in spawner.jobs.all().iter().rev() {
                            let job = &self.jobs[ji.idx()];
                            if matches!(job.process_status, JobStatus::Cancelled) {
                                continue;
                            }
                            if job.process_status.is_successful_completion() {
                                if expected_cache_key.is_empty() || job.cache_key == expected_cache_key {
                                    resolved = Some(ResolvedRequirement::Cached);
                                    break;
                                }
                                continue;
                            }
                            if job.process_status.is_pending_completion()
                                && (expected_cache_key.is_empty() || job.cache_key == expected_cache_key)
                            {
                                resolved = Some(ResolvedRequirement::Pending(*ji));
                                break;
                            }
                        }
                    }

                    if let Some(r) = resolved {
                        batch.mark_resolved(key, r);
                        continue;
                    }

                    let new_job = self.spawn_task(
                        workspace_id,
                        channel,
                        base_task,
                        log_start,
                        params,
                        &profile,
                        ScheduleReason::Dependency,
                    );
                    batch.mark_resolved(key, ResolvedRequirement::Spawned(new_job));
                }
                TaskKind::Service => {
                    let cache_never = dep_config.cache.as_ref().is_some_and(|c| c.never);

                    if !cache_never {
                        match self.check_service_compatibility(base_task, &profile, &params) {
                            ServiceCompatibility::Compatible(ji) => {
                                batch.mark_resolved(key, ResolvedRequirement::Pending(ji));
                                continue;
                            }
                            ServiceCompatibility::Conflict { running_job, running_profile, requested_profile } => {
                                kvlog::warn!(
                                    "Service profile conflict, queuing",
                                    ?base_task,
                                    running_profile,
                                    requested_profile,
                                );
                                let queued_job =
                                    self.schedule_queued_service(base_task, log_start, params, &profile, running_job);
                                batch.mark_resolved(key, ResolvedRequirement::Pending(queued_job));
                                continue;
                            }
                            ServiceCompatibility::Available => {}
                        }
                    }

                    let new_job = self.spawn_task(
                        workspace_id,
                        channel,
                        base_task,
                        log_start,
                        params,
                        &profile,
                        ScheduleReason::Dependency,
                    );
                    batch.mark_resolved(key, ResolvedRequirement::Spawned(new_job));
                }
                TaskKind::Test => {
                    batch.mark_resolved(key, ResolvedRequirement::Cached);
                }
            }
        }
    }
}

pub struct Workspace {
    pub workspace_id: u32,
    pub logs: Arc<RwLock<Logs>>,
    pub state: RwLock<WorkspaceState>,
    pub process_channel: Arc<MioChannel>,
}

pub fn extract_rust_panic_from_line(line: &str) -> Option<(&str, &str, u64, u64)> {
    let after_thread = line.strip_prefix("thread ")?;
    let thread_start = after_thread.strip_prefix('\'')?;
    let (thread, rest) = thread_start.split_once('\'')?;
    let after_panic = rest.split_once(") panicked at ")?.1;
    let (file, nums) = after_panic.split_once(":")?;
    let (line_str, rest) = nums.split_once(":")?;
    let (col_str, _) = rest.split_once(":")?;
    let line = line_str.parse::<u64>().ok()?;
    let col = col_str.parse::<u64>().ok()?;
    Some((thread, file, line, col))
}

pub enum FunctionGlobalAction {
    RestartSelected,
}

impl Workspace {
    pub fn logged_rust_panics(&self) -> Vec<LoggedPanic> {
        struct PanicFromLog {
            age: u32,
            line: u64,
            column: u64,
            file: String,
            thread: String,
            log_group: LogGroup,
            next_line: Option<String>,
        }

        let from_logs = {
            let logs = self.logs.read().unwrap();
            let current_elapsed = logs.elapsed_secs();
            let cutoff = current_elapsed.saturating_sub(30);
            let (a, b) = logs.slices();
            let mut collected = Vec::new();

            let entries: Vec<_> = a.iter().chain(b.iter()).collect();
            for (i, entry) in entries.iter().enumerate() {
                if entry.time < cutoff {
                    continue;
                }
                let text = unsafe { entry.text(&logs) };
                let Some((thread, file, line, column)) = extract_rust_panic_from_line(text) else {
                    continue;
                };
                let next_line = entries.get(i + 1).and_then(|next| {
                    if next.log_group == entry.log_group && next.time <= entry.time + 1 {
                        Some(unsafe { next.text(&logs) }.to_string())
                    } else {
                        None
                    }
                });
                collected.push(PanicFromLog {
                    age: current_elapsed - entry.time,
                    line,
                    column,
                    file: file.to_string(),
                    thread: thread.to_string(),
                    log_group: entry.log_group,
                    next_line,
                });
            }
            collected
        };

        let state = self.state.read().unwrap();
        from_logs
            .into_iter()
            .map(|p| {
                let base_task_idx = p.log_group.base_task_index();
                let task_name = state.base_tasks.get(base_task_idx.idx()).map(|bt| bt.name).unwrap_or("<unknown>");
                let job = state.jobs.iter().find(|job| job.log_group == p.log_group);
                let (pwd, cmd) = match job {
                    Some(job) => {
                        let config = job.task.config();
                        let pwd = state.config.current.base_path.join(config.pwd).to_string_lossy().to_string();
                        let cmd = match &config.command {
                            Command::Cmd(args) => args.iter().map(|s| s.to_string()).collect(),
                            Command::Sh(sh) => vec!["sh".to_string(), "-c".to_string(), sh.to_string()],
                        };
                        (pwd, cmd)
                    }
                    None => (String::new(), Vec::new()),
                };
                LoggedPanic {
                    age: p.age,
                    line: p.line,
                    column: p.column,
                    file: p.file,
                    thread: p.thread,
                    task: task_name.to_string(),
                    pwd,
                    cmd,
                    next_line: p.next_line,
                }
            })
            .collect()
    }

    pub fn state(&self) -> std::sync::RwLockReadGuard<'_, WorkspaceState> {
        self.state.read().unwrap()
    }
    pub fn restart_task(&self, base_task: BaseTaskIndex, params: ValueMap, profile: &str) -> JobIndex {
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
            ScheduleReason::Requested,
        )
    }

    pub fn terminate_tasks(&self, base_task: BaseTaskIndex) {
        let state = &mut *self.state.write().unwrap();
        state.change_number = state.change_number.wrapping_add(1);

        let task_name = state.base_tasks[base_task.idx()].name;
        let job_indices: Vec<JobIndex> = state.base_tasks[base_task.idx()].jobs.non_terminal().to_vec();

        let mut jobs_to_cancel = Vec::new();
        for job_index in job_indices {
            let job = &state.jobs[job_index.idx()];
            match &job.process_status {
                JobStatus::Running { process_index, .. } => {
                    kvlog::info!("Terminating running job", task_name, job_index, process_index);
                    self.process_channel.send(crate::event_loop::ProcessRequest::TerminateJob {
                        job_id: job.log_group,
                        process_index: *process_index,
                        exit_cause: ExitCause::Killed,
                    });
                }
                JobStatus::Starting => {
                    kvlog::warn!(
                        "Job is in Starting state during termination (spawn in progress)",
                        task_name,
                        job_index
                    );
                }
                JobStatus::Scheduled { .. } => {
                    kvlog::info!("Cancelling scheduled job", task_name, job_index);
                    jobs_to_cancel.push(job_index);
                }
                JobStatus::Exited { .. } | JobStatus::Cancelled => {}
            }
        }

        for job_index in jobs_to_cancel {
            state.update_job_status(job_index, JobStatus::Cancelled);
        }
    }

    /// Layer 1: Restart task by name.
    ///
    /// Acquires state lock, looks up task, and spawns it.
    #[expect(unused, reason = "public API for programmatic restart without cache checking")]
    pub fn restart_task_by_name(&self, name: &str, params: ValueMap, profile: &str) -> Result<JobIndex, String> {
        let log_start = self.logs.read().unwrap().tail();
        let state = &mut *self.state.write().unwrap();
        let (_, job_index) =
            state.lookup_and_spawn_task(self.workspace_id, &self.process_channel, name, log_start, params, profile)?;
        Ok(job_index)
    }

    /// Layer 1: Restart task by name with cache checking.
    ///
    /// If `cached` is true and there's a cache hit (task already running/completed
    /// with matching cache key), returns Ok(Some(message)) without restarting.
    /// Otherwise restarts the task and returns Ok(None).
    ///
    /// Cache key computation (which may involve filesystem I/O) is done outside
    /// the workspace lock to avoid blocking other operations.
    pub fn spawn_task_by_name_cached(
        &self,
        name: &str,
        params: ValueMap,
        profile: &str,
        cached: bool,
    ) -> Result<Option<String>, String> {
        let log_start = self.logs.read().unwrap().tail();

        if cached {
            // Phase 1: Gather info needed for cache key computation (hold lock briefly)
            let cache_info = {
                let state = self.state.read().unwrap();
                let Some(&base_index) = state.name_map.get(name) else {
                    return Err(format!("Task '{}' not found", name));
                };
                let bt = &state.base_tasks[base_index.idx()];
                let Some(cache_config) = &bt.config.cache else {
                    drop(state);
                    let state = &mut *self.state.write().unwrap();
                    let (_, _) = state.lookup_and_spawn_task(
                        self.workspace_id,
                        &self.process_channel,
                        name,
                        log_start,
                        params,
                        profile,
                    )?;
                    return Ok(None);
                };
                if cache_config.never {
                    drop(state);
                    let state = &mut *self.state.write().unwrap();
                    let (_, _) = state.lookup_and_spawn_task(
                        self.workspace_id,
                        &self.process_channel,
                        name,
                        log_start,
                        params,
                        profile,
                    )?;
                    return Ok(None);
                };

                let base_path = state.config.current.base_path.to_path_buf();
                let cache_key_inputs: Vec<_> = cache_config
                    .key
                    .iter()
                    .map(|input| match input {
                        CacheKeyInput::Modified { paths, ignore } => CacheKeyInfoItem::Modified {
                            paths: paths.iter().map(|p| base_path.join(p)).collect(),
                            ignore,
                        },
                        CacheKeyInput::ProfileChanged(task_name) => {
                            let counter = state
                                .name_map
                                .get(*task_name)
                                .map_or(0, |&bti| state.base_tasks[bti.idx()].profile_change_counter);
                            CacheKeyInfoItem::ProfileChanged { task_name: task_name.to_string(), counter }
                        }
                    })
                    .collect();

                CacheKeyInfo { base_index, cache_key_inputs }
            };
            // Lock released here

            // Phase 2: Compute cache key (filesystem I/O, no lock held)
            let expected_cache_key = compute_cache_key_standalone(&cache_info.cache_key_inputs, profile, &params);

            // Phase 3: Check for cache hit and spawn if needed (re-acquire lock)
            let state = &mut *self.state.write().unwrap();
            if let Some(msg) = state.check_cache_hit_with_key(name, cache_info.base_index, &expected_cache_key) {
                return Ok(Some(msg));
            }

            let (_, _job_index) = state.lookup_and_spawn_task(
                self.workspace_id,
                &self.process_channel,
                name,
                log_start,
                params,
                profile,
            )?;
            Ok(None)
        } else {
            let state = &mut *self.state.write().unwrap();
            let (_, _job_index) = state.lookup_and_spawn_task(
                self.workspace_id,
                &self.process_channel,
                name,
                log_start,
                params,
                profile,
            )?;
            Ok(None)
        }
    }

    /// Layer 1: Restart task by name and mark as test.
    ///
    /// Acquires state lock, looks up task, spawns it, and records it as a test group.
    pub fn spawn_task_as_test(&self, name: &str, params: ValueMap, profile: &str) -> Result<(), String> {
        let log_start = self.logs.read().unwrap().tail();
        let state = &mut *self.state.write().unwrap();
        let (base_index, job_index) =
            state.lookup_and_spawn_task(self.workspace_id, &self.process_channel, name, log_start, params, profile)?;
        state.record_test_group(base_index, job_index);
        Ok(())
    }

    /// Layer 1: Terminate task by name.
    ///
    /// Acquires state lock, looks up task, and terminates all running instances.
    pub fn terminate_task_by_name(&self, name: &str) -> Result<String, String> {
        let state = &mut *self.state.write().unwrap();
        state.lookup_and_terminate_task(&self.process_channel, name)
    }

    /// Layer 1: Execute a function by name.
    ///
    /// Looks up function from session_functions or config.functions, then executes its action.
    pub fn call_function(&self, name: &str) -> Result<Option<FunctionGlobalAction>, String> {
        use crate::config::FunctionDefAction;
        use crate::function::FunctionAction;

        let log_start = self.logs.read().unwrap().tail();
        let state = &mut *self.state.write().unwrap();

        if let Some(FunctionAction::RestartCaptured { task_name, profile }) = state.session_functions.get(name).cloned()
        {
            state.lookup_and_spawn_task(
                self.workspace_id,
                &self.process_channel,
                &task_name,
                log_start,
                ValueMap::new(),
                &profile,
            )?;
            return Ok(None);
        }

        for func_def in state.config.current.functions {
            if func_def.name == name {
                match &func_def.action {
                    FunctionDefAction::Restart { task } => {
                        state.lookup_and_spawn_task(
                            self.workspace_id,
                            &self.process_channel,
                            task,
                            log_start,
                            ValueMap::new(),
                            "",
                        )?;
                    }
                    FunctionDefAction::Kill { task } => {
                        state.lookup_and_terminate_task(&self.process_channel, task)?;
                    }
                    FunctionDefAction::Spawn { tasks } => {
                        for task_call in *tasks {
                            state.lookup_and_spawn_task(
                                self.workspace_id,
                                &self.process_channel,
                                &task_call.name,
                                log_start,
                                task_call.vars.clone(),
                                task_call.profile.unwrap_or(""),
                            )?;
                        }
                    }
                    FunctionDefAction::RestartSelected => {
                        return Ok(Some(FunctionGlobalAction::RestartSelected));
                    }
                }
                return Ok(None);
            }
        }

        Err(format!("Function '{}' not configured", name))
    }

    /// Starts a test run with the given filters.
    /// Returns the test run containing all scheduled test jobs, or an error
    /// if any test has conflicting service profile requirements.
    ///
    /// Uses batch spawning to deduplicate requirements across all tests.
    pub fn start_test_run(&self, filters: &[TestFilter]) -> Result<TestRun, String> {
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
            if base_task.removed || base_task.config.kind != TaskKind::Test {
                continue;
            }
            let tags = base_task.config.tags;
            if !matches_test_filters(base_task.name, tags, filters) {
                continue;
            }
            let env = Environment { profile: "", param: ValueMap::new(), vars: base_task.config.vars };
            let Ok(task_config) = base_task.config.eval(&env) else {
                kvlog::error!("Failed to evaluate test config", name = base_task.name);
                continue;
            };
            matched_tests.push(MatchedTest { base_task_idx: BaseTaskIndex::new_or_panic(base_task_idx), task_config });
        }

        struct TestRequirements {
            base_task_idx: BaseTaskIndex,
            task_config: TaskConfigRc,
            requirements: Vec<(RequirementKey, JobPredicate)>,
        }

        let mut batch: SpawnBatch<TestRequirements> = SpawnBatch::new();

        for matched in &matched_tests {
            let task_config = &matched.task_config;
            let mut requirements = Vec::new();

            // Check for service profile conflicts (including transitive through services).
            // Services need to stay Active, so their transitive service deps must also be active.
            // Actions complete and terminate, so transitive conflicts through actions are fine.
            let mut service_profiles: hashbrown::HashMap<BaseTaskIndex, String> = hashbrown::HashMap::new();
            let mut services_to_check: Vec<(String, String)> = task_config
                .config()
                .require
                .iter()
                .filter_map(|tc| {
                    let dep_name = &*tc.name;
                    let dep_base_task = state.name_map.get(dep_name)?;
                    let dep_config = &state.base_tasks[dep_base_task.idx()].config;
                    if dep_config.kind == TaskKind::Service {
                        Some((dep_name.to_string(), tc.profile.unwrap_or("").to_string()))
                    } else {
                        None
                    }
                })
                .collect();
            let mut visited_services: hashbrown::HashSet<BaseTaskIndex> = hashbrown::HashSet::new();

            while let Some((dep_name, dep_profile)) = services_to_check.pop() {
                let Some(&dep_base_task) = state.name_map.get(&*dep_name) else {
                    continue;
                };
                let dep_config = &state.base_tasks[dep_base_task.idx()].config;

                // Check for conflicts first, before checking visited
                if let Some(existing_profile) = service_profiles.get(&dep_base_task) {
                    if *existing_profile != dep_profile {
                        let test_name = state.base_tasks[matched.base_task_idx.idx()].name;
                        let service_name = state.base_tasks[dep_base_task.idx()].name;
                        return Err(format!(
                            "Test '{}' has conflicting service requirements: '{}:{}' and '{}:{}'",
                            test_name, service_name, existing_profile, service_name, dep_profile
                        ));
                    }
                    // Same profile already processed, skip recursion
                    continue;
                }
                service_profiles.insert(dep_base_task, dep_profile.clone());

                // Skip if already visited with this profile (avoid infinite loops)
                if !visited_services.insert(dep_base_task) {
                    continue;
                }

                // Recurse into this service's service dependencies
                let env = Environment { profile: &dep_profile, param: ValueMap::new(), vars: dep_config.vars };
                if let Ok(srv_config) = dep_config.eval(&env) {
                    for req in srv_config.config().require.iter() {
                        let req_name = &*req.name;
                        let Some(&req_base_task) = state.name_map.get(req_name) else {
                            continue;
                        };
                        let req_config = &state.base_tasks[req_base_task.idx()].config;
                        if req_config.kind == TaskKind::Service {
                            services_to_check.push((req_name.to_string(), req.profile.unwrap_or("").to_string()));
                        }
                    }
                }
            }

            for tc in task_config.config().require.iter() {
                let dep_name = &*tc.name;
                let dep_profile = tc.profile.unwrap_or("");
                let dep_params = tc.vars.clone().to_owned();

                let Some(&dep_base_task) = state.name_map.get(dep_name) else {
                    continue;
                };
                let dep_config = &state.base_tasks[dep_base_task.idx()].config;

                let predicate = match dep_config.kind {
                    TaskKind::Action => JobPredicate::TerminatedNaturallyAndSuccessfully,
                    TaskKind::Service => JobPredicate::Active,
                    TaskKind::Test => continue,
                };

                let key = batch.add_requirement(dep_base_task, dep_profile, dep_params, predicate.clone());
                requirements.push((key, predicate));
            }

            batch.add_task(TestRequirements {
                base_task_idx: matched.base_task_idx,
                task_config: task_config.clone(),
                requirements,
            });
        }

        state.resolve_batch_requirements(self.workspace_id, &self.process_channel, &mut batch, log_start);

        let tasks = batch.take_tasks();
        let mut test_jobs = Vec::new();

        for task in tasks {
            let task_config = task.task_data.task_config;
            let mut pred = Vec::new();

            for (key, predicate) in &task.task_data.requirements {
                match batch.get_resolved(key) {
                    Some(ResolvedRequirement::Cached) => {}
                    Some(ResolvedRequirement::Pending(ji)) | Some(ResolvedRequirement::Spawned(ji)) => {
                        pred.push(ScheduleRequirement { job: *ji, predicate: predicate.clone() });
                    }
                    None => {}
                }
            }

            let cache_key =
                task_config.config().cache.as_ref().map_or(String::new(), |c| state.compute_cache_key(c.key));

            let job_index = JobIndex(state.jobs.len() as u32);
            let base_task = &mut state.base_tasks[task.task_data.base_task_idx.idx()];
            let task_name = base_task.name;
            let pc = base_task.jobs.len();
            let job_id = LogGroup::new(task.task_data.base_task_idx, pc);

            let spawn = pred.is_empty();
            if spawn {
                base_task.jobs.push_active(job_index);
                state.test_jobs.push_active(job_index);
            } else {
                base_task.jobs.push_scheduled(job_index);
                state.test_jobs.push_scheduled(job_index);
            }

            for req in &pred {
                if matches!(req.predicate, JobPredicate::Active) {
                    state.service_dependents.add_dependent(req.job, job_index);
                }
            }

            state.jobs.push(Job {
                process_status: if !spawn { JobStatus::Scheduled { after: pred } } else { JobStatus::Starting },
                log_group: job_id,
                task: task_config.clone(),
                started_at: crate::clock::now(),
                log_start,
                cache_key,
                spawn_profile: String::new(),
                spawn_params: ValueMap::new(),
            });

            if !spawn {
                kvlog::info!("Job scheduled", task_name, job_index, reason = ScheduleReason::TestRun.name());
            }

            test_jobs.push(TestJob {
                base_task_index: task.task_data.base_task_idx,
                job_index,
                status: TestJobStatus::Pending,
            });

            if spawn {
                self.process_channel.send(crate::event_loop::ProcessRequest::Spawn {
                    task: task_config,
                    job_index,
                    workspace_id: self.workspace_id,
                    job_id,
                });
            }
        }

        let test_run = TestRun { run_id, started_at: crate::clock::now(), test_jobs };
        state.active_test_run =
            Some(TestRun { run_id: test_run.run_id, started_at: test_run.started_at, test_jobs: Vec::new() });

        let group_id = state.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
        let base_tasks_in_group: Vec<BaseTaskIndex> = test_run.test_jobs.iter().map(|tj| tj.base_task_index).collect();
        let job_indices: Vec<JobIndex> = test_run.test_jobs.iter().map(|tj| tj.job_index).collect();

        state.last_test_group = Some(TestGroup { group_id, base_tasks: base_tasks_in_group, job_indices });

        Ok(test_run)
    }

    pub fn start_test_run_from_base_tasks(
        &self,
        base_task_indices: &[(BaseTaskIndex, Option<JobIndex>)],
    ) -> Result<TestRun, String> {
        let state = &mut *self.state.write().unwrap();
        state.change_number = state.change_number.wrapping_add(1);
        state.refresh_config();
        let log_start = self.logs.read().unwrap().tail();

        let run_id = state.active_test_run.as_ref().map_or(0, |r| r.run_id + 1);

        struct MatchedTest {
            base_task_idx: BaseTaskIndex,
            task_config: TaskConfigRc,
            spawn_profile: String,
            spawn_params: ValueMap<'static>,
        }
        let mut matched_tests = Vec::new();
        for &(base_task_idx, original_job) in base_task_indices {
            let Some(base_task) = state.base_tasks.get(base_task_idx.idx()) else {
                continue;
            };
            if base_task.removed {
                continue;
            }
            let (spawn_profile, spawn_params) = original_job
                .and_then(|ji| state.jobs.get(ji.idx()))
                .map(|job| (job.spawn_profile.clone(), job.spawn_params.clone()))
                .unwrap_or_else(|| (String::new(), ValueMap::new()));
            let env = Environment { profile: &spawn_profile, param: spawn_params.clone(), vars: base_task.config.vars };
            let Ok(task_config) = base_task.config.eval(&env) else {
                kvlog::error!("Failed to evaluate test config", name = base_task.name);
                continue;
            };
            drop(env);
            matched_tests.push(MatchedTest { base_task_idx, task_config, spawn_profile, spawn_params });
        }

        struct TestRequirements {
            base_task_idx: BaseTaskIndex,
            task_config: TaskConfigRc,
            spawn_profile: String,
            spawn_params: ValueMap<'static>,
            requirements: Vec<(RequirementKey, JobPredicate)>,
        }

        let mut batch: SpawnBatch<TestRequirements> = SpawnBatch::new();

        for matched in matched_tests {
            let task_config = &matched.task_config;
            let mut requirements = Vec::new();

            let mut service_profiles: hashbrown::HashMap<BaseTaskIndex, String> = hashbrown::HashMap::new();
            let mut services_to_check: Vec<(String, String)> = task_config
                .config()
                .require
                .iter()
                .filter_map(|tc| {
                    let dep_name = &*tc.name;
                    let dep_base_task = state.name_map.get(dep_name)?;
                    let dep_config = &state.base_tasks[dep_base_task.idx()].config;
                    if dep_config.kind == TaskKind::Service {
                        Some((dep_name.to_string(), tc.profile.unwrap_or("").to_string()))
                    } else {
                        None
                    }
                })
                .collect();
            let mut visited_services: hashbrown::HashSet<BaseTaskIndex> = hashbrown::HashSet::new();

            while let Some((dep_name, dep_profile)) = services_to_check.pop() {
                let Some(&dep_base_task) = state.name_map.get(&*dep_name) else {
                    continue;
                };
                let dep_config = &state.base_tasks[dep_base_task.idx()].config;

                if let Some(existing_profile) = service_profiles.get(&dep_base_task) {
                    if *existing_profile != dep_profile {
                        let test_name = state.base_tasks[matched.base_task_idx.idx()].name;
                        let service_name = state.base_tasks[dep_base_task.idx()].name;
                        return Err(format!(
                            "Test '{}' has conflicting service requirements: '{}:{}' and '{}:{}'",
                            test_name, service_name, existing_profile, service_name, dep_profile
                        ));
                    }
                    continue;
                }
                service_profiles.insert(dep_base_task, dep_profile.clone());

                if !visited_services.insert(dep_base_task) {
                    continue;
                }

                let env = Environment { profile: &dep_profile, param: ValueMap::new(), vars: dep_config.vars };
                if let Ok(srv_config) = dep_config.eval(&env) {
                    for req in srv_config.config().require.iter() {
                        let req_name = &*req.name;
                        let Some(&req_base_task) = state.name_map.get(req_name) else {
                            continue;
                        };
                        let req_config = &state.base_tasks[req_base_task.idx()].config;
                        if req_config.kind == TaskKind::Service {
                            services_to_check.push((req_name.to_string(), req.profile.unwrap_or("").to_string()));
                        }
                    }
                }
            }

            for tc in task_config.config().require.iter() {
                let dep_name = &*tc.name;
                let dep_profile = tc.profile.unwrap_or("");
                let dep_params = tc.vars.clone().to_owned();

                let Some(&dep_base_task) = state.name_map.get(dep_name) else {
                    continue;
                };
                let dep_config = &state.base_tasks[dep_base_task.idx()].config;

                let predicate = match dep_config.kind {
                    TaskKind::Action => JobPredicate::TerminatedNaturallyAndSuccessfully,
                    TaskKind::Service => JobPredicate::Active,
                    TaskKind::Test => continue,
                };

                let key = batch.add_requirement(dep_base_task, dep_profile, dep_params, predicate.clone());
                requirements.push((key, predicate));
            }

            batch.add_task(TestRequirements {
                base_task_idx: matched.base_task_idx,
                task_config: task_config.clone(),
                spawn_profile: matched.spawn_profile,
                spawn_params: matched.spawn_params,
                requirements,
            });
        }

        state.resolve_batch_requirements(self.workspace_id, &self.process_channel, &mut batch, log_start);

        let tasks = batch.take_tasks();
        let mut test_jobs = Vec::new();

        for task in tasks {
            let task_config = task.task_data.task_config;
            let spawn_profile = task.task_data.spawn_profile;
            let spawn_params = task.task_data.spawn_params;
            let mut pred = Vec::new();

            for (key, predicate) in &task.task_data.requirements {
                match batch.get_resolved(key) {
                    Some(ResolvedRequirement::Cached) => {}
                    Some(ResolvedRequirement::Pending(ji)) | Some(ResolvedRequirement::Spawned(ji)) => {
                        pred.push(ScheduleRequirement { job: *ji, predicate: predicate.clone() });
                    }
                    None => {}
                }
            }

            let cache_key =
                task_config.config().cache.as_ref().map_or(String::new(), |c| state.compute_cache_key(c.key));

            let job_index = JobIndex(state.jobs.len() as u32);
            let base_task = &mut state.base_tasks[task.task_data.base_task_idx.idx()];
            let task_name = base_task.name;
            let pc = base_task.jobs.len();
            let job_id = LogGroup::new(task.task_data.base_task_idx, pc);

            let spawn = pred.is_empty();
            if spawn {
                base_task.jobs.push_active(job_index);
                state.test_jobs.push_active(job_index);
            } else {
                base_task.jobs.push_scheduled(job_index);
                state.test_jobs.push_scheduled(job_index);
            }

            for req in &pred {
                if matches!(req.predicate, JobPredicate::Active) {
                    state.service_dependents.add_dependent(req.job, job_index);
                }
            }

            state.jobs.push(Job {
                process_status: if !spawn { JobStatus::Scheduled { after: pred } } else { JobStatus::Starting },
                log_group: job_id,
                task: task_config.clone(),
                started_at: crate::clock::now(),
                log_start,
                cache_key,
                spawn_profile,
                spawn_params,
            });

            if !spawn {
                kvlog::info!("Job scheduled", task_name, job_index, reason = ScheduleReason::TestRun.name());
            }

            test_jobs.push(TestJob {
                base_task_index: task.task_data.base_task_idx,
                job_index,
                status: TestJobStatus::Pending,
            });

            if spawn {
                self.process_channel.send(crate::event_loop::ProcessRequest::Spawn {
                    task: task_config,
                    job_index,
                    workspace_id: self.workspace_id,
                    job_id,
                });
            }
        }

        let test_run = TestRun { run_id, started_at: crate::clock::now(), test_jobs };
        state.active_test_run =
            Some(TestRun { run_id: test_run.run_id, started_at: test_run.started_at, test_jobs: Vec::new() });

        let group_id = state.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
        let base_tasks_in_group: Vec<BaseTaskIndex> = test_run.test_jobs.iter().map(|tj| tj.base_task_index).collect();
        let job_indices: Vec<JobIndex> = test_run.test_jobs.iter().map(|tj| tj.job_index).collect();

        state.last_test_group = Some(TestGroup { group_id, base_tasks: base_tasks_in_group, job_indices });

        Ok(test_run)
    }

    /// Reruns the last test group.
    /// If only_failed is true, only runs tests that failed in the last run.
    /// Returns the TestRun or an error if no test group exists.
    pub fn rerun_test_group(&self, only_failed: bool) -> Result<TestRun, String> {
        let state = self.state.read().unwrap();
        let test_group = state.last_test_group.as_ref().ok_or("No test group to rerun")?;

        let tasks_to_run: Vec<(BaseTaskIndex, Option<JobIndex>)> = if only_failed {
            let mut failed = Vec::new();
            for (i, &job_index) in test_group.job_indices.iter().enumerate() {
                let Some(job) = state.jobs.get(job_index.idx()) else { continue };
                let is_failed = matches!(&job.process_status, JobStatus::Exited { status, .. } if *status != 0)
                    || matches!(&job.process_status, JobStatus::Cancelled);
                if is_failed && let Some(&bti) = test_group.base_tasks.get(i) {
                    failed.push((bti, Some(job_index)));
                }
            }
            if failed.is_empty() {
                return Err("No failed tests to rerun".to_string());
            }
            failed
        } else {
            test_group.base_tasks.iter().zip(test_group.job_indices.iter()).map(|(&bti, &ji)| (bti, Some(ji))).collect()
        };

        if tasks_to_run.is_empty() {
            return Err("No tests to rerun".to_string());
        }

        drop(state);
        self.start_test_run_from_base_tasks(&tasks_to_run)
    }

    /// Narrows the test group by removing passed tests.
    /// Returns Ok(count) with number of remaining failed tests, or Err if no failures.
    pub fn narrow_test_group(&self) -> Result<usize, String> {
        let mut state = self.state.write().unwrap();

        let test_group = state.last_test_group.as_ref().ok_or("No test group to narrow")?;
        let job_indices = test_group.job_indices.clone();
        let base_tasks = test_group.base_tasks.clone();

        let mut failed_indices = Vec::new();
        for (i, &job_index) in job_indices.iter().enumerate() {
            let Some(job) = state.jobs.get(job_index.idx()) else { continue };
            let failed = matches!(&job.process_status, JobStatus::Exited { status, .. } if *status != 0)
                || matches!(&job.process_status, JobStatus::Cancelled);
            if failed {
                failed_indices.push(i);
            }
        }

        if failed_indices.is_empty() {
            return Err("No failed tests to narrow to".to_string());
        }

        let new_job_indices: Vec<JobIndex> =
            failed_indices.iter().filter_map(|&i| job_indices.get(i).copied()).collect();
        let new_base_tasks: Vec<BaseTaskIndex> =
            failed_indices.iter().filter_map(|&i| base_tasks.get(i).copied()).collect();

        let count = new_job_indices.len();
        let test_group = state.last_test_group.as_mut().unwrap();
        test_group.job_indices = new_job_indices;
        test_group.base_tasks = new_base_tasks;
        state.change_number = state.change_number.wrapping_add(1);
        Ok(count)
    }
}

/// Persistent record of a test group for rerun functionality.
pub struct TestGroup {
    pub group_id: u32,
    /// Base task indices included in this group.
    pub base_tasks: Vec<BaseTaskIndex>,
    /// Associated job indices from the test run.
    pub job_indices: Vec<JobIndex>,
}

/// Summary for status bar display.
#[derive(Clone, Copy, Default)]
pub struct TestGroupSummary {
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
    pub running: u32,
    pub pending: u32,
}

/// Checks if a test matches the given filters.
/// Filter logic:
/// - `include_names`: Test name must match one (if any specified)
/// - `include_tags`: Test must have at least one matching tag (if any specified)
/// - `exclude_tags`: Test must not have any matching tags (if any specified)
/// - All conditions are AND'd together
fn matches_test_filters(name: &str, tags: &[&str], filters: &[TestFilter]) -> bool {
    let mut include_names: Vec<&str> = Vec::new();
    let mut include_tags: Vec<&str> = Vec::new();
    let mut exclude_tags: Vec<&str> = Vec::new();

    for filter in filters {
        match filter {
            TestFilter::IncludeName(n) => include_names.push(n),
            TestFilter::IncludeTag(t) => include_tags.push(t),
            TestFilter::ExcludeTag(t) => exclude_tags.push(t),
        }
    }

    if !include_names.is_empty() && !include_names.iter().any(|prefix| name.starts_with(prefix)) {
        return false;
    }
    if !include_tags.is_empty() && !include_tags.iter().any(|tag| tags.contains(tag)) {
        return false;
    }
    if !exclude_tags.is_empty() && exclude_tags.iter().any(|tag| tags.contains(tag)) {
        return false;
    }
    true
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;

    #[test]
    fn test_job_status_is_pending_completion() {
        assert!(JobStatus::Scheduled { after: vec![] }.is_pending_completion());
        assert!(JobStatus::Starting.is_pending_completion());
        assert!(JobStatus::Running { process_index: 0, ready_state: None }.is_pending_completion());
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
        assert!(!JobStatus::Running { process_index: 0, ready_state: None }.is_successful_completion());
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
        // when evaluating the TerminatedNaturallyAndSuccessfully predicate.
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
        assert_eq!(extracted, Some(("log_storage::tests::test_rotation_on_max_lines", "src/log_storage.rs", 639, 9)));
    }

    mod service_dependents_tests {
        use super::*;

        #[test]
        fn empty_dependents_can_stop() {
            let dependents = ServiceDependents::default();
            let service = JobIndex::from_usize(0);
            assert!(dependents.can_stop(service));
            assert_eq!(dependents.dependent_count(service), 0);
        }

        #[test]
        fn add_dependent_tracks_relationship() {
            let mut dependents = ServiceDependents::default();
            let service = JobIndex::from_usize(0);
            let dependent1 = JobIndex::from_usize(1);
            let dependent2 = JobIndex::from_usize(2);

            dependents.add_dependent(service, dependent1);
            assert!(!dependents.can_stop(service));
            assert_eq!(dependents.dependent_count(service), 1);

            dependents.add_dependent(service, dependent2);
            assert!(!dependents.can_stop(service));
            assert_eq!(dependents.dependent_count(service), 2);
        }

        #[test]
        fn remove_dependent_updates_count() {
            let mut dependents = ServiceDependents::default();
            let service = JobIndex::from_usize(0);
            let dependent1 = JobIndex::from_usize(1);
            let dependent2 = JobIndex::from_usize(2);

            dependents.add_dependent(service, dependent1);
            dependents.add_dependent(service, dependent2);
            assert_eq!(dependents.dependent_count(service), 2);

            dependents.remove_dependent(service, dependent1);
            assert_eq!(dependents.dependent_count(service), 1);
            assert!(!dependents.can_stop(service));

            dependents.remove_dependent(service, dependent2);
            assert_eq!(dependents.dependent_count(service), 0);
            assert!(dependents.can_stop(service));
        }

        #[test]
        fn remove_from_all_clears_dependent() {
            let mut dependents = ServiceDependents::default();
            let service1 = JobIndex::from_usize(0);
            let service2 = JobIndex::from_usize(1);
            let dependent = JobIndex::from_usize(2);

            dependents.add_dependent(service1, dependent);
            dependents.add_dependent(service2, dependent);
            assert_eq!(dependents.dependent_count(service1), 1);
            assert_eq!(dependents.dependent_count(service2), 1);

            dependents.remove_from_all(dependent);
            assert_eq!(dependents.dependent_count(service1), 0);
            assert_eq!(dependents.dependent_count(service2), 0);
            assert!(dependents.can_stop(service1));
            assert!(dependents.can_stop(service2));
        }

        #[test]
        fn duplicate_add_is_idempotent() {
            let mut dependents = ServiceDependents::default();
            let service = JobIndex::from_usize(0);
            let dependent = JobIndex::from_usize(1);

            dependents.add_dependent(service, dependent);
            dependents.add_dependent(service, dependent);
            dependents.add_dependent(service, dependent);
            assert_eq!(dependents.dependent_count(service), 1);
        }

        #[test]
        fn remove_nonexistent_is_safe() {
            let mut dependents = ServiceDependents::default();
            let service = JobIndex::from_usize(0);
            let dependent = JobIndex::from_usize(1);

            dependents.remove_dependent(service, dependent);
            dependents.remove_from_all(dependent);
            assert!(dependents.can_stop(service));
        }

        #[test]
        fn multiple_services_tracked_independently() {
            let mut dependents = ServiceDependents::default();
            let service1 = JobIndex::from_usize(0);
            let service2 = JobIndex::from_usize(1);
            let dep_a = JobIndex::from_usize(10);
            let dep_b = JobIndex::from_usize(11);
            let dep_c = JobIndex::from_usize(12);

            dependents.add_dependent(service1, dep_a);
            dependents.add_dependent(service1, dep_b);
            dependents.add_dependent(service2, dep_c);

            assert_eq!(dependents.dependent_count(service1), 2);
            assert_eq!(dependents.dependent_count(service2), 1);

            dependents.remove_dependent(service1, dep_a);
            assert_eq!(dependents.dependent_count(service1), 1);
            assert_eq!(dependents.dependent_count(service2), 1);
        }
    }

    mod requirement_key_tests {
        use super::*;
        use jsony_value::ValueMap;

        #[test]
        fn same_inputs_produce_same_key() {
            let base_task = BaseTaskIndex(0);
            let profile = "test";
            let params = ValueMap::new();

            let key1 = RequirementKey::new(base_task, profile, &params);
            let key2 = RequirementKey::new(base_task, profile, &params);

            assert_eq!(key1, key2);
            assert_eq!(key1.params_hash, key2.params_hash);
        }

        #[test]
        fn different_profile_produces_different_key() {
            let base_task = BaseTaskIndex(0);
            let params = ValueMap::new();

            let key1 = RequirementKey::new(base_task, "profile1", &params);
            let key2 = RequirementKey::new(base_task, "profile2", &params);

            assert_ne!(key1, key2);
        }

        #[test]
        fn different_base_task_produces_different_key() {
            let profile = "test";
            let params = ValueMap::new();

            let key1 = RequirementKey::new(BaseTaskIndex(0), profile, &params);
            let key2 = RequirementKey::new(BaseTaskIndex(1), profile, &params);

            assert_ne!(key1, key2);
        }

        #[test]
        fn key_is_hashable() {
            use std::collections::HashSet;

            let base_task = BaseTaskIndex(0);
            let params = ValueMap::new();

            let key1 = RequirementKey::new(base_task, "a", &params);
            let key2 = RequirementKey::new(base_task, "b", &params);
            let key3 = RequirementKey::new(base_task, "a", &params);

            let mut set = HashSet::new();
            set.insert(key1.clone());
            set.insert(key2);
            set.insert(key3);

            assert_eq!(set.len(), 2);
        }
    }

    mod spawn_batch_tests {
        use super::*;
        use jsony_value::ValueMap;

        #[test]
        fn empty_batch_has_no_requirements() {
            let batch: SpawnBatch<()> = SpawnBatch::new();
            assert_eq!(batch.requirement_count(), 0);
        }

        #[test]
        fn add_requirement_increases_count() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            let base_task = BaseTaskIndex(0);

            batch.add_requirement(base_task, "test", ValueMap::new().to_owned(), JobPredicate::Active);
            assert_eq!(batch.requirement_count(), 1);

            batch.add_requirement(BaseTaskIndex(1), "test", ValueMap::new().to_owned(), JobPredicate::Active);
            assert_eq!(batch.requirement_count(), 2);
        }

        #[test]
        fn duplicate_requirement_is_deduplicated() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            let base_task = BaseTaskIndex(0);

            let key1 = batch.add_requirement(base_task, "test", ValueMap::new().to_owned(), JobPredicate::Active);
            let key2 = batch.add_requirement(base_task, "test", ValueMap::new().to_owned(), JobPredicate::Active);
            let key3 = batch.add_requirement(base_task, "test", ValueMap::new().to_owned(), JobPredicate::Active);

            assert_eq!(batch.requirement_count(), 1);
            assert_eq!(key1, key2);
            assert_eq!(key2, key3);
        }

        #[test]
        fn different_profiles_not_deduplicated() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            let base_task = BaseTaskIndex(0);

            batch.add_requirement(base_task, "profile1", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(base_task, "profile2", ValueMap::new().to_owned(), JobPredicate::Active);

            assert_eq!(batch.requirement_count(), 2);
        }

        #[test]
        fn mark_resolved_and_get_resolved() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            let base_task = BaseTaskIndex(0);

            let key = batch.add_requirement(base_task, "test", ValueMap::new().to_owned(), JobPredicate::Active);

            assert!(batch.get_resolved(&key).is_none());

            batch.mark_resolved(key.clone(), ResolvedRequirement::Spawned(JobIndex::from_usize(5)));

            match batch.get_resolved(&key) {
                Some(ResolvedRequirement::Spawned(ji)) => assert_eq!(ji.idx(), 5),
                _ => panic!("Expected Spawned resolution"),
            }
        }

        #[test]
        fn mark_resolved_cached() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            let key = batch.add_requirement(BaseTaskIndex(0), "test", ValueMap::new().to_owned(), JobPredicate::Active);

            batch.mark_resolved(key.clone(), ResolvedRequirement::Cached);

            assert!(matches!(batch.get_resolved(&key), Some(ResolvedRequirement::Cached)));
        }

        #[test]
        fn mark_resolved_pending() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            let key = batch.add_requirement(BaseTaskIndex(0), "test", ValueMap::new().to_owned(), JobPredicate::Active);
            let existing_job = JobIndex::from_usize(3);

            batch.mark_resolved(key.clone(), ResolvedRequirement::Pending(existing_job));

            match batch.get_resolved(&key) {
                Some(ResolvedRequirement::Pending(ji)) => assert_eq!(ji.idx(), 3),
                _ => panic!("Expected Pending resolution"),
            }
        }

        #[test]
        fn pending_requirements_iterator() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();

            batch.add_requirement(BaseTaskIndex(0), "a", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(1), "b", ValueMap::new().to_owned(), JobPredicate::Terminated);

            let reqs: Vec<_> = batch.pending_requirements().collect();
            assert_eq!(reqs.len(), 2);
        }

        #[test]
        fn no_conflicts_with_same_profile() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            batch.add_requirement(BaseTaskIndex(0), "alpha", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(0), "alpha", ValueMap::new().to_owned(), JobPredicate::Active);

            let conflicts = batch.detect_profile_conflicts();
            assert!(conflicts.is_empty(), "Same profile should not conflict");
        }

        #[test]
        fn conflict_with_different_profiles() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            batch.add_requirement(BaseTaskIndex(0), "alpha", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(0), "beta", ValueMap::new().to_owned(), JobPredicate::Active);

            let conflicts = batch.detect_profile_conflicts();
            assert_eq!(conflicts.len(), 1, "Different profiles should conflict");
            assert_eq!(conflicts[0].base_task, BaseTaskIndex(0));
            assert!(conflicts[0].profiles.contains(&"alpha".to_string()));
            assert!(conflicts[0].profiles.contains(&"beta".to_string()));
        }

        #[test]
        fn multiple_conflicts_detected() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            batch.add_requirement(BaseTaskIndex(0), "alpha", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(0), "beta", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(1), "prod", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(1), "dev", ValueMap::new().to_owned(), JobPredicate::Active);

            let conflicts = batch.detect_profile_conflicts();
            assert_eq!(conflicts.len(), 2, "Should detect conflicts for both base tasks");
        }

        #[test]
        fn different_base_tasks_no_conflict() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();
            batch.add_requirement(BaseTaskIndex(0), "alpha", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(1), "beta", ValueMap::new().to_owned(), JobPredicate::Active);

            let conflicts = batch.detect_profile_conflicts();
            assert!(conflicts.is_empty(), "Different base tasks should not conflict");
        }
    }

    mod service_compatibility_tests {
        use super::*;

        #[test]
        fn service_compatibility_enum_variants() {
            let compatible = ServiceCompatibility::Compatible(JobIndex::from_usize(0));
            let available = ServiceCompatibility::Available;
            let conflict = ServiceCompatibility::Conflict {
                running_job: JobIndex::from_usize(1),
                running_profile: "prod".to_string(),
                requested_profile: "test".to_string(),
            };

            match compatible {
                ServiceCompatibility::Compatible(ji) => assert_eq!(ji.idx(), 0),
                _ => panic!("Expected Compatible"),
            }

            match available {
                ServiceCompatibility::Available => {}
                _ => panic!("Expected Available"),
            }

            match conflict {
                ServiceCompatibility::Conflict { running_job, running_profile, requested_profile } => {
                    assert_eq!(running_job.idx(), 1);
                    assert_eq!(running_profile, "prod");
                    assert_eq!(requested_profile, "test");
                }
                _ => panic!("Expected Conflict"),
            }
        }
    }
}
