use crate::{
    cache_key::CacheKeyHasher,
    cli::TestFilter,
    config::{
        AllowMultiple, CARGO_AUTO_EXPR, CacheKeyInput, Command, ConfigGeneration, Environment, TaskConfigRc,
        TaskConfigSource, TaskKind,
    },
    event_loop::MioChannel,
    function::FunctionAction,
    log_storage::{LogGroup, Logs},
};
pub use job_index_list::JobIndexList;
pub use job_store::{JobIndex, JobStore};
use jsony_value::{Value, ValueMap, ValueNumber, ValueRef};
use std::{
    path::PathBuf,
    sync::{Arc, RwLock, Weak},
    time::{Instant, SystemTime},
};
mod job_index_list;
mod job_store;

/// Lower bound on `[daemon] max_job_history`. Values below this are clamped
/// up so eviction still has room to work — the 25% churn per batch would
/// otherwise fire on almost every insert.
pub const MIN_JOB_HISTORY: u32 = 128;
/// Upper bound on `[daemon] max_job_history`. Guards against absurd user
/// input. 1M live jobs at ~128 bytes each is already ~128 MB of metadata —
/// well past any reasonable dev workflow.
pub const MAX_JOB_HISTORY: u32 = 1_000_000;
/// Default when `[daemon] max_job_history` is absent.
pub const DEFAULT_JOB_HISTORY: u32 = 10_000;

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
            hash_value(&mut hasher, v);
        }
    }
    hasher.finalize_hex()
}

/// Byte sink for structural hashing. Implemented by both `CacheKeyHasher`
/// (used for user-visible cache keys) and `blake3::Hasher` (used for
/// internal cache-bucket keys).
trait HashByteSink {
    fn update(&mut self, bytes: &[u8]);
}

impl HashByteSink for CacheKeyHasher {
    fn update(&mut self, bytes: &[u8]) {
        CacheKeyHasher::update(self, bytes)
    }
}

impl HashByteSink for blake3::Hasher {
    fn update(&mut self, bytes: &[u8]) {
        blake3::Hasher::update(self, bytes);
    }
}

fn hash_len_prefixed(hasher: &mut impl HashByteSink, bytes: &[u8]) {
    let len: u32 = bytes.len().try_into().expect("hash input too large");
    hasher.update(&len.to_le_bytes());
    hasher.update(bytes);
}

fn hash_value(hasher: &mut impl HashByteSink, value: &Value<'_>) {
    match value.as_ref() {
        ValueRef::Null(_) => hasher.update(b"n"),
        ValueRef::Number(number) => {
            hasher.update(b"d");
            match number {
                ValueNumber::U64(value) => {
                    hasher.update(b"u");
                    hasher.update(&value.to_le_bytes());
                }
                ValueNumber::I64(value) => {
                    hasher.update(b"i");
                    hasher.update(&value.to_le_bytes());
                }
                ValueNumber::F64(value) => {
                    hasher.update(b"f");
                    hasher.update(&value.to_bits().to_le_bytes());
                }
            }
        }
        ValueRef::String(value) => {
            hasher.update(b"s");
            hash_len_prefixed(hasher, value.as_bytes());
        }
        ValueRef::Other(value) => {
            hasher.update(b"o");
            hash_len_prefixed(hasher, value.as_bytes());
        }
        ValueRef::Map(map) => {
            hasher.update(b"m");
            let len: u32 = map.entries().len().try_into().expect("hash map too large");
            hasher.update(&len.to_le_bytes());
            for (key, value) in map.entries() {
                hash_len_prefixed(hasher, key.as_bytes());
                hash_value(hasher, value);
            }
        }
        ValueRef::List(list) => {
            hasher.update(b"l");
            let len: u32 = list.as_slice().len().try_into().expect("hash list too large");
            hasher.update(&len.to_le_bytes());
            for value in list.as_slice() {
                hash_value(hasher, value);
            }
        }
        ValueRef::Boolean(value) => {
            if value.value == 0 {
                hasher.update(b"b0");
            } else {
                hasher.update(b"b1");
            }
        }
    }
}

fn hash_value_map(hasher: &mut impl HashByteSink, params: &ValueMap) {
    let len: u32 = params.entries().len().try_into().expect("hash map too large");
    hasher.update(&len.to_le_bytes());
    for (key, value) in params.entries() {
        hash_len_prefixed(hasher, key.as_bytes());
        hash_value(hasher, value);
    }
}

fn blake3_to_u64(hasher: &blake3::Hasher) -> u64 {
    let bytes = hasher.finalize();
    u64::from_le_bytes(bytes.as_bytes()[..8].try_into().unwrap())
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
    pub started_at: Instant,
    /// Computed cache key for cache invalidation. Empty string means no key-based caching.
    pub cache_key: String,
    pub spawn: Arc<ResolvedSpawnSpec>,
}

pub struct ResolvedSpawnSpec {
    pub generation_id: u64,
    pub base_task: BaseTaskIndex,
    pub task: TaskConfigRc,
    pub profile: Box<str>,
    pub params: Arc<ValueMap<'static>>,
}

impl Job {
    pub fn task(&self) -> &TaskConfigRc {
        &self.spawn.task
    }

    pub fn spawn_profile(&self) -> &str {
        &self.spawn.profile
    }

    pub fn spawn_params(&self) -> &ValueMap<'static> {
        self.spawn.params.as_ref()
    }
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
        let Some(job) = ws.jobs.get(self.job) else {
            return RequirementStatus::Met;
        };
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
    pub current: Arc<ConfigGeneration>,
}

impl LatestConfig {
    fn new(path: PathBuf) -> Result<Self, crate::config::ConfigError> {
        let metadata = path.metadata().map_err(|e| crate::config::ConfigError {
            message: format!("error: failed to read {}: {}\n", path.display(), e),
        })?;
        let modified_time = metadata.modified().map_err(|e| crate::config::ConfigError {
            message: format!("error: failed to get modification time for {}: {}\n", path.display(), e),
        })?;
        let content = std::fs::read_to_string(&path).map_err(|e| crate::config::ConfigError {
            message: format!("error: failed to read {}: {}\n", path.display(), e),
        })?;
        let current = crate::config::load_workspace_generation_capturing(&path, content)?;
        Ok(Self { modified_time, path, current })
    }
    fn refresh(&mut self) -> anyhow::Result<bool> {
        let metadata = self.path.metadata()?;
        let modified = metadata.modified()?;
        if self.modified_time == modified {
            return Ok(false);
        }
        let content = std::fs::read_to_string(&self.path)?;
        let new_config = crate::config::load_workspace_generation_capturing(&self.path, content)
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
        let new_config =
            crate::config::load_workspace_generation_capturing(&self.path, content).map_err(|e| e.message)?;

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
        name_map: &mut hashbrown::HashMap<Box<str>, BaseTaskIndex>,
    ) {
        for base_task in base_tasks.iter_mut() {
            base_task.removed = true;
        }
        let generation = self.current.clone();
        for (task_index, (name, _)) in self.current.workspace().tasks.iter().enumerate() {
            let config = TaskConfigSource::from_workspace_task(generation.clone(), task_index);
            if let Some(&index) = name_map.get(*name) {
                let base_task = &mut base_tasks[index.idx()];
                base_task.removed = false;
                base_task.config = config;
                continue;
            }
            if base_tasks.len() > u32::MAX as usize {
                panic!("Too many base tasks");
            }
            let index = BaseTaskIndex(base_tasks.len() as u32);
            name_map.insert((*name).into(), index);
            base_tasks.push(BaseTask {
                name: (*name).into(),
                config,
                removed: false,
                jobs: JobIndexList::default(),
                profile_change_counter: 0,
                spawn_counter: 0,
                last_profile: None,
                has_run_this_session: false,
            });
        }
        for (derived_index, derived) in self.current.derived_tests.iter().enumerate() {
            let config = TaskConfigSource::from_derived_test(generation.clone(), derived_index);
            if let Some(&index) = name_map.get(derived.entry_name.as_ref()) {
                let base_task = &mut base_tasks[index.idx()];
                base_task.removed = false;
                base_task.config = config;
                continue;
            }
            let index = BaseTaskIndex::new_or_panic(base_tasks.len());
            name_map.insert(derived.entry_name.clone(), index);
            base_tasks.push(BaseTask {
                name: derived.display_name.clone(),
                config,
                removed: false,
                jobs: JobIndexList::default(),
                profile_change_counter: 0,
                spawn_counter: 0,
                last_profile: None,
                has_run_this_session: false,
            });
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
    pub name: Box<str>,
    pub config: TaskConfigSource,
    pub removed: bool,
    pub jobs: JobIndexList,
    /// Counter incremented when the task's profile changes (not on first run).
    /// Used as cache key input for `profile_changed` invalidation.
    pub profile_change_counter: u32,
    /// Monotonic count of jobs ever spawned for this base task. Feeds the
    /// LogGroup counter so a log group id stays unique across the daemon
    /// lifetime even after old jobs are pruned from `jobs` by history
    /// eviction. Never decremented.
    pub spawn_counter: u32,
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

fn spawn_spec_cache_key(generation_id: u64, base_task: BaseTaskIndex, profile: &str, params: &ValueMap) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&generation_id.to_le_bytes());
    hasher.update(&base_task.0.to_le_bytes());
    hash_len_prefixed(&mut hasher, profile.as_bytes());
    hash_value_map(&mut hasher, params);
    blake3_to_u64(&hasher)
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

struct MatchedTest {
    base_task_idx: BaseTaskIndex,
    task_config: TaskConfigRc,
    spawn_profile: String,
    spawn_params: ValueMap<'static>,
}

/// Checks if a running service job matches the required profile and parameters.
fn service_matches_require(job: &Job, require_profile: &str, require_params: &ValueMap) -> bool {
    if !require_profile.is_empty() && job.spawn_profile() != require_profile {
        return false;
    }
    require_params == job.spawn_params()
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

    /// Drop the entry for an evicted service (if any). Callers should only
    /// invoke this after the service has moved to a terminal state and its
    /// dependents have all been released via [`remove_from_all`].
    pub fn remove_service(&mut self, service: JobIndex) {
        self.dependents.remove(&service);
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
///
/// `params_digest` is the full 256-bit blake3 digest of the params, not a
/// truncated hash — this key is used as an identity (via derived `Eq`), so
/// truncation would fold distinct requirements into one.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RequirementKey {
    pub base_task: BaseTaskIndex,
    pub profile: String,
    pub params_digest: [u8; blake3::OUT_LEN],
}

impl RequirementKey {
    pub fn new(base_task: BaseTaskIndex, profile: &str, params: &ValueMap) -> Self {
        let mut hasher = blake3::Hasher::new();
        hash_value_map(&mut hasher, params);
        Self { base_task, profile: profile.to_string(), params_digest: *hasher.finalize().as_bytes() }
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
    pub name_map: hashbrown::HashMap<Box<str>, BaseTaskIndex>,
    pub jobs: JobStore,
    /// Maximum live jobs retained in `jobs` before history pruning kicks in.
    pub max_job_history: u32,
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
    spawn_specs: hashbrown::HashMap<u64, Vec<Weak<ResolvedSpawnSpec>>>,
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
                        let full_path = self.config.current.base_path().join(path);
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
                        let full_path = self.config.current.base_path().join(path);
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
                hash_value(&mut self.cache_key_hasher, v);
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
                name: "~cargo".into(),
                config: TaskConfigSource::Static(&CARGO_AUTO_EXPR),
                removed: false,
                jobs: JobIndexList::default(),
                profile_change_counter: 0,
                spawn_counter: 0,
                last_profile: None,
                has_run_this_session: false,
            });
            if index > u32::MAX as usize {
                panic!("Too many base tasks");
            }
            let index = BaseTaskIndex(index as u32);
            self.name_map.insert("~cargo".into(), index);
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
            self.spawn_specs.clear();
        }
        // Pick up any daemon-side knob the user has adjusted via
        // ~/.config/devsm.user.toml reload, independent of whether the
        // workspace toml itself changed.
        self.max_job_history = crate::user_config::global_max_job_history();
    }

    fn get_or_create_spawn_spec(
        &mut self,
        base_task: BaseTaskIndex,
        profile: &str,
        params: ValueMap<'static>,
    ) -> Arc<ResolvedSpawnSpec> {
        let generation_id = self.base_tasks[base_task.idx()].config.generation_id();
        if let Some(spec) = self.find_cached_spawn_spec(generation_id, base_task, profile, &params) {
            return spec;
        }
        let config = self.base_tasks[base_task.idx()].config.clone();
        let env = Environment { profile, param: params.clone(), vars: config.vars };
        let task = config.eval(&env).unwrap();
        self.insert_spawn_spec(generation_id, base_task, profile, params, task)
    }

    fn cache_spawn_spec(
        &mut self,
        base_task: BaseTaskIndex,
        profile: &str,
        params: ValueMap<'static>,
        task: TaskConfigRc,
    ) -> Arc<ResolvedSpawnSpec> {
        let generation_id = self.base_tasks[base_task.idx()].config.generation_id();
        if let Some(spec) = self.find_cached_spawn_spec(generation_id, base_task, profile, &params) {
            return spec;
        }
        self.insert_spawn_spec(generation_id, base_task, profile, params, task)
    }

    fn find_cached_spawn_spec(
        &mut self,
        generation_id: u64,
        base_task: BaseTaskIndex,
        profile: &str,
        params: &ValueMap<'static>,
    ) -> Option<Arc<ResolvedSpawnSpec>> {
        let cache_key = spawn_spec_cache_key(generation_id, base_task, profile, params);
        let specs = self.spawn_specs.get_mut(&cache_key)?;
        let mut found = None;
        specs.retain(|spec| {
            let Some(spec) = spec.upgrade() else {
                return false;
            };
            if found.is_none()
                && spec.generation_id == generation_id
                && spec.base_task == base_task
                && spec.profile.as_ref() == profile
                && spec.params.as_ref() == params
            {
                found = Some(spec.clone());
            }
            true
        });
        found
    }

    fn insert_spawn_spec(
        &mut self,
        generation_id: u64,
        base_task: BaseTaskIndex,
        profile: &str,
        params: ValueMap<'static>,
        task: TaskConfigRc,
    ) -> Arc<ResolvedSpawnSpec> {
        let cache_key = spawn_spec_cache_key(generation_id, base_task, profile, &params);
        let spec = Arc::new(ResolvedSpawnSpec {
            generation_id,
            base_task,
            task,
            profile: profile.into(),
            params: Arc::new(params),
        });
        self.spawn_specs.entry(cache_key).or_default().push(Arc::downgrade(&spec));
        spec
    }

    fn plan_conflicts(
        &mut self,
        base_task: BaseTaskIndex,
        profile: &str,
        force_restart: bool,
        channel: &MioChannel,
    ) -> Vec<ScheduleRequirement> {
        let bt = &mut self.base_tasks[base_task.idx()];
        let task_kind = bt.config.kind;
        let allow_multiple = if force_restart { AllowMultiple::False } else { bt.config.allow_multiple };
        let mut pred = Vec::new();

        match allow_multiple {
            AllowMultiple::False => {
                for &job_index in bt.jobs.terminate_scheduled() {
                    self.jobs[job_index].process_status = JobStatus::Cancelled;
                    match task_kind {
                        TaskKind::Action => self.action_jobs.set_terminal(job_index),
                        TaskKind::Test => self.test_jobs.set_terminal(job_index),
                        TaskKind::Service => self.service_jobs.set_terminal(job_index),
                    }
                    self.service_dependents.remove_from_all(job_index);
                }

                for &job_index in bt.jobs.running() {
                    let job = &mut self.jobs[job_index];
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
            }
            AllowMultiple::True => {
                // No killing — new instance spawns alongside existing ones.
            }
            AllowMultiple::DistinctProfiles | AllowMultiple::SingleProfile => {
                let match_same = matches!(allow_multiple, AllowMultiple::DistinctProfiles);
                let to_cancel: Vec<_> = self.base_tasks[base_task.idx()]
                    .jobs
                    .scheduled()
                    .iter()
                    .filter(|ji| (self.jobs[**ji].spawn_profile() == profile) == match_same)
                    .copied()
                    .collect();
                for job_index in &to_cancel {
                    self.jobs[*job_index].process_status = JobStatus::Cancelled;
                    let bt = &mut self.base_tasks[base_task.idx()];
                    bt.jobs.set_terminal(*job_index);
                    match task_kind {
                        TaskKind::Action => self.action_jobs.set_terminal(*job_index),
                        TaskKind::Test => self.test_jobs.set_terminal(*job_index),
                        TaskKind::Service => self.service_jobs.set_terminal(*job_index),
                    }
                    self.service_dependents.remove_from_all(*job_index);
                }

                let to_terminate: Vec<_> = self.base_tasks[base_task.idx()]
                    .jobs
                    .running()
                    .iter()
                    .filter(|ji| (self.jobs[**ji].spawn_profile() == profile) == match_same)
                    .copied()
                    .collect();
                for job_index in to_terminate {
                    let job = &self.jobs[job_index];
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
            }
        }

        pred
    }

    fn spawn_task(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        base_task: BaseTaskIndex,
        params: ValueMap,
        profile: &str,
        reason: ScheduleReason,
        force_restart: bool,
    ) -> JobIndex {
        let profile = {
            let bt = &self.base_tasks[base_task.idx()];
            if profile.is_empty() { bt.config.profiles.first().copied().unwrap_or("") } else { profile }
        }
        .to_string();
        let params = params.to_owned();
        let bt = &mut self.base_tasks[base_task.idx()];
        bt.update_profile_tracking(&profile);

        let mut pred = self.plan_conflicts(base_task, &profile, force_restart, channel);
        let spec = self.get_or_create_spawn_spec(base_task, &profile, params.clone());
        let task = spec.task.clone();

        let mut batch: SpawnBatch<()> = SpawnBatch::new();
        let mut req_keys = Vec::new();

        for dep_call in task.config().require {
            let dep_name = &*dep_call.name;
            let dep_profile = dep_call.profile.unwrap_or("");
            let dep_params = dep_call.vars.clone().to_owned();

            let Some(&dep_base_task) = self.name_map.get(dep_name) else {
                kvlog::error!("unknown alias", dep_name);
                continue;
            };
            let dep_config = &self.base_tasks[dep_base_task.idx()].config;

            let predicate = match dep_config.kind {
                TaskKind::Action => JobPredicate::TerminatedNaturallyAndSuccessfully,
                TaskKind::Service => JobPredicate::Active,
                TaskKind::Test => continue,
            };

            let key = batch.add_requirement(dep_base_task, dep_profile, dep_params, predicate.clone());
            req_keys.push((key, predicate));
        }

        self.resolve_batch_requirements(workspace_id, channel, &mut batch);

        for (key, predicate) in &req_keys {
            match batch.get_resolved(key) {
                Some(ResolvedRequirement::Cached) => {}
                Some(ResolvedRequirement::Pending(ji)) | Some(ResolvedRequirement::Spawned(ji)) => {
                    pred.push(ScheduleRequirement { job: *ji, predicate: predicate.clone() });
                }
                None => {}
            }
        }

        let cache_key = task
            .config()
            .cache
            .as_ref()
            .map_or(String::new(), |c| self.compute_cache_key_with_require(c.key, &profile, spec.params.as_ref()));

        self.create_job(base_task, task, &profile, params, pred, cache_key, channel, workspace_id, reason)
    }

    /// Schedule a queued service that waits for a blocking service to terminate.
    ///
    /// Creates a job in Scheduled state that will be spawned when the blocking
    /// service terminates. This is used when a service with a different profile
    /// is requested while another profile is still running.
    fn schedule_queued_service(
        &mut self,
        base_task: BaseTaskIndex,
        params: ValueMap,
        profile: &str,
        blocked_by: JobIndex,
        channel: &MioChannel,
        workspace_id: u32,
    ) -> JobIndex {
        let task = {
            let spawner = &self.base_tasks[base_task.idx()];
            let eval_profile =
                if profile.is_empty() { spawner.config.profiles.first().copied().unwrap_or("") } else { profile };
            let env = Environment { profile: eval_profile, param: params.clone(), vars: spawner.config.vars };
            spawner.config.eval(&env).expect("Failed to eval queued service config")
        };
        let profile = if profile.is_empty() {
            self.base_tasks[base_task.idx()].config.profiles.first().copied().unwrap_or("").to_string()
        } else {
            profile.to_string()
        };
        let params = params.to_owned();
        let cache_key = task.config().cache.as_ref().map_or(String::new(), |c| self.compute_cache_key(c.key));
        let requirements = vec![ScheduleRequirement { job: blocked_by, predicate: JobPredicate::Terminated }];

        self.create_job(
            base_task,
            task,
            &profile,
            params,
            requirements,
            cache_key,
            channel,
            workspace_id,
            ScheduleReason::ProfileConflict,
        )
    }

    fn create_job(
        &mut self,
        base_task: BaseTaskIndex,
        task: TaskConfigRc,
        profile: &str,
        params: ValueMap<'static>,
        requirements: Vec<ScheduleRequirement>,
        cache_key: String,
        channel: &MioChannel,
        workspace_id: u32,
        reason: ScheduleReason,
    ) -> JobIndex {
        let spec = self.cache_spawn_spec(base_task, profile, params, task.clone());
        let (task_name, task_kind, job_id) = {
            let bt = &mut self.base_tasks[base_task.idx()];
            let task_name = bt.name.clone();
            let task_kind = bt.config.kind;
            if task_kind == TaskKind::Service {
                bt.has_run_this_session = true;
            }
            let pc = bt.spawn_counter as usize;
            bt.spawn_counter = bt.spawn_counter.wrapping_add(1);
            (task_name, task_kind, LogGroup::new(base_task, pc))
        };

        let spawn = requirements.is_empty();
        let active_deps: Vec<JobIndex> = requirements
            .iter()
            .filter(|req| matches!(req.predicate, JobPredicate::Active))
            .map(|req| req.job)
            .collect();
        let job_index = self.jobs.insert(Job {
            process_status: if spawn { JobStatus::Starting } else { JobStatus::Scheduled { after: requirements } },
            log_group: job_id,
            started_at: crate::clock::now(),
            cache_key,
            spawn: spec.clone(),
        });

        let bt = &mut self.base_tasks[base_task.idx()];
        if spawn {
            bt.jobs.push_active(job_index);
        } else {
            bt.jobs.push_scheduled(job_index);
        }
        let global_list = match task_kind {
            TaskKind::Action => &mut self.action_jobs,
            TaskKind::Test => &mut self.test_jobs,
            TaskKind::Service => &mut self.service_jobs,
        };
        if spawn {
            global_list.push_active(job_index);
        } else {
            global_list.push_scheduled(job_index);
        }
        for dep in active_deps {
            self.service_dependents.add_dependent(dep, job_index);
        }

        if spawn {
            channel.send(crate::event_loop::ProcessRequest::Spawn { task, job_index, workspace_id, job_id });
        } else {
            kvlog::info!("Job scheduled", task_name = task_name.as_ref(), job_index, reason = reason.name());
        }
        job_index
    }
}

impl std::ops::Index<JobIndex> for WorkspaceState {
    type Output = Job;
    fn index(&self, index: JobIndex) -> &Self::Output {
        &self.jobs[index]
    }
}

impl WorkspaceState {
    /// Returns the name used to look up a base task in `name_map` / to pass to
    /// `SpawnSpec::task`. Tests are registered under a `~test/` prefix, so their
    /// display name (`BaseTask::name`) is not a valid spawn key on its own.
    pub fn spawn_name_for(&self, bti: BaseTaskIndex) -> String {
        let bt = &self.base_tasks[bti.idx()];
        match bt.config.kind {
            TaskKind::Test => format!("~test/{}", bt.name),
            _ => bt.name.to_string(),
        }
    }

    /// Returns all job indices for tasks of the given kind.
    pub fn jobs_by_kind(&self, kind: TaskKind) -> &[JobIndex] {
        match kind {
            TaskKind::Action => self.action_jobs.all(),
            TaskKind::Test => self.test_jobs.all(),
            TaskKind::Service => self.service_jobs.all(),
        }
    }

    /// Returns the full job list for the given task kind.
    pub fn jobs_list_by_kind(&self, kind: TaskKind) -> &JobIndexList {
        match kind {
            TaskKind::Action => &self.action_jobs,
            TaskKind::Test => &self.test_jobs,
            TaskKind::Service => &self.service_jobs,
        }
    }

    /// Computes a summary of the current test group for status bar display.
    pub fn compute_test_group_summary(&self) -> Option<TestGroupSummary> {
        let test_group = self.last_test_group.as_ref()?;

        let mut summary = TestGroupSummary { total: test_group.job_indices.len() as u32, ..Default::default() };

        for &job_index in &test_group.job_indices {
            let Some(job) = self.jobs.get(job_index) else { continue };
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
    /// Increments change_number and spawns the task.
    /// Returns the base task index and job index on success.
    ///
    /// Callers must ensure config is refreshed before calling this method.
    pub fn lookup_and_spawn_task(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        name: &str,
        params: ValueMap,
        profile: &str,
        force_restart: bool,
    ) -> Result<(BaseTaskIndex, JobIndex), String> {
        let Some(base_index) = self.base_index_by_name(name) else {
            return Err(format!("Task '{}' not found", name));
        };
        self.change_number = self.change_number.wrapping_add(1);
        let job_index = self.spawn_task(
            workspace_id,
            channel,
            base_index,
            params,
            profile,
            ScheduleReason::Requested,
            force_restart,
        );
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

        for &job_index in bt.jobs.non_terminal() {
            let job = &self.jobs[job_index];
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
                    jobs_to_cancel.push(job_index);
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
}
impl std::ops::IndexMut<JobIndex> for WorkspaceState {
    fn index_mut(&mut self, index: JobIndex) -> &mut Self::Output {
        &mut self.jobs[index]
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
        let job = &mut self.jobs[job_index];
        let job_id = job.log_group;
        let base_task = &mut self.base_tasks[job_id.base_task_index().idx()];
        let task_name = base_task.name.as_ref();
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

        let is_now_terminal = matches!(status, S::Exited { .. } | S::Cancelled);
        job.process_status = status;

        if is_now_terminal && self.jobs.len() as u32 > self.max_job_history {
            self.prune_history();
        }
    }

    /// Resolve a [`JobIndex`] without panicking — returns `None` for stale
    /// handles that have been evicted.
    #[allow(dead_code)]
    pub fn get_job(&self, ji: JobIndex) -> Option<&Job> {
        self.jobs.get(ji)
    }

    /// Build the set of job indices that must not be evicted this pass.
    /// Terminal jobs referenced by a still-`Scheduled` job's `after` list
    /// need to survive so `ScheduleRequirement::status` can read their exit
    /// state when the waiter finally runs.
    fn collect_protected_deps(&self) -> hashbrown::HashSet<JobIndex> {
        let mut protected: hashbrown::HashSet<JobIndex> = hashbrown::HashSet::new();
        for (_, job) in self.jobs.iter() {
            if let JobStatus::Scheduled { after } = &job.process_status {
                for req in after {
                    protected.insert(req.job);
                }
            }
        }
        protected
    }

    /// Drop the oldest terminal jobs to bring `jobs.len()` down to
    /// `max * 3 / 4`. Called from [`update_job_status`] when a terminal
    /// transition takes us over the cap. Non-terminal jobs and jobs
    /// referenced by live `Scheduled` waiters are preserved.
    fn prune_history(&mut self) {
        let max = self.max_job_history;
        let current = self.jobs.len() as u32;
        if current <= max {
            return;
        }
        let target = max - max / 4;
        let to_drop = (current - target) as usize;

        let protected = self.collect_protected_deps();

        let mut victims: Vec<(Instant, JobIndex)> = Vec::with_capacity(current as usize);
        for (ji, job) in self.jobs.iter() {
            if !matches!(job.process_status, JobStatus::Exited { .. } | JobStatus::Cancelled) {
                continue;
            }
            if protected.contains(&ji) {
                continue;
            }
            victims.push((job.started_at, ji));
        }

        if victims.is_empty() {
            return;
        }
        if victims.len() > to_drop {
            victims.select_nth_unstable_by_key(to_drop, |(t, _)| *t);
            victims.truncate(to_drop);
        }

        let evicted: hashbrown::HashSet<JobIndex> = victims.into_iter().map(|(_, ji)| ji).collect();
        if evicted.is_empty() {
            return;
        }

        for &ji in &evicted {
            self.jobs.remove(ji);
            self.service_dependents.remove_service(ji);
        }

        let still_live = |ji: JobIndex| !evicted.contains(&ji);
        for bt in &mut self.base_tasks {
            bt.jobs.retain_live(still_live);
        }
        self.action_jobs.retain_live(still_live);
        self.test_jobs.retain_live(still_live);
        self.service_jobs.retain_live(still_live);

        if let Some(tg) = &mut self.last_test_group {
            tg.job_indices.retain(|ji| still_live(*ji));
            if tg.job_indices.is_empty() {
                self.last_test_group = None;
            }
        }

        kvlog::info!("Job history pruned", evicted = evicted.len(), live = self.jobs.len());
    }

    pub fn new(config_path: PathBuf) -> Result<WorkspaceState, crate::config::ConfigError> {
        let config = LatestConfig::new(config_path)?;
        let mut base_tasks = Vec::new();
        let mut name_map = hashbrown::HashMap::new();
        config.update_base_tasks(&mut base_tasks, &mut name_map);
        let max_job_history = crate::user_config::global_max_job_history();

        Ok(WorkspaceState {
            change_number: 0,
            config,
            name_map,
            base_tasks,
            jobs: JobStore::new(),
            max_job_history,
            active_test_run: None,
            action_jobs: JobIndexList::default(),
            test_jobs: JobIndexList::default(),
            service_jobs: JobIndexList::default(),
            service_dependents: ServiceDependents::default(),
            session_functions: hashbrown::HashMap::new(),
            last_test_group: None,
            cache_key_hasher: CacheKeyHasher::new(),
            spawn_specs: hashbrown::HashMap::new(),
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
    pub fn service_to_terminate_for_queue(&self) -> Option<(JobIndex, ExitCause)> {
        for &scheduled_job_index in self.service_jobs.scheduled() {
            let JobStatus::Scheduled { after } = &self[scheduled_job_index].process_status else {
                continue;
            };
            let scheduled_base_task = self[scheduled_job_index].log_group.base_task_index();
            for req in after {
                if req.predicate == JobPredicate::Terminated {
                    let blocking_job = &self.jobs[req.job];
                    if blocking_job.process_status.is_running() && self.service_dependents.can_stop(req.job) {
                        let exit_cause = if blocking_job.log_group.base_task_index() == scheduled_base_task {
                            ExitCause::Restarted
                        } else {
                            ExitCause::ProfileConflict
                        };
                        return Some((req.job, exit_cause));
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

        for &ji in spawner.jobs.running() {
            let job = &self.jobs[ji];
            if service_matches_require(job, requested_profile, requested_params) {
                return ServiceCompatibility::Compatible(ji);
            }
        }

        if let Some(&ji) = spawner.jobs.running().iter().next() {
            let job = &self.jobs[ji];
            match spawner.config.allow_multiple {
                AllowMultiple::True | AllowMultiple::DistinctProfiles => {
                    return ServiceCompatibility::Available;
                }
                AllowMultiple::False | AllowMultiple::SingleProfile => {
                    return ServiceCompatibility::Conflict {
                        running_job: ji,
                        running_profile: job.spawn_profile().to_string(),
                        requested_profile: requested_profile.to_string(),
                    };
                }
            }
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

                        for &ji in spawner.jobs.all().iter().rev() {
                            let job = &self.jobs[ji];
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
                                resolved = Some(ResolvedRequirement::Pending(ji));
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
                        params,
                        &profile,
                        ScheduleReason::Dependency,
                        false,
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
                                let queued_job = self.schedule_queued_service(
                                    base_task,
                                    params,
                                    &profile,
                                    running_job,
                                    channel,
                                    workspace_id,
                                );
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
                        params,
                        &profile,
                        ScheduleReason::Dependency,
                        false,
                    );
                    batch.mark_resolved(key, ResolvedRequirement::Spawned(new_job));
                }
                TaskKind::Test => {
                    batch.mark_resolved(key, ResolvedRequirement::Cached);
                }
            }
        }
    }

    fn run_test_batch(
        &mut self,
        matched_tests: Vec<MatchedTest>,
        run_id: u32,
        channel: &MioChannel,
        workspace_id: u32,
    ) -> Result<TestRun, String> {
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
                    let dep_base_task = self.name_map.get(dep_name)?;
                    let dep_config = &self.base_tasks[dep_base_task.idx()].config;
                    if dep_config.kind == TaskKind::Service {
                        Some((dep_name.to_string(), tc.profile.unwrap_or("").to_string()))
                    } else {
                        None
                    }
                })
                .collect();
            let mut visited_services: hashbrown::HashSet<BaseTaskIndex> = hashbrown::HashSet::new();

            while let Some((dep_name, dep_profile)) = services_to_check.pop() {
                let Some(&dep_base_task) = self.name_map.get(&*dep_name) else {
                    continue;
                };
                let dep_config = &self.base_tasks[dep_base_task.idx()].config;

                if let Some(existing_profile) = service_profiles.get(&dep_base_task) {
                    if *existing_profile != dep_profile {
                        let test_name = self.base_tasks[matched.base_task_idx.idx()].name.as_ref();
                        let service_name = self.base_tasks[dep_base_task.idx()].name.as_ref();
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
                        let Some(&req_base_task) = self.name_map.get(req_name) else {
                            continue;
                        };
                        let req_config = &self.base_tasks[req_base_task.idx()].config;
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

                let Some(&dep_base_task) = self.name_map.get(dep_name) else {
                    continue;
                };
                let dep_config = &self.base_tasks[dep_base_task.idx()].config;

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

        self.resolve_batch_requirements(workspace_id, channel, &mut batch);

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
                task_config.config().cache.as_ref().map_or(String::new(), |c| self.compute_cache_key(c.key));

            let job_index = self.create_job(
                task.task_data.base_task_idx,
                task_config,
                &task.task_data.spawn_profile,
                task.task_data.spawn_params,
                pred,
                cache_key,
                channel,
                workspace_id,
                ScheduleReason::TestRun,
            );

            test_jobs.push(TestJob {
                base_task_index: task.task_data.base_task_idx,
                job_index,
                status: TestJobStatus::Pending,
            });
        }

        let test_run = TestRun { run_id, started_at: crate::clock::now(), test_jobs };
        self.active_test_run =
            Some(TestRun { run_id: test_run.run_id, started_at: test_run.started_at, test_jobs: Vec::new() });

        let group_id = self.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
        let base_tasks_in_group: Vec<BaseTaskIndex> = test_run.test_jobs.iter().map(|tj| tj.base_task_index).collect();
        let job_indices: Vec<JobIndex> = test_run.test_jobs.iter().map(|tj| tj.job_index).collect();

        self.last_test_group = Some(TestGroup { group_id, base_tasks: base_tasks_in_group, job_indices });

        Ok(test_run)
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

pub struct TaskSpec {
    pub name: String,
    pub profile: String,
    pub params: ValueMap<'static>,
    pub force_restart: bool,
}

pub struct SpawnSpec {
    pub tasks: Vec<TaskSpec>,
    pub test_group: bool,
}

impl SpawnSpec {
    pub fn task(name: &str, profile: &str, params: ValueMap<'static>, force_restart: bool) -> Self {
        SpawnSpec {
            tasks: vec![TaskSpec { name: name.into(), profile: profile.into(), params, force_restart }],
            test_group: false,
        }
    }
}

pub struct SubmitResult {
    pub jobs: Vec<(BaseTaskIndex, JobIndex)>,
}

impl Workspace {
    pub fn submit(&self, spec: SpawnSpec) -> Result<SubmitResult, String> {
        let state = &mut *self.state.write().unwrap();
        state.refresh_config();
        state.change_number = state.change_number.wrapping_add(1);

        let mut jobs = Vec::new();
        for task in &spec.tasks {
            let (bti, ji) = state.lookup_and_spawn_task(
                self.workspace_id,
                &self.process_channel,
                &task.name,
                task.params.clone(),
                &task.profile,
                task.force_restart,
            )?;
            jobs.push((bti, ji));
        }

        if spec.test_group && !jobs.is_empty() {
            let group_id = state.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
            state.last_test_group = Some(TestGroup {
                group_id,
                base_tasks: jobs.iter().map(|(bti, _)| *bti).collect(),
                job_indices: jobs.iter().map(|(_, ji)| *ji).collect(),
            });
        }

        Ok(SubmitResult { jobs })
    }

    pub fn call_function(&self, name: &str) -> Result<Option<FunctionGlobalAction>, String> {
        use crate::config::FunctionDefAction;
        use crate::function::FunctionAction;

        let state = &mut *self.state.write().unwrap();
        state.refresh_config();
        state.change_number = state.change_number.wrapping_add(1);

        if let Some(FunctionAction::RestartCaptured { task_name, profile }) = state.session_functions.get(name).cloned()
        {
            state.lookup_and_spawn_task(
                self.workspace_id,
                &self.process_channel,
                &task_name,
                ValueMap::new(),
                &profile,
                true,
            )?;
            return Ok(None);
        }

        let generation = Arc::clone(&state.config.current);
        let Some(func_def) = generation.workspace().functions.iter().find(|f| f.name == name) else {
            return Err(format!("Function '{}' not configured", name));
        };

        match &func_def.action {
            FunctionDefAction::Restart { task } => {
                state.lookup_and_spawn_task(
                    self.workspace_id,
                    &self.process_channel,
                    task,
                    ValueMap::new(),
                    "",
                    true,
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
                        task_call.vars.clone().to_owned(),
                        task_call.profile.unwrap_or(""),
                        false,
                    )?;
                }
            }
            FunctionDefAction::RestartSelected => {
                return Ok(Some(FunctionGlobalAction::RestartSelected));
            }
        }
        Ok(None)
    }

    pub fn rerun_test_group(&self, only_failed: bool) -> Result<TestRun, String> {
        let state = &mut *self.state.write().unwrap();
        state.refresh_config();
        state.change_number = state.change_number.wrapping_add(1);

        let test_group = state.last_test_group.as_ref().ok_or("No test group to rerun")?;
        let tasks_to_run: Vec<(BaseTaskIndex, Option<JobIndex>)> = if only_failed {
            let mut failed = Vec::new();
            for (i, &job_index) in test_group.job_indices.iter().enumerate() {
                let Some(job) = state.jobs.get(job_index) else { continue };
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

        let run_id = state.active_test_run.as_ref().map_or(0, |r| r.run_id + 1);
        let mut matched_tests = Vec::new();
        for (base_task_idx, original_job) in tasks_to_run {
            let Some(base_task) = state.base_tasks.get(base_task_idx.idx()) else { continue };
            if base_task.removed {
                continue;
            }
            let (spawn_profile, spawn_params) = original_job
                .and_then(|ji| state.jobs.get(ji))
                .map(|job| (job.spawn_profile().to_string(), job.spawn_params().clone()))
                .unwrap_or_else(|| (String::new(), ValueMap::new()));
            let env = Environment { profile: &spawn_profile, param: spawn_params.clone(), vars: base_task.config.vars };
            let Ok(task_config) = base_task.config.eval(&env) else {
                kvlog::error!("Failed to evaluate test config", name = base_task.name.as_ref());
                continue;
            };
            drop(env);
            matched_tests.push(MatchedTest { base_task_idx, task_config, spawn_profile, spawn_params });
        }

        state.run_test_batch(matched_tests, run_id, &self.process_channel, self.workspace_id)
    }
}

impl Workspace {
    pub fn refresh_config_if_changed(&self) {
        let state = &mut *self.state.write().unwrap();
        state.refresh_config();
    }

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
                let task_name =
                    state.base_tasks.get(base_task_idx.idx()).map(|bt| bt.name.as_ref()).unwrap_or("<unknown>");
                let job = state.jobs.iter().find(|(_, job)| job.log_group == p.log_group).map(|(_, job)| job);
                let (pwd, cmd) = match job {
                    Some(job) => {
                        let config = job.task().config();
                        let pwd = state.config.current.base_path().join(config.pwd).to_string_lossy().to_string();
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

    pub fn terminate_tasks(&self, base_task: BaseTaskIndex) {
        let state = &mut *self.state.write().unwrap();
        state.change_number = state.change_number.wrapping_add(1);

        let task_name = state.base_tasks[base_task.idx()].name.clone();
        let job_indices: Vec<JobIndex> = state.base_tasks[base_task.idx()].jobs.non_terminal().to_vec();

        let mut jobs_to_cancel = Vec::new();
        for job_index in job_indices {
            let job = &state.jobs[job_index];
            match &job.process_status {
                JobStatus::Running { process_index, .. } => {
                    kvlog::info!("Terminating running job", task_name = task_name.as_ref(), job_index, process_index);
                    self.process_channel.send(crate::event_loop::ProcessRequest::TerminateJob {
                        job_id: job.log_group,
                        process_index: *process_index,
                        exit_cause: ExitCause::Killed,
                    });
                }
                JobStatus::Starting => {
                    kvlog::warn!(
                        "Job is in Starting state during termination (spawn in progress)",
                        task_name = task_name.as_ref(),
                        job_index
                    );
                }
                JobStatus::Scheduled { .. } => {
                    kvlog::info!("Cancelling scheduled job", task_name = task_name.as_ref(), job_index);
                    jobs_to_cancel.push(job_index);
                }
                JobStatus::Exited { .. } | JobStatus::Cancelled => {}
            }
        }

        for job_index in jobs_to_cancel {
            state.update_job_status(job_index, JobStatus::Cancelled);
        }
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
        if cached {
            self.refresh_config_if_changed();
            // Phase 1: Gather info needed for cache key computation (hold lock briefly)
            let (cache_info, profile) = {
                let state = self.state.read().unwrap();
                let Some(&base_index) = state.name_map.get(name) else {
                    return Err(format!("Task '{}' not found", name));
                };
                let bt = &state.base_tasks[base_index.idx()];
                let profile =
                    if profile.is_empty() { bt.config.profiles.first().copied().unwrap_or("") } else { profile };
                let Some(cache_config) = &bt.config.cache else {
                    drop(state);
                    let state = &mut *self.state.write().unwrap();
                    let (_, _) = state.lookup_and_spawn_task(
                        self.workspace_id,
                        &self.process_channel,
                        name,
                        params,
                        profile,
                        false,
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
                        params,
                        profile,
                        false,
                    )?;
                    return Ok(None);
                };

                let base_path = state.config.current.base_path().to_path_buf();
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

                (CacheKeyInfo { base_index, cache_key_inputs }, profile)
            };
            // Lock released here

            // Phase 2: Compute cache key (filesystem I/O, no lock held)
            let expected_cache_key = compute_cache_key_standalone(&cache_info.cache_key_inputs, profile, &params);

            // Phase 3: Check for cache hit and spawn if needed (re-acquire lock)
            let state = &mut *self.state.write().unwrap();
            if let Some(msg) = state.check_cache_hit_with_key(name, cache_info.base_index, &expected_cache_key) {
                return Ok(Some(msg));
            }

            let (_, _job_index) =
                state.lookup_and_spawn_task(self.workspace_id, &self.process_channel, name, params, profile, false)?;
            Ok(None)
        } else {
            let state = &mut *self.state.write().unwrap();
            state.refresh_config();
            let (_, _job_index) =
                state.lookup_and_spawn_task(self.workspace_id, &self.process_channel, name, params, profile, false)?;
            Ok(None)
        }
    }

    /// Layer 1: Terminate task by name.
    ///
    /// Acquires state lock, looks up task, and terminates all running instances.
    pub fn terminate_task_by_name(&self, name: &str) -> Result<String, String> {
        let state = &mut *self.state.write().unwrap();
        state.refresh_config();
        state.lookup_and_terminate_task(&self.process_channel, name)
    }

    pub fn start_test_run(&self, filters: &[TestFilter]) -> Result<TestRun, String> {
        let state = &mut *self.state.write().unwrap();
        state.change_number = state.change_number.wrapping_add(1);
        state.refresh_config();

        let run_id = state.active_test_run.as_ref().map_or(0, |r| r.run_id + 1);

        let mut matched_tests = Vec::new();
        for (base_task_idx, base_task) in state.base_tasks.iter().enumerate() {
            if base_task.removed || base_task.config.kind != TaskKind::Test {
                continue;
            }
            let tags = base_task.config.tags;
            if !matches_test_filters(base_task.name.as_ref(), tags, filters) {
                continue;
            }
            let env = Environment { profile: "", param: ValueMap::new(), vars: base_task.config.vars };
            let Ok(task_config) = base_task.config.eval(&env) else {
                kvlog::error!("Failed to evaluate test config", name = base_task.name.as_ref());
                continue;
            };
            matched_tests.push(MatchedTest {
                base_task_idx: BaseTaskIndex::new_or_panic(base_task_idx),
                task_config,
                spawn_profile: String::new(),
                spawn_params: ValueMap::new(),
            });
        }

        state.run_test_batch(matched_tests, run_id, &self.process_channel, self.workspace_id)
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
            let Some(job) = state.jobs.get(job_index) else { continue };
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
            TestFilter::IncludeName(n) => include_names.push(n.as_ref()),
            TestFilter::IncludeTag(t) => include_tags.push(t.as_ref()),
            TestFilter::ExcludeTag(t) => exclude_tags.push(t.as_ref()),
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
            !JobStatus::Exited { finished_at: Instant::now(), cause: ExitCause::Unknown, status: 0 }
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
            JobStatus::Exited { finished_at: Instant::now(), cause: ExitCause::Unknown, status: 0 }
                .is_successful_completion()
        );

        assert!(
            !JobStatus::Exited { finished_at: Instant::now(), cause: ExitCause::Unknown, status: 1 }
                .is_successful_completion()
        );

        // Note: is_successful_completion only checks status code, not exit cause.
        // The ScheduleRequirement::status method does check for Killed separately
        // when evaluating the TerminatedNaturallyAndSuccessfully predicate.
        assert!(
            JobStatus::Exited { finished_at: Instant::now(), cause: ExitCause::Killed, status: 0 }
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
            assert_eq!(key1.params_digest, key2.params_digest);
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

    mod spawn_spec_cache_tests {
        use super::*;

        fn manifest_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        #[test]
        fn get_or_create_spawn_spec_reuses_cached_spec_before_eval() {
            let mut state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let base_task = state.name_map["simple_cmd"];
            let failing_task = state.name_map["with_var"];

            let config = state.base_tasks[base_task.idx()].config.clone();
            let task = config.eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars }).unwrap();
            let cached = state.cache_spawn_spec(base_task, "", ValueMap::new(), task);

            state.base_tasks[base_task.idx()].config = state.base_tasks[failing_task.idx()].config.clone();

            let reused = state.get_or_create_spawn_spec(base_task, "", ValueMap::new());
            assert!(Arc::ptr_eq(&cached, &reused));
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

    mod job_history_tests {
        use super::*;

        fn manifest_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        /// Build a workspace state loaded from the big example config,
        /// drop the configured history cap to `max`, and return a spawn spec
        /// bound to the first non-synthetic base task so tests can mint jobs
        /// without a MioChannel.
        fn fixture(max: u32) -> (WorkspaceState, BaseTaskIndex, Arc<ResolvedSpawnSpec>) {
            let mut state =
                WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).expect("load test config");
            state.max_job_history = max;
            let base_task = state.name_map["simple_cmd"];
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task = config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars })
                .expect("eval task");
            let spec = state.cache_spawn_spec(base_task, "", ValueMap::new(), task);
            (state, base_task, spec)
        }

        fn insert_job(state: &mut WorkspaceState, base_task: BaseTaskIndex, spec: Arc<ResolvedSpawnSpec>) -> JobIndex {
            let bt = &mut state.base_tasks[base_task.idx()];
            let pc = bt.spawn_counter as usize;
            bt.spawn_counter = bt.spawn_counter.wrapping_add(1);
            let log_group = LogGroup::new(base_task, pc);
            let ji = state.jobs.insert(Job {
                process_status: JobStatus::Starting,
                log_group,
                started_at: crate::clock::now(),
                cache_key: String::new(),
                spawn: spec,
            });
            state.base_tasks[base_task.idx()].jobs.push_active(ji);
            state.action_jobs.push_active(ji);
            ji
        }

        fn exit(state: &mut WorkspaceState, ji: JobIndex, status: u32) {
            // Match the real spawn_task flow: Starting → Running → Exited.
            // The (Starting, Exited) direct transition is not modelled by
            // the global kind-list and would leak stale entries there.
            state.update_job_status(ji, JobStatus::Running { process_index: 0, ready_state: None });
            state.update_job_status(
                ji,
                JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status },
            );
        }

        #[test]
        fn eviction_caps_terminal_history_at_three_quarters() {
            let max = 128;
            let (mut state, base_task, spec) = fixture(max);

            // Insert max + 40 jobs, drive each to Exited. Prune fires on the
            // terminal transition that takes live count over max; from there
            // on the count stays bounded.
            let mut jis = Vec::new();
            for _ in 0..(max as usize + 40) {
                let ji = insert_job(&mut state, base_task, spec.clone());
                jis.push(ji);
                exit(&mut state, ji, 0);
            }

            let live = state.jobs.len() as u32;
            assert!(live <= max, "live count {live} should stay at or below max {max}");
            assert!(
                live >= max - max / 4,
                "live count {live} should hover near the post-prune target {}",
                max - max / 4
            );
            // The oldest JobIndices must be evicted; newest are retained.
            let oldest = jis[0];
            let newest = *jis.last().unwrap();
            assert!(state.jobs.get(oldest).is_none(), "oldest should be evicted");
            assert!(state.jobs.get(newest).is_some(), "newest should survive");
        }

        #[test]
        fn eviction_preserves_running_jobs() {
            let max = 128;
            let (mut state, base_task, spec) = fixture(max);

            // Pin a running job at the very front, then saturate with terminal
            // actions behind it. The running job has no Exited transition,
            // so prune must leave it alone.
            let running = insert_job(&mut state, base_task, spec.clone());
            for _ in 0..(max as usize * 2) {
                let ji = insert_job(&mut state, base_task, spec.clone());
                exit(&mut state, ji, 0);
            }

            assert!(state.jobs.get(running).is_some(), "running job must not be evicted");
            assert!(matches!(state.jobs[running].process_status, JobStatus::Starting | JobStatus::Running { .. }));
        }

        #[test]
        fn eviction_preserves_scheduled_dep_targets() {
            let max = 128;
            let (mut state, base_task, spec) = fixture(max);

            // A is terminal, B is still Scheduled with `after: [A]`. Even
            // though A is the oldest terminal job, prune must protect it
            // because B's dependency predicate still needs its exit state.
            let a = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, a, 0);

            let b = state.jobs.insert(Job {
                process_status: JobStatus::Scheduled {
                    after: vec![ScheduleRequirement {
                        job: a,
                        predicate: JobPredicate::TerminatedNaturallyAndSuccessfully,
                    }],
                },
                log_group: LogGroup::new(base_task, 999),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                spawn: spec.clone(),
            });
            state.base_tasks[base_task.idx()].jobs.push_scheduled(b);

            // Now hammer with enough terminal jobs that A would otherwise be
            // evicted many times over.
            for _ in 0..(max as usize * 3) {
                let ji = insert_job(&mut state, base_task, spec.clone());
                exit(&mut state, ji, 0);
            }

            assert!(state.jobs.get(a).is_some(), "terminal dep target must be protected");
            assert!(state.jobs.get(b).is_some(), "scheduled waiter must survive");
        }

        #[test]
        fn eviction_cleans_base_task_list() {
            let max = 128;
            let (mut state, base_task, spec) = fixture(max);

            for _ in 0..(max as usize + 40) {
                let ji = insert_job(&mut state, base_task, spec.clone());
                exit(&mut state, ji, 0);
            }

            // Every index still in the per-base-task list must resolve.
            let bt = &state.base_tasks[base_task.idx()];
            for &ji in bt.jobs.all() {
                assert!(state.jobs.get(ji).is_some(), "base_task.jobs referenced an evicted index {:?}", ji);
            }
            // Same for the global kind list.
            for &ji in state.action_jobs.all() {
                assert!(state.jobs.get(ji).is_some(), "action_jobs referenced an evicted index {:?}", ji);
            }
        }

        #[test]
        fn log_group_counter_stays_monotonic_across_eviction() {
            let max = 128;
            let (mut state, base_task, spec) = fixture(max);

            let first = insert_job(&mut state, base_task, spec.clone());
            let first_lg = state.jobs[first].log_group;

            for _ in 0..(max as usize + 80) {
                let ji = insert_job(&mut state, base_task, spec.clone());
                exit(&mut state, ji, 0);
            }
            // At this point many per-base-task entries have been pruned and
            // `bt.jobs.len()` is smaller than it was at peak, but
            // `spawn_counter` must still be monotonic so new LogGroups do
            // not collide with any that already went to the log buffer.
            let latest = insert_job(&mut state, base_task, spec.clone());
            let latest_lg = state.jobs[latest].log_group;
            assert_ne!(first_lg, latest_lg);
            // spawn_counter is the monotonic source of truth; LogGroups
            // derived from it must stay distinct across eviction because the
            // counter is never decremented even after per-base-task list
            // entries are pruned.
            assert!(state.base_tasks[base_task.idx()].spawn_counter > 1, "spawn_counter should have advanced");
        }

        #[test]
        fn generation_invalidates_stale_handle_after_slot_reuse() {
            let (mut state, base_task, spec) = fixture(128);

            let first = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, first, 0);
            // Force prune to evict `first` by dropping the cap under the
            // current live count.
            state.max_job_history = 1;
            // Need another terminal transition to re-enter prune_history.
            let filler = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, filler, 0);

            assert!(state.jobs.get(first).is_none(), "old handle should be evicted");

            // Insert a fresh job; the slab may reuse `first`'s slot, but the
            // generation check on the stale handle must still reject it.
            let reused = insert_job(&mut state, base_task, spec.clone());
            if reused.slot() == first.slot() {
                assert_ne!(reused.generation(), first.generation());
            }
            assert!(state.jobs.get(first).is_none());
            assert!(state.jobs.get(reused).is_some());
        }
    }
}
