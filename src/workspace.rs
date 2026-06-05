use crate::{
    cache_key::{CacheKeyHasher, expand_modified_path},
    cli::TestFilter,
    config::{
        AllowMultiple, CARGO_AUTO_EXPR, CacheKeyInput, Command, ConfigGeneration, Environment, EvalError, TaskConfigRc,
        TaskConfigSource, TaskKind,
    },
    event_loop::MioChannel,
    function::FunctionAction,
    log_storage::{LogGroup, Logs},
};
pub use job_index_list::JobIndexList;
pub use job_store::{JobIndex, JobStore};
pub use require_graph::{RequireAnalysis, TaskInput};
pub use resource::{ResourceIndex, ResourceSlab};

fn task_inputs<'a>(base_tasks: &'a [BaseTask]) -> Vec<TaskInput<'a>> {
    base_tasks
        .iter()
        .map(|bt| TaskInput { name: bt.name.as_ref(), kind: bt.config.kind, require: bt.config.require })
        .collect()
}

fn build_require_analysis(
    base_tasks: &[BaseTask],
    name_map: &hashbrown::HashMap<Box<str>, NameEntry>,
) -> RequireAnalysis {
    RequireAnalysis::build(&task_inputs(base_tasks), name_map)
}
use jsony_value::{Value, ValueMap, ValueNumber, ValueRef};
use smallvec::SmallVec;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock, Weak},
    time::{Duration, Instant, SystemTime},
};
mod job_index_list;
mod job_store;
mod persistent_cache;
pub mod require_graph;
mod resource;
use persistent_cache::PersistentCache;

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
    persistent: bool,
    max_age: Option<Duration>,
}

fn hash_modified_path(hasher: &mut CacheKeyHasher, base_path: &Path, path: &str, ignore: &[&str]) {
    for expanded in expand_modified_path(path) {
        hasher.hash_path(&base_path.join(expanded), ignore);
    }
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

/// At most one of `service` / `action` may be present (mutually exclusive),
/// alongside an optional test sharing the same short name.
#[derive(Clone, Copy, Debug, Default)]
pub enum TaskEntry {
    #[default]
    None,
    Service(BaseTaskIndex),
    Action(BaseTaskIndex),
}

impl TaskEntry {
    pub fn index(self) -> Option<BaseTaskIndex> {
        match self {
            TaskEntry::None => None,
            TaskEntry::Service(i) | TaskEntry::Action(i) => Some(i),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NameEntry {
    pub task: TaskEntry,
    pub test: Option<BaseTaskIndex>,
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
    /// True for a synthetic success job created to represent a cache hit in
    /// views that require a job handle. Synthetic jobs do not refresh caches.
    pub cache_synthetic: bool,
    pub spawn: Arc<ResolvedSpawnSpec>,
    /// Resources currently held by this job. Populated on `Scheduled → Starting`,
    /// drained on any terminal transition.
    pub held_resources: SmallVec<[ResourceIndex; 2]>,
    /// Action dependency jobs whose output is considered in use until this
    /// service becomes ready.
    pub action_deps_until_ready: SmallVec<[JobIndex; 2]>,
    /// When true, the spawned process is run under ptrace and a trace
    /// report is delivered to the attached run client at exit. Always
    /// false for tasks materialized by `require` chains.
    pub trace: bool,
    /// Trace report attached on exit when `trace == true`, consumed by
    /// the log forwarder to send a `JobTraceReport` RPC message.
    pub trace_report: Option<crate::auto_deps::TraceReportPayload>,
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
    Ready,
}

#[derive(Debug)]
pub enum ScheduleRequirement {
    Task { job: JobIndex, predicate: JobPredicate },
    Resource { id: ResourceIndex, priority: i32 },
}

enum RequirementStatus {
    Pending,
    Met,
    Never,
}

impl ScheduleRequirement {
    fn status(&self, ws: &WorkspaceState) -> RequirementStatus {
        match self {
            ScheduleRequirement::Resource { id, .. } => {
                if ws.resources.is_free(*id) {
                    RequirementStatus::Met
                } else {
                    RequirementStatus::Pending
                }
            }
            ScheduleRequirement::Task { job: job_index, predicate } => {
                let Some(job) = ws.jobs.get(*job_index) else {
                    return RequirementStatus::Met;
                };
                match predicate {
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
                    JobPredicate::Ready => match &job.process_status {
                        JobStatus::Scheduled { .. } => RequirementStatus::Pending,
                        JobStatus::Starting => RequirementStatus::Pending,
                        JobStatus::Cancelled => RequirementStatus::Met,
                        JobStatus::Running { ready_state, .. } => match ready_state {
                            None => RequirementStatus::Met,
                            Some(true) => RequirementStatus::Met,
                            Some(false) => RequirementStatus::Pending,
                        },
                        JobStatus::Exited { .. } => RequirementStatus::Met,
                    },
                }
            }
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

fn finished_within_max_age(status: &JobStatus, max_age: Option<Duration>) -> bool {
    let Some(max_age) = max_age else {
        return true;
    };
    let JobStatus::Exited { finished_at, .. } = status else {
        return true;
    };
    let elapsed = crate::clock::now().checked_duration_since(*finished_at).unwrap_or_default();
    elapsed <= max_age
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
        name_map: &mut hashbrown::HashMap<Box<str>, NameEntry>,
    ) {
        for base_task in base_tasks.iter_mut() {
            // Synthetic Static tasks like `~cargo` are not generation-bound
            // and persist across reloads. Marking them removed would orphan
            // them from `name_map` after the prune step below.
            if matches!(&base_task.config, TaskConfigSource::Static(_)) {
                continue;
            }
            base_task.removed = true;
        }
        let generation = self.current.clone();
        for (task_index, (name, expr)) in self.current.workspace().tasks.iter().enumerate() {
            let config = TaskConfigSource::from_workspace_task(generation.clone(), task_index);
            let entry = name_map.entry((*name).into()).or_default();
            let existing = match expr.kind {
                TaskKind::Service => match entry.task {
                    TaskEntry::Service(i) => Some(i),
                    _ => None,
                },
                TaskKind::Action => match entry.task {
                    TaskEntry::Action(i) => Some(i),
                    _ => None,
                },
                TaskKind::Test => unreachable!("workspace.tasks contains only action/service"),
            };
            if let Some(index) = existing {
                let base_task = &mut base_tasks[index.idx()];
                base_task.removed = false;
                base_task.config = config;
                continue;
            }
            let index = BaseTaskIndex::new_or_panic(base_tasks.len());
            entry.task = match expr.kind {
                TaskKind::Service => TaskEntry::Service(index),
                TaskKind::Action => TaskEntry::Action(index),
                TaskKind::Test => unreachable!(),
            };
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
            let entry = name_map.entry(derived.name.clone()).or_default();
            if let Some(index) = entry.test {
                let base_task = &mut base_tasks[index.idx()];
                base_task.removed = false;
                base_task.config = config;
                continue;
            }
            let index = BaseTaskIndex::new_or_panic(base_tasks.len());
            entry.test = Some(index);
            base_tasks.push(BaseTask {
                name: derived.name.clone(),
                config,
                removed: false,
                jobs: JobIndexList::default(),
                profile_change_counter: 0,
                spawn_counter: 0,
                last_profile: None,
                has_run_this_session: false,
            });
        }

        // Drop name_map entries pointing at base tasks that the new generation
        // did not revive. Without this, `lookup_name` and the `NameLookup`
        // impl used by `RequireAnalysis` keep resolving removed task names to
        // their stale slots.
        name_map.retain(|_, entry| {
            let task_alive = match entry.task {
                TaskEntry::None => false,
                TaskEntry::Service(i) | TaskEntry::Action(i) => !base_tasks[i.idx()].removed,
            };
            let test_alive = entry.test.is_some_and(|i| !base_tasks[i.idx()].removed);
            if !task_alive {
                entry.task = TaskEntry::None;
            }
            if !test_alive {
                entry.test = None;
            }
            task_alive || test_alive
        });
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
    Cached,
    Failed(i32),
}

/// A single test job within a test run.
pub struct TestJob {
    /// Index into base_tasks for this test.
    pub base_task_index: BaseTaskIndex,
    pub job_index: Option<JobIndex>,
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
        let should_remove_service = if let Some(deps) = self.dependents.get_mut(&service) {
            deps.remove(&dependent);
            deps.is_empty()
        } else {
            false
        };
        if should_remove_service {
            self.dependents.remove(&service);
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

/// Result of checking service compatibility with a request. References are
/// [`JobRef`] because a candidate may be a service decided earlier in the same
/// submit and not yet inserted into the slab.
pub enum ServiceCompatibility {
    /// A matching service is already running or planned.
    Compatible(JobRef),
    /// No service is currently running.
    Available,
    /// One or more services must terminate before the request can run.
    Conflict { running_jobs: Vec<JobRef>, running_profiles: Vec<String>, requested_profile: String },
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

/// Result of resolving a requirement during batch spawning. `Pending`/`Spawned`
/// carry a [`JobRef`] because a dependency may be a job decided earlier in the
/// same submit that is not yet inserted into the slab.
pub enum ResolvedRequirement {
    Cached,
    Pending(JobRef),
    Spawned(JobRef),
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
    pending_requirement_order: Vec<RequirementKey>,
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
            pending_requirement_order: Vec::new(),
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
        if !self.pending_requirements.contains_key(&key) {
            self.pending_requirement_order.push(key.clone());
            self.pending_requirements
                .insert(key.clone(), PendingRequirement { base_task, profile: profile.to_string(), params });
        }
        key
    }

    pub fn add_task(&mut self, task_data: T) {
        self.pending_tasks.push(PendingTask { task_data });
    }

    fn pending_requirements_ordered(&self) -> impl Iterator<Item = (&RequirementKey, &PendingRequirement)> {
        self.pending_requirement_order.iter().filter_map(|key| self.pending_requirements.get_key_value(key))
    }

    #[cfg(test)]
    pub fn pending_requirements(&self) -> impl Iterator<Item = (&RequirementKey, &PendingRequirement)> {
        self.pending_requirements_ordered()
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
    pub name_map: hashbrown::HashMap<Box<str>, NameEntry>,
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
    /// Jobs returned by group invocations, keyed by configured group name.
    /// This lets `devsm stop <group>` stop the work that was launched through
    /// that group without blindly killing every task that happens to share a
    /// base task with the group.
    pub group_jobs: hashbrown::HashMap<Box<str>, Vec<JobIndex>>,
    /// Daemon-lifetime intern table for `{ resource = "..." }` requirements,
    /// plus the current holder of each resource.
    pub resources: ResourceSlab,
    /// Pre-computed cycle and resource-deadlock errors for the current config
    /// generation. Rebuilt on every `refresh_config`; per-spawn callers do an
    /// O(1) lookup via [`detect_require_problems`].
    pub require_analysis: RequireAnalysis,
    cache_key_hasher: CacheKeyHasher,
    persistent_cache: PersistentCache,
    spawn_specs: hashbrown::HashMap<u64, Vec<Weak<ResolvedSpawnSpec>>>,
}

/// A reference to a job from within a [`SchedulePlan`]. Either an already-live
/// job in the slab, or one this plan will create (by index into `new_jobs`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobRef {
    Live(JobIndex),
    Planned(usize),
}

/// A requirement of a planned job, resolved to a real [`ScheduleRequirement`]
/// when the plan is applied.
enum PlannedReq {
    Task { target: JobRef, predicate: JobPredicate },
    Resource { id: ResourceIndex, priority: i32 },
}

/// A job to create when the plan is applied. Planning never inserts jobs or
/// bumps counters, so a plan that fails to build leaves `WorkspaceState`
/// untouched and no rollback is needed.
struct PlannedJob {
    base_task: BaseTaskIndex,
    task: TaskConfigRc,
    profile: String,
    params: ValueMap<'static>,
    cache_key: String,
    requirements: Vec<PlannedReq>,
    /// Action deps a planned service holds until ready, for ready-barrier checks
    /// during planning. Only populated for services; apply recomputes the real
    /// `JobIndex` list once dep jobs exist.
    action_deps_until_ready: Vec<JobRef>,
    reason: ScheduleReason,
    trace: bool,
    /// Marks a synthetic terminal cached-success job (uses `cache_key`).
    synthetic_cached: bool,
}

/// The full set of changes a submit intends to make: jobs to create, scheduled
/// jobs to cancel, and running jobs to terminate. Built by reading state only,
/// then applied in one infallible pass by [`WorkspaceState::apply_plan`].
#[derive(Default)]
struct SchedulePlan {
    new_jobs: Vec<PlannedJob>,
    cancelled_planned: hashbrown::HashSet<usize>,
    cancel_scheduled: Vec<JobIndex>,
    cancel_scheduled_set: hashbrown::HashSet<JobIndex>,
    terminate_running: Vec<TerminatePlan>,
    terminate_running_set: hashbrown::HashSet<JobIndex>,
}

struct TerminatePlan {
    job: JobIndex,
    job_id: LogGroup,
    process_index: usize,
    exit_cause: ExitCause,
}

/// A node in the held-reachability graph: one `(base, effective_profile, params)`
/// requirement instance reachable from the validated task.
struct HeldNode {
    base: BaseTaskIndex,
    profile: String,
    params: ValueMap<'static>,
    is_service: bool,
}

/// The require closure as a DAG with two edge colors. A `require` on a service
/// is a *service edge*: that service (and its own service closure) stays held
/// alongside the requirer. A `require` on an action is an *action edge*: the
/// held set flows down into the action's subtree but sibling actions sequence
/// and do not share held services. Node 0 is the synthetic owner of the
/// validated task's own requirements.
struct HeldGraph {
    nodes: Vec<HeldNode>,
    index: hashbrown::HashMap<RequirementKey, usize>,
    service_edges: Vec<Vec<usize>>,
    action_edges: Vec<Vec<usize>>,
}

impl HeldGraph {
    fn with_root() -> Self {
        let root =
            HeldNode { base: BaseTaskIndex(0), profile: String::new(), params: ValueMap::new(), is_service: false };
        Self {
            nodes: vec![root],
            index: hashbrown::HashMap::new(),
            service_edges: vec![Vec::new()],
            action_edges: vec![Vec::new()],
        }
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }

    fn intern(&mut self, node: HeldNode) -> usize {
        let key = RequirementKey::new(node.base, &node.profile, &node.params);
        if let Some(id) = self.index.get(&key) {
            return *id;
        }
        let id = self.nodes.len();
        self.index.insert(key, id);
        self.nodes.push(node);
        self.service_edges.push(Vec::new());
        self.action_edges.push(Vec::new());
        id
    }

    /// For each node, the set of service variants it holds (transitive over
    /// service edges, excluding the node itself).
    fn service_closures(&self) -> Vec<hashbrown::HashSet<usize>> {
        let mut closures = vec![hashbrown::HashSet::new(); self.len()];
        for owner in 0..self.len() {
            let mut stack: Vec<usize> = self.service_edges[owner].clone();
            while let Some(service) = stack.pop() {
                if closures[owner].insert(service) {
                    stack.extend(self.service_edges[service].iter().copied());
                }
            }
        }
        closures
    }

    /// Action-spine adjacency: from a node, the action deps of the node and of
    /// every service it holds. The held set propagates along these edges.
    fn spine_adjacency(&self, closures: &[hashbrown::HashSet<usize>]) -> Vec<Vec<usize>> {
        let mut adjacency = vec![Vec::new(); self.len()];
        for owner in 0..self.len() {
            let mut seen = hashbrown::HashSet::new();
            for &action in
                self.action_edges[owner].iter().chain(closures[owner].iter().flat_map(|&s| &self.action_edges[s]))
            {
                if seen.insert(action) {
                    adjacency[owner].push(action);
                }
            }
        }
        adjacency
    }
}

struct Reachability {
    rows: hashbrown::HashMap<usize, Box<[u64]>>,
}

impl Reachability {
    fn for_sources(adjacency: &[Vec<usize>], sources: impl IntoIterator<Item = usize>) -> Self {
        let words = adjacency.len().div_ceil(64);
        let mut rows = hashbrown::HashMap::new();

        for src in sources {
            if rows.contains_key(&src) {
                continue;
            }

            let mut row = vec![0u64; words].into_boxed_slice();
            Self::set_reached(&mut row, src);
            let mut stack = adjacency[src].clone();

            while let Some(next) = stack.pop() {
                if Self::is_reached(&row, next) {
                    continue;
                }
                Self::set_reached(&mut row, next);
                stack.extend(adjacency[next].iter().copied());
            }

            rows.insert(src, row);
        }

        Self { rows }
    }

    fn reaches(&self, src: usize, dst: usize) -> bool {
        src == dst || self.rows.get(&src).is_some_and(|row| Self::is_reached(row, dst))
    }

    fn is_reached(row: &[u64], node: usize) -> bool {
        (row[node / 64] & (1u64 << (node % 64))) != 0
    }

    fn set_reached(row: &mut [u64], node: usize) {
        row[node / 64] |= 1u64 << (node % 64);
    }
}

impl SchedulePlan {
    fn is_running_terminate_pending(&self, job: JobIndex) -> bool {
        self.terminate_running_set.contains(&job)
    }

    /// A live job that this plan will cancel or terminate is no longer a
    /// candidate for reuse, conflict, or barrier purposes.
    fn is_conflict_pending(&self, job: JobIndex) -> bool {
        self.cancel_scheduled_set.contains(&job) || self.terminate_running_set.contains(&job)
    }

    fn record_cancel_scheduled(&mut self, job: JobIndex) {
        if self.cancel_scheduled_set.insert(job) {
            self.cancel_scheduled.push(job);
        }
    }

    fn record_terminate_running(&mut self, terminate: TerminatePlan) {
        if self.terminate_running_set.insert(terminate.job) {
            self.terminate_running.push(terminate);
        }
    }

    fn push_job(&mut self, job: PlannedJob) -> JobRef {
        let id = self.new_jobs.len();
        self.new_jobs.push(job);
        JobRef::Planned(id)
    }

    /// Jobs this plan will create and not cancel, for reuse and compatibility
    /// checks that must see jobs decided earlier in the same submit.
    fn active_planned_jobs(&self) -> impl Iterator<Item = (usize, &PlannedJob)> {
        self.new_jobs
            .iter()
            .enumerate()
            .filter(|(id, job)| !job.synthetic_cached && !self.cancelled_planned.contains(id))
    }
}

/// Which scheduled/running jobs of a base task a new spawn supersedes.
enum ConflictScan {
    All,
    SameProfile(String),
    DifferentProfile(String),
}

impl ConflictScan {
    fn matches(&self, profile: &str) -> bool {
        match self {
            ConflictScan::All => true,
            ConflictScan::SameProfile(p) => profile == p,
            ConflictScan::DifferentProfile(p) => profile != p,
        }
    }
}

#[derive(Default)]
struct ConflictOutcome {
    predicates: Vec<PlannedReq>,
    cancel_scheduled: Vec<JobIndex>,
    cancel_planned: Vec<usize>,
    terminate_running: Vec<TerminatePlan>,
}

impl ConflictOutcome {
    fn record_into(self, plan: &mut SchedulePlan) -> Vec<PlannedReq> {
        for job in self.cancel_scheduled {
            plan.record_cancel_scheduled(job);
        }
        for id in self.cancel_planned {
            plan.cancelled_planned.insert(id);
        }
        for terminate in self.terminate_running {
            plan.record_terminate_running(terminate);
        }
        self.predicates
    }
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
                    let base_path = self.config.current.base_path();
                    for path in *paths {
                        hash_modified_path(&mut self.cache_key_hasher, base_path, path, ignore);
                    }
                }
                CacheKeyInput::ProfileChanged(task_name) => {
                    let counter =
                        self.lookup_name(task_name).map_or(0, |bti| self.base_tasks[bti.idx()].profile_change_counter);
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

    fn job_cache_key_matches(job: &Job, expected_cache_key: &str) -> bool {
        expected_cache_key.is_empty() || job.cache_key == expected_cache_key
    }

    fn successful_job_satisfies_cache(job: &Job, expected_cache_key: &str, max_age: Option<Duration>) -> bool {
        !job.cache_synthetic
            && job.process_status.is_successful_completion()
            && Self::job_cache_key_matches(job, expected_cache_key)
            && finished_within_max_age(&job.process_status, max_age)
    }

    fn persistent_cache_hit(
        &self,
        base_task: BaseTaskIndex,
        expected_cache_key: &str,
        max_age: Option<Duration>,
    ) -> bool {
        let bt = &self.base_tasks[base_task.idx()];
        if bt.config.kind == TaskKind::Service {
            return false;
        }
        self.persistent_cache.is_fresh(bt.config.kind, bt.name.as_ref(), expected_cache_key, max_age)
    }

    fn completed_cache_hit(
        &self,
        base_task: BaseTaskIndex,
        expected_cache_key: &str,
        max_age: Option<Duration>,
        persistent: bool,
    ) -> bool {
        let bt = &self.base_tasks[base_task.idx()];
        for &ji in bt.jobs.all().iter().rev() {
            let job = &self.jobs[ji];
            if Self::successful_job_satisfies_cache(job, expected_cache_key, max_age) {
                return true;
            }
        }
        persistent && self.persistent_cache_hit(base_task, expected_cache_key, max_age)
    }

    /// Resolves a task name (bare or `kind.name`) to a `BaseTaskIndex` using
    /// the priority rules: action/service of the same short name win over a
    /// test of that name. Does not create the synthetic `~cargo` task — for
    /// that, use `base_index_by_name`.
    pub fn lookup_name(&self, name: &str) -> Option<BaseTaskIndex> {
        let (kind_filter, short) = match name.split_once('.') {
            Some(("service", rest)) => (Some(TaskKind::Service), rest),
            Some(("action", rest)) => (Some(TaskKind::Action), rest),
            Some(("test", rest)) => (Some(TaskKind::Test), rest),
            Some(("group", _)) => return None,
            _ => (None, name),
        };
        let entry = self.name_map.get(short)?;
        match kind_filter {
            Some(TaskKind::Service) => match entry.task {
                TaskEntry::Service(i) => Some(i),
                _ => None,
            },
            Some(TaskKind::Action) => match entry.task {
                TaskEntry::Action(i) => Some(i),
                _ => None,
            },
            Some(TaskKind::Test) => entry.test,
            None => entry.task.index().or(entry.test),
        }
    }

    pub fn base_index_by_name(&mut self, name: &str) -> Option<BaseTaskIndex> {
        if name == "~cargo" {
            if let Some(entry) = self.name_map.get("~cargo")
                && let Some(index) = entry.task.index()
            {
                return Some(index);
            }
            let index = BaseTaskIndex::new_or_panic(self.base_tasks.len());
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
            self.name_map.insert("~cargo".into(), NameEntry { task: TaskEntry::Action(index), test: None });
            return Some(index);
        }
        self.lookup_name(name)
    }

    pub fn is_explicit_group_reference(name: &str) -> bool {
        name.split_once('.').is_some_and(|(namespace, _)| namespace == "group")
    }

    fn group_lookup_short_name(name: &str) -> Option<&str> {
        match name.split_once('.') {
            Some(("group", rest)) => Some(rest),
            Some(("service" | "action" | "test", _)) => None,
            _ => Some(name),
        }
    }

    fn group_task_specs(&self, name: &str, force_restart: bool) -> Option<(String, Vec<TaskSpec>)> {
        let short = Self::group_lookup_short_name(name)?;
        let (group_name, tasks) = self.config.current.workspace().groups.iter().find(|(group, _)| *group == short)?;
        let specs = tasks
            .iter()
            .map(|task| TaskSpec {
                name: task.name.to_string(),
                profile: task.profile.unwrap_or_default().to_string(),
                params: task.vars.clone().to_owned(),
                force_restart,
                trace: false,
            })
            .collect();
        Some(((*group_name).to_string(), specs))
    }

    fn lookup_group_name(&self, name: &str) -> Option<String> {
        let short = Self::group_lookup_short_name(name)?;
        self.config
            .current
            .workspace()
            .groups
            .iter()
            .find(|(group, _)| *group == short)
            .map(|(group, _)| (*group).to_string())
    }

    fn record_group_jobs(&mut self, group_name: &str, jobs: &[JobIndex]) {
        let entry = self.group_jobs.entry(group_name.into()).or_default();
        for &job in jobs {
            if !entry.contains(&job) {
                entry.push(job);
            }
        }
    }

    fn refresh_config(&mut self) {
        let Ok(changed) = self.config.refresh() else {
            return;
        };
        if changed {
            self.apply_config_changes();
        }
        // Pick up any daemon-side knob the user has adjusted via
        // ~/.config/devsm.user.toml reload, independent of whether the
        // workspace toml itself changed.
        self.max_job_history = crate::user_config::global_max_job_history();
    }

    /// Canonical reload step. Updates `base_tasks` and `name_map` from the
    /// current `LatestConfig`, drops the per-spawn cache so eval'd configs
    /// from the previous generation are not reused, and rebuilds the static
    /// require analysis.
    ///
    /// Both `refresh_config` and the TUI reload path go through this. Skipping
    /// the require analysis rebuild lets stale cycles or deadlocks linger
    /// across reloads.
    pub fn apply_config_changes(&mut self) {
        self.config.update_base_tasks(&mut self.base_tasks, &mut self.name_map);
        self.spawn_specs.clear();
        self.require_analysis = build_require_analysis(&self.base_tasks, &self.name_map);
        let inputs = task_inputs(&self.base_tasks);
        for (name, err) in self.require_analysis.iter_problems(&inputs) {
            kvlog::warn!("require graph problem", task = name, error = err);
        }
    }

    fn get_or_create_spawn_spec(
        &mut self,
        base_task: BaseTaskIndex,
        profile: &str,
        params: ValueMap<'static>,
    ) -> Result<Arc<ResolvedSpawnSpec>, EvalError> {
        let generation_id = self.base_tasks[base_task.idx()].config.generation_id();
        if let Some(spec) = self.find_cached_spawn_spec(generation_id, base_task, profile, &params) {
            return Ok(spec);
        }
        let config = self.base_tasks[base_task.idx()].config.clone();
        let env = Environment { profile, param: params.clone(), vars: config.vars };
        let task = config.eval(&env)?;
        Ok(self.insert_spawn_spec(generation_id, base_task, profile, params, task))
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

    /// Compute (read-only) the jobs that spawning `base_task`@`profile` conflicts
    /// with, against live state and decisions already in `plan`. The caller
    /// records the result once the new job is added. A live scheduled list never
    /// changes during planning, so this is a plain filtered scan — bounded by the
    /// base task's fan-out within one submit, with no scan-skip heuristic.
    fn plan_conflicts(
        &self,
        plan: &SchedulePlan,
        base_task: BaseTaskIndex,
        profile: &str,
        force_restart: bool,
        protected_jobs: &[JobRef],
    ) -> ConflictOutcome {
        let allow_multiple =
            if force_restart { AllowMultiple::False } else { self.base_tasks[base_task.idx()].config.allow_multiple };
        let mut outcome = ConflictOutcome::default();

        let scan = match allow_multiple {
            AllowMultiple::True => return outcome,
            AllowMultiple::False => ConflictScan::All,
            AllowMultiple::DistinctProfiles => ConflictScan::SameProfile(profile.to_string()),
            AllowMultiple::SingleProfile => ConflictScan::DifferentProfile(profile.to_string()),
        };

        for &job_index in self.base_tasks[base_task.idx()].jobs.scheduled() {
            if plan.is_conflict_pending(job_index) || protected_jobs.contains(&JobRef::Live(job_index)) {
                continue;
            }
            if scan.matches(self.jobs[job_index].spawn_profile()) {
                outcome.cancel_scheduled.push(job_index);
            }
        }
        for (id, job) in plan.new_jobs.iter().enumerate() {
            if job.base_task != base_task
                || job.synthetic_cached
                || plan.cancelled_planned.contains(&id)
                || protected_jobs.contains(&JobRef::Planned(id))
            {
                continue;
            }
            if scan.matches(&job.profile) {
                outcome.cancel_planned.push(id);
            }
        }

        for &job_index in self.base_tasks[base_task.idx()].jobs.running() {
            if protected_jobs.contains(&JobRef::Live(job_index)) {
                continue;
            }
            let job = &self.jobs[job_index];
            let JobStatus::Running { process_index, .. } = &job.process_status else {
                continue;
            };
            if !scan.matches(job.spawn_profile()) {
                continue;
            }
            outcome
                .predicates
                .push(PlannedReq::Task { target: JobRef::Live(job_index), predicate: JobPredicate::Terminated });
            if plan.is_running_terminate_pending(job_index) {
                continue;
            }
            outcome.terminate_running.push(TerminatePlan {
                job: job_index,
                job_id: job.log_group,
                process_index: *process_index,
                exit_cause: ExitCause::Restarted,
            });
        }

        outcome
    }

    fn validate_service_requirement_variants(
        &self,
        owner_base_task: BaseTaskIndex,
        task: &TaskConfigRc,
    ) -> Result<(), String> {
        let task_name = self.base_tasks[owner_base_task.idx()].name.as_ref();
        self.validate_service_requirement_variants_for("Task", task_name, task.config().require)
    }

    fn validate_service_requirement_variants_for(
        &self,
        owner_label: &str,
        task_name: &str,
        requirements: &[crate::config::Requirement<'_>],
    ) -> Result<(), String> {
        let graph = self.build_held_graph(requirements);
        let closures = graph.service_closures();
        let spine = graph.spine_adjacency(&closures);

        // Service-ancestors of a variant node: every node that holds it via
        // service edges. Two conflicting variants are co-held iff some holder of
        // each pair sits on a common action spine (one reaches the other).
        let mut held_by: Vec<Vec<usize>> = vec![Vec::new(); graph.len()];
        let mut reachability_sources = hashbrown::HashSet::new();
        for owner in 0..graph.len() {
            for &service in &closures[owner] {
                held_by[service].push(owner);
                reachability_sources.insert(owner);
            }
        }
        let reachability = Reachability::for_sources(&spine, reachability_sources);

        let mut by_base: hashbrown::HashMap<BaseTaskIndex, Vec<usize>> = hashbrown::HashMap::new();
        for (id, node) in graph.nodes.iter().enumerate() {
            if node.is_service {
                by_base.entry(node.base).or_default().push(id);
            }
        }

        for (base, variants) in &by_base {
            if matches!(self.base_tasks[base.idx()].config.allow_multiple, AllowMultiple::True) {
                continue;
            }
            for i in 0..variants.len() {
                for j in (i + 1)..variants.len() {
                    let a = &graph.nodes[variants[i]];
                    let b = &graph.nodes[variants[j]];
                    if !self.service_variants_conflict(*base, &a.profile, &a.params, &b.profile, &b.params) {
                        continue;
                    }
                    let co_held = held_by[variants[i]].iter().any(|&o1| {
                        held_by[variants[j]]
                            .iter()
                            .any(|&o2| reachability.reaches(o1, o2) || reachability.reaches(o2, o1))
                    });
                    if co_held {
                        let dep_task_name = self.base_tasks[base.idx()].name.as_ref();
                        return Err(format!(
                            "{} '{}' has conflicting service requirements on '{}'",
                            owner_label, task_name, dep_task_name
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn build_held_graph(&self, requirements: &[crate::config::Requirement<'_>]) -> HeldGraph {
        let mut graph = HeldGraph::with_root();
        for child in self.classify_children(requirements) {
            let is_service = child.is_service;
            let id = graph.intern(child);
            if is_service {
                graph.service_edges[0].push(id);
            } else {
                graph.action_edges[0].push(id);
            }
        }

        // `intern` appends, so walking ids in order expands every unique node
        // exactly once; the dedup on `RequirementKey` terminates cyclic requires.
        let mut owner = 1;
        while owner < graph.len() {
            let base = graph.nodes[owner].base;
            let profile = graph.nodes[owner].profile.clone();
            let params = graph.nodes[owner].params.clone();
            let config = &self.base_tasks[base.idx()].config;
            let env = Environment { profile: &profile, param: params, vars: config.vars };
            if let Ok(task) = config.eval(&env) {
                for child in self.classify_children(task.config().require) {
                    let is_service = child.is_service;
                    let id = graph.intern(child);
                    if is_service {
                        graph.service_edges[owner].push(id);
                    } else {
                        graph.action_edges[owner].push(id);
                    }
                }
            }
            owner += 1;
        }
        graph
    }

    fn classify_children(&self, requirements: &[crate::config::Requirement<'_>]) -> Vec<HeldNode> {
        let mut out = Vec::new();
        for req in requirements {
            let crate::config::Requirement::Task(dep_call) = req else {
                continue;
            };
            let dep_name = &*dep_call.name;
            let Some(base) = self.lookup_name(dep_name) else {
                continue;
            };
            let is_service = match self.base_tasks[base.idx()].config.kind {
                TaskKind::Service => true,
                TaskKind::Action => false,
                TaskKind::Test => continue,
            };
            let profile = self.effective_profile_for_task(base, dep_call.profile.unwrap_or(""));
            let params = dep_call.vars.clone().to_owned();
            out.push(HeldNode { base, profile, params, is_service });
        }
        out
    }

    /// Test-only helper for exercising scheduled cancellation through the
    /// canonical status-transition path.
    #[cfg(test)]
    pub fn cancel_scheduled_jobs(&mut self, base_task: BaseTaskIndex) {
        let to_cancel: Vec<JobIndex> = self.base_tasks[base_task.idx()].jobs.scheduled().to_vec();
        for ji in to_cancel {
            self.update_job_status(ji, JobStatus::Cancelled);
        }
    }

    /// O(1) lookup of the precomputed cycle/deadlock result for `root`.
    /// Runs before any job is created so a problematic spawn fails up-front
    /// instead of leaving jobs stuck in `Scheduled` forever.
    pub fn detect_require_problems(&self, root: BaseTaskIndex) -> Result<(), String> {
        self.require_analysis.problem(root)
    }

    /// Spawn a single task (self-contained): build a plan, then apply it. A
    /// failure to build leaves state untouched, so no rollback is needed.
    fn spawn_task(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        base_task: BaseTaskIndex,
        params: ValueMap,
        profile: &str,
        reason: ScheduleReason,
        force_restart: bool,
        trace: bool,
    ) -> Result<JobIndex, String> {
        let mut plan = SchedulePlan::default();
        let job_ref = self.spawn_task_with_extra_requirements_impl(
            &mut plan,
            workspace_id,
            channel,
            base_task,
            params,
            profile,
            reason,
            force_restart,
            trace,
            Vec::new(),
            Vec::new(),
        )?;
        let created = self.apply_plan(plan, workspace_id, channel);
        Ok(Self::resolve_job_ref(job_ref, &created))
    }

    fn resolve_job_ref(job_ref: JobRef, created: &[JobIndex]) -> JobIndex {
        match job_ref {
            JobRef::Live(ji) => ji,
            JobRef::Planned(id) => created[id],
        }
    }

    fn resolve_live_job_ref(job_ref: JobRef, created: &[JobIndex], state: &WorkspaceState) -> Option<JobIndex> {
        let ji = Self::resolve_job_ref(job_ref, created);
        state.jobs.get(ji).is_some().then_some(ji)
    }

    fn spawn_task_tracked(
        &mut self,
        plan: &mut SchedulePlan,
        workspace_id: u32,
        channel: &MioChannel,
        base_task: BaseTaskIndex,
        params: ValueMap,
        profile: &str,
        reason: ScheduleReason,
        force_restart: bool,
        trace: bool,
    ) -> Result<JobRef, String> {
        self.spawn_task_with_extra_requirements_impl(
            plan,
            workspace_id,
            channel,
            base_task,
            params,
            profile,
            reason,
            force_restart,
            trace,
            Vec::new(),
            Vec::new(),
        )
    }

    /// Record one task spawn into `plan` (read-only against `WorkspaceState`).
    /// Returns a [`JobRef`] to the (possibly reused) job; the actual insert
    /// happens in [`Self::apply_plan`].
    #[allow(clippy::too_many_arguments)]
    fn spawn_task_with_extra_requirements_impl(
        &mut self,
        plan: &mut SchedulePlan,
        workspace_id: u32,
        channel: &MioChannel,
        base_task: BaseTaskIndex,
        params: ValueMap,
        profile: &str,
        reason: ScheduleReason,
        force_restart: bool,
        trace: bool,
        extra_requirements: Vec<PlannedReq>,
        protected_conflict_jobs: Vec<JobRef>,
    ) -> Result<JobRef, String> {
        self.detect_require_problems(base_task)?;

        let profile = {
            let bt = &self.base_tasks[base_task.idx()];
            if profile.is_empty() { bt.config.profiles.first().copied().unwrap_or("") } else { profile }
        }
        .to_string();
        let params = params.to_owned();

        // Reuse a compatible scheduled/starting service (live or planned this
        // submit) instead of cancelling it. Cancelling a service that dependents
        // are already wired to via `JobPredicate::Active` would cascade them into
        // "will never be ready" cancellations. Running services keep their
        // documented "explicit spawn restarts" semantic.
        if !force_restart && self.base_tasks[base_task.idx()].config.kind == TaskKind::Service {
            let cache_never = self.base_tasks[base_task.idx()].config.cache.as_ref().is_some_and(|c| c.never);
            if !cache_never {
                for &ji in self.base_tasks[base_task.idx()].jobs.non_terminal() {
                    if plan.is_conflict_pending(ji) {
                        continue;
                    }
                    let job = &self.jobs[ji];
                    if matches!(job.process_status, JobStatus::Running { .. }) {
                        continue;
                    }
                    if service_matches_require(job, &profile, &params) {
                        return Ok(JobRef::Live(ji));
                    }
                }
                for (id, pjob) in plan.active_planned_jobs() {
                    if pjob.base_task == base_task && pjob.profile == profile && pjob.params == params {
                        return Ok(JobRef::Planned(id));
                    }
                }
            }
        }

        let spec = self.get_or_create_spawn_spec(base_task, &profile, params.clone()).map_err(|e| {
            format!("Failed to evaluate task '{}': {:?}", self.base_tasks[base_task.idx()].name.as_ref(), e)
        })?;
        let task = spec.task.clone();

        self.validate_service_requirement_variants(base_task, &task)?;

        let outcome = self.plan_conflicts(plan, base_task, &profile, force_restart, &protected_conflict_jobs);
        let mut pred = outcome.record_into(plan);
        pred.extend(extra_requirements);

        let cache_key = self.compute_task_cache_key(&task, &profile, &params);
        let resolved = self.resolve_task_dep_requirements(plan, workspace_id, channel, &task)?;
        pred.extend(resolved);

        let action_deps_until_ready = self.planned_action_deps_until_ready(plan, base_task, &pred);

        Ok(plan.push_job(PlannedJob {
            base_task,
            task,
            profile,
            params,
            cache_key,
            requirements: pred,
            action_deps_until_ready,
            reason,
            trace,
            synthetic_cached: false,
        }))
    }

    /// The action deps a planned service holds until ready (mirrors the field
    /// `create_job` computes at apply time, but over [`JobRef`]s for barriers).
    fn planned_action_deps_until_ready(
        &self,
        plan: &SchedulePlan,
        base_task: BaseTaskIndex,
        requirements: &[PlannedReq],
    ) -> Vec<JobRef> {
        if self.base_tasks[base_task.idx()].config.kind != TaskKind::Service {
            return Vec::new();
        }
        requirements
            .iter()
            .filter_map(|req| match req {
                PlannedReq::Task { target, predicate: JobPredicate::TerminatedNaturallyAndSuccessfully }
                    if self.job_ref_is_action(plan, *target) =>
                {
                    Some(*target)
                }
                _ => None,
            })
            .collect()
    }

    fn compute_task_cache_key(&mut self, task: &TaskConfigRc, profile: &str, params: &ValueMap) -> String {
        match task.config().cache.as_ref() {
            Some(cache) => self.compute_cache_key_with_require(cache.key, profile, params),
            None => String::new(),
        }
    }

    /// Build, resolve, and convert a task's `require` list into planned
    /// requirements, recording any newly-spawned dependencies into `plan`.
    fn resolve_task_dep_requirements(
        &mut self,
        plan: &mut SchedulePlan,
        workspace_id: u32,
        channel: &MioChannel,
        task: &TaskConfigRc,
    ) -> Result<Vec<PlannedReq>, String> {
        let mut out: Vec<PlannedReq> = Vec::new();
        let mut batch: SpawnBatch<()> = SpawnBatch::new();
        let mut req_keys = Vec::new();

        for req in task.config().require {
            match req {
                crate::config::Requirement::Resource { name, priority } => {
                    let id = self.resources.intern(name);
                    out.push(PlannedReq::Resource { id, priority: *priority });
                }
                crate::config::Requirement::Task(dep_call) => {
                    let dep_name = &*dep_call.name;
                    let dep_profile = dep_call.profile.unwrap_or("");
                    let dep_params = dep_call.vars.clone().to_owned();

                    let Some(dep_base_task) = self.lookup_name(dep_name) else {
                        kvlog::error!("unknown alias", dep_name);
                        continue;
                    };

                    let predicate = match self.base_tasks[dep_base_task.idx()].config.kind {
                        TaskKind::Action => JobPredicate::TerminatedNaturallyAndSuccessfully,
                        TaskKind::Service => JobPredicate::Active,
                        TaskKind::Test => continue,
                    };

                    let key = batch.add_requirement(dep_base_task, dep_profile, dep_params, predicate.clone());
                    req_keys.push((key, predicate));
                }
            }
        }

        self.resolve_batch_requirements(plan, workspace_id, channel, &mut batch)?;

        for (key, predicate) in &req_keys {
            match batch.get_resolved(key) {
                Some(ResolvedRequirement::Cached) => {}
                Some(ResolvedRequirement::Pending(target)) | Some(ResolvedRequirement::Spawned(target)) => {
                    out.push(PlannedReq::Task { target: *target, predicate: predicate.clone() });
                }
                None => {}
            }
        }
        Ok(out)
    }

    /// Record a queued service that waits for blocking services to terminate
    /// before it can start (used on a service profile conflict).
    fn schedule_queued_service(
        &mut self,
        plan: &mut SchedulePlan,
        workspace_id: u32,
        channel: &MioChannel,
        base_task: BaseTaskIndex,
        params: ValueMap,
        profile: &str,
        blocked_by: Vec<JobRef>,
    ) -> Result<JobRef, String> {
        self.detect_require_problems(base_task)?;
        let task = {
            let spawner = &self.base_tasks[base_task.idx()];
            let eval_profile =
                if profile.is_empty() { spawner.config.profiles.first().copied().unwrap_or("") } else { profile };
            let env = Environment { profile: eval_profile, param: params.clone(), vars: spawner.config.vars };
            spawner.config.eval(&env).map_err(|e| format!("Failed to evaluate queued service config: {:?}", e))?
        };
        self.validate_service_requirement_variants(base_task, &task)?;
        let profile = if profile.is_empty() {
            self.base_tasks[base_task.idx()].config.profiles.first().copied().unwrap_or("").to_string()
        } else {
            profile.to_string()
        };
        let params = params.to_owned();
        let cache_key = self.compute_task_cache_key(&task, &profile, &params);
        let mut requirements: Vec<PlannedReq> = blocked_by
            .into_iter()
            .map(|target| PlannedReq::Task { target, predicate: JobPredicate::Terminated })
            .collect();
        let resolved = self.resolve_task_dep_requirements(plan, workspace_id, channel, &task)?;
        requirements.extend(resolved);
        let action_deps_until_ready = self.planned_action_deps_until_ready(plan, base_task, &requirements);

        Ok(plan.push_job(PlannedJob {
            base_task,
            task,
            profile,
            params,
            cache_key,
            requirements,
            action_deps_until_ready,
            reason: ScheduleReason::ProfileConflict,
            trace: false,
            synthetic_cached: false,
        }))
    }

    fn create_job(
        &mut self,
        base_task: BaseTaskIndex,
        task: TaskConfigRc,
        profile: &str,
        params: ValueMap<'static>,
        cache_key: String,
        requirements: Vec<ScheduleRequirement>,
        channel: &MioChannel,
        _workspace_id: u32,
        reason: ScheduleReason,
        trace: bool,
    ) -> JobIndex {
        let (task_name, task_kind, job_id) = {
            let bt = &mut self.base_tasks[base_task.idx()];
            let task_name = bt.name.clone();
            let task_kind = bt.config.kind;
            bt.update_profile_tracking(profile);
            if task_kind == TaskKind::Service {
                bt.has_run_this_session = true;
            }
            let pc = bt.spawn_counter as usize;
            bt.spawn_counter = bt.spawn_counter.wrapping_add(1);
            (task_name, task_kind, LogGroup::new(base_task, pc))
        };
        let spec = self.cache_spawn_spec(base_task, profile, params, task.clone());

        let action_deps_until_ready: SmallVec<[JobIndex; 2]> = if task_kind == TaskKind::Service {
            requirements
                .iter()
                .filter_map(|req| match req {
                    ScheduleRequirement::Task { job, predicate: JobPredicate::TerminatedNaturallyAndSuccessfully } => {
                        self.jobs.get(*job).and_then(|dep_job| {
                            let dep_base_task = dep_job.log_group.base_task_index();
                            (self.base_tasks[dep_base_task.idx()].config.kind == TaskKind::Action).then_some(*job)
                        })
                    }
                    _ => None,
                })
                .collect()
        } else {
            SmallVec::new()
        };

        let active_deps: Vec<JobIndex> = requirements
            .iter()
            .filter_map(|req| match req {
                ScheduleRequirement::Task { job, predicate: JobPredicate::Active } => Some(*job),
                _ => None,
            })
            .collect();
        let job_index = self.jobs.insert(Job {
            process_status: JobStatus::Scheduled { after: requirements },
            log_group: job_id,
            started_at: crate::clock::now(),
            cache_key,
            cache_synthetic: false,
            spawn: spec.clone(),
            held_resources: SmallVec::new(),
            action_deps_until_ready,
            trace,
            trace_report: None,
        });

        self.base_tasks[base_task.idx()].jobs.push_scheduled(job_index);
        let global_list = match task_kind {
            TaskKind::Action => &mut self.action_jobs,
            TaskKind::Test => &mut self.test_jobs,
            TaskKind::Service => &mut self.service_jobs,
        };
        global_list.push_scheduled(job_index);
        for dep in active_deps {
            self.service_dependents.add_dependent(dep, job_index);
        }

        kvlog::info!("Job scheduled", task_name = task_name.as_ref(), job_index, reason = reason.name());
        channel.wake();
        let _ = (task, job_id);
        job_index
    }

    fn create_cached_success_job(
        &mut self,
        base_task: BaseTaskIndex,
        task: TaskConfigRc,
        profile: &str,
        params: ValueMap<'static>,
        cache_key: String,
        reason: ScheduleReason,
    ) -> JobIndex {
        let spec = self.cache_spawn_spec(base_task, profile, params, task);
        let (task_kind, job_id) = {
            let bt = &mut self.base_tasks[base_task.idx()];
            let task_kind = bt.config.kind;
            let pc = bt.spawn_counter as usize;
            bt.spawn_counter = bt.spawn_counter.wrapping_add(1);
            (task_kind, LogGroup::new(base_task, pc))
        };
        let now = crate::clock::now();
        let job_index = self.jobs.insert(Job {
            process_status: JobStatus::Exited { finished_at: now, cause: ExitCause::Unknown, status: 0 },
            log_group: job_id,
            started_at: now,
            cache_key,
            cache_synthetic: true,
            spawn: spec,
            held_resources: SmallVec::new(),
            action_deps_until_ready: SmallVec::new(),
            trace: false,
            trace_report: None,
        });

        self.base_tasks[base_task.idx()].jobs.push_terminated(job_index);
        let global_list = match task_kind {
            TaskKind::Action => &mut self.action_jobs,
            TaskKind::Test => &mut self.test_jobs,
            TaskKind::Service => &mut self.service_jobs,
        };
        global_list.push_terminated(job_index);
        self.change_number = self.change_number.wrapping_add(1);
        if self.jobs.len() as u32 > self.max_job_history {
            self.prune_history();
        }

        kvlog::info!("Created cached success job", ?base_task, ?job_index, reason = reason.name());
        job_index
    }

    fn resolve_planned_reqs(reqs: &[PlannedReq], local_to_job: &[JobIndex]) -> Vec<ScheduleRequirement> {
        let mut out = Vec::with_capacity(reqs.len());
        for req in reqs {
            match req {
                PlannedReq::Resource { id, priority } => {
                    out.push(ScheduleRequirement::Resource { id: *id, priority: *priority })
                }
                PlannedReq::Task { target, predicate } => {
                    let job = match target {
                        JobRef::Live(ji) => *ji,
                        JobRef::Planned(local) => local_to_job[*local],
                    };
                    out.push(ScheduleRequirement::Task { job, predicate: predicate.clone() });
                }
            }
        }
        out
    }

    /// Apply a fully-built plan. This is the only mutating step and cannot fail:
    /// jobs are inserted (deps before dependents), superseded jobs cancelled, and
    /// running conflicts terminated. Returns the created `JobIndex` per planned
    /// job, in plan order, so callers can resolve their [`JobRef`]s.
    fn apply_plan(&mut self, plan: SchedulePlan, workspace_id: u32, channel: &MioChannel) -> Vec<JobIndex> {
        let SchedulePlan { new_jobs, cancelled_planned, cancel_scheduled, terminate_running, .. } = plan;
        let created_any = !new_jobs.is_empty();
        let mut local_to_job: Vec<JobIndex> = Vec::with_capacity(new_jobs.len());

        for planned in new_jobs {
            let PlannedJob {
                base_task,
                task,
                profile,
                params,
                cache_key,
                requirements,
                action_deps_until_ready: _,
                reason,
                trace,
                synthetic_cached,
            } = planned;
            let job_index = if synthetic_cached {
                self.create_cached_success_job(base_task, task, &profile, params, cache_key, reason)
            } else {
                let reqs = Self::resolve_planned_reqs(&requirements, &local_to_job);
                self.create_job(
                    base_task,
                    task,
                    &profile,
                    params,
                    cache_key,
                    reqs,
                    channel,
                    workspace_id,
                    reason,
                    trace,
                )
            };
            local_to_job.push(job_index);
        }

        // A planned job superseded by a later same-base spawn is created and then
        // cancelled, exactly as the eager path did, so dependents wired to it
        // cascade through the canonical "will never be ready" path.
        for id in cancelled_planned {
            let job_index = local_to_job[id];
            if matches!(self.jobs.get(job_index).map(|j| &j.process_status), Some(JobStatus::Scheduled { .. })) {
                self.update_job_status(job_index, JobStatus::Cancelled);
            }
        }

        for job_index in cancel_scheduled {
            let Some(job) = self.jobs.get(job_index) else { continue };
            if !matches!(job.process_status, JobStatus::Scheduled { .. }) {
                continue;
            }
            self.update_job_status(job_index, JobStatus::Cancelled);
        }

        for terminate in terminate_running {
            let Some(job) = self.jobs.get(terminate.job) else { continue };
            let JobStatus::Running { process_index, .. } = &job.process_status else {
                continue;
            };
            if job.log_group != terminate.job_id || *process_index != terminate.process_index {
                continue;
            }
            channel.send(crate::event_loop::ProcessRequest::TerminateJob {
                job_id: terminate.job_id,
                process_index: terminate.process_index,
                exit_cause: terminate.exit_cause,
            });
        }

        if created_any && self.jobs.len() as u32 > self.max_job_history {
            self.prune_history();
        }
        local_to_job
    }
}

impl std::ops::Index<JobIndex> for WorkspaceState {
    type Output = Job;
    fn index(&self, index: JobIndex) -> &Self::Output {
        &self.jobs[index]
    }
}

impl WorkspaceState {
    /// Returns the canonical full name (`kind.name`) for a base task — the
    /// form passed across RPC boundaries and used by `SpawnSpec::task`.
    /// `~cargo` is the one synthetic exception kept as a bare name.
    pub fn spawn_name_for(&self, bti: BaseTaskIndex) -> String {
        let bt = &self.base_tasks[bti.idx()];
        if bt.name.as_ref() == "~cargo" {
            return "~cargo".to_string();
        }
        format!("{}.{}", bt.config.kind.as_str(), bt.name)
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
                    if job.cache_synthetic {
                        summary.cached += 1;
                    } else if *status == 0 {
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
        self.lookup_and_spawn_task_with_trace(workspace_id, channel, name, params, profile, force_restart, false)
    }

    pub fn lookup_and_spawn_task_with_trace(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        name: &str,
        params: ValueMap,
        profile: &str,
        force_restart: bool,
        trace: bool,
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
            trace,
        )?;
        Ok((base_index, job_index))
    }

    fn active_matching_job(
        &self,
        base_task: BaseTaskIndex,
        profile: &str,
        params: &ValueMap<'static>,
    ) -> Option<JobIndex> {
        self.base_tasks[base_task.idx()].jobs.non_terminal().iter().rev().copied().find(|&job_index| {
            let job = &self.jobs[job_index];
            job.spawn_profile() == profile && job.spawn_params() == params
        })
    }

    fn active_matching_job_in_plan(
        &self,
        base_task: BaseTaskIndex,
        profile: &str,
        params: &ValueMap<'static>,
        plan: &SchedulePlan,
    ) -> Option<JobRef> {
        for &job_index in self.base_tasks[base_task.idx()].jobs.non_terminal().iter().rev() {
            if plan.is_conflict_pending(job_index) {
                continue;
            }
            let job = &self.jobs[job_index];
            if job.spawn_profile() == profile && job.spawn_params() == params {
                return Some(JobRef::Live(job_index));
            }
        }
        for (id, pjob) in plan.active_planned_jobs() {
            if pjob.base_task == base_task && pjob.profile.as_str() == profile && &pjob.params == params {
                return Some(JobRef::Planned(id));
            }
        }
        None
    }

    pub fn lookup_and_start_task_with_trace(
        &mut self,
        workspace_id: u32,
        channel: &MioChannel,
        name: &str,
        params: ValueMap,
        profile: &str,
        trace: bool,
    ) -> Result<(BaseTaskIndex, JobIndex), String> {
        let Some(base_index) = self.base_index_by_name(name) else {
            return Err(format!("Task '{}' not found", name));
        };
        let profile = self.effective_profile_for_task(base_index, profile);
        let params = params.to_owned();

        if let Some(job_index) = self.active_matching_job(base_index, &profile, &params) {
            return Ok((base_index, job_index));
        }

        self.change_number = self.change_number.wrapping_add(1);
        let job_index = self.spawn_task(
            workspace_id,
            channel,
            base_index,
            params,
            &profile,
            ScheduleReason::Requested,
            false,
            trace,
        )?;
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
        max_age: Option<Duration>,
        persistent: bool,
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
                    if Self::successful_job_satisfies_cache(job, expected_cache_key, max_age) {
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

        if persistent && self.persistent_cache_hit(base_index, expected_cache_key, max_age) {
            return Some(format!("Task '{}' cache hit (persistent)", name));
        }

        None
    }

    fn terminate_job_indices(
        &mut self,
        channel: &MioChannel,
        label: &str,
        name: &str,
        job_indices: Vec<JobIndex>,
    ) -> String {
        self.change_number = self.change_number.wrapping_add(1);

        let mut seen = hashbrown::HashSet::new();
        let mut jobs_to_cancel = Vec::new();
        let mut killed_count = 0u32;
        let mut cancelled_count = 0u32;

        for job_index in job_indices {
            if !seen.insert(job_index) {
                continue;
            }
            if self.jobs.get(job_index).is_none() {
                continue;
            }
            let job = &self.jobs[job_index];
            match &job.process_status {
                JobStatus::Running { process_index, .. } => {
                    kvlog::info!("Terminating running job", label, name, job_index, process_index);
                    channel.send(crate::event_loop::ProcessRequest::TerminateJob {
                        job_id: job.log_group,
                        process_index: *process_index,
                        exit_cause: ExitCause::Killed,
                    });
                    killed_count += 1;
                }
                JobStatus::Starting => {
                    kvlog::warn!("Job is in Starting state during termination", label, name, job_index);
                }
                JobStatus::Scheduled { .. } => {
                    kvlog::info!("Cancelling scheduled job", label, name, job_index);
                    jobs_to_cancel.push(job_index);
                    cancelled_count += 1;
                }
                JobStatus::Exited { .. } | JobStatus::Cancelled => {}
            }
        }

        for job_index in jobs_to_cancel {
            self.update_job_status(job_index, JobStatus::Cancelled);
        }

        match (killed_count, cancelled_count) {
            (0, 0) => format!("{} '{}' was already finished", label, name),
            (k, 0) => format!("{} '{}' terminated ({} killed)", label, name, k),
            (0, c) => format!("{} '{}' cancelled ({} scheduled)", label, name, c),
            (k, c) => format!("{} '{}' terminated ({} killed, {} cancelled)", label, name, k, c),
        }
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
        let task_name = bt.name.to_string();
        let job_indices = bt.jobs.non_terminal().to_vec();

        Ok(self.terminate_job_indices(channel, "Task", &task_name, job_indices))
    }

    pub fn lookup_and_terminate_group(&mut self, channel: &MioChannel, name: &str) -> Result<String, String> {
        let Some(group_name) = self.lookup_group_name(name) else {
            let short = Self::group_lookup_short_name(name).unwrap_or(name);
            return Err(format!("Group '{}' not found", short));
        };
        let job_indices = self.group_jobs.get(group_name.as_str()).cloned().unwrap_or_default();
        Ok(self.terminate_job_indices(channel, "Group", &group_name, job_indices))
    }
}
impl std::ops::IndexMut<JobIndex> for WorkspaceState {
    fn index_mut(&mut self, index: JobIndex) -> &mut Self::Output {
        &mut self.jobs[index]
    }
}

#[derive(Debug)]
pub enum Scheduled {
    Ready(JobIndex),
    Never(JobIndex),
    None,
}

struct ScheduledCandidate {
    job: JobIndex,
    resources: SmallVec<[(ResourceIndex, i32); 2]>,
}

impl WorkspaceState {
    fn effective_profile_for_task(&self, base_task: BaseTaskIndex, profile: &str) -> String {
        if profile.is_empty() {
            self.base_tasks[base_task.idx()].config.profiles.first().copied().unwrap_or("").to_string()
        } else {
            profile.to_string()
        }
    }

    fn service_variants_conflict(
        &self,
        base_task: BaseTaskIndex,
        existing_profile: &str,
        existing_params: &ValueMap,
        requested_profile: &str,
        requested_params: &ValueMap,
    ) -> bool {
        match self.base_tasks[base_task.idx()].config.allow_multiple {
            AllowMultiple::True => false,
            AllowMultiple::False => existing_profile != requested_profile || existing_params != requested_params,
            AllowMultiple::DistinctProfiles => {
                existing_profile == requested_profile && existing_params != requested_params
            }
            AllowMultiple::SingleProfile => existing_profile != requested_profile,
        }
    }

    fn service_still_needs_action_outputs_until_ready(job: &Job) -> bool {
        match &job.process_status {
            JobStatus::Scheduled { .. } | JobStatus::Starting => true,
            JobStatus::Running { ready_state, .. } => matches!(ready_state, Some(false)),
            JobStatus::Exited { .. } | JobStatus::Cancelled => false,
        }
    }

    fn action_job_conflicts_with_request(
        &self,
        action_base_task: BaseTaskIndex,
        existing_job: JobIndex,
        requested_profile: &str,
    ) -> bool {
        let Some(existing) = self.jobs.get(existing_job) else {
            return false;
        };
        if existing.log_group.base_task_index() != action_base_task {
            return false;
        }
        match self.base_tasks[action_base_task.idx()].config.allow_multiple {
            AllowMultiple::True => false,
            AllowMultiple::False => true,
            AllowMultiple::DistinctProfiles => existing.spawn_profile() == requested_profile,
            AllowMultiple::SingleProfile => existing.spawn_profile() != requested_profile,
        }
    }

    /// Whether a planned (not-yet-inserted) action job conflicts with a request.
    fn planned_action_conflicts_with_request(
        &self,
        pjob: &PlannedJob,
        action_base_task: BaseTaskIndex,
        requested_profile: &str,
    ) -> bool {
        if pjob.base_task != action_base_task {
            return false;
        }
        match self.base_tasks[action_base_task.idx()].config.allow_multiple {
            AllowMultiple::True => false,
            AllowMultiple::False => true,
            AllowMultiple::DistinctProfiles => pjob.profile == requested_profile,
            AllowMultiple::SingleProfile => pjob.profile != requested_profile,
        }
    }

    fn job_ref_conflicts_as_action(
        &self,
        plan: &SchedulePlan,
        target: JobRef,
        action_base_task: BaseTaskIndex,
        requested_profile: &str,
    ) -> bool {
        match target {
            JobRef::Live(ji) => self.action_job_conflicts_with_request(action_base_task, ji, requested_profile),
            JobRef::Planned(id) => {
                self.planned_action_conflicts_with_request(&plan.new_jobs[id], action_base_task, requested_profile)
            }
        }
    }

    fn job_ref_is_action(&self, plan: &SchedulePlan, target: JobRef) -> bool {
        let base = match target {
            JobRef::Live(ji) => match self.jobs.get(ji) {
                Some(job) => job.log_group.base_task_index(),
                None => return false,
            },
            JobRef::Planned(id) => plan.new_jobs[id].base_task,
        };
        self.base_tasks[base.idx()].config.kind == TaskKind::Action
    }

    fn service_uses_action_output_until_ready(
        &self,
        service_job: JobIndex,
        action_base_task: BaseTaskIndex,
        requested_profile: &str,
    ) -> bool {
        let Some(job) = self.jobs.get(service_job) else {
            return false;
        };
        if !Self::service_still_needs_action_outputs_until_ready(job) {
            return false;
        }
        job.action_deps_until_ready
            .iter()
            .any(|dep| self.action_job_conflicts_with_request(action_base_task, *dep, requested_profile))
    }

    /// Services (live or planned this submit) that still depend on this action's
    /// output until they become ready. The new action must wait for them so it
    /// is not restarted out from under a service that still needs its output.
    fn action_output_ready_barriers(
        &self,
        action_base_task: BaseTaskIndex,
        requested_profile: &str,
        plan: &SchedulePlan,
    ) -> Vec<JobRef> {
        let mut barriers: Vec<JobRef> = self
            .service_jobs
            .non_terminal()
            .iter()
            .copied()
            .filter(|service_job| !plan.is_conflict_pending(*service_job))
            .filter(|service_job| {
                self.service_uses_action_output_until_ready(*service_job, action_base_task, requested_profile)
            })
            .map(JobRef::Live)
            .collect();
        for (id, pjob) in plan.active_planned_jobs() {
            if self.base_tasks[pjob.base_task.idx()].config.kind != TaskKind::Service {
                continue;
            }
            if pjob
                .action_deps_until_ready
                .iter()
                .any(|dep| self.job_ref_conflicts_as_action(plan, *dep, action_base_task, requested_profile))
            {
                barriers.push(JobRef::Planned(id));
            }
        }
        barriers
    }

    fn action_jobs_protected_by_ready_barriers(
        &self,
        action_base_task: BaseTaskIndex,
        requested_profile: &str,
        barriers: &[JobRef],
        plan: &SchedulePlan,
    ) -> Vec<JobRef> {
        let mut protected: Vec<JobRef> = Vec::new();
        for &barrier in barriers {
            let deps: Vec<JobRef> = match barrier {
                JobRef::Live(ji) => match self.jobs.get(ji) {
                    Some(job) => job.action_deps_until_ready.iter().copied().map(JobRef::Live).collect(),
                    None => Vec::new(),
                },
                JobRef::Planned(id) => plan.new_jobs[id].action_deps_until_ready.clone(),
            };
            for dep in deps {
                if self.job_ref_conflicts_as_action(plan, dep, action_base_task, requested_profile)
                    && !protected.contains(&dep)
                {
                    protected.push(dep);
                }
            }
        }
        protected
    }

    fn conflicting_non_terminal_action_jobs(
        &self,
        action_base_task: BaseTaskIndex,
        requested_profile: &str,
        plan: &SchedulePlan,
    ) -> Vec<JobRef> {
        let mut jobs: Vec<JobRef> = self.base_tasks[action_base_task.idx()]
            .jobs
            .non_terminal()
            .iter()
            .copied()
            .filter(|job| !plan.is_conflict_pending(*job))
            .filter(|job| self.action_job_conflicts_with_request(action_base_task, *job, requested_profile))
            .map(JobRef::Live)
            .collect();
        for (id, pjob) in plan.active_planned_jobs() {
            if self.planned_action_conflicts_with_request(pjob, action_base_task, requested_profile) {
                jobs.push(JobRef::Planned(id));
            }
        }
        jobs
    }

    /// Update a job's `JobStatus`, maintaining the side-tables that depend on it.
    ///
    /// On `Scheduled → Starting` this acquires every `Resource` requirement in
    /// the old `after` list. On any terminal transition (`→ Exited` or
    /// `→ Cancelled`) it releases all resources the job currently holds.
    /// Callers must drive [`Self::next_scheduled`] after a terminal transition
    /// so any waiters can pick up the freed resources.
    #[track_caller]
    pub fn update_job_status(&mut self, job_index: JobIndex, status: JobStatus) -> Option<u32> {
        use JobStatus as S;

        // Capture the public id before any side effects: a terminal transition
        // can trigger `prune_history`, which may evict the just-finished job.
        // Callers that broadcast on the wire need the public id even when the
        // handle is no longer live by the time the broadcast runs.
        let captured_public_id = self.jobs.public_id_of(job_index);

        let resources_to_acquire: SmallVec<[ResourceIndex; 2]> = match (&self.jobs[job_index].process_status, &status) {
            (S::Scheduled { after }, S::Starting) => after
                .iter()
                .filter_map(|r| match r {
                    ScheduleRequirement::Resource { id, .. } => Some(*id),
                    _ => None,
                })
                .collect(),
            _ => SmallVec::new(),
        };

        let release_held = matches!(
            (&self.jobs[job_index].process_status, &status),
            (S::Starting, S::Cancelled)
                | (S::Running { .. }, S::Cancelled)
                | (S::Starting, S::Exited { .. })
                | (S::Running { .. }, S::Exited { .. })
        );

        let job = &mut self.jobs[job_index];
        let job_id = job.log_group;
        let base_task = &mut self.base_tasks[job_id.base_task_index().idx()];
        let task_name_owned = base_task.name.clone();
        let task_name = task_name_owned.as_ref();
        let task_kind = base_task.config.kind;
        let jobs_list = &mut base_task.jobs;

        kvlog::info!("Job status changed", job_index, task_name, status = status.name());

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
                | (S::Starting, S::Exited { .. })
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
            | (S::Starting, S::Exited { .. })
            | (S::Running { .. }, S::Exited { .. }) => {
                self.service_dependents.remove_from_all(job_index);
            }
            _ => {}
        }

        let should_record_persistent_cache = matches!(&status, S::Exited { status, .. } if *status == 0);
        let is_now_terminal = matches!(status, S::Exited { .. } | S::Cancelled);
        self.jobs[job_index].process_status = status;

        for id in &resources_to_acquire {
            self.resources.acquire(*id, job_index);
        }
        if !resources_to_acquire.is_empty() {
            self.jobs[job_index].held_resources.extend(resources_to_acquire);
        }

        if release_held {
            let to_release = std::mem::take(&mut self.jobs[job_index].held_resources);
            for id in to_release {
                self.resources.release(id);
            }
        }

        if should_record_persistent_cache && task_kind != TaskKind::Service {
            let cache_key = {
                let job = &self.jobs[job_index];
                let cache_config = job.task().config().cache.as_ref();
                if !job.cache_synthetic && cache_config.is_some_and(|cache| cache.persistent && !cache.never) {
                    Some(job.cache_key.clone())
                } else {
                    None
                }
            };
            if let Some(cache_key) = cache_key {
                self.persistent_cache.record_success(task_kind, task_name_owned.as_ref(), &cache_key);
            }
        }

        if is_now_terminal && self.jobs.len() as u32 > self.max_job_history {
            self.prune_history();
        }

        captured_public_id
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
                    if let ScheduleRequirement::Task { job: ji, .. } = req {
                        protected.insert(*ji);
                    }
                }
            }
            if Self::service_still_needs_action_outputs_until_ready(job) {
                protected.extend(job.action_deps_until_ready.iter().copied());
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

        for jobs in self.group_jobs.values_mut() {
            jobs.retain(|ji| still_live(*ji));
        }
        self.group_jobs.retain(|_, jobs| !jobs.is_empty());

        if let Some(tg) = &mut self.last_test_group {
            // `base_tasks` and `job_indices` are parallel arrays. Filter both
            // in lockstep so positions stay aligned for rerun and narrow.
            let mut write = 0;
            for read in 0..tg.job_indices.len() {
                if still_live(tg.job_indices[read]) {
                    tg.job_indices[write] = tg.job_indices[read];
                    tg.base_tasks[write] = tg.base_tasks[read];
                    write += 1;
                }
            }
            tg.job_indices.truncate(write);
            tg.base_tasks.truncate(write);
            if tg.job_indices.is_empty() {
                self.last_test_group = None;
            }
        }

        kvlog::info!("Job history pruned", evicted = evicted.len(), live = self.jobs.len());
    }

    pub fn new(config_path: PathBuf) -> Result<WorkspaceState, crate::config::ConfigError> {
        let config = LatestConfig::new(config_path.clone())?;
        let mut base_tasks = Vec::new();
        let mut name_map = hashbrown::HashMap::new();
        config.update_base_tasks(&mut base_tasks, &mut name_map);
        let max_job_history = crate::user_config::global_max_job_history();
        let require_analysis = build_require_analysis(&base_tasks, &name_map);

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
            group_jobs: hashbrown::HashMap::new(),
            resources: ResourceSlab::default(),
            require_analysis,
            cache_key_hasher: CacheKeyHasher::new(),
            persistent_cache: PersistentCache::new(&config_path),
            spawn_specs: hashbrown::HashMap::new(),
        })
    }

    fn winner_per_resource(
        candidates: &[ScheduledCandidate],
    ) -> hashbrown::HashMap<ResourceIndex, (JobIndex, i32, usize)> {
        let mut winner_per_resource: hashbrown::HashMap<ResourceIndex, (JobIndex, i32, usize)> =
            hashbrown::HashMap::new();
        for (rank, c) in candidates.iter().enumerate() {
            for &(id, priority) in &c.resources {
                let take = match winner_per_resource.get(&id) {
                    None => true,
                    Some(&(_, cur_prio, cur_rank)) => priority > cur_prio || (priority == cur_prio && rank < cur_rank),
                };
                if take {
                    winner_per_resource.insert(id, (c.job, priority, rank));
                }
            }
        }
        winner_per_resource
    }

    fn candidate_wins_all_resources(
        candidate: &ScheduledCandidate,
        winner_per_resource: &hashbrown::HashMap<ResourceIndex, (JobIndex, i32, usize)>,
    ) -> bool {
        candidate.resources.iter().all(|&(id, _)| winner_per_resource.get(&id).map(|w| w.0) == Some(candidate.job))
    }

    fn select_scheduled_candidate(candidates: &[ScheduledCandidate]) -> Option<JobIndex> {
        if candidates.is_empty() {
            return None;
        }

        let winner_per_resource = Self::winner_per_resource(candidates);
        for c in candidates {
            if Self::candidate_wins_all_resources(c, &winner_per_resource) {
                return Some(c.job);
            }
        }

        // Crossed multi-resource priorities can otherwise produce no candidate
        // that wins every resource. FIFO fallback preserves progress while the
        // normal per-resource priority winner remains unchanged when one exists.
        candidates.first().map(|c| c.job)
    }

    fn resource_available_after_terminations(&self, id: ResourceIndex, termination_jobs: &[JobIndex]) -> bool {
        self.resources.holder(id).is_none_or(|holder| termination_jobs.contains(&holder))
    }

    fn requirements_ready_after_terminations(
        &self,
        requirements: &[ScheduleRequirement],
        termination_jobs: &[JobIndex],
    ) -> Option<SmallVec<[(ResourceIndex, i32); 2]>> {
        let mut resources: SmallVec<[(ResourceIndex, i32); 2]> = SmallVec::new();
        for req in requirements {
            match req {
                ScheduleRequirement::Resource { id, priority } => {
                    if !self.resource_available_after_terminations(*id, termination_jobs) {
                        return None;
                    }
                    resources.push((*id, *priority));
                }
                ScheduleRequirement::Task { job, predicate: JobPredicate::Terminated }
                    if termination_jobs.contains(job) => {}
                ScheduleRequirement::Task { .. } => {
                    if !matches!(req.status(self), RequirementStatus::Met) {
                        return None;
                    }
                }
            }
        }
        Some(resources)
    }

    fn scheduled_candidates_after_terminations(&self, termination_jobs: &[JobIndex]) -> Vec<ScheduledCandidate> {
        let mut candidates = Vec::new();
        for job_set in [&self.action_jobs, &self.service_jobs, &self.test_jobs] {
            for &job_index in job_set.scheduled() {
                let JobStatus::Scheduled { after } = &self[job_index].process_status else {
                    kvlog::error!("Inconsistent JobStatus in queued service resource arbitration",
                     status = ?&self[job_index].process_status, ?job_index);
                    continue;
                };
                if let Some(resources) = self.requirements_ready_after_terminations(after, termination_jobs) {
                    candidates.push(ScheduledCandidate { job: job_index, resources });
                }
            }
        }
        candidates
    }

    /// Pick one job to start next.
    ///
    /// Returns the first scheduled job whose non-resource requirements are met
    /// AND which wins every resource it needs against any other candidate
    /// contending for the same resource. Resource arbitration: highest
    /// `priority` wins; FIFO tiebreak by candidate enumeration order
    /// (`action_jobs` → `service_jobs` → `test_jobs`, scheduled order within
    /// each pool). Cross-pool contention is intentionally arbitrated by
    /// priority — a high-priority test wins resource over a low-priority
    /// action.
    pub fn next_scheduled(&self) -> Scheduled {
        if !self.has_scheduled_task() {
            return Scheduled::None;
        }

        let mut candidates: Vec<ScheduledCandidate> = Vec::new();

        for job_set in [&self.action_jobs, &self.service_jobs, &self.test_jobs] {
            'pending: for &job_index in job_set.scheduled() {
                let JobStatus::Scheduled { after } = &self[job_index].process_status else {
                    kvlog::error!("Inconsistent JobStatus in WorkspaceState::next_scheduled",
                     status = ?&self[job_index].process_status, ?job_index);
                    continue;
                };
                let mut resources: SmallVec<[(ResourceIndex, i32); 2]> = SmallVec::new();
                for req in after {
                    match req {
                        ScheduleRequirement::Resource { id, priority } => {
                            if !self.resources.is_free(*id) {
                                continue 'pending;
                            }
                            resources.push((*id, *priority));
                        }
                        ScheduleRequirement::Task { .. } => match req.status(self) {
                            RequirementStatus::Pending => continue 'pending,
                            RequirementStatus::Never => return Scheduled::Never(job_index),
                            RequirementStatus::Met => (),
                        },
                    }
                }
                candidates.push(ScheduledCandidate { job: job_index, resources });
            }
        }

        if candidates.is_empty() {
            return Scheduled::None;
        }

        Self::select_scheduled_candidate(&candidates).map_or(Scheduled::None, Scheduled::Ready)
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
                let ScheduleRequirement::Task { job: req_job, predicate: JobPredicate::Terminated } = req else {
                    continue;
                };
                let blocking_job = &self.jobs[*req_job];
                if !blocking_job.process_status.is_running() || !self.service_dependents.can_stop(*req_job) {
                    continue;
                }
                // Resource arbitration is constant for the scheduled job, so check it once a
                // stoppable blocker exists rather than for every scheduled service every tick.
                if !self.queued_service_replacement_requirements_met(scheduled_job_index, after) {
                    break;
                }
                let exit_cause = if blocking_job.log_group.base_task_index() == scheduled_base_task {
                    ExitCause::Restarted
                } else {
                    ExitCause::ProfileConflict
                };
                return Some((*req_job, exit_cause));
            }
        }
        None
    }

    /// Find a service that should be terminated to free a resource a scheduled
    /// task is waiting on.
    ///
    /// Mirrors [`Self::service_to_terminate_for_queue`] but for
    /// [`ScheduleRequirement::Resource`]: a scheduled task (any kind) is
    /// blocked on a resource currently held by a running service that has no
    /// active dependents. Actions and tests holding resources are never
    /// evicted — they are expected to terminate on their own.
    pub fn service_to_terminate_for_resource(&self) -> Option<(JobIndex, ExitCause)> {
        for job_set in [&self.action_jobs, &self.service_jobs, &self.test_jobs] {
            for &scheduled_ji in job_set.scheduled() {
                let JobStatus::Scheduled { after } = &self[scheduled_ji].process_status else {
                    continue;
                };
                if !self.non_resource_requirements_met(after) {
                    continue;
                }
                for req in after {
                    let ScheduleRequirement::Resource { id, .. } = req else { continue };
                    if self.resources.is_free(*id) {
                        continue;
                    }
                    let Some(holder_ji) = self.resources.holder(*id) else { continue };
                    let holder = &self.jobs[holder_ji];
                    if !holder.process_status.is_running() {
                        continue;
                    }
                    let bti = holder.log_group.base_task_index();
                    if self.base_tasks[bti.idx()].config.kind != TaskKind::Service {
                        continue;
                    }
                    if !self.service_dependents.can_stop(holder_ji) {
                        continue;
                    }
                    return Some((holder_ji, ExitCause::Killed));
                }
            }
        }
        None
    }

    fn non_resource_requirements_met(&self, requirements: &[ScheduleRequirement]) -> bool {
        requirements.iter().all(|req| match req {
            ScheduleRequirement::Task { .. } => matches!(req.status(self), RequirementStatus::Met),
            ScheduleRequirement::Resource { .. } => true,
        })
    }

    fn queued_service_replacement_requirements_met(
        &self,
        scheduled_job_index: JobIndex,
        requirements: &[ScheduleRequirement],
    ) -> bool {
        let termination_jobs: SmallVec<[JobIndex; 4]> = requirements
            .iter()
            .filter_map(|req| match req {
                ScheduleRequirement::Task { job, predicate: JobPredicate::Terminated } => Some(*job),
                _ => None,
            })
            .collect();

        let candidates = self.scheduled_candidates_after_terminations(&termination_jobs);
        Self::select_scheduled_candidate(&candidates) == Some(scheduled_job_index)
    }

    /// Check compatibility of a service request with running instances.
    ///
    /// Returns:
    /// - `Compatible(job_index)` if a matching service is running
    /// - `Available` if no instance is running
    /// - `Conflict { ... }` if a service is running with a different profile
    #[cfg(test)]
    pub fn check_service_compatibility(
        &self,
        base_task: BaseTaskIndex,
        requested_profile: &str,
        requested_params: &ValueMap,
    ) -> ServiceCompatibility {
        self.check_service_compatibility_in_plan(
            base_task,
            requested_profile,
            requested_params,
            &SchedulePlan::default(),
        )
    }

    /// Service compatibility against live state plus services already decided in
    /// `plan` (so two requirements on the same service across one submit share an
    /// instance instead of conflicting).
    fn check_service_compatibility_in_plan(
        &self,
        base_task: BaseTaskIndex,
        requested_profile: &str,
        requested_params: &ValueMap,
        plan: &SchedulePlan,
    ) -> ServiceCompatibility {
        let allow_multiple = self.base_tasks[base_task.idx()].config.allow_multiple;
        let requested_effective_profile = self.effective_profile_for_task(base_task, requested_profile);

        let planned_match = |pjob: &PlannedJob| {
            (requested_profile.is_empty() || pjob.profile == requested_effective_profile)
                && &pjob.params == requested_params
        };
        let planned_blocks = |pjob: &PlannedJob| match allow_multiple {
            AllowMultiple::True => false,
            AllowMultiple::False => true,
            AllowMultiple::DistinctProfiles => pjob.profile == requested_effective_profile,
            AllowMultiple::SingleProfile => pjob.profile != requested_effective_profile,
        };

        for &ji in self.base_tasks[base_task.idx()].jobs.non_terminal() {
            if plan.is_conflict_pending(ji) {
                continue;
            }
            if service_matches_require(&self.jobs[ji], requested_profile, requested_params) {
                return ServiceCompatibility::Compatible(JobRef::Live(ji));
            }
        }
        for (id, pjob) in plan.active_planned_jobs() {
            if pjob.base_task == base_task && planned_match(pjob) {
                return ServiceCompatibility::Compatible(JobRef::Planned(id));
            }
        }

        let mut blockers: Vec<JobRef> = Vec::new();
        for &ji in self.base_tasks[base_task.idx()].jobs.non_terminal() {
            if plan.is_conflict_pending(ji) {
                continue;
            }
            let blocks = match allow_multiple {
                AllowMultiple::True => false,
                AllowMultiple::False => true,
                AllowMultiple::DistinctProfiles => self.jobs[ji].spawn_profile() == requested_effective_profile,
                AllowMultiple::SingleProfile => self.jobs[ji].spawn_profile() != requested_effective_profile,
            };
            if blocks {
                blockers.push(JobRef::Live(ji));
            }
        }
        for (id, pjob) in plan.active_planned_jobs() {
            if pjob.base_task == base_task && planned_blocks(pjob) {
                blockers.push(JobRef::Planned(id));
            }
        }

        if !blockers.is_empty() {
            let running_profiles = blockers
                .iter()
                .map(|job_ref| match job_ref {
                    JobRef::Live(ji) => self.jobs[*ji].spawn_profile().to_string(),
                    JobRef::Planned(id) => plan.new_jobs[*id].profile.clone(),
                })
                .collect::<Vec<_>>();
            return ServiceCompatibility::Conflict {
                running_jobs: blockers,
                running_profiles,
                requested_profile: requested_effective_profile.to_string(),
            };
        }

        ServiceCompatibility::Available
    }

    /// Resolves a batch of requirements with deduplication.
    ///
    /// Takes a SpawnBatch and resolves all pending requirements, spawning each unique
    /// requirement at most once.
    fn resolve_batch_requirements<T>(
        &mut self,
        plan: &mut SchedulePlan,
        workspace_id: u32,
        channel: &MioChannel,
        batch: &mut SpawnBatch<T>,
    ) -> Result<(), String> {
        let reqs: Vec<_> = batch
            .pending_requirements_ordered()
            .map(|(key, req)| (key.clone(), req.base_task, req.profile.clone(), req.params.clone()))
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
                        let max_age = cache_config.max_age;
                        let persistent = cache_config.persistent;
                        // The spawned job stores its cache key under the *effective*
                        // profile (empty resolves to the first declared profile), so the
                        // expected key must resolve identically or a default-profile
                        // required action would never hit cache and re-run every time.
                        let effective_profile = self.effective_profile_for_task(base_task, &profile);
                        let expected_cache_key =
                            self.compute_cache_key_with_require(cache_config.key, &effective_profile, &params);
                        let spawner = &self.base_tasks[base_task.idx()];

                        for &ji in spawner.jobs.all().iter().rev() {
                            if plan.is_conflict_pending(ji) {
                                continue;
                            }
                            let job = &self.jobs[ji];
                            if matches!(job.process_status, JobStatus::Cancelled) {
                                continue;
                            }
                            if job.process_status.is_successful_completion() {
                                if Self::successful_job_satisfies_cache(job, &expected_cache_key, max_age) {
                                    resolved = Some(ResolvedRequirement::Cached);
                                    break;
                                }
                                continue;
                            }
                            if job.process_status.is_pending_completion()
                                && (expected_cache_key.is_empty() || job.cache_key == expected_cache_key)
                            {
                                resolved = Some(ResolvedRequirement::Pending(JobRef::Live(ji)));
                                break;
                            }
                        }
                        // An action decided earlier this same submit is pending too,
                        // so a group sharing a cached action across entries reuses it.
                        if resolved.is_none() {
                            for (id, pjob) in plan.active_planned_jobs() {
                                if pjob.base_task == base_task
                                    && (expected_cache_key.is_empty() || pjob.cache_key == expected_cache_key)
                                {
                                    resolved = Some(ResolvedRequirement::Pending(JobRef::Planned(id)));
                                    break;
                                }
                            }
                        }
                        if resolved.is_none()
                            && persistent
                            && self.persistent_cache_hit(base_task, &expected_cache_key, max_age)
                        {
                            resolved = Some(ResolvedRequirement::Cached);
                        }
                    }

                    if let Some(r) = resolved {
                        batch.mark_resolved(key, r);
                        continue;
                    }

                    let effective_profile = self.effective_profile_for_task(base_task, &profile);
                    let ready_barriers = self.action_output_ready_barriers(base_task, &effective_profile, plan);
                    let mut protected_conflict_jobs = self.action_jobs_protected_by_ready_barriers(
                        base_task,
                        &effective_profile,
                        &ready_barriers,
                        plan,
                    );
                    for job in self.conflicting_non_terminal_action_jobs(base_task, &effective_profile, plan) {
                        if !protected_conflict_jobs.contains(&job) {
                            protected_conflict_jobs.push(job);
                        }
                    }
                    let mut extra_requirements: Vec<PlannedReq> = ready_barriers
                        .into_iter()
                        .map(|target| PlannedReq::Task { target, predicate: JobPredicate::Ready })
                        .collect();
                    extra_requirements.extend(
                        protected_conflict_jobs
                            .iter()
                            .copied()
                            .map(|target| PlannedReq::Task { target, predicate: JobPredicate::Terminated }),
                    );

                    let new_job = self.spawn_task_with_extra_requirements_impl(
                        plan,
                        workspace_id,
                        channel,
                        base_task,
                        params,
                        &profile,
                        ScheduleReason::Dependency,
                        false,
                        false,
                        extra_requirements,
                        protected_conflict_jobs,
                    )?;
                    batch.mark_resolved(key, ResolvedRequirement::Spawned(new_job));
                }
                TaskKind::Service => {
                    let cache_never = dep_config.cache.as_ref().is_some_and(|c| c.never);

                    if !cache_never {
                        match self.check_service_compatibility_in_plan(base_task, &profile, &params, plan) {
                            ServiceCompatibility::Compatible(target) => {
                                batch.mark_resolved(key, ResolvedRequirement::Pending(target));
                                continue;
                            }
                            ServiceCompatibility::Conflict { running_jobs, running_profiles, requested_profile } => {
                                kvlog::warn!(
                                    "Service profile conflict, queuing",
                                    ?base_task,
                                    running_profiles = ?running_profiles,
                                    requested_profile,
                                );
                                let queued_job = self.schedule_queued_service(
                                    plan,
                                    workspace_id,
                                    channel,
                                    base_task,
                                    params,
                                    &profile,
                                    running_jobs,
                                )?;
                                batch.mark_resolved(key, ResolvedRequirement::Pending(queued_job));
                                continue;
                            }
                            ServiceCompatibility::Available => {}
                        }
                    }

                    let new_job = self.spawn_task_tracked(
                        plan,
                        workspace_id,
                        channel,
                        base_task,
                        params,
                        &profile,
                        ScheduleReason::Dependency,
                        false,
                        false,
                    )?;
                    batch.mark_resolved(key, ResolvedRequirement::Spawned(new_job));
                }
                TaskKind::Test => {
                    batch.mark_resolved(key, ResolvedRequirement::Cached);
                }
            }
        }
        Ok(())
    }

    fn run_test_batch(
        &mut self,
        matched_tests: Vec<MatchedTest>,
        run_id: u32,
        channel: &MioChannel,
        workspace_id: u32,
        force: bool,
    ) -> Result<TestRun, String> {
        struct TestRequirements {
            position: usize,
            base_task_idx: BaseTaskIndex,
            task_config: TaskConfigRc,
            spawn_profile: String,
            spawn_params: ValueMap<'static>,
            requirements: Vec<(RequirementKey, JobPredicate)>,
            resources: Vec<(ResourceIndex, i32)>,
        }

        enum TestJobSlot {
            Cached { base_task_idx: BaseTaskIndex },
            Ready { base_task_idx: BaseTaskIndex, job_ref: JobRef },
        }

        for matched in &matched_tests {
            self.detect_require_problems(matched.base_task_idx)?;
        }

        let mut batch: SpawnBatch<TestRequirements> = SpawnBatch::new();
        let mut test_jobs: Vec<Option<TestJobSlot>> = Vec::new();

        for matched in matched_tests {
            let position = test_jobs.len();
            test_jobs.push(None);

            let task_config = &matched.task_config;
            if !force
                && let Some(cache_config) = task_config.config().cache.as_ref()
                && !cache_config.never
            {
                let cache_key = self.compute_cache_key_with_require(
                    cache_config.key,
                    &matched.spawn_profile,
                    &matched.spawn_params,
                );
                if self.completed_cache_hit(
                    matched.base_task_idx,
                    &cache_key,
                    cache_config.max_age,
                    cache_config.persistent,
                ) {
                    test_jobs[position] = Some(TestJobSlot::Cached { base_task_idx: matched.base_task_idx });
                    continue;
                }
            }

            let mut requirements = Vec::new();
            let test_name = self.base_tasks[matched.base_task_idx.idx()].name.as_ref();
            self.validate_service_requirement_variants_for("Test", test_name, task_config.config().require)?;

            let mut resources: Vec<(ResourceIndex, i32)> = Vec::new();
            for req in task_config.config().require.iter() {
                match req {
                    crate::config::Requirement::Resource { name, priority } => {
                        let id = self.resources.intern(name);
                        resources.push((id, *priority));
                    }
                    crate::config::Requirement::Task(tc) => {
                        let dep_name = &*tc.name;
                        let dep_profile = tc.profile.unwrap_or("");
                        let dep_params = tc.vars.clone().to_owned();

                        let Some(dep_base_task) = self.lookup_name(dep_name) else {
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
                }
            }

            batch.add_task(TestRequirements {
                position,
                base_task_idx: matched.base_task_idx,
                task_config: task_config.clone(),
                spawn_profile: matched.spawn_profile,
                spawn_params: matched.spawn_params,
                requirements,
                resources,
            });
        }

        let mut plan = SchedulePlan::default();
        self.resolve_batch_requirements(&mut plan, workspace_id, channel, &mut batch)?;

        let tasks = batch.take_tasks();

        for task in tasks {
            let mut pred: Vec<PlannedReq> = Vec::new();

            for (key, predicate) in &task.task_data.requirements {
                match batch.get_resolved(key) {
                    Some(ResolvedRequirement::Cached) => {}
                    Some(ResolvedRequirement::Pending(target)) | Some(ResolvedRequirement::Spawned(target)) => {
                        pred.push(PlannedReq::Task { target: *target, predicate: predicate.clone() });
                    }
                    None => {}
                }
            }

            for (id, priority) in task.task_data.resources {
                pred.push(PlannedReq::Resource { id, priority });
            }

            let cache_key = self.compute_task_cache_key(
                &task.task_data.task_config,
                &task.task_data.spawn_profile,
                &task.task_data.spawn_params,
            );
            let job_ref = plan.push_job(PlannedJob {
                base_task: task.task_data.base_task_idx,
                task: task.task_data.task_config,
                profile: task.task_data.spawn_profile,
                params: task.task_data.spawn_params,
                cache_key,
                requirements: pred,
                action_deps_until_ready: Vec::new(),
                reason: ScheduleReason::TestRun,
                trace: false,
                synthetic_cached: false,
            });

            test_jobs[task.task_data.position] =
                Some(TestJobSlot::Ready { base_task_idx: task.task_data.base_task_idx, job_ref });
        }

        let slots: Vec<(BaseTaskIndex, Option<JobRef>, TestJobStatus)> = test_jobs
            .into_iter()
            .map(|slot| match slot.expect("test job slot should be filled") {
                TestJobSlot::Cached { base_task_idx } => (base_task_idx, None, TestJobStatus::Cached),
                TestJobSlot::Ready { base_task_idx, job_ref } => (base_task_idx, Some(job_ref), TestJobStatus::Pending),
            })
            .collect();

        let created = self.apply_plan(plan, workspace_id, channel);
        let test_jobs: Vec<TestJob> = slots
            .into_iter()
            .filter_map(|(base_task_index, job_ref, status)| {
                let job_index = match job_ref {
                    Some(job_ref) => {
                        let job_index = Self::resolve_job_ref(job_ref, &created);
                        if self.jobs.get(job_index).is_none() {
                            return None;
                        }
                        Some(job_index)
                    }
                    None => None,
                };
                Some(TestJob { base_task_index, job_index, status })
            })
            .collect();

        let test_run = TestRun { run_id, started_at: crate::clock::now(), test_jobs };
        self.active_test_run =
            Some(TestRun { run_id: test_run.run_id, started_at: test_run.started_at, test_jobs: Vec::new() });

        let group_id = self.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
        let group_entries: Vec<(BaseTaskIndex, JobIndex)> =
            test_run.test_jobs.iter().filter_map(|tj| tj.job_index.map(|ji| (tj.base_task_index, ji))).collect();
        if group_entries.is_empty() {
            self.last_test_group = None;
        } else {
            let base_tasks_in_group: Vec<BaseTaskIndex> = group_entries.iter().map(|(bti, _)| *bti).collect();
            let job_indices: Vec<JobIndex> = group_entries.iter().map(|(_, ji)| *ji).collect();
            self.last_test_group = Some(TestGroup { group_id, base_tasks: base_tasks_in_group, job_indices });
        }

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
    /// When true, the spawned process is traced via ptrace and an
    /// `InferredDeps` report is delivered to the run client at exit.
    /// Only set on the leaf task requested by the user — never on
    /// services or actions materialized by `require` chains.
    pub trace: bool,
}

pub struct SpawnSpec {
    pub tasks: Vec<TaskSpec>,
    pub test_group: bool,
}

impl SpawnSpec {
    pub fn task(name: &str, profile: &str, params: ValueMap<'static>, force_restart: bool) -> Self {
        SpawnSpec {
            tasks: vec![TaskSpec { name: name.into(), profile: profile.into(), params, force_restart, trace: false }],
            test_group: false,
        }
    }
}

pub struct SubmitResult {
    pub jobs: Vec<(BaseTaskIndex, JobIndex)>,
    pub group_names: Vec<String>,
}

struct SpawnPlanEntry {
    group_name: Option<String>,
    task: TaskSpec,
}

impl Workspace {
    fn spawn_plan_transactional(
        &self,
        state: &mut WorkspaceState,
        entries: Vec<SpawnPlanEntry>,
        start: bool,
    ) -> Result<(Vec<(BaseTaskIndex, JobIndex)>, hashbrown::HashMap<String, Vec<JobIndex>>), String> {
        for entry in &entries {
            let Some(base_index) = state.base_index_by_name(&entry.task.name) else {
                return Err(format!("Task '{}' not found", entry.task.name));
            };
            state.detect_require_problems(base_index)?;
        }

        let mut sched = SchedulePlan::default();
        let mut job_refs: Vec<(BaseTaskIndex, JobRef)> = Vec::new();
        let mut group_refs: Vec<(String, JobRef)> = Vec::new();

        // Build the whole submit by reading state only. Any failure returns here
        // with nothing applied, so no rollback is needed.
        for entry in entries {
            let task = entry.task;
            let Some(base_index) = state.base_index_by_name(&task.name) else {
                return Err(format!("Task '{}' not found", task.name));
            };

            let job_ref = if start {
                let profile = state.effective_profile_for_task(base_index, &task.profile);
                let params = task.params.to_owned();
                match state.active_matching_job_in_plan(base_index, &profile, &params, &sched) {
                    Some(existing) => existing,
                    None => state.spawn_task_with_extra_requirements_impl(
                        &mut sched,
                        self.workspace_id,
                        &self.process_channel,
                        base_index,
                        params,
                        &profile,
                        ScheduleReason::Requested,
                        false,
                        task.trace,
                        Vec::new(),
                        Vec::new(),
                    )?,
                }
            } else {
                state.spawn_task_with_extra_requirements_impl(
                    &mut sched,
                    self.workspace_id,
                    &self.process_channel,
                    base_index,
                    task.params,
                    &task.profile,
                    ScheduleReason::Requested,
                    task.force_restart,
                    task.trace,
                    Vec::new(),
                    Vec::new(),
                )?
            };
            if let Some(group_name) = entry.group_name {
                group_refs.push((group_name, job_ref));
            }
            job_refs.push((base_index, job_ref));
        }

        let created = state.apply_plan(sched, self.workspace_id, &self.process_channel);

        let jobs: Vec<(BaseTaskIndex, JobIndex)> = job_refs
            .into_iter()
            .filter_map(|(bti, r)| WorkspaceState::resolve_live_job_ref(r, &created, state).map(|ji| (bti, ji)))
            .collect();
        let mut group_job_indices: hashbrown::HashMap<String, Vec<JobIndex>> = hashbrown::HashMap::new();
        for (name, r) in group_refs {
            if let Some(ji) = WorkspaceState::resolve_live_job_ref(r, &created, state) {
                group_job_indices.entry(name).or_default().push(ji);
            }
        }
        Ok((jobs, group_job_indices))
    }

    fn submit_impl(&self, spec: SpawnSpec, start: bool) -> Result<SubmitResult, String> {
        let state = &mut *self.state.write().unwrap();
        state.refresh_config();
        state.change_number = state.change_number.wrapping_add(1);

        let mut plan = Vec::new();
        let mut group_names = Vec::new();
        for task in spec.tasks {
            let explicit_group = WorkspaceState::is_explicit_group_reference(&task.name);
            if !explicit_group && state.base_index_by_name(&task.name).is_some() {
                plan.push(SpawnPlanEntry { group_name: None, task });
                continue;
            }

            let Some((group_name, group_tasks)) = state.group_task_specs(&task.name, task.force_restart) else {
                if explicit_group {
                    let short = task.name.split_once('.').map_or(task.name.as_str(), |(_, rest)| rest);
                    return Err(format!("Group '{}' not found", short));
                }
                return Err(format!("Task '{}' not found", task.name));
            };

            if !task.profile.is_empty() || !task.params.entries().is_empty() {
                return Err(format!("Group '{}' does not support profiles or parameters", group_name));
            }

            if !group_names.contains(&group_name) {
                group_names.push(group_name.clone());
            }
            for group_task in group_tasks {
                plan.push(SpawnPlanEntry { group_name: Some(group_name.clone()), task: group_task });
            }
        }

        let (jobs, group_job_indices) = self.spawn_plan_transactional(state, plan, start)?;

        for group_name in &group_names {
            if let Some(job_indices) = group_job_indices.get(group_name) {
                state.record_group_jobs(group_name, job_indices);
            }
        }

        if spec.test_group && !jobs.is_empty() {
            let group_id = state.last_test_group.as_ref().map_or(0, |g| g.group_id + 1);
            state.last_test_group = Some(TestGroup {
                group_id,
                base_tasks: jobs.iter().map(|(bti, _)| *bti).collect(),
                job_indices: jobs.iter().map(|(_, ji)| *ji).collect(),
            });
        }

        Ok(SubmitResult { jobs, group_names })
    }

    pub fn submit(&self, spec: SpawnSpec) -> Result<SubmitResult, String> {
        self.submit_impl(spec, false)
    }

    pub fn submit_start(&self, spec: SpawnSpec) -> Result<SubmitResult, String> {
        self.submit_impl(spec, true)
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
                let plan = tasks
                    .iter()
                    .map(|task_call| SpawnPlanEntry {
                        group_name: None,
                        task: TaskSpec {
                            name: task_call.name.to_string(),
                            profile: task_call.profile.unwrap_or("").to_string(),
                            params: task_call.vars.clone().to_owned(),
                            force_restart: false,
                            trace: false,
                        },
                    })
                    .collect();
                self.spawn_plan_transactional(state, plan, false)?;
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

        state.run_test_batch(matched_tests, run_id, &self.process_channel, self.workspace_id, false)
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
        force_restart: bool,
    ) -> Result<Option<String>, String> {
        self.refresh_config_if_changed();
        {
            let state = self.state.read().unwrap();
            let resolves_as_group = WorkspaceState::is_explicit_group_reference(name)
                || (state.lookup_name(name).is_none() && state.lookup_group_name(name).is_some());
            if resolves_as_group {
                if !profile.is_empty() || !params.entries().is_empty() {
                    let group_name = state.lookup_group_name(name).unwrap_or_else(|| name.to_string());
                    return Err(format!("Group '{}' does not support profiles or parameters", group_name));
                }
                drop(state);
                self.submit(SpawnSpec::task(name, "", ValueMap::new(), force_restart))?;
                return Ok(None);
            }
        }

        if cached {
            // Phase 1: Gather info needed for cache key computation (hold lock briefly)
            let (cache_info, profile) = {
                let state = self.state.read().unwrap();
                let Some(base_index) = state.lookup_name(name) else {
                    return Err(format!("Task '{}' not found", name));
                };
                state.detect_require_problems(base_index)?;
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
                        force_restart,
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
                        force_restart,
                    )?;
                    return Ok(None);
                };

                let base_path = state.config.current.base_path().to_path_buf();
                let cache_key_inputs: Vec<_> = cache_config
                    .key
                    .iter()
                    .map(|input| match input {
                        CacheKeyInput::Modified { paths, ignore } => CacheKeyInfoItem::Modified {
                            paths: paths
                                .iter()
                                .flat_map(|p| {
                                    expand_modified_path(p).into_iter().map(|expanded| base_path.join(expanded))
                                })
                                .collect(),
                            ignore,
                        },
                        CacheKeyInput::ProfileChanged(task_name) => {
                            let counter = state
                                .lookup_name(task_name)
                                .map_or(0, |bti| state.base_tasks[bti.idx()].profile_change_counter);
                            CacheKeyInfoItem::ProfileChanged { task_name: task_name.to_string(), counter }
                        }
                    })
                    .collect();

                (
                    CacheKeyInfo {
                        base_index,
                        cache_key_inputs,
                        persistent: cache_config.persistent,
                        max_age: cache_config.max_age,
                    },
                    profile,
                )
            };
            // Lock released here

            // Phase 2: Compute cache key (filesystem I/O, no lock held)
            let expected_cache_key = compute_cache_key_standalone(&cache_info.cache_key_inputs, profile, &params);

            // Phase 3: Check for cache hit and spawn if needed (re-acquire lock)
            let state = &mut *self.state.write().unwrap();
            if let Some(msg) = state.check_cache_hit_with_key(
                name,
                cache_info.base_index,
                &expected_cache_key,
                cache_info.max_age,
                cache_info.persistent,
            ) {
                return Ok(Some(msg));
            }

            let (_, _job_index) = state.lookup_and_spawn_task(
                self.workspace_id,
                &self.process_channel,
                name,
                params,
                profile,
                force_restart,
            )?;
            Ok(None)
        } else {
            let state = &mut *self.state.write().unwrap();
            state.refresh_config();
            let (_, _job_index) = state.lookup_and_spawn_task(
                self.workspace_id,
                &self.process_channel,
                name,
                params,
                profile,
                force_restart,
            )?;
            Ok(None)
        }
    }

    pub fn start_task_by_name_cached(
        &self,
        name: &str,
        params: ValueMap,
        profile: &str,
        cached: bool,
    ) -> Result<Option<String>, String> {
        self.refresh_config_if_changed();
        {
            let state = self.state.read().unwrap();
            let resolves_as_group = WorkspaceState::is_explicit_group_reference(name)
                || (state.lookup_name(name).is_none() && state.lookup_group_name(name).is_some());
            if resolves_as_group {
                if !profile.is_empty() || !params.entries().is_empty() {
                    let group_name = state.lookup_group_name(name).unwrap_or_else(|| name.to_string());
                    return Err(format!("Group '{}' does not support profiles or parameters", group_name));
                }
                drop(state);
                self.submit_start(SpawnSpec::task(name, "", ValueMap::new(), false))?;
                return Ok(None);
            }

            let Some(base_index) = state.lookup_name(name) else {
                return Err(format!("Task '{}' not found", name));
            };
            state.detect_require_problems(base_index)?;
            let profile = state.effective_profile_for_task(base_index, profile);
            let active_params = params.clone().to_owned();
            if state.active_matching_job(base_index, &profile, &active_params).is_some() {
                return Ok(None);
            }
        }

        if cached {
            self.spawn_task_by_name_cached(name, params, profile, true, false)
        } else {
            let state = &mut *self.state.write().unwrap();
            state.refresh_config();
            let (_, _) = state.lookup_and_start_task_with_trace(
                self.workspace_id,
                &self.process_channel,
                name,
                params,
                profile,
                false,
            )?;
            Ok(None)
        }
    }

    /// Layer 1: Terminate task by name.
    ///
    /// Acquires state lock, looks up task, and terminates all running instances.
    pub fn terminate_task_by_name(&self, name: &str) -> Result<String, String> {
        let state = &mut *self.state.write().unwrap();
        state.refresh_config();
        if WorkspaceState::is_explicit_group_reference(name)
            || (state.lookup_name(name).is_none() && state.lookup_group_name(name).is_some())
        {
            return state.lookup_and_terminate_group(&self.process_channel, name);
        }
        state.lookup_and_terminate_task(&self.process_channel, name)
    }

    pub fn start_test_run(&self, filters: &[TestFilter], force: bool) -> Result<TestRun, String> {
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

        state.run_test_batch(matched_tests, run_id, &self.process_channel, self.workspace_id, force)
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
    pub cached: u32,
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

    mod requirement_status_tests {
        use super::*;

        fn manifest_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        fn fixture() -> (WorkspaceState, BaseTaskIndex, Arc<ResolvedSpawnSpec>) {
            let mut state =
                WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).expect("load test config");
            let base_task = state.lookup_name("simple_cmd").unwrap();
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task = config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars })
                .expect("eval task");
            let spec = state.cache_spawn_spec(base_task, "", ValueMap::new(), task);
            (state, base_task, spec)
        }

        fn status_for(predicate: JobPredicate, process_status: JobStatus) -> RequirementStatus {
            let (mut state, base_task, spec) = fixture();
            let ji = state.jobs.insert(Job {
                process_status,
                log_group: LogGroup::new(base_task, 0),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            ScheduleRequirement::Task { job: ji, predicate }.status(&state)
        }

        #[test]
        fn ready_predicate_is_met_when_service_is_ready_or_terminal() {
            assert!(matches!(
                status_for(JobPredicate::Ready, JobStatus::Running { process_index: 0, ready_state: None }),
                RequirementStatus::Met
            ));
            assert!(matches!(
                status_for(JobPredicate::Ready, JobStatus::Running { process_index: 0, ready_state: Some(true) }),
                RequirementStatus::Met
            ));
            assert!(matches!(
                status_for(
                    JobPredicate::Ready,
                    JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status: 1 },
                ),
                RequirementStatus::Met
            ));
            assert!(matches!(status_for(JobPredicate::Ready, JobStatus::Cancelled), RequirementStatus::Met));
        }

        #[test]
        fn ready_predicate_waits_while_service_may_still_need_action_output() {
            assert!(matches!(
                status_for(JobPredicate::Ready, JobStatus::Scheduled { after: Vec::new() }),
                RequirementStatus::Pending
            ));
            assert!(matches!(status_for(JobPredicate::Ready, JobStatus::Starting), RequirementStatus::Pending));
            assert!(matches!(
                status_for(JobPredicate::Ready, JobStatus::Running { process_index: 0, ready_state: Some(false) }),
                RequirementStatus::Pending
            ));
        }

        #[test]
        fn active_predicate_still_fails_for_terminal_service() {
            assert!(matches!(
                status_for(
                    JobPredicate::Active,
                    JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status: 0 },
                ),
                RequirementStatus::Never
            ));
            assert!(matches!(status_for(JobPredicate::Active, JobStatus::Cancelled), RequirementStatus::Never));
        }
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
            let base_task = state.lookup_name("simple_cmd").unwrap();
            let failing_task = state.lookup_name("with_var").unwrap();

            let config = state.base_tasks[base_task.idx()].config.clone();
            let task = config.eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars }).unwrap();
            let cached = state.cache_spawn_spec(base_task, "", ValueMap::new(), task);

            state.base_tasks[base_task.idx()].config = state.base_tasks[failing_task.idx()].config.clone();

            let reused = state.get_or_create_spawn_spec(base_task, "", ValueMap::new()).unwrap();
            assert!(Arc::ptr_eq(&cached, &reused));
        }

        // A task whose evaluation fails (here `with_pwd_var` has a scalar
        // `pwd = { var = "workdir" }` with no default and no param) must surface
        // an error rather than panic: `get_or_create_spawn_spec` runs under
        // `state.write()`, and a panic would poison the lock and brick the
        // daemon for all clients.
        #[test]
        fn get_or_create_spawn_spec_propagates_eval_error_without_panicking() {
            let mut state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let failing = state.lookup_name("with_pwd_var").unwrap();
            let result = state.get_or_create_spawn_spec(failing, "", ValueMap::new());
            assert!(result.is_err(), "expected eval error to propagate, got Ok");
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

            batch.mark_resolved(key.clone(), ResolvedRequirement::Spawned(JobRef::Live(JobIndex::from_usize(5))));

            match batch.get_resolved(&key) {
                Some(ResolvedRequirement::Spawned(JobRef::Live(ji))) => assert_eq!(ji.idx(), 5),
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
            let existing_job = JobRef::Live(JobIndex::from_usize(3));

            batch.mark_resolved(key.clone(), ResolvedRequirement::Pending(existing_job));

            match batch.get_resolved(&key) {
                Some(ResolvedRequirement::Pending(JobRef::Live(ji))) => assert_eq!(ji.idx(), 3),
                _ => panic!("Expected Pending resolution"),
            }
        }

        #[test]
        fn pending_requirements_iterator() {
            let mut batch: SpawnBatch<()> = SpawnBatch::new();

            batch.add_requirement(BaseTaskIndex(0), "a", ValueMap::new().to_owned(), JobPredicate::Active);
            batch.add_requirement(BaseTaskIndex(1), "b", ValueMap::new().to_owned(), JobPredicate::Terminated);

            let reqs: Vec<_> = batch.pending_requirements().collect();
            let observed: Vec<_> = reqs
                .into_iter()
                .map(|(key, req)| (key.base_task, key.profile.as_str(), req.base_task, req.profile.as_str()))
                .collect();
            assert_eq!(
                observed,
                vec![(BaseTaskIndex(0), "a", BaseTaskIndex(0), "a"), (BaseTaskIndex(1), "b", BaseTaskIndex(1), "b"),]
            );
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

    mod service_requirement_validation_tests {
        use super::*;
        use std::fs;

        fn temp_manifest(name: &str, content: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "devsm-workspace-test-{}-{}-{}",
                name,
                std::process::id(),
                crate::clock::now().elapsed().as_nanos()
            ));
            fs::create_dir_all(&path).expect("create temp workspace");
            let manifest = path.join("devsm.toml");
            fs::write(&manifest, content).expect("write temp manifest");
            manifest
        }

        #[test]
        fn direct_service_plus_action_transitive_service_conflict_is_rejected() {
            let manifest = temp_manifest(
                "direct-service-action-transitive-conflict",
                r#"
[service.svc]
cmd = ["true"]
profiles = ["alpha", "beta"]
allow_multiple = false

[action.child]
cmd = ["true"]
require = ["svc:beta"]

[action.parent]
cmd = ["true"]
require = ["svc:alpha", "child"]
"#,
            );
            let state = WorkspaceState::new(manifest).expect("load test config");
            let parent = state.lookup_name("parent").expect("parent task");
            let config = state.base_tasks[parent.idx()].config.clone();
            let task = config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars })
                .expect("eval parent");

            let err = state
                .validate_service_requirement_variants(parent, &task)
                .expect_err("parent must reject service held while action needs incompatible service");
            assert!(err.contains("conflicting service requirements"), "unexpected error: {err}");
        }

        #[test]
        fn service_requirement_validation_is_bounded_on_shared_action_dag() {
            const DEPTH: usize = 20;

            let mut config = String::from(
                r#"
[service.held]
cmd = ["true"]

[action.root]
cmd = ["true"]
require = ["held", "a0"]
"#,
            );
            for i in 0..DEPTH {
                config.push_str(&format!(
                    r#"
[action.a{i}]
cmd = ["true"]
require = ["b{i}", "c{i}"]

[action.b{i}]
cmd = ["true"]
require = ["a{}"]

[action.c{i}]
cmd = ["true"]
require = ["a{}"]
"#,
                    i + 1,
                    i + 1
                ));
            }
            config.push_str(&format!(
                r#"
[action.a{DEPTH}]
cmd = ["true"]
"#
            ));

            let manifest = temp_manifest("shared-action-dag", &config);
            let state = WorkspaceState::new(manifest).expect("load test config");
            let root = state.lookup_name("root").expect("root task");
            let root_config = state.base_tasks[root.idx()].config.clone();
            let task = root_config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: root_config.vars })
                .expect("eval root");

            let started = Instant::now();
            state.validate_service_requirement_variants(root, &task).expect("valid shared DAG");
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(500),
                "service requirement validation must stay bounded on shared DAGs, elapsed {elapsed:?}"
            );
        }

        fn validate_root(manifest: PathBuf, root_name: &str) -> Result<(), String> {
            let state = WorkspaceState::new(manifest).expect("load test config");
            let root = state.lookup_name(root_name).expect("root task");
            let config = state.base_tasks[root.idx()].config.clone();
            let task = config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars })
                .expect("eval root");
            state.validate_service_requirement_variants(root, &task)
        }

        #[test]
        fn conflicting_variants_in_sibling_action_branches_are_accepted() {
            // svc:alpha is held only over `left`, svc:beta only over `right`; the two
            // are never co-held on a single path, so this must NOT be rejected. A naive
            // "union held-sets at the shared `sink`" check would wrongly reject it.
            let manifest = temp_manifest(
                "sibling-branch-services",
                r#"
[service.svc]
cmd = ["true"]
profiles = ["alpha", "beta"]
allow_multiple = false

[action.left]
cmd = ["true"]
require = ["svc:alpha", "sink"]

[action.right]
cmd = ["true"]
require = ["svc:beta", "sink"]

[action.sink]
cmd = ["true"]

[action.root]
cmd = ["true"]
require = ["left", "right"]
"#,
            );
            validate_root(manifest, "root").expect("sibling-branch conflicting variants must be accepted");
        }

        #[test]
        fn conflicting_variants_through_service_closure_are_rejected() {
            // svc:alpha (held directly) and svc:beta (held transitively through svc's
            // own service requirement) are co-held, so this must be rejected.
            let manifest = temp_manifest(
                "service-closure-conflict",
                r#"
[service.leaf]
cmd = ["true"]
profiles = ["alpha", "beta"]
allow_multiple = false

[service.mid]
cmd = ["true"]
require = ["leaf:beta"]

[action.root]
cmd = ["true"]
require = ["leaf:alpha", "mid"]
"#,
            );
            let err =
                validate_root(manifest, "root").expect_err("service-closure conflicting variants must be rejected");
            assert!(err.contains("conflicting service requirements"), "unexpected error: {err}");
        }

        #[test]
        fn cyclic_service_requirements_terminate() {
            let manifest = temp_manifest(
                "cyclic-service-requirements",
                r#"
[service.a]
cmd = ["true"]
require = ["b"]

[service.b]
cmd = ["true"]
require = ["a"]

[action.root]
cmd = ["true"]
require = ["a"]
"#,
            );
            validate_root(manifest, "root").expect("cyclic service requirements must terminate and validate");
        }

        #[test]
        fn distinct_service_per_branch_dag_stays_bounded() {
            const DEPTH: usize = 30;

            let mut config = String::from(
                r#"
[action.root]
cmd = ["true"]
require = ["a0"]
"#,
            );
            for i in 0..DEPTH {
                config.push_str(&format!(
                    r#"
[service.sb{i}]
cmd = ["true"]

[service.sc{i}]
cmd = ["true"]

[action.a{i}]
cmd = ["true"]
require = ["b{i}", "c{i}"]

[action.b{i}]
cmd = ["true"]
require = ["sb{i}", "a{next}"]

[action.c{i}]
cmd = ["true"]
require = ["sc{i}", "a{next}"]
"#,
                    next = i + 1
                ));
            }
            config.push_str(&format!("\n[action.a{DEPTH}]\ncmd = [\"true\"]\n"));

            let manifest = temp_manifest("distinct-service-per-branch", &config);
            let started = Instant::now();
            validate_root(manifest, "root").expect("distinct-service-per-branch DAG must validate");
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(250),
                "validation must stay polynomial on distinct-service-per-branch DAGs, elapsed {elapsed:?}"
            );
        }

        #[test]
        fn wide_conflicting_sibling_services_stays_bounded() {
            const WIDTH: usize = 260;
            const SINK_DEPTH: usize = 260;

            let mut config = String::from(
                r#"
[service.svc]
cmd = ["true"]
allow_multiple = "distinct_profiles"

[action.root]
cmd = ["true"]
require = [
"#,
            );
            for i in 0..WIDTH {
                config.push_str(&format!("  \"a{i}\",\n"));
            }
            config.push_str("]\n");

            for i in 0..WIDTH {
                config.push_str(&format!(
                    r#"
[action.a{i}]
cmd = ["true"]
require = [["svc", {{ id = "{i}" }}], "sink0"]
"#
                ));
            }

            for i in 0..SINK_DEPTH {
                config.push_str(&format!(
                    r#"
[action.sink{i}]
cmd = ["true"]
require = ["sink{next}"]
"#,
                    next = i + 1
                ));
            }
            config.push_str(&format!("\n[action.sink{SINK_DEPTH}]\ncmd = [\"true\"]\n"));

            let manifest = temp_manifest("wide-conflicting-sibling-services", &config);
            let started = Instant::now();
            validate_root(manifest, "root").expect("sibling service variants should be sequenceable");
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(250),
                "validation must not repeat graph searches for every service pair, elapsed {elapsed:?}"
            );
        }
    }

    mod service_compatibility_tests {
        use super::*;
        use jsony_value::ValueMap;

        fn manifest_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        fn params(json: &str) -> ValueMap<'static> {
            jsony::from_json::<ValueMap>(json).expect("valid params").to_owned()
        }

        fn insert_running_service(
            state: &mut WorkspaceState,
            base_task: BaseTaskIndex,
            profile: &str,
            params: ValueMap<'static>,
        ) -> JobIndex {
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task =
                config.eval(&Environment { profile, param: params.clone(), vars: config.vars }).expect("eval service");
            let spec = state.cache_spawn_spec(base_task, profile, params, task);
            let pc = state.base_tasks[base_task.idx()].spawn_counter as usize;
            state.base_tasks[base_task.idx()].spawn_counter =
                state.base_tasks[base_task.idx()].spawn_counter.wrapping_add(1);
            let ji = state.jobs.insert(Job {
                process_status: JobStatus::Running { process_index: pc, ready_state: None },
                log_group: LogGroup::new(base_task, pc),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            state.base_tasks[base_task.idx()].jobs.push_active(ji);
            state.service_jobs.push_active(ji);
            ji
        }

        fn insert_scheduled_service(
            state: &mut WorkspaceState,
            base_task: BaseTaskIndex,
            profile: &str,
            params: ValueMap<'static>,
        ) -> JobIndex {
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task =
                config.eval(&Environment { profile, param: params.clone(), vars: config.vars }).expect("eval service");
            let spec = state.cache_spawn_spec(base_task, profile, params, task);
            let pc = state.base_tasks[base_task.idx()].spawn_counter as usize;
            state.base_tasks[base_task.idx()].spawn_counter =
                state.base_tasks[base_task.idx()].spawn_counter.wrapping_add(1);
            let ji = state.jobs.insert(Job {
                process_status: JobStatus::Scheduled { after: Vec::new() },
                log_group: LogGroup::new(base_task, pc),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            state.base_tasks[base_task.idx()].jobs.push_scheduled(ji);
            state.service_jobs.push_scheduled(ji);
            ji
        }

        #[test]
        fn service_compatibility_enum_variants() {
            let compatible = ServiceCompatibility::Compatible(JobRef::Live(JobIndex::from_usize(0)));
            let available = ServiceCompatibility::Available;
            let conflict = ServiceCompatibility::Conflict {
                running_jobs: vec![JobRef::Live(JobIndex::from_usize(1))],
                running_profiles: vec!["prod".to_string()],
                requested_profile: "test".to_string(),
            };

            match compatible {
                ServiceCompatibility::Compatible(JobRef::Live(ji)) => assert_eq!(ji.idx(), 0),
                _ => panic!("Expected Compatible"),
            }

            match available {
                ServiceCompatibility::Available => {}
                _ => panic!("Expected Available"),
            }

            match conflict {
                ServiceCompatibility::Conflict { running_jobs, running_profiles, requested_profile } => {
                    assert_eq!(running_jobs, vec![JobRef::Live(JobIndex::from_usize(1))]);
                    assert_eq!(running_profiles, vec!["prod".to_string()]);
                    assert_eq!(requested_profile, "test");
                }
                _ => panic!("Expected Conflict"),
            }
        }

        #[test]
        fn distinct_profiles_conflicts_with_same_profile_different_params() {
            let mut state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let base_task = state.lookup_name("multi_profile_service").unwrap();
            let running = insert_running_service(&mut state, base_task, "dev", params(r#"{"id":"one"}"#));

            match state.check_service_compatibility(base_task, "dev", &params(r#"{"id":"two"}"#)) {
                ServiceCompatibility::Conflict { running_jobs, .. } => {
                    assert_eq!(running_jobs, vec![JobRef::Live(running)])
                }
                ServiceCompatibility::Available => panic!("same-profile distinct_profiles request must conflict"),
                ServiceCompatibility::Compatible(_) => panic!("different params must not reuse the running service"),
            }
        }

        #[test]
        fn empty_profile_request_uses_default_profile_for_conflicts() {
            let mut state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let base_task = state.lookup_name("multi_profile_service").unwrap();
            let running = insert_running_service(&mut state, base_task, "dev", params(r#"{"id":"one"}"#));

            match state.check_service_compatibility(base_task, "", &params(r#"{"id":"two"}"#)) {
                ServiceCompatibility::Conflict { running_jobs, .. } => {
                    assert_eq!(running_jobs, vec![JobRef::Live(running)])
                }
                ServiceCompatibility::Available => panic!("default-profile request must conflict with same profile"),
                ServiceCompatibility::Compatible(_) => panic!("different params must not reuse the running service"),
            }
        }

        #[test]
        fn empty_profile_request_matches_non_default_running_service() {
            let mut state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let base_task = state.lookup_name("service_conditional_cmd").unwrap();
            let running = insert_running_service(&mut state, base_task, "watch", ValueMap::new());

            match state.check_service_compatibility(base_task, "", &ValueMap::new()) {
                ServiceCompatibility::Compatible(JobRef::Live(ji)) => assert_eq!(ji, running),
                ServiceCompatibility::Available => panic!("bare-profile request must reuse matching running service"),
                ServiceCompatibility::Conflict { running_jobs, .. } => {
                    panic!("bare-profile request must not conflict with matching running service: {running_jobs:?}")
                }
                ServiceCompatibility::Compatible(JobRef::Planned(id)) => panic!("expected live job, got planned {id}"),
            }
        }

        #[test]
        fn empty_profile_request_matches_non_default_planned_service() {
            let state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let base_task = state.lookup_name("service_conditional_cmd").unwrap();
            let config = state.base_tasks[base_task.idx()].config.clone();
            let params = ValueMap::new();
            let task = config
                .eval(&Environment { profile: "watch", param: params.clone(), vars: config.vars })
                .expect("eval service");
            let mut plan = SchedulePlan::default();
            let planned = plan.push_job(PlannedJob {
                base_task,
                task,
                profile: "watch".to_string(),
                params,
                cache_key: String::new(),
                requirements: Vec::new(),
                action_deps_until_ready: Vec::new(),
                reason: ScheduleReason::Dependency,
                trace: false,
                synthetic_cached: false,
            });

            match state.check_service_compatibility_in_plan(base_task, "", &ValueMap::new(), &plan) {
                ServiceCompatibility::Compatible(job_ref) => assert_eq!(job_ref, planned),
                ServiceCompatibility::Available => panic!("bare-profile request must reuse matching planned service"),
                ServiceCompatibility::Conflict { running_jobs, .. } => {
                    panic!("bare-profile request must not conflict with matching planned service: {running_jobs:?}")
                }
            }
        }

        #[test]
        fn transaction_service_compatibility_ignores_pending_termination() {
            let mut state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let base_task = state.lookup_name("simple_service").unwrap();
            let running = insert_running_service(&mut state, base_task, "", ValueMap::new());
            let job = &state.jobs[running];
            let JobStatus::Running { process_index, .. } = job.process_status else {
                panic!("expected running service");
            };

            let mut plan = SchedulePlan::default();
            plan.record_terminate_running(TerminatePlan {
                job: running,
                job_id: job.log_group,
                process_index,
                exit_cause: ExitCause::Restarted,
            });

            match state.check_service_compatibility_in_plan(base_task, "", &ValueMap::new(), &plan) {
                ServiceCompatibility::Available => {}
                ServiceCompatibility::Compatible(ji) => {
                    panic!("service pending termination must not satisfy a new requirement: {ji:?}")
                }
                ServiceCompatibility::Conflict { running_jobs, .. } => {
                    panic!("service pending termination must not block a new requirement: {running_jobs:?}")
                }
            }
        }

        #[test]
        fn plan_conflicts_skips_already_planned_jobs() {
            let mut state = WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).unwrap();
            let base_task = state.lookup_name("simple_service").unwrap();
            let scheduled = insert_scheduled_service(&mut state, base_task, "", ValueMap::new());
            let running = insert_running_service(&mut state, base_task, "", ValueMap::new());

            let mut plan = SchedulePlan::default();
            let first = state.plan_conflicts(&plan, base_task, "", false, &[]);
            assert_eq!(first.cancel_scheduled, vec![scheduled]);
            assert_eq!(first.terminate_running.iter().map(|t| t.job).collect::<Vec<_>>(), vec![running]);
            first.record_into(&mut plan);

            let second = state.plan_conflicts(&plan, base_task, "", false, &[]);
            assert_eq!(second.predicates.len(), 1, "already planned running jobs must still block new jobs");
            match &second.predicates[0] {
                PlannedReq::Task { target: JobRef::Live(job), predicate: JobPredicate::Terminated } => {
                    assert_eq!(*job, running)
                }
                _ => panic!("expected terminated predicate for already planned running job"),
            }
            assert!(
                second.cancel_scheduled.is_empty(),
                "already planned scheduled cancellations must not be duplicated"
            );
            assert!(second.terminate_running.is_empty(), "already planned running terminations must not be duplicated");
        }
    }

    mod job_history_tests {
        use super::*;
        use crate::log_storage::LogWriter;
        use std::fs;

        fn manifest_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        fn temp_manifest(name: &str, content: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "devsm-workspace-test-{}-{}-{}",
                name,
                std::process::id(),
                crate::clock::now().elapsed().as_nanos()
            ));
            fs::create_dir_all(&path).expect("create temp workspace");
            let manifest = path.join("devsm.toml");
            fs::write(&manifest, content).expect("write temp manifest");
            manifest
        }

        fn test_channel() -> Arc<MioChannel> {
            let poll = Box::leak(Box::new(mio::Poll::new().expect("poll")));
            let waker = Box::leak(Box::new(mio::Waker::new(poll.registry(), mio::Token(0)).expect("waker")));
            Arc::new(MioChannel { waker, events: std::sync::Mutex::new(Vec::new()) })
        }

        /// Build a workspace state loaded from the big example config,
        /// drop the configured history cap to `max`, and return a spawn spec
        /// bound to the first non-synthetic base task so tests can mint jobs
        /// without a MioChannel.
        fn fixture(max: u32) -> (WorkspaceState, BaseTaskIndex, Arc<ResolvedSpawnSpec>) {
            let mut state =
                WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).expect("load test config");
            state.max_job_history = max;
            let base_task = state.lookup_name("simple_cmd").unwrap();
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
                cache_synthetic: false,
                spawn: spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
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
                    after: vec![ScheduleRequirement::Task {
                        job: a,
                        predicate: JobPredicate::TerminatedNaturallyAndSuccessfully,
                    }],
                },
                log_group: LogGroup::new(base_task, 999),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: spec.clone(),
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
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
        fn eviction_preserves_action_outputs_used_until_service_ready() {
            let max = 128;
            let (mut state, base_task, spec) = fixture(max);

            let action_dep = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, action_dep, 0);

            let service_task = state.lookup_name("simple_service").unwrap();
            let service_config = state.base_tasks[service_task.idx()].config.clone();
            let task = service_config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: service_config.vars })
                .expect("eval service");
            let service_spec = state.cache_spawn_spec(service_task, "", ValueMap::new(), task);
            let service_job = state.jobs.insert(Job {
                process_status: JobStatus::Running { process_index: 0, ready_state: Some(false) },
                log_group: LogGroup::new(service_task, 0),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: service_spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: smallvec::smallvec![action_dep],
                trace: false,
                trace_report: None,
            });
            state.base_tasks[service_task.idx()].jobs.push_active(service_job);
            state.service_jobs.push_active(service_job);

            for _ in 0..(max as usize * 3) {
                let ji = insert_job(&mut state, base_task, spec.clone());
                exit(&mut state, ji, 0);
            }

            assert!(
                state.jobs.get(action_dep).is_some(),
                "terminal action output must survive while a not-ready service still uses it"
            );
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

        #[test]
        fn cancel_scheduled_jobs_respects_history_cap() {
            // `plan_conflicts` previously cancelled scheduled jobs by directly
            // assigning `JobStatus::Cancelled`, sidestepping the canonical
            // transition path. That left history pruning out of the loop, so
            // repeated restarts could pile cancelled jobs above
            // `max_job_history`. The fix is a `cancel_scheduled_jobs` helper
            // routed through `update_job_status` for every transition.
            let (mut state, base_task, spec) = fixture(128);
            state.max_job_history = 32;

            for _ in 0..200 {
                let pc = state.base_tasks[base_task.idx()].spawn_counter as usize;
                state.base_tasks[base_task.idx()].spawn_counter =
                    state.base_tasks[base_task.idx()].spawn_counter.wrapping_add(1);
                let log_group = LogGroup::new(base_task, pc);
                let ji = state.jobs.insert(Job {
                    process_status: JobStatus::Scheduled { after: Vec::new() },
                    log_group,
                    started_at: crate::clock::now(),
                    cache_key: String::new(),
                    cache_synthetic: false,
                    spawn: spec.clone(),
                    held_resources: SmallVec::new(),
                    action_deps_until_ready: SmallVec::new(),
                    trace: false,
                    trace_report: None,
                });
                state.base_tasks[base_task.idx()].jobs.push_scheduled(ji);
                state.action_jobs.push_scheduled(ji);
            }

            assert_eq!(state.jobs.len(), 200, "all 200 scheduled jobs should be in the slab");
            state.cancel_scheduled_jobs(base_task);
            assert!(
                state.jobs.len() as u32 <= state.max_job_history,
                "canonical cancellation must trigger history pruning; got {} > {}",
                state.jobs.len(),
                state.max_job_history
            );
        }

        #[test]
        fn cached_success_jobs_respect_history_cap() {
            let (mut state, base_task, spec) = fixture(32);
            let task = spec.task.clone();

            for i in 0..200 {
                state.create_cached_success_job(
                    base_task,
                    task.clone(),
                    "",
                    ValueMap::new(),
                    format!("cached-{i}"),
                    ScheduleReason::TestRun,
                );
            }

            assert!(
                state.jobs.len() as u32 <= state.max_job_history,
                "cached synthetic jobs must be pruned; got {} > {}",
                state.jobs.len(),
                state.max_job_history
            );
        }

        #[test]
        fn cached_test_batch_does_not_return_or_record_pruned_job_indices() {
            let mut state =
                WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).expect("load test config");
            state.max_job_history = MIN_JOB_HISTORY;
            let base_task = state.lookup_name("test.test_with_cache").expect("cached test task");
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task = config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars })
                .expect("eval cached test");
            let spec = state.cache_spawn_spec(base_task, "", ValueMap::new(), task.clone());
            let cache_key = String::new();

            let pc = state.base_tasks[base_task.idx()].spawn_counter as usize;
            state.base_tasks[base_task.idx()].spawn_counter =
                state.base_tasks[base_task.idx()].spawn_counter.wrapping_add(1);
            let now = crate::clock::now();
            let seed = state.jobs.insert(Job {
                process_status: JobStatus::Exited { finished_at: now, cause: ExitCause::Unknown, status: 0 },
                log_group: LogGroup::new(base_task, pc),
                started_at: now,
                cache_key: cache_key.clone(),
                cache_synthetic: false,
                spawn: spec.clone(),
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            state.base_tasks[base_task.idx()].jobs.push_terminated(seed);
            state.test_jobs.push_terminated(seed);

            let matched = (0..(MIN_JOB_HISTORY as usize + 40))
                .map(|_| MatchedTest {
                    base_task_idx: base_task,
                    task_config: task.clone(),
                    spawn_profile: String::new(),
                    spawn_params: ValueMap::new(),
                })
                .collect();
            let poll = Box::leak(Box::new(mio::Poll::new().expect("poll")));
            let waker = Box::leak(Box::new(mio::Waker::new(poll.registry(), mio::Token(0)).expect("waker")));
            let channel = MioChannel { waker, events: std::sync::Mutex::new(Vec::new()) };

            let test_run = state.run_test_batch(matched, 0, &channel, 0, false).expect("cached test batch should run");

            assert!(
                test_run.test_jobs.iter().all(|job| job.job_index.is_none_or(|ji| state.jobs.get(ji).is_some())),
                "returned TestRun must not contain pruned job indices"
            );
            assert!(
                state.last_test_group.is_none(),
                "cached-only test runs must not record a last_test_group with non-rerunnable synthetic jobs"
            );
        }

        #[test]
        fn cached_test_batch_reports_all_cached_matches_under_history_cap() {
            let mut state =
                WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).expect("load test config");
            state.max_job_history = MIN_JOB_HISTORY;
            let base_task = state.lookup_name("test.test_with_cache").expect("cached test task");
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task = config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars })
                .expect("eval cached test");
            let spec = state.cache_spawn_spec(base_task, "", ValueMap::new(), task.clone());
            let cache_key = String::new();

            let pc = state.base_tasks[base_task.idx()].spawn_counter as usize;
            state.base_tasks[base_task.idx()].spawn_counter =
                state.base_tasks[base_task.idx()].spawn_counter.wrapping_add(1);
            let now = crate::clock::now();
            let seed = state.jobs.insert(Job {
                process_status: JobStatus::Exited { finished_at: now, cause: ExitCause::Unknown, status: 0 },
                log_group: LogGroup::new(base_task, pc),
                started_at: now,
                cache_key: cache_key.clone(),
                cache_synthetic: false,
                spawn: spec.clone(),
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            state.base_tasks[base_task.idx()].jobs.push_terminated(seed);
            state.test_jobs.push_terminated(seed);

            let expected = MIN_JOB_HISTORY as usize + 40;
            let matched = (0..expected)
                .map(|_| MatchedTest {
                    base_task_idx: base_task,
                    task_config: task.clone(),
                    spawn_profile: String::new(),
                    spawn_params: ValueMap::new(),
                })
                .collect();
            let poll = Box::leak(Box::new(mio::Poll::new().expect("poll")));
            let waker = Box::leak(Box::new(mio::Waker::new(poll.registry(), mio::Token(0)).expect("waker")));
            let channel = MioChannel { waker, events: std::sync::Mutex::new(Vec::new()) };

            let test_run = state.run_test_batch(matched, 0, &channel, 0, false).expect("cached test batch should run");

            assert_eq!(
                test_run.test_jobs.len(),
                expected,
                "cached test accounting must include every matched test even when history pruning evicts synthetic jobs"
            );
            assert_eq!(
                test_run.test_jobs.iter().filter(|job| matches!(job.status, TestJobStatus::Cached)).count(),
                expected
            );
        }

        #[test]
        fn transactional_submit_does_not_return_or_record_pruned_planned_jobs() {
            let manifest = temp_manifest(
                "transactional-pruned-planned-jobs",
                r#"
[action.a]
cmd = ["true"]
"#,
            );
            let mut state = WorkspaceState::new(manifest.clone()).expect("load test config");
            state.max_job_history = 1;

            let writer = LogWriter::new();
            let workspace = Workspace {
                workspace_id: 0,
                logs: writer.reader(),
                state: RwLock::new(WorkspaceState::new(manifest).expect("load dummy workspace state")),
                process_channel: test_channel(),
            };

            let task = |name: &str| TaskSpec {
                name: name.into(),
                profile: String::new(),
                params: ValueMap::new(),
                force_restart: false,
                trace: false,
            };
            let entries = vec![
                SpawnPlanEntry { group_name: Some("dupe".to_string()), task: task("a") },
                SpawnPlanEntry { group_name: Some("dupe".to_string()), task: task("a") },
            ];

            let (jobs, group_jobs) = workspace
                .spawn_plan_transactional(&mut state, entries, false)
                .expect("transactional spawn should succeed");

            assert!(
                jobs.iter().all(|(_, ji)| state.jobs.get(*ji).is_some()),
                "SubmitResult must not contain pruned job indices: {:?}",
                jobs
            );
            let group = group_jobs.get("dupe").expect("group refs should be returned");
            assert!(
                group.iter().all(|ji| state.jobs.get(*ji).is_some()),
                "group refs must not contain pruned job indices: {:?}",
                group
            );
        }

        #[test]
        fn update_job_status_returns_public_id_even_when_pruned() {
            // Reproduce a scenario where a terminal transition triggers a
            // prune that evicts the just-finished job. When `c` exits with
            // `max_job_history = 1` and one older terminal job in the slab,
            // both `a` (oldest terminal) and `c` (newly terminal) get
            // evicted. The broadcaster needs `c`'s public id to fan out the
            // `JobExited` event, so `update_job_status` has to capture it
            // before any side effects run.
            let (mut state, base_task, spec) = fixture(128);

            let a = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, a, 0);
            let _b = insert_job(&mut state, base_task, spec.clone());
            let c = insert_job(&mut state, base_task, spec.clone());
            let c_public_id = state.jobs.public_id_of(c).expect("c must be live before transition");

            state.max_job_history = 1;
            state.update_job_status(c, JobStatus::Running { process_index: 0, ready_state: None });
            let returned = state.update_job_status(
                c,
                JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status: 0 },
            );

            assert!(state.jobs.public_id_of(c).is_none(), "c must be evicted by its own terminal-transition prune");
            assert_eq!(
                returned,
                Some(c_public_id),
                "update_job_status must return the just-exited public id even if pruning evicted it"
            );
        }

        #[test]
        fn test_group_arrays_stay_aligned_after_pruning() {
            let (mut state, base_task, spec) = fixture(128);

            let a = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, a, 0);
            // started_at increments are coarse, sleep so the pruner can
            // distinguish oldest from newest by `started_at`.
            std::thread::sleep(std::time::Duration::from_millis(2));
            let b = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, b, 0);
            std::thread::sleep(std::time::Duration::from_millis(2));
            let c = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, c, 0);

            state.last_test_group = Some(TestGroup {
                group_id: 0,
                base_tasks: vec![BaseTaskIndex(10), BaseTaskIndex(11), BaseTaskIndex(12)],
                job_indices: vec![a, b, c],
            });

            // Pin the cap below the current live count, then force another
            // terminal transition so prune_history evicts the two oldest test
            // jobs while leaving `c` alive.
            state.max_job_history = 2;
            std::thread::sleep(std::time::Duration::from_millis(2));
            let filler = insert_job(&mut state, base_task, spec.clone());
            exit(&mut state, filler, 0);

            assert!(state.jobs.get(a).is_none(), "a should be evicted");
            assert!(state.jobs.get(b).is_none(), "b should be evicted");
            assert!(state.jobs.get(c).is_some(), "c should survive");

            let tg = state.last_test_group.as_ref().expect("group should still hold the surviving job");
            assert_eq!(tg.job_indices.len(), tg.base_tasks.len(), "parallel arrays must stay aligned after pruning");
            assert_eq!(tg.job_indices, vec![c]);
            assert_eq!(tg.base_tasks, vec![BaseTaskIndex(12)]);
        }
    }

    mod resource_lock_tests {
        use super::*;

        fn manifest_path(relative: &str) -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        fn fresh_state() -> (WorkspaceState, BaseTaskIndex, Arc<ResolvedSpawnSpec>) {
            let mut state =
                WorkspaceState::new(manifest_path("schema/devsm.example-big.toml")).expect("load test config");
            state.max_job_history = 1024;
            let base_task = state.lookup_name("simple_cmd").unwrap();
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task = config
                .eval(&Environment { profile: "", param: ValueMap::new(), vars: config.vars })
                .expect("eval task");
            let spec = state.cache_spawn_spec(base_task, "", ValueMap::new(), task);
            (state, base_task, spec)
        }

        fn insert_scheduled_with_resources(
            state: &mut WorkspaceState,
            base_task: BaseTaskIndex,
            spec: Arc<ResolvedSpawnSpec>,
            resources: Vec<(ResourceIndex, i32)>,
        ) -> JobIndex {
            let bt = &mut state.base_tasks[base_task.idx()];
            let pc = bt.spawn_counter as usize;
            bt.spawn_counter = bt.spawn_counter.wrapping_add(1);
            let log_group = LogGroup::new(base_task, pc);
            let after =
                resources.into_iter().map(|(id, priority)| ScheduleRequirement::Resource { id, priority }).collect();
            let ji = state.jobs.insert(Job {
                process_status: JobStatus::Scheduled { after },
                log_group,
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            state.base_tasks[base_task.idx()].jobs.push_scheduled(ji);
            state.action_jobs.push_scheduled(ji);
            ji
        }

        fn insert_running_service(state: &mut WorkspaceState, base_task: BaseTaskIndex, profile: &str) -> JobIndex {
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task =
                config.eval(&Environment { profile, param: ValueMap::new(), vars: config.vars }).expect("eval service");
            let spec = state.cache_spawn_spec(base_task, profile, ValueMap::new(), task);
            let bt = &mut state.base_tasks[base_task.idx()];
            let pc = bt.spawn_counter as usize;
            bt.spawn_counter = bt.spawn_counter.wrapping_add(1);
            let ji = state.jobs.insert(Job {
                process_status: JobStatus::Running { process_index: pc, ready_state: None },
                log_group: LogGroup::new(base_task, pc),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            state.base_tasks[base_task.idx()].jobs.push_active(ji);
            state.service_jobs.push_active(ji);
            ji
        }

        fn insert_scheduled_service_with_requirements(
            state: &mut WorkspaceState,
            base_task: BaseTaskIndex,
            profile: &str,
            after: Vec<ScheduleRequirement>,
        ) -> JobIndex {
            let config = state.base_tasks[base_task.idx()].config.clone();
            let task =
                config.eval(&Environment { profile, param: ValueMap::new(), vars: config.vars }).expect("eval service");
            let spec = state.cache_spawn_spec(base_task, profile, ValueMap::new(), task);
            let bt = &mut state.base_tasks[base_task.idx()];
            let pc = bt.spawn_counter as usize;
            bt.spawn_counter = bt.spawn_counter.wrapping_add(1);
            let ji = state.jobs.insert(Job {
                process_status: JobStatus::Scheduled { after },
                log_group: LogGroup::new(base_task, pc),
                started_at: crate::clock::now(),
                cache_key: String::new(),
                cache_synthetic: false,
                spawn: spec,
                held_resources: SmallVec::new(),
                action_deps_until_ready: SmallVec::new(),
                trace: false,
                trace_report: None,
            });
            state.base_tasks[base_task.idx()].jobs.push_scheduled(ji);
            state.service_jobs.push_scheduled(ji);
            ji
        }

        #[test]
        fn intern_returns_same_id_for_same_name() {
            let mut slab = ResourceSlab::default();
            let a = slab.intern("foo");
            let b = slab.intern("foo");
            assert_eq!(a, b);
            let c = slab.intern("bar");
            assert_ne!(a, c);
        }

        #[test]
        fn fresh_resource_is_free() {
            let mut slab = ResourceSlab::default();
            let id = slab.intern("foo");
            assert!(slab.is_free(id));
        }

        #[test]
        fn acquire_marks_resource_held() {
            let (mut state, base_task, spec) = fresh_state();
            let id = state.resources.intern("R");
            let ji = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(id, 0)]);

            assert!(state.resources.is_free(id));
            state.update_job_status(ji, JobStatus::Starting);
            assert!(!state.resources.is_free(id));
            assert_eq!(state.jobs[ji].held_resources.as_slice(), &[id]);
        }

        #[test]
        fn exit_releases_held_resources() {
            let (mut state, base_task, spec) = fresh_state();
            let id = state.resources.intern("R");
            let ji = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(id, 0)]);

            state.update_job_status(ji, JobStatus::Starting);
            state.update_job_status(ji, JobStatus::Running { process_index: 0, ready_state: None });
            state.update_job_status(
                ji,
                JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status: 0 },
            );

            assert!(state.resources.is_free(id));
            assert!(state.jobs[ji].held_resources.is_empty());
        }

        #[test]
        fn cancel_after_starting_releases_resources() {
            let (mut state, base_task, spec) = fresh_state();
            let id = state.resources.intern("R");
            let ji = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(id, 0)]);

            state.update_job_status(ji, JobStatus::Starting);
            assert!(!state.resources.is_free(id));
            state.update_job_status(ji, JobStatus::Cancelled);
            assert!(state.resources.is_free(id));
        }

        #[test]
        fn cancel_before_starting_does_not_touch_resource() {
            let (mut state, base_task, spec) = fresh_state();
            let id = state.resources.intern("R");
            let ji = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(id, 0)]);

            assert!(state.resources.is_free(id));
            state.update_job_status(ji, JobStatus::Cancelled);
            assert!(state.resources.is_free(id));
            assert!(state.jobs[ji].held_resources.is_empty());
        }

        #[test]
        fn next_scheduled_blocks_on_held_resource() {
            let (mut state, base_task, spec) = fresh_state();
            let id = state.resources.intern("R");
            let first = insert_scheduled_with_resources(&mut state, base_task, spec.clone(), vec![(id, 0)]);
            let second = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(id, 0)]);

            match state.next_scheduled() {
                Scheduled::Ready(ji) => assert_eq!(ji, first),
                other => panic!("expected first job ready, got {other:?}"),
            }
            state.update_job_status(first, JobStatus::Starting);

            match state.next_scheduled() {
                Scheduled::None => {}
                other => panic!("expected None while resource is held, got {other:?}"),
            }

            state.update_job_status(first, JobStatus::Running { process_index: 0, ready_state: None });
            state.update_job_status(
                first,
                JobStatus::Exited { finished_at: crate::clock::now(), cause: ExitCause::Unknown, status: 0 },
            );

            match state.next_scheduled() {
                Scheduled::Ready(ji) => assert_eq!(ji, second),
                other => panic!("expected second job ready after release, got {other:?}"),
            }
        }

        #[test]
        fn higher_priority_wins_resource_contention() {
            let (mut state, base_task, spec) = fresh_state();
            let id = state.resources.intern("R");
            let low = insert_scheduled_with_resources(&mut state, base_task, spec.clone(), vec![(id, 0)]);
            let high = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(id, 5)]);

            match state.next_scheduled() {
                Scheduled::Ready(ji) => assert_eq!(ji, high, "higher priority must win even though enqueued later"),
                other => panic!("expected high priority job ready, got {other:?}"),
            }
            let _ = low;
        }

        #[test]
        fn equal_priority_resolves_fifo() {
            let (mut state, base_task, spec) = fresh_state();
            let id = state.resources.intern("R");
            let first = insert_scheduled_with_resources(&mut state, base_task, spec.clone(), vec![(id, 1)]);
            let _second = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(id, 1)]);

            match state.next_scheduled() {
                Scheduled::Ready(ji) => assert_eq!(ji, first, "FIFO breaks ties on equal priority"),
                other => panic!("expected first job ready, got {other:?}"),
            }
        }

        #[test]
        fn multi_resource_atomic_acquire() {
            let (mut state, base_task, spec) = fresh_state();
            let r_a = state.resources.intern("A");
            let r_b = state.resources.intern("B");

            let multi = insert_scheduled_with_resources(&mut state, base_task, spec.clone(), vec![(r_a, 0), (r_b, 0)]);
            let only_b = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(r_b, 0)]);

            match state.next_scheduled() {
                Scheduled::Ready(ji) => assert_eq!(ji, multi),
                other => panic!("expected multi job ready, got {other:?}"),
            }
            state.update_job_status(multi, JobStatus::Starting);
            assert!(!state.resources.is_free(r_a));
            assert!(!state.resources.is_free(r_b));
            assert_eq!(state.jobs[multi].held_resources.len(), 2);

            match state.next_scheduled() {
                Scheduled::None => {}
                other => panic!("expected None while B is held, got {other:?}"),
            }
            let _ = only_b;
        }

        #[test]
        fn crossed_multi_resource_priorities_still_make_progress() {
            let (mut state, base_task, spec) = fresh_state();
            let r_a = state.resources.intern("A");
            let r_b = state.resources.intern("B");

            let first = insert_scheduled_with_resources(&mut state, base_task, spec.clone(), vec![(r_a, 10), (r_b, 0)]);
            let second = insert_scheduled_with_resources(&mut state, base_task, spec, vec![(r_a, 0), (r_b, 10)]);

            match state.next_scheduled() {
                Scheduled::Ready(ji) => assert!(
                    ji == first || ji == second,
                    "scheduler must pick a ready candidate from the crossed-priority set"
                ),
                other => panic!("crossed multi-resource priorities must not stall, got {other:?}"),
            }
        }

        #[test]
        fn queued_service_waits_until_it_wins_resource_contention_before_stopping_current_profile() {
            let (mut state, action_base, action_spec) = fresh_state();
            let service_base = state.lookup_name("service_conditional_cmd").expect("service task");
            let running = insert_running_service(&mut state, service_base, "watch");
            let resource = state.resources.intern("R");

            let queued = insert_scheduled_service_with_requirements(
                &mut state,
                service_base,
                "default",
                vec![
                    ScheduleRequirement::Task { job: running, predicate: JobPredicate::Terminated },
                    ScheduleRequirement::Resource { id: resource, priority: 0 },
                ],
            );
            let high_priority =
                insert_scheduled_with_resources(&mut state, action_base, action_spec, vec![(resource, 10)]);

            assert!(
                state.service_to_terminate_for_queue().is_none(),
                "queued replacement must not stop current service while another ready job wins its resource"
            );
            match state.next_scheduled() {
                Scheduled::Ready(ji) => assert_eq!(ji, high_priority),
                other => panic!("expected high-priority resource contender to run first, got {other:?}"),
            }
            let _ = queued;
        }
    }
}
