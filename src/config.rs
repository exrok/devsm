use std::{
    ops::Deref,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::bail;
use bumpalo::Bump;
use jsony::Jsony;
use jsony_value::{Value, ValueMap, ValueRef};

use crate::diagnostic::{Diagnostic, emit_diagnostic, render_diagnostic, toml_error_to_diagnostic};

pub mod toml_handler;

pub fn emit_config_error(file_name: &str, content: &str, diagnostic: &Diagnostic) {
    emit_diagnostic(file_name, content, diagnostic);
}

pub fn format_config_error(file_name: &str, content: &str, diagnostic: &Diagnostic) -> String {
    render_diagnostic(file_name, content, diagnostic)
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Alias<'a>(&'a str);
impl<'a> Alias<'a> {
    #[cfg(test)]
    pub fn new(s: &'a str) -> Self {
        Alias(s)
    }
}
impl<'a> std::ops::Deref for Alias<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct TaskCall<'a> {
    pub name: Alias<'a>,
    pub profile: Option<&'a str>,
    /// todo this leaks when bump allows because ValueMap allocates globally
    pub vars: ValueMap<'a>,
}

/// A single entry in a `require` slice. Tasks declare dependencies on either
/// other tasks (existing form) or on named external resources.
///
/// Resources serialize concurrent tasks that touch the same external state
/// (e.g. a build directory). While one task holds a resource, other tasks
/// declaring the same `name` wait. `priority` resolves contention; ties break
/// FIFO by enqueue time.
#[derive(Debug, Clone)]
pub enum Requirement<'a> {
    Task(TaskCall<'a>),
    Resource { name: &'a str, priority: i32 },
}

#[derive(Debug, Clone)]
pub enum RequirementExpr<'a> {
    Requirement(Requirement<'a>),
    If(&'a If<'a, RequirementListExpr<'a>>),
}

#[derive(Debug, Clone)]
pub struct RequirementListExpr<'a> {
    pub items: &'a [RequirementExpr<'a>],
}

/// Empty slice of requirement expressions, used as default for parsed `require`.
pub static EMPTY_REQUIREMENT_EXPRS: &[RequirementExpr<'static>] = &[];

impl<'a> RequirementExpr<'a> {
    pub fn visit_requirements(&self, f: &mut impl FnMut(&Requirement<'a>)) {
        match self {
            RequirementExpr::Requirement(req) => f(req),
            RequirementExpr::If(if_expr) => {
                if_expr.then.visit_requirements(f);
                if let Some(or_else) = &if_expr.or_else {
                    or_else.visit_requirements(f);
                }
            }
        }
    }

    pub fn eval_for_profile_append(&self, profile: &str, out: &mut Vec<Requirement<'a>>) {
        match self {
            RequirementExpr::Requirement(req) => out.push(req.clone()),
            RequirementExpr::If(if_expr) => {
                if if_expr.cond.eval_profile(profile) {
                    if_expr.then.eval_for_profile_append(profile, out);
                } else if let Some(or_else) = &if_expr.or_else {
                    or_else.eval_for_profile_append(profile, out);
                }
            }
        }
    }

    pub fn visit_profile_predicates(&self, f: &mut impl FnMut(&'a str)) {
        match self {
            RequirementExpr::Requirement(_) => {}
            RequirementExpr::If(if_expr) => {
                if_expr.cond.visit_profiles(f);
                if_expr.then.visit_profile_predicates(f);
                if let Some(or_else) = &if_expr.or_else {
                    or_else.visit_profile_predicates(f);
                }
            }
        }
    }
}

impl<'a> RequirementListExpr<'a> {
    pub fn visit_requirements(&self, f: &mut impl FnMut(&Requirement<'a>)) {
        for item in self.items {
            item.visit_requirements(f);
        }
    }

    pub fn eval_for_profile_append(&self, profile: &str, out: &mut Vec<Requirement<'a>>) {
        for item in self.items {
            item.eval_for_profile_append(profile, out);
        }
    }

    pub fn visit_profile_predicates(&self, f: &mut impl FnMut(&'a str)) {
        for item in self.items {
            item.visit_profile_predicates(f);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VarMeta<'a> {
    pub description: Option<&'a str>,
    pub default: Option<&'a str>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Jsony)]
#[jsony(rename_all = "snake_case")]
pub enum TaskKind {
    Service,
    Action,
    Test,
}

impl TaskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskKind::Service => "service",
            TaskKind::Action => "action",
            TaskKind::Test => "test",
        }
    }
}

/// Controls when a service is visible in the task list.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ServiceHidden {
    /// Always show the service in the task list (default behavior).
    #[default]
    Never,
    /// Hide the service until it has been run at least once this session.
    UntilRan,
}

/// Controls whether multiple instances of a task can run concurrently.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AllowMultiple {
    /// Only one instance at a time (default). Starting a new instance kills the old one.
    #[default]
    False,
    /// Multiple instances allowed, but each must have a distinct profile.
    DistinctProfiles,
    /// Multiple instances allowed, but all must share the same profile.
    SingleProfile,
    /// Multiple instances with no restrictions.
    True,
}

/// Per-task command-line behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CliConfig<'a> {
    pub forward_arguments: bool,
    pub autocomplete: CliAutocomplete<'a>,
}

impl<'a> CliConfig<'a> {
    pub const DEFAULT: Self = Self { forward_arguments: false, autocomplete: CliAutocomplete::None };
}

/// Per-task command-line autocomplete behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CliAutocomplete<'a> {
    #[default]
    None,
    Forward,
    Schema {
        command: &'a [&'a str],
    },
}

/// A single cache key input that contributes to cache invalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheKeyInput<'a> {
    /// Invalidate cache when file(s) modification times change.
    /// Supports directories (recursively walked) and ignore patterns.
    Modified { paths: &'a [&'a str], ignore: &'a [&'a str] },
    /// Invalidate cache when the referenced task's profile changes.
    ProfileChanged(&'a str),
}

/// Cache configuration for tasks. When present, the task's result
/// is cached for the session - it won't re-run via `require` if the
/// last non-cancelled run was successful.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheConfig<'a> {
    /// Cache key inputs that determine when the cache should be invalidated.
    /// Empty means no key-based invalidation (simple success-based caching).
    pub key: &'a [CacheKeyInput<'a>],
    /// When true, the task is never considered initially satisfied.
    /// For actions: always re-run when required, ignoring any cached results.
    /// For services: always restart when required, even if already running.
    pub never: bool,
    /// When true, successful cache entries are saved and can satisfy future
    /// daemon sessions.
    pub persistent: bool,
    /// Optional upper bound on how long successful cache entries remain valid.
    pub max_age: Option<Duration>,
}

/// Predicate determining when a service is ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadyPredicate<'a> {
    /// Ready when stdout/stderr contains this string (ANSI stripped, case-sensitive).
    OutputContains(&'a str),
}

/// Ready condition configuration for services.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadyConfig<'a> {
    pub when: ReadyPredicate<'a>,
    pub timeout: Option<f64>,
}

/// Predicate determining when a timeout condition triggers.
/// Reuses the same predicates as ReadyPredicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutPredicate<'a> {
    /// Timeout starts when stdout/stderr contains this string (ANSI stripped, case-sensitive).
    OutputContains(&'a str),
}

/// Timeout configuration for actions, tests, and services.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TimeoutConfig<'a> {
    /// Optional predicate that starts the conditional timeout.
    pub when: Option<TimeoutPredicate<'a>>,
    /// Timeout in seconds after the predicate matches.
    pub conditional: Option<f64>,
    /// Maximum absolute timeout in seconds from task start.
    pub max: Option<f64>,
    /// Idle timeout in seconds - terminates if no output is generated within this duration.
    pub idle: Option<f64>,
}

/// Parses a duration string like "10m", "30s", "1.5h", "2d" into seconds.
/// Supports suffixes: s (seconds), m (minutes), h (hours), d (days).
/// Plain numbers without suffix are treated as seconds.
pub fn parse_duration(s: &str) -> Result<f64, &'static str> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string");
    }

    let (num_str, multiplier) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, 0.001)
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 86400.0)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3600.0)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60.0)
    } else if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1.0)
    } else {
        (s, 1.0)
    };
    let num: f64 =
        num_str.trim().parse().map_err(|s| &*format!("invalid duration number '{num_str}': {s:?}").leak())?;
    if num < 0.0 {
        return Err("duration cannot be negative");
    }
    Ok(num * multiplier)
}

/// Action that a saved function performs.
#[derive(Debug, Clone)]
pub enum FunctionDefAction<'a> {
    /// Restart a specific task.
    Restart { task: &'a str },
    /// Spawn one or more tasks (same syntax as groups).
    Spawn { tasks: &'a [TaskCall<'a>] },
    /// Kill a specific task.
    Kill { task: &'a str },
    /// Restart the currently selected task (TUI context required).
    RestartSelected,
}

/// Definition of a saved function from workspace config.
#[derive(Debug, Clone)]
pub struct FunctionDef<'a> {
    pub name: &'a str,
    pub action: FunctionDefAction<'a>,
}

struct EvaluatedTaskConfig {
    config: TaskConfig<'static>,
    _bump: Bump,
    _generation: Option<Arc<ConfigGeneration>>,
}

#[derive(Clone)]
pub struct TaskConfigRc(Arc<EvaluatedTaskConfig>);
unsafe impl Send for TaskConfigRc {}
unsafe impl Sync for TaskConfigRc {}

impl TaskConfigRc {
    pub fn config<'a>(&'a self) -> &'a TaskConfig<'a> {
        &self.0.config
    }

    fn new(config: TaskConfig<'static>, bump: Bump, generation: Option<Arc<ConfigGeneration>>) -> Self {
        TaskConfigRc(Arc::new(EvaluatedTaskConfig { config, _bump: bump, _generation: generation }))
    }

    #[cfg(test)]
    pub(crate) fn allocated_bytes_including_metadata(&self) -> usize {
        self.0._bump.allocated_bytes_including_metadata()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command<'a> {
    Cmd(&'a [&'a str]),
    Sh { script: &'a str, args: &'a [&'a str] },
}

#[derive(Clone, Debug)]
pub struct TaskConfig<'a> {
    pub pwd: &'a str,
    pub command: Command<'a>,
    pub envvar: &'a [(&'a str, &'a str)],
    pub require: &'a [Requirement<'a>],
    pub cache: Option<CacheConfig<'a>>,
    pub ready: Option<ReadyConfig<'a>>,
    pub timeout: Option<TimeoutConfig<'a>>,
}

pub fn find_config_path_from(path: &Path) -> Option<PathBuf> {
    let mut pwd = path.to_path_buf();
    loop {
        pwd.push("devsm.toml");
        if pwd.exists() {
            return Some(pwd);
        }
        if !pwd.pop() {
            break;
        }
        if !pwd.pop() {
            break;
        }
    }
    None
}

pub fn load_from_env() -> anyhow::Result<WorkspaceConfig<'static>> {
    let mut pwd = std::env::current_dir()?;
    loop {
        pwd.push("devsm.toml");
        if pwd.exists() {
            let config_path = pwd.clone();
            let content = std::fs::read_to_string(&pwd)?.leak();
            pwd.pop();
            return load_workspace_config_from_path(&pwd, &config_path, content);
        }
        if !pwd.pop() {
            break;
        }
        if !pwd.pop() {
            break;
        }
    }
    Err(anyhow::anyhow!("Cannot find devsm.toml in current or parent directories"))
}

pub fn load_workspace_config_from_path(
    base_path: &Path,
    config_path: &Path,
    content: &'static str,
) -> anyhow::Result<WorkspaceConfig<'static>> {
    let elapsed = kvlog::Timer::start();
    let bump = Box::leak(Box::new(Bump::new()));
    let base_path = Box::leak(Box::new(base_path.to_path_buf()));
    let arena = Box::leak(Box::new(toml_spanner::Arena::new()));
    let file_name = config_path.display().to_string();

    let mut doc = toml_spanner::parse_recoverable(content, arena);
    let result = toml_handler::parse_workspace(base_path, bump, &mut doc);
    doc.compute_error_paths();
    let had_error = doc.has_errors();
    for err in doc.errors() {
        emit_config_error(&file_name, content, &toml_error_to_diagnostic(err, content));
    }

    match result {
        Ok(value) => {
            kvlog::info!("Workspace config loaded", path = config_path.as_os_str().as_bytes(), elapsed);
            Ok(value)
        }
        Err(_) => {
            if !had_error {
                eprintln!("error: failed to parse {}", file_name);
            }
            bail!("Failed to parse config")
        }
    }
}

#[derive(Debug)]
pub struct ConfigError {
    pub message: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
pub fn load_workspace_config_capturing(
    config_path: &Path,
    content: &'static str,
) -> Result<WorkspaceConfig<'static>, ConfigError> {
    let elapsed = kvlog::Timer::start();
    let bump = Box::leak(Box::new(Bump::new()));
    let base_path = config_path.parent().unwrap_or(Path::new("."));
    let base_path = Box::leak(Box::new(base_path.to_path_buf()));
    let arena = Box::leak(Box::new(toml_spanner::Arena::new()));
    let file_name = config_path.display().to_string();

    let mut doc = toml_spanner::parse_recoverable(content, arena);
    let result = toml_handler::parse_workspace(base_path, bump, &mut doc);
    doc.compute_error_paths();
    let mut errors = String::new();
    for err in doc.errors() {
        errors.push_str(&format_config_error(&file_name, content, &toml_error_to_diagnostic(err, content)));
    }

    match result {
        Ok(value) => {
            kvlog::info!("Workspace config loaded", path = config_path.as_os_str().as_bytes(), elapsed);
            Ok(value)
        }
        Err(_) => {
            if errors.is_empty() {
                errors = format!("error: failed to parse {}\n", file_name);
            }
            Err(ConfigError { message: errors })
        }
    }
}

#[derive(Debug)]
pub struct WorkspaceConfig<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [(&'a str, TaskConfigExpr<'a>)],
    pub tests: &'a [(&'a str, &'a TestConfigExpr<'a>)],
    pub groups: &'a [(&'a str, &'a [TaskCall<'a>])],
    /// Saved function definitions (fn1, fn2).
    pub functions: &'a [FunctionDef<'a>],
}

#[derive(Debug, Clone)]
enum CommandExpr<'a> {
    Cmd(StringListExpr<'a>),
    Sh(StringExpr<'a>),
}

#[derive(Debug)]
pub struct TaskConfigExpr<'a> {
    pub kind: TaskKind,
    #[expect(unused, reason = "TODO display in TUI and other output")]
    info: &'a str,
    pub pwd: StringExpr<'a>,
    command: CommandExpr<'a>,
    pub profiles: &'a [&'a str],
    envvar: &'a [(&'a str, StringExpr<'a>)],
    pub require: &'a [RequirementExpr<'a>],
    pub cache: Option<CacheConfig<'a>>,
    pub ready: Option<ReadyConfig<'a>>,
    /// Timeout configuration for the task.
    pub timeout: Option<TimeoutConfig<'a>>,
    /// Tags for test filtering. Empty for non-test tasks.
    pub tags: &'a [&'a str],
    /// Controls how the task can be executed:
    /// - `None`: default behavior, can use either `run` or `exec`
    /// - `Some(true)`: must use `run` (through daemon), for tasks with complex dependencies
    /// - `Some(false)`: must use `exec` (direct execution), for interactive commands
    pub managed: Option<bool>,
    /// Controls when this service is visible in the task list.
    /// Only meaningful for services; ignored for actions and tests.
    pub hidden: ServiceHidden,
    /// Controls whether multiple instances of this task can run concurrently.
    pub allow_multiple: AllowMultiple,
    /// Per-task command-line behavior.
    pub cli: CliConfig<'a>,
    /// Variable metadata (description, default) for variables used in this task.
    pub vars: &'a [(&'a str, VarMeta<'a>)],
}

/// Test configuration expression (parsed form, not yet evaluated).
#[derive(Debug)]
pub struct TestConfigExpr<'a> {
    pub info: &'a str,
    pub pwd: StringExpr<'a>,
    command: CommandExpr<'a>,
    envvar: &'a [(&'a str, StringExpr<'a>)],
    pub require: &'a [RequirementExpr<'a>],
    pub tags: &'a [&'a str],
    pub cache: Option<CacheConfig<'a>>,
    /// Timeout configuration for the test.
    pub timeout: Option<TimeoutConfig<'a>>,
    /// Per-test command-line behavior.
    pub cli: CliConfig<'a>,
    /// Variable metadata (description, default) for variables used in this test.
    pub vars: &'a [(&'a str, VarMeta<'a>)],
}

impl TestConfigExpr<'static> {
    /// Converts this test config to a [`TaskConfigExpr`] with kind=Test.
    ///
    /// The result is leaked and valid for 'static lifetime.
    pub fn to_task_config_expr(&self) -> &'static TaskConfigExpr<'static> {
        Box::leak(Box::new(TaskConfigExpr {
            kind: TaskKind::Test,
            info: self.info,
            pwd: self.pwd,
            command: self.command.clone(),
            profiles: &[],
            envvar: self.envvar,
            require: self.require,
            cache: self.cache.clone(),
            ready: None,
            timeout: self.timeout.clone(),
            tags: self.tags,
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: self.cli,
            vars: self.vars,
        }))
    }
}

pub static CARGO_AUTO_EXPR: TaskConfigExpr<'static> = {
    TaskConfigExpr {
        kind: TaskKind::Test,
        info: "Default Expression for Cargo Innvocations",
        pwd: StringExpr::Var("pwd"),
        command: CommandExpr::Cmd(StringListExpr::List(&[
            StringListExpr::Literal("cargo"),
            StringListExpr::Var("args"),
        ])),
        profiles: &[],
        envvar: &[],
        require: EMPTY_REQUIREMENT_EXPRS,
        cache: None,
        ready: None,
        timeout: None,
        tags: &[],
        managed: None,
        hidden: ServiceHidden::Never,
        allow_multiple: AllowMultiple::False,
        cli: CliConfig::DEFAULT,
        vars: &[],
    }
};

static NEXT_CONFIG_GENERATION_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct DerivedTestTask {
    pub(crate) name: Box<str>,
    pub(crate) expr: TaskConfigExpr<'static>,
}

pub struct ConfigGeneration {
    id: u64,
    _content: Box<str>,
    _toml_arena: toml_spanner::Arena,
    _parse_bump: Bump,
    _base_path: PathBuf,
    workspace: WorkspaceConfig<'static>,
    pub(crate) derived_tests: Vec<DerivedTestTask>,
}

unsafe impl Send for ConfigGeneration {}
unsafe impl Sync for ConfigGeneration {}

impl ConfigGeneration {
    fn new(
        content: Box<str>,
        toml_arena: toml_spanner::Arena,
        parse_bump: Bump,
        base_path: PathBuf,
        workspace: WorkspaceConfig<'static>,
    ) -> Arc<Self> {
        let mut derived_tests = Vec::new();
        for (base_name, config) in workspace.tests {
            derived_tests.push(DerivedTestTask {
                name: (*base_name).into(),
                expr: TaskConfigExpr {
                    kind: TaskKind::Test,
                    info: config.info,
                    pwd: config.pwd,
                    command: config.command.clone(),
                    profiles: &[],
                    envvar: config.envvar,
                    require: config.require,
                    cache: config.cache.clone(),
                    ready: None,
                    timeout: config.timeout.clone(),
                    tags: config.tags,
                    managed: None,
                    hidden: ServiceHidden::Never,
                    allow_multiple: AllowMultiple::False,
                    cli: config.cli,
                    vars: config.vars,
                },
            });
        }
        Arc::new(Self {
            id: NEXT_CONFIG_GENERATION_ID.fetch_add(1, Ordering::Relaxed),
            _content: content,
            _toml_arena: toml_arena,
            _parse_bump: parse_bump,
            _base_path: base_path,
            workspace,
            derived_tests,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn workspace<'a>(&'a self) -> &'a WorkspaceConfig<'a> {
        &self.workspace
    }

    pub fn base_path(&self) -> &Path {
        self.workspace().base_path
    }

    fn task_expr(&self, task_index: usize) -> &TaskConfigExpr<'static> {
        &self.workspace.tasks[task_index].1
    }

    fn derived_test_expr(&self, derived_index: usize) -> &TaskConfigExpr<'static> {
        &self.derived_tests[derived_index].expr
    }
}

#[derive(Clone)]
pub enum TaskConfigSource {
    Static(&'static TaskConfigExpr<'static>),
    WorkspaceTask { generation: Arc<ConfigGeneration>, task_index: usize },
    DerivedTest { generation: Arc<ConfigGeneration>, derived_index: usize },
}

impl TaskConfigSource {
    pub fn from_workspace_task(generation: Arc<ConfigGeneration>, task_index: usize) -> Self {
        TaskConfigSource::WorkspaceTask { generation, task_index }
    }

    pub fn from_derived_test(generation: Arc<ConfigGeneration>, derived_index: usize) -> Self {
        TaskConfigSource::DerivedTest { generation, derived_index }
    }

    pub fn generation_id(&self) -> u64 {
        match self {
            TaskConfigSource::Static(_) => 0,
            TaskConfigSource::WorkspaceTask { generation, .. } | TaskConfigSource::DerivedTest { generation, .. } => {
                generation.id()
            }
        }
    }

    fn generation(&self) -> Option<Arc<ConfigGeneration>> {
        match self {
            TaskConfigSource::Static(_) => None,
            TaskConfigSource::WorkspaceTask { generation, .. } | TaskConfigSource::DerivedTest { generation, .. } => {
                Some(generation.clone())
            }
        }
    }

    pub fn expr(&self) -> &TaskConfigExpr<'static> {
        match self {
            TaskConfigSource::Static(expr) => expr,
            TaskConfigSource::WorkspaceTask { generation, task_index } => generation.task_expr(*task_index),
            TaskConfigSource::DerivedTest { generation, derived_index } => generation.derived_test_expr(*derived_index),
        }
    }

    pub fn eval(&self, env: &Environment) -> Result<TaskConfigRc, EvalError> {
        self.expr().eval_with_generation(env, self.generation())
    }
}

impl Deref for TaskConfigSource {
    type Target = TaskConfigExpr<'static>;

    fn deref(&self) -> &Self::Target {
        self.expr()
    }
}

pub fn load_workspace_generation_capturing(
    config_path: &Path,
    content: String,
) -> Result<Arc<ConfigGeneration>, ConfigError> {
    let elapsed = kvlog::Timer::start();
    let content = content.into_boxed_str();
    let toml_arena = toml_spanner::Arena::new();
    let parse_bump = Bump::new();
    let base_path = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let file_name = config_path.display().to_string();

    let mut doc = toml_spanner::parse_recoverable(&content, &toml_arena);
    let result = toml_handler::parse_workspace(&base_path, &parse_bump, &mut doc);
    doc.compute_error_paths();
    let mut errors = String::new();
    for err in doc.errors() {
        errors.push_str(&format_config_error(&file_name, &content, &toml_error_to_diagnostic(err, &content)));
    }
    drop(doc);

    match result {
        Ok(value) => {
            let workspace = unsafe { std::mem::transmute::<WorkspaceConfig<'_>, WorkspaceConfig<'static>>(value) };
            kvlog::info!("Workspace config loaded", path = config_path.as_os_str().as_bytes(), elapsed);
            Ok(ConfigGeneration::new(content, toml_arena, parse_bump, base_path, workspace))
        }
        Err(_) => {
            if errors.is_empty() {
                errors = format!("error: failed to parse {}\n", file_name);
            }
            Err(ConfigError { message: errors })
        }
    }
}

pub struct Environment<'a> {
    pub profile: &'a str,
    pub param: jsony_value::ValueMap<'a>,
    pub vars: &'a [(&'a str, VarMeta<'a>)],
}

fn get_var_default<'a>(vars: &[(&str, VarMeta<'a>)], name: &str) -> Option<&'a str> {
    vars.iter().find(|(n, _)| *n == name).and_then(|(_, meta)| meta.default)
}

impl Environment<'_> {
    fn resolve_special(&self, name: &str) -> Option<&str> {
        let name = name.strip_prefix('$')?;
        match name {
            "profile" => Some(self.profile),
            _ => None,
        }
    }

    fn var_str<'a>(&self, name: &str, bump: &'a Bump) -> Result<&'a str, EvalError> {
        if let Some(s) = self.resolve_special(name) {
            return Ok(bump.alloc_str(s));
        }
        match self.param[name].as_ref() {
            ValueRef::String(s) | ValueRef::Other(s) => Ok(bump.alloc_str(s)),
            _ => get_var_default(self.vars, name).map(|s| bump.alloc_str(s) as &str).ok_or(EvalError::Todo),
        }
    }

    fn var_append<'a>(
        &self,
        name: &str,
        bump: &'a Bump,
        target: &mut bumpalo::collections::Vec<&'a str>,
    ) -> Result<(), EvalError> {
        if let Some(s) = self.resolve_special(name) {
            target.push(bump.alloc_str(s));
            return Ok(());
        }
        match self.param[name].as_ref() {
            ValueRef::Null(_) => {
                if let Some(default) = get_var_default(self.vars, name) {
                    target.push(bump.alloc_str(default));
                }
                Ok(())
            }
            _ => append_value(&self.param[name], bump, target),
        }
    }

    fn forwarded_args<'a>(&self, bump: &'a Bump) -> Result<&'a [&'a str], EvalError> {
        let mut result = bumpalo::collections::Vec::new_in(bump);
        self.var_append("args", bump, &mut result)?;
        Ok(result.into_bump_slice())
    }
}

#[derive(Debug)]
pub enum EvalError {
    Todo,
    EmptyBranch,
    DuplicateResource,
}

impl TaskConfigExpr<'static> {
    pub fn eval(&self, env: &Environment) -> Result<TaskConfigRc, EvalError> {
        self.eval_with_generation(env, None)
    }

    fn eval_with_generation(
        &self,
        env: &Environment,
        generation: Option<Arc<ConfigGeneration>>,
    ) -> Result<TaskConfigRc, EvalError> {
        let bump = Bump::new();
        let evaluated = self.bump_eval(env, &bump)?;
        let config = unsafe { std::mem::transmute::<TaskConfig<'_>, TaskConfig<'static>>(evaluated) };
        Ok(TaskConfigRc::new(config, bump, generation))
    }
}

impl<'a> BumpEval<'a> for CommandExpr<'static> {
    type Object = Command<'a>;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<Command<'a>, EvalError> {
        Ok(match self {
            CommandExpr::Cmd(cmd_expr) => Command::Cmd(cmd_expr.bump_eval(env, bump)?),
            CommandExpr::Sh(sh_expr) => Command::Sh { script: sh_expr.bump_eval(env, bump)?, args: &[] },
        })
    }
}

impl<'a> BumpEval<'a> for TaskConfigExpr<'static> {
    type Object = TaskConfig<'a>;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<TaskConfig<'a>, EvalError> {
        let command = match &self.command {
            CommandExpr::Cmd(cmd_expr) => Command::Cmd(cmd_expr.bump_eval(env, bump)?),
            CommandExpr::Sh(sh_expr) => {
                let script = sh_expr.bump_eval(env, bump)?;
                let args = if self.cli.forward_arguments { env.forwarded_args(bump)? } else { &[] };
                Command::Sh { script, args }
            }
        };

        Ok(TaskConfig {
            pwd: self.pwd.bump_eval(env, bump)?,
            command,
            require: RequirementListExpr { items: self.require }.bump_eval(env, bump)?,
            cache: self.cache.clone(),
            ready: self.ready.clone(),
            timeout: self.timeout.clone(),
            envvar: if self.envvar.is_empty() {
                &[]
            } else {
                let mut result = bumpalo::collections::Vec::new_in(bump);
                for (key, value_expr) in self.envvar.iter() {
                    let value = value_expr.bump_eval(env, bump)?;
                    result.push((*key, value));
                }
                result.into_bump_slice()
            },
        })
    }
}

fn clone_requirement_for_eval<'a>(req: &Requirement<'static>) -> Requirement<'a> {
    match req {
        Requirement::Task(call) => {
            Requirement::Task(TaskCall { name: Alias(call.name.0), profile: call.profile, vars: call.vars.clone() })
        }
        Requirement::Resource { name, priority } => Requirement::Resource { name, priority: *priority },
    }
}

impl RequirementExpr<'static> {
    fn bump_eval_append<'a>(
        &self,
        env: &Environment,
        bump: &'a Bump,
        target: &mut bumpalo::collections::Vec<'a, Requirement<'a>>,
    ) -> Result<(), EvalError> {
        match self {
            RequirementExpr::Requirement(req) => {
                target.push(clone_requirement_for_eval(req));
                Ok(())
            }
            RequirementExpr::If(if_expr) => {
                if if_expr.cond.eval(env) {
                    if_expr.then.bump_eval_append(env, bump, target)
                } else if let Some(or_else) = &if_expr.or_else {
                    or_else.bump_eval_append(env, bump, target)
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl RequirementListExpr<'static> {
    fn bump_eval_append<'a>(
        &self,
        env: &Environment,
        bump: &'a Bump,
        target: &mut bumpalo::collections::Vec<'a, Requirement<'a>>,
    ) -> Result<(), EvalError> {
        for item in self.items {
            item.bump_eval_append(env, bump, target)?;
        }
        Ok(())
    }
}

impl<'a> BumpEval<'a> for RequirementListExpr<'static> {
    type Object = &'a [Requirement<'a>];

    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<Self::Object, EvalError> {
        if self.items.is_empty() {
            return Ok(&[]);
        }
        let mut result = bumpalo::collections::Vec::new_in(bump);
        self.bump_eval_append(env, bump, &mut result)?;
        if has_duplicate_resource(&result) {
            return Err(EvalError::DuplicateResource);
        }
        Ok(result.into_bump_slice())
    }
}

fn has_duplicate_resource(requirements: &[Requirement<'_>]) -> bool {
    for (i, req) in requirements.iter().enumerate() {
        let Requirement::Resource { name, .. } = req else { continue };
        for prior in &requirements[..i] {
            if let Requirement::Resource { name: prior_name, .. } = prior
                && prior_name == name
            {
                return true;
            }
        }
    }
    false
}

impl<'a> BumpEval<'a> for StringExpr<'static> {
    type Object = &'a str;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<&'a str, EvalError> {
        match self {
            StringExpr::Literal(s) => Ok(*s),
            StringExpr::Var(var_name) => env.var_str(var_name, bump),
            StringExpr::If(if_expr) => Ok(if_expr.bump_eval(env, bump)?),
        }
    }
}

impl<'a> BumpEval<'a> for StringListExpr<'static> {
    type Object = &'a [&'a str];
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<&'a [&'a str], EvalError> {
        match self {
            StringListExpr::List([StringListExpr::Literal(s)]) => Ok(std::slice::from_ref(s)),
            _ => {
                let mut result = bumpalo::collections::Vec::new_in(bump);
                eval_append_str(self, env, bump, &mut result)?;
                Ok(result.into_bump_slice())
            }
        }
    }
}

fn append_value<'a>(
    value: &Value<'_>,
    bump: &'a Bump,
    target: &mut bumpalo::collections::Vec<&'a str>,
) -> Result<(), EvalError> {
    match value.as_ref() {
        ValueRef::Null(_) => (),
        ValueRef::Number(value_number) => {
            target.push(bump.alloc_str(&value_number.to_string()));
        }
        ValueRef::String(value_string) | ValueRef::Other(value_string) => {
            target.push(bump.alloc_str(value_string));
        }
        ValueRef::Map(_) => return Err(EvalError::Todo),
        ValueRef::List(list) => {
            for item in list {
                append_value(item, bump, target)?;
            }
        }
        ValueRef::Boolean(value_boolean) => {
            if *value_boolean == true {
                target.push("true");
            } else {
                target.push("false");
            }
        }
    }
    Ok(())
}

fn eval_append_str<'a>(
    expr: &StringListExpr<'static>,
    env: &Environment,
    bump: &'a Bump,
    target: &mut bumpalo::collections::Vec<&'a str>,
) -> Result<(), EvalError> {
    use StringListExpr as Expr;
    match expr {
        Expr::Literal(value) => target.push(value),
        Expr::List(string_list_exprs) => {
            for item in string_list_exprs.iter() {
                eval_append_str(item, env, bump, target)?;
            }
        }
        Expr::Var(key) => return env.var_append(key, bump, target),
        Expr::If(branch) => {
            if branch.cond.eval(env) {
                eval_append_str(&branch.then, env, bump, target)?;
            } else if let Some(or_else) = &branch.or_else {
                eval_append_str(or_else, env, bump, target)?;
            }
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Predicate<'a> {
    Profile(&'a str),
}
impl<'a> Predicate<'a> {
    fn visit_profiles(&self, f: &mut impl FnMut(&'a str)) {
        match self {
            Predicate::Profile(p) => f(p),
        }
    }

    fn eval_profile(&self, profile: &str) -> bool {
        match self {
            Predicate::Profile(p) => *p == profile,
        }
    }

    fn eval(&self, env: &Environment) -> bool {
        self.eval_profile(env.profile)
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct If<'a, T> {
    cond: Predicate<'a>,
    then: T,
    or_else: Option<T>,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum StringExpr<'a> {
    Literal(&'a str),
    Var(&'a str),
    If(&'a If<'a, StringExpr<'a>>),
}
impl<'a, T: BumpEval<'a>> BumpEval<'a> for If<'a, T> {
    type Object = T::Object;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<Self::Object, EvalError> {
        match &self.cond {
            Predicate::Profile(p) => {
                if *p == env.profile {
                    self.then.bump_eval(env, bump)
                } else if let Some(or_else) = &self.or_else {
                    or_else.bump_eval(env, bump)
                } else {
                    Err(EvalError::EmptyBranch)
                }
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum StringListExpr<'a> {
    Literal(&'a str),
    List(&'a [StringListExpr<'a>]),
    Var(&'a str),
    If(&'a If<'a, StringListExpr<'a>>),
}

pub trait BumpEval<'a> {
    type Object: Sized;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<Self::Object, EvalError>;
}

fn collect_string_expr_vars(expr: &StringExpr<'static>, out: &mut Vec<&'static str>) {
    match expr {
        StringExpr::Literal(_) => {}
        StringExpr::Var(name) => {
            if !name.starts_with('$') && !out.contains(name) {
                out.push(name);
            }
        }
        StringExpr::If(if_expr) => {
            collect_string_expr_vars(&if_expr.then, out);
            if let Some(or_else) = &if_expr.or_else {
                collect_string_expr_vars(or_else, out);
            }
        }
    }
}

fn collect_string_list_expr_vars(expr: &StringListExpr<'static>, out: &mut Vec<&'static str>) {
    match expr {
        StringListExpr::Literal(_) => {}
        StringListExpr::Var(name) => {
            if !name.starts_with('$') && !out.contains(name) {
                out.push(name);
            }
        }
        StringListExpr::List(items) => {
            for item in *items {
                collect_string_list_expr_vars(item, out);
            }
        }
        StringListExpr::If(if_expr) => {
            collect_string_list_expr_vars(&if_expr.then, out);
            if let Some(or_else) = &if_expr.or_else {
                collect_string_list_expr_vars(or_else, out);
            }
        }
    }
}

impl TaskConfigExpr<'static> {
    /// Collects all variable names referenced in this task configuration.
    ///
    /// Traverses the `pwd`, `command`, and `envvar` expressions to find all
    /// `Var(name)` references, including those inside `If` branches.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let vars = CARGO_AUTO_EXPR.collect_variables();
    /// assert!(vars.contains(&"pwd"));
    /// assert!(vars.contains(&"args"));
    /// ```
    pub fn collect_variables(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        collect_string_expr_vars(&self.pwd, &mut out);
        match &self.command {
            CommandExpr::Cmd(list_expr) => collect_string_list_expr_vars(list_expr, &mut out),
            CommandExpr::Sh(str_expr) => collect_string_expr_vars(str_expr, &mut out),
        }
        for (_key, value_expr) in self.envvar {
            collect_string_expr_vars(value_expr, &mut out);
        }
        out
    }

    /// Returns a short preview of the command for display purposes.
    ///
    /// For `cmd` style commands, returns the first literal argument (usually the binary name).
    /// For `sh` style commands, returns the first non-comment line of the shell script.
    pub fn command_preview(&self) -> &'static str {
        match &self.command {
            CommandExpr::Cmd(list_expr) => first_literal_from_list(list_expr).unwrap_or(""),
            CommandExpr::Sh(str_expr) => first_literal_from_string(str_expr).unwrap_or(""),
        }
    }

    /// Returns the literal command prefix used when forwarding shell completions.
    ///
    /// The prefix stops at the first dynamic command component. For example,
    /// `["git", "checkout", { var = "args" }]` returns `["git", "checkout"]`.
    pub fn autocomplete_forward_prefix(&self) -> Option<Vec<&'static str>> {
        if !matches!(self.cli.autocomplete, CliAutocomplete::Forward) {
            return None;
        }

        let CommandExpr::Cmd(list_expr) = &self.command else {
            return None;
        };

        let mut prefix = Vec::new();
        collect_literal_prefix_from_list(list_expr, &mut prefix);
        if prefix.is_empty() { None } else { Some(prefix) }
    }

    /// Evaluates only the task working directory for completion-time behavior.
    pub fn eval_pwd(&self, env: &Environment) -> Result<String, EvalError> {
        let bump = Bump::new();
        Ok(self.pwd.bump_eval(env, &bump)?.to_string())
    }
}

fn collect_literal_prefix_from_list(expr: &StringListExpr<'static>, out: &mut Vec<&'static str>) -> bool {
    match expr {
        StringListExpr::Literal(s) => {
            out.push(s);
            true
        }
        StringListExpr::List(items) => {
            for item in *items {
                if !collect_literal_prefix_from_list(item, out) {
                    return false;
                }
            }
            true
        }
        StringListExpr::Var(_) | StringListExpr::If(_) => false,
    }
}

fn first_literal_from_list(expr: &StringListExpr<'static>) -> Option<&'static str> {
    match expr {
        StringListExpr::Literal(s) => Some(s),
        StringListExpr::List(items) => {
            for item in *items {
                if let Some(lit) = first_literal_from_list(item) {
                    return Some(lit);
                }
            }
            None
        }
        StringListExpr::Var(_) => None,
        StringListExpr::If(if_expr) => first_literal_from_list(&if_expr.then)
            .or_else(|| if_expr.or_else.as_ref().and_then(first_literal_from_list)),
    }
}

fn first_literal_from_string(expr: &StringExpr<'static>) -> Option<&'static str> {
    match expr {
        StringExpr::Literal(s) => shell_preview_line(s),
        StringExpr::Var(_) => None,
        StringExpr::If(if_expr) => first_literal_from_string(&if_expr.then)
            .or_else(|| if_expr.or_else.as_ref().and_then(first_literal_from_string)),
    }
}

fn shell_preview_line(script: &'static str) -> Option<&'static str> {
    script.lines().map(str::trim).find(|line| !line.is_empty() && !line.starts_with('#'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsony_value::ValueMap;

    #[test]
    fn cargo_auto_expr_collects_pwd_and_args() {
        let vars = CARGO_AUTO_EXPR.collect_variables();
        assert!(vars.contains(&"pwd"), "should find pwd variable: {:?}", vars);
        assert!(vars.contains(&"args"), "should find args variable: {:?}", vars);
        assert_eq!(vars.len(), 2, "should have exactly 2 variables: {:?}", vars);
    }

    #[test]
    fn collect_variables_deduplicates() {
        static TEST_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Var("dup"),
            command: CommandExpr::Cmd(StringListExpr::List(&[
                StringListExpr::Var("dup"),
                StringListExpr::Var("other"),
            ])),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig::DEFAULT,
            vars: &[],
        };
        let vars = TEST_EXPR.collect_variables();
        assert_eq!(vars.iter().filter(|&&v| v == "dup").count(), 1, "dup should appear once");
        assert!(vars.contains(&"other"), "should contain other");
    }

    #[test]
    fn collect_variables_traverses_if_branches() {
        static IF_BRANCH: If<'static, StringListExpr<'static>> = If {
            cond: Predicate::Profile("prod"),
            then: StringListExpr::Var("then_var"),
            or_else: Some(StringListExpr::Var("else_var")),
        };
        static TEST_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Literal("./"),
            command: CommandExpr::Cmd(StringListExpr::If(&IF_BRANCH)),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig::DEFAULT,
            vars: &[],
        };
        let vars = TEST_EXPR.collect_variables();
        assert!(vars.contains(&"then_var"), "should find then_var: {:?}", vars);
        assert!(vars.contains(&"else_var"), "should find else_var: {:?}", vars);
    }

    #[test]
    fn special_var_profile_resolves_in_string_expr() {
        let bump = Bump::new();
        let env = Environment { profile: "production", param: ValueMap::new(), vars: &[] };
        let expr = StringExpr::Var("$profile");
        let result = expr.bump_eval(&env, &bump).unwrap();
        assert_eq!(result, "production");
    }

    #[test]
    fn special_var_profile_resolves_in_string_list_expr() {
        let bump = Bump::new();
        let env = Environment { profile: "staging", param: ValueMap::new(), vars: &[] };
        let expr = StringListExpr::List(&[StringListExpr::Literal("echo"), StringListExpr::Var("$profile")]);
        let result = expr.bump_eval(&env, &bump).unwrap();
        assert_eq!(result, &["echo", "staging"]);
    }

    #[test]
    fn collect_variables_excludes_special_vars() {
        static TEST_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Var("$profile"),
            command: CommandExpr::Cmd(StringListExpr::List(&[
                StringListExpr::Literal("echo"),
                StringListExpr::Var("$profile"),
                StringListExpr::Var("user_var"),
            ])),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig::DEFAULT,
            vars: &[],
        };
        let vars = TEST_EXPR.collect_variables();
        assert!(!vars.contains(&"$profile"), "should exclude $profile: {:?}", vars);
        assert!(vars.contains(&"user_var"), "should include user_var: {:?}", vars);
        assert_eq!(vars.len(), 1);
    }

    // A Map appended to a string-list var must return `EvalError` rather than
    // panic: eval runs under `state.write()`, where a panic poisons the lock and
    // bricks the daemon for every client.
    #[test]
    fn map_valued_list_var_surfaces_eval_error_without_panicking() {
        static TEST_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Literal("./"),
            command: CommandExpr::Cmd(StringListExpr::List(&[
                StringListExpr::Literal("echo"),
                StringListExpr::Var("mapvar"),
            ])),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig::DEFAULT,
            vars: &[],
        };

        let param =
            jsony::from_json::<ValueMap>(r#"{ "mapvar": { "nested": "value" } }"#).expect("valid params").to_owned();
        let env = Environment { profile: "", param, vars: &[] };

        assert!(TEST_EXPR.eval(&env).is_err(), "expected eval error, got Ok");
    }

    #[test]
    fn autocomplete_forward_prefix_returns_static_command_prefix() {
        static TEST_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Literal("./"),
            command: CommandExpr::Cmd(StringListExpr::List(&[
                StringListExpr::Literal("git"),
                StringListExpr::Literal("checkout"),
                StringListExpr::Var("args"),
                StringListExpr::Literal("--ignored-after-args"),
            ])),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig { forward_arguments: true, autocomplete: CliAutocomplete::Forward },
            vars: &[],
        };

        assert_eq!(TEST_EXPR.autocomplete_forward_prefix(), Some(vec!["git", "checkout"]));
    }

    #[test]
    fn autocomplete_forward_prefix_requires_forward_mode_and_cmd() {
        static DEFAULT_CLI_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Literal("./"),
            command: CommandExpr::Cmd(StringListExpr::List(&[
                StringListExpr::Literal("git"),
                StringListExpr::Var("args"),
            ])),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig::DEFAULT,
            vars: &[],
        };
        static SHELL_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Literal("./"),
            command: CommandExpr::Sh(StringExpr::Literal("git checkout \"$@\"")),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig { forward_arguments: true, autocomplete: CliAutocomplete::Forward },
            vars: &[],
        };

        assert_eq!(DEFAULT_CLI_EXPR.autocomplete_forward_prefix(), None);
        assert_eq!(SHELL_EXPR.autocomplete_forward_prefix(), None);
    }

    #[test]
    fn shell_command_preview_uses_first_non_comment_line() {
        static TEST_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Literal("./"),
            command: CommandExpr::Sh(StringExpr::Literal(
                r#"
                    # Setup
                    COMMAND="cargo run"
                    cargo test
                "#,
            )),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig::DEFAULT,
            vars: &[],
        };

        assert_eq!(TEST_EXPR.command_preview(), r#"COMMAND="cargo run""#);
    }

    #[test]
    fn shell_command_preview_is_empty_for_empty_or_comment_only_script() {
        static TEST_EXPR: TaskConfigExpr<'static> = TaskConfigExpr {
            kind: TaskKind::Action,
            info: "",
            pwd: StringExpr::Literal("./"),
            command: CommandExpr::Sh(StringExpr::Literal(
                r#"
                    # Setup
                    # More setup
                "#,
            )),
            profiles: &[],
            envvar: &[],
            require: EMPTY_REQUIREMENT_EXPRS,
            cache: None,
            ready: None,
            timeout: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
            allow_multiple: AllowMultiple::False,
            cli: CliConfig::DEFAULT,
            vars: &[],
        };

        assert_eq!(TEST_EXPR.command_preview(), "");
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("10s").unwrap(), 10.0);
        assert_eq!(parse_duration("5m").unwrap(), 300.0);
        assert_eq!(parse_duration("2h").unwrap(), 7200.0);
        assert_eq!(parse_duration("1d").unwrap(), 86400.0);
        assert_eq!(parse_duration("1.5m").unwrap(), 90.0);
        assert_eq!(parse_duration("30").unwrap(), 30.0);
        assert_eq!(parse_duration(" 10s ").unwrap(), 10.0);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-5s").is_err());
    }
}
