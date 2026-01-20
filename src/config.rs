use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::bail;
use bumpalo::Bump;
use jsony::Jsony;
use jsony_value::{Value, ValueMap, ValueRef};

use crate::diagnostic::{Diagnostic, emit_diagnostic, render_diagnostic};

pub mod toml_handler;

pub fn emit_config_error(file_name: &str, content: &str, diagnostic: &Diagnostic) {
    emit_diagnostic(file_name, content, diagnostic);
}

pub fn format_config_error(file_name: &str, content: &str, diagnostic: &Diagnostic) -> String {
    render_diagnostic(file_name, content, diagnostic)
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Alias<'a>(&'a str);
impl<'a> std::ops::Deref for Alias<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug)]
pub struct TaskCall<'a> {
    pub name: Alias<'a>,
    pub profile: Option<&'a str>,
    /// todo this leaks when bump allows because ValueMap allocates globally
    pub vars: ValueMap<'a>,
}

/// Empty slice of task calls, used as default for require field.
pub static EMPTY_TASK_CALLS: &[TaskCall<'static>] = &[];

#[derive(Clone, Copy, PartialEq, Eq, Debug, Jsony)]
#[jsony(rename_all = "snake_case")]
pub enum TaskKind {
    Service,
    Action,
    Test,
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

/// A single cache key input that contributes to cache invalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheKeyInput<'a> {
    /// Invalidate cache when the file's modification time changes.
    Modified(&'a str),
    /// Invalidate cache when the referenced task's profile changes.
    ProfileChanged(&'a str),
}

/// Cache configuration for actions. When present, the action's result
/// is cached for the session - it won't re-run via `require` if the
/// last non-cancelled run was successful.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheConfig<'a> {
    /// Cache key inputs that determine when the cache should be invalidated.
    /// Empty means no key-based invalidation (simple success-based caching).
    pub key: &'a [CacheKeyInput<'a>],
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
#[derive(Clone)]
pub struct TaskConfigRc(Arc<(TaskConfig<'static>, Bump)>);
unsafe impl Send for TaskConfigRc {}
unsafe impl Sync for TaskConfigRc {}

impl TaskConfigRc {
    pub fn config<'a>(&'a self) -> &'a TaskConfig<'a> {
        unsafe { std::mem::transmute::<&'a TaskConfig<'static>, &'a TaskConfig<'a>>(&self.0.0) }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command<'a> {
    Cmd(&'a [&'a str]),
    Sh(&'a str),
}

#[derive(Clone, Debug)]
pub struct TaskConfig<'a> {
    pub pwd: &'a str,
    pub command: Command<'a>,
    pub envvar: &'a [(&'a str, &'a str)],
    pub require: &'a [TaskCall<'a>],
    pub cache: Option<CacheConfig<'a>>,
    pub ready: Option<ReadyConfig<'a>>,
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
    let bump = Box::leak(Box::new(Bump::new()));
    let base_path = Box::leak(Box::new(base_path.to_path_buf()));
    let file_name = config_path.display().to_string();
    let mut had_error = false;
    match toml_handler::parse(base_path, bump, content, &mut |diagnostic| {
        emit_config_error(&file_name, content, &diagnostic);
        had_error = true;
    }) {
        Ok(value) => Ok(value),
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

pub fn load_workspace_config_capturing(
    config_path: &Path,
    content: &'static str,
) -> Result<WorkspaceConfig<'static>, ConfigError> {
    let bump = Box::leak(Box::new(Bump::new()));
    let base_path = config_path.parent().unwrap_or(Path::new("."));
    let base_path = Box::leak(Box::new(base_path.to_path_buf()));
    let file_name = config_path.display().to_string();
    let mut errors = String::new();
    match toml_handler::parse(base_path, bump, content, &mut |diagnostic| {
        errors.push_str(&format_config_error(&file_name, content, &diagnostic));
    }) {
        Ok(value) => Ok(value),
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
    /// Tests stored as (name, variants) where variants is an array of test configs.
    /// Single tests `[test.name]` have one variant, arrays `[[test.name]]` have multiple.
    pub tests: &'a [(&'a str, &'a [TestConfigExpr<'a>])],
    pub groups: &'a [(&'a str, &'a [TaskCall<'a>])],
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
    pub require: &'a [TaskCall<'a>],
    pub cache: Option<CacheConfig<'a>>,
    pub ready: Option<ReadyConfig<'a>>,
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
}

/// Test configuration expression (parsed form, not yet evaluated).
#[derive(Debug)]
pub struct TestConfigExpr<'a> {
    pub info: &'a str,
    pub pwd: StringExpr<'a>,
    command: CommandExpr<'a>,
    envvar: &'a [(&'a str, StringExpr<'a>)],
    pub require: &'a [TaskCall<'a>],
    pub tags: &'a [&'a str],
    pub cache: Option<CacheConfig<'a>>,
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
            tags: self.tags,
            managed: None,
            hidden: ServiceHidden::Never,
        }))
    }
}

pub static CARGO_AUTO_EXPR: TaskConfigExpr<'static> = {
    TaskConfigExpr {
        kind: TaskKind::Action,
        info: "Default Expression for Cargo Innvocations",
        pwd: StringExpr::Var("pwd"),
        command: CommandExpr::Cmd(StringListExpr::List(&[
            StringListExpr::Literal("cargo"),
            StringListExpr::Var("args"),
        ])),
        profiles: &["default"],
        envvar: &[],
        require: EMPTY_TASK_CALLS,
        cache: None,
        ready: None,
        tags: &[],
        managed: None,
        hidden: ServiceHidden::Never,
    }
};

pub struct Environment<'a> {
    pub profile: &'a str,
    pub param: jsony_value::ValueMap<'a>,
}

#[derive(Debug)]
pub enum EvalError {
    Todo,
    EmptyBranch,
}

impl TaskConfigExpr<'static> {
    pub fn eval(&self, env: &Environment) -> Result<TaskConfigRc, EvalError> {
        #[allow(clippy::arc_with_non_send_sync)]
        let mut new = Arc::new((
            TaskConfig { pwd: "", command: Command::Cmd(&[]), require: &[], cache: None, ready: None, envvar: &[] },
            Bump::new(),
        ));
        let alloc = Arc::get_mut(&mut new).unwrap();
        {
            let env = self.bump_eval(env, &alloc.1)?;
            unsafe {
                alloc.0 = std::mem::transmute::<TaskConfig<'_>, TaskConfig<'static>>(env);
            }
        }

        Ok(TaskConfigRc(new))
    }
}

impl<'a> BumpEval<'a> for CommandExpr<'static> {
    type Object = Command<'a>;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<Command<'a>, EvalError> {
        Ok(match self {
            CommandExpr::Cmd(cmd_expr) => Command::Cmd(cmd_expr.bump_eval(env, bump)?),
            CommandExpr::Sh(sh_expr) => Command::Sh(sh_expr.bump_eval(env, bump)?),
        })
    }
}

impl<'a> BumpEval<'a> for TaskConfigExpr<'static> {
    type Object = TaskConfig<'a>;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<TaskConfig<'a>, EvalError> {
        Ok(TaskConfig {
            pwd: self.pwd.bump_eval(env, bump)?,
            command: self.command.bump_eval(env, bump)?,
            require: self.require,
            cache: self.cache.clone(),
            ready: self.ready.clone(),
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

impl<'a> BumpEval<'a> for StringExpr<'static> {
    type Object = &'a str;
    fn bump_eval(&self, env: &Environment, bump: &'a Bump) -> Result<&'a str, EvalError> {
        match self {
            StringExpr::Literal(s) => Ok(*s),
            StringExpr::Var(var_name) => match env.param[*var_name].as_ref() {
                ValueRef::String(value_string) | ValueRef::Other(value_string) => Ok(bump.alloc_str(value_string)),
                _ => Err(EvalError::Todo),
            },
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
                eval_append_str(self, env, bump, &mut result);
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
) {
    use StringListExpr as Expr;
    match expr {
        Expr::Literal(value) => target.push(value),
        Expr::List(string_list_exprs) => {
            for item in string_list_exprs.iter() {
                eval_append_str(item, env, bump, target);
            }
        }
        Expr::Var(key) => append_value(&env.param[key], bump, target).unwrap(),
        Expr::If(branch) => {
            if branch.cond.eval(env) {
                eval_append_str(&branch.then, env, bump, target);
            } else if let Some(or_else) = &branch.or_else {
                eval_append_str(or_else, env, bump, target);
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Predicate<'a> {
    Profile(&'a str),
}
impl<'a> Predicate<'a> {
    fn eval(&self, env: &Environment) -> bool {
        match self {
            Predicate::Profile(p) => *p == env.profile,
        }
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
            if !out.contains(name) {
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
            if !out.contains(name) {
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
    /// For `sh` style commands, returns a truncated prefix of the shell script.
    pub fn command_preview(&self) -> &'static str {
        match &self.command {
            CommandExpr::Cmd(list_expr) => first_literal_from_list(list_expr).unwrap_or(""),
            CommandExpr::Sh(str_expr) => first_literal_from_string(str_expr).unwrap_or(""),
        }
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
        StringExpr::Literal(s) => {
            let s = s.trim();
            if s.is_empty() { None } else { Some(s) }
        }
        StringExpr::Var(_) => None,
        StringExpr::If(if_expr) => first_literal_from_string(&if_expr.then)
            .or_else(|| if_expr.or_else.as_ref().and_then(first_literal_from_string)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            require: EMPTY_TASK_CALLS,
            cache: None,
            ready: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
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
            require: EMPTY_TASK_CALLS,
            cache: None,
            ready: None,
            tags: &[],
            managed: None,
            hidden: ServiceHidden::Never,
        };
        let vars = TEST_EXPR.collect_variables();
        assert!(vars.contains(&"then_var"), "should find then_var: {:?}", vars);
        assert!(vars.contains(&"else_var"), "should find else_var: {:?}", vars);
    }
}
