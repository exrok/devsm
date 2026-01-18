use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::bail;
use bumpalo::Bump;
use jsony::Jsony;
use jsony_value::{Value, ValueMap, ValueRef};

pub mod toml_handler;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Alias<'a>(&'a str);
impl<'a> std::ops::Deref for Alias<'a> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct TaskCall<'a> {
    pub name: Alias<'a>,
    pub profile: Option<&'a str>,
    /// todo this leaks when bump allows because ValueMap allocates globally
    pub vars: ValueMap<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Jsony)]
#[jsony(rename_all = "snake_case")]
pub enum TaskKind {
    Service,
    Action,
    Test,
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TaskConfig<'a> {
    pub kind: TaskKind,
    pub pwd: &'a str,
    pub command: Command<'a>,
    pub profiles: &'a [&'a str],
    pub envvar: &'a [(&'a str, &'a str)],
    pub require: &'a [Alias<'a>],
    pub cache: Option<CacheConfig<'a>>,
}

/// Evaluated test configuration (runtime form).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TestConfig<'a> {
    pub pwd: &'a str,
    pub command: Command<'a>,
    pub envvar: &'a [(&'a str, &'a str)],
    pub require: &'a [Alias<'a>],
    pub tags: &'a [&'a str],
    pub cache: Option<CacheConfig<'a>>,
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
            let content = std::fs::read_to_string(&pwd)?.leak();
            pwd.pop();
            return load_workspace_config_leaking(&pwd, content);
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

pub fn load_workspace_config_leaking(
    base_path: &Path,
    content: &'static str,
) -> anyhow::Result<WorkspaceConfig<'static>> {
    let bump = Box::leak(Box::new(Bump::new()));
    // todo put in the bump allocator
    let base_path = Box::leak(Box::new(base_path.to_path_buf()));
    match toml_handler::parse(base_path, bump, content, &mut |err| {
        println!("{:#?}", err);
    }) {
        Ok(value) => Ok(value),
        Err(_) => bail!("Failed to parse config"),
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
    pwd: StringExpr<'a>,
    command: CommandExpr<'a>,
    pub profiles: &'a [&'a str],
    envvar: &'a [(&'a str, StringExpr<'a>)],
    require: AliasListExpr<'a>,
    pub cache: Option<CacheConfig<'a>>,
    /// Tags for test filtering. Empty for non-test tasks.
    pub tags: &'a [&'a str],
}

/// Test configuration expression (parsed form, not yet evaluated).
#[derive(Debug)]
pub struct TestConfigExpr<'a> {
    pub info: &'a str,
    pwd: StringExpr<'a>,
    command: CommandExpr<'a>,
    envvar: &'a [(&'a str, StringExpr<'a>)],
    require: AliasListExpr<'a>,
    pub tags: &'a [&'a str],
    pub cache: Option<CacheConfig<'a>>,
}

impl TestConfigExpr<'static> {
    /// Converts this test config to a TaskConfigExpr with kind=Test.
    /// The result is leaked and valid for 'static lifetime.
    pub fn to_task_config_expr(&self) -> &'static TaskConfigExpr<'static> {
        Box::leak(Box::new(TaskConfigExpr {
            kind: TaskKind::Test,
            info: self.info,
            pwd: self.pwd.clone(),
            command: self.command.clone(),
            profiles: &[],
            envvar: self.envvar,
            require: self.require.clone(),
            cache: self.cache.clone(),
            tags: self.tags,
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
        require: AliasListExpr::List(&[]),
        cache: None,
        tags: &[],
    }
};

pub struct Enviroment<'a> {
    pub profile: &'a str,
    pub param: jsony_value::ValueMap<'a>,
}

#[derive(Debug)]
pub enum EvalError {
    Todo,
    EmptyBranch,
}

impl TaskConfigExpr<'static> {
    pub fn eval(&self, env: &Enviroment) -> Result<TaskConfigRc, EvalError> {
        let mut new = Arc::new((
            TaskConfig {
                kind: TaskKind::Action,
                pwd: "",
                command: Command::Cmd(&[]),
                require: &[],
                cache: None,
                profiles: &[],
                envvar: &[],
            },
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
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<Command<'a>, EvalError> {
        Ok(match self {
            CommandExpr::Cmd(cmd_expr) => Command::Cmd(cmd_expr.bump_eval(env, bump)?),
            CommandExpr::Sh(sh_expr) => Command::Sh(sh_expr.bump_eval(env, bump)?),
        })
    }
}

impl<'a> BumpEval<'a> for TaskConfigExpr<'static> {
    type Object = TaskConfig<'a>;
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<TaskConfig<'a>, EvalError> {
        Ok(TaskConfig {
            kind: self.kind,
            pwd: self.pwd.bump_eval(env, bump)?,
            command: self.command.bump_eval(env, bump)?,
            require: self.require.bump_eval(env, bump)?,
            cache: self.cache.clone(),
            profiles: self.profiles,
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

impl<'a> BumpEval<'a> for TestConfigExpr<'static> {
    type Object = TestConfig<'a>;
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<TestConfig<'a>, EvalError> {
        Ok(TestConfig {
            pwd: self.pwd.bump_eval(env, bump)?,
            command: self.command.bump_eval(env, bump)?,
            require: self.require.bump_eval(env, bump)?,
            tags: self.tags,
            cache: self.cache.clone(),
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
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<&'a str, EvalError> {
        match self {
            StringExpr::Literal(s) => Ok(*s),
            StringExpr::Var(var_name) => match env.param[*var_name].as_ref() {
                ValueRef::String(value_string) | ValueRef::Other(value_string) => Ok(bump.alloc_str(&value_string)),
                _ => Err(EvalError::Todo),
            },
            StringExpr::If(if_expr) => Ok(if_expr.bump_eval(env, bump)?),
        }
    }
}

impl<'a> BumpEval<'a> for AliasListExpr<'static> {
    type Object = &'a [Alias<'a>];
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<&'a [Alias<'a>], EvalError> {
        match self {
            AliasListExpr::List([AliasListExpr::Literal(s)]) => Ok(std::slice::from_ref(s)),
            _ => {
                let mut result = bumpalo::collections::Vec::new_in(bump);
                eval_append_alias(self, env, bump, &mut result);
                Ok(result.into_bump_slice())
            }
        }
    }
}
impl<'a> BumpEval<'a> for StringListExpr<'static> {
    type Object = &'a [&'a str];
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<&'a [&'a str], EvalError> {
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

fn eval_append_alias<'a>(
    expr: &AliasListExpr<'static>,
    env: &Enviroment,
    bump: &'a Bump,
    target: &mut bumpalo::collections::Vec<Alias<'a>>,
) {
    use AliasListExpr as Expr;
    match expr {
        Expr::Literal(value) => target.push(*value),
        Expr::List(string_list_exprs) => {
            for item in string_list_exprs.iter() {
                eval_append_alias(item, env, bump, target);
            }
        }
        Expr::If(branch) => {
            if branch.cond.eval(env) {
                eval_append_alias(&branch.then, env, bump, target);
            } else if let Some(or_else) = &branch.or_else {
                eval_append_alias(or_else, env, bump, target);
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
            target.push(bump.alloc_str(&value_string));
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
    env: &Enviroment,
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
    fn eval(&self, env: &Enviroment) -> bool {
        match self {
            Predicate::Profile(p) => *p == env.profile,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct If<'a, T> {
    cond: Predicate<'a>,
    then: T,
    or_else: Option<T>,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum StringExpr<'a> {
    Literal(&'a str),
    Var(&'a str),
    If(&'a If<'a, StringExpr<'a>>),
}
impl<'a, T: BumpEval<'a>> BumpEval<'a> for If<'a, T> {
    type Object = T::Object;
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<Self::Object, EvalError> {
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

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum AliasListExpr<'a> {
    Literal(Alias<'a>),
    List(&'a [AliasListExpr<'a>]),
    If(&'a If<'a, AliasListExpr<'a>>),
}

pub trait BumpEval<'a> {
    type Object: Sized;
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<Self::Object, EvalError>;
}
