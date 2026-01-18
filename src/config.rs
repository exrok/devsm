use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::bail;
use bumpalo::Bump;
use jsony::Jsony;
use jsony_value::{Value, ValueMap, ValueRef};

use crate::config::template_string::TemplatePart;
mod template_string;
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
    pub before: &'a [Alias<'a>],
    pub before_once: &'a [Alias<'a>],
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
    match toml_handler::parse(bump, content, &mut |_| ()) {
        Ok(value) => Ok(value),
        Err(_) => bail!("Failed to parse config"),
    }
}

#[derive(Debug)]
pub struct WorkspaceConfig<'a> {
    pub base_path: &'a Path,
    pub tasks: &'a [(&'a str, TaskConfigExpr<'a>)],
    pub groups: &'a [(&'a str, &'a [TaskCall<'a>])],
}

#[derive(Debug)]
enum CommandExpr<'a> {
    Cmd(StringListExpr<'a>),
    Sh(StringExpr<'a>),
}

#[derive(Debug)]
pub struct TaskConfigExpr<'a> {
    pub kind: TaskKind,
    info: &'a str,
    pwd: StringExpr<'a>,
    command: CommandExpr<'a>,
    pub profiles: &'a [&'a str],
    envvar: &'a [(&'a str, StringExpr<'a>)],
    before: AliasListExpr<'a>,
    before_once: AliasListExpr<'a>,
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
        before: AliasListExpr::List(&[]),
        before_once: AliasListExpr::List(&[]),
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
                before: &[],
                before_once: &[],
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
            before: self.before.bump_eval(env, bump)?,
            before_once: self.before_once.bump_eval(env, bump)?,
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
            StringExpr::TemplateLiteral(parts) => {
                let mut result = bumpalo::collections::String::new_in(bump);
                for part in *parts {
                    match part {
                        TemplatePart::Lit(s) => result.push_str(s),
                        TemplatePart::Var(var_name) => match env.param[*var_name].as_ref() {
                            ValueRef::String(value_string) | ValueRef::Other(value_string) => {
                                result.push_str(&value_string);
                            }
                            _ => return Err(EvalError::Todo),
                        },
                    }
                }
                Ok(result.into_bump_str())
            }
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

#[derive(PartialEq, Eq, Debug)]
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

#[derive(PartialEq, Eq, Debug)]
struct If<'a, T> {
    cond: Predicate<'a>,
    then: T,
    or_else: Option<T>,
}

#[derive(PartialEq, Eq, Debug)]
enum StringExpr<'a> {
    Literal(&'a str),
    Var(&'a str),
    If(&'a If<'a, StringExpr<'a>>),
    TemplateLiteral(&'a [TemplatePart<'a>]),
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

#[derive(PartialEq, Eq, Debug)]
enum StringListExpr<'a> {
    Literal(&'a str),
    List(&'a [StringListExpr<'a>]),
    Var(&'a str),
    If(&'a If<'a, StringListExpr<'a>>),
}

#[derive(PartialEq, Eq, Debug)]
enum AliasListExpr<'a> {
    Literal(Alias<'a>),
    List(&'a [AliasListExpr<'a>]),
    If(&'a If<'a, AliasListExpr<'a>>),
}

pub trait BumpEval<'a> {
    type Object: Sized;
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<Self::Object, EvalError>;
}
