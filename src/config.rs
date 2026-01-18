use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use bumpalo::Bump;
use jsony::{
    FromJson, Jsony,
    json::{DecodeError, Parser, Peek},
};
use jsony_value::{Value, ValueMap, ValueRef};

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

impl<'a> BumpJsonDecode<'a> for TaskCall<'a> {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError> {
        match parser.peek()? {
            Peek::Array => {
                let start = parser.at.enter_array()?;
                let Some(first) = start else {
                    return Err(&DecodeError { message: "Expected atleast the name" });
                };
                let name;
                let mut profile = None::<&str>;
                match first {
                    Peek::String => {
                        let sname = <&str>::decode(parser, bump)?;
                        if let Some((sname, sprofile)) = sname.rsplit_once(':') {
                            name = Alias(sname);
                            profile = Some(sprofile);
                        } else {
                            name = Alias(sname);
                        }
                    }
                    _ => name = Alias::decode(parser, bump)?,
                }
                let vars = if let Some(_) = parser.at.array_step()? {
                    ValueMap::decode_json(parser)?
                } else {
                    ValueMap::new()
                };
                if parser.at.array_step()?.is_some() {
                    return Err(&DecodeError { message: "Extra item found in task innovcation list" });
                }
                Ok(TaskCall { name, profile, vars })
            }
            Peek::String => {
                let name = <&str>::decode(parser, bump)?;
                if let Some((name, profile)) = name.rsplit_once(':') {
                    Ok(TaskCall { name: Alias(name), profile: Some(profile), vars: ValueMap::new() })
                } else {
                    Ok(TaskCall { name: Alias(name), profile: None, vars: ValueMap::new() })
                }
            }
            _ => {
                let name = Alias::decode(parser, bump)?;
                Ok(TaskCall { name, profile: None, vars: ValueMap::new() })
            }
        }
    }
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

pub fn split_once(this: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let index = this.iter().position(|pred| byte == *pred)?;
    Some((&this[..index], &this[index + 1..]))
}
fn next_const(parser: &mut Parser<'static>) -> Option<&'static str> {
    let bytes = parser.at.ctx.as_bytes();
    let index = parser.at.index;
    let prefix = bytes.get(index..)?;
    if let Some(prefix) = prefix.strip_prefix(b"let ") {
        let (key, _) = split_once(prefix, b'=')?;
        parser.at.index += 4 + key.len() + 1;
        return Some(unsafe { std::str::from_utf8_unchecked(key.trim_ascii()) });
    }

    if let Some(index) = memchr::memmem::find(prefix, b"\nlet ") {
        let after_const = &prefix[index + 1 + 3..];
        let (key, _) = split_once(after_const, b'=')?;
        parser.at.index += index + 1 + 3 + key.len() + 1;
        return Some(unsafe { std::str::from_utf8_unchecked(key.trim_ascii()) });
    }
    None
}
pub fn find_config_path_from(path: &Path) -> Option<PathBuf> {
    let mut pwd = path.to_path_buf();
    loop {
        pwd.push("devsm.js");
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
        pwd.push("devsm.js");
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
    Err(anyhow::anyhow!("Cannot find devsm.js in current or parent directories"))
}

pub fn load_workspace_config_leaking(
    base_path: &Path,
    content: &'static str,
) -> anyhow::Result<WorkspaceConfig<'static>> {
    let bump = Box::leak(Box::new(Bump::new()));
    // todo put in the bump allocator
    let base_path = Box::leak(Box::new(base_path.to_path_buf()));
    let parser = &mut jsony::json::Parser::new(
        content,
        jsony::JsonParserConfig {
            recursion_limit: 100,
            allow_trailing_commas: true,
            allow_comments: true,
            allow_unquoted_field_keys: true,
            allow_trailing_data: true,
        },
    );
    let mut tasks = bumpalo::collections::Vec::new_in(bump);
    let mut groups = bumpalo::collections::Vec::new_in(bump);
    while let Some(key) = next_const(parser) {
        if parser.peek().ok() == Some(Peek::Array) {
            match <&[TaskCall]>::decode(parser, bump) {
                Ok(task) => groups.push((key, task)),
                Err(err) => {
                    println!("{} while parsing: const {}", jsony::JsonError::extract(err, parser), key);
                }
            }
        } else {
            match TaskConfigExpr::decode(parser, bump) {
                Ok(task) => tasks.push((key, task)),
                Err(err) => {
                    println!("{} while parsing: const {}", jsony::JsonError::extract(err, parser), key);
                }
            }
        }
    }
    Ok(WorkspaceConfig { base_path, tasks: tasks.into_bump_slice(), groups: groups.into_bump_slice() })
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
        command: CommandExpr::Cmd(StringListExpr::List(&[StringListExpr::Literal("cargo"), StringListExpr::Var("args")])),
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

impl<'a> BumpJsonDecode<'a> for TaskConfigExpr<'a> {
    fn decode(
        parser: &mut jsony::json::Parser<'static>,
        bump: &'a Bump,
    ) -> Result<Self, &'static jsony::json::DecodeError> {
        let mut pwd = StringExpr::Literal("./");
        let mut cmd: Option<StringListExpr> = None;
        let mut sh: Option<StringExpr> = None;
        let mut profiles: &[&str] = &[];
        let mut envvar: &[(&str, StringExpr)] = &[];
        let mut before = AliasListExpr::List(&[]);
        let mut before_once = AliasListExpr::List(&[]);
        let mut next_key = parser.enter_object()?;
        let mut kind = TaskKind::Action;
        let mut info = "";
        while let Some(key) = next_key {
            match key {
                "pwd" => pwd = StringExpr::decode(parser, bump)?,
                "info" => info = take_string(parser, bump)?,
                "kind" | "type" => kind = TaskKind::decode_json(parser)?,
                "cmd" => cmd = Some(StringListExpr::decode(parser, bump)?),
                "sh" => sh = Some(StringExpr::decode(parser, bump)?),
                "profiles" => profiles = <&[&str]>::decode(parser, bump)?,
                "before" => before = AliasListExpr::decode(parser, bump)?,
                "before_once" => before_once = AliasListExpr::decode(parser, bump)?,
                "env" => {
                    let mut vars = bumpalo::collections::Vec::new_in(bump);
                    let mut next_env_key = parser.at.enter_object(&mut parser.scratch)?;
                    while let Some(env_key) = next_env_key {
                        let env_key =
                            if let Some(key) = parser.at.try_zerocopy(env_key) { key } else { bump.alloc_str(env_key) };
                        let value_expr = StringExpr::decode(parser, bump)?;
                        vars.push((env_key, value_expr));
                        next_env_key = parser.at.object_step(&mut parser.scratch)?;
                    }
                    envvar = vars.into_bump_slice();
                }
                _ => {
                    let error = format!("Unexpected key `{}` in TaskConfig", key);
                    parser.report_error(error);
                    return Err(&DecodeError { message: "Unexpected key in TaskConfig" });
                }
            }
            next_key = parser.object_step()?;
        }

        // Validate that exactly one of cmd or sh is specified
        let command = match (cmd, sh) {
            (Some(cmd), None) => CommandExpr::Cmd(cmd),
            (None, Some(sh)) => CommandExpr::Sh(sh),
            (Some(_), Some(_)) => {
                return Err(&DecodeError { message: "Fields `cmd` and `sh` are mutually exclusive in TaskConfig" });
            }
            (None, None) => {
                return Err(&DecodeError { message: "Either `cmd` or `sh` field is required in TaskConfig" });
            }
        };

        Ok(TaskConfigExpr {
            info,
            kind,
            pwd,
            command,
            envvar,
            before,
            before_once,
            profiles,
        })
    }
}

impl<'a> BumpJsonDecode<'a> for Alias<'a> {
    fn decode(
        parser: &mut jsony::json::Parser<'static>,
        _bump: &'a Bump,
    ) -> Result<Self, &'static jsony::json::DecodeError> {
        // todo should accept string
        let _ = parser.peek()?;
        let bytes = parser.at.ctx.as_bytes();
        let index = parser.at.index;
        let prefix = bytes.get(index..).ok_or(&DecodeError { message: "Unexpected EOF" })?;
        let start = prefix.first().ok_or(&DecodeError { message: "Unexpected EOF" })?;
        if !start.is_ascii_alphabetic() {
            parser.report_error(format!("Found `{}`", *start as char));
            return Err(&DecodeError { message: "Identifier must start with an letter." });
        }
        let len = 'len: {
            for ch in prefix[1..].iter().enumerate() {
                if !ch.1.is_ascii_alphanumeric() && *ch.1 != b'_' {
                    break 'len ch.0 + 1;
                }
            }
            prefix.len()
        };
        let s = &prefix[..len];
        parser.at.index += len;
        Ok(Alias(unsafe { std::str::from_utf8_unchecked(s) }))
    }
}
#[derive(PartialEq, Eq, Debug)]
enum Predicate<'a> {
    ProfileIs(&'a str),
}
impl<'a> Predicate<'a> {
    fn eval(&self, env: &Enviroment) -> bool {
        match self {
            Predicate::ProfileIs(p) => *p == env.profile,
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
}
impl<'a, T: BumpEval<'a>> BumpEval<'a> for If<'a, T> {
    type Object = T::Object;
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<Self::Object, EvalError> {
        match &self.cond {
            Predicate::ProfileIs(p) => {
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
impl<'a, T: BumpJsonDecode<'a>> If<'a, T> {
    fn decode_from_seen_key(
        parser: &mut Parser<'static>,
        bump: &'a Bump,
    ) -> Result<Self, &'static jsony::json::DecodeError> {
        let cond = Predicate::decode(parser, bump)?;
        let mut then = None::<T>;
        let mut or_else = None::<T>;
        while let Some(key) = parser.object_step()? {
            match key {
                "then" => then = Some(T::decode(parser, bump)?),
                "else" => or_else = Some(T::decode(parser, bump)?),
                _ => panic!(),
            }
        }
        if let Some(then) = then {
            return Ok(If { cond, then, or_else });
        } else {
            return Err(&DecodeError { message: "`then` branch is required in if expression" });
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

impl<'a> BumpJsonDecode<'a> for &'a str {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError> {
        take_string(parser, bump)
    }
}

impl<'a, T: BumpJsonDecode<'a>> BumpJsonDecode<'a> for &'a [T] {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError> {
        if parser.at.enter_array()?.is_none() {
            return Ok(&[]);
        }
        let mut items = bumpalo::collections::Vec::new_in(bump);
        loop {
            let item = T::decode(parser, bump)?;
            items.push(item);
            if parser.at.array_step()?.is_none() {
                return Ok(items.into_bump_slice());
            }
        }
    }
}

fn take_string<'a>(
    parser: &mut Parser<'static>,
    alloc: &'a Bump,
) -> Result<&'a str, &'static jsony::json::DecodeError> {
    let text = parser.at.take_string(&mut parser.scratch)?;
    if let Some(text) = parser.at.try_zerocopy(text) { Ok(text) } else { Ok(alloc.alloc_str(text)) }
}

pub trait BumpEval<'a> {
    type Object: Sized;
    fn bump_eval(&self, env: &Enviroment, bump: &'a Bump) -> Result<Self::Object, EvalError>;
}

trait BumpJsonDecode<'a>: Sized {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError>;
}

impl<'a> BumpJsonDecode<'a> for Predicate<'a> {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError> {
        let Some(key) = parser.enter_object()? else {
            return Err(&DecodeError { message: "Expected object for Predicate" });
        };
        match key {
            "profile_is" => {
                let value = take_string(parser, bump)?;
                if let Some(_key) = parser.object_step()? {
                    return Err(&DecodeError { message: "Unexpected extra key in profile_is predicate" });
                }
                Ok(Predicate::ProfileIs(value))
            }
            _ => Err(&DecodeError { message: "Unknown predicate key" }),
        }
    }
}
impl<'a> BumpJsonDecode<'a> for StringExpr<'a> {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError> {
        const DOLLAR: Peek = Peek::new(b'$');
        match parser.peek()? {
            Peek::String => Ok(StringExpr::Literal(take_string(parser, bump)?)),
            Peek::Object => {
                let Some(key) = parser.enter_seen_object()? else { panic!() };
                if key == "if" {
                    return Ok(StringExpr::If(bump.alloc(If::decode_from_seen_key(parser, bump)?)));
                }
                Err(&DecodeError { message: "Unexpected string operator" })
            }
            DOLLAR => {
                parser.at.index += 1;
                let alias = Alias::decode(parser, bump)?;
                Ok(StringExpr::Var(&alias.0))
            }
            _ => Err(&DecodeError { message: "Expected String or Object for String Expression" }),
        }
    }
}

impl<'a> BumpJsonDecode<'a> for StringListExpr<'a> {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError> {
        use StringListExpr as Expr;
        const DOLLAR: Peek = Peek::new(b'$');
        match parser.peek()? {
            Peek::String => Ok(Expr::Literal(BumpJsonDecode::decode(parser, bump)?)),
            Peek::Array => Ok(Expr::List(BumpJsonDecode::decode(parser, bump)?)),
            Peek::Object => {
                let Some(key) = parser.enter_seen_object()? else { panic!() };
                if key == "if" {
                    return Ok(Expr::If(bump.alloc(If::decode_from_seen_key(parser, bump)?)));
                }
                Err(&DecodeError { message: "Unexpected string operator" })
            }
            DOLLAR => {
                parser.at.index += 1;
                let alias = Alias::decode(parser, bump)?;
                Ok(StringListExpr::Var(&alias.0))
            }
            _ => Err(&DecodeError { message: "Expected String or Object for String Expression" }),
        }
    }
}
impl<'a> BumpJsonDecode<'a> for AliasListExpr<'a> {
    fn decode(parser: &mut Parser<'static>, bump: &'a Bump) -> Result<Self, &'static jsony::json::DecodeError> {
        use AliasListExpr as Expr;
        match parser.peek()? {
            Peek::String => Ok(Expr::Literal(BumpJsonDecode::decode(parser, bump)?)),
            Peek::Array => Ok(Expr::List(BumpJsonDecode::decode(parser, bump)?)),
            Peek::Object => {
                let Some(key) = parser.enter_seen_object()? else { panic!() };
                if key == "if" {
                    return Ok(Expr::If(bump.alloc(If::decode_from_seen_key(parser, bump)?)));
                }
                Err(&DecodeError { message: "Unexpected string operator" })
            }
            _ => Ok(Expr::Literal(BumpJsonDecode::decode(parser, bump)?)),
        }
    }
}

// enum MultiStringExpr {
//     Single(Box<str>),
//     List(Box<[MultiStringExpr]>),
//     If {
//         cond: Predicate,
//         then: Option<Box<MultiStringExpr>>,
//         or: Option<Box<MultiStringExpr>>,
//     },
// }

// enum MultiAliasExpr {
//     Single(Alias),
//     List(Box<[MultiAliasExpr]>),
//     If {
//         cond: Predicate,
//         then: Option<Box<MultiAliasExpr>>,
//         or: Option<Box<MultiAliasExpr>>,
//     },
// }

#[cfg(test)]
mod test {

    use jsony::JsonError;
    use jsony_value::ValueMap;

    use super::*;
    #[test]
    fn task_config() {
        let complex = stringify! {
            {
                pwd: "/tmp/",
                cmd: [
                    "cargo",
                    "build",
                    { if: {profile_is: "production"}, then: "--release" }
                ],
                profiles: ["default", "production"],
                env: {
                    "hello": "nice"
                }
            }
        };
        let config = jsony::JsonParserConfig {
            recursion_limit: 50,
            allow_trailing_commas: true,
            allow_comments: true,
            allow_unquoted_field_keys: true,
            allow_trailing_data: true,
        };
        let mut parser = jsony::json::Parser::new(complex, config);
        let bump = Bump::new();
        let config_expr = match TaskConfigExpr::decode(&mut parser, &bump) {
            Ok(config) => config,
            Err(err) => {
                panic!("{}", JsonError::extract(err, &mut parser));
            }
        };
        let asdf = unsafe { std::mem::transmute::<TaskConfigExpr<'_>, TaskConfigExpr<'static>>(config_expr) };
        let bump2 = Bump::new();
        let res = asdf.bump_eval(&Enviroment { profile: "default", param: ValueMap::new() }, &bump2).unwrap();
        println!("{:#?}", res);
    }

    // #[test]
    // fn parseit() {
    //     let path = "/home/user/am/libra/devsm.js";
    //     let input = stringify!({
    //         hello: what
    //     });
    //     let mut parser = jsony::json::Parser::new(input, config);
    //     let value = Foo::decode_json(&mut parser).unwrap();
    //     assert_eq!(&*value.hello, "what");
    // }
}
