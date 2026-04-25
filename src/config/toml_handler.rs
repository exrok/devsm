use bumpalo::Bump;
use toml_spanner::{Context, Document, Failed, Item, Table, Value};

use crate::config::{
    Alias, AllowMultiple, CacheConfig, CacheKeyInput, CommandExpr, FunctionDef, FunctionDefAction, If, Predicate,
    ReadyConfig, ReadyPredicate, Requirement, ServiceHidden, StringExpr, StringListExpr, TaskCall, TaskConfigExpr,
    TaskKind, TestConfigExpr, TimeoutConfig, TimeoutPredicate, VarMeta, WorkspaceConfig, parse_duration,
};

fn parse_predicate<'a>(value: &Item<'a>, ctx: &mut Context<'a>) -> Result<Predicate<'a>, Failed> {
    let table = value.require_table(ctx)?;
    let mut profile: Option<&'a str> = None;
    for (key, val) in table {
        match key.name {
            "profile" => profile = Some(val.require_string(ctx)?),
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
    }
    match profile {
        Some(p) => Ok(Predicate::Profile(p)),
        None => Err(ctx.report_missing_field("profile", value)),
    }
}

fn parse_string_expr<'a>(alloc: &'a Bump, value: &Item<'a>, ctx: &mut Context<'a>) -> Result<StringExpr<'a>, Failed> {
    match value.value() {
        Value::String(&s) => Ok(StringExpr::Literal(s)),
        Value::Table(table) => {
            if let Some(var_val) = table.get("var") {
                for (key, val) in table {
                    if key.name != "var" {
                        ctx.report_unexpected_key(0, val, key.span);
                    }
                }
                return Ok(StringExpr::Var(var_val.require_string(ctx)?));
            }

            let mut cond: Option<Predicate<'a>> = None;
            let mut then_expr: Option<StringExpr<'a>> = None;
            let mut or_else: Option<StringExpr<'a>> = None;

            for (key, val) in table {
                match key.name {
                    "if" => cond = Some(parse_predicate(val, ctx)?),
                    "then" => then_expr = Some(parse_string_expr(alloc, val, ctx)?),
                    "or_else" | "else" => or_else = Some(parse_string_expr(alloc, val, ctx)?),
                    _ => {
                        ctx.report_unexpected_key(0, val, key.span);
                    }
                }
            }

            match (cond, then_expr) {
                (Some(cond), Some(then)) => Ok(StringExpr::If(alloc.alloc(If { cond, then, or_else }))),
                (Some(_), None) => Err(ctx.report_missing_field("then", value)),
                _ => Err(ctx.report_custom_error("invalid string expression", value)),
            }
        }
        _ => Err(ctx.report_expected_but_found(&"a string or table", value)),
    }
}

fn parse_var_meta<'a>(value: &Item<'a>, ctx: &mut Context<'a>) -> Result<VarMeta<'a>, Failed> {
    let table = value.require_table(ctx)?;

    let mut description = None;
    let mut default = None;

    for (key, val) in table {
        match key.name {
            "description" => description = Some(val.require_string(ctx)?),
            "default" => default = Some(val.require_string(ctx)?),
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
    }

    Ok(VarMeta { description, default })
}

fn parse_duration_value<'a>(value: &Item<'a>, ctx: &mut Context<'a>) -> Result<f64, Failed> {
    match value.value() {
        Value::Float(&f) => Ok(f),
        Value::Integer(&i) => Ok(i.as_i128() as f64),
        Value::String(&s) => match parse_duration(s) {
            Ok(secs) => Ok(secs),
            Err(err) => Err(ctx.report_custom_error(format!("invalid duration: {}", err), value)),
        },
        _ => Err(ctx.report_expected_but_found(&"a number or duration string", value)),
    }
}

fn parse_timeout_predicate<'a>(
    when_table: &Table<'a>,
    when_value: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<TimeoutPredicate<'a>, Failed> {
    let mut output_contains: Option<&'a str> = None;
    for (key, val) in when_table {
        match key.name {
            "output_contains" => output_contains = Some(val.require_string(ctx)?),
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
    }
    match output_contains {
        Some(s) => Ok(TimeoutPredicate::OutputContains(s)),
        None => {
            Err(ctx
                .report_custom_error("`timeout.when` must specify a predicate (e.g., `output_contains`)", when_value))
        }
    }
}

fn parse_ready_predicate<'a>(
    when_table: &Table<'a>,
    when_value: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<ReadyPredicate<'a>, Failed> {
    let mut output_contains: Option<&'a str> = None;
    for (key, val) in when_table {
        match key.name {
            "output_contains" => output_contains = Some(val.require_string(ctx)?),
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
    }
    match output_contains {
        Some(s) => Ok(ReadyPredicate::OutputContains(s)),
        None => {
            Err(ctx.report_custom_error("`ready.when` must specify a predicate (e.g., `output_contains`)", when_value))
        }
    }
}

fn parse_ready_config<'a>(value: &Item<'a>, ctx: &mut Context<'a>) -> Result<ReadyConfig<'a>, Failed> {
    let ready_table = value.require_table(ctx)?;
    let mut when: Option<ReadyPredicate<'a>> = None;
    let mut timeout: Option<f64> = None;

    for (key, val) in ready_table {
        match key.name {
            "when" => {
                let when_table = val.require_table(ctx)?;
                when = Some(parse_ready_predicate(when_table, val, ctx)?);
            }
            "timeout" => match val.value() {
                Value::Float(&f) => timeout = Some(f),
                Value::Integer(&i) => timeout = Some(i.as_f64()),
                _ => return Err(ctx.report_expected_but_found(&"a number", val)),
            },
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
    }

    let when = when.ok_or_else(|| ctx.report_missing_field("when", value))?;
    Ok(ReadyConfig { when, timeout })
}

fn parse_timeout_config<'a>(value: &Item<'a>, ctx: &mut Context<'a>) -> Result<TimeoutConfig<'a>, Failed> {
    match value.value() {
        Value::String(&s) => {
            let max = parse_duration(s)
                .map_err(|err| ctx.report_custom_error(format!("invalid duration for `timeout`: {}", err), value))?;
            Ok(TimeoutConfig { when: None, conditional: None, max: Some(max), idle: None })
        }
        Value::Float(&f) => Ok(TimeoutConfig { when: None, conditional: None, max: Some(f), idle: None }),
        Value::Integer(&i) => Ok(TimeoutConfig { when: None, conditional: None, max: Some(i.as_f64()), idle: None }),
        Value::Table(timeout_table) => {
            let mut when: Option<TimeoutPredicate<'a>> = None;
            let mut conditional: Option<f64> = None;
            let mut max: Option<f64> = None;
            let mut idle: Option<f64> = None;

            for (key, val) in timeout_table {
                match key.name {
                    "when" => {
                        let when_table = val.require_table(ctx)?;
                        when = Some(parse_timeout_predicate(when_table, val, ctx)?);
                    }
                    "conditional" => conditional = Some(parse_duration_value(val, ctx)?),
                    "max" => max = Some(parse_duration_value(val, ctx)?),
                    "idle" => idle = Some(parse_duration_value(val, ctx)?),
                    _ => {
                        ctx.report_unexpected_key(0, val, key.span);
                    }
                }
            }

            if conditional.is_some() && when.is_none() {
                return Err(
                    ctx.report_custom_error("`timeout.conditional` requires `timeout.when` to be specified", value)
                );
            }

            Ok(TimeoutConfig { when, conditional, max, idle })
        }
        _ => Err(ctx.report_expected_but_found(&"a duration string, number, or table", value)),
    }
}

fn parse_string_list_expr<'a>(
    alloc: &'a Bump,
    value: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<StringListExpr<'a>, Failed> {
    match value.value() {
        Value::String(&s) => Ok(StringListExpr::Literal(s)),
        Value::Array(arr) => {
            let mut items_vec = bumpalo::collections::Vec::new_in(alloc);
            for item in arr {
                items_vec.push(parse_string_list_expr(alloc, item, ctx)?);
            }
            Ok(StringListExpr::List(items_vec.into_bump_slice()))
        }
        Value::Table(table) => {
            if let Some(var_val) = table.get("var") {
                for (key, val) in table {
                    if key.name != "var" {
                        ctx.report_unexpected_key(0, val, key.span);
                    }
                }
                return Ok(StringListExpr::Var(var_val.require_string(ctx)?));
            }

            let mut cond: Option<Predicate<'a>> = None;
            let mut then_expr: Option<StringListExpr<'a>> = None;
            let mut or_else: Option<StringListExpr<'a>> = None;

            for (key, val) in table {
                match key.name {
                    "if" => cond = Some(parse_predicate(val, ctx)?),
                    "then" => then_expr = Some(parse_string_list_expr(alloc, val, ctx)?),
                    "or_else" | "else" => or_else = Some(parse_string_list_expr(alloc, val, ctx)?),
                    _ => {
                        ctx.report_unexpected_key(0, val, key.span);
                    }
                }
            }

            match (cond, then_expr) {
                (Some(cond), Some(then)) => Ok(StringListExpr::If(alloc.alloc(If { cond, then, or_else }))),
                (Some(_), None) => Err(ctx.report_missing_field("then", value)),
                _ => Err(ctx.report_custom_error("invalid string list expression", value)),
            }
        }
        _ => Err(ctx.report_expected_but_found(&"a string, array, or table", value)),
    }
}

fn parse_string_or_array<'a>(
    alloc: &'a Bump,
    value: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<&'a [&'a str], Failed> {
    match value.value() {
        Value::String(&s) => Ok(alloc.alloc_slice_copy(&[s])),
        Value::Array(arr) => {
            let mut items = bumpalo::collections::Vec::new_in(alloc);
            for item in arr {
                items.push(item.require_string(ctx)?);
            }
            Ok(items.into_bump_slice())
        }
        _ => Err(ctx.report_expected_but_found(&"a string or array", value)),
    }
}

fn parse_task<'a>(
    alloc: &'a Bump,
    task_table: &Table<'a>,
    kind: TaskKind,
    ctx: &mut Context<'a>,
) -> Result<TaskConfigExpr<'a>, Failed> {
    let mut pwd = StringExpr::Literal("./");
    let mut profiles_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut envvar_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut require: &[Requirement<'a>] = &[];
    let mut cache: Option<CacheConfig<'a>> = None;
    let mut ready: Option<ReadyConfig<'a>> = None;
    let mut timeout: Option<TimeoutConfig<'a>> = None;
    let mut info = "";
    let mut cmd: Option<StringListExpr> = None;
    let mut sh: Option<StringExpr> = None;
    let mut managed: Option<bool> = None;
    let mut hidden = ServiceHidden::Never;
    let mut allow_multiple = AllowMultiple::False;
    let mut vars_vec = bumpalo::collections::Vec::new_in(alloc);

    for (key, value) in task_table {
        match key.name {
            "pwd" => pwd = parse_string_expr(alloc, value, ctx)?,
            "profiles" => {
                let arr = value.require_array(ctx)?;
                for item in arr {
                    profiles_vec.push(item.require_string(ctx)?);
                }
            }
            "cmd" => cmd = Some(parse_string_list_expr(alloc, value, ctx)?),
            "sh" => sh = Some(parse_string_expr(alloc, value, ctx)?),
            "env" => {
                let env_table = value.require_table(ctx)?;
                envvar_vec.clear();
                for (env_key, env_value) in env_table {
                    let val_expr = parse_string_expr(alloc, env_value, ctx)?;
                    envvar_vec.push((env_key.name, val_expr));
                }
            }
            "require" => {
                let arr = value.require_array(ctx)?;
                let mut calls = bumpalo::collections::Vec::new_in(alloc);
                for item in arr {
                    calls.push(parse_requirement(item, ctx)?);
                }
                check_no_duplicate_resources(&calls, value, ctx)?;
                require = calls.into_bump_slice();
            }
            "cache" => {
                let cache_table = value.require_table(ctx)?;
                cache = Some(parse_cache_config(alloc, cache_table, ctx)?);
            }
            "before" => {
                ctx.report_deprecated_field(0, &"before", &"require", key.span, value);
                return Err(Failed);
            }
            "before_once" => {
                return Err(ctx.report_custom_error(
                    "`before_once` is deprecated, use `require` with `cache = {}` instead",
                    value,
                ));
            }
            "info" => info = value.require_string(ctx)?,
            "ready" => {
                if kind != TaskKind::Service {
                    return Err(ctx.report_custom_error("`ready` is only valid for services", value));
                }
                ready = Some(parse_ready_config(value, ctx)?);
            }
            "timeout" => timeout = Some(parse_timeout_config(value, ctx)?),
            "managed" => match value.value() {
                Value::Boolean(&b) => managed = Some(b),
                _ => return Err(ctx.report_expected_but_found(&"a boolean", value)),
            },
            "hidden" => {
                if kind != TaskKind::Service {
                    return Err(ctx.report_custom_error("`hidden` is only valid for services", value));
                }
                hidden = match value.require_string(ctx)? {
                    "never" => ServiceHidden::Never,
                    "until_ran" => ServiceHidden::UntilRan,
                    _ => return Err(ctx.report_unexpected_variant(&["never", "until_ran"], value)),
                };
            }
            "allow_multiple" => match value.value() {
                Value::Boolean(&b) => {
                    allow_multiple = if b { AllowMultiple::True } else { AllowMultiple::False };
                }
                Value::String(&s) => {
                    allow_multiple = match s {
                        "distinct_profiles" => AllowMultiple::DistinctProfiles,
                        "single_profile" => AllowMultiple::SingleProfile,
                        _ => {
                            return Err(ctx.report_unexpected_variant(&["distinct_profiles", "single_profile"], value));
                        }
                    };
                }
                _ => return Err(ctx.report_expected_but_found(&"a boolean or string", value)),
            },
            "var" => {
                let var_table = value.require_table(ctx)?;
                for (var_key, var_value) in var_table {
                    let meta = parse_var_meta(var_value, ctx)?;
                    vars_vec.push((var_key.name, meta));
                }
            }
            _ => {
                ctx.report_unexpected_key(0, value, key.span);
            }
        }
    }

    let command = match (cmd, sh) {
        (Some(cmd), None) => CommandExpr::Cmd(cmd),
        (None, Some(sh)) => CommandExpr::Sh(sh),
        (Some(_), Some(_)) => {
            return Err(ctx.report_custom_error("fields `cmd` and `sh` are mutually exclusive", task_table.as_item()));
        }
        (None, None) => {
            return Err(ctx.report_custom_error("either `cmd` or `sh` field is required", task_table.as_item()));
        }
    };

    Ok(TaskConfigExpr {
        kind,
        info,
        pwd,
        command,
        profiles: profiles_vec.into_bump_slice(),
        envvar: envvar_vec.into_bump_slice(),
        require,
        cache,
        ready,
        timeout,
        tags: &[],
        managed,
        hidden,
        allow_multiple,
        vars: vars_vec.into_bump_slice(),
    })
}

fn parse_cache_key_input<'a>(
    alloc: &'a Bump,
    item: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<CacheKeyInput<'a>, Failed> {
    let item_table = item.require_table(ctx)?;

    if let Some(profile_val) = item_table.get("profile_changed") {
        for (key, val) in item_table {
            if key.name != "profile_changed" {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
        return Ok(CacheKeyInput::ProfileChanged(profile_val.require_string(ctx)?));
    }

    let mut paths: Option<&'a [&'a str]> = None;
    let mut ignore: &'a [&'a str] = &[];

    for (key, val) in item_table {
        match key.name {
            "modified" => paths = Some(parse_string_or_array(alloc, val, ctx)?),
            "ignore" => ignore = parse_string_or_array(alloc, val, ctx)?,
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
    }

    match paths {
        Some(paths) => Ok(CacheKeyInput::Modified { paths, ignore }),
        None => Err(ctx.report_custom_error("cache key input must have either `modified` or `profile_changed`", item)),
    }
}

/// Parse cache config from a table (shared between tasks and tests).
fn parse_cache_config<'a>(
    alloc: &'a Bump,
    cache_table: &Table<'a>,
    ctx: &mut Context<'a>,
) -> Result<CacheConfig<'a>, Failed> {
    let mut key_inputs = bumpalo::collections::Vec::new_in(alloc);
    let mut never = false;

    for (key, val) in cache_table {
        match key.name {
            "never" => match val.value() {
                Value::Boolean(&b) => never = b,
                _ => return Err(ctx.report_expected_but_found(&"a boolean", val)),
            },
            "key" => {
                let key_array = val.require_array(ctx)?;
                for item in key_array {
                    key_inputs.push(parse_cache_key_input(alloc, item, ctx)?);
                }
            }
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
            }
        }
    }

    Ok(CacheConfig { key: key_inputs.into_bump_slice(), never })
}

/// Parse a test configuration from a TOML table.
/// Tests have: cmd/sh, pwd, env, require, tag, cache (optional).
fn parse_test<'a>(
    alloc: &'a Bump,
    test_table: &Table<'a>,
    ctx: &mut Context<'a>,
) -> Result<TestConfigExpr<'a>, Failed> {
    let mut pwd = StringExpr::Literal("./");
    let mut envvar_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut require: &[Requirement<'a>] = &[];
    let mut tags_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut cache: Option<CacheConfig<'a>> = None;
    let mut timeout: Option<TimeoutConfig<'a>> = None;
    let mut info = "";
    let mut cmd: Option<StringListExpr> = None;
    let mut sh: Option<StringExpr> = None;
    let mut vars_vec = bumpalo::collections::Vec::new_in(alloc);

    for (key, value) in test_table {
        match key.name {
            "pwd" => pwd = parse_string_expr(alloc, value, ctx)?,
            "cmd" => cmd = Some(parse_string_list_expr(alloc, value, ctx)?),
            "sh" => sh = Some(parse_string_expr(alloc, value, ctx)?),
            "env" => {
                let env_table = value.require_table(ctx)?;
                envvar_vec.clear();
                for (env_key, env_value) in env_table {
                    let val_expr = parse_string_expr(alloc, env_value, ctx)?;
                    envvar_vec.push((env_key.name, val_expr));
                }
            }
            "require" => {
                let arr = value.require_array(ctx)?;
                let mut calls = bumpalo::collections::Vec::new_in(alloc);
                for item in arr {
                    calls.push(parse_requirement(item, ctx)?);
                }
                check_no_duplicate_resources(&calls, value, ctx)?;
                require = calls.into_bump_slice();
            }
            "tag" => match value.value() {
                Value::String(&s) => tags_vec.push(s),
                Value::Array(arr) => {
                    for item in arr {
                        tags_vec.push(item.require_string(ctx)?);
                    }
                }
                _ => return Err(ctx.report_expected_but_found(&"a string or array", value)),
            },
            "cache" => {
                let cache_table = value.require_table(ctx)?;
                cache = Some(parse_cache_config(alloc, cache_table, ctx)?);
            }
            "info" => info = value.require_string(ctx)?,
            "timeout" => timeout = Some(parse_timeout_config(value, ctx)?),
            "var" => {
                let var_table = value.require_table(ctx)?;
                for (var_key, var_value) in var_table {
                    let meta = parse_var_meta(var_value, ctx)?;
                    vars_vec.push((var_key.name, meta));
                }
            }
            _ => {
                ctx.report_unexpected_key(0, value, key.span);
            }
        }
    }

    let command = match (cmd, sh) {
        (Some(cmd), None) => CommandExpr::Cmd(cmd),
        (None, Some(sh)) => CommandExpr::Sh(sh),
        (Some(_), Some(_)) => {
            return Err(ctx.report_custom_error("fields `cmd` and `sh` are mutually exclusive", test_table.as_item()));
        }
        (None, None) => {
            return Err(ctx.report_custom_error("either `cmd` or `sh` field is required", test_table.as_item()));
        }
    };

    Ok(TestConfigExpr {
        info,
        pwd,
        command,
        envvar: envvar_vec.into_bump_slice(),
        require,
        tags: tags_vec.into_bump_slice(),
        cache,
        timeout,
        vars: vars_vec.into_bump_slice(),
    })
}

fn parse_requirement<'a>(value: &Item<'a>, ctx: &mut Context<'a>) -> Result<Requirement<'a>, Failed> {
    match value.value() {
        Value::String(_) | Value::Array(_) => Ok(Requirement::Task(parse_task_call(value, ctx)?)),
        Value::Table(table) => parse_resource_entry(table, value, ctx),
        _ => Err(ctx.report_expected_but_found(&"a string, array, or `{ resource = \"...\" }` table", value)),
    }
}

fn parse_resource_entry<'a>(
    table: &Table<'a>,
    value: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<Requirement<'a>, Failed> {
    let mut name: Option<&'a str> = None;
    let mut priority: i32 = 0;

    for (key, val) in table {
        match key.name {
            "resource" => {
                name = Some(val.require_string(ctx)?);
            }
            "priority" => match val.value() {
                Value::Integer(&i) => {
                    let raw = i.as_i128();
                    let Ok(p) = i32::try_from(raw) else {
                        return Err(ctx.report_custom_error("priority must fit in an i32", val));
                    };
                    priority = p;
                }
                _ => return Err(ctx.report_expected_but_found(&"an integer", val)),
            },
            "name" | "profile" | "vars" => {
                return Err(ctx.report_custom_error(
                    "resource requirement cannot also specify `name`, `profile`, or `vars` — \
                     use a string or array entry for task-call requirements",
                    val,
                ));
            }
            _ => {
                return Err(ctx.report_custom_error(
                    "unknown key on resource requirement (expected `resource` and optional `priority`)",
                    val,
                ));
            }
        }
    }

    let Some(name) = name else {
        return Err(ctx.report_custom_error("resource requirement is missing the `resource` field", value));
    };

    Ok(Requirement::Resource { name, priority })
}

fn check_no_duplicate_resources<'a>(
    items: &[Requirement<'a>],
    value: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<(), Failed> {
    for (i, r) in items.iter().enumerate() {
        let Requirement::Resource { name, .. } = r else { continue };
        for prior in &items[..i] {
            if let Requirement::Resource { name: prior_name, .. } = prior
                && *prior_name == *name
            {
                return Err(
                    ctx.report_custom_error(&format!("duplicate resource `{}` within a single `require`", name), value)
                );
            }
        }
    }
    Ok(())
}

fn parse_task_call<'a>(value: &Item<'a>, ctx: &mut Context<'a>) -> Result<TaskCall<'a>, Failed> {
    match value.value() {
        Value::String(&s) => {
            let (name, profile) = match s.rsplit_once(':') {
                Some((n, p)) => (n, Some(p)),
                None => (s, None),
            };
            Ok(TaskCall { name: Alias(name), profile, vars: jsony_value::ValueMap::new() })
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(ctx.report_custom_error("task call array cannot be empty", value));
            }
            if arr.len() > 2 {
                return Err(ctx.report_custom_error("task call array can have at most 2 elements", value));
            }

            let first = &arr.as_slice()[0];
            let s = first.require_string(ctx)?;
            let (name, profile) = match s.rsplit_once(':') {
                Some((n, p)) => (n, Some(p)),
                None => (s, None),
            };

            let mut vars = jsony_value::ValueMap::new();
            if arr.len() == 2 {
                let second = &arr.as_slice()[1];
                let vars_table = second.require_table(ctx)?;
                for (key, val) in vars_table {
                    let val_str = match val.value() {
                        Value::String(s) => s.to_string(),
                        Value::Integer(i) => i.to_string(),
                        Value::Boolean(b) => b.to_string(),
                        _ => continue,
                    };
                    vars.insert(key.name.into(), val_str.into());
                }
            }

            Ok(TaskCall { name: Alias(name), profile, vars })
        }
        _ => Err(ctx.report_expected_but_found(&"a string or array", value)),
    }
}

fn parse_function_action<'a>(
    alloc: &'a Bump,
    func_table: &Table<'a>,
    func_value: &Item<'a>,
    ctx: &mut Context<'a>,
) -> Result<FunctionDefAction<'a>, Failed> {
    let mut action: Option<FunctionDefAction<'a>> = None;

    for (key, val) in func_table {
        let parsed = match key.name {
            "restart" => FunctionDefAction::Restart { task: val.require_string(ctx)? },
            "kill" => FunctionDefAction::Kill { task: val.require_string(ctx)? },
            "spawn" => {
                let tasks: &[TaskCall<'a>] = match val.value() {
                    Value::Array(arr) => {
                        let mut calls = bumpalo::collections::Vec::new_in(alloc);
                        for item in arr {
                            calls.push(parse_task_call(item, ctx)?);
                        }
                        calls.into_bump_slice()
                    }
                    Value::String(_) => std::slice::from_ref(alloc.alloc(parse_task_call(val, ctx)?)),
                    _ => return Err(ctx.report_expected_but_found(&"a string or array", val)),
                };
                FunctionDefAction::Spawn { tasks }
            }
            _ => {
                ctx.report_unexpected_key(0, val, key.span);
                continue;
            }
        };

        if action.is_some() {
            return Err(ctx.report_custom_error("function action keys are mutually exclusive", val));
        }
        action = Some(parsed);
    }

    action.ok_or_else(|| ctx.report_custom_error("function must have 'restart', 'kill', or 'spawn' action", func_value))
}

fn parse_functions<'a>(
    alloc: &'a Bump,
    func_table: Option<&Table<'a>>,
    ctx: &mut Context<'a>,
) -> Result<&'a [FunctionDef<'a>], Failed> {
    let mut functions = bumpalo::collections::Vec::new_in(alloc);
    let mut has_fn1 = false;
    let mut has_fn2 = false;

    if let Some(func_table) = func_table {
        for (name, func_value) in func_table {
            let name_str = name.name;
            if name_str == "fn1" {
                has_fn1 = true;
            }
            if name_str == "fn2" {
                has_fn2 = true;
            }

            let action = match func_value.value() {
                Value::String(&"restart-selected") => FunctionDefAction::RestartSelected,
                Value::String(_) => {
                    return Err(ctx.report_unexpected_variant(&["restart-selected"], func_value));
                }
                Value::Table(table) => parse_function_action(alloc, table, func_value, ctx)?,
                _ => return Err(ctx.report_expected_but_found(&"a string or table", func_value)),
            };

            functions.push(FunctionDef { name: name_str, action });
        }
    }

    if !has_fn1 {
        functions.push(FunctionDef { name: "fn1", action: FunctionDefAction::RestartSelected });
    }
    if !has_fn2 {
        functions.push(FunctionDef { name: "fn2", action: FunctionDefAction::RestartSelected });
    }

    Ok(functions.into_bump_slice())
}

/// Parses a workspace from a parsed [`Document`].
///
/// Errors encountered while walking the parsed tree are pushed into
/// [`Document::ctx`]. Call [`Document::compute_error_paths`] after this
/// function returns to resolve every error's [`toml_spanner::Error::path`]
/// against the parsed tree before reporting.
pub fn parse_workspace<'a>(
    base_path: &'a std::path::Path,
    alloc: &'a Bump,
    doc: &mut Document<'a>,
) -> Result<WorkspaceConfig<'a>, Failed> {
    let (ctx, root) = doc.split();
    parse_root(base_path, alloc, root, ctx)
}

fn parse_root<'a>(
    base_path: &'a std::path::Path,
    alloc: &'a Bump,
    root: &Table<'a>,
    ctx: &mut Context<'a>,
) -> Result<WorkspaceConfig<'a>, Failed> {
    let mut tasks_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut tests_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut groups_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut function_table: Option<&Table<'a>> = None;

    for (key, value) in root {
        match key.name {
            "action" => {
                let action_table = value.require_table(ctx)?;
                for (name, task_value) in action_table {
                    let task_table = task_value.require_table(ctx)?;
                    let task = parse_task(alloc, task_table, TaskKind::Action, ctx)?;
                    tasks_vec.push((name.name, task));
                }
            }
            "service" => {
                let service_table = value.require_table(ctx)?;
                for (name, task_value) in service_table {
                    let task_table = task_value.require_table(ctx)?;
                    let task = parse_task(alloc, task_table, TaskKind::Service, ctx)?;
                    tasks_vec.push((name.name, task));
                }
            }
            "group" => {
                let group_table = value.require_table(ctx)?;
                for (name, group_value) in group_table {
                    let group_array = group_value.require_array(ctx)?;
                    let mut calls = bumpalo::collections::Vec::new_in(alloc);
                    for item in group_array {
                        calls.push(parse_task_call(item, ctx)?);
                    }
                    groups_vec.push((name.name, calls.into_bump_slice()));
                }
            }
            "test" => {
                let test_table = value.require_table(ctx)?;
                for (name, test_value) in test_table {
                    match test_value.value() {
                        Value::Table(single_test_table) => {
                            let test = parse_test(alloc, single_test_table, ctx)?;
                            let test_slice = std::slice::from_ref(alloc.alloc(test));
                            tests_vec.push((name.name, test_slice));
                        }
                        Value::Array(arr) => {
                            let mut test_array = bumpalo::collections::Vec::new_in(alloc);
                            for item in arr {
                                let item_table = item.require_table(ctx)?;
                                test_array.push(parse_test(alloc, item_table, ctx)?);
                            }
                            tests_vec.push((name.name, test_array.into_bump_slice()));
                        }
                        _ => return Err(ctx.report_expected_but_found(&"a table or array", test_value)),
                    }
                }
            }
            "function" => function_table = Some(value.require_table(ctx)?),
            _ => {
                ctx.report_unexpected_key(0, value, key.span);
            }
        }
    }

    let functions = parse_functions(alloc, function_table, ctx)?;

    Ok(WorkspaceConfig {
        base_path,
        tasks: tasks_vec.into_bump_slice(),
        tests: tests_vec.into_bump_slice(),
        groups: groups_vec.into_bump_slice(),
        functions,
    })
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use super::*;

    fn collect_messages(doc: &Document<'_>) -> Vec<String> {
        doc.errors().iter().map(|e| e.message(doc.ctx.source())).collect()
    }

    #[test]
    fn test_parse_string_expr() {
        let text = r#"hello = "world""#;
        let arena = toml_spanner::Arena::new();
        let mut doc = toml_spanner::parse(text, &arena).unwrap();
        let bump = Bump::new();
        let (ctx, table) = doc.split();
        let hello_val = table.get("hello").unwrap();
        let result = parse_string_expr(&bump, hello_val, ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            StringExpr::Literal(s) => assert_eq!(s, "world"),
            _ => panic!("Expected literal"),
        }
    }

    #[test]
    fn test_parse_var_expr() {
        let text = r#"path = { var = "dir" }"#;
        let arena = toml_spanner::Arena::new();
        let mut doc = toml_spanner::parse(text, &arena).unwrap();
        let bump = Bump::new();
        let (ctx, table) = doc.split();
        let path_val = table.get("path").unwrap();
        let result = parse_string_expr(&bump, path_val, ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            StringExpr::Var(v) => assert_eq!(v, "dir"),
            _ => panic!("Expected var"),
        }
    }

    #[test]
    fn test_parse_if_expr() {
        let text = r#"arg = { if.profile = "verbose", then = "-al" }"#;
        let arena = toml_spanner::Arena::new();
        let mut doc = toml_spanner::parse(text, &arena).unwrap();
        let bump = Bump::new();
        let (ctx, table) = doc.split();
        let arg_val = table.get("arg").unwrap();
        let result = parse_string_expr(&bump, arg_val, ctx);
        assert!(result.is_ok());
        match result.unwrap() {
            StringExpr::If(if_expr) => {
                assert!(matches!(if_expr.cond, Predicate::Profile(_)));
                assert!(matches!(if_expr.then, StringExpr::Literal(_)));
            }
            _ => panic!("Expected if expression"),
        }
    }

    fn parse_text<'a>(
        text: &'a str,
        arena: &'a toml_spanner::Arena,
        bump: &'a Bump,
    ) -> (Document<'a>, Result<WorkspaceConfig<'a>, Failed>) {
        let mut doc = toml_spanner::parse_recoverable(text, arena);
        let result = parse_workspace(Path::new("/"), bump, &mut doc);
        doc.compute_error_paths();
        (doc, result)
    }

    #[test]
    fn test_parse_require_field() {
        let text = "[action.test]\ncmd = [\"cargo\", \"test\"]\nrequire = [\"build\"]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "Expected successful parse: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        assert_eq!(config.tasks.len(), 1);
        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "test");
        assert_eq!(task.kind, TaskKind::Action);
    }

    #[test]
    fn test_parse_cache_field() {
        let text = "[action.build]\ncmd = [\"cargo\", \"build\"]\ncache = {}\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "Expected successful parse: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        assert_eq!(config.tasks.len(), 1);
        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "build");
        assert!(task.cache.is_some());
    }

    #[test]
    fn test_cache_key_valid_for_service() {
        let text = "[service.server]\ncmd = [\"./server\"]\ncache.key = [{ modified = \"/tmp/file\" }]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "cache.key should be valid for services: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "server");
        assert!(task.cache.is_some());
        assert!(!task.cache.as_ref().unwrap().key.is_empty());
    }

    #[test]
    fn test_cache_never_valid_for_service() {
        let text = "[service.server]\ncmd = [\"./server\"]\ncache.never = true\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "Expected successful parse: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        assert_eq!(config.tasks.len(), 1);
        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "server");
        let cache = task.cache.as_ref().expect("cache should be present");
        assert!(cache.never);
        assert!(cache.key.is_empty());
    }

    #[test]
    fn test_deprecated_before_errors() {
        let text = "[action.test]\ncmd = [\"cargo\", \"test\"]\nbefore = [\"build\"]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_err(), "Expected error for deprecated 'before'");
        let messages = collect_messages(&doc);
        assert!(!messages.is_empty());
        assert!(messages.iter().any(|m| m.contains("deprecated")), "messages: {:?}", messages);
    }

    #[test]
    fn test_deprecated_before_once_errors() {
        let text = "[action.test]\ncmd = [\"cargo\", \"test\"]\nbefore_once = [\"setup\"]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_err(), "Expected error for deprecated 'before_once'");
        let messages = collect_messages(&doc);
        assert!(!messages.is_empty());
        assert!(messages.iter().any(|m| m.contains("deprecated")), "messages: {:?}", messages);
    }

    #[test]
    fn test_require_with_cache() {
        let text = "[action.setup]\ncmd = [\"./setup.sh\"]\ncache = {}\n\n[action.build]\ncmd = [\"cargo\", \"build\"]\nrequire = [\"setup\"]\ncache = {}\n\n[action.test]\ncmd = [\"cargo\", \"test\"]\nrequire = [\"build\"]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "Expected successful parse: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        assert_eq!(config.tasks.len(), 3);

        let setup = &config.tasks.iter().find(|(n, _)| *n == "setup").unwrap().1;
        assert!(setup.cache.is_some());

        let build = &config.tasks.iter().find(|(n, _)| *n == "build").unwrap().1;
        assert!(build.cache.is_some());

        let test = &config.tasks.iter().find(|(n, _)| *n == "test").unwrap().1;
        assert!(test.cache.is_none());
    }

    #[test]
    fn test_parse_cache_with_key() {
        let text = "[action.init_db]\ncmd = [\"./init-db.sh\"]\ncache.key = [\n    { modified = \"./backend/database/schema.sql\" },\n    { profile_changed = \"backend\" },\n]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "Expected successful parse: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        assert_eq!(config.tasks.len(), 1);

        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "init_db");
        let cache = task.cache.as_ref().expect("cache should be present");
        assert_eq!(cache.key.len(), 2);

        match &cache.key[0] {
            CacheKeyInput::Modified { paths, ignore } => {
                assert_eq!(paths.len(), 1);
                assert_eq!(paths[0], "./backend/database/schema.sql");
                assert!(ignore.is_empty());
            }
            _ => panic!("Expected Modified cache key input"),
        }
        match &cache.key[1] {
            CacheKeyInput::ProfileChanged(task_name) => assert_eq!(*task_name, "backend"),
            _ => panic!("Expected ProfileChanged cache key input"),
        }
    }

    #[test]
    fn parse_resource_requirement_basic() {
        let text = "[action.t]\ncmd = [\"echo\"]\nrequire = [{ resource = \"cargo-bin\", priority = 2 }]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "Expected success: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        let (_, task) = &config.tasks[0];
        assert_eq!(task.require.len(), 1);
        match &task.require[0] {
            Requirement::Resource { name, priority } => {
                assert_eq!(*name, "cargo-bin");
                assert_eq!(*priority, 2);
            }
            other => panic!("expected resource requirement, got {other:?}"),
        }
    }

    #[test]
    fn parse_resource_default_priority() {
        let text = "[action.t]\ncmd = [\"echo\"]\nrequire = [{ resource = \"R\" }]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_ok(), "Expected success: {:?}", collect_messages(&doc));
        let config = result.unwrap();
        let (_, task) = &config.tasks[0];
        match &task.require[0] {
            Requirement::Resource { priority, .. } => assert_eq!(*priority, 0),
            other => panic!("expected resource requirement, got {other:?}"),
        }
    }

    #[test]
    fn reject_priority_on_non_resource_table() {
        let text = "[action.t]\ncmd = [\"echo\"]\nrequire = [{ name = \"build\", priority = 1 }]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_err());
        let messages = collect_messages(&doc);
        assert!(
            messages.iter().any(|m| m.contains("resource") || m.contains("priority")),
            "expected error to mention `resource`/`priority`, got: {:?}",
            messages
        );
    }

    #[test]
    fn reject_resource_mixed_with_name() {
        let text = "[action.t]\ncmd = [\"echo\"]\nrequire = [{ resource = \"R\", name = \"build\" }]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_err());
        let messages = collect_messages(&doc);
        assert!(
            messages.iter().any(|m| m.contains("resource")),
            "expected message about mixed keys, got: {:?}",
            messages
        );
    }

    #[test]
    fn reject_duplicate_resource_in_one_require() {
        let text = "[action.t]\ncmd = [\"echo\"]\nrequire = [{ resource = \"R\" }, { resource = \"R\" }]\n";
        let arena = toml_spanner::Arena::new();
        let bump = Bump::new();
        let (doc, result) = parse_text(text, &arena, &bump);
        assert!(result.is_err());
        let messages = collect_messages(&doc);
        assert!(
            messages.iter().any(|m| m.contains("duplicate") && m.contains("R")),
            "expected duplicate-resource message, got: {:?}",
            messages
        );
    }
}
