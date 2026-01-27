use bumpalo::Bump;
use std::borrow::Cow;
use toml_spanner::{
    Value as TomlValue,
    value::{Table, ValueInner},
};

use crate::config::{
    Alias, CacheConfig, CacheKeyInput, CommandExpr, FunctionDef, FunctionDefAction, If, Predicate, ReadyConfig,
    ReadyPredicate, ServiceHidden, StringExpr, StringListExpr, TaskCall, TaskConfigExpr, TaskKind, TestConfigExpr,
    TimeoutConfig, TimeoutPredicate, VarMeta, WorkspaceConfig, parse_duration,
};
use crate::diagnostic::{Diagnostic, DiagnosticLabel, toml_error_to_diagnostic};

fn mismatched_in_object(report_error: &mut dyn FnMut(Diagnostic), expected: &str, found: &TomlValue, key: &str) {
    report_error(
        Diagnostic::error()
            .with_message("mismatched types")
            .with_label(
                DiagnosticLabel::primary(found.span.into())
                    .with_message(format!("expected `{expected}`, found `{}`", found.value.type_str())),
            )
            .with_note(format!("The {key:?} property should be a `{expected}`")),
    );
}

fn table<'a, 'b>(table: &'b Table<'a>, key: &str, re: &mut dyn FnMut(Diagnostic)) -> Result<Option<&'b Table<'a>>, ()> {
    if let Some(action) = table.get(key) {
        let Some(t) = action.as_table() else {
            mismatched_in_object(re, "table", action, key);
            return Err(());
        };
        Ok(Some(t))
    } else {
        Ok(None)
    }
}

fn as_str<'a>(cow: &'a Cow<'a, str>) -> &'a str {
    cow.as_ref()
}

fn parse_string_expr<'a>(
    alloc: &'a Bump,
    value: &TomlValue<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<StringExpr<'a>, ()> {
    match &value.value {
        ValueInner::String(s) => Ok(StringExpr::Literal(alloc.alloc_str(as_str(s)))),
        ValueInner::Table(table) => {
            if let Some(var_val) = table.get("var") {
                let Some(var_name) = var_val.as_str() else {
                    mismatched_in_object(re, "string", var_val, "var");
                    return Err(());
                };
                return Ok(StringExpr::Var(alloc.alloc_str(var_name)));
            }
            if let Some(if_val) = table.get("if") {
                let if_table = if_val.as_table().ok_or(())?;
                let profile_val = if_table.get("profile").ok_or(())?;
                let Some(profile) = profile_val.as_str() else {
                    mismatched_in_object(re, "string", profile_val, "profile");
                    return Err(());
                };

                let then_val = table.get("then").ok_or(())?;
                let then_expr = parse_string_expr(alloc, then_val, re)?;

                let mut or_else = None;
                if let Some(else_val) = table.get("or_else") {
                    or_else = Some(parse_string_expr(alloc, else_val, re)?);
                }

                return Ok(StringExpr::If(alloc.alloc(If {
                    cond: Predicate::Profile(alloc.alloc_str(profile)),
                    then: then_expr,
                    or_else,
                })));
            }
            re(Diagnostic::error()
                .with_message("invalid string expression")
                .with_label(DiagnosticLabel::primary(value.span.into())));
            Err(())
        }
        _ => {
            mismatched_in_object(re, "string or table", value, "expression");
            Err(())
        }
    }
}

fn parse_var_meta<'a>(
    alloc: &'a Bump,
    value: &TomlValue<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<VarMeta<'a>, ()> {
    let Some(table) = value.as_table() else {
        mismatched_in_object(re, "table", value, "var");
        return Err(());
    };

    let mut description = None;
    let mut default = None;

    for (key, val) in table.iter() {
        match key.name.as_ref() {
            "description" => {
                let Some(s) = val.as_str() else {
                    mismatched_in_object(re, "string", val, "description");
                    return Err(());
                };
                description = Some(alloc.alloc_str(s) as &str);
            }
            "default" => {
                let Some(s) = val.as_str() else {
                    mismatched_in_object(re, "string", val, "default");
                    return Err(());
                };
                default = Some(alloc.alloc_str(s) as &str);
            }
            unknown => {
                re(Diagnostic::error()
                    .with_message(format!("unknown key `{}` in var definition", unknown))
                    .with_label(DiagnosticLabel::primary(val.span.into())));
                return Err(());
            }
        }
    }

    Ok(VarMeta { description, default })
}

fn parse_duration_value(value: &TomlValue, key: &str, re: &mut dyn FnMut(Diagnostic)) -> Result<f64, ()> {
    match &value.value {
        ValueInner::Float(f) => Ok(*f),
        ValueInner::Integer(i) => Ok(*i as f64),
        ValueInner::String(s) => match parse_duration(as_str(s)) {
            Ok(secs) => Ok(secs),
            Err(err) => {
                re(Diagnostic::error()
                    .with_message(format!("invalid duration for `{}`: {}", key, err))
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                Err(())
            }
        },
        _ => {
            mismatched_in_object(re, "number or duration string", value, key);
            Err(())
        }
    }
}

fn parse_timeout_predicate<'a>(
    alloc: &'a Bump,
    when_table: &Table<'a>,
    when_value: &TomlValue<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<TimeoutPredicate<'a>, ()> {
    if let Some(output_contains_val) = when_table.get("output_contains") {
        let Some(needle) = output_contains_val.as_str() else {
            mismatched_in_object(re, "string", output_contains_val, "output_contains");
            return Err(());
        };
        return Ok(TimeoutPredicate::OutputContains(alloc.alloc_str(needle)));
    }
    re(Diagnostic::error()
        .with_message("`timeout.when` must specify a predicate (e.g., `output_contains`)")
        .with_label(DiagnosticLabel::primary(when_value.span.into())));
    Err(())
}

fn parse_timeout_config<'a>(
    alloc: &'a Bump,
    value: &TomlValue<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<TimeoutConfig<'a>, ()> {
    match &value.value {
        ValueInner::String(s) => {
            let max = match parse_duration(as_str(s)) {
                Ok(secs) => secs,
                Err(err) => {
                    re(Diagnostic::error()
                        .with_message(format!("invalid duration for `timeout`: {}", err))
                        .with_label(DiagnosticLabel::primary(value.span.into())));
                    return Err(());
                }
            };
            Ok(TimeoutConfig { when: None, conditional: None, max: Some(max), idle: None })
        }
        ValueInner::Float(f) => Ok(TimeoutConfig { when: None, conditional: None, max: Some(*f), idle: None }),
        ValueInner::Integer(i) => Ok(TimeoutConfig { when: None, conditional: None, max: Some(*i as f64), idle: None }),
        ValueInner::Table(timeout_table) => {
            let mut when: Option<TimeoutPredicate<'a>> = None;
            let mut conditional: Option<f64> = None;
            let mut max: Option<f64> = None;
            let mut idle: Option<f64> = None;

            for (key, val) in timeout_table.iter() {
                let key_str = key.name.as_ref();
                match key_str {
                    "when" => {
                        let Some(when_table) = val.as_table() else {
                            mismatched_in_object(re, "table", val, "when");
                            return Err(());
                        };
                        when = Some(parse_timeout_predicate(alloc, when_table, val, re)?);
                    }
                    "conditional" => {
                        conditional = Some(parse_duration_value(val, "conditional", re)?);
                    }
                    "max" => {
                        max = Some(parse_duration_value(val, "max", re)?);
                    }
                    "idle" => {
                        idle = Some(parse_duration_value(val, "idle", re)?);
                    }
                    _ => {
                        re(Diagnostic::error()
                            .with_message(format!("unknown key `{}` in timeout configuration", key_str))
                            .with_label(DiagnosticLabel::primary(val.span.into())));
                        return Err(());
                    }
                }
            }

            if conditional.is_some() && when.is_none() {
                re(Diagnostic::error()
                    .with_message("`timeout.conditional` requires `timeout.when` to be specified")
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                return Err(());
            }

            Ok(TimeoutConfig { when, conditional, max, idle })
        }
        _ => {
            mismatched_in_object(re, "duration string, number, or table", value, "timeout");
            Err(())
        }
    }
}

fn parse_string_list_expr<'a>(
    alloc: &'a Bump,
    value: &TomlValue<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<StringListExpr<'a>, ()> {
    match &value.value {
        ValueInner::String(s) => Ok(StringListExpr::Literal(alloc.alloc_str(as_str(s)))),
        ValueInner::Array(arr) => {
            let mut items_vec = bumpalo::collections::Vec::new_in(alloc);
            for item in arr {
                items_vec.push(parse_string_list_expr(alloc, item, re)?);
            }
            Ok(StringListExpr::List(items_vec.into_bump_slice()))
        }
        ValueInner::Table(table) => {
            if let Some(var_val) = table.get("var") {
                let Some(var_name) = var_val.as_str() else {
                    mismatched_in_object(re, "string", var_val, "var");
                    return Err(());
                };
                return Ok(StringListExpr::Var(alloc.alloc_str(var_name)));
            }
            if let Some(if_val) = table.get("if") {
                let if_table = if_val.as_table().ok_or(())?;
                let profile_val = if_table.get("profile").ok_or(())?;
                let Some(profile) = profile_val.as_str() else {
                    mismatched_in_object(re, "string", profile_val, "profile");
                    return Err(());
                };

                let then_val = table.get("then").ok_or(())?;
                let then_expr = parse_string_list_expr(alloc, then_val, re)?;

                let mut or_else = None;
                if let Some(else_val) = table.get("or_else") {
                    or_else = Some(parse_string_list_expr(alloc, else_val, re)?);
                }

                return Ok(StringListExpr::If(alloc.alloc(If {
                    cond: Predicate::Profile(alloc.alloc_str(profile)),
                    then: then_expr,
                    or_else,
                })));
            }
            re(Diagnostic::error()
                .with_message("invalid string list expression")
                .with_label(DiagnosticLabel::primary(value.span.into())));
            Err(())
        }
        _ => {
            mismatched_in_object(re, "string, array, or table", value, "expression");
            Err(())
        }
    }
}

fn parse_string_or_array<'a>(
    alloc: &'a Bump,
    value: &TomlValue<'a>,
    field_name: &str,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<&'a [&'a str], ()> {
    match &value.value {
        ValueInner::String(s) => {
            let s: &'a str = alloc.alloc_str(as_str(s));
            Ok(alloc.alloc_slice_copy(&[s]))
        }
        ValueInner::Array(arr) => {
            let mut items = bumpalo::collections::Vec::new_in(alloc);
            for item in arr {
                let Some(s) = item.as_str() else {
                    mismatched_in_object(re, "string", item, field_name);
                    return Err(());
                };
                items.push(alloc.alloc_str(s) as &str);
            }
            Ok(items.into_bump_slice())
        }
        _ => {
            mismatched_in_object(re, "string or array", value, field_name);
            Err(())
        }
    }
}

fn parse_task<'a>(
    alloc: &'a Bump,
    task_table: &Table<'a>,
    kind: TaskKind,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<TaskConfigExpr<'a>, ()> {
    let mut pwd = StringExpr::Literal("./");
    let mut profiles_vec = bumpalo::collections::Vec::new_in(alloc);
    profiles_vec.push("default");
    let mut envvar_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut require: &[TaskCall<'a>] = &[];
    let mut cache: Option<CacheConfig<'a>> = None;
    let mut ready: Option<ReadyConfig<'a>> = None;
    let mut timeout: Option<TimeoutConfig<'a>> = None;
    let mut info = "";
    let mut cmd: Option<StringListExpr> = None;
    let mut sh: Option<StringExpr> = None;
    let mut managed: Option<bool> = None;
    let mut hidden = ServiceHidden::Never;
    let mut vars_vec = bumpalo::collections::Vec::new_in(alloc);

    for (key, value) in task_table.iter() {
        let key_str = key.name.as_ref();
        match key_str {
            "pwd" => {
                pwd = parse_string_expr(alloc, value, re)?;
            }
            "profiles" => {
                let Some(arr) = value.as_array() else {
                    mismatched_in_object(re, "array", value, "profiles");
                    return Err(());
                };
                profiles_vec.clear();
                for item in arr {
                    let Some(s) = item.as_str() else {
                        mismatched_in_object(re, "string", item, "profile");
                        return Err(());
                    };
                    profiles_vec.push(alloc.alloc_str(s) as &str);
                }
            }
            "cmd" => {
                cmd = Some(parse_string_list_expr(alloc, value, re)?);
            }
            "sh" => {
                sh = Some(parse_string_expr(alloc, value, re)?);
            }
            "env" => {
                let Some(env_table) = value.as_table() else {
                    mismatched_in_object(re, "table", value, "env");
                    return Err(());
                };
                envvar_vec.clear();
                for (env_key, env_value) in env_table.iter() {
                    let key_str = alloc.alloc_str(env_key.name.as_ref()) as &str;
                    let val_expr = parse_string_expr(alloc, env_value, re)?;
                    envvar_vec.push((key_str, val_expr));
                }
            }
            "require" => {
                let Some(arr) = value.as_array() else {
                    mismatched_in_object(re, "array", value, "require");
                    return Err(());
                };
                let mut calls = bumpalo::collections::Vec::new_in(alloc);
                for item in arr {
                    calls.push(parse_task_call(alloc, item, re)?);
                }
                require = calls.into_bump_slice();
            }
            "cache" => {
                let Some(cache_table) = value.as_table() else {
                    mismatched_in_object(re, "table", value, "cache");
                    return Err(());
                };

                let mut key_inputs = bumpalo::collections::Vec::new_in(alloc);
                let mut never = false;

                if let Some(never_value) = cache_table.get("never") {
                    let ValueInner::Boolean(b) = &never_value.value else {
                        mismatched_in_object(re, "boolean", never_value, "never");
                        return Err(());
                    };
                    never = *b;
                }

                if let Some(key_value) = cache_table.get("key") {
                    let Some(key_array) = key_value.as_array() else {
                        mismatched_in_object(re, "array", key_value, "key");
                        return Err(());
                    };
                    for item in key_array {
                        let Some(item_table) = item.as_table() else {
                            mismatched_in_object(re, "table", item, "cache key input");
                            return Err(());
                        };
                        if let Some(modified_val) = item_table.get("modified") {
                            let paths = parse_string_or_array(alloc, modified_val, "modified", re)?;
                            let ignore = if let Some(ignore_val) = item_table.get("ignore") {
                                parse_string_or_array(alloc, ignore_val, "ignore", re)?
                            } else {
                                &[]
                            };
                            key_inputs.push(CacheKeyInput::Modified { paths, ignore });
                        } else if let Some(profile_val) = item_table.get("profile_changed") {
                            let Some(task_name) = profile_val.as_str() else {
                                mismatched_in_object(re, "string", profile_val, "profile_changed");
                                return Err(());
                            };
                            key_inputs.push(CacheKeyInput::ProfileChanged(alloc.alloc_str(task_name)));
                        } else {
                            re(Diagnostic::error()
                                .with_message("cache key input must have either `modified` or `profile_changed`")
                                .with_label(DiagnosticLabel::primary(item.span.into())));
                            return Err(());
                        }
                    }
                }
                cache = Some(CacheConfig { key: key_inputs.into_bump_slice(), never });
            }
            "before" => {
                re(Diagnostic::error()
                    .with_message("`before` is deprecated, use `require` instead")
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                return Err(());
            }
            "before_once" => {
                re(Diagnostic::error()
                    .with_message("`before_once` is deprecated, use `require` with `cache = {}` instead")
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                return Err(());
            }
            "info" => {
                let Some(s) = value.as_str() else {
                    mismatched_in_object(re, "string", value, "info");
                    return Err(());
                };
                info = alloc.alloc_str(s);
            }
            "ready" => {
                if kind != TaskKind::Service {
                    re(Diagnostic::error()
                        .with_message("`ready` is only valid for services")
                        .with_label(DiagnosticLabel::primary(value.span.into())));
                    return Err(());
                }
                let Some(ready_table) = value.as_table() else {
                    mismatched_in_object(re, "table", value, "ready");
                    return Err(());
                };
                let Some(when_value) = ready_table.get("when") else {
                    re(Diagnostic::error()
                        .with_message("`ready` requires a `when` field")
                        .with_label(DiagnosticLabel::primary(value.span.into())));
                    return Err(());
                };
                let Some(when_table) = when_value.as_table() else {
                    mismatched_in_object(re, "table", when_value, "when");
                    return Err(());
                };
                let when = if let Some(output_contains_val) = when_table.get("output_contains") {
                    let Some(needle) = output_contains_val.as_str() else {
                        mismatched_in_object(re, "string", output_contains_val, "output_contains");
                        return Err(());
                    };
                    ReadyPredicate::OutputContains(alloc.alloc_str(needle))
                } else {
                    re(Diagnostic::error()
                        .with_message("`ready.when` must specify a predicate (e.g., `output_contains`)")
                        .with_label(DiagnosticLabel::primary(when_value.span.into())));
                    return Err(());
                };
                let ready_timeout = if let Some(timeout_val) = ready_table.get("timeout") {
                    match &timeout_val.value {
                        ValueInner::Float(f) => Some(*f),
                        ValueInner::Integer(i) => Some(*i as f64),
                        _ => {
                            mismatched_in_object(re, "number", timeout_val, "timeout");
                            return Err(());
                        }
                    }
                } else {
                    None
                };
                ready = Some(ReadyConfig { when, timeout: ready_timeout });
            }
            "timeout" => {
                timeout = Some(parse_timeout_config(alloc, value, re)?);
            }
            "managed" => {
                let ValueInner::Boolean(b) = &value.value else {
                    mismatched_in_object(re, "boolean", value, "managed");
                    return Err(());
                };
                managed = Some(*b);
            }
            "hidden" => {
                if kind != TaskKind::Service {
                    re(Diagnostic::error()
                        .with_message("`hidden` is only valid for services")
                        .with_label(DiagnosticLabel::primary(value.span.into())));
                    return Err(());
                }
                let Some(hidden_str) = value.as_str() else {
                    mismatched_in_object(re, "string", value, "hidden");
                    return Err(());
                };
                hidden = match hidden_str {
                    "never" => ServiceHidden::Never,
                    "until_ran" => ServiceHidden::UntilRan,
                    _ => {
                        re(Diagnostic::error()
                            .with_message(format!(
                                "unknown hidden value `{}`, expected `never` or `until_ran`",
                                hidden_str
                            ))
                            .with_label(DiagnosticLabel::primary(value.span.into())));
                        return Err(());
                    }
                };
            }
            "var" => {
                let Some(var_table) = value.as_table() else {
                    mismatched_in_object(re, "table", value, "var");
                    return Err(());
                };
                for (var_key, var_value) in var_table.iter() {
                    let var_name = alloc.alloc_str(var_key.name.as_ref()) as &str;
                    let meta = parse_var_meta(alloc, var_value, re)?;
                    vars_vec.push((var_name, meta));
                }
            }
            _ => {
                re(Diagnostic::error()
                    .with_message(format!("unknown key `{}` in task definition", key_str))
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                return Err(());
            }
        }
    }

    let command = match (cmd, sh) {
        (Some(cmd), None) => CommandExpr::Cmd(cmd),
        (None, Some(sh)) => CommandExpr::Sh(sh),
        (Some(_), Some(_)) => {
            re(Diagnostic::error()
                .with_message("fields `cmd` and `sh` are mutually exclusive")
                .with_label(DiagnosticLabel::primary(0..0)));
            return Err(());
        }
        (None, None) => {
            re(Diagnostic::error()
                .with_message("either `cmd` or `sh` field is required")
                .with_label(DiagnosticLabel::primary(0..0)));
            return Err(());
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
        vars: vars_vec.into_bump_slice(),
    })
}

/// Parse cache config from a table (shared between tasks and tests).
fn parse_cache_config<'a>(
    alloc: &'a Bump,
    cache_table: &Table<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<CacheConfig<'a>, ()> {
    let mut key_inputs = bumpalo::collections::Vec::new_in(alloc);
    let mut never = false;

    if let Some(never_value) = cache_table.get("never") {
        let ValueInner::Boolean(b) = &never_value.value else {
            mismatched_in_object(re, "boolean", never_value, "never");
            return Err(());
        };
        never = *b;
    }

    if let Some(key_value) = cache_table.get("key") {
        let Some(key_array) = key_value.as_array() else {
            mismatched_in_object(re, "array", key_value, "key");
            return Err(());
        };
        for item in key_array {
            let Some(item_table) = item.as_table() else {
                mismatched_in_object(re, "table", item, "cache key input");
                return Err(());
            };
            if let Some(modified_val) = item_table.get("modified") {
                let paths = parse_string_or_array(alloc, modified_val, "modified", re)?;
                let ignore = if let Some(ignore_val) = item_table.get("ignore") {
                    parse_string_or_array(alloc, ignore_val, "ignore", re)?
                } else {
                    &[]
                };
                key_inputs.push(CacheKeyInput::Modified { paths, ignore });
            } else if let Some(profile_val) = item_table.get("profile_changed") {
                let Some(task_name) = profile_val.as_str() else {
                    mismatched_in_object(re, "string", profile_val, "profile_changed");
                    return Err(());
                };
                key_inputs.push(CacheKeyInput::ProfileChanged(alloc.alloc_str(task_name)));
            } else {
                re(Diagnostic::error()
                    .with_message("cache key input must have either `modified` or `profile_changed`")
                    .with_label(DiagnosticLabel::primary(item.span.into())));
                return Err(());
            }
        }
    }
    Ok(CacheConfig { key: key_inputs.into_bump_slice(), never })
}

/// Parse a test configuration from a TOML table.
/// Tests have: cmd/sh, pwd, env, require, tag, cache (optional).
fn parse_test<'a>(
    alloc: &'a Bump,
    _name: &'a str,
    test_table: &Table<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<TestConfigExpr<'a>, ()> {
    let mut pwd = StringExpr::Literal("./");
    let mut envvar_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut require: &[TaskCall<'a>] = &[];
    let mut tags_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut cache: Option<CacheConfig<'a>> = None;
    let mut timeout: Option<TimeoutConfig<'a>> = None;
    let mut info = "";
    let mut cmd: Option<StringListExpr> = None;
    let mut sh: Option<StringExpr> = None;
    let mut vars_vec = bumpalo::collections::Vec::new_in(alloc);

    for (key, value) in test_table.iter() {
        let key_str = key.name.as_ref();
        match key_str {
            "pwd" => {
                pwd = parse_string_expr(alloc, value, re)?;
            }
            "cmd" => {
                cmd = Some(parse_string_list_expr(alloc, value, re)?);
            }
            "sh" => {
                sh = Some(parse_string_expr(alloc, value, re)?);
            }
            "env" => {
                let Some(env_table) = value.as_table() else {
                    mismatched_in_object(re, "table", value, "env");
                    return Err(());
                };
                envvar_vec.clear();
                for (env_key, env_value) in env_table.iter() {
                    let key_str = alloc.alloc_str(env_key.name.as_ref()) as &str;
                    let val_expr = parse_string_expr(alloc, env_value, re)?;
                    envvar_vec.push((key_str, val_expr));
                }
            }
            "require" => {
                let Some(arr) = value.as_array() else {
                    mismatched_in_object(re, "array", value, "require");
                    return Err(());
                };
                let mut calls = bumpalo::collections::Vec::new_in(alloc);
                for item in arr {
                    calls.push(parse_task_call(alloc, item, re)?);
                }
                require = calls.into_bump_slice();
            }
            "tag" => match &value.value {
                ValueInner::String(s) => {
                    tags_vec.push(alloc.alloc_str(as_str(s)) as &str);
                }
                ValueInner::Array(arr) => {
                    for item in arr {
                        let Some(s) = item.as_str() else {
                            mismatched_in_object(re, "string", item, "tag");
                            return Err(());
                        };
                        tags_vec.push(alloc.alloc_str(s) as &str);
                    }
                }
                _ => {
                    mismatched_in_object(re, "string or array", value, "tag");
                    return Err(());
                }
            },
            "cache" => {
                let Some(cache_table) = value.as_table() else {
                    mismatched_in_object(re, "table", value, "cache");
                    return Err(());
                };
                cache = Some(parse_cache_config(alloc, cache_table, re)?);
            }
            "info" => {
                let Some(s) = value.as_str() else {
                    mismatched_in_object(re, "string", value, "info");
                    return Err(());
                };
                info = alloc.alloc_str(s);
            }
            "timeout" => {
                timeout = Some(parse_timeout_config(alloc, value, re)?);
            }
            "var" => {
                let Some(var_table) = value.as_table() else {
                    mismatched_in_object(re, "table", value, "var");
                    return Err(());
                };
                for (var_key, var_value) in var_table.iter() {
                    let var_name = alloc.alloc_str(var_key.name.as_ref()) as &str;
                    let meta = parse_var_meta(alloc, var_value, re)?;
                    vars_vec.push((var_name, meta));
                }
            }
            _ => {
                re(Diagnostic::error()
                    .with_message(format!("unknown key `{}` in test definition", key_str))
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                return Err(());
            }
        }
    }

    let command = match (cmd, sh) {
        (Some(cmd), None) => CommandExpr::Cmd(cmd),
        (None, Some(sh)) => CommandExpr::Sh(sh),
        (Some(_), Some(_)) => {
            re(Diagnostic::error()
                .with_message("fields `cmd` and `sh` are mutually exclusive")
                .with_label(DiagnosticLabel::primary(0..0)));
            return Err(());
        }
        (None, None) => {
            re(Diagnostic::error()
                .with_message("either `cmd` or `sh` field is required")
                .with_label(DiagnosticLabel::primary(0..0)));
            return Err(());
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

fn parse_task_call<'a>(
    alloc: &'a Bump,
    value: &TomlValue<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<TaskCall<'a>, ()> {
    match &value.value {
        ValueInner::String(s) => {
            let s_str = as_str(s);
            let (name_str, profile_str) =
                if let Some((n, p)) = s_str.rsplit_once(':') { (n, Some(p)) } else { (s_str, None) };
            let name = alloc.alloc_str(name_str) as &str;
            let profile = profile_str.map(|p| alloc.alloc_str(p) as &str);
            Ok(TaskCall { name: Alias(name), profile, vars: jsony_value::ValueMap::new() })
        }
        ValueInner::Array(arr) => {
            if arr.is_empty() {
                re(Diagnostic::error()
                    .with_message("task call array cannot be empty")
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                return Err(());
            }
            if arr.len() > 2 {
                re(Diagnostic::error()
                    .with_message("task call array can have at most 2 elements")
                    .with_label(DiagnosticLabel::primary(value.span.into())));
                return Err(());
            }

            let first = &arr[0];
            let (name, profile) = match &first.value {
                ValueInner::String(s) => {
                    let s_str = as_str(s);
                    let (name_str, profile_str) =
                        if let Some((n, p)) = s_str.rsplit_once(':') { (n, Some(p)) } else { (s_str, None) };
                    let name = alloc.alloc_str(name_str) as &str;
                    let profile = profile_str.map(|p| alloc.alloc_str(p) as &str);
                    (name, profile)
                }
                _ => {
                    mismatched_in_object(re, "string", first, "task name");
                    return Err(());
                }
            };

            let mut vars = jsony_value::ValueMap::new();
            if arr.len() == 2 {
                let second = &arr[1];
                let Some(vars_table) = second.as_table() else {
                    mismatched_in_object(re, "table", second, "variables");
                    return Err(());
                };
                for (key, val) in vars_table.iter() {
                    let val_str = match &val.value {
                        ValueInner::String(s) => as_str(s).to_string(),
                        ValueInner::Integer(i) => i.to_string(),
                        ValueInner::Boolean(b) => b.to_string(),
                        _ => continue,
                    };
                    vars.insert(key.name.as_ref().to_string().into(), val_str.into());
                }
            }

            Ok(TaskCall { name: Alias(name), profile, vars })
        }
        _ => {
            mismatched_in_object(re, "string or array", value, "task call");
            Err(())
        }
    }
}

fn parse_function_action<'a>(
    alloc: &'a Bump,
    func_table: &Table<'a>,
    func_value: &TomlValue<'a>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<FunctionDefAction<'a>, ()> {
    if let Some(restart_val) = func_table.get("restart") {
        let Some(task_name) = restart_val.as_str() else {
            mismatched_in_object(re, "string", restart_val, "restart");
            return Err(());
        };
        return Ok(FunctionDefAction::Restart { task: alloc.alloc_str(task_name) });
    }

    if let Some(kill_val) = func_table.get("kill") {
        let Some(task_name) = kill_val.as_str() else {
            mismatched_in_object(re, "string", kill_val, "kill");
            return Err(());
        };
        return Ok(FunctionDefAction::Kill { task: alloc.alloc_str(task_name) });
    }

    if let Some(spawn_val) = func_table.get("spawn") {
        let tasks = match &spawn_val.value {
            ValueInner::Array(arr) => {
                let mut calls = bumpalo::collections::Vec::new_in(alloc);
                for item in arr {
                    calls.push(parse_task_call(alloc, item, re)?);
                }
                calls.into_bump_slice()
            }
            ValueInner::String(_) => {
                let call = parse_task_call(alloc, spawn_val, re)?;
                std::slice::from_ref(alloc.alloc(call))
            }
            _ => {
                mismatched_in_object(re, "string or array", spawn_val, "spawn");
                return Err(());
            }
        };
        return Ok(FunctionDefAction::Spawn { tasks });
    }

    re(Diagnostic::error()
        .with_message("function must have 'restart', 'kill', or 'spawn' action")
        .with_label(DiagnosticLabel::primary(func_value.span.into())));
    Err(())
}

fn parse_functions<'a>(
    alloc: &'a Bump,
    func_table: Option<&Table<'a>>,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<&'a [FunctionDef<'a>], ()> {
    let mut functions = bumpalo::collections::Vec::new_in(alloc);
    let mut has_fn1 = false;
    let mut has_fn2 = false;

    if let Some(func_table) = func_table {
        for (name, func_value) in func_table.iter() {
            let name_str = name.name.as_ref();
            if name_str == "fn1" {
                has_fn1 = true;
            }
            if name_str == "fn2" {
                has_fn2 = true;
            }

            let action = if let Some(s) = func_value.as_str() {
                if s == "restart-selected" {
                    FunctionDefAction::RestartSelected
                } else {
                    re(Diagnostic::error()
                        .with_message(format!(
                            "unknown function action: '{}', expected 'restart-selected' or a table",
                            s
                        ))
                        .with_label(DiagnosticLabel::primary(func_value.span.into())));
                    return Err(());
                }
            } else if let Some(table) = func_value.as_table() {
                parse_function_action(alloc, table, func_value, re)?
            } else {
                mismatched_in_object(re, "string or table", func_value, name_str);
                return Err(());
            };

            functions.push(FunctionDef { name: alloc.alloc_str(name_str), action });
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

pub fn parse<'a>(
    base_path: &'a std::path::Path,
    alloc: &'a Bump,
    data: &'a str,
    re: &mut dyn FnMut(Diagnostic),
) -> Result<WorkspaceConfig<'a>, ()> {
    let value = match toml_spanner::parse(data) {
        Ok(value) => value,
        Err(err) => {
            re(toml_error_to_diagnostic(&err));
            return Err(());
        }
    };

    let root = value.as_table().unwrap();

    let mut tasks_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut tests_vec = bumpalo::collections::Vec::new_in(alloc);
    let mut groups_vec = bumpalo::collections::Vec::new_in(alloc);

    if let Some(action_table) = table(root, "action", re)? {
        for (name, task_value) in action_table.iter() {
            let Some(task_table) = task_value.as_table() else {
                mismatched_in_object(re, "table", task_value, name.name.as_ref());
                return Err(());
            };
            let name_str = alloc.alloc_str(name.name.as_ref()) as &str;
            let task = parse_task(alloc, task_table, TaskKind::Action, re)?;
            tasks_vec.push((name_str, task));
        }
    }

    if let Some(service_table) = table(root, "service", re)? {
        for (name, task_value) in service_table.iter() {
            let Some(task_table) = task_value.as_table() else {
                mismatched_in_object(re, "table", task_value, name.name.as_ref());
                return Err(());
            };
            let name_str = alloc.alloc_str(name.name.as_ref()) as &str;
            let task = parse_task(alloc, task_table, TaskKind::Service, re)?;
            tasks_vec.push((name_str, task));
        }
    }

    if let Some(group_table) = table(root, "group", re)? {
        for (name, group_value) in group_table.iter() {
            let Some(group_array) = group_value.as_array() else {
                mismatched_in_object(re, "array", group_value, name.name.as_ref());
                return Err(());
            };
            let name_str = alloc.alloc_str(name.name.as_ref()) as &str;
            let mut calls = bumpalo::collections::Vec::new_in(alloc);
            for item in group_array {
                calls.push(parse_task_call(alloc, item, re)?);
            }
            groups_vec.push((name_str, calls.into_bump_slice()));
        }
    }

    if let Some(test_table) = table(root, "test", re)? {
        for (name, test_value) in test_table.iter() {
            let name_str = alloc.alloc_str(name.name.as_ref()) as &str;
            match &test_value.value {
                ValueInner::Table(single_test_table) => {
                    let test = parse_test(alloc, name_str, single_test_table, re)?;
                    let test_slice = std::slice::from_ref(alloc.alloc(test));
                    tests_vec.push((name_str, test_slice));
                }
                ValueInner::Array(arr) => {
                    let mut test_array = bumpalo::collections::Vec::new_in(alloc);
                    for item in arr {
                        let Some(item_table) = item.as_table() else {
                            mismatched_in_object(re, "table", item, name.name.as_ref());
                            return Err(());
                        };
                        test_array.push(parse_test(alloc, name_str, item_table, re)?);
                    }
                    tests_vec.push((name_str, test_array.into_bump_slice()));
                }
                _ => {
                    mismatched_in_object(re, "table or array", test_value, name.name.as_ref());
                    return Err(());
                }
            }
        }
    }

    let functions = parse_functions(alloc, table(root, "function", re)?, re)?;

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

    #[test]
    fn test_parse_string_expr() {
        let text = r#"hello = "world""#;
        let value = toml_spanner::parse(text).unwrap();
        let table = value.as_table().unwrap();
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let hello_val = table.get("hello").unwrap();
        let result = parse_string_expr(&bump, hello_val, &mut error);
        assert!(result.is_ok());
        match result.unwrap() {
            StringExpr::Literal(s) => assert_eq!(s, "world"),
            _ => panic!("Expected literal"),
        }
    }

    #[test]
    fn test_parse_var_expr() {
        let text = r#"path = { var = "dir" }"#;
        let value = toml_spanner::parse(text).unwrap();
        let table = value.as_table().unwrap();
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let path_val = table.get("path").unwrap();
        let result = parse_string_expr(&bump, path_val, &mut error);
        assert!(result.is_ok());
        match result.unwrap() {
            StringExpr::Var(v) => assert_eq!(v, "dir"),
            _ => panic!("Expected var"),
        }
    }

    #[test]
    fn test_parse_if_expr() {
        let text = r#"arg = { if.profile = "verbose", then = "-al" }"#;
        let value = toml_spanner::parse(text).unwrap();
        let table = value.as_table().unwrap();
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let arg_val = table.get("arg").unwrap();
        let result = parse_string_expr(&bump, arg_val, &mut error);
        assert!(result.is_ok());
        match result.unwrap() {
            StringExpr::If(if_expr) => {
                assert!(matches!(if_expr.cond, Predicate::Profile(_)));
                assert!(matches!(if_expr.then, StringExpr::Literal(_)));
            }
            _ => panic!("Expected if expression"),
        }
    }

    #[test]
    fn test_parse_require_field() {
        let text = r#"
[action.test]
cmd = ["cargo", "test"]
require = ["build"]
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_ok(), "Expected successful parse");
        let config = result.unwrap();
        assert_eq!(config.tasks.len(), 1);
        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "test");
        assert_eq!(task.kind, TaskKind::Action);
    }

    #[test]
    fn test_parse_cache_field() {
        let text = r#"
[action.build]
cmd = ["cargo", "build"]
cache = {}
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_ok(), "Expected successful parse");
        let config = result.unwrap();
        assert_eq!(config.tasks.len(), 1);
        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "build");
        assert!(task.cache.is_some());
    }

    #[test]
    fn test_cache_key_valid_for_service() {
        let text = r#"
[service.server]
cmd = ["./server"]
cache.key = [{ modified = "/tmp/file" }]
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_ok(), "cache.key should be valid for services: {:?}", errors);
        let config = result.unwrap();
        let (name, task) = &config.tasks[0];
        assert_eq!(*name, "server");
        assert!(task.cache.is_some());
        assert!(!task.cache.as_ref().unwrap().key.is_empty());
    }

    #[test]
    fn test_cache_never_valid_for_service() {
        let text = r#"
[service.server]
cmd = ["./server"]
cache.never = true
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_ok(), "Expected successful parse for cache.never on service: {:?}", errors);
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
        let text = r#"
[action.test]
cmd = ["cargo", "test"]
before = ["build"]
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_err(), "Expected error for deprecated 'before'");
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("deprecated"));
    }

    #[test]
    fn test_deprecated_before_once_errors() {
        let text = r#"
[action.test]
cmd = ["cargo", "test"]
before_once = ["setup"]
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_err(), "Expected error for deprecated 'before_once'");
        assert!(!errors.is_empty());
        assert!(errors[0].message.contains("deprecated"));
    }

    #[test]
    fn test_require_with_cache() {
        let text = r#"
[action.setup]
cmd = ["./setup.sh"]
cache = {}

[action.build]
cmd = ["cargo", "build"]
require = ["setup"]
cache = {}

[action.test]
cmd = ["cargo", "test"]
require = ["build"]
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_ok(), "Expected successful parse");
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
        let text = r#"
[action.init_db]
cmd = ["./init-db.sh"]
cache.key = [
    { modified = "./backend/database/schema.sql" },
    { profile_changed = "backend" },
]
"#;
        let bump = Bump::new();
        let mut errors = Vec::new();
        let mut error = |diag: Diagnostic| {
            errors.push(diag);
        };

        let result = parse(Path::new("/"), &bump, text, &mut error);
        assert!(result.is_ok(), "Expected successful parse: {:?}", errors);
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
}
