use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;

use bumpalo::Bump;
use toml_spanner::Value as TomlValue;
use toml_spanner::span::Span;
use toml_spanner::value::{Table, ValueInner};

use crate::config::toml_handler;
use crate::config::{StringExpr, WorkspaceConfig};
use crate::diagnostic::{Diagnostic, DiagnosticLabel, emit_diagnostic, toml_error_to_diagnostic};

fn span_to_range(span: Span) -> Range<usize> {
    (span.start as usize)..(span.end as usize)
}

pub struct ValidateOptions {
    pub skip_path_checks: bool,
}

pub fn validate_config(path: &Path, options: &ValidateOptions) -> anyhow::Result<bool> {
    let content = std::fs::read_to_string(path)?;

    let file_name = path.file_name().map(|s| s.to_string_lossy()).unwrap_or_default();
    if file_name.ends_with("devsm.user.toml") {
        return validate_user_config(path, &content);
    }

    validate_workspace_config(path, &content, options)
}

fn validate_user_config(path: &Path, content: &str) -> anyhow::Result<bool> {
    let file_name = path.display().to_string();

    let toml = match toml_spanner::parse(content) {
        Ok(value) => value,
        Err(err) => {
            let diagnostic = toml_error_to_diagnostic(&err);
            emit_diagnostic(&file_name, content, &diagnostic);
            return Ok(false);
        }
    };

    let mut has_errors = false;
    let mut emit = |diag: Diagnostic| {
        has_errors = true;
        emit_diagnostic(&file_name, content, &diag);
    };

    let root = toml.as_table().unwrap();

    if let Some(bind_value) = root.get("bind") {
        let Some(bind_table) = bind_value.as_table() else {
            emit(
                Diagnostic::error()
                    .with_message("'bind' must be a table")
                    .with_labels(vec![DiagnosticLabel::primary(span_to_range(bind_value.span))]),
            );
            return Ok(false);
        };

        let valid_modes = ["global", "joblist", "log", "search", "group_select"];
        for (mode_key, mode_value) in bind_table.iter() {
            let mode_name = mode_key.name.as_ref();
            if !valid_modes.contains(&mode_name) {
                emit(
                    Diagnostic::error()
                        .with_message(format!("unknown mode '{}'", mode_name))
                        .with_labels(vec![DiagnosticLabel::primary(span_to_range(mode_key.span))])
                        .with_notes(vec![format!("valid modes are: {}", valid_modes.join(", "))]),
                );
                continue;
            }

            let Some(bindings) = mode_value.as_table() else {
                emit(
                    Diagnostic::error()
                        .with_message(format!("'bind.{}' must be a table", mode_name))
                        .with_labels(vec![DiagnosticLabel::primary(span_to_range(mode_value.span))]),
                );
                continue;
            };

            for (key_str, cmd_value) in bindings.iter() {
                if let Some(f) = cmd_value.as_float() {
                    if !f.is_nan() {
                        emit(
                            Diagnostic::error()
                                .with_message("invalid binding value")
                                .with_labels(vec![
                                    DiagnosticLabel::primary(span_to_range(cmd_value.span))
                                        .with_message("expected command string or nan"),
                                ])
                                .with_notes(vec!["use nan to unbind a key".to_string()]),
                        );
                    }
                } else if cmd_value.as_str().is_none() {
                    emit(
                        Diagnostic::error()
                            .with_message("invalid binding value")
                            .with_labels(vec![
                                DiagnosticLabel::primary(span_to_range(cmd_value.span))
                                    .with_message("expected command string or nan"),
                            ])
                            .with_notes(vec![format!("binding for key '{}'", key_str.name)]),
                    );
                }
            }
        }
    }

    for (key, _value) in root.iter() {
        let key_name = key.name.as_ref();
        if key_name != "bind" {
            emit(
                Diagnostic::warning()
                    .with_message(format!("unknown top-level key '{}'", key_name))
                    .with_labels(vec![DiagnosticLabel::primary(span_to_range(key.span))])
                    .with_notes(vec!["user config only supports the 'bind' section".to_string()]),
            );
        }
    }

    if has_errors {
        Ok(false)
    } else {
        eprintln!("{} is valid", path.display());
        Ok(true)
    }
}

fn validate_workspace_config(path: &Path, content: &str, options: &ValidateOptions) -> anyhow::Result<bool> {
    let file_name = path.display().to_string();

    let bump = Bump::new();
    let base_path = path.parent().unwrap_or(Path::new("."));

    let mut has_errors = false;
    let mut emit = |diag: Diagnostic| {
        has_errors = true;
        emit_diagnostic(&file_name, content, &diag);
    };

    let workspace_config = match toml_handler::parse(base_path, &bump, content, &mut emit) {
        Ok(config) => config,
        Err(_) => return Ok(false),
    };

    let toml = match toml_spanner::parse(content) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let root = toml.as_table().unwrap();

    validate_cross_references(&workspace_config, root, &mut emit);

    if !options.skip_path_checks {
        validate_pwd_paths(&workspace_config, base_path, root, &mut emit);
    }

    if has_errors {
        Ok(false)
    } else {
        eprintln!("{} is valid", path.display());
        Ok(true)
    }
}

fn validate_cross_references(config: &WorkspaceConfig, root: &Table, emit: &mut dyn FnMut(Diagnostic)) {
    let mut task_profiles: HashSet<(&str, &str)> = HashSet::new();
    let mut task_names: HashSet<&str> = HashSet::new();

    for (name, task_expr) in config.tasks.iter() {
        task_names.insert(name);
        for profile in task_expr.profiles.iter() {
            task_profiles.insert((name, profile));
        }
    }

    for (name, _) in config.tests.iter() {
        task_names.insert(name);
    }

    for (group_name, calls) in config.groups.iter() {
        for call in calls.iter() {
            let task_name: &str = &call.name;

            if !task_names.contains(task_name) {
                if let Some(span) = find_group_item_span(root, group_name, task_name) {
                    emit(
                        Diagnostic::error()
                            .with_message(format!("task '{}' does not exist", task_name))
                            .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                            .with_notes(vec![format!("in group '{}'", group_name)]),
                    );
                }
            } else if let Some(profile) = call.profile
                && !task_profiles.contains(&(task_name, profile))
                && let Some(span) = find_group_item_span(root, group_name, task_name)
            {
                let available: Vec<_> =
                    task_profiles.iter().filter(|(n, _)| *n == task_name).map(|(_, p)| *p).collect();
                emit(
                    Diagnostic::error()
                        .with_message(format!("task '{}' does not have profile '{}'", task_name, profile))
                        .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                        .with_notes(vec![format!("available profiles: {}", available.join(", "))]),
                );
            }
        }
    }

    for (task_name, task_expr) in config.tasks.iter() {
        for call in task_expr.require.iter() {
            let required_name: &str = &call.name;

            if !task_names.contains(required_name) {
                if let Some(span) = find_require_span(root, task_name, required_name) {
                    emit(
                        Diagnostic::error()
                            .with_message(format!("required task '{}' does not exist", required_name))
                            .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                            .with_notes(vec![format!("in task '{}'", task_name)]),
                    );
                }
            } else if let Some(profile) = call.profile
                && !task_profiles.contains(&(required_name, profile))
                && let Some(span) = find_require_span(root, task_name, required_name)
            {
                let available: Vec<_> =
                    task_profiles.iter().filter(|(n, _)| *n == required_name).map(|(_, p)| *p).collect();
                emit(
                    Diagnostic::error()
                        .with_message(format!("required task '{}' does not have profile '{}'", required_name, profile))
                        .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                        .with_notes(vec![format!("available profiles: {}", available.join(", "))]),
                );
            }
        }

        if let Some(cache) = &task_expr.cache {
            for key_input in cache.key.iter() {
                if let crate::config::CacheKeyInput::ProfileChanged(ref_task) = key_input
                    && !task_names.contains(ref_task)
                    && let Some(span) = find_profile_changed_span(root, task_name, ref_task)
                {
                    emit(
                        Diagnostic::error()
                            .with_message(format!(
                                "profile_changed references task '{}' which does not exist",
                                ref_task
                            ))
                            .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")]),
                    );
                }
            }
        }
    }

    for (test_name, test_variants) in config.tests.iter() {
        for test_expr in test_variants.iter() {
            for call in test_expr.require.iter() {
                let required_name: &str = &call.name;

                if !task_names.contains(required_name) {
                    if let Some(span) = find_test_require_span(root, test_name, required_name) {
                        emit(
                            Diagnostic::error()
                                .with_message(format!("required task '{}' does not exist", required_name))
                                .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                                .with_notes(vec![format!("in test '{}'", test_name)]),
                        );
                    }
                } else if let Some(profile) = call.profile
                    && !task_profiles.contains(&(required_name, profile))
                    && let Some(span) = find_test_require_span(root, test_name, required_name)
                {
                    let available: Vec<_> =
                        task_profiles.iter().filter(|(n, _)| *n == required_name).map(|(_, p)| *p).collect();
                    emit(
                        Diagnostic::error()
                            .with_message(format!(
                                "required task '{}' does not have profile '{}'",
                                required_name, profile
                            ))
                            .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                            .with_notes(vec![format!("available profiles: {}", available.join(", "))]),
                    );
                }
            }
        }
    }
}

fn validate_pwd_paths(config: &WorkspaceConfig, base_path: &Path, root: &Table, emit: &mut dyn FnMut(Diagnostic)) {
    for (task_name, task_expr) in config.tasks.iter() {
        if let StringExpr::Literal(pwd_literal) = task_expr.pwd {
            let full_path = base_path.join(pwd_literal);
            if !full_path.exists()
                && let Some(span) = find_task_pwd_span(root, task_name)
            {
                emit(
                    Diagnostic::error()
                        .with_message(format!("pwd path '{}' does not exist", pwd_literal))
                        .with_labels(vec![DiagnosticLabel::primary(span).with_message("path not found")])
                        .with_notes(vec![format!("resolved to: {}", full_path.display())]),
                );
            }
        }
    }

    for (test_name, test_variants) in config.tests.iter() {
        for test_expr in test_variants.iter() {
            if let StringExpr::Literal(pwd_literal) = test_expr.pwd {
                let full_path = base_path.join(pwd_literal);
                if !full_path.exists()
                    && let Some(span) = find_test_pwd_span(root, test_name)
                {
                    emit(
                        Diagnostic::error()
                            .with_message(format!("pwd path '{}' does not exist", pwd_literal))
                            .with_labels(vec![DiagnosticLabel::primary(span).with_message("path not found")])
                            .with_notes(vec![format!("resolved to: {}", full_path.display())]),
                    );
                }
            }
        }
    }
}

fn find_group_item_span(root: &Table, group_name: &str, task_name: &str) -> Option<Range<usize>> {
    let group_table = root.get("group")?.as_table()?;
    let group_array = group_table.get(group_name)?.as_array()?;

    for item in group_array {
        let item_name = match &item.value {
            ValueInner::String(s) => {
                let s = s.as_ref();
                s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s)
            }
            ValueInner::Array(arr) if !arr.is_empty() => {
                if let ValueInner::String(s) = &arr[0].value {
                    let s = s.as_ref();
                    s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s)
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        if item_name == task_name {
            return Some(span_to_range(item.span));
        }
    }
    None
}

fn find_require_span(root: &Table, task_name: &str, required_name: &str) -> Option<Range<usize>> {
    let task = table_by_task_name(root, task_name)?;
    if let Some(require_array) = task.get("require").and_then(|v| v.as_array()) {
        for item in require_array {
            if let Some(span) = match_task_call_span(item, required_name) {
                return Some(span);
            }
        }
    }
    None
}

fn find_test_require_span(root: &Table, test_name: &str, required_name: &str) -> Option<Range<usize>> {
    let test_table = root.get("test")?.as_table()?;
    let test_value = test_table.get(test_name)?;

    let search_require = |table: &Table| -> Option<Range<usize>> {
        let require_array = table.get("require")?.as_array()?;
        for item in require_array {
            if let Some(span) = match_task_call_span(item, required_name) {
                return Some(span);
            }
        }
        None
    };

    match &test_value.value {
        ValueInner::Table(table) => search_require(table),
        ValueInner::Array(arr) => {
            for item in arr {
                if let ValueInner::Table(table) = &item.value
                    && let Some(span) = search_require(table)
                {
                    return Some(span);
                }
            }
            None
        }
        _ => None,
    }
}

fn match_task_call_span(item: &TomlValue, target_name: &str) -> Option<Range<usize>> {
    let item_name = match &item.value {
        ValueInner::String(s) => {
            let s = s.as_ref();
            s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s)
        }
        ValueInner::Array(arr) if !arr.is_empty() => {
            if let ValueInner::String(s) = &arr[0].value {
                let s = s.as_ref();
                s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s)
            } else {
                return None;
            }
        }
        _ => return None,
    };

    if item_name == target_name { Some(span_to_range(item.span)) } else { None }
}

fn table_by_task_name<'a>(root: &'a Table<'a>, task_name: &str) -> Option<&'a Table<'a>> {
    for section in ["action", "service"] {
        if let Some(task_table) = root.get(section).and_then(|v| v.as_table())
            && let Some(task) = task_table.get(task_name).and_then(|v| v.as_table())
        {
            return Some(task);
        }
    }
    None
}

fn find_profile_changed_span(root: &Table, task_name: &str, ref_task: &str) -> Option<Range<usize>> {
    let task = table_by_task_name(root, task_name)?;
    let keys = task.get("cache")?.as_table()?.get("key")?.as_array()?;
    for item in keys {
        if let Some(item_table) = item.as_table()
            && let Some(pc_value) = item_table.get("profile_changed")
            && let Some(pc_str) = pc_value.as_str()
            && pc_str == ref_task
        {
            return Some(span_to_range(pc_value.span));
        }
    }
    None
}

fn find_task_pwd_span(root: &Table, task_name: &str) -> Option<Range<usize>> {
    let task = table_by_task_name(root, task_name)?;
    if let Some(pwd_value) = task.get("pwd") {
        return Some(span_to_range(pwd_value.span));
    }
    None
}

fn find_test_pwd_span(root: &Table, test_name: &str) -> Option<Range<usize>> {
    let test_table = root.get("test")?.as_table()?;
    let test_value = test_table.get(test_name)?;

    match &test_value.value {
        ValueInner::Table(table) => table.get("pwd").map(|v| span_to_range(v.span)),
        ValueInner::Array(arr) => {
            for item in arr {
                if let ValueInner::Table(table) = &item.value
                    && let Some(pwd_value) = table.get("pwd")
                {
                    return Some(span_to_range(pwd_value.span));
                }
            }
            None
        }
        _ => None,
    }
}
