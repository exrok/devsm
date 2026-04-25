use bumpalo::Bump;
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;
use toml_spanner::{Item, Table, Value};

use crate::config::toml_handler;
use crate::config::{StringExpr, TaskKind, WorkspaceConfig};
use crate::diagnostic::{Diagnostic, DiagnosticLabel, DiagnosticLevel, emit_diagnostic, toml_error_to_diagnostic};
use crate::workspace::require_graph::{NameLookup, RequireAnalysis, TaskInput};

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

    let arena = toml_spanner::Arena::new();
    let root = match toml_spanner::parse(content, &arena) {
        Ok(value) => value,
        Err(err) => {
            let diagnostic = toml_error_to_diagnostic(&err, content);
            emit_diagnostic(&file_name, content, &diagnostic);
            return Ok(false);
        }
    };
    let root = root.table();

    let mut has_errors = false;
    let mut warnings = 0usize;
    let mut emit = |diag: Diagnostic| {
        match diag.level {
            DiagnosticLevel::Error => has_errors = true,
            DiagnosticLevel::Warning => warnings += 1,
        }
        emit_diagnostic(&file_name, content, &diag);
    };

    if let Some(bind_value) = root.get("bind") {
        let Some(bind_table) = bind_value.as_table() else {
            emit(
                Diagnostic::error()
                    .with_message("'bind' must be a table")
                    .with_labels(vec![DiagnosticLabel::primary(bind_value.span().range())]),
            );
            return Ok(false);
        };

        let valid_modes = ["global", "joblist", "log", "search", "group_select"];
        for (mode_key, mode_value) in bind_table {
            let mode_name = mode_key.name.as_ref();
            if !valid_modes.contains(&mode_name) {
                emit(
                    Diagnostic::error()
                        .with_message(format!("unknown mode '{}'", mode_name))
                        .with_labels(vec![DiagnosticLabel::primary(mode_key.span.range())])
                        .with_notes(vec![format!("valid modes are: {}", valid_modes.join(", "))]),
                );
                continue;
            }

            let Some(bindings) = mode_value.as_table() else {
                emit(
                    Diagnostic::error()
                        .with_message(format!("'bind.{}' must be a table", mode_name))
                        .with_labels(vec![DiagnosticLabel::primary(mode_value.span().range())]),
                );
                continue;
            };

            for (key_str, cmd_value) in bindings {
                if let Some(f) = cmd_value.as_f64() {
                    if !f.is_nan() {
                        emit(
                            Diagnostic::error()
                                .with_message("invalid binding value")
                                .with_labels(vec![
                                    DiagnosticLabel::primary(cmd_value.span().range())
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
                                DiagnosticLabel::primary(cmd_value.span().range())
                                    .with_message("expected command string or nan"),
                            ])
                            .with_notes(vec![format!("binding for key '{}'", key_str.name)]),
                    );
                }
            }
        }
    }

    for (key, _value) in root {
        let key_name = key.name;
        if key_name != "bind" {
            emit(
                Diagnostic::warning()
                    .with_message(format!("unknown top-level key '{}'", key_name))
                    .with_labels(vec![DiagnosticLabel::primary(key.span.range())])
                    .with_notes(vec!["user config only supports the 'bind' section".to_string()]),
            );
        }
    }

    if has_errors {
        Ok(false)
    } else {
        eprintln!("{}", validity_summary(path, warnings));
        Ok(true)
    }
}

fn validate_workspace_config(path: &Path, content: &str, options: &ValidateOptions) -> anyhow::Result<bool> {
    let file_name = path.display().to_string();

    let bump = Bump::new();
    let base_path = path.parent().unwrap_or(Path::new("."));

    let mut has_errors = false;
    let mut warnings = 0usize;
    let mut emit = |diag: Diagnostic| {
        match diag.level {
            DiagnosticLevel::Error => has_errors = true,
            DiagnosticLevel::Warning => warnings += 1,
        }
        emit_diagnostic(&file_name, content, &diag);
    };

    let arena = toml_spanner::Arena::new();
    let mut doc = toml_spanner::parse_recoverable(content, &arena);
    let workspace_config = toml_handler::parse_workspace(base_path, &bump, &mut doc).ok();
    doc.compute_error_paths();
    for err in doc.errors() {
        emit(toml_error_to_diagnostic(err, content));
    }

    let Some(workspace_config) = workspace_config else {
        return Ok(false);
    };

    validate_cross_references(&workspace_config, doc.table(), &mut emit);
    validate_require_graph(&workspace_config, doc.table(), &mut emit);

    if !options.skip_path_checks {
        validate_pwd_paths(&workspace_config, base_path, doc.table(), &mut emit);
    }

    if has_errors {
        Ok(false)
    } else {
        eprintln!("{}", validity_summary(path, warnings));
        Ok(true)
    }
}

fn validity_summary(path: &Path, warnings: usize) -> String {
    match warnings {
        0 => format!("{} is valid", path.display()),
        1 => format!("{} is valid but has 1 warning.", path.display()),
        n => format!("{} is valid but has {} warnings.", path.display(), n),
    }
}

/// Resolves a `kind.name` or bare task reference to its short name, mirroring
/// the daemon's [`crate::workspace::WorkspaceState::lookup_name`] semantics.
/// Returns `Some(short_name)` if the reference resolves, `None` otherwise.
fn resolve_qualified_reference<'a>(
    name: &'a str,
    name_kinds: &hashbrown::HashMap<&str, TaskKind>,
    test_names: &HashSet<&str>,
) -> Option<&'a str> {
    let (kind_filter, short) = match name.split_once('.') {
        Some(("service", rest)) => (Some(TaskKind::Service), rest),
        Some(("action", rest)) => (Some(TaskKind::Action), rest),
        Some(("test", rest)) => (Some(TaskKind::Test), rest),
        _ => (None, name),
    };
    match kind_filter {
        Some(TaskKind::Service) | Some(TaskKind::Action) => {
            if name_kinds.get(short) == Some(&kind_filter.unwrap()) { Some(short) } else { None }
        }
        Some(TaskKind::Test) => {
            if test_names.contains(short) { Some(short) } else { None }
        }
        None => {
            if name_kinds.contains_key(name) || test_names.contains(name) { Some(name) } else { None }
        }
    }
}

fn validate_cross_references(config: &WorkspaceConfig, root: &Table, emit: &mut dyn FnMut(Diagnostic)) {
    let mut task_profiles: HashSet<(&str, &str)> = HashSet::new();
    let mut task_names: HashSet<&str> = HashSet::new();
    let mut name_kinds: hashbrown::HashMap<&str, TaskKind> = hashbrown::HashMap::new();
    let mut test_names: HashSet<&str> = HashSet::new();

    for (name, task_expr) in config.tasks.iter() {
        task_names.insert(name);
        name_kinds.insert(name, task_expr.kind);
        for profile in task_expr.profiles.iter() {
            task_profiles.insert((name, profile));
        }
    }

    for (name, _) in config.tests.iter() {
        task_names.insert(name);
        test_names.insert(name);
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
        for req in task_expr.require.iter() {
            let crate::config::Requirement::Task(call) = req else { continue };
            let required_name: &str = &call.name;
            let resolved = resolve_qualified_reference(required_name, &name_kinds, &test_names);

            let Some(short) = resolved else {
                if let Some(span) = find_require_span(root, task_name, required_name) {
                    emit(
                        Diagnostic::error()
                            .with_message(format!("required task '{}' does not exist", required_name))
                            .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                            .with_notes(vec![format!("in task '{}'", task_name)]),
                    );
                }
                continue;
            };
            if let Some(profile) = call.profile
                && !task_profiles.contains(&(short, profile))
                && let Some(span) = find_require_span(root, task_name, required_name)
            {
                let available: Vec<_> = task_profiles.iter().filter(|(n, _)| *n == short).map(|(_, p)| *p).collect();
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

    for (test_name, test_expr) in config.tests.iter() {
        for req in test_expr.require.iter() {
            let crate::config::Requirement::Task(call) = req else { continue };
            let required_name: &str = &call.name;
            let resolved = resolve_qualified_reference(required_name, &name_kinds, &test_names);

            let Some(short) = resolved else {
                if let Some(span) = find_test_require_span(root, test_name, required_name) {
                    emit(
                        Diagnostic::error()
                            .with_message(format!("required task '{}' does not exist", required_name))
                            .with_labels(vec![DiagnosticLabel::primary(span).with_message("referenced here")])
                            .with_notes(vec![format!("in test '{}'", test_name)]),
                    );
                }
                continue;
            };
            if let Some(profile) = call.profile
                && !task_profiles.contains(&(short, profile))
                && let Some(span) = find_test_require_span(root, test_name, required_name)
            {
                let available: Vec<_> = task_profiles.iter().filter(|(n, _)| *n == short).map(|(_, p)| *p).collect();
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

fn validate_require_graph(config: &WorkspaceConfig, root: &Table, emit: &mut dyn FnMut(Diagnostic)) {
    let mut tasks: Vec<TaskInput> = Vec::with_capacity(config.tasks.len() + config.tests.len());
    let mut name_map: hashbrown::HashMap<&str, usize> = hashbrown::HashMap::new();
    let mut name_kind: Vec<&str> = Vec::new();

    for (name, expr) in config.tasks.iter() {
        if name_map.contains_key(*name) {
            continue;
        }
        name_map.insert(*name, tasks.len());
        tasks.push(TaskInput { name, kind: expr.kind, require: expr.require });
        name_kind.push(*name);
    }

    for (name, test_expr) in config.tests.iter() {
        if name_map.contains_key(*name) {
            continue;
        }
        name_map.insert(*name, tasks.len());
        tasks.push(TaskInput { name, kind: TaskKind::Test, require: test_expr.require });
        name_kind.push(*name);
    }

    if tasks.is_empty() {
        return;
    }

    struct StrLookup<'a> {
        map: &'a hashbrown::HashMap<&'a str, usize>,
        tasks: &'a [TaskInput<'a>],
    }
    impl<'a> NameLookup for StrLookup<'a> {
        fn lookup(&self, name: &str) -> Option<usize> {
            let (kind_filter, short) = match name.split_once('.') {
                Some(("service", rest)) => (Some(TaskKind::Service), rest),
                Some(("action", rest)) => (Some(TaskKind::Action), rest),
                Some(("test", rest)) => (Some(TaskKind::Test), rest),
                _ => (None, name),
            };
            let idx = self.map.get(short).copied()?;
            match kind_filter {
                Some(k) if self.tasks[idx].kind == k => Some(idx),
                Some(_) => None,
                None => Some(idx),
            }
        }
    }
    let analysis = RequireAnalysis::build(&tasks, &StrLookup { map: &name_map, tasks: &tasks });

    for (name, message) in analysis.iter_problems(&tasks) {
        let label = find_require_array_span(root, name)
            .map(|span| vec![DiagnosticLabel::primary(span).with_message("declared here")])
            .unwrap_or_default();
        emit(Diagnostic::error().with_message(message.to_string()).with_labels(label));
    }
}

fn find_require_array_span(root: &Table, task_name: &str) -> Option<Range<usize>> {
    for section in ["action", "service"] {
        if let Some(task_table) = root.get(section).and_then(|v| v.as_table())
            && let Some(task) = task_table.get(task_name).and_then(|v| v.as_table())
            && let Some(req) = task.get("require")
        {
            return Some(req.span().range());
        }
    }
    let test_table = root.get("test")?.as_table()?;
    let test_value = test_table.get(task_name)?;
    match test_value.value() {
        Value::Table(table) => Some(table.get("require")?.span().range()),
        Value::Array(arr) => {
            for item in arr {
                if let Value::Table(t) = item.value()
                    && let Some(req) = t.get("require")
                {
                    return Some(req.span().range());
                }
            }
            None
        }
        _ => None,
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

    for (test_name, test_expr) in config.tests.iter() {
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

fn find_group_item_span(root: &Table, group_name: &str, task_name: &str) -> Option<Range<usize>> {
    let group_table = root.get("group")?.as_table()?;
    let group_array = group_table.get(group_name)?.as_array()?;

    for item in group_array {
        let item_name = match item.value() {
            Value::String(s) => s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s),
            Value::Array(arr) if !arr.is_empty() => {
                if let Value::String(s) = arr.as_slice()[0].value() {
                    s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s)
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        if item_name == task_name {
            return Some(item.span().range());
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

    match test_value.value() {
        Value::Table(table) => search_require(table),
        Value::Array(arr) => {
            for item in arr {
                if let Value::Table(table) = item.value()
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

fn match_task_call_span(item: &Item, target_name: &str) -> Option<Range<usize>> {
    let item_name = match item.value() {
        Value::String(s) => s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s),
        Value::Array(arr) if !arr.is_empty() => {
            if let Value::String(s) = arr.as_slice()[0].value() {
                s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s)
            } else {
                return None;
            }
        }
        _ => return None,
    };

    if item_name == target_name { Some(item.span().range()) } else { None }
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
    let keys = task["cache"]["key"].as_array()?;
    for item in keys {
        if let Some(item_table) = item.as_table()
            && let Some(pc_value) = item_table.get("profile_changed")
            && let Some(pc_str) = pc_value.as_str()
            && pc_str == ref_task
        {
            return Some(pc_value.span().range());
        }
    }
    None
}

fn find_task_pwd_span(root: &Table, task_name: &str) -> Option<Range<usize>> {
    let task = table_by_task_name(root, task_name)?;
    if let Some(pwd_value) = task.get("pwd") {
        return Some(pwd_value.span().range());
    }
    None
}

fn find_test_pwd_span(root: &Table, test_name: &str) -> Option<Range<usize>> {
    match root["test"][test_name].value()? {
        Value::Table(table) => Some(table["pwd"].span().range()),
        Value::Array(arr) => {
            for item in arr {
                return Some(item["pwd"].span().range());
            }
            None
        }
        _ => None,
    }
}
