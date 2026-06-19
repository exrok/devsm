use bumpalo::Bump;
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;
use toml_spanner::{Item, Table, Value};

use crate::config::toml_handler;
use crate::config::{StringExpr, TaskKind, WorkspaceConfig};
use crate::diagnostic::{Diagnostic, DiagnosticLabel, DiagnosticLevel, emit_diagnostic, toml_error_to_diagnostic};
use crate::workspace::require_graph::{NameLookup, ProfileTaskInput, RequireAnalysis};

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
            if name_kinds.get(short) == Some(&kind_filter.unwrap()) {
                Some(short)
            } else {
                None
            }
        }
        Some(TaskKind::Test) => {
            if test_names.contains(short) {
                Some(short)
            } else {
                None
            }
        }
        None => {
            if name_kinds.contains_key(name) || test_names.contains(name) {
                Some(name)
            } else {
                None
            }
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
        let inferred_profiles = requirement_profile_predicates(task_expr.require);
        if task_has_profiles_field(root, name) {
            for profile in inferred_profiles {
                if !task_expr.profiles.contains(&profile) {
                    let label = find_require_array_span(root, name)
                        .map(|span| vec![DiagnosticLabel::primary(span).with_message("profile predicate here")])
                        .unwrap_or_default();
                    emit(
                        Diagnostic::error()
                            .with_message(format!(
                                "profile-dependent require uses profile '{}' not listed in `profiles`",
                                profile
                            ))
                            .with_labels(label)
                            .with_notes(vec![format!("add '{}' to the explicit profiles list", profile)]),
                    );
                }
            }
        } else {
            for profile in inferred_profiles {
                task_profiles.insert((name, profile));
            }
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
        for req_expr in task_expr.require.iter() {
            req_expr.visit_requirements(&mut |req| {
                let crate::config::Requirement::Task(call) = req else { return };
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
                    return;
                };
                if let Some(profile) = call.profile
                    && !task_profiles.contains(&(short, profile))
                    && let Some(span) = find_require_span(root, task_name, required_name)
                {
                    let available: Vec<_> =
                        task_profiles.iter().filter(|(n, _)| *n == short).map(|(_, p)| *p).collect();
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
            });
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
        for req_expr in test_expr.require.iter() {
            req_expr.visit_requirements(&mut |req| {
                let crate::config::Requirement::Task(call) = req else { return };
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
                    return;
                };
                if let Some(profile) = call.profile
                    && !task_profiles.contains(&(short, profile))
                    && let Some(span) = find_test_require_span(root, test_name, required_name)
                {
                    let available: Vec<_> =
                        task_profiles.iter().filter(|(n, _)| *n == short).map(|(_, p)| *p).collect();
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
            });
        }
    }
}

fn requirement_profile_predicates<'a>(require: &'a [crate::config::RequirementExpr<'a>]) -> Vec<&'a str> {
    let mut profiles = Vec::new();
    crate::config::RequirementListExpr { items: require }.visit_profile_predicates(&mut |profile| {
        if !profiles.contains(&profile) {
            profiles.push(profile);
        }
    });
    profiles
}

fn task_has_profiles_field(root: &Table, task_name: &str) -> bool {
    table_by_task_name(root, task_name).is_some_and(|table| table.get("profiles").is_some())
}

const VALIDATE_OTHER_PROFILE: &str = "\0devsm-other-profile";

fn analysis_profiles<'a>(
    declared_profiles: &[&'a str],
    require: &'a [crate::config::RequirementExpr<'a>],
) -> Vec<String> {
    let mut profiles: Vec<String> = if declared_profiles.is_empty() {
        vec![String::new()]
    } else {
        declared_profiles.iter().map(|p| (*p).to_string()).collect()
    };
    crate::config::RequirementListExpr { items: require }.visit_profile_predicates(&mut |profile| {
        if !profiles.iter().any(|p| p == profile) {
            profiles.push(profile.to_string());
        }
    });
    profiles.push(VALIDATE_OTHER_PROFILE.to_string());
    profiles
}

#[allow(clippy::too_many_arguments)]
fn push_validate_variant<'a>(
    base: usize,
    base_name: &str,
    kind: TaskKind,
    require_exprs: &'a [crate::config::RequirementExpr<'a>],
    profile: String,
    variant_base: &mut Vec<usize>,
    variant_kind: &mut Vec<TaskKind>,
    variant_fallback: &mut Vec<bool>,
    profile_storage: &mut Vec<String>,
    name_storage: &mut Vec<String>,
    requirement_storage: &mut Vec<Vec<crate::config::Requirement<'a>>>,
    variant_map: &mut hashbrown::HashMap<(usize, Box<str>), usize>,
    fallback_map: &mut hashbrown::HashMap<usize, usize>,
) {
    let fallback = profile == VALIDATE_OTHER_PROFILE;
    let eval_profile = if fallback { VALIDATE_OTHER_PROFILE } else { profile.as_str() };
    let mut requirements = Vec::new();
    crate::config::RequirementListExpr { items: require_exprs }
        .eval_for_profile_append(eval_profile, &mut requirements);
    let input_idx = variant_base.len();
    if fallback {
        fallback_map.insert(base, input_idx);
        name_storage.push(format!("{base_name}:<other>"));
    } else {
        variant_map.insert((base, profile.clone().into()), input_idx);
        if profile.is_empty() {
            name_storage.push(base_name.to_string());
        } else {
            name_storage.push(format!("{base_name}:{profile}"));
        }
    }
    requirement_storage.push(requirements);
    profile_storage.push(profile);
    variant_base.push(base);
    variant_kind.push(kind);
    variant_fallback.push(fallback);
}

fn duplicate_resource_name<'a>(requirements: &'a [crate::config::Requirement<'a>]) -> Option<&'a str> {
    for (i, req) in requirements.iter().enumerate() {
        let crate::config::Requirement::Resource { name, .. } = req else { continue };
        for prior in &requirements[..i] {
            if let crate::config::Requirement::Resource { name: prior_name, .. } = prior
                && prior_name == name
            {
                return Some(name);
            }
        }
    }
    None
}

fn validate_require_graph(config: &WorkspaceConfig, root: &Table, emit: &mut dyn FnMut(Diagnostic)) {
    let mut name_map: hashbrown::HashMap<&str, usize> = hashbrown::HashMap::new();
    let mut base_names: Vec<&str> = Vec::with_capacity(config.tasks.len() + config.tests.len());
    let mut base_kinds: Vec<TaskKind> = Vec::with_capacity(config.tasks.len() + config.tests.len());
    let mut default_profiles: Vec<String> = Vec::with_capacity(config.tasks.len() + config.tests.len());
    let mut variant_base: Vec<usize> = Vec::new();
    let mut variant_kind: Vec<TaskKind> = Vec::new();
    let mut variant_fallback: Vec<bool> = Vec::new();
    let mut profile_storage: Vec<String> = Vec::new();
    let mut name_storage: Vec<String> = Vec::new();
    let mut requirement_storage: Vec<Vec<crate::config::Requirement<'_>>> = Vec::new();
    let mut variant_map: hashbrown::HashMap<(usize, Box<str>), usize> = hashbrown::HashMap::new();
    let mut fallback_map: hashbrown::HashMap<usize, usize> = hashbrown::HashMap::new();

    for (name, expr) in config.tasks.iter() {
        if name_map.contains_key(*name) {
            continue;
        }
        let base = base_names.len();
        name_map.insert(*name, base);
        base_names.push(name);
        base_kinds.push(expr.kind);
        default_profiles.push(expr.profiles.first().copied().unwrap_or("").to_string());
        for profile in analysis_profiles(expr.profiles, expr.require) {
            push_validate_variant(
                base,
                name,
                expr.kind,
                expr.require,
                profile,
                &mut variant_base,
                &mut variant_kind,
                &mut variant_fallback,
                &mut profile_storage,
                &mut name_storage,
                &mut requirement_storage,
                &mut variant_map,
                &mut fallback_map,
            );
        }
    }

    for (name, test_expr) in config.tests.iter() {
        if name_map.contains_key(*name) {
            continue;
        }
        let base = base_names.len();
        name_map.insert(*name, base);
        base_names.push(name);
        base_kinds.push(TaskKind::Test);
        default_profiles.push(String::new());
        for profile in analysis_profiles(&[], test_expr.require) {
            push_validate_variant(
                base,
                name,
                TaskKind::Test,
                test_expr.require,
                profile,
                &mut variant_base,
                &mut variant_kind,
                &mut variant_fallback,
                &mut profile_storage,
                &mut name_storage,
                &mut requirement_storage,
                &mut variant_map,
                &mut fallback_map,
            );
        }
    }

    if variant_base.is_empty() {
        return;
    }

    struct StrLookup<'a> {
        map: &'a hashbrown::HashMap<&'a str, usize>,
        base_kinds: &'a [TaskKind],
        default_profiles: &'a [String],
        variant_map: &'a hashbrown::HashMap<(usize, Box<str>), usize>,
        fallback_map: &'a hashbrown::HashMap<usize, usize>,
    }
    impl<'a> NameLookup for StrLookup<'a> {
        fn lookup(&self, name: &str, profile: Option<&str>) -> Option<usize> {
            let (kind_filter, short) = match name.split_once('.') {
                Some(("service", rest)) => (Some(TaskKind::Service), rest),
                Some(("action", rest)) => (Some(TaskKind::Action), rest),
                Some(("test", rest)) => (Some(TaskKind::Test), rest),
                _ => (None, name),
            };
            let idx = self.map.get(short).copied()?;
            match kind_filter {
                Some(k) if self.base_kinds[idx] != k => return None,
                Some(_) | None => {}
            };
            let requested_profile = profile.unwrap_or_else(|| self.default_profiles[idx].as_str());
            self.variant_map
                .get(&(idx, requested_profile.into()))
                .copied()
                .or_else(|| self.fallback_map.get(&idx).copied())
        }
    }

    let inputs: Vec<ProfileTaskInput<'_>> = variant_base
        .iter()
        .enumerate()
        .map(|(idx, base)| ProfileTaskInput {
            base_task: crate::workspace::BaseTaskIndex::new_or_panic(*base),
            profile: profile_storage[idx].as_str(),
            fallback: variant_fallback[idx],
            name: name_storage[idx].as_str(),
            kind: variant_kind[idx],
            require: requirement_storage[idx].as_slice(),
        })
        .collect();
    let lookup = StrLookup {
        map: &name_map,
        base_kinds: &base_kinds,
        default_profiles: &default_profiles,
        variant_map: &variant_map,
        fallback_map: &fallback_map,
    };
    let analysis = RequireAnalysis::build_profiled(&inputs, &lookup);

    let mut emitted = HashSet::new();
    for (idx, base) in variant_base.iter().enumerate() {
        if let Some(resource) = duplicate_resource_name(&requirement_storage[idx])
            && emitted.insert((*base, format!("duplicate resource `{resource}` within evaluated `require`")))
        {
            let name = base_names[*base];
            let label = find_require_array_span(root, name)
                .map(|span| vec![DiagnosticLabel::primary(span).with_message("declared here")])
                .unwrap_or_default();
            emit(
                Diagnostic::error()
                    .with_message(format!("duplicate resource `{resource}` within evaluated `require`"))
                    .with_labels(label),
            );
        }
        if variant_fallback[idx] {
            continue;
        }
        let bti = crate::workspace::BaseTaskIndex::new_or_panic(*base);
        let profile = profile_storage[idx].as_str();
        let Err(message) = analysis.problem_for_profile(bti, profile) else { continue };
        if !emitted.insert((*base, message.clone())) {
            continue;
        }
        let name = base_names[*base];
        let label = find_require_array_span(root, name)
            .map(|span| vec![DiagnosticLabel::primary(span).with_message("declared here")])
            .unwrap_or_default();
        emit(Diagnostic::error().with_message(message).with_labels(label));
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
    match item.value() {
        Value::String(s) => {
            let item_name = s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s);
            if item_name == target_name { Some(item.span().range()) } else { None }
        }
        Value::Array(arr) if !arr.is_empty() => {
            if let Value::String(s) = arr.as_slice()[0].value() {
                let item_name = s.rsplit_once(':').map(|(n, _)| n).unwrap_or(s);
                if item_name == target_name {
                    return Some(item.span().range());
                }
            }
            for child in arr {
                if let Some(span) = match_task_call_span(child, target_name) {
                    return Some(span);
                }
            }
            None
        }
        Value::Table(table) if table.get("if").is_some() => {
            for key in ["then", "or_else", "else"] {
                if let Some(branch) = table.get(key)
                    && let Some(span) = match_task_call_span(branch, target_name)
                {
                    return Some(span);
                }
            }
            None
        }
        _ => None,
    }
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
