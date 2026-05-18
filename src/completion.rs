use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsony::Jsony;

use crate::config::{self, CliAutocomplete};

const SCHEMA_CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionItem {
    pub value: String,
    pub description: Option<String>,
}

#[derive(Jsony, Debug, Clone, PartialEq, Eq, Default)]
#[jsony(Json)]
pub struct CompletionSchema {
    #[jsony(default = 1)]
    pub version: u32,
    #[jsony(default)]
    pub options: Vec<CompletionOption>,
    #[jsony(default)]
    pub positionals: Vec<CompletionPositional>,
}

#[derive(Jsony, Debug, Clone, PartialEq, Eq)]
#[jsony(Json)]
pub struct CompletionOption {
    pub name: String,
    #[jsony(default)]
    pub short: Option<String>,
    #[jsony(default)]
    pub description: Option<String>,
    #[jsony(default)]
    pub repeatable: bool,
    #[jsony(default)]
    pub value: Option<CompletionValue>,
}

#[derive(Jsony, Debug, Clone, PartialEq, Eq, Default)]
#[jsony(Json)]
pub struct CompletionValue {
    #[jsony(default)]
    pub name: Option<String>,
    #[jsony(default)]
    pub candidates: Vec<CompletionCandidate>,
}

#[derive(Jsony, Debug, Clone, PartialEq, Eq, Default)]
#[jsony(Json)]
pub struct CompletionPositional {
    #[jsony(default)]
    pub name: Option<String>,
    #[jsony(default)]
    pub description: Option<String>,
    #[jsony(default)]
    pub repeatable: bool,
    #[jsony(default)]
    pub candidates: Vec<CompletionCandidate>,
}

#[derive(Jsony, Debug, Clone, PartialEq, Eq)]
#[jsony(Json, untagged)]
pub enum CompletionCandidate {
    Value(String),
    Entry(CompletionCandidateEntry),
}

#[derive(Jsony, Debug, Clone, PartialEq, Eq)]
#[jsony(Json)]
pub struct CompletionCandidateEntry {
    pub value: String,
    #[jsony(default)]
    pub description: Option<String>,
}

pub fn complete_schema_task(
    workspace: &config::WorkspaceConfig<'static>,
    expr: &'static config::TaskConfigExpr<'static>,
    task: &str,
    profile: &str,
    args: &[String],
) -> Option<Vec<CompletionItem>> {
    let CliAutocomplete::Schema { command } = expr.cli.autocomplete else {
        return None;
    };
    let profile = if profile.is_empty() { expr.profiles.first().copied().unwrap_or("") } else { profile };
    let env = config::Environment { profile, param: jsony_value::ValueMap::new(), vars: expr.vars };
    let evaluated = expr.eval(&env).ok()?;
    let task_config = evaluated.config();
    let cwd = workspace.base_path.join(task_config.pwd);
    let config_path = workspace.base_path.join("devsm.toml");
    let schema_json = load_schema_json(&config_path, task, profile, &cwd, task_config.envvar, command)?;
    let schema = parse_schema(&schema_json)?;
    Some(complete_schema(&schema, args))
}

pub fn parse_schema(input: &str) -> Option<CompletionSchema> {
    let schema = jsony::from_json::<CompletionSchema>(input).ok()?;
    if schema.version == 1 { Some(schema) } else { None }
}

pub fn complete_schema(schema: &CompletionSchema, args: &[String]) -> Vec<CompletionItem> {
    let (before, current) = match args.split_last() {
        Some((current, before)) => (before, current.as_str()),
        None => (&[][..], ""),
    };
    let options_stopped = before.iter().any(|arg| arg == "--");

    if !options_stopped {
        if let Some((option, prefix, render)) = current_value_option(schema, current) {
            return complete_option_values(option, prefix, render);
        }

        if let Some(option) = previous_value_option(schema, before) {
            return complete_option_values(option, current, ValueRender::Bare);
        }
    }

    let mut items = Vec::new();
    if !options_stopped && (current.is_empty() || current.starts_with('-')) {
        items.extend(complete_options(schema, before, current));
    }
    if options_stopped || (!current.is_empty() && !current.starts_with('-')) || schema.options.is_empty() {
        items.extend(complete_positionals(schema, before, current));
    }
    items
}

#[derive(Clone, Copy)]
enum ValueRender<'a> {
    Bare,
    LongEquals(&'a str),
}

fn current_value_option<'a>(
    schema: &'a CompletionSchema,
    current: &'a str,
) -> Option<(&'a CompletionOption, &'a str, ValueRender<'a>)> {
    let long = current.strip_prefix("--")?;
    let (name, prefix) = long.split_once('=')?;
    let option = find_long_option(schema, name)?;
    option.value.as_ref()?;
    Some((option, prefix, ValueRender::LongEquals(name)))
}

fn previous_value_option<'a>(schema: &'a CompletionSchema, before: &'a [String]) -> Option<&'a CompletionOption> {
    let previous = before.last()?.as_str();
    if previous == "--" || previous.contains('=') {
        return None;
    }
    if let Some(name) = previous.strip_prefix("--") {
        let option = find_long_option(schema, name)?;
        return option.value.as_ref().map(|_| option);
    }
    if let Some(short) = previous.strip_prefix('-')
        && short.len() == 1
    {
        let option = find_short_option(schema, short)?;
        return option.value.as_ref().map(|_| option);
    }
    None
}

fn complete_option_values(option: &CompletionOption, prefix: &str, render: ValueRender<'_>) -> Vec<CompletionItem> {
    let Some(value) = &option.value else {
        return Vec::new();
    };
    value
        .candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_value = candidate.value();
            if !candidate_value.starts_with(prefix) {
                return None;
            }
            let value = match render {
                ValueRender::Bare => candidate_value.to_owned(),
                ValueRender::LongEquals(name) => format!("--{name}={candidate_value}"),
            };
            Some(CompletionItem { value, description: candidate.description().map(str::to_owned) })
        })
        .collect()
}

fn complete_options(schema: &CompletionSchema, before: &[String], current: &str) -> Vec<CompletionItem> {
    let used = used_nonrepeatable_options(schema, before);
    let mut items = Vec::new();

    let long_prefix = current.strip_prefix("--");
    let short_prefix = current.strip_prefix('-').filter(|_| !current.starts_with("--"));

    for option in &schema.options {
        if !option.repeatable && used.contains(option.name.as_str()) {
            continue;
        }

        if let Some(prefix) = long_prefix {
            if option.name.starts_with(prefix) {
                items.push(CompletionItem {
                    value: format!("--{}", option.name),
                    description: option.description.clone(),
                });
            }
            continue;
        }

        if current.is_empty() || current == "-" {
            items.push(CompletionItem { value: format!("--{}", option.name), description: option.description.clone() });
        }

        if let Some(prefix) = short_prefix
            && let Some(short) = option.short.as_deref()
            && short.starts_with(prefix)
        {
            items.push(CompletionItem { value: format!("-{short}"), description: option.description.clone() });
        }
    }

    items
}

fn complete_positionals(schema: &CompletionSchema, before: &[String], current: &str) -> Vec<CompletionItem> {
    let Some(positional) = current_positional(schema, before) else {
        return Vec::new();
    };
    positional
        .candidates
        .iter()
        .filter_map(|candidate| {
            let value = candidate.value();
            if value.starts_with(current) {
                Some(CompletionItem {
                    value: value.to_owned(),
                    description: candidate.description().map(str::to_owned),
                })
            } else {
                None
            }
        })
        .collect()
}

fn current_positional<'a>(schema: &'a CompletionSchema, before: &[String]) -> Option<&'a CompletionPositional> {
    let index = positional_count(schema, before);
    schema.positionals.get(index).or_else(|| schema.positionals.last().filter(|positional| positional.repeatable))
}

fn used_nonrepeatable_options<'a>(schema: &'a CompletionSchema, args: &[String]) -> HashSet<&'a str> {
    let mut used = HashSet::new();
    let mut i = 0;
    let mut options_stopped = false;

    while i < args.len() {
        let token = args[i].as_str();
        if options_stopped {
            i += 1;
            continue;
        }
        if token == "--" {
            options_stopped = true;
            i += 1;
            continue;
        }
        if let Some(long) = token.strip_prefix("--") {
            let (name, has_inline_value) = long.split_once('=').map_or((long, false), |(name, _)| (name, true));
            if let Some(option) = find_long_option(schema, name) {
                if !option.repeatable {
                    used.insert(option.name.as_str());
                }
                if option.value.is_some() && !has_inline_value {
                    i += 2;
                    continue;
                }
            }
        } else if let Some(short) = token.strip_prefix('-')
            && short.len() == 1
            && let Some(option) = find_short_option(schema, short)
        {
            if !option.repeatable {
                used.insert(option.name.as_str());
            }
            if option.value.is_some() {
                i += 2;
                continue;
            }
        }
        i += 1;
    }

    used
}

fn positional_count(schema: &CompletionSchema, args: &[String]) -> usize {
    let mut count = 0;
    let mut i = 0;
    let mut options_stopped = false;

    while i < args.len() {
        let token = args[i].as_str();
        if !options_stopped && token == "--" {
            options_stopped = true;
            i += 1;
            continue;
        }
        if !options_stopped && token.starts_with("--") {
            let long = token.strip_prefix("--").unwrap();
            let (name, has_inline_value) = long.split_once('=').map_or((long, false), |(name, _)| (name, true));
            if let Some(option) = find_long_option(schema, name)
                && option.value.is_some()
                && !has_inline_value
            {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if !options_stopped
            && let Some(short) = token.strip_prefix('-')
            && short.len() == 1
        {
            if let Some(option) = find_short_option(schema, short)
                && option.value.is_some()
            {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        count += 1;
        i += 1;
    }

    count
}

fn find_long_option<'a>(schema: &'a CompletionSchema, name: &str) -> Option<&'a CompletionOption> {
    schema.options.iter().find(|option| option.name == name)
}

fn find_short_option<'a>(schema: &'a CompletionSchema, short: &str) -> Option<&'a CompletionOption> {
    schema.options.iter().find(|option| option.short.as_deref() == Some(short))
}

impl CompletionCandidate {
    fn value(&self) -> &str {
        match self {
            CompletionCandidate::Value(value) => value,
            CompletionCandidate::Entry(entry) => &entry.value,
        }
    }

    fn description(&self) -> Option<&str> {
        match self {
            CompletionCandidate::Value(_) => None,
            CompletionCandidate::Entry(entry) => entry.description.as_deref(),
        }
    }
}

fn load_schema_json(
    config_path: &Path,
    task: &str,
    profile: &str,
    cwd: &Path,
    envvar: &[(&str, &str)],
    command: &[&str],
) -> Option<String> {
    let cache_path = schema_cache_path(config_path, task, profile, cwd, envvar, command);

    if let Some(path) = cache_path.as_deref()
        && let Some(cached) = read_cached_schema(path, true)
        && parse_schema(&cached).is_some()
    {
        return Some(cached);
    }

    match run_schema_command(cwd, envvar, command).and_then(|json| parse_schema(&json).map(|_| json)) {
        Some(json) => {
            if let Some(path) = cache_path.as_deref() {
                write_cached_schema(path, &json);
            }
            Some(json)
        }
        None => cache_path
            .as_deref()
            .and_then(|path| read_cached_schema(path, false))
            .filter(|json| parse_schema(json).is_some()),
    }
}

fn run_schema_command(cwd: &Path, envvar: &[(&str, &str)], command: &[&str]) -> Option<String> {
    let (program, args) = command.split_first()?;
    let output =
        std::process::Command::new(program).args(args).current_dir(cwd).envs(envvar.iter().copied()).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn schema_cache_path(
    config_path: &Path,
    task: &str,
    profile: &str,
    cwd: &Path,
    envvar: &[(&str, &str)],
    command: &[&str],
) -> Option<PathBuf> {
    let db_path = crate::db::resolve_db_path()?;
    let file_name = db_path.file_name().and_then(|name| name.to_str()).unwrap_or("devsm.db");
    let cache_dir = db_path.with_file_name(format!("{file_name}.cache")).join("autocomplete");

    let mut hasher = blake3::Hasher::new();
    update_hash_path(&mut hasher, config_path);
    update_hash_str(&mut hasher, task);
    update_hash_str(&mut hasher, profile);
    update_hash_path(&mut hasher, cwd);
    for (key, value) in envvar {
        update_hash_str(&mut hasher, key);
        update_hash_str(&mut hasher, value);
    }
    for arg in command {
        update_hash_str(&mut hasher, arg);
    }

    Some(cache_dir.join(format!("{}.json", hasher.finalize().to_hex())))
}

fn update_hash_str(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn update_hash_path(hasher: &mut blake3::Hasher, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let bytes = path.as_os_str().as_bytes();
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn read_cached_schema(path: &Path, require_fresh: bool) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let (timestamp, json) = text.split_once('\n')?;
    let fetched_ms = timestamp.parse::<u64>().ok()?;
    if require_fresh && now_ms().saturating_sub(fetched_ms) > SCHEMA_CACHE_TTL.as_millis() as u64 {
        return None;
    }
    Some(json.to_owned())
}

fn write_cached_schema(path: &Path, json: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, format!("{}\n{}", now_ms(), json));
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> CompletionSchema {
        parse_schema(
            r#"{
                "version": 1,
                "options": [
                    {
                        "name": "env",
                        "short": "e",
                        "description": "Target environment",
                        "value": {
                            "name": "ENV",
                            "candidates": [
                                "xo",
                                { "value": "demo", "description": "Demo environment" }
                            ]
                        }
                    },
                    { "name": "deploy", "description": "Deploy build" },
                    {
                        "name": "component",
                        "repeatable": true,
                        "value": { "candidates": ["libra_webserver", "libra_frontend"] }
                    }
                ],
                "positionals": [
                    { "name": "target", "candidates": ["all", "backend"] }
                ]
            }"#,
        )
        .unwrap()
    }

    fn values(items: Vec<CompletionItem>) -> Vec<String> {
        items.into_iter().map(|item| item.value).collect()
    }

    #[test]
    fn completes_option_names_and_suppresses_used_nonrepeatable() {
        let args = vec!["--deploy".to_string(), "".to_string()];
        assert_eq!(values(complete_schema(&schema(), &args)), vec!["--env", "--component"]);
    }

    #[test]
    fn completes_long_equals_values_with_original_option_prefix() {
        let args = vec!["--env=d".to_string()];
        let items = complete_schema(&schema(), &args);
        assert_eq!(values(items.clone()), vec!["--env=demo"]);
        assert_eq!(items[0].description.as_deref(), Some("Demo environment"));
    }

    #[test]
    fn completes_values_after_previous_option() {
        let args = vec!["--env".to_string(), "x".to_string()];
        assert_eq!(values(complete_schema(&schema(), &args)), vec!["xo"]);

        let args = vec!["-e".to_string(), "".to_string()];
        assert_eq!(values(complete_schema(&schema(), &args)), vec!["xo", "demo"]);
    }

    #[test]
    fn repeatable_options_are_not_suppressed() {
        let args = vec!["--component=libra_webserver".to_string(), "--".to_string()];
        assert!(values(complete_schema(&schema(), &args)).contains(&"--component".to_string()));
    }

    #[test]
    fn completes_positionals_when_current_token_is_not_an_option() {
        let args = vec!["b".to_string()];
        assert_eq!(values(complete_schema(&schema(), &args)), vec!["backend"]);
    }

    #[test]
    fn forwarded_option_terminator_stops_option_parsing() {
        let args = vec!["--".to_string(), "b".to_string()];
        assert_eq!(values(complete_schema(&schema(), &args)), vec!["backend"]);

        let args = vec!["--".to_string(), "--env=".to_string()];
        assert_eq!(values(complete_schema(&schema(), &args)), Vec::<String>::new());
    }
}
