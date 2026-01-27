use std::fmt::Write;
use std::path::PathBuf;

use crate::diagnostic::{Diagnostic, DiagnosticLabel, render_diagnostic, toml_error_to_diagnostic};
use crate::function::SetFunctionAction;
use crate::keybinds::{BindingEntry, ChainGroup, Command, InputEvent, Keybinds, Mode};

/// User configuration loaded from ~/.config/devsm.user.toml
#[derive(Default)]
pub struct UserConfig {
    pub keybinds: Keybinds,
    /// Whether the config was loaded from a user config file.
    pub loaded_from_file: bool,
}

/// Returns the path to the user config file.
pub fn user_config_path() -> Option<PathBuf> {
    dirs_path().map(|p| p.join("devsm.user.toml"))
}

/// Returns the default user configuration as a TOML string.
pub fn default_user_config_toml() -> String {
    let keybinds = Keybinds::default();
    let mut output = String::new();

    output.push_str(
        r#"# devsm user configuration
# Save to: ~/.config/devsm.user.toml
#
# Keybinding Modes:
#   global     - Always active (fallback for all modes)
#   task_tree  - Main TUI view for task/job navigation and log viewing
#   pager      - Read-only scrollable views (e.g., config errors)
#   input      - Modal overlays with selection (confirm/cancel)
#   select_search, log_search, task_launcher, test_filter_launcher - Overlay-specific
#
# Tips:
#   - Run `devsm get self-logs --follow` to see keybindings and commands as you use them
#   - Press 'R' (Shift+r) to reload all configs including this user config (default binding)
#   - Set a key to `nan` to unbind it (e.g., g = nan)
#   - Chain bindings: "SPACE l" = "LaunchTask" (press SPACE then l)

"#,
    );

    for (i, mode) in Mode::ALL.iter().enumerate() {
        let mut bindings: Vec<_> = keybinds
            .mode_bindings(*mode)
            .filter_map(|(input, entry)| match entry {
                BindingEntry::Command(cmd) => Some((input, cmd)),
                BindingEntry::Chain(_) => None,
            })
            .collect();
        if bindings.is_empty() {
            continue;
        }

        bindings.sort_by_key(|(input, _)| *input);

        if i > 0 {
            output.push('\n');
        }
        writeln!(output, "[bind.{}]", mode.config_name()).unwrap();

        for (input, command) in bindings {
            let key_str = input.to_string();
            let formatted_key = format_toml_key(&key_str);
            writeln!(output, "{} = \"{}\"", formatted_key, command.config_name()).unwrap();
        }
    }

    output
}

fn format_toml_key(key: &str) -> String {
    let needs_quotes =
        key.is_empty() || key.bytes().any(|b| !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));

    if needs_quotes { format!("\"{}\"", key.replace('\\', "\\\\").replace('"', "\\\"")) } else { key.to_string() }
}

fn dirs_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
}

impl UserConfig {
    /// Loads user config from the default location.
    /// Returns default config if file doesn't exist or can't be parsed.
    pub fn load() -> Self {
        let Some(path) = user_config_path() else {
            kvlog::debug!("No user config path found, using defaults");
            return UserConfig::default();
        };

        let file_name = path.display().to_string();
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_user_config_for_daemon(&content, &file_name) {
                Ok(mut config) => {
                    kvlog::info!("Loaded user config", path = %path.display());
                    config.loaded_from_file = true;
                    config
                }
                Err(err) => {
                    kvlog::error!("Failed to parse user config", path = %path.display(), %err);
                    UserConfig::default()
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                kvlog::debug!("User config not found, using defaults", path = %path.display());
                UserConfig::default()
            }
            Err(err) => {
                kvlog::error!("Failed to read user config", path = %path.display(), ?err);
                UserConfig::default()
            }
        }
    }
}

pub fn reload_user_config() -> Result<UserConfig, String> {
    let Some(path) = user_config_path() else {
        return Ok(UserConfig::default());
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UserConfig::default());
        }
        Err(e) => {
            return Err(format!("Failed to read {}: {}", path.display(), e));
        }
    };

    let file_name = path.display().to_string();
    parse_user_config_for_daemon(&content, &file_name)
}

fn parse_table_binding(
    table: &toml_spanner::value::Table<'_>,
    span: std::ops::Range<usize>,
    file_name: &str,
    content: &str,
) -> Result<Option<Command>, String> {
    for (key, value) in table.iter() {
        let key_name = key.name.as_ref();

        if key_name == "set_function" {
            let Some(inner_table) = value.as_table() else {
                let diagnostic = Diagnostic::error()
                    .with_message("set_function must be a table like {set_function.fn1 = \"...\"}")
                    .with_label(DiagnosticLabel::primary(span));
                return Err(render_diagnostic(file_name, content, &diagnostic));
            };

            for (fn_key, action_value) in inner_table.iter() {
                let fn_name = fn_key.name.as_ref();

                let Some(action_str) = action_value.as_str() else {
                    let diagnostic = Diagnostic::error()
                        .with_message("set_function action must be a string")
                        .with_label(DiagnosticLabel::primary(span));
                    return Err(render_diagnostic(file_name, content, &diagnostic));
                };

                let action = match action_str {
                    "RestartCurrentSelection" => SetFunctionAction::RestartCurrentSelection,
                    _ => {
                        let diagnostic = Diagnostic::error()
                            .with_message(format!("unknown set_function action: '{}'", action_str))
                            .with_label(DiagnosticLabel::primary(span))
                            .with_note("valid actions: RestartCurrentSelection");
                        return Err(render_diagnostic(file_name, content, &diagnostic));
                    }
                };

                return Ok(Some(Command::SetFunction { name: fn_name.into(), action }));
            }
        }
    }

    let diagnostic = Diagnostic::error()
        .with_message("unrecognized table binding")
        .with_label(DiagnosticLabel::primary(span))
        .with_note("expected {set_function.<name> = \"...\"}");
    Err(render_diagnostic(file_name, content, &diagnostic))
}

fn parse_chain_keys(
    key_str: &str,
    span: std::ops::Range<usize>,
    file_name: &str,
    content: &str,
) -> Result<Vec<InputEvent>, String> {
    let mut keys = Vec::new();
    for part in key_str.split_whitespace() {
        let input: InputEvent = part.parse().map_err(|e: String| {
            let diagnostic = Diagnostic::error().with_message(e).with_label(DiagnosticLabel::primary(span.clone()));
            render_diagnostic(file_name, content, &diagnostic)
        })?;
        keys.push(input);
    }
    Ok(keys)
}

fn get_or_create_chain_at_key(keybinds: &mut Keybinds, mode: Mode, key: InputEvent) -> u32 {
    if let Some(BindingEntry::Chain(idx)) = keybinds.lookup_entry(mode, key) {
        return *idx;
    }
    let idx = keybinds.add_chain(ChainGroup::default());
    keybinds.set_binding_entry(mode, key, BindingEntry::Chain(idx));
    idx
}

fn get_or_create_chain_in_group(keybinds: &mut Keybinds, group_idx: u32, key: InputEvent) -> u32 {
    let Some(group) = keybinds.chain(group_idx) else { return group_idx };
    if let Some(BindingEntry::Chain(idx)) = group.lookup(key) {
        return *idx;
    }
    let new_idx = keybinds.add_chain(ChainGroup::default());
    keybinds.chain_mut(group_idx).unwrap().bindings.push((key, BindingEntry::Chain(new_idx)));
    new_idx
}

fn insert_chain_binding(keybinds: &mut Keybinds, mode: Mode, keys: &[InputEvent], entry: BindingEntry) {
    let [first_key, rest @ ..] = keys else { return };

    if rest.is_empty() {
        keybinds.set_binding_entry(mode, *first_key, entry);
        return;
    }

    let mut group_idx = get_or_create_chain_at_key(keybinds, mode, *first_key);

    for &key in &rest[..rest.len() - 1] {
        group_idx = get_or_create_chain_in_group(keybinds, group_idx, key);
    }

    let last_key = rest[rest.len() - 1];
    let Some(group) = keybinds.chain_mut(group_idx) else { return };
    if let Some((_, existing)) = group.bindings.iter_mut().find(|(k, _)| *k == last_key) {
        *existing = entry;
    } else {
        group.bindings.push((last_key, entry));
    }
}

fn set_chain_label(keybinds: &mut Keybinds, mode: Mode, keys: &[InputEvent], label: Box<str>) {
    let [first_key, rest @ ..] = keys else { return };

    let mut group_idx = get_or_create_chain_at_key(keybinds, mode, *first_key);

    for &key in rest {
        group_idx = get_or_create_chain_in_group(keybinds, group_idx, key);
    }

    let Some(group) = keybinds.chain_mut(group_idx) else { return };
    group.label = Some(label);
}

fn parse_user_config_for_daemon(content: &str, file_name: &str) -> Result<UserConfig, String> {
    let toml = toml_spanner::parse(content).map_err(|e| {
        let diagnostic = toml_error_to_diagnostic(&e);
        render_diagnostic(file_name, content, &diagnostic)
    })?;

    let mut keybinds = Keybinds::default();

    let root_table = toml.as_table().ok_or_else(|| {
        let diagnostic = Diagnostic::error()
            .with_message("expected table at root")
            .with_label(DiagnosticLabel::primary(0..content.len().min(1)));
        render_diagnostic(file_name, content, &diagnostic)
    })?;

    for (key, _value) in root_table.iter() {
        if key.name != "bind" {
            let span: std::ops::Range<usize> = key.span.into();
            let diagnostic = Diagnostic::error()
                .with_message(format!("unknown key '{}'", key.name))
                .with_label(DiagnosticLabel::primary(span))
                .with_note("only 'bind' is supported at the root level");
            return Err(render_diagnostic(file_name, content, &diagnostic));
        }
    }

    if let Some(bind_value) = root_table.get("bind") {
        let bind_table = bind_value.as_table().ok_or_else(|| {
            let span: std::ops::Range<usize> = bind_value.span.into();
            let diagnostic =
                Diagnostic::error().with_message("'bind' must be a table").with_label(DiagnosticLabel::primary(span));
            render_diagnostic(file_name, content, &diagnostic)
        })?;

        for (mode_key, mode_value) in bind_table.iter() {
            let mode: Mode = mode_key.name.parse().map_err(|e: String| {
                let span: std::ops::Range<usize> = mode_key.span.into();
                let diagnostic = Diagnostic::error().with_message(e).with_label(DiagnosticLabel::primary(span));
                render_diagnostic(file_name, content, &diagnostic)
            })?;

            let bindings = mode_value.as_table().ok_or_else(|| {
                let span: std::ops::Range<usize> = mode_value.span.into();
                let diagnostic = Diagnostic::error()
                    .with_message(format!("'bind.{}' must be a table", mode_key.name))
                    .with_label(DiagnosticLabel::primary(span));
                render_diagnostic(file_name, content, &diagnostic)
            })?;

            for (key_str, cmd_value) in bindings.iter() {
                let key_span: std::ops::Range<usize> = key_str.span.into();
                let is_chain = key_str.name.as_ref().contains(' ');

                if is_chain {
                    let keys = parse_chain_keys(&key_str.name, key_span.clone(), file_name, content)?;
                    if keys.is_empty() {
                        let diagnostic = Diagnostic::error()
                            .with_message("empty key binding")
                            .with_label(DiagnosticLabel::primary(key_span));
                        return Err(render_diagnostic(file_name, content, &diagnostic));
                    }

                    if let Some(label_table) = cmd_value.as_table() {
                        if let Some(label_value) = label_table.get("Label") {
                            let label_str = label_value.as_str().ok_or_else(|| {
                                let span: std::ops::Range<usize> = label_value.span.into();
                                let diagnostic = Diagnostic::error()
                                    .with_message("Label must be a string")
                                    .with_label(DiagnosticLabel::primary(span));
                                render_diagnostic(file_name, content, &diagnostic)
                            })?;
                            set_chain_label(&mut keybinds, mode, &keys, label_str.into());
                            continue;
                        }
                    }

                    if let Some(cmd_str) = cmd_value.as_str() {
                        let cmd: Command = cmd_str.parse().map_err(|e: String| {
                            let span: std::ops::Range<usize> = cmd_value.span.into();
                            let diagnostic =
                                Diagnostic::error().with_message(e).with_label(DiagnosticLabel::primary(span));
                            render_diagnostic(file_name, content, &diagnostic)
                        })?;
                        insert_chain_binding(&mut keybinds, mode, &keys, BindingEntry::Command(cmd));
                    } else {
                        let span: std::ops::Range<usize> = cmd_value.span.into();
                        let diagnostic = Diagnostic::error()
                            .with_message("chain bindings must map to command string or {Label = \"...\"}")
                            .with_label(DiagnosticLabel::primary(span));
                        return Err(render_diagnostic(file_name, content, &diagnostic));
                    }
                } else {
                    let input: InputEvent = key_str.name.parse().map_err(|e: String| {
                        let diagnostic =
                            Diagnostic::error().with_message(e).with_label(DiagnosticLabel::primary(key_span.clone()));
                        render_diagnostic(file_name, content, &diagnostic)
                    })?;

                    if let Some(label_table) = cmd_value.as_table() {
                        if let Some(label_value) = label_table.get("Label") {
                            let label_str = label_value.as_str().ok_or_else(|| {
                                let span: std::ops::Range<usize> = label_value.span.into();
                                let diagnostic = Diagnostic::error()
                                    .with_message("Label must be a string")
                                    .with_label(DiagnosticLabel::primary(span));
                                render_diagnostic(file_name, content, &diagnostic)
                            })?;
                            set_chain_label(&mut keybinds, mode, &[input], label_str.into());
                            continue;
                        }
                    }

                    let command = if let Some(f) = cmd_value.as_float() {
                        if f.is_nan() {
                            None
                        } else {
                            let span: std::ops::Range<usize> = cmd_value.span.into();
                            let diagnostic = Diagnostic::error()
                                .with_message("expected command string, table, or nan to unbind")
                                .with_label(DiagnosticLabel::primary(span));
                            return Err(render_diagnostic(file_name, content, &diagnostic));
                        }
                    } else if let Some(cmd_str) = cmd_value.as_str() {
                        let cmd: Command = cmd_str.parse().map_err(|e: String| {
                            let span: std::ops::Range<usize> = cmd_value.span.into();
                            let diagnostic =
                                Diagnostic::error().with_message(e).with_label(DiagnosticLabel::primary(span));
                            render_diagnostic(file_name, content, &diagnostic)
                        })?;
                        Some(cmd)
                    } else if let Some(cmd_table) = cmd_value.as_table() {
                        parse_table_binding(cmd_table, cmd_value.span.into(), file_name, content)?
                    } else {
                        let span: std::ops::Range<usize> = cmd_value.span.into();
                        let diagnostic = Diagnostic::error()
                            .with_message("expected command string, table, or nan to unbind")
                            .with_label(DiagnosticLabel::primary(span));
                        return Err(render_diagnostic(file_name, content, &diagnostic));
                    };

                    keybinds.set_binding(mode, input, command);
                }
            }
        }
    }

    Ok(UserConfig { keybinds, loaded_from_file: false })
}

#[cfg(test)]
fn parse_user_config(content: &str) -> Result<UserConfig, String> {
    let toml = toml_spanner::parse(content).map_err(|e| format!("TOML parse error: {e}"))?;

    let mut keybinds = Keybinds::default();

    if let Some(bind_table) = toml.as_table().and_then(|t| t.get("bind")) {
        let bind_table = bind_table.as_table().ok_or("'bind' must be a table")?;

        for (mode_name, mode_value) in bind_table.iter() {
            let mode: Mode = mode_name.name.parse().map_err(|e: String| e)?;
            let bindings = mode_value.as_table().ok_or_else(|| format!("'bind.{}' must be a table", mode_name.name))?;

            for (key_str, cmd_value) in bindings.iter() {
                let input: InputEvent = key_str.name.parse().map_err(|e: String| e)?;

                let command = if let Some(f) = cmd_value.as_float() {
                    if f.is_nan() {
                        None // Unbind
                    } else {
                        return Err(format!(
                            "Invalid binding value for '{}': expected command string or nan",
                            key_str.name
                        ));
                    }
                } else if let Some(cmd_str) = cmd_value.as_str() {
                    let cmd: Command = cmd_str.parse().map_err(|e: String| e)?;
                    Some(cmd)
                } else {
                    return Err(format!(
                        "Invalid binding value for '{}': expected command string or nan",
                        key_str.name
                    ));
                };

                keybinds.set_binding(mode, input, command);
            }
        }
    }

    Ok(UserConfig { keybinds, loaded_from_file: false })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_config_keybinds() {
        let config = parse_user_config("").unwrap();
        let j: InputEvent = "j".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::TaskTree, j), Some(Command::SelectNext), "j is in TaskTree mode");
        let ctrl_c: InputEvent = "C-c".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::Global, ctrl_c), Some(Command::Quit), "C-c is in Global mode");

        let config = parse_user_config(
            r#"
            [bind.global]
            C-j = "SelectNext"
            C-k = "SelectPrev"
            "#,
        )
        .unwrap();
        let ctrl_j: InputEvent = "C-j".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::Global, ctrl_j), Some(Command::SelectNext), "custom binding");

        let config = parse_user_config(
            r#"
            [bind.task_tree]
            g = nan
            "#,
        )
        .unwrap();
        let g: InputEvent = "g".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::TaskTree, g), None, "unbind with nan");

        let config = parse_user_config(
            r#"
            [bind.joblist]
            C-g = "StartGroup"
            "#,
        )
        .unwrap();
        let ctrl_g: InputEvent = "C-g".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::TaskTree, ctrl_g), Some(Command::StartGroup), "mode-specific");

        let config = parse_user_config(
            r#"
            [bind.pager]
            "4" = "LogModeAll"
            "#,
        )
        .unwrap();
        let four: InputEvent = "4".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::Pager, four), Some(Command::LogModeAll), "numeric key 4");

        let config = parse_user_config(
            r#"
            [bind.pager]
            4 = "LogModeAll"
            "#,
        )
        .unwrap();
        let four: InputEvent = "4".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::Pager, four), Some(Command::LogModeAll), "numeric key 4 unquoted");
    }

    #[test]
    fn parse_chain_bindings() {
        let config = parse_user_config_for_daemon(
            r#"
            [bind.task_tree]
            "SPACE".Label = "Leader"
            "SPACE l" = "LaunchTask"
            "#,
            "test.toml",
        )
        .unwrap();

        let space: InputEvent = "SPACE".parse().unwrap();
        let l: InputEvent = "l".parse().unwrap();

        let Some(BindingEntry::Chain(idx)) = config.keybinds.lookup_entry(Mode::TaskTree, space) else {
            panic!("SPACE should be a chain");
        };

        let group = config.keybinds.chain(*idx).expect("chain should exist");
        assert_eq!(group.label.as_deref(), Some("Leader"), "chain should have label 'Leader'");

        let inner = group.lookup(l);
        assert!(matches!(inner, Some(BindingEntry::Command(Command::LaunchTask))), "SPACE l should map to LaunchTask");
    }

    #[test]
    fn parse_nested_chain_bindings() {
        let config = parse_user_config_for_daemon(
            r#"
            [bind.task_tree]
            "SPACE t".Label = "Test"
            "SPACE t n" = "LaunchTestFilter"
            "SPACE t r" = "RerunTestGroup"
            "#,
            "test.toml",
        )
        .unwrap();

        let space: InputEvent = "SPACE".parse().unwrap();
        let t: InputEvent = "t".parse().unwrap();
        let n: InputEvent = "n".parse().unwrap();
        let r: InputEvent = "r".parse().unwrap();

        let Some(BindingEntry::Chain(space_idx)) = config.keybinds.lookup_entry(Mode::TaskTree, space) else {
            panic!("SPACE should be a chain");
        };

        let space_group = config.keybinds.chain(*space_idx).expect("space chain should exist");
        let Some(BindingEntry::Chain(t_idx)) = space_group.lookup(t) else {
            panic!("SPACE t should be a chain");
        };

        let t_group = config.keybinds.chain(*t_idx).expect("t chain should exist");
        assert_eq!(t_group.label.as_deref(), Some("Test"), "chain should have label 'Test'");

        let n_entry = t_group.lookup(n);
        assert!(
            matches!(n_entry, Some(BindingEntry::Command(Command::LaunchTestFilter))),
            "SPACE t n should map to LaunchTestFilter"
        );

        let r_entry = t_group.lookup(r);
        assert!(
            matches!(r_entry, Some(BindingEntry::Command(Command::RerunTestGroup))),
            "SPACE t r should map to RerunTestGroup"
        );
    }
}
