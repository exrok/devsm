use std::fmt::Write;
use std::path::PathBuf;

use crate::diagnostic::{Diagnostic, DiagnosticLabel, render_diagnostic, toml_error_to_diagnostic};
use crate::keybinds::{Command, InputEvent, Keybinds, Mode};

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

    for (i, mode) in Mode::ALL.iter().enumerate() {
        let mut bindings: Vec<_> = keybinds.mode_bindings(*mode).collect();
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
                let input: InputEvent = key_str.name.parse().map_err(|e: String| {
                    let span: std::ops::Range<usize> = key_str.span.into();
                    let diagnostic = Diagnostic::error().with_message(e).with_label(DiagnosticLabel::primary(span));
                    render_diagnostic(file_name, content, &diagnostic)
                })?;

                let command = if let Some(f) = cmd_value.as_float() {
                    if f.is_nan() {
                        None
                    } else {
                        let span: std::ops::Range<usize> = cmd_value.span.into();
                        let diagnostic = Diagnostic::error()
                            .with_message("expected command string or nan to unbind")
                            .with_label(DiagnosticLabel::primary(span));
                        return Err(render_diagnostic(file_name, content, &diagnostic));
                    }
                } else if let Some(cmd_str) = cmd_value.as_str() {
                    let cmd: Command = cmd_str.parse().map_err(|e: String| {
                        let span: std::ops::Range<usize> = cmd_value.span.into();
                        let diagnostic = Diagnostic::error().with_message(e).with_label(DiagnosticLabel::primary(span));
                        render_diagnostic(file_name, content, &diagnostic)
                    })?;
                    Some(cmd)
                } else {
                    let span: std::ops::Range<usize> = cmd_value.span.into();
                    let diagnostic = Diagnostic::error()
                        .with_message("expected command string or nan to unbind")
                        .with_label(DiagnosticLabel::primary(span));
                    return Err(render_diagnostic(file_name, content, &diagnostic));
                };

                keybinds.set_binding(mode, input, command);
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
        assert_eq!(config.keybinds.lookup(Mode::Global, j), Some(Command::SelectNext), "empty config uses defaults");

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
            [bind.global]
            g = nan
            "#,
        )
        .unwrap();
        let g: InputEvent = "g".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::Global, g), None, "unbind with nan");

        let config = parse_user_config(
            r#"
            [bind.joblist]
            C-g = "StartGroup"
            "#,
        )
        .unwrap();
        let ctrl_g: InputEvent = "C-g".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::JobList, ctrl_g), Some(Command::StartGroup), "mode-specific");

        // Test numeric key binding
        let config = parse_user_config(
            r#"
            [bind.global]
            "4" = "LogModeAll"
            "#,
        )
        .unwrap();
        let four: InputEvent = "4".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::Global, four), Some(Command::LogModeAll), "numeric key 4");

        // Verify the numeric key works without quotes too
        let config = parse_user_config(
            r#"
            [bind.global]
            4 = "LogModeAll"
            "#,
        )
        .unwrap();
        let four: InputEvent = "4".parse().unwrap();
        assert_eq!(config.keybinds.lookup(Mode::Global, four), Some(Command::LogModeAll), "numeric key 4 unquoted");
    }
}
