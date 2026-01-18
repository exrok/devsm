use std::path::PathBuf;

use crate::keybinds::{Command, InputEvent, Keybinds, Mode};

/// User configuration loaded from ~/.config/devsm.user.toml
#[derive(Default)]
pub struct UserConfig {
    pub keybinds: Keybinds,
}

/// Returns the path to the user config file.
pub fn user_config_path() -> Option<PathBuf> {
    dirs_path().map(|p| p.join("devsm.user.toml"))
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

        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_user_config_for_daemon(&content) {
                Ok(config) => {
                    kvlog::info!("Loaded user config", path = %path.display());
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

fn parse_user_config_for_daemon(content: &str) -> Result<UserConfig, String> {
    let toml = toml_spanner::parse(content).map_err(|e| format!("TOML parse error: {e}"))?;

    let mut keybinds = Keybinds::default();

    if let Some(bind_table) = toml.as_table().and_then(|t| t.get("bind")) {
        let bind_table = bind_table.as_table().ok_or("'bind' must be a table")?;

        for (mode_name, mode_value) in bind_table.iter() {
            let mode: Mode = mode_name.name.parse().map_err(|e: String| e)?;
            let bindings = mode_value
                .as_table()
                .ok_or_else(|| format!("'bind.{}' must be a table", mode_name.name))?;

            for (key_str, cmd_value) in bindings.iter() {
                let input: InputEvent = key_str.name.parse().map_err(|e: String| e)?;

                let command = if let Some(f) = cmd_value.as_float() {
                    if f.is_nan() {
                        None
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

    Ok(UserConfig { keybinds })
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

    Ok(UserConfig { keybinds })
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
    }
}
