use std::{
    io::{self, Write},
    time::Duration,
};

use extui::{
    Terminal, TerminalFeatures,
    event::Events,
    vt::{BufferWrite, ClipboardSelection, SetClipboard},
};

const QUERY_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClipboardConfig {
    pub mechanism: ClipboardMechanism,
    pub command: Option<Box<str>>,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self { mechanism: ClipboardMechanism::Auto, command: None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardMechanism {
    Auto,
    Osc52,
    Command,
    Disabled,
}

impl std::str::FromStr for ClipboardMechanism {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "auto" => Self::Auto,
            "osc52" | "osc_52" => Self::Osc52,
            "command" | "cli" => Self::Command,
            "disabled" | "none" | "off" => Self::Disabled,
            _ => {
                return Err(format!(
                    "unknown clipboard mechanism '{}'; expected auto, osc52, command, or disabled",
                    value
                ));
            }
        })
    }
}

pub struct CopyReport {
    pub backend: String,
    pub note: String,
}

pub fn copy_text<Input>(
    term: &mut Terminal,
    input: &Input,
    events: &mut Events,
    cached_features: &mut Option<TerminalFeatures>,
    config: &ClipboardConfig,
    text: &str,
    // Runs a clipboard command. `Some(command)` must run that exact command;
    // `None` runs platform fallbacks. In devsm this is forwarded to the event
    // loop, not spawned from the TUI/client thread.
    mut run_command: impl FnMut(&str, Option<&str>) -> io::Result<String>,
) -> io::Result<CopyReport>
where
    Input: std::os::fd::AsFd + std::os::fd::AsRawFd,
{
    match config.mechanism {
        ClipboardMechanism::Auto => {
            copy_auto(term, input, events, cached_features, config.command.as_deref(), text, &mut run_command)
        }
        ClipboardMechanism::Osc52 => {
            write_osc52_copy(term, text)?;
            Ok(CopyReport { backend: "OSC 52".to_string(), note: "sent without probing".to_string() })
        }
        ClipboardMechanism::Command => {
            let Some(command) = config.command.as_deref() else {
                return Err(io::Error::other("clipboard.command is required when mechanism = \"command\""));
            };
            run_command(text, Some(command))?;
            Ok(CopyReport { backend: command.to_string(), note: "configured command".to_string() })
        }
        ClipboardMechanism::Disabled => Err(io::Error::other("clipboard copy is disabled by user config")),
    }
}

fn copy_auto<Input, F>(
    term: &mut Terminal,
    input: &Input,
    events: &mut Events,
    cached_features: &mut Option<TerminalFeatures>,
    preferred_command: Option<&str>,
    text: &str,
    run_command: &mut F,
) -> io::Result<CopyReport>
where
    Input: std::os::fd::AsFd + std::os::fd::AsRawFd,
    F: FnMut(&str, Option<&str>) -> io::Result<String>,
{
    let features = match *cached_features {
        Some(features) => features,
        None => {
            let detected = term.detect_features(
                input,
                events,
                TerminalFeatures::OSC52_CLIPBOARD | TerminalFeatures::OSC52_CLIPBOARD_READ,
                QUERY_TIMEOUT,
            )?;
            *cached_features = Some(detected);
            detected
        }
    };

    if features.contains(TerminalFeatures::OSC52_CLIPBOARD) {
        write_osc52_copy(term, text)?;
        if features.contains(TerminalFeatures::OSC52_CLIPBOARD_READ) {
            if let Some(response) = term.read_clipboard(input, events, ClipboardSelection::Clipboard, QUERY_TIMEOUT)?
                && response.text == text
            {
                return Ok(CopyReport {
                    backend: "OSC 52".to_string(),
                    note: "verified by terminal readback".to_string(),
                });
            }

            match run_command_fallbacks(text, preferred_command, run_command) {
                Ok(command) => {
                    return Ok(CopyReport {
                        backend: command,
                        note: "OSC 52 verification failed; used clipboard command".to_string(),
                    });
                }
                Err(cli_error) => {
                    return Ok(CopyReport {
                        backend: "OSC 52".to_string(),
                        note: format!("sent via detected OSC 52 support; CLI fallback failed: {cli_error}"),
                    });
                }
            }
        }

        return Ok(CopyReport {
            backend: "OSC 52".to_string(),
            note: "sent via DA1/XTGETTCAP-detected support".to_string(),
        });
    }

    match run_command_fallbacks(text, preferred_command, run_command) {
        Ok(command) => Ok(CopyReport { backend: command, note: "OSC 52 support was not detected".to_string() }),
        Err(cli_error) => {
            Err(io::Error::other(format!("OSC 52 support was not detected and CLI fallback failed: {cli_error}")))
        }
    }
}

fn run_command_fallbacks<F>(text: &str, preferred_command: Option<&str>, run_command: &mut F) -> io::Result<String>
where
    F: FnMut(&str, Option<&str>) -> io::Result<String>,
{
    let preferred_error = if let Some(command) = preferred_command {
        match run_command(text, Some(command)) {
            Ok(command) => return Ok(command),
            Err(err) => Some(format!("{command}: {err}")),
        }
    } else {
        None
    };

    match run_command(text, None) {
        Ok(command) => Ok(command),
        Err(err) => match preferred_error {
            Some(preferred_error) => Err(io::Error::other(format!("{preferred_error}; platform fallbacks: {err}"))),
            None => Err(err),
        },
    }
}

fn write_osc52_copy(term: &mut Terminal, text: &str) -> io::Result<()> {
    let mut out = Vec::new();
    SetClipboard { selection: ClipboardSelection::Clipboard, text }.write_to_buffer(&mut out);
    term.write_all(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_command_fallback_tries_platform_defaults_after_preferred_failure() {
        let mut attempts = Vec::new();
        let result = run_command_fallbacks("text", Some("bad-copy"), &mut |_text, command| {
            attempts.push(command.map(str::to_owned));
            match command {
                Some("bad-copy") => Err(io::Error::other("failed")),
                None => Ok("default-copy".to_string()),
                Some(other) => panic!("unexpected command: {other}"),
            }
        });

        assert_eq!(result.unwrap(), "default-copy");
        assert_eq!(attempts, vec![Some("bad-copy".to_string()), None]);
    }
}
