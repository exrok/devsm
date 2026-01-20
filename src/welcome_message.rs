use extui::{Rect, vt};

use crate::keybinds::{Command, Keybinds};

enum WelcomeLine<'a> {
    Text(&'static str),
    TextBinding(&'static str),
    Section(&'static str),
    Binding {
        key: String,
        desc: &'static str,
    },
    Binding3 {
        key1: String,
        key2: String,
        key3: String,
        desc: &'static str,
    },
    Empty,
    #[expect(unused, reason = "reserved for future use")]
    Dynamic(&'a str),
}

const KEY_WIDTH: usize = 13;
const SPACES: &[u8; KEY_WIDTH] = b"             ";
const COLUMN_GAP: usize = 4;

fn line_width(line: &WelcomeLine) -> usize {
    match line {
        WelcomeLine::Text(s) | WelcomeLine::TextBinding(s) | WelcomeLine::Section(s) => s.len(),
        WelcomeLine::Binding { desc, .. } | WelcomeLine::Binding3 { desc, .. } => 2 + KEY_WIDTH + desc.len(),
        WelcomeLine::Dynamic(s) => s.len(),
        WelcomeLine::Empty => 0,
    }
}

fn render_line(buf: &mut Vec<u8>, line: &WelcomeLine) {
    use extui::{Color, splat};

    let section_style = Color::Grey[18].as_fg();
    let text_style = Color::Grey[14].as_fg();
    let key_style = Color::Grey[23].as_fg();
    let desc_style = Color::Grey[14].as_fg();

    match line {
        WelcomeLine::Text(s) | WelcomeLine::Dynamic(s) => splat!(buf, text_style, *s),
        WelcomeLine::TextBinding(s) => splat!(buf, key_style, *s, vt::CLEAR_STYLE),
        WelcomeLine::Section(s) => splat!(buf, section_style, *s),
        WelcomeLine::Binding { key, desc } => {
            splat!(buf, "  ", key_style, key, vt::CLEAR_STYLE);
            buf.extend_from_slice(&SPACES[..KEY_WIDTH.saturating_sub(key.chars().count())]);
            splat!(buf, desc_style, *desc);
        }
        WelcomeLine::Binding3 { key1, key2, key3, desc } => {
            splat!(buf, "  ", key_style, key1, " ", key2, " ", key3, vt::CLEAR_STYLE);
            let key_len = key1.chars().count() + 1 + key2.chars().count() + 1 + key3.chars().count();
            buf.extend_from_slice(&SPACES[..KEY_WIDTH.saturating_sub(key_len)]);
            splat!(buf, desc_style, *desc);
        }
        WelcomeLine::Empty => {}
    }
}

/// Renders a centered welcome message when no jobs have been spawned.
pub fn render_welcome_message(buf: &mut Vec<u8>, rect: Rect, keybinds: &Keybinds, user_config_loaded: bool) {
    use WelcomeLine::*;
    use extui::splat;

    let key_str = |cmd: Command| -> Option<String> {
        keybinds.key_for_command(cmd).map(|k| {
            let s = k.to_string();
            if s == " " { "Space".to_string() } else { s }
        })
    };

    let header: Vec<WelcomeLine> =
        vec![Section("Welcome to devsm"), Empty, Text("No jobs have been spawned yet."), Empty];

    let mut quick_start: Vec<WelcomeLine> = vec![Section("Quick start:")];
    if let Some(key) = key_str(Command::LaunchTask) {
        quick_start.push(Binding { key, desc: "Spawn task" });
    }
    if let Some(key) = key_str(Command::StartGroup) {
        quick_start.push(Binding { key, desc: "Group Spawn" });
    }
    if let Some(key) = key_str(Command::StartSelection) {
        quick_start.push(Binding { key, desc: "Start selection" });
    }
    if let Some(key) = key_str(Command::RestartTask) {
        quick_start.push(Binding { key, desc: "Restart selection" });
    }
    if let Some(key) = key_str(Command::TerminateTask) {
        quick_start.push(Binding { key, desc: "Kill selection" });
    }

    let mut log_view: Vec<WelcomeLine> = vec![Section("Log view:")];
    if let Some(key) = key_str(Command::SearchLogs) {
        log_view.push(Binding { key, desc: "Search logs" });
    }
    if let (Some(key1), Some(key2), Some(key3)) =
        (key_str(Command::LogModeAll), key_str(Command::LogModeSelected), key_str(Command::LogModeHybrid))
    {
        log_view.push(Binding3 { key1, key2, key3, desc: "Switch log view mode" });
    }
    if let Some(key) = key_str(Command::LogScrollUp) {
        log_view.push(Binding { key, desc: "Scroll logs up" });
    }
    if let Some(key) = key_str(Command::LogScrollDown) {
        log_view.push(Binding { key, desc: "Scroll logs down" });
    }
    if let Some(key) = key_str(Command::JumpToOldestLogs) {
        log_view.push(Binding { key, desc: "Jump to oldest logs" });
    }
    if let Some(key) = key_str(Command::JumpToNewestLogs) {
        log_view.push(Binding { key, desc: "Jump to newest logs" });
    }

    let mut navigation: Vec<WelcomeLine> = vec![Section("Navigation:")];
    navigation.push(TextBinding("  h  j  k  l "));
    navigation.push(Text("      or       Navigate the task tree below"));
    navigation.push(TextBinding("  Arrow Keys "));
    navigation.push(Empty);
    navigation.push(Binding { key: "Mouse Wheel".into(), desc: "Scroll list or logs under cursor" });
    navigation.push(Empty);
    if let Some(key) = key_str(Command::ToggleHelp) {
        navigation.push(Binding { key, desc: "Toggle help menu" });
    }
    if let Some(key) = key_str(Command::Quit) {
        navigation.push(Binding { key, desc: "Quit" });
    }

    let mut customization: Vec<WelcomeLine> = vec![Section("Customization:")];
    customization.push(Text(" Keybindings are customizable."));
    if user_config_loaded {
        customization.push(Text(" Loaded config ~/.config/devsm.user.toml"));
        customization.push(Text(" Run `devsm get default-user-config` to see defaults."));
    } else {
        customization.push(Text(" Initialize user config with default settings:"));
        customization.push(Text(" devsm get default-user-config > ~/.config/devsm.user.toml"));
    }

    let use_batch_clear = rect.y == 0;
    if use_batch_clear {
        splat!(buf, vt::MoveCursor(rect.x + rect.w, rect.y + rect.h - 1), vt::CLEAR_ABOVE);
    }

    let left_width = quick_start.iter().chain(&log_view).map(line_width).max().unwrap_or(0);
    let right_width = navigation.iter().chain(&customization).map(line_width).max().unwrap_or(0);
    let two_col_width = left_width + COLUMN_GAP + right_width;

    let use_two_columns = rect.w as usize >= two_col_width + 4;

    if use_two_columns {
        let left_col: Vec<WelcomeLine> =
            quick_start.into_iter().chain(std::iter::once(Empty)).chain(log_view).collect();
        let right_col: Vec<WelcomeLine> =
            navigation.into_iter().chain(std::iter::once(Empty)).chain(customization).collect();

        let body_height = left_col.len().max(right_col.len());
        let content_height = header.len() + body_height;
        let start_y = rect.y + rect.h.saturating_sub(content_height as u16) / 2;

        let left_x = rect.x + (rect.w as usize).saturating_sub(two_col_width) as u16 / 2;

        for (i, line) in header.iter().enumerate() {
            let y = start_y + i as u16;
            if y >= rect.y + rect.h {
                break;
            }
            splat!(buf, vt::MoveCursor(left_x, y));
            render_line(buf, line);
            splat!(buf, vt::CLEAR_STYLE, vt::CLEAR_LINE_TO_RIGHT);
        }

        let body_start_y = start_y + header.len() as u16;
        let right_x = left_x + left_width as u16 + COLUMN_GAP as u16;

        for i in 0..body_height {
            let y = body_start_y + i as u16;
            if y >= rect.y + rect.h {
                break;
            }

            splat!(buf, vt::MoveCursor(left_x, y));
            if let Some(line) = left_col.get(i) {
                render_line(buf, line);
            }

            splat!(buf, vt::MoveCursor(right_x, y));
            if let Some(line) = right_col.get(i) {
                render_line(buf, line);
            }
            splat!(buf, vt::CLEAR_STYLE, vt::CLEAR_LINE_TO_RIGHT);
        }

        if !use_batch_clear {
            let content_height = content_height as u16;
            for y in 0..rect.h {
                let line_y = rect.y + y;
                if line_y >= start_y && line_y < start_y + content_height {
                    continue;
                }
                splat!(buf, vt::MoveCursor(rect.x, line_y), vt::CLEAR_LINE_TO_RIGHT);
            }
        }
    } else {
        let lines: Vec<WelcomeLine> = header
            .into_iter()
            .chain(quick_start)
            .chain(std::iter::once(Empty))
            .chain(navigation)
            .chain(std::iter::once(Empty))
            .chain(log_view)
            .chain(std::iter::once(Empty))
            .chain(customization)
            .collect();

        let content_height = lines.len() as u16;
        let start_y = rect.y + rect.h.saturating_sub(content_height) / 2;

        let max_width = lines.iter().map(line_width).max().unwrap_or(0) as u16;
        let x_offset = rect.w.saturating_sub(max_width) / 2;

        for (i, line) in lines.iter().enumerate() {
            let y = start_y + i as u16;
            if y >= rect.y + rect.h {
                break;
            }

            splat!(buf, vt::MoveCursor(rect.x + x_offset, y));
            render_line(buf, line);
            splat!(buf, vt::CLEAR_STYLE, vt::CLEAR_LINE_TO_RIGHT);
        }

        if !use_batch_clear {
            for y in 0..rect.h {
                let line_y = rect.y + y;
                if line_y >= start_y && line_y < start_y + content_height {
                    continue;
                }
                splat!(buf, vt::MoveCursor(rect.x, line_y), vt::CLEAR_LINE_TO_RIGHT);
            }
        }
    }
}
