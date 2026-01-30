use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use extui::event::KeyEvent;
use extui::{Color, DoubleBuffer, Rect, Style};

use crate::keybinds::{Command, InputEvent, Keybinds, Mode};
use crate::line_width::{Segment, apply_raw_display_mode_vt_to_style};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    User,
    Workspace,
    Both,
}

pub enum ConfigErrorAction {
    Retry,
    None,
}

pub struct ConfigErrorState {
    error_lines: Vec<String>,
    scroll_offset: usize,
    source: ConfigSource,
    user_path: Option<PathBuf>,
    workspace_path: Option<PathBuf>,
    user_mtime: Option<SystemTime>,
    workspace_mtime: Option<SystemTime>,
    last_poll: Instant,
}

impl ConfigErrorState {
    pub fn new(
        error_message: String,
        source: ConfigSource,
        user_path: Option<PathBuf>,
        workspace_path: Option<PathBuf>,
    ) -> Self {
        let error_lines: Vec<String> = error_message.lines().map(|s| s.to_string()).collect();

        let user_mtime = user_path.as_ref().and_then(|p| p.metadata().ok()?.modified().ok());
        let workspace_mtime = workspace_path.as_ref().and_then(|p| p.metadata().ok()?.modified().ok());

        ConfigErrorState {
            error_lines,
            scroll_offset: 0,
            source,
            user_path,
            workspace_path,
            user_mtime,
            workspace_mtime,
            last_poll: crate::clock::now(),
        }
    }

    pub fn poll_interval() -> Duration {
        Duration::from_millis(50)
    }

    pub fn check_file_changed(&mut self) -> bool {
        let now = crate::clock::now();
        if now.duration_since(self.last_poll) < Self::poll_interval() {
            return false;
        }
        self.last_poll = now;

        let user_changed = self.user_path.as_ref().is_some_and(|p| {
            let current = p.metadata().ok().and_then(|m| m.modified().ok());
            current != self.user_mtime
        });

        let workspace_changed = self.workspace_path.as_ref().is_some_and(|p| {
            let current = p.metadata().ok().and_then(|m| m.modified().ok());
            current != self.workspace_mtime
        });

        user_changed || workspace_changed
    }

    pub fn process_input(&mut self, key: KeyEvent, keybinds: &Keybinds) -> ConfigErrorAction {
        let input = InputEvent::from(key);

        if keybinds.lookup(Mode::Global, input) == Some(Command::RefreshConfig) {
            return ConfigErrorAction::Retry;
        }

        match keybinds.lookup(Mode::Pager, input) {
            Some(Command::SelectNext) => {
                self.scroll_offset = self.scroll_offset.saturating_add(1);
            }
            Some(Command::SelectPrev) => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            Some(Command::HelpScrollDown) => {
                self.scroll_offset = self.scroll_offset.saturating_add(10);
            }
            Some(Command::HelpScrollUp) => {
                self.scroll_offset = self.scroll_offset.saturating_sub(10);
            }
            Some(Command::JumpToOldestLogs) => {
                self.scroll_offset = 0;
            }
            Some(Command::JumpToNewestLogs) => {
                self.scroll_offset = self.error_lines.len().saturating_sub(1);
            }
            _ => {}
        }

        ConfigErrorAction::None
    }

    pub fn render(&mut self, out: &mut DoubleBuffer, mut rect: Rect) {
        let header_style = Color::Red1.with_fg(Color::White);
        let mut header_rect = rect.take_top(1);
        header_rect.with(header_style).fill(out);

        let watching_text = match self.source {
            ConfigSource::User => {
                if let Some(path) = &self.user_path {
                    format!(" {} ", path.display())
                } else {
                    " user config ".to_string()
                }
            }
            ConfigSource::Workspace => {
                if let Some(path) = &self.workspace_path {
                    format!(" {} ", path.display())
                } else {
                    " workspace config ".to_string()
                }
            }
            ConfigSource::Both => {
                let user = self.user_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                let ws = self.workspace_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
                format!(" {}, {} ", user, ws)
            }
        };

        let right_text = format!("Watching:{}", watching_text);
        let right_width = right_text.len() as i32;
        header_rect.take_left(header_rect.w as i32 - right_width).with(header_style).text(out, " Config Error");
        header_rect.with(header_style).text(out, &right_text);

        let content_height = rect.h as usize;

        if !self.error_lines.is_empty() && content_height > 0 {
            let max_scroll = self.error_lines.len().saturating_sub(content_height);
            self.scroll_offset = self.scroll_offset.min(max_scroll);
        }

        for line in self.error_lines.iter().skip(self.scroll_offset) {
            let line_rect = rect.take_top(1);
            if line_rect.is_empty() {
                break;
            }
            render_ansi_line(line_rect, out, line);
        }
    }
}

fn render_ansi_line(rect: Rect, out: &mut DoubleBuffer, text: &str) {
    use extui::DisplayRect;

    let mut current_style = Style::DEFAULT;
    let mut styled: DisplayRect = rect.with(current_style);

    for segment in Segment::iterator(text) {
        match segment {
            Segment::Ascii(s) | Segment::Utf8(s) => {
                styled = styled.text(out, s);
            }
            Segment::AnsiEscapes(escape) => {
                apply_raw_display_mode_vt_to_style(&mut current_style, escape);
                styled = styled.with(current_style);
            }
        }
    }
}
