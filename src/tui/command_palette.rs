//! Command palette overlay that sits on top of the log view.
//!
//! Fuzzy-searchable list of user-invocable commands. Opens via
//! `Command::OpenCommandPalette`, runs the selected command on confirm, closes
//! on cancel. Rendered into a dedicated secondary DoubleBuffer sized exactly
//! to the palette box so keystroke updates diff just the box area. The log
//! view treats the box as a `skip_rect` cutout: it clears the cells outside
//! the box on each full reset but never writes to the cells inside, so the
//! overlay owns them.

use extui::{
    AnsiColor, DoubleBuffer, Rect, Style,
    event::{KeyCode, KeyEvent},
};
use unicode_width::UnicodeWidthStr;

use crate::{
    keybinds::{Command, InputEvent, Keybinds, Mode},
    searcher::{Entry, FatSearch},
    tui::constrain_scroll_offset,
};

/// One selectable command in the palette.
struct CommandEntry {
    command: Command,
    display: &'static str,
    binding: Option<InputEvent>,
}

pub enum PaletteAction {
    None,
    Cancel,
    Execute(Command),
}

pub struct CommandPaletteState {
    input: String,
    cursor: usize,
    searcher: FatSearch,
    commands: Vec<CommandEntry>,
    results: Vec<Entry>,
    selected: usize,
    scroll_offset: usize,
}

impl CommandPaletteState {
    pub fn new(keybinds: &Keybinds) -> Self {
        let commands = available_commands(keybinds);

        let mut searcher = FatSearch::default();
        for cmd in &commands {
            searcher.insert(cmd.display);
        }

        let mut results = Vec::new();
        searcher.query("", &mut results);

        Self {
            input: String::new(),
            cursor: 0,
            searcher,
            commands,
            results,
            selected: 0,
            scroll_offset: 0,
        }
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn selected_display(&self) -> Option<&str> {
        let entry = self.results.get(self.selected)?;
        self.commands.get(entry.index()).map(|c| c.display)
    }

    fn update_search(&mut self) {
        self.searcher.query(&self.input, &mut self.results);
        self.selected = 0;
        self.scroll_offset = 0;
    }

    pub fn process_input(&mut self, key: KeyEvent, keybinds: &Keybinds) -> PaletteAction {
        let input = InputEvent::from(key);

        if let Some(cmd) = keybinds.lookup_chain(&[Mode::CommandPalette, Mode::Input, Mode::Global], input) {
            match cmd {
                Command::SelectPrev => {
                    self.selected = self.selected.saturating_sub(1);
                    return PaletteAction::None;
                }
                Command::SelectNext => {
                    if self.selected + 1 < self.results.len() {
                        self.selected += 1;
                    }
                    return PaletteAction::None;
                }
                Command::OverlayCancel => return PaletteAction::Cancel,
                Command::OverlayConfirm => {
                    let Some(entry) = self.results.get(self.selected) else { return PaletteAction::Cancel };
                    let Some(cmd_entry) = self.commands.get(entry.index()) else { return PaletteAction::Cancel };
                    return PaletteAction::Execute(cmd_entry.command.clone());
                }
                _ => {
                    kvlog::warn!("Unsupported command triggered by binding", %input, mode = "CommandPalette", ?cmd);
                    return PaletteAction::None;
                }
            }
        }

        match key.code {
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.input.remove(self.cursor - 1);
                    self.cursor -= 1;
                    self.update_search();
                }
            }
            KeyCode::Char(ch) => {
                self.input.insert(self.cursor, ch);
                self.cursor += ch.len_utf8();
                self.update_search();
            }
            _ => {}
        }
        PaletteAction::None
    }

    /// Renders the palette into its dedicated DoubleBuffer. `rect` is the
    /// palette box itself (in buffer-local coordinates) — the overlay buffer
    /// is sized exactly to this rect, so cells outside it don't exist in the
    /// overlay and the log view owns them.
    pub fn render(&mut self, out: &mut DoubleBuffer, rect: Rect) {
        if rect.is_empty() {
            return;
        }

        let bg = AnsiColor::Grey[3].with_fg(AnsiColor::Grey[25]);
        rect.with(bg).fill(out);

        let border_style = AnsiColor::Grey[3].with_fg(AnsiColor::Grey[16]);
        draw_border(out, rect, border_style, " Command Palette ");

        let mut inner = rect;
        inner.x += 1;
        inner.y += 1;
        inner.w = inner.w.saturating_sub(2);
        inner.h = inner.h.saturating_sub(2);
        if inner.is_empty() {
            return;
        }

        let input_rect = {
            let mut r = inner;
            r.h = 1;
            r
        };
        let prompt = "> ";
        input_rect.with(AnsiColor::Cyan1.as_fg()).text(out, prompt).with(Style::DEFAULT).text(out, &self.input);

        let cursor_x = input_rect.x + prompt.width() as u16 + self.input[..self.cursor].width() as u16;
        if cursor_x < input_rect.x + input_rect.w {
            let cursor_rect = Rect { x: cursor_x, w: 1, ..input_rect };
            cursor_rect.with(AnsiColor::Grey[28].with_fg(AnsiColor::Grey[2])).fill(out);
        }

        if inner.h <= 1 {
            return;
        }
        let mut list_rect = inner;
        list_rect.y += 1;
        list_rect.h -= 1;

        if self.results.is_empty() {
            list_rect.with(AnsiColor::Grey[14].as_fg()).text(out, " no matches");
            return;
        }

        self.selected = self.selected.min(self.results.len().saturating_sub(1));
        self.scroll_offset =
            constrain_scroll_offset(list_rect.h as usize, self.selected, self.scroll_offset, self.results.len());

        for (i, entry) in self.results.iter().enumerate().skip(self.scroll_offset) {
            let row = list_rect.take_top(1);
            if row.is_empty() {
                break;
            }
            let Some(cmd_entry) = self.commands.get(entry.index()) else { continue };

            let is_selected = i == self.selected;
            let (row_style, sub_style) = if is_selected {
                (AnsiColor(153).with_fg(AnsiColor::Black), AnsiColor::Grey[5].with_bg(AnsiColor(153)))
            } else {
                (bg, AnsiColor::Grey[14].as_fg())
            };

            row.with(row_style).fill(out);
            let mut r = row.with(row_style).text(out, " ").text(out, cmd_entry.display);
            if let Some(binding) = cmd_entry.binding {
                let key_text = format!(" [{}]", binding);
                r = r.with(sub_style).text(out, &key_text);
            }
            let _ = r;
        }
    }
}

fn draw_border(out: &mut DoubleBuffer, rect: Rect, style: extui::Style, title: &str) {
    if rect.w < 2 || rect.h < 2 {
        return;
    }

    let top = Rect { x: rect.x, y: rect.y, w: rect.w, h: 1 };
    let bottom = Rect { x: rect.x, y: rect.y + rect.h - 1, w: rect.w, h: 1 };
    let left = Rect { x: rect.x, y: rect.y, w: 1, h: rect.h };
    let right = Rect { x: rect.x + rect.w - 1, y: rect.y, w: 1, h: rect.h };

    top.with(style).fill(out);
    bottom.with(style).fill(out);
    left.with(style).fill(out);
    right.with(style).fill(out);

    let title_width = title.width() as u16;
    if title_width + 2 < rect.w {
        let title_rect = Rect { x: rect.x + 2, y: rect.y, w: title_width, h: 1 };
        title_rect.with(style).text(out, title);
    }
}

fn available_commands(keybinds: &Keybinds) -> Vec<CommandEntry> {
    const COMMANDS: &[Command] = &[
        Command::Quit,
        Command::RestartTask,
        Command::TerminateTask,
        Command::LaunchTask,
        Command::LaunchTestFilter,
        Command::StartGroup,
        Command::StartSelection,
        Command::SearchLogs,
        Command::LogModeAll,
        Command::LogModeSelected,
        Command::LogModeHybrid,
        Command::JumpToOldestLogs,
        Command::JumpToNewestLogs,
        Command::ToggleHelp,
        Command::ToggleGroupExpand,
        Command::ToggleTaskTree,
        Command::ToggleShortcutBar,
        Command::RefreshConfig,
        Command::RerunTestGroup,
        Command::NarrowTestGroup,
        Command::NextFailInTestGroup,
        Command::PrevFailInTestGroup,
    ];

    COMMANDS
        .iter()
        .map(|cmd| CommandEntry {
            display: cmd.display_name(),
            binding: keybinds.key_for_command(cmd),
            command: cmd.clone(),
        })
        .collect()
}
