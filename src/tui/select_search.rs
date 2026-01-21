use extui::{
    Color, DoubleBuffer, Rect, Style,
    event::{KeyCode, KeyEvent},
};
use unicode_width::UnicodeWidthStr;

use crate::{
    keybinds::{Command, InputEvent, Keybinds, Mode},
    searcher::{Entry, FatSearch},
    tui::constrain_scroll_offset,
    workspace::BaseTaskIndex,
};

pub struct SelectSearch {
    pattern: String,
    cursor: usize,
    pattern_updated: bool,
    searcher: FatSearch,
    scroll_offset: usize,
    selected: usize,
    results: Vec<Entry>,
    ids: Vec<u64>,
}

pub trait PackU64 {
    fn pack_u64(self) -> u64;
    fn unpack_u64(value: u64) -> Self;
}
impl PackU64 for usize {
    fn pack_u64(self) -> u64 {
        self as u64
    }
    fn unpack_u64(value: u64) -> Self {
        value as usize
    }
}
impl PackU64 for BaseTaskIndex {
    fn pack_u64(self) -> u64 {
        self.0 as u64
    }
    fn unpack_u64(value: u64) -> Self {
        BaseTaskIndex(value as _)
    }
}

pub enum Action {
    Cancel,
    Enter,
    None,
}

impl SelectSearch {
    fn raw_selected(&self) -> Option<u64> {
        self.ids.get(self.results.get(self.selected)?.index()).copied()
    }
    pub fn selected<Id: PackU64>(&self) -> Option<Id> {
        Some(Id::unpack_u64(self.raw_selected()?))
    }
    pub fn process_input(&mut self, key: KeyEvent, keybinds: &Keybinds) -> Action {
        let input = InputEvent::from(key);

        if let Some(cmd) = keybinds.lookup_chain(&[Mode::SelectSearch, Mode::Input, Mode::Global], input) {
            match cmd {
                Command::SelectPrev => {
                    self.flush();
                    self.selected = self.selected.saturating_sub(1);
                    return Action::None;
                }
                Command::SelectNext => {
                    self.flush();
                    if self.selected + 1 < self.results.len() {
                        self.selected += 1;
                    }
                    return Action::None;
                }
                Command::OverlayCancel => {
                    return Action::Cancel;
                }
                Command::OverlayConfirm => {
                    self.flush();
                    if self.results.is_empty() {
                        return Action::Cancel;
                    } else {
                        return Action::Enter;
                    }
                }
                _ => {
                    kvlog::warn!("Unsupported command triggered by binding", %input, mode = "SelectSearch", ?cmd);
                    return Action::None;
                }
            }
        }

        match key.code {
            KeyCode::Backspace => {
                if self.cursor != 0 {
                    self.pattern.remove(self.cursor - 1);
                    self.cursor -= 1;
                }
                self.pattern_updated = true;
            }
            KeyCode::Char(ch) => {
                let len = self.pattern.len();
                self.pattern.insert(self.cursor, ch);
                let len2 = self.pattern.len();
                self.cursor += len2 - len;
                self.pattern_updated = true;
            }
            _ => {}
        }
        Action::None
    }
    pub fn flush(&mut self) {
        if self.pattern_updated {
            self.searcher.query(&self.pattern, &mut self.results);
            self.scroll_offset = 0;
            self.selected = 0;
            self.pattern_updated = false;
        }
    }
    pub fn render<Id: PackU64>(
        &mut self,
        out: &mut DoubleBuffer,
        rect: Rect,
        label: &str,
        render: impl Fn(&mut extui::DoubleBuffer, Rect, Id, bool),
    ) {
        self.render_internal(out, rect, label, &move |out, r, id, sel| render(out, r, Id::unpack_u64(id), sel));
    }
    fn render_internal(
        &mut self,
        out: &mut DoubleBuffer,
        mut rect: Rect,
        label: &str,
        func: &dyn Fn(&mut extui::DoubleBuffer, Rect, u64, bool),
    ) {
        // todo need to scroll text but is probably better to put this in a separate input boxk
        let input_rect = rect.take_top(1);

        input_rect.with(Color::Grey[16].as_fg()).text(out, label).with(Style::DEFAULT).text(out, &self.pattern);
        let cursor_rect = Rect {
            x: input_rect.x + label.width() as u16 + self.pattern[..self.cursor].width() as u16,
            w: 1,
            ..input_rect
        };
        cursor_rect.with(Color::Grey[28].with_fg(Color::Grey[2])).fill(out);

        if self.results.is_empty() {
            return;
        }
        self.selected = (self.results.len() - 1).min(self.selected);
        self.scroll_offset =
            constrain_scroll_offset(rect.h as usize, self.selected, self.scroll_offset, self.results.len());
        let selected = &self.results[self.selected];
        for entry in &self.results[self.scroll_offset..] {
            let entry_rect = rect.take_top(1);
            if entry_rect.is_empty() {
                break;
            }
            func(out, entry_rect, self.ids[entry.index()], std::ptr::eq(entry, selected));
        }
    }
    pub fn new<Id: PackU64>(entries: impl Iterator<Item = (Id, impl AsRef<str>)>) -> SelectSearch {
        let mut searcher = FatSearch::default();
        let mut ids = Vec::new();
        let mut results: Vec<Entry> = Vec::new();
        for (id, text) in entries {
            searcher.insert(text.as_ref());
            ids.push(id.pack_u64())
        }
        // perf: todo avoid filling empty buffer
        searcher.query("", &mut results);
        SelectSearch {
            cursor: 0,
            pattern: String::new(),
            searcher,
            results,
            ids,
            pattern_updated: false,
            scroll_offset: 0,
            selected: 0,
        }
    }
}

impl<Id: PackU64, Value: AsRef<str>> FromIterator<(Id, Value)> for SelectSearch {
    fn from_iter<T: IntoIterator<Item = (Id, Value)>>(iter: T) -> Self {
        Self::new(iter.into_iter())
    }
}
