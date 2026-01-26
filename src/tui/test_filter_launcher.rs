//! Test filter launcher overlay for running tests with filters.
//!
//! Provides an interactive input interface that parses test filter specifications
//! in the format `name +tag -tag` with context-aware autocomplete.

use extui::{
    Color, DoubleBuffer, Rect, Style,
    event::{KeyCode, KeyEvent},
};
use unicode_width::UnicodeWidthStr;

use crate::{
    cli::TestFilter,
    config::TaskKind,
    keybinds::{Command, InputEvent, Keybinds, Mode},
    searcher::{Entry, FatSearch},
    tui::constrain_scroll_offset,
    workspace::WorkspaceState,
};

struct TestInfo {
    name: &'static str,
    tags: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterMode {
    Name,
    IncludeTag,
    ExcludeTag,
}

impl FilterMode {
    fn is_tag(self) -> bool {
        matches!(self, FilterMode::IncludeTag | FilterMode::ExcludeTag)
    }

    fn prefix(self) -> &'static str {
        match self {
            FilterMode::Name => "",
            FilterMode::IncludeTag => "+",
            FilterMode::ExcludeTag => "-",
        }
    }

    fn color(self) -> Color {
        match self {
            FilterMode::Name => Color::Grey[23],
            FilterMode::IncludeTag => Color::Green1,
            FilterMode::ExcludeTag => Color::Red1,
        }
    }
}

pub enum TestFilterAction {
    Cancel,
    Start { filters: Vec<TestFilter<'static>> },
    None,
}

pub struct TestFilterLauncherState {
    input: String,
    cursor: usize,
    mode: FilterMode,

    searcher: FatSearch,
    results: Vec<Entry>,
    selected: Option<usize>,
    scroll_offset: usize,

    filters: Vec<TestFilter<'static>>,
    tests: Vec<TestInfo>,
    all_tags: Vec<&'static str>,
}

impl TestFilterLauncherState {
    pub fn new(ws: &WorkspaceState) -> Self {
        let mut test_map: std::collections::HashMap<&'static str, Vec<&'static str>> = std::collections::HashMap::new();
        for bt in &ws.base_tasks {
            if bt.removed || bt.config.kind != TaskKind::Test {
                continue;
            }
            // TODO: The test launcher needs to be entirely rethough
            let tags = test_map.entry(bt.name).or_default();
            for &tag in bt.config.tags {
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
        }
        let tests: Vec<_> = test_map.into_iter().map(|(name, tags)| TestInfo { name, tags }).collect();

        let mut all_tags: Vec<&'static str> = tests.iter().flat_map(|t| t.tags.iter().copied()).collect();
        all_tags.sort_unstable();
        all_tags.dedup();

        let mut searcher = FatSearch::default();
        for test in &tests {
            searcher.insert(test.name);
        }

        let mut results = Vec::new();
        searcher.query("", &mut results);

        Self {
            input: String::new(),
            cursor: 0,
            mode: FilterMode::Name,
            searcher,
            results,
            selected: None,
            scroll_offset: 0,
            filters: Vec::new(),
            tests,
            all_tags,
        }
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn matching_test_count(&self, ws: &WorkspaceState) -> usize {
        ws.base_tasks
            .iter()
            .filter(|bt| {
                if bt.removed || bt.config.kind != TaskKind::Test {
                    return false;
                }
                self.matches_filters(bt.name, bt.config.tags)
            })
            .count()
    }

    pub fn total_test_count(&self, ws: &WorkspaceState) -> usize {
        ws.base_tasks.iter().filter(|bt| !bt.removed && bt.config.kind == TaskKind::Test).count()
    }

    fn matches_filters(&self, name: &str, tags: &[&str]) -> bool {
        let has_name_filter = self.filters.iter().any(|f| matches!(f, TestFilter::IncludeName(_)));
        if has_name_filter {
            let name_matches = self.filters.iter().any(|f| matches!(f, TestFilter::IncludeName(n) if *n == name));
            if !name_matches {
                return false;
            }
        }

        let has_include_tag = self.filters.iter().any(|f| matches!(f, TestFilter::IncludeTag(_)));
        if has_include_tag {
            let tag_matches = self.filters.iter().any(|f| matches!(f, TestFilter::IncludeTag(t) if tags.contains(t)));
            if !tag_matches {
                return false;
            }
        }

        let has_excluded = self.filters.iter().any(|f| matches!(f, TestFilter::ExcludeTag(t) if tags.contains(t)));
        if has_excluded {
            return false;
        }

        true
    }

    fn rebuild_searcher(&mut self) {
        self.searcher = FatSearch::default();
        match self.mode {
            FilterMode::Name => {
                for test in &self.tests {
                    self.searcher.insert(test.name);
                }
            }
            FilterMode::IncludeTag | FilterMode::ExcludeTag => {
                for tag in &self.all_tags {
                    self.searcher.insert(tag);
                }
            }
        }
        self.searcher.query(&self.input, &mut self.results);
        self.selected = None;
        self.scroll_offset = 0;
    }

    fn update_search(&mut self) {
        self.searcher.query(&self.input, &mut self.results);
        self.selected = if self.results.is_empty() { None } else { Some(0) };
        self.scroll_offset = 0;
    }

    fn accept_autocomplete(&mut self) {
        let Some(selected) = self.selected else { return };
        let Some(entry) = self.results.get(selected) else { return };

        let filter = match self.mode {
            FilterMode::Name => self.tests.get(entry.index()).map(|t| TestFilter::IncludeName(t.name)),
            FilterMode::IncludeTag => self.all_tags.get(entry.index()).map(|&t| TestFilter::IncludeTag(t)),
            FilterMode::ExcludeTag => self.all_tags.get(entry.index()).map(|&t| TestFilter::ExcludeTag(t)),
        };
        if let Some(filter) = filter {
            self.filters.push(filter);
        }

        self.input.clear();
        self.cursor = 0;
        self.mode = FilterMode::Name;
        self.rebuild_searcher();
    }

    fn handle_backspace(&mut self) {
        if self.cursor > 0 {
            self.input.remove(self.cursor - 1);
            self.cursor -= 1;
            self.update_search();
            return;
        }

        if self.mode.is_tag() {
            self.mode = FilterMode::Name;
            self.rebuild_searcher();
            return;
        }

        let Some(filter) = self.filters.pop() else { return };
        let (text, mode) = match filter {
            TestFilter::IncludeName(n) => (n, FilterMode::Name),
            TestFilter::IncludeTag(t) => (t, FilterMode::IncludeTag),
            TestFilter::ExcludeTag(t) => (t, FilterMode::ExcludeTag),
        };
        self.input = text.to_string();
        self.cursor = self.input.len();
        self.mode = mode;
        self.rebuild_searcher();
    }

    pub fn process_input(&mut self, key: KeyEvent, keybinds: &Keybinds) -> TestFilterAction {
        let input = InputEvent::from(key);

        if let Some(cmd) = keybinds.lookup_chain(&[Mode::TestFilterLauncher, Mode::Input, Mode::Global], input) {
            match cmd {
                Command::SelectPrev => {
                    if let Some(sel) = self.selected {
                        self.selected = Some(sel.saturating_sub(1));
                    } else if !self.results.is_empty() {
                        self.selected = Some(0);
                    }
                    return TestFilterAction::None;
                }
                Command::SelectNext => {
                    if let Some(sel) = self.selected {
                        if sel + 1 < self.results.len() {
                            self.selected = Some(sel + 1);
                        }
                    } else if !self.results.is_empty() {
                        self.selected = Some(0);
                    }
                    return TestFilterAction::None;
                }
                Command::OverlayCancel => {
                    return TestFilterAction::Cancel;
                }
                Command::OverlayConfirm => {
                    return self.handle_confirm();
                }
                _ => {
                    return TestFilterAction::None;
                }
            }
        }

        match key.code {
            KeyCode::Backspace => {
                self.handle_backspace();
            }
            KeyCode::Tab => {
                self.accept_autocomplete();
            }
            KeyCode::Char(' ') if !self.input.is_empty() => {
                self.accept_autocomplete();
            }
            KeyCode::Char('+') if self.input.is_empty() => {
                self.mode = FilterMode::IncludeTag;
                self.rebuild_searcher();
            }
            KeyCode::Char('-') if self.input.is_empty() => {
                self.mode = FilterMode::ExcludeTag;
                self.rebuild_searcher();
            }
            KeyCode::Char(ch) => {
                self.input.insert(self.cursor, ch);
                self.cursor += ch.len_utf8();
                self.update_search();
            }
            _ => {}
        }
        TestFilterAction::None
    }

    fn handle_confirm(&mut self) -> TestFilterAction {
        if self.selected.is_some() {
            self.accept_autocomplete();
        }

        TestFilterAction::Start { filters: std::mem::take(&mut self.filters) }
    }

    pub fn render(&mut self, out: &mut DoubleBuffer, mut rect: Rect) {
        let input_rect = rect.take_top(1);

        let prefix = self.build_display_prefix();
        let label = "test> ";
        let mode_indicator = self.mode.prefix();
        let mode_style = if self.mode == FilterMode::Name { Style::DEFAULT } else { self.mode.color().as_fg() };

        input_rect
            .with(Color::Grey[16].as_fg())
            .text(out, label)
            .with(Color::Cyan1.as_fg())
            .text(out, &prefix)
            .with(mode_style)
            .text(out, mode_indicator)
            .with(Style::DEFAULT)
            .text(out, &self.input);

        let cursor_x = input_rect.x
            + label.width() as u16
            + prefix.width() as u16
            + mode_indicator.width() as u16
            + self.input[..self.cursor].width() as u16;
        let cursor_rect = Rect { x: cursor_x, w: 1, ..input_rect };
        cursor_rect.with(Color::Grey[28].with_fg(Color::Grey[2])).fill(out);

        if self.results.is_empty() {
            return;
        }

        if let Some(sel) = self.selected {
            self.selected = Some(sel.min(self.results.len().saturating_sub(1)));
        }
        let scroll_target = self.selected.unwrap_or(0);
        self.scroll_offset =
            constrain_scroll_offset(rect.h as usize, scroll_target, self.scroll_offset, self.results.len());

        for (i, entry) in self.results.iter().enumerate().skip(self.scroll_offset) {
            let entry_rect = rect.take_top(1);
            if entry_rect.is_empty() {
                break;
            }

            let is_selected = self.selected == Some(i);
            let style = if is_selected { Color(153).with_fg(Color::Black) } else { Style::DEFAULT };
            if is_selected {
                entry_rect.with(style).fill(out);
            }

            match self.mode {
                FilterMode::Name => {
                    if let Some(test) = self.tests.get(entry.index()) {
                        let substyle =
                            if is_selected { Color::Grey[5].with_bg(Color(153)) } else { Color::Grey[14].as_fg() };
                        let r = entry_rect.with(style).text(out, test.name);
                        if !test.tags.is_empty() {
                            let tags_str = test.tags.join(", ");
                            r.with(substyle).text(out, " [").text(out, &tags_str).text(out, "]");
                        }
                    }
                }
                FilterMode::IncludeTag | FilterMode::ExcludeTag => {
                    if let Some(&tag) = self.all_tags.get(entry.index()) {
                        let color = self.mode.color();
                        let prefix_style = if is_selected { color.with_bg(Color(153)) } else { color.as_fg() };
                        entry_rect.with(prefix_style).text(out, self.mode.prefix()).with(style).text(out, tag);
                    }
                }
            }
        }
    }

    fn build_display_prefix(&self) -> String {
        use std::fmt::Write;
        let mut prefix = String::new();
        for filter in &self.filters {
            let (sigil, text) = match filter {
                TestFilter::IncludeName(name) => ("", *name),
                TestFilter::IncludeTag(tag) => ("+", *tag),
                TestFilter::ExcludeTag(tag) => ("-", *tag),
            };
            let _ = write!(prefix, "{sigil}{text} ");
        }
        prefix
    }
}
