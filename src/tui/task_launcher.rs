//! Task launcher overlay for starting tasks with profiles and variables.
//!
//! Provides an interactive input interface that parses task specifications
//! in the format `taskname:profile var1=value1 var2=value2` with context-aware
//! autocomplete at each stage.

use extui::{
    Color, DoubleBuffer, Rect, Style,
    event::{KeyCode, KeyEvent},
};
use jsony_value::ValueMap;
use unicode_width::UnicodeWidthStr;

use crate::{
    config::{TaskKind, VarMeta},
    keybinds::{Command, InputEvent, Keybinds, Mode},
    searcher::{Entry, FatSearch},
    tui::constrain_scroll_offset,
    workspace::{BaseTaskIndex, WorkspaceState},
};

/// Information about a task for display in autocomplete.
struct TaskInfo {
    bti: BaseTaskIndex,
    name: &'static str,
    kind: TaskKind,
    command_preview: &'static str,
}

/// Current parsing mode within the launcher input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherMode {
    TaskName,
    Profile,
    Variable,
    Value,
}

/// Result of processing launcher input.
pub enum LauncherAction {
    Cancel,
    Start { base_task: BaseTaskIndex, profile: String, params: ValueMap<'static> },
    None,
}

/// State for the task launcher overlay.
pub struct TaskLauncherState {
    input: String,
    cursor: usize,
    mode: LauncherMode,

    searcher: FatSearch,
    results: Vec<Entry>,
    selected: usize,
    scroll_offset: usize,

    confirmed_task: Option<(BaseTaskIndex, &'static str)>,
    confirmed_profile: Option<&'static str>,
    completed_vars: Vec<(&'static str, String)>,
    current_var_name: Option<&'static str>,

    tasks: Vec<TaskInfo>,
    available_profiles: &'static [&'static str],
    available_variables: Vec<&'static str>,
    available_var_meta: &'static [(&'static str, VarMeta<'static>)],
}

impl TaskLauncherState {
    /// Creates a new task launcher with the given workspace state.
    pub fn new(ws: &WorkspaceState) -> Self {
        let tasks: Vec<_> = ws
            .base_tasks
            .iter()
            .enumerate()
            .filter(|(_, bt)| !bt.removed && bt.config.managed != Some(false))
            .map(|(i, bt)| TaskInfo {
                bti: BaseTaskIndex(i as u32),
                name: bt.name,
                kind: bt.config.kind,
                command_preview: bt.config.command_preview(),
            })
            .collect();

        let mut searcher = FatSearch::default();
        for task in &tasks {
            searcher.insert(task.name);
        }

        let mut results = Vec::new();
        searcher.query("", &mut results);

        Self {
            input: String::new(),
            cursor: 0,
            mode: LauncherMode::TaskName,
            searcher,
            results,
            selected: 0,
            scroll_offset: 0,
            confirmed_task: None,
            confirmed_profile: None,
            completed_vars: Vec::new(),
            current_var_name: None,
            tasks,
            available_profiles: &[],
            available_variables: Vec::new(),
            available_var_meta: &[],
        }
    }

    /// Creates a task launcher prefilled with a specific task, starting in Profile mode.
    pub fn with_task(ws: &WorkspaceState, bti: BaseTaskIndex) -> Self {
        let tasks: Vec<_> = ws
            .base_tasks
            .iter()
            .enumerate()
            .filter(|(_, bt)| !bt.removed && bt.config.managed != Some(false))
            .map(|(i, bt)| TaskInfo {
                bti: BaseTaskIndex(i as u32),
                name: bt.name,
                kind: bt.config.kind,
                command_preview: bt.config.command_preview(),
            })
            .collect();

        let bt = &ws.base_tasks[bti.idx()];
        let profiles = bt.config.profiles;
        let variables = bt.config.collect_variables();

        let mut searcher = FatSearch::default();
        for profile in profiles {
            searcher.insert(profile);
        }

        let mut results = Vec::new();
        searcher.query("", &mut results);

        Self {
            input: String::new(),
            cursor: 0,
            mode: LauncherMode::Profile,
            searcher,
            results,
            selected: 0,
            scroll_offset: 0,
            confirmed_task: Some((bti, bt.name)),
            confirmed_profile: None,
            completed_vars: Vec::new(),
            current_var_name: None,
            tasks,
            available_profiles: profiles,
            available_variables: variables,
            available_var_meta: bt.config.vars,
        }
    }

    /// Attempts to auto-start if only one profile exists.
    /// Returns `Start` if no variables needed, otherwise advances to Variable mode.
    pub fn try_auto_start(&mut self, ws: &WorkspaceState) -> LauncherAction {
        if self.available_profiles.len() == 1 {
            return self.handle_confirm(ws);
        }
        LauncherAction::None
    }

    /// Returns the current input string.
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Returns the current mode.
    pub fn mode(&self) -> LauncherMode {
        self.mode
    }

    /// Returns the confirmed task if any.
    pub fn confirmed_task(&self) -> Option<(BaseTaskIndex, &'static str)> {
        self.confirmed_task
    }

    /// Returns the confirmed profile if any.
    pub fn confirmed_profile(&self) -> Option<&'static str> {
        self.confirmed_profile
    }

    /// Returns completed variables.
    pub fn completed_vars(&self) -> &[(&'static str, String)] {
        &self.completed_vars
    }

    fn rebuild_task_searcher(&mut self) {
        self.searcher = FatSearch::default();
        for task in &self.tasks {
            self.searcher.insert(task.name);
        }
        self.searcher.query(&self.input, &mut self.results);
        self.selected = 0;
        self.scroll_offset = 0;
    }

    fn rebuild_profile_searcher(&mut self) {
        self.searcher = FatSearch::default();
        for profile in self.available_profiles {
            self.searcher.insert(profile);
        }
        self.searcher.query(&self.input, &mut self.results);
        self.selected = 0;
        self.scroll_offset = 0;
    }

    fn rebuild_variable_searcher(&mut self) {
        self.searcher = FatSearch::default();
        for var in &self.available_variables {
            if !self.completed_vars.iter().any(|(n, _)| n == var) {
                self.searcher.insert(var);
            }
        }
        self.searcher.query(&self.input, &mut self.results);
        self.selected = 0;
        self.scroll_offset = 0;
    }

    fn accept_task_autocomplete(&mut self, ws: &WorkspaceState) {
        let Some(entry) = self.results.get(self.selected) else { return };
        let Some(task) = self.tasks.get(entry.index()) else { return };

        self.confirmed_task = Some((task.bti, task.name));
        self.input.clear();
        self.cursor = 0;

        let config = &ws.base_tasks[task.bti.idx()].config;
        self.available_profiles = config.profiles;
        self.available_variables = config.collect_variables();
        self.available_var_meta = config.vars;
    }

    fn switch_to_profile_mode(&mut self) {
        if self.available_profiles.len() == 1 {
            self.confirmed_profile = Some(self.available_profiles[0]);
            self.switch_to_variable_mode();
        } else {
            self.mode = LauncherMode::Profile;
            self.rebuild_profile_searcher();
        }
    }

    fn accept_profile_autocomplete(&mut self) {
        let profile = if let Some(entry) = self.results.get(self.selected) {
            self.available_profiles.get(entry.index()).copied()
        } else if self.available_profiles.len() == 1 {
            Some(self.available_profiles[0])
        } else if self.available_profiles.contains(&"default") {
            Some("default")
        } else {
            self.available_profiles.first().copied()
        };

        if let Some(profile) = profile {
            self.confirmed_profile = Some(profile);
        }
        self.input.clear();
        self.cursor = 0;
    }

    fn switch_to_variable_mode(&mut self) {
        self.mode = LauncherMode::Variable;
        self.rebuild_variable_searcher();
    }

    fn accept_variable_autocomplete(&mut self) {
        self.current_var_name = self.results.get(self.selected).and_then(|entry| {
            self.available_variables
                .iter()
                .filter(|v| !self.completed_vars.iter().any(|(n, _)| n == *v))
                .nth(entry.index())
                .copied()
        });
        self.input.clear();
        self.cursor = 0;
    }

    fn store_current_variable(&mut self) {
        let Some(var_name) = self.current_var_name.take() else { return };
        let value = std::mem::take(&mut self.input);
        self.completed_vars.push((var_name, value));
        self.cursor = 0;
    }

    fn try_build_launch(&self) -> Option<LauncherAction> {
        let (base_task, _) = self.confirmed_task?;
        let profile = self.confirmed_profile.unwrap_or("default").to_string();

        let mut params = ValueMap::new();
        for (name, value) in &self.completed_vars {
            params.insert((*name).to_string().into(), value.clone().into());
        }

        for (name, meta) in self.available_var_meta {
            if !params.entries().iter().any(|(k, _)| k.as_ref() as &str == *name) {
                if let Some(default) = meta.default {
                    params.insert((*name).to_string().into(), default.to_string().into());
                }
            }
        }

        Some(LauncherAction::Start { base_task, profile, params })
    }

    fn handle_backspace(&mut self) {
        if self.cursor == 0 {
            match self.mode {
                LauncherMode::Value => {
                    self.current_var_name = None;
                    self.mode = LauncherMode::Variable;
                    self.rebuild_variable_searcher();
                }
                LauncherMode::Variable => {
                    if !self.completed_vars.is_empty() {
                        let (name, value) = self.completed_vars.pop().unwrap();
                        self.current_var_name = Some(name);
                        self.input = value;
                        self.cursor = self.input.len();
                        self.mode = LauncherMode::Value;
                    } else {
                        self.confirmed_profile = None;
                        self.mode = LauncherMode::Profile;
                        self.rebuild_profile_searcher();
                    }
                }
                LauncherMode::Profile => {
                    self.confirmed_task = None;
                    self.available_profiles = &[];
                    self.available_variables.clear();
                    self.mode = LauncherMode::TaskName;
                    self.rebuild_task_searcher();
                }
                LauncherMode::TaskName => {}
            }
        } else {
            self.input.remove(self.cursor - 1);
            self.cursor -= 1;
            self.update_search();
        }
    }

    fn update_search(&mut self) {
        self.searcher.query(&self.input, &mut self.results);
        self.selected = 0;
        self.scroll_offset = 0;
    }

    /// Processes keyboard input and returns the resulting action.
    pub fn process_input(&mut self, key: KeyEvent, keybinds: &Keybinds, ws: &WorkspaceState) -> LauncherAction {
        let input = InputEvent::from(key);

        if let Some(cmd) = keybinds.lookup_chain(&[Mode::TaskLauncher, Mode::Input, Mode::Global], input) {
            match cmd {
                Command::SelectPrev => {
                    self.selected = self.selected.saturating_sub(1);
                    return LauncherAction::None;
                }
                Command::SelectNext => {
                    if self.selected + 1 < self.results.len() {
                        self.selected += 1;
                    }
                    return LauncherAction::None;
                }
                Command::OverlayCancel => {
                    return LauncherAction::Cancel;
                }
                Command::OverlayConfirm => {
                    return self.handle_confirm(ws);
                }
                _ => {
                    kvlog::warn!("Unsupported command triggered by binding", %input, mode = "TaskLauncher", ?cmd);
                    return LauncherAction::None;
                }
            }
        }

        match key.code {
            KeyCode::Backspace => {
                self.handle_backspace();
            }
            KeyCode::Tab if self.mode == LauncherMode::TaskName => {
                self.accept_task_autocomplete(ws);
                self.switch_to_profile_mode();
            }
            KeyCode::Tab if self.mode == LauncherMode::Profile => {
                self.accept_profile_autocomplete();
                self.switch_to_variable_mode();
            }
            KeyCode::Tab if self.mode == LauncherMode::Variable => {
                self.accept_variable_autocomplete();
                self.mode = LauncherMode::Value;
            }
            KeyCode::Char(':') if self.mode == LauncherMode::TaskName => {
                self.accept_task_autocomplete(ws);
                self.switch_to_profile_mode();
            }
            KeyCode::Char(' ') if self.mode == LauncherMode::Profile => {
                self.accept_profile_autocomplete();
                self.switch_to_variable_mode();
            }
            KeyCode::Char('=') if self.mode == LauncherMode::Variable => {
                self.accept_variable_autocomplete();
                self.mode = LauncherMode::Value;
            }
            KeyCode::Char(' ') if self.mode == LauncherMode::Value => {
                self.store_current_variable();
                self.switch_to_variable_mode();
            }
            KeyCode::Char(ch) => {
                self.input.insert(self.cursor, ch);
                self.cursor += ch.len_utf8();
                self.update_search();
            }
            _ => {}
        }
        LauncherAction::None
    }

    fn handle_confirm(&mut self, ws: &WorkspaceState) -> LauncherAction {
        match self.mode {
            LauncherMode::TaskName => {
                if self.results.is_empty() {
                    return LauncherAction::Cancel;
                }
                self.accept_task_autocomplete(ws);
                self.confirmed_profile = Some(if self.available_profiles.contains(&"default") {
                    "default"
                } else {
                    self.available_profiles.first().copied().unwrap_or("default")
                });
                return self.try_build_launch().unwrap_or(LauncherAction::Cancel);
            }
            LauncherMode::Profile => {
                self.accept_profile_autocomplete();
                if self.available_variables.is_empty() {
                    return self.try_build_launch().unwrap_or(LauncherAction::Cancel);
                }
                self.switch_to_variable_mode();
            }
            LauncherMode::Variable => {
                if self.input.is_empty() && self.current_var_name.is_none() {
                    return self.try_build_launch().unwrap_or(LauncherAction::Cancel);
                }
                self.accept_variable_autocomplete();
                self.mode = LauncherMode::Value;
            }
            LauncherMode::Value => {
                self.store_current_variable();
                return self.try_build_launch().unwrap_or(LauncherAction::Cancel);
            }
        }
        LauncherAction::None
    }

    /// Renders the launcher overlay.
    pub fn render(&mut self, out: &mut DoubleBuffer, mut rect: Rect) {
        let input_rect = rect.take_top(1);

        let prefix = self.build_display_prefix();
        let label = "launch> ";

        input_rect
            .with(Color::Grey[16].as_fg())
            .text(out, label)
            .with(Color::Cyan1.as_fg())
            .text(out, &prefix)
            .with(Style::DEFAULT)
            .text(out, &self.input);

        let cursor_x =
            input_rect.x + label.width() as u16 + prefix.width() as u16 + self.input[..self.cursor].width() as u16;
        let cursor_rect = Rect { x: cursor_x, w: 1, ..input_rect };
        cursor_rect.with(Color::Grey[28].with_fg(Color::Grey[2])).fill(out);

        if self.mode == LauncherMode::Value {
            return;
        }

        if self.results.is_empty() {
            return;
        }

        self.selected = self.selected.min(self.results.len().saturating_sub(1));
        self.scroll_offset =
            constrain_scroll_offset(rect.h as usize, self.selected, self.scroll_offset, self.results.len());

        let (name_col_width, kind_col_width) = if self.mode == LauncherMode::TaskName {
            let max_name =
                self.results.iter().filter_map(|e| self.task_at_entry(e)).map(|t| t.name.width()).max().unwrap_or(0);
            (max_name + 2, 9)
        } else {
            (0, 0)
        };

        for (i, entry) in self.results.iter().enumerate().skip(self.scroll_offset) {
            let mut entry_rect = rect.take_top(1);
            if entry_rect.is_empty() {
                break;
            }

            let is_selected = i == self.selected;
            let style = if is_selected { Color(153).with_fg(Color::Black) } else { Style::DEFAULT };
            if is_selected {
                entry_rect.with(style).fill(out);
            }

            match self.mode {
                LauncherMode::TaskName => {
                    let substyle =
                        if is_selected { Color::Grey[5].with_bg(Color(153)) } else { Color::Grey[14].as_fg() };

                    let Some(task) = self.task_at_entry(entry) else { continue };
                    let kind_str = match task.kind {
                        TaskKind::Service => "service",
                        TaskKind::Action => "action",
                        TaskKind::Test => "test",
                    };
                    entry_rect.take_left(name_col_width as i32).with(style).text(out, task.name);
                    entry_rect.take_left(kind_col_width as i32).with(substyle).text(out, kind_str);

                    if !task.command_preview.is_empty() {
                        let preview = if task.command_preview.len() > 40 {
                            let b = task.command_preview.floor_char_boundary(40);
                            &task.command_preview[..b]
                        } else {
                            task.command_preview
                        };
                        entry_rect.with(substyle).text(out, preview);
                    }
                }
                LauncherMode::Profile => {
                    let task_name = self.confirmed_task.map(|(_, n)| n).unwrap_or("");
                    let profile = self.available_profiles.get(entry.index()).copied().unwrap_or("");
                    entry_rect.with(style).text(out, task_name).text(out, ":").text(out, profile);
                }
                LauncherMode::Variable => {
                    let substyle =
                        if is_selected { Color::Grey[5].with_bg(Color(153)) } else { Color::Grey[14].as_fg() };
                    let Some(&var) = self
                        .available_variables
                        .iter()
                        .filter(|v| !self.completed_vars.iter().any(|(n, _)| n == *v))
                        .nth(entry.index())
                    else {
                        return;
                    };
                    let mut r = entry_rect.with(style).text(out, var);
                    if let Some((_, meta)) = self.available_var_meta.iter().find(|(n, _)| *n == var) {
                        if let Some(desc) = meta.description {
                            r = r.with(substyle).text(out, " - ").text(out, desc);
                        }
                        if let Some(default) = meta.default {
                            r.with(substyle).text(out, " (default: ").text(out, default).text(out, ")");
                        }
                    }
                }
                LauncherMode::Value => {}
            }
        }
    }

    fn build_display_prefix(&self) -> String {
        let mut prefix = String::new();

        if let Some((_, name)) = self.confirmed_task {
            prefix.push_str(name);
            prefix.push(':');
        }

        if let Some(profile) = self.confirmed_profile {
            prefix.push_str(profile);
            prefix.push(' ');
        }

        for (name, value) in &self.completed_vars {
            prefix.push_str(name);
            prefix.push('=');
            prefix.push_str(value);
            prefix.push(' ');
        }

        if let Some(var_name) = self.current_var_name {
            prefix.push_str(var_name);
            prefix.push('=');
        }

        prefix
    }

    fn task_at_entry(&self, entry: &Entry) -> Option<&TaskInfo> {
        self.tasks.get(entry.index())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_display_prefix_empty_initially() {
        let state = TaskLauncherState {
            input: String::new(),
            cursor: 0,
            mode: LauncherMode::TaskName,
            searcher: FatSearch::default(),
            results: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            confirmed_task: None,
            confirmed_profile: None,
            completed_vars: Vec::new(),
            current_var_name: None,
            tasks: Vec::new(),
            available_profiles: &[],
            available_variables: Vec::new(),
            available_var_meta: &[],
        };
        assert_eq!(state.build_display_prefix(), "");
    }

    #[test]
    fn build_display_prefix_with_task() {
        let state = TaskLauncherState {
            input: String::new(),
            cursor: 0,
            mode: LauncherMode::Profile,
            searcher: FatSearch::default(),
            results: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            confirmed_task: Some((BaseTaskIndex(0), "my_task")),
            confirmed_profile: None,
            completed_vars: Vec::new(),
            current_var_name: None,
            tasks: Vec::new(),
            available_profiles: &[],
            available_variables: Vec::new(),
            available_var_meta: &[],
        };
        assert_eq!(state.build_display_prefix(), "my_task:");
    }

    #[test]
    fn build_display_prefix_with_profile() {
        let state = TaskLauncherState {
            input: String::new(),
            cursor: 0,
            mode: LauncherMode::Variable,
            searcher: FatSearch::default(),
            results: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            confirmed_task: Some((BaseTaskIndex(0), "my_task")),
            confirmed_profile: Some("release"),
            completed_vars: Vec::new(),
            current_var_name: None,
            tasks: Vec::new(),
            available_profiles: &[],
            available_variables: Vec::new(),
            available_var_meta: &[],
        };
        assert_eq!(state.build_display_prefix(), "my_task:release ");
    }

    #[test]
    fn build_display_prefix_with_vars() {
        let state = TaskLauncherState {
            input: String::new(),
            cursor: 0,
            mode: LauncherMode::Variable,
            searcher: FatSearch::default(),
            results: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            confirmed_task: Some((BaseTaskIndex(0), "my_task")),
            confirmed_profile: Some("default"),
            completed_vars: vec![("foo", "bar".to_string())],
            current_var_name: None,
            tasks: Vec::new(),
            available_profiles: &[],
            available_variables: Vec::new(),
            available_var_meta: &[],
        };
        assert_eq!(state.build_display_prefix(), "my_task:default foo=bar ");
    }

    #[test]
    fn build_display_prefix_with_current_var() {
        let state = TaskLauncherState {
            input: "hello".to_string(),
            cursor: 5,
            mode: LauncherMode::Value,
            searcher: FatSearch::default(),
            results: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            confirmed_task: Some((BaseTaskIndex(0), "my_task")),
            confirmed_profile: Some("default"),
            completed_vars: Vec::new(),
            current_var_name: Some("message"),
            tasks: Vec::new(),
            available_profiles: &[],
            available_variables: Vec::new(),
            available_var_meta: &[],
        };
        assert_eq!(state.build_display_prefix(), "my_task:default message=");
    }

    #[test]
    fn mode_transitions_tracked() {
        let mut state = TaskLauncherState {
            input: String::new(),
            cursor: 0,
            mode: LauncherMode::TaskName,
            searcher: FatSearch::default(),
            results: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            confirmed_task: None,
            confirmed_profile: None,
            completed_vars: Vec::new(),
            current_var_name: None,
            tasks: Vec::new(),
            available_profiles: &["default", "release"],
            available_variables: vec!["foo", "bar"],
            available_var_meta: &[],
        };

        assert_eq!(state.mode(), LauncherMode::TaskName);

        state.confirmed_task = Some((BaseTaskIndex(0), "test"));
        state.switch_to_profile_mode();
        assert_eq!(state.mode(), LauncherMode::Profile);

        state.confirmed_profile = Some("default");
        state.switch_to_variable_mode();
        assert_eq!(state.mode(), LauncherMode::Variable);
    }
}
