use extui::{Color, Rect, vt::BufferWrite};

use crate::{
    config::TaskKind,
    keybinds::Keybinds,
    log_storage::{BaseTaskSet, LogFilter, LogId},
    process_manager::user_config_loaded,
    scroll_view::{LogHighlight, LogStyle, LogWidget, ScrollState},
    tui::task_tree::{MetaGroupKind, SelectionState},
    welcome_message::render_welcome_message,
    workspace::{BaseTaskIndex, Workspace, WorkspaceState},
};

#[derive(Debug, Clone, Copy, Default)]
pub struct LogStackScrollState {
    pub top: ScrollState,
    pub bottom: Option<ScrollState>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    All,
    OnlySelected(SelectionState),
    Hybrid(SelectionState),
}

/// Builds a `BaseTaskSet` containing all base tasks of the given kind.
fn build_task_set(ws: &WorkspaceState, kind: TaskKind) -> BaseTaskSet {
    let mut set = BaseTaskSet::new();
    for (i, bt) in ws.base_tasks.iter().enumerate() {
        if !bt.removed && bt.config.kind == kind {
            set.insert(BaseTaskIndex(i as u32));
        }
    }
    set
}

/// Builds a filter based on the selection state.
fn selection_filter(ss: &SelectionState, ws: &WorkspaceState) -> LogFilter {
    if let Some(job) = ss.job {
        LogFilter::IsGroup(ws[job].log_group)
    } else if let Some(bti) = ss.base_task {
        LogFilter::IsBaseTask(bti)
    } else if let Some(kind) = ss.meta_group {
        LogFilter::IsInSet(build_task_set(ws, kind.task_kind()))
    } else {
        LogFilter::All
    }
}

/// Builds the inverse filter for the selection state (used in hybrid mode).
fn selection_not_filter(ss: &SelectionState, ws: &WorkspaceState) -> LogFilter {
    if let Some(job) = ss.job {
        LogFilter::NotGroup(ws[job].log_group)
    } else if let Some(bti) = ss.base_task {
        LogFilter::NotBaseTask(bti)
    } else {
        // For meta-groups without a job, we don't have a "not in set" filter,
        // so just return All (show everything in top pane)
        LogFilter::All
    }
}

impl Mode {
    pub fn top_filter(&self, ws: &WorkspaceState) -> LogFilter {
        match self {
            Mode::All => LogFilter::All,
            Mode::OnlySelected(ss) => selection_filter(ss, ws),
            Mode::Hybrid(ss) => selection_not_filter(ss, ws),
        }
    }
    pub fn bottom_filter(&self, ws: &WorkspaceState) -> Option<LogFilter> {
        match self {
            Mode::All => None,
            Mode::OnlySelected(..) => None,
            Mode::Hybrid(ss) => Some(selection_filter(ss, ws)),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SeparatorState {
    selection: SelectionState,
    y: u16,
}

#[derive(Default)]
pub struct LogStack {
    mode: Mode,
    top: LogWidget,
    bottom: LogWidget,
    pub pending_top_scroll: i32,
    pub pending_bottom_scroll: i32,
    base_task_log_style: LogStyle,
    /// Highlight info for search result highlighting in the log view.
    pub highlight: Option<LogHighlight>,
    /// Cached separator bar state to avoid redundant redraws.
    last_separator: Option<SeparatorState>,
    /// Tracks whether the welcome message was rendered (to avoid redundant redraws).
    welcome_shown: bool,
}
impl LogStack {
    /// Returns the current display mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Returns the scroll state for both top and bottom panes.
    pub fn scroll_state(&self, ws_state: &WorkspaceState, ws: &Workspace) -> LogStackScrollState {
        let logs = ws.logs.read().unwrap();

        let (top_filter, bot_filter) = (self.mode.top_filter(ws_state), self.mode.bottom_filter(ws_state));

        let top_view = logs.view(top_filter);
        let top_style = match &self.mode {
            Mode::All | Mode::Hybrid(..) => &self.base_task_log_style,
            Mode::OnlySelected(..) => &LogStyle::default(),
        };
        let top = self.top.scroll_state(&top_view, top_style);

        let bottom = bot_filter.map(|filter| {
            let view = logs.view(filter);
            self.bottom.scroll_state(&view, &LogStyle::default())
        });

        LogStackScrollState { top, bottom }
    }

    /// Forces the appropriate log view into scroll mode at the current position.
    /// In Hybrid mode, this affects the bottom (narrowed) view since that's where search results are.
    pub fn enter_scroll_mode(&mut self, ws: &Workspace) {
        let ws_state = ws.state();
        let logs = ws.logs.read().unwrap();

        match &self.mode {
            Mode::All => {
                let view = logs.view(LogFilter::All);
                self.top.scrollify(&view, &self.base_task_log_style);
            }
            Mode::OnlySelected(ss) => {
                let filter = selection_filter(ss, &ws_state);
                let view = logs.view(filter);
                self.top.scrollify(&view, &LogStyle::default());
            }
            Mode::Hybrid(ss) => {
                // In Hybrid mode, search results are in the bottom (selected task) view
                let filter = selection_filter(ss, &ws_state);
                let view = logs.view(filter);
                self.bottom.scrollify(&view, &LogStyle::default());
            }
        }
    }

    /// Scrolls the appropriate log view to show a specific LogId.
    /// In Hybrid mode, this affects the bottom (narrowed) view since that's where search results are.
    pub fn scroll_to_log_id(&mut self, target: LogId, ws: &Workspace) {
        let ws_state = ws.state();
        let logs = ws.logs.read().unwrap();

        match &self.mode {
            Mode::All => {
                let view = logs.view(LogFilter::All);
                self.top.scroll_to_log_id(target, &view, &self.base_task_log_style);
            }
            Mode::OnlySelected(ss) => {
                let filter = selection_filter(ss, &ws_state);
                let view = logs.view(filter);
                self.top.scroll_to_log_id(target, &view, &LogStyle::default());
            }
            Mode::Hybrid(ss) => {
                // In Hybrid mode, search results are in the bottom (selected task) view
                let filter = selection_filter(ss, &ws_state);
                let view = logs.view(filter);
                self.bottom.scroll_to_log_id(target, &view, &LogStyle::default());
            }
        }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            self.mode = mode;
            self.top.reset();
            self.bottom.reset();
            self.last_separator = None;
        }
    }

    /// Jumps to the oldest logs in both panels.
    pub fn jump_to_oldest(&mut self, ws: &Workspace) {
        let ws_state = ws.state();
        let logs = ws.logs.read().unwrap();
        let top_view = logs.view(self.mode.top_filter(&ws_state));
        self.top.jump_to_oldest(&top_view, &self.base_task_log_style);
        if let Some(bot_filter) = self.mode.bottom_filter(&ws_state) {
            let bot_view = logs.view(bot_filter);
            self.bottom.jump_to_oldest(&bot_view, &LogStyle::default());
        }
    }

    /// Jumps to the newest logs in both panels (resets to tailing mode).
    pub fn jump_to_newest(&mut self) {
        self.top.reset();
        self.bottom.reset();
    }
    pub fn update_selection(&mut self, selection: SelectionState) {
        match &self.mode {
            Mode::All => {}
            Mode::OnlySelected(current) => {
                if *current != selection {
                    self.mode = Mode::OnlySelected(selection);
                    self.top.reset();
                }
            }
            Mode::Hybrid(current) => {
                if *current != selection {
                    self.mode = Mode::Hybrid(selection);
                    self.top.reset();
                    self.bottom.reset();
                }
            }
        }
    }
    pub fn render(&mut self, buf: &mut Vec<u8>, mut dest: Rect, ws: &Workspace, keybinds: &Keybinds, resized: bool) {
        let (top_filter, bot_filter) = {
            let ws = ws.state();

            let no_jobs_spawned = ws.jobs.is_empty();

            if no_jobs_spawned {
                if !self.welcome_shown || resized {
                    render_welcome_message(buf, dest, keybinds, user_config_loaded());
                    self.welcome_shown = true;
                }
                return;
            }

            self.welcome_shown = false;

            if self.base_task_log_style.prefixes.len() != ws.base_tasks.len() {
                self.base_task_log_style.prefixes.clear();
                for (i, base_task) in ws.base_tasks.iter().enumerate() {
                    const SPAN_COLORS: &[&str] = &[
                        "\x1b[48;5;235;38;5;195m",
                        "\x1b[48;5;16;38;5;189m",
                        "\x1b[48;5;235;38;5;183m",
                        "\x1b[48;5;16;38;5;149m",
                        "\x1b[48;5;235;38;5;157m",
                        "\x1b[48;5;16;38;5;110m",
                        "\x1b[48;5;235;38;5;229m",
                        "\x1b[48;5;16;38;5;182m",
                        "\x1b[48;5;235;38;5;151m",
                    ];
                    let text = format!("{} {} \x1b[m ", SPAN_COLORS[i % SPAN_COLORS.len()], base_task.name);
                    self.base_task_log_style
                        .prefixes
                        .push(crate::scroll_view::Prefix { width: text.len(), bytes: text.into() });
                }
            }
            (self.mode.top_filter(&ws), self.mode.bottom_filter(&ws))
        };

        self.base_task_log_style.highlight = self.highlight;
        let mut def = LogStyle::default();
        def.highlight = self.highlight;

        let logs = ws.logs.read().unwrap();
        if let Some(bot_filter) = bot_filter {
            let view = logs.view(bot_filter);
            let bot_rect = dest.take_bottom(0.5);
            if resized {
                self.bottom.check_resize_revert_to_tail(&view, &def, bot_rect);
            }
            self.bottom.scrollable_render(self.pending_bottom_scroll, buf, bot_rect, &view, &def);
            self.pending_bottom_scroll = 0;

            let br = dest.take_bottom(1);
            let Mode::Hybrid(selection_state) = &self.mode else { unreachable!() };
            let current_sep = SeparatorState { selection: *selection_state, y: br.y };

            if self.last_separator.as_ref() != Some(&current_sep) {
                extui::vt::MoveCursor(br.x, br.y).write_to_buffer(buf);
                Color::Grey[6].with_fg(Color::Grey[25]).write_to_buffer(buf);
                if selection_state.job.is_none() {
                    if let Some(bti) = selection_state.base_task {
                        let ws_state = ws.state();
                        let name = ws_state.base_tasks[bti.idx()].name;
                        buf.extend_from_slice(b" NOT ");
                        buf.extend_from_slice(name.as_bytes());
                    } else if let Some(kind) = selection_state.meta_group {
                        buf.extend_from_slice(b" NOT ");
                        let label = match kind {
                            MetaGroupKind::Tests => "@tests",
                            MetaGroupKind::Actions => "@actions",
                        };
                        buf.extend_from_slice(label.as_bytes());
                    }
                }
                extui::vt::CLEAR_LINE_TO_RIGHT.write_to_buffer(buf);
                extui::vt::CLEAR_STYLE.write_to_buffer(buf);
                self.last_separator = Some(current_sep);
            }
        } else {
            self.pending_top_scroll += self.pending_bottom_scroll;
            self.pending_bottom_scroll = 0;
        }

        let view = logs.view(top_filter);
        let top_style = match &self.mode {
            Mode::All => &self.base_task_log_style,
            Mode::OnlySelected(..) => &def,
            Mode::Hybrid(..) => &self.base_task_log_style,
        };
        if resized {
            self.top.check_resize_revert_to_tail(&view, top_style, dest);
        }
        self.top.scrollable_render(self.pending_top_scroll, buf, dest, &view, top_style);
        self.pending_top_scroll = 0;
    }
}

// if let Some(scroll_request) = scroll_request.take() {
//     if scroll_request < 0 {
//         log_widget.scroll_down(
//             -scroll_request as u32,
//             &mut buf,
//             dest,
//             logs.view(filter),
//             &style,
//         );
//     } else if scroll_request > 0 {
//         log_widget.scroll_up(
//             scroll_request as u32,
//             &mut buf,
//             dest,
//             logs.view(filter),
//             &style,
//         );
//     }
// }
