use vtui::{Color, Rect, vt::BufferWrite};

use crate::{
    log_storage::{LogFilter, LogId},
    scroll_view::{LogHighlight, LogStyle, LogWidget},
    tui::task_tree::SelectionState,
    workspace::{Workspace, WorkspaceState},
};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    All,
    OnlySelected(SelectionState),
    Hybrid(SelectionState),
}

impl Mode {
    pub fn top_filter(&self, ws: &WorkspaceState) -> LogFilter {
        match self {
            Mode::All => LogFilter::All,
            Mode::OnlySelected(ss) => {
                if let Some(job) = ss.job {
                    LogFilter::IsJob(ws[job].job_id)
                } else {
                    LogFilter::IsBaseTask(ss.base_task)
                }
            }
            Mode::Hybrid(ss) => {
                if let Some(job) = ss.job {
                    LogFilter::NotJob(ws[job].job_id)
                } else {
                    LogFilter::NotBaseTask(ss.base_task)
                }
            }
        }
    }
    pub fn bottom_filter(&self, ws: &WorkspaceState) -> Option<LogFilter> {
        match self {
            Mode::All => None,
            Mode::OnlySelected(..) => None,
            Mode::Hybrid(ss) => {
                if let Some(job) = ss.job {
                    Some(LogFilter::IsJob(ws[job].job_id))
                } else {
                    Some(LogFilter::IsBaseTask(ss.base_task))
                }
            }
        }
    }
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
}
impl LogStack {
    /// Returns the current display mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Returns the current tail position of the top log view.
    pub fn current_tail(&self) -> LogId {
        match &self.top {
            LogWidget::Tail(tail) => tail.tail(),
            LogWidget::Scroll(scroll) => scroll.tail(),
        }
    }

    /// Forces the appropriate log view into scroll mode at the current position.
    /// In Hybrid mode, this affects the bottom (narrowed) view since that's where search results are.
    pub fn enter_scroll_mode(&mut self, ws: &Workspace) {
        let ws_state = ws.state();
        let logs = ws.logs.read().unwrap();

        match &self.mode {
            Mode::All => {
                let view = logs.view(LogFilter::All);
                self.top.scrollify(view, &self.base_task_log_style);
            }
            Mode::OnlySelected(ss) => {
                let filter = if let Some(job) = ss.job {
                    LogFilter::IsJob(ws_state[job].job_id)
                } else {
                    LogFilter::IsBaseTask(ss.base_task)
                };
                let view = logs.view(filter);
                self.top.scrollify(view, &LogStyle::default());
            }
            Mode::Hybrid(ss) => {
                // In Hybrid mode, search results are in the bottom (selected task) view
                let filter = if let Some(job) = ss.job {
                    LogFilter::IsJob(ws_state[job].job_id)
                } else {
                    LogFilter::IsBaseTask(ss.base_task)
                };
                let view = logs.view(filter);
                self.bottom.scrollify(view, &LogStyle::default());
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
                self.top.scroll_to_log_id(target, view, &self.base_task_log_style);
            }
            Mode::OnlySelected(ss) => {
                let filter = if let Some(job) = ss.job {
                    LogFilter::IsJob(ws_state[job].job_id)
                } else {
                    LogFilter::IsBaseTask(ss.base_task)
                };
                let view = logs.view(filter);
                self.top.scroll_to_log_id(target, view, &LogStyle::default());
            }
            Mode::Hybrid(ss) => {
                // In Hybrid mode, search results are in the bottom (selected task) view
                let filter = if let Some(job) = ss.job {
                    LogFilter::IsJob(ws_state[job].job_id)
                } else {
                    LogFilter::IsBaseTask(ss.base_task)
                };
                let view = logs.view(filter);
                self.bottom.scroll_to_log_id(target, view, &LogStyle::default());
            }
        }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            self.mode = mode;
            self.top.reset();
            self.bottom.reset();
        }
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
    pub fn render(&mut self, buf: &mut Vec<u8>, mut dest: Rect, ws: &Workspace) {
        // self.base_task_log_style.assume_blank = true;
        // todo move this logic else where to avoid taking the log
        let (top_filter, bot_filter) = {
            let ws = ws.state();
            if self.base_task_log_style.prefixes.len() != ws.base_tasks.len() {
                self.base_task_log_style.prefixes.clear();
                for base_task in &ws.base_tasks {
                    let text = format!("{}> ", base_task.name);
                    self.base_task_log_style
                        .prefixes
                        .push(crate::scroll_view::Prefix { width: text.len(), bytes: text.into() });
                }
            }
            (self.mode.top_filter(&ws), self.mode.bottom_filter(&ws))
        };

        // Apply highlighting to styles
        self.base_task_log_style.highlight = self.highlight;
        let mut def = LogStyle::default();
        def.highlight = self.highlight;

        let logs = ws.logs.read().unwrap();
        if let Some(bot_filter) = bot_filter {
            self.bottom.scrollable_render(
                self.pending_bottom_scroll,
                buf,
                dest.take_bottom(0.5),
                logs.view(bot_filter),
                &def,
            );
            self.pending_bottom_scroll = 0;
            // todo don't alaways render the value
            let br = dest.take_bottom(1);
            vtui::vt::move_cursor(buf, br.x, br.y);
            Color::Grey[6].with_fg(Color::Grey[25]).write_to_buffer(buf);
            match &self.mode {
                Mode::All => todo!(),
                Mode::OnlySelected(_selection_state) => todo!(),
                Mode::Hybrid(selection_state) => {
                    let ws = ws.state();
                    if let Some(_job) = selection_state.job {
                    } else {
                        let name = ws.base_tasks[selection_state.base_task.idx()].name;
                        buf.extend_from_slice(b" NOT ");
                        buf.extend_from_slice(name.as_bytes());
                    }
                }
            }
            vtui::vt::CLEAR_LINE_TO_RIGHT.write_to_buffer(buf);
            vtui::vt::clear_style(buf);
        } else {
            self.pending_top_scroll += self.pending_bottom_scroll;
            self.pending_bottom_scroll = 0;
        }

        self.top.scrollable_render(
            self.pending_top_scroll,
            buf,
            dest,
            logs.view(top_filter),
            match &self.mode {
                Mode::All => &self.base_task_log_style,
                Mode::OnlySelected(..) => &def,
                Mode::Hybrid(..) => &self.base_task_log_style,
            },
        );
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
