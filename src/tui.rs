use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use extui::event::{Event, KeyEvent};
use extui::vt::BufferWrite;
use extui::{Color, DoubleBuffer, HAlign, Rect, Style, TerminalFlags, vt};
use jsony_value::ValueMap;

use crate::config::{FunctionDefAction, TaskKind};
use crate::function::{FunctionAction, SetFunctionAction};
use crate::keybinds::{BindingEntry, Command, InputEvent, Keybinds, Mode};
use crate::log_storage::{BaseTaskSet, LogFilter};
use crate::process_manager::{Action, ClientChannel, SELECTED_META_GROUP_ACTIONS, SELECTED_META_GROUP_TESTS};
use crate::tui::log_search::{LogSearchState, SearchAction};
use crate::tui::log_stack::LogStack;
use crate::tui::select_search::SelectSearch;
use crate::tui::task_launcher::LauncherMode;
use crate::tui::task_launcher::{LauncherAction, TaskLauncherState};
use crate::tui::task_tree::{MetaGroupKind, SelectionState, TaskTreeState};
use crate::tui::test_filter_launcher::{TestFilterAction, TestFilterLauncherState};
use crate::workspace::{BaseTaskIndex, Workspace, WorkspaceState};

/// Constrains scroll offset to keep the selected item visible with padding.
///
/// Implements the "one before scrolling" policy: when scrolling is needed, ensures
/// at least one item is visible above and below the selected item (unless the
/// selected item is at the absolute start or end of the list).
///
/// # Examples
///
/// ```ignore
/// // Middle item in a long list - ensure padding on both sides
/// let offset = constrain_scroll_offset(5, 10, 0, 20);
/// assert!(offset <= 9);  // At least 1 item visible above
/// assert!(offset + 5 > 11);  // At least 1 item visible below
/// ```
pub fn constrain_scroll_offset(
    visible_height: usize,
    item_index: usize,
    scroll_offset: usize,
    list_length: usize,
) -> usize {
    if list_length == 0 || visible_height == 0 {
        return 0;
    }

    if list_length <= visible_height || visible_height <= 2 {
        if item_index < scroll_offset {
            return item_index;
        }
        if item_index >= scroll_offset + visible_height {
            return item_index + 1 - visible_height;
        }
        return scroll_offset;
    }

    let last_index = list_length - 1;

    if item_index == 0 {
        return 0;
    }
    if item_index == last_index {
        return list_length.saturating_sub(visible_height);
    }

    let min_offset = (item_index + 2).saturating_sub(visible_height);
    let max_offset = item_index.saturating_sub(1);

    scroll_offset.clamp(min_offset, max_offset)
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

/// Converts a SelectionState to a LogFilter for log filtering.
fn selection_to_filter(sel: &SelectionState, ws: &WorkspaceState) -> LogFilter {
    if let Some(job) = sel.job {
        LogFilter::IsGroup(ws[job].log_group)
    } else if let Some(bti) = sel.base_task {
        LogFilter::IsBaseTask(bti)
    } else if let Some(kind) = sel.meta_group {
        LogFilter::IsInSet(build_task_set(ws, kind.task_kind()))
    } else {
        LogFilter::All
    }
}

mod config_error;
mod log_search;
mod log_stack;
mod select_search;
mod task_launcher;
mod task_tree;
mod test_filter_launcher;

use config_error::{ConfigErrorAction, ConfigErrorState, ConfigSource};

struct StatusMessage {
    text: String,
    is_error: bool,
    created_at: Instant,
}

impl StatusMessage {
    fn info(text: impl Into<String>) -> Self {
        Self { text: text.into(), is_error: false, created_at: Instant::now() }
    }

    fn error(text: impl Into<String>) -> Self {
        Self { text: text.into(), is_error: true, created_at: Instant::now() }
    }

    fn is_visible(&self) -> bool {
        let duration = if self.is_error { Duration::from_millis(800) } else { Duration::from_millis(600) };
        self.created_at.elapsed() < duration
    }
}

enum FocusOverlap {
    Group { selection: SelectSearch },
    LogSearch { state: LogSearchState },
    TaskLauncher { state: TaskLauncherState },
    TestFilterLauncher { state: TestFilterLauncherState },
    ConfigError { state: ConfigErrorState },
    None,
}

struct HelpMenu {
    visible: bool,
    scroll: usize,
}

/// State for multi-key binding chains (e.g., SPACE l for "Leader" + "LaunchTask")
#[derive(Default)]
struct ChainState {
    /// Current chain group index (None = not in chain)
    current: Option<u32>,
}

impl ChainState {
    fn is_active(&self) -> bool {
        self.current.is_some()
    }

    fn reset(&mut self) {
        self.current = None;
    }
}

struct TuiState {
    frame: DoubleBuffer,
    frame_width: u16,
    frame_height: u16,

    logs: LogStack,
    task_tree: TaskTreeState,
    overlay: FocusOverlap,
    help: HelpMenu,
    status_message: Option<StatusMessage>,
    task_tree_hidden: bool,
    chain: ChainState,
}

fn compute_menu_height(terminal_height: u16) -> u16 {
    const MIN_HEIGHT: u16 = 5;
    const MAX_HEIGHT: u16 = 10;
    const MIN_TERMINAL: u16 = 35;
    const MAX_TERMINAL: u16 = 60;

    if terminal_height >= MAX_TERMINAL {
        MAX_HEIGHT
    } else if terminal_height <= MIN_TERMINAL {
        MIN_HEIGHT
    } else {
        (MIN_HEIGHT + (terminal_height - MIN_TERMINAL + 4) / 5).min(MAX_HEIGHT)
    }
}

fn render<'a>(
    w: u16,
    h: u16,
    tui: &'a mut TuiState,
    workspace: &Workspace,
    keybinds: &Keybinds,
    delta: Has,
) -> &'a [u8] {
    let has_overlay = !matches!(tui.overlay, FocusOverlap::None);
    let show_task_tree_area = has_overlay || !tui.task_tree_hidden;
    let menu_height = if show_task_tree_area { compute_menu_height(h) } else { 1 };

    let dimensions_changed = tui.frame_width != w || tui.frame_height != menu_height;
    let resized = delta.any(Has::RESIZED) || dimensions_changed;
    if dimensions_changed {
        tui.frame.resize(w, menu_height);
        tui.frame_width = w;
        tui.frame_height = menu_height;
    }
    if resized {
        tui.frame.reset();
    }

    let sel = {
        let ws = workspace.state();
        tui.task_tree.selection_state(&ws)
    };

    if let Some(sel) = sel {
        tui.logs.update_selection(sel);
    }

    tui.frame.y_offset = h - menu_height;
    tui.frame.buf.clear();

    Style::DEFAULT.delta().write_to_buffer(&mut tui.frame.buf);

    tui.logs.highlight = match &tui.overlay {
        FocusOverlap::LogSearch { state } => state.selected_match().map(|m| crate::scroll_view::LogHighlight {
            log_id: m.log_id,
            match_info: crate::line_width::MatchHighlight { start: m.match_start, len: state.pattern_len() as u32 },
        }),
        _ => None,
    };

    let dest = Rect { x: 0, y: 0, w, h: h - menu_height };
    tui.logs.render(&mut tui.frame.buf, dest, workspace, keybinds, resized);

    let mut bot = Rect { x: 0, y: 0, w, h: menu_height };

    {
        let status_data = build_status_bar_data(tui, workspace, keybinds);
        render_status_bar(&mut tui.frame, bot.take_top(1), &status_data);
    }

    if show_task_tree_area {
        let mut task_tree_rect = bot.take_top(19);

        let help_rect = if tui.help.visible {
            let help_width = 32.min(task_tree_rect.w as i32);
            Some(task_tree_rect.take_right(help_width))
        } else {
            None
        };

        match &mut tui.overlay {
            FocusOverlap::Group { selection } => {
                let ws = &*workspace.state();
                let groups = &ws.config.current.groups;
                let max_name_width = groups.iter().map(|(name, _)| name.len()).max().unwrap_or(0) + 2;
                selection.render(&mut tui.frame, task_tree_rect, "group> ", |out, mut rect, idx: usize, selected| {
                    let style = if selected { Color(153).with_fg(Color::Black) } else { Style::DEFAULT };
                    let substyle = if selected { Color::Grey[5].with_bg(Color(153)) } else { Color::Grey[14].as_fg() };
                    if selected {
                        rect.with(style).fill(out);
                    }
                    let (name, tasks) = &groups[idx];
                    rect.take_left(max_name_width as i32).with(style).text(out, *name);
                    let task_list: Vec<_> = tasks.iter().map(|t| &*t.name).collect();
                    rect.with(substyle).text(out, &task_list.join(", "));
                });
            }
            FocusOverlap::LogSearch { state } => {
                let logs = workspace.logs.read().unwrap();
                state.render(&mut tui.frame, task_tree_rect, &logs);
            }
            FocusOverlap::TaskLauncher { state } => {
                state.render(&mut tui.frame, task_tree_rect);
            }
            FocusOverlap::TestFilterLauncher { state } => {
                state.render(&mut tui.frame, task_tree_rect);
            }
            FocusOverlap::ConfigError { state } => {
                state.render(&mut tui.frame, task_tree_rect);
            }
            FocusOverlap::None => {
                let (p, mut s) = task_tree_rect.h_split(0.5);
                s.take_left(1);
                let ws = workspace.state();
                tui.task_tree.render_primary(&mut tui.frame, p, &ws);
                tui.task_tree.render_secondary(&mut tui.frame, s, &ws);
            }
        }

        if let Some(help_rect) = help_rect {
            let current_mode = match &tui.overlay {
                FocusOverlap::Group { .. } => Mode::SelectSearch,
                FocusOverlap::LogSearch { .. } => Mode::LogSearch,
                FocusOverlap::TaskLauncher { .. } => Mode::TaskLauncher,
                FocusOverlap::TestFilterLauncher { .. } => Mode::TestFilterLauncher,
                FocusOverlap::ConfigError { .. } => Mode::Global,
                FocusOverlap::None => Mode::Global,
            };
            let chain_idx = if matches!(tui.overlay, FocusOverlap::None) { tui.chain.current } else { None };
            render_help_menu(&mut tui.frame, help_rect, keybinds, &mut tui.help, current_mode, chain_idx);
        }
    }

    tui.frame.render_internal();

    pre_truncate(&mut tui.frame.buf)
}

struct StatusBarData {
    mode_name: &'static str,
    mode_bg: Color,
    selection_text: String,
    search_info: Option<(usize, usize)>,
    running: usize,
    scheduled: usize,
    is_collapsed: bool,
    log_mode: &'static str,
    is_scrolled: bool,
    status_message: Option<(String, bool)>,
    test_summary: Option<crate::workspace::TestGroupSummary>,
    chain_label: Option<String>,
}

fn render_status_bar(frame: &mut DoubleBuffer, rect: Rect, data: &StatusBarData) {
    rect.with(Color::Grey[4].with_fg(Color::Grey[4])).fill(frame);

    let mode_text = format_args!(" {} ", data.mode_name);
    let mut r = rect.with(data.mode_bg.with_fg(Color::Black)).fmt(frame, mode_text);

    if let Some(label) = &data.chain_label {
        let label_text = format!(" {} ", label);
        r = r.with(Color::LightGoldenrod1.with_fg(Color::Black)).text(frame, &label_text);
    } else if !data.selection_text.is_empty() {
        r = r.with(Color::Grey[8].with_fg(Color::Grey[25])).text(frame, &data.selection_text);
    }

    if let Some((selected, total)) = data.search_info {
        let match_text = format_args!(" {}/{} ", selected + 1, total);
        r = r.with(Color::Grey[6].with_fg(Color::Grey[20])).fmt(frame, match_text);
    }

    if data.is_scrolled {
        let scroll_text = " SCROLL ";
        r = r.with(Color(215).with_fg(Color::Black)).text(frame, scroll_text);
    }

    r = r.with(HAlign::Right);

    let view_mode = if data.is_collapsed { "C" } else { "E" };
    r = r.with(Color::Grey[8].with_fg(Color::Grey[25])).fmt(frame, format_args!(" {} {} ", data.log_mode, view_mode));

    let block_style = if data.running > 0 {
        Color::DarkOliveGreen.with_fg(Color::Black)
    } else if data.scheduled > 0 {
        Color::Violet.with_fg(Color::Black)
    } else {
        Color::Grey[6].with_fg(Color::Grey[20])
    };
    r = r.with(block_style).fmt(frame, format_args!(" R:{} S:{} ", data.running, data.scheduled));

    if let Some(ts) = &data.test_summary {
        let test_style = if ts.running > 0 || ts.pending > 0 {
            Color::Cyan1.with_fg(Color::Black)
        } else if ts.failed > 0 {
            Color::NeonRed.with_fg(Color::Black)
        } else {
            Color::SpringGreen.with_fg(Color::Black)
        };
        if ts.running > 0 {
            r = r.with(test_style).fmt(frame, format_args!(" T:{}/{} ({}) ", ts.passed, ts.total, ts.running));
        } else {
            r = r.with(test_style).fmt(frame, format_args!(" T:{}/{} ", ts.passed, ts.total));
        }
    }

    if let Some((text, is_error)) = &data.status_message {
        let msg_text = format!(" {} ", text);
        let fg_color = if *is_error { Color::Salmon } else { Color::Grey[14] };
        r.with(Color::Grey[4].with_fg(fg_color)).text(frame, &msg_text);
    }
}

fn build_status_bar_data(tui: &TuiState, workspace: &Workspace, keybinds: &Keybinds) -> StatusBarData {
    let ws = workspace.state();

    let (mode_name, mode_bg) = match &tui.overlay {
        FocusOverlap::Group { .. } => ("GROUP", Color::Violet),
        FocusOverlap::LogSearch { .. } => ("SEARCH", Color::LightSkyBlue1),
        FocusOverlap::TaskLauncher { .. } => ("LAUNCH", Color::LightGoldenrod2),
        FocusOverlap::TestFilterLauncher { .. } => ("TEST", Color::Cyan1),
        FocusOverlap::ConfigError { .. } => ("ERROR", Color::Red1),
        FocusOverlap::None => ("NORMAL", Color::DarkOliveGreen),
    };

    let sel = tui.task_tree.selection_state_readonly(&ws);
    let selection_text = if let FocusOverlap::TestFilterLauncher { state } = &tui.overlay {
        format!(" {}/{} tests ", state.matching_test_count(&ws), state.total_test_count(&ws))
    } else if let Some(sel) = sel {
        if let Some(job_idx) = sel.job {
            let job = &ws[job_idx];
            let bti = job.log_group.base_task_index();
            let name = ws.base_tasks[bti.idx()].name;
            format!(" {}:{} ", name, job_idx.idx())
        } else if let Some(bti) = sel.base_task {
            format!(" {} ", ws.base_tasks[bti.idx()].name)
        } else if let Some(kind) = sel.meta_group {
            match kind {
                MetaGroupKind::Tests => " @tests ".to_string(),
                MetaGroupKind::Actions => " @actions ".to_string(),
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let search_info = if let FocusOverlap::LogSearch { state } = &tui.overlay {
        Some((state.selected_index(), state.matches.len()))
    } else {
        None
    };

    let mut running = 0usize;
    let mut scheduled = 0usize;
    for bt in &ws.base_tasks {
        if bt.removed {
            continue;
        }
        running += bt.jobs.running().len();
        scheduled += bt.jobs.scheduled().len();
    }

    let log_mode = match tui.logs.mode() {
        log_stack::Mode::All => "1",
        log_stack::Mode::OnlySelected(_) => "2",
        log_stack::Mode::Hybrid(_) => "3",
    };

    let scroll_state = tui.logs.scroll_state(&ws, workspace);
    let is_scrolled = scroll_state.top.is_scrolled || scroll_state.bottom.map_or(false, |b| b.is_scrolled);

    let has_active_status = tui.status_message.as_ref().is_some_and(|m| m.is_visible());
    let status_message = if has_active_status {
        tui.status_message.as_ref().map(|m| (m.text.clone(), m.is_error))
    } else if tui.task_tree_hidden && matches!(tui.overlay, FocusOverlap::None) {
        keybinds
            .key_for_command(&Command::ToggleTaskTree)
            .map(|key| (format!("Press '{}' to show task tree", key), false))
    } else {
        None
    };

    let test_summary = ws.compute_test_group_summary();

    let chain_info = tui.chain.current.and_then(|idx| {
        let group = keybinds.chain(idx)?;
        let label = group.label.as_deref().unwrap_or("...");
        Some(label.to_string())
    });

    StatusBarData {
        mode_name,
        mode_bg,
        selection_text,
        search_info,
        running,
        scheduled,
        is_collapsed: tui.task_tree.is_collapsed(),
        log_mode,
        is_scrolled,
        status_message,
        test_summary,
        chain_label: chain_info,
    }
}

enum ProcessKeyResult {
    Continue,
    Quit,
    ReloadConfig,
}

fn render_help_menu(
    frame: &mut DoubleBuffer,
    mut rect: Rect,
    keybinds: &Keybinds,
    help: &mut HelpMenu,
    current_mode: Mode,
    chain_idx: Option<u32>,
) {
    let (bindings, header_text): (Vec<(InputEvent, HelpEntry)>, String) =
        if let Some(group) = chain_idx.and_then(|idx| keybinds.chain(idx)) {
            let bindings = group.bindings.iter().map(|(k, e)| (*k, HelpEntry::from_binding(keybinds, e))).collect();
            let label = group.label.as_deref().unwrap_or("...");
            (bindings, format!("Chain: {} (? to cancel)", label))
        } else if chain_idx.is_some() {
            (Vec::new(), "Chain (invalid)".to_string())
        } else {
            let mut bindings: Vec<(InputEvent, HelpEntry)> = keybinds
                .mode_bindings(current_mode)
                .map(|(input, entry)| (input, HelpEntry::from_binding(keybinds, entry)))
                .collect();
            let mode_keys: std::collections::HashSet<_> = bindings.iter().map(|(k, _)| *k).collect();

            for (input, entry) in keybinds.global_bindings() {
                if !mode_keys.contains(&input) {
                    bindings.push((input, HelpEntry::from_binding(keybinds, entry)));
                }
            }

            bindings.sort_by(|a, b| a.1.display_name().cmp(b.1.display_name()));
            (bindings, "Keybindings (? to close)".to_string())
        };

    let total_items = bindings.len();
    let visible_height = rect.h as usize;

    if total_items <= visible_height {
        help.scroll = 0;
    } else if help.scroll > total_items - visible_height {
        help.scroll = total_items - visible_height;
    }

    let header = rect.take_top(1);
    header.with(Color::Grey[6].with_fg(Color::Grey[25])).fill(frame).skip(1).text(frame, &header_text);

    for (input, entry) in bindings.iter().skip(help.scroll) {
        let line_rect = rect.take_top(1);
        if line_rect.is_empty() {
            break;
        }

        let key_str = input.to_string();
        let display_name = entry.display_name();

        let mut styled = line_rect.with(Style::DEFAULT);
        styled = styled.with(Color::Cyan1.as_fg()).text(frame, &key_str);

        let key_width = key_str.len();
        let pad_width = 10usize.saturating_sub(key_width);
        for _ in 0..pad_width {
            styled = styled.text(frame, " ");
        }

        styled.with(Color::Grey[20].as_fg()).text(frame, display_name);
    }
}

enum HelpEntry<'a> {
    Command(&'a Command),
    Chain { label: Option<&'a str> },
}

impl<'a> HelpEntry<'a> {
    fn from_binding(keybinds: &'a Keybinds, entry: &'a BindingEntry) -> Self {
        match entry {
            BindingEntry::Command(cmd) => HelpEntry::Command(cmd),
            BindingEntry::Chain(idx) => {
                let label = keybinds.chain(*idx).and_then(|g| g.label.as_deref());
                HelpEntry::Chain { label }
            }
        }
    }

    fn display_name(&self) -> &str {
        match self {
            HelpEntry::Command(cmd) => cmd.display_name(),
            HelpEntry::Chain { label: Some(l) } => l,
            HelpEntry::Chain { label: None } => "...",
        }
    }
}

fn process_key(
    tui: &mut TuiState,
    workspace: &Workspace,
    key_event: KeyEvent,
    keybinds: &Keybinds,
) -> ProcessKeyResult {
    let input = InputEvent::from(key_event);

    if keybinds.lookup(Mode::Global, input) == Some(Command::Quit) {
        return ProcessKeyResult::Quit;
    }

    match &mut tui.overlay {
        FocusOverlap::Group { selection } => {
            match selection.process_input(key_event, keybinds) {
                select_search::Action::Cancel => {
                    tui.overlay = FocusOverlap::None;
                }
                select_search::Action::Enter => {
                    if let Some(group) = selection.selected::<usize>() {
                        let mut ws1 = workspace.state.write().unwrap();
                        let ws = &mut *ws1;
                        if let Some((_, tasks)) = ws.config.current.groups.get(group) {
                            let mut new_tasks = Vec::new();
                            for task in *tasks {
                                if let Some(bti) = ws.base_index_by_name(&task.name) {
                                    new_tasks.push((bti, task.vars.clone(), task.profile.unwrap_or_default()));
                                }
                            }
                            drop(ws1);
                            for (task, vars, profile) in new_tasks {
                                workspace.restart_task(task, vars, profile);
                            }
                            tui.status_message = Some(StatusMessage::info("Group Started"));
                        }
                    }

                    tui.overlay = FocusOverlap::None;
                }
                select_search::Action::None => selection.flush(),
            }
            return ProcessKeyResult::Continue;
        }
        FocusOverlap::LogSearch { state } => {
            match state.process_input(key_event, keybinds) {
                SearchAction::Cancel => {
                    tui.overlay = FocusOverlap::None;
                }
                SearchAction::Confirm(log_id) => {
                    tui.logs.scroll_to_log_id(log_id, workspace);
                    tui.overlay = FocusOverlap::None;
                }
                SearchAction::None => {
                    let logs = workspace.logs.read().unwrap();
                    state.update_index(&logs);
                    state.flush();

                    if let Some(log_id) = state.selected_log_id() {
                        drop(logs);
                        tui.logs.scroll_to_log_id(log_id, workspace);
                    }
                }
            }
            return ProcessKeyResult::Continue;
        }
        FocusOverlap::TaskLauncher { state } => {
            let ws = workspace.state();
            match state.process_input(key_event, keybinds, &ws) {
                LauncherAction::Cancel => {
                    tui.overlay = FocusOverlap::None;
                }
                LauncherAction::Start { base_task, profile, params } => {
                    drop(ws);
                    workspace.restart_task(base_task, params, &profile);
                    tui.overlay = FocusOverlap::None;
                    tui.status_message = Some(StatusMessage::info("Task Spawned"));
                }
                LauncherAction::None => {}
            }
            return ProcessKeyResult::Continue;
        }
        FocusOverlap::TestFilterLauncher { state } => {
            match state.process_input(key_event, keybinds) {
                TestFilterAction::Cancel => {
                    tui.overlay = FocusOverlap::None;
                }
                TestFilterAction::Start { filters } => {
                    match workspace.start_test_run(&filters) {
                        Ok(_) => {
                            let count = filters.len();
                            let msg = if count == 0 {
                                "All tests started".to_string()
                            } else {
                                format!("Tests started with {} filter(s)", count)
                            };
                            tui.status_message = Some(StatusMessage::info(msg));
                        }
                        Err(e) => {
                            tui.status_message = Some(StatusMessage::error(e));
                        }
                    }
                    tui.overlay = FocusOverlap::None;
                }
                TestFilterAction::None => {}
            }
            return ProcessKeyResult::Continue;
        }
        FocusOverlap::ConfigError { state } => {
            match state.process_input(key_event, keybinds) {
                ConfigErrorAction::Retry => {
                    return ProcessKeyResult::ReloadConfig;
                }
                ConfigErrorAction::None => {}
            }
            return ProcessKeyResult::Continue;
        }
        FocusOverlap::None => {}
    }

    let modes = &[Mode::TaskTree, Mode::Pager, Mode::Global];

    let entry = if let Some(chain_idx) = tui.chain.current {
        let Some(group) = keybinds.chain(chain_idx) else {
            tui.chain.reset();
            tui.status_message = Some(StatusMessage::error("Chain invalidated"));
            return ProcessKeyResult::Continue;
        };
        group.lookup(input)
    } else {
        keybinds.lookup_entry_chain(modes, input)
    };

    let command = match entry {
        Some(BindingEntry::Command(cmd)) => {
            tui.chain.reset();
            cmd.clone()
        }
        Some(BindingEntry::Chain(idx)) => {
            let label = keybinds.chain(*idx).and_then(|g| g.label.as_deref()).unwrap_or("...");
            tui.chain.current = Some(*idx);
            tui.status_message = Some(StatusMessage::info(format!("Chain: {}", label)));
            return ProcessKeyResult::Continue;
        }
        None => {
            if tui.chain.is_active() {
                tui.chain.reset();
                tui.status_message = Some(StatusMessage::error(format!("No binding for: {}", input)));
            } else {
                tui.status_message = Some(StatusMessage::error(format!("No binding for input: {}", input)));
            }
            kvlog::info!("no input command found", %input);
            return ProcessKeyResult::Continue;
        }
    };
    kvlog::info!("Processed Input Event", %input, ?command);

    match command {
        Command::Quit => return ProcessKeyResult::Quit,
        Command::SearchLogs => {
            let ws_state = workspace.state();
            let filter = match tui.logs.mode() {
                log_stack::Mode::All => LogFilter::All,
                log_stack::Mode::OnlySelected(sel) | log_stack::Mode::Hybrid(sel) => {
                    selection_to_filter(&sel, &ws_state)
                }
            };
            let logs = workspace.logs.read().unwrap();
            let initial_view_pos = logs.tail();
            let state = LogSearchState::new(&logs, filter, initial_view_pos);
            drop(logs);
            tui.logs.enter_scroll_mode(workspace);
            tui.overlay = FocusOverlap::LogSearch { state };
        }
        Command::StartGroup => {
            let ws = workspace.state();
            let entries = ws.config.current.groups.iter().enumerate().map(|(index, (name, _))| (index, name));
            tui.overlay = FocusOverlap::Group { selection: entries.collect() }
        }
        Command::RestartTask => {
            restart_selected_task(tui, workspace);
        }
        Command::TerminateTask => {
            let ws = workspace.state();
            let bti = tui.task_tree.selection_state(&ws).and_then(|sel| sel.base_task);
            drop(ws);
            if let Some(bti) = bti {
                workspace.terminate_tasks(bti);
                tui.status_message = Some(StatusMessage::info("Task Killed"));
            }
        }
        Command::LaunchTask => {
            let ws = workspace.state();
            let state = TaskLauncherState::new(&ws);
            tui.overlay = FocusOverlap::TaskLauncher { state };
        }
        Command::LaunchTestFilter => {
            let ws = workspace.state();
            let state = TestFilterLauncherState::new(&ws);
            tui.overlay = FocusOverlap::TestFilterLauncher { state };
        }
        Command::ToggleViewMode => {
            tui.task_tree.toggle_collapsed();
        }
        Command::ToggleTaskTree => {
            tui.task_tree_hidden = !tui.task_tree_hidden;
        }
        Command::LogModeAll => {
            tui.logs.set_mode(log_stack::Mode::All);
        }
        Command::LogModeSelected => {
            if let Some(sel) = tui.task_tree.selection_state(&workspace.state()) {
                tui.logs.set_mode(log_stack::Mode::OnlySelected(sel));
            }
        }
        Command::LogModeHybrid => {
            if let Some(sel) = tui.task_tree.selection_state(&workspace.state()) {
                tui.logs.set_mode(log_stack::Mode::Hybrid(sel));
            }
        }
        Command::StartSelection => {
            let ws = workspace.state();
            if let Some(sel) = tui.task_tree.selection_state(&ws) {
                if sel.meta_group == Some(MetaGroupKind::Tests) {
                    let state = TestFilterLauncherState::new(&ws);
                    tui.overlay = FocusOverlap::TestFilterLauncher { state };
                    return ProcessKeyResult::Continue;
                }
                let Some(bti) = sel.base_task else {
                    return ProcessKeyResult::Continue;
                };
                if ws.base_tasks[bti.idx()].config.profiles.is_empty() {
                    return ProcessKeyResult::Continue;
                }
                let mut state = TaskLauncherState::with_task(&ws, bti);
                match state.try_auto_start(&ws) {
                    LauncherAction::Start { base_task, profile, params } => {
                        drop(ws);
                        workspace.restart_task(base_task, params, &profile);
                    }
                    _ => tui.overlay = FocusOverlap::TaskLauncher { state },
                }
            }
        }
        Command::SelectPrev => {
            if !tui.task_tree.move_cursor_up(&workspace.state()) {
                tui.status_message = Some(StatusMessage::error("Already at top of list"));
            }
        }
        Command::SelectNext => {
            if !tui.task_tree.move_cursor_down(&workspace.state()) {
                tui.status_message = Some(StatusMessage::error("Already at bottom of list"));
            }
        }
        Command::FocusPrimary => {
            tui.task_tree.exit_secondary();
        }
        Command::FocusSecondary => {
            tui.task_tree.enter_secondary(&workspace.state());
        }
        Command::JumpToOldestLogs => {
            tui.logs.jump_to_oldest(workspace);
        }
        Command::JumpToNewestLogs => {
            kvlog::info!("Jump to newest");
            tui.logs.jump_to_newest();
        }
        Command::LogScrollUp => {
            tui.logs.pending_top_scroll += 5;
        }
        Command::LogScrollDown => {
            tui.logs.pending_top_scroll -= 5;
        }
        Command::ToggleHelp => {
            tui.help.visible = !tui.help.visible;
        }
        Command::HelpScrollUp => {
            tui.help.scroll = tui.help.scroll.saturating_sub(5);
        }
        Command::HelpScrollDown => {
            tui.help.scroll = tui.help.scroll.saturating_add(5);
        }
        Command::OverlayCancel | Command::OverlayConfirm => {}
        Command::RefreshConfig => {
            return ProcessKeyResult::ReloadConfig;
        }
        Command::CallFunction(fn_name) => {
            call_function(tui, workspace, &fn_name);
        }
        Command::SetFunction { name, action } => {
            set_function(tui, workspace, &name, action);
        }
        Command::RerunTestGroup => match workspace.rerun_test_group(false) {
            Ok(_) => tui.status_message = Some(StatusMessage::info("Rerunning tests")),
            Err(e) => tui.status_message = Some(StatusMessage::error(e)),
        },
        Command::NarrowTestGroup => match workspace.narrow_test_group() {
            Ok(count) => tui.status_message = Some(StatusMessage::info(format!("Narrowed to {} failed tests", count))),
            Err(e) => tui.status_message = Some(StatusMessage::error(e)),
        },
        Command::NextFailInTestGroup => {
            jump_to_fail_in_test_group(tui, workspace, true);
        }
        Command::PrevFailInTestGroup => {
            jump_to_fail_in_test_group(tui, workspace, false);
        }
    }
    ProcessKeyResult::Continue
}

fn call_function(tui: &mut TuiState, workspace: &Workspace, fn_name: &str) {
    let ws = workspace.state();
    if let Some(FunctionAction::RestartCaptured { task_name, profile }) = ws.session_functions.get(fn_name) {
        let task_name = task_name.clone();
        let profile = profile.clone();
        if let Some(&bti) = ws.name_map.get(task_name.as_str()) {
            drop(ws);
            workspace.restart_task(bti, ValueMap::new(), &profile);
            tui.status_message = Some(StatusMessage::info(format!("{} restarted {}", fn_name, task_name)));
        } else {
            tui.status_message = Some(StatusMessage::error(format!("{} task '{}' not found", fn_name, task_name)));
        }
        return;
    }

    for func_def in ws.config.current.functions {
        if func_def.name == fn_name {
            match &func_def.action {
                FunctionDefAction::Restart { task } => {
                    let task_name = *task;
                    if let Some(&bti) = ws.name_map.get(task_name) {
                        drop(ws);
                        workspace.restart_task(bti, ValueMap::new(), "");
                        tui.status_message = Some(StatusMessage::info(format!("{} restarted {}", fn_name, task_name)));
                    } else {
                        tui.status_message =
                            Some(StatusMessage::error(format!("{} task '{}' not found", fn_name, task_name)));
                    }
                }
                FunctionDefAction::Kill { task } => {
                    let task_name = *task;
                    if let Some(&bti) = ws.name_map.get(task_name) {
                        drop(ws);
                        workspace.terminate_tasks(bti);
                        tui.status_message = Some(StatusMessage::info(format!("{} killed {}", fn_name, task_name)));
                    } else {
                        tui.status_message =
                            Some(StatusMessage::error(format!("{} task '{}' not found", fn_name, task_name)));
                    }
                }
                FunctionDefAction::Spawn { tasks } => {
                    drop(ws);
                    for call in *tasks {
                        if let Some(&bti) = workspace.state().name_map.get(&*call.name) {
                            let profile = call.profile.unwrap_or("");
                            workspace.restart_task(bti, call.vars.clone(), profile);
                        }
                    }
                    tui.status_message = Some(StatusMessage::info(format!("{} spawned tasks", fn_name)));
                }
            }
            return;
        }
    }

    if let Some(FunctionAction::RestartSelected) = ws.session_functions.get(fn_name) {
        drop(ws);
        restart_selected_task(tui, workspace);
        return;
    }

    tui.status_message = Some(StatusMessage::error(format!("{} not configured", fn_name)));
}

fn set_function(tui: &mut TuiState, workspace: &Workspace, fn_name: &str, action: SetFunctionAction) {
    match action {
        SetFunctionAction::RestartCurrentSelection => {
            let ws = workspace.state();
            if let Some(sel) = tui.task_tree.selection_state(&ws) {
                if let Some(bti) = sel.base_task {
                    let task_name = ws.base_tasks[bti.idx()].name.to_string();
                    let profile = sel.job.map(|ji| ws[ji].spawn_profile.clone()).unwrap_or_default();
                    drop(ws);
                    let mut ws = workspace.state.write().unwrap();
                    ws.session_functions.insert(
                        fn_name.to_string(),
                        FunctionAction::RestartCaptured { task_name: task_name.clone(), profile: profile.clone() },
                    );
                    drop(ws);
                    let msg = if profile.is_empty() {
                        format!("{} set to restart {}", fn_name, task_name)
                    } else {
                        format!("{} set to restart {}:{}", fn_name, task_name, profile)
                    };
                    tui.status_message = Some(StatusMessage::info(msg));
                    return;
                }
            }
            tui.status_message = Some(StatusMessage::error(format!("No task selected for {}", fn_name)));
        }
    }
}

fn pre_truncate(data: &mut Vec<u8>) -> &[u8] {
    unsafe {
        let len = data.len();
        let ptr = data.as_ptr();
        data.set_len(0);
        std::slice::from_raw_parts(ptr, len)
    }
}

#[derive(Clone, Copy)]
pub struct Has(u32);
impl Has {
    pub const RESIZED: Has = Has(1 << 0);
    // pub const BASED_TASKS_STATE: Has = Has(2 << 0);
    // pub const BASED_JOB_STATE: Has = Has(3 << 0);
    // pub const LOGS: Has = Has(4 << 0);
    pub fn any(&self, has: Has) -> bool {
        self.0 & has.0 != 0
    }
}
impl std::ops::BitOr for Has {
    type Output = Has;

    fn bitor(self, rhs: Self) -> Self::Output {
        Has(rhs.0 | self.0)
    }
}
impl std::ops::BitOrAssign for Has {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Has(self.0 | rhs.0)
    }
}

fn jump_to_fail_in_test_group(tui: &mut TuiState, workspace: &Workspace, forward: bool) {
    let ws = workspace.state();
    let Some(test_group) = &ws.last_test_group else {
        tui.status_message = Some(StatusMessage::error("No test group"));
        return;
    };

    let failed_indices: Vec<usize> = test_group
        .job_indices
        .iter()
        .enumerate()
        .filter(|&(_, ji)| {
            let Some(job) = ws.jobs.get(ji.idx()) else { return false };
            matches!(&job.process_status, crate::workspace::JobStatus::Exited { status, .. } if *status != 0)
                || matches!(&job.process_status, crate::workspace::JobStatus::Cancelled)
        })
        .map(|(i, _)| i)
        .collect();

    if failed_indices.is_empty() {
        tui.status_message = Some(StatusMessage::error("No failures in test group"));
        return;
    }

    let current_job = tui.task_tree.selection_state_readonly(&ws).and_then(|s| s.job);
    let current_pos = current_job.and_then(|cj| test_group.job_indices.iter().position(|&ji| ji == cj));

    let next_fail_idx = if forward {
        match current_pos {
            Some(pos) => failed_indices.iter().find(|&&i| i > pos).or(failed_indices.first()),
            None => failed_indices.first(),
        }
    } else {
        match current_pos {
            Some(pos) => failed_indices.iter().rev().find(|&&i| i < pos).or(failed_indices.last()),
            None => failed_indices.last(),
        }
    };

    let Some(&fail_idx) = next_fail_idx else {
        tui.status_message = Some(StatusMessage::error("No failures in test group"));
        return;
    };

    let job_index = test_group.job_indices[fail_idx];
    tui.task_tree.select_test_group_job(job_index, &ws);

    let fail_num = failed_indices.iter().position(|&i| i == fail_idx).unwrap_or(0) + 1;
    tui.status_message = Some(StatusMessage::info(format!("Failure {}/{}", fail_num, failed_indices.len())));
}

fn restart_selected_task(tui: &mut TuiState, workspace: &Workspace) {
    let ws = workspace.state();
    let Some(sel) = tui.task_tree.selection_state(&ws) else {
        return;
    };
    let had_job_selected = sel.job.is_some();
    let Some((base_task, params, profile)) = (if let Some(job_index) = sel.job {
        let job = &ws[job_index];
        Some((job.log_group.base_task_index(), job.spawn_params.clone(), job.spawn_profile.clone()))
    } else if let Some(bti) = sel.base_task {
        Some((bti, ValueMap::new(), String::new()))
    } else if let Some(kind) = sel.meta_group {
        let jobs = ws.jobs_by_kind(kind.task_kind());
        if let Some(&last_ji) = jobs.last() {
            let job = &ws[last_ji];
            Some((job.log_group.base_task_index(), job.spawn_params.clone(), job.spawn_profile.clone()))
        } else {
            let msg = match kind {
                MetaGroupKind::Tests => "No Test to Restart",
                MetaGroupKind::Actions => "No Action to Restart",
            };
            tui.status_message = Some(StatusMessage::error(msg));
            return;
        }
    } else {
        None
    }) else {
        return;
    };
    drop(ws);
    let new_job = workspace.restart_task(base_task, params, &profile);
    if had_job_selected {
        let ws = workspace.state();
        tui.task_tree.select_job(new_job, &ws);
    }
    tui.status_message = Some(StatusMessage::info("Task Restarted"));
}

#[derive(Debug)]
pub enum ScrollTarget {
    TopLog,
    BottomLog,
    TaskList { row: u16 },
    JobList { row: u16 },
    None,
}

fn scroll_target(w: u16, h: u16, x: u16, y: u16, show_task_tree: bool) -> ScrollTarget {
    let menu_height = if show_task_tree { compute_menu_height(h) } else { 1 } as i32;
    let mut dest = Rect { x: 0, y: 0, w, h };
    let mut bot = dest.take_bottom(menu_height);
    let (tl, bl) = dest.v_split(0.5);
    bot.take_top(1);
    if !show_task_tree {
        return if tl.contains(x, y) {
            ScrollTarget::TopLog
        } else if bl.contains(x, y) {
            ScrollTarget::BottomLog
        } else {
            ScrollTarget::None
        };
    }
    let task_tree_rect = bot.take_top(19);
    let (p, mut s) = task_tree_rect.h_split(0.5);
    s.take_left(1);
    if p.contains(x, y) {
        ScrollTarget::TaskList { row: y - p.y }
    } else if tl.contains(x, y) {
        ScrollTarget::TopLog
    } else if bl.contains(x, y) {
        ScrollTarget::BottomLog
    } else if s.contains(x, y) {
        ScrollTarget::JobList { row: y - s.y }
    } else {
        ScrollTarget::None
    }
}

fn job_status_str(status: &crate::workspace::JobStatus) -> &'static str {
    match status {
        crate::workspace::JobStatus::Scheduled { .. } => "Scheduled",
        crate::workspace::JobStatus::Starting => "Starting",
        crate::workspace::JobStatus::Running { .. } => "Running",
        crate::workspace::JobStatus::Exited { .. } => "Exited",
        crate::workspace::JobStatus::Cancelled => "Cancelled",
    }
}

fn meta_group_kind_str(kind: MetaGroupKind) -> &'static str {
    match kind {
        MetaGroupKind::Tests => "tests",
        MetaGroupKind::Actions => "actions",
    }
}

fn output_json_state(workspace: &Workspace, tui: &mut TuiState, tty_render_byte_count: usize, out: &File) {
    let mut file = out;
    let ws = workspace.state();
    let selection = tui.task_tree.selection_state(&ws);
    let scroll_state = tui.logs.scroll_state(&ws, workspace);
    let mut message = jsony::object! {
        tty_render_byte_count,
        collapsed: tui.task_tree.is_collapsed(),
        scroll: {
            top: {
                is_scrolled: scroll_state.top.is_scrolled,
                can_scroll_up: scroll_state.top.can_scroll_up
            },
            @[if let Some(bottom) = scroll_state.bottom]
            bottom: {
                is_scrolled: bottom.is_scrolled,
                can_scroll_up: bottom.can_scroll_up
            }
        },
        overlay: match &tui.overlay {
            FocusOverlap::Group { selection } => {
                kind: "Group",
                selection: selection.selected::<usize>(),
                groups: [for (name, _) in ws.config.current.groups; name]
            },
            FocusOverlap::LogSearch { state } => {
                kind: "LogSearch",
                pattern: state.pattern,
                selected_match: match state.selected_match() {
                    Some(m) => {
                        log_id: m.log_id.0,
                        match_start: m.match_start,
                        match_len: state.pattern_len() as u32
                    },
                    None => None,
                },
                total_matches: state.matches.len()
            },
            FocusOverlap::TaskLauncher { state } => {
                kind: "TaskLauncher",
                input: state.input(),
                mode: match state.mode() {
                    LauncherMode::TaskName => "TaskName",
                    LauncherMode::Profile => "Profile",
                    LauncherMode::Variable => "Variable",
                    LauncherMode::Value => "Value",
                },
                confirmed_task: match state.confirmed_task() {
                    Some((bti, name)) => { index: bti.idx(), name: name },
                    None => None,
                },
                confirmed_profile: state.confirmed_profile(),
                completed_vars: [for (name, value) in state.completed_vars(); { name: name, value: value }]
            },
            FocusOverlap::TestFilterLauncher { state } => {
                kind: "TestFilterLauncher",
                input: state.input(),
                matching_count: state.matching_test_count(&ws),
                total_count: state.total_test_count(&ws)
            },
            FocusOverlap::ConfigError { .. } => {
                kind: "ConfigError"
            },
            FocusOverlap::None => None,
        },
        @[if let Some(sel) = &selection]
        selection: {
            @[if let Some(bti) = sel.base_task]
            base_task: bti.idx(),
            @[if let Some(job) = sel.job]
            job: job.idx(),
            @[if let Some(kind) = sel.meta_group]
            meta_group: meta_group_kind_str(kind)
        },
        base_tasks: [for (i, bt) in ws.base_tasks.iter().enumerate(); {
            index: i,
            name: bt.name,
            jobs: [for ji in bt.jobs.all(); {
                index: ji.idx(),
                status: job_status_str(&ws[*ji].process_status),
                @[if let crate::workspace::JobStatus::Exited { status, .. } = &ws[*ji].process_status]
                exit_code: *status
            }]
        }],
        meta_groups: {
            tests: { job_count: ws.jobs_by_kind(TaskKind::Test).len() },
            actions: { job_count: ws.jobs_by_kind(TaskKind::Action).len() }
        }
    };
    message.push('\n');
    use std::io::Write;
    let _ = file.write_all(message.as_bytes());
}

pub enum OutputMode {
    /// The normal tui interface
    Terminal,
    /// A line separated JSON stream used for testing
    JsonStateStream,
}

fn attempt_config_reload(tui: &mut TuiState, workspace: &Workspace, keybinds: &mut Arc<Keybinds>) {
    let mut errors = Vec::new();
    let mut workspace_errored = false;
    let mut user_errored = false;

    {
        let mut ws = workspace.state.write().unwrap();
        match ws.config.refresh_capturing() {
            Ok(changed) => {
                if changed {
                    let ws = &mut *ws;
                    ws.config.update_base_tasks(&mut ws.base_tasks, &mut ws.name_map);
                }
            }
            Err(e) => {
                errors.push(e);
                workspace_errored = true;
            }
        }
    }

    match crate::user_config::reload_user_config() {
        Ok(config) => {
            crate::process_manager::update_global_keybinds(config.keybinds);
            *keybinds = crate::process_manager::global_keybinds();
        }
        Err(e) => {
            errors.push(e);
            user_errored = true;
        }
    }

    if errors.is_empty() {
        tui.overlay = FocusOverlap::None;
        tui.status_message = Some(StatusMessage::info("Config Reloaded"));
    } else {
        let error_message = errors.join("\n");
        let source = match (user_errored, workspace_errored) {
            (true, true) => ConfigSource::Both,
            (true, false) => ConfigSource::User,
            (false, true) => ConfigSource::Workspace,
            (false, false) => return,
        };

        let user_path = crate::user_config::user_config_path();
        let workspace_path = Some(workspace.state.read().unwrap().config.path().clone());

        tui.overlay = FocusOverlap::ConfigError {
            state: ConfigErrorState::new(error_message, source, user_path, workspace_path),
        };
    }
}
pub fn run(
    stdin: File,
    stdout: File,
    workspace: &Workspace,
    extui_channel: Arc<ClientChannel>,
    mut keybinds: Arc<Keybinds>,
    output_mode: OutputMode,
) -> anyhow::Result<()> {
    let mode = TerminalFlags::RAW_MODE
        | TerminalFlags::ALT_SCREEN
        | TerminalFlags::HIDE_CURSOR
        | TerminalFlags::MOUSE_CAPTURE
        | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
    let mut terminal = match output_mode {
        OutputMode::Terminal => Some(extui::Terminal::new(stdout.as_raw_fd(), mode)?),
        OutputMode::JsonStateStream => None,
    };
    let mut events = extui::event::Events::default();
    use std::io::Write;
    if let Some(terminal) = &mut terminal {
        terminal.write_all(&[vt::MOVE_CURSOR_TO_ORIGIN, vt::CLEAR_BELOW].concat())?;
    }
    let (mut w, mut h) = if let Some(terminal) = &terminal { terminal.size()? } else { (160, 90) };
    let initial_menu_height = compute_menu_height(h);

    let mut previous = 0;
    let mut tui = TuiState {
        frame: DoubleBuffer::new(w, initial_menu_height),
        frame_width: w,
        frame_height: initial_menu_height,
        logs: LogStack::default(),
        task_tree: TaskTreeState::default(),
        overlay: FocusOverlap::None,
        help: HelpMenu { visible: false, scroll: 0 },
        status_message: None,
        task_tree_hidden: false,
        chain: ChainState::default(),
    };

    let mut delta = Has(0);
    loop {
        if delta.any(Has::RESIZED) {
            (w, h) = if let Some(terminal) = &terminal { terminal.size()? } else { (150, 80) };
        }
        let data = render(w, h, &mut tui, workspace, &keybinds, delta);
        kvlog::debug!("Rendered TUI", tty_render_byte_count = data.len());
        if let Some(terminal) = &mut terminal {
            terminal.write_all(data)?;
        } else {
            let byte_count = data.len();
            output_json_state(workspace, &mut tui, byte_count, &stdout);
        }
        delta = Has(0);

        {
            let ws = workspace.state();
            if let Some(sel) = tui.task_tree.selection_state(&ws) {
                tui.logs.update_selection(sel);
                let selected_value = if let Some(bti) = sel.base_task {
                    bti.idx() as u64
                } else if let Some(kind) = sel.meta_group {
                    match kind {
                        MetaGroupKind::Tests => SELECTED_META_GROUP_TESTS,
                        MetaGroupKind::Actions => SELECTED_META_GROUP_ACTIONS,
                    }
                } else {
                    0
                };
                extui_channel.selected.store(selected_value, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let poll_timeout = match &tui.overlay {
            FocusOverlap::ConfigError { .. } => Some(ConfigErrorState::poll_interval()),
            _ => None,
        };

        match extui::event::poll_with_custom_waker(&stdin, Some(&extui_channel.waker), poll_timeout)? {
            extui::event::Polled::ReadReady => events.read_from(&stdin)?,
            extui::event::Polled::Woken => {}
            extui::event::Polled::TimedOut => {
                if let FocusOverlap::ConfigError { state } = &mut tui.overlay {
                    if state.check_file_changed() {
                        attempt_config_reload(&mut tui, workspace, &mut keybinds);
                    }
                }
            }
        }
        match extui_channel.actions(&mut previous) {
            Some(Action::Resized) => delta |= Has::RESIZED,
            Some(Action::Terminated) => return Ok(()),
            None => (),
        }

        if extui::event::polling::termination_requested() {
            return Ok(());
        }

        while let Some(event) = events.next(true) {
            match event {
                Event::Key(key_event) => match process_key(&mut tui, workspace, key_event, &keybinds) {
                    ProcessKeyResult::Quit => return Ok(()),
                    ProcessKeyResult::ReloadConfig => {
                        attempt_config_reload(&mut tui, workspace, &mut keybinds);
                    }
                    ProcessKeyResult::Continue => {}
                },
                Event::Resized => (),
                Event::Mouse(mouse) => {
                    let x = mouse.column;
                    let y = mouse.row;
                    let has_overlay = !matches!(tui.overlay, FocusOverlap::None);
                    let show_task_tree = has_overlay || !tui.task_tree_hidden;
                    let target = scroll_target(w, h, x, y, show_task_tree);
                    match mouse.kind {
                        extui::event::MouseEventKind::ScrollDown => match target {
                            ScrollTarget::TopLog => tui.logs.pending_top_scroll -= 5,
                            ScrollTarget::BottomLog => tui.logs.pending_bottom_scroll -= 5,
                            ScrollTarget::TaskList { .. } | ScrollTarget::JobList { .. } => {
                                let _ = tui.task_tree.move_cursor_down(&workspace.state());
                            }
                            ScrollTarget::None => (),
                        },
                        extui::event::MouseEventKind::ScrollUp => match target {
                            ScrollTarget::TopLog => tui.logs.pending_top_scroll += 5,
                            ScrollTarget::BottomLog => tui.logs.pending_bottom_scroll += 5,
                            ScrollTarget::TaskList { .. } | ScrollTarget::JobList { .. } => {
                                let _ = tui.task_tree.move_cursor_up(&workspace.state());
                            }
                            ScrollTarget::None => (),
                        },
                        extui::event::MouseEventKind::Down(button) => match target {
                            ScrollTarget::TaskList { row } => {
                                tui.task_tree.select_primary_by_row(row as usize, &workspace.state());
                                if matches!(button, extui::event::MouseButton::Right) {
                                    restart_selected_task(&mut tui, workspace);
                                }
                            }
                            ScrollTarget::JobList { row } => {
                                tui.task_tree.select_job_by_row(row as usize, &workspace.state());
                                if matches!(button, extui::event::MouseButton::Right) {
                                    restart_selected_task(&mut tui, workspace);
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
                evt => {
                    println!("{:#?}", evt);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::constrain_scroll_offset;

    #[test]
    fn scroll_offset_edge_cases() {
        assert_eq!(constrain_scroll_offset(5, 0, 0, 0), 0, "empty list");
        assert_eq!(constrain_scroll_offset(5, 0, 0, 1), 0, "single item");
        assert_eq!(constrain_scroll_offset(10, 3, 0, 5), 0, "list fits in view");
        assert_eq!(constrain_scroll_offset(5, 2, 0, 5), 0, "list exactly fits");
        assert_eq!(constrain_scroll_offset(2, 5, 0, 10), 4, "small height no padding");
        assert_eq!(constrain_scroll_offset(1, 5, 0, 10), 5, "height=1 no padding");
    }

    #[test]
    fn scroll_offset_boundary_items() {
        assert_eq!(constrain_scroll_offset(5, 0, 0, 20), 0, "first item from 0");
        assert_eq!(constrain_scroll_offset(5, 0, 3, 20), 0, "first item resets offset");
        assert_eq!(constrain_scroll_offset(5, 19, 0, 20), 15, "last item from 0");
        assert_eq!(constrain_scroll_offset(5, 19, 10, 20), 15, "last item from middle");

        let offset = constrain_scroll_offset(5, 1, 0, 20);
        assert_eq!(offset, 0, "near-top item keeps offset 0");

        let offset = constrain_scroll_offset(5, 18, 0, 20);
        assert!(offset <= 17 && offset + 5 > 19, "near-bottom has padding both sides");
    }

    #[test]
    fn scroll_offset_middle_items_with_padding() {
        for initial_offset in [0, 8, 15] {
            let offset = constrain_scroll_offset(5, 10, initial_offset, 20);
            assert!(offset <= 9, "item 10 needs 1 visible above: got {offset}");
            assert!(offset + 5 > 11, "item 10 needs 1 visible below: got {offset}");
        }

        assert_eq!(constrain_scroll_offset(5, 10, 8, 20), 8, "valid offset preserved");

        let offset = constrain_scroll_offset(5, 10, 12, 20);
        assert!(offset <= 9, "offset too high corrected");

        let offset = constrain_scroll_offset(5, 10, 3, 20);
        assert!(offset + 5 > 11, "offset too low corrected");
    }
}
