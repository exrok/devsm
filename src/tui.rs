use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use jsony_value::ValueMap;
use vtui::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use vtui::vt::BufferWrite;
use vtui::{Color, DoubleBuffer, Rect, Style, TerminalFlags, vt};

use crate::log_storage::LogFilter;
use crate::process_manager::{Action, ClientChannel};
use crate::tui::log_search::{LogSearchState, SearchAction};
use crate::tui::log_stack::LogStack;
use crate::tui::select_search::SelectSearch;
use crate::tui::task_tree::TaskTreeState;
use crate::workspace::{BaseTaskIndex, Workspace};

pub fn constrain_scroll_offset(visible_height: usize, item_index: usize, scroll_offset: usize) -> usize {
    if item_index < scroll_offset {
        item_index
    } else if item_index >= scroll_offset + visible_height {
        item_index + 1 - visible_height
    } else {
        scroll_offset
    }
}

mod log_search;
mod log_stack;
mod select_search;
mod task_tree;

enum FocusOverlap {
    Group { selection: SelectSearch },
    SpawnProfile { selection: SelectSearch, bti: BaseTaskIndex, profiles: &'static [&'static str] },
    LogSearch { state: LogSearchState },
    None,
}

struct TuiState {
    frame: DoubleBuffer,

    logs: LogStack,
    task_tree: TaskTreeState,
    overlay: FocusOverlap,
}

fn render<'a>(w: u16, h: u16, tui: &'a mut TuiState, workspace: &Workspace, delta: Has) -> &'a [u8] {
    if delta.any(Has::RESIZED) {
        tui.frame.resize(w, h);
    }
    let menu_height = 10;
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

    // Set highlighted log for search mode
    tui.logs.highlight = match &tui.overlay {
        FocusOverlap::LogSearch { state } => {
            state.selected_match().map(|m| crate::scroll_view::LogHighlight {
                log_id: m.log_id,
                match_info: crate::line_width::MatchHighlight {
                    start: m.match_start,
                    len: state.pattern_len() as u32,
                },
            })
        }
        _ => None,
    };

    let dest = Rect { x: 0, y: 0, w, h: h - menu_height };
    tui.logs.render(&mut tui.frame.buf, dest, &workspace);

    let mut bot = Rect { x: 0, y: 0, w, h: menu_height };

    bot.take_top(1)
        .with(Color::Grey[6].with_fg(Color::Grey[25]))
        .fill(&mut tui.frame)
        .skip(1)
        .text(&mut tui.frame, "Placeholder");
    {
        let task_tree_rect = bot.take_top(19);
        match &mut tui.overlay {
            FocusOverlap::Group { selection } => {
                let ws = &*workspace.state();
                selection.render(&mut tui.frame, task_tree_rect, "group> ", |out, rect, bti: usize, selected| {
                    let mut x = rect.with(Style::default());
                    if selected {
                        x = x.with(Color::LightSkyBlue1.with_fg(Color::Black)).fill(out)
                    }
                    x.text(out, ws.config.current.groups[bti].0);
                });
            }
            FocusOverlap::SpawnProfile { selection, profiles, .. } => {
                let (p, mut s) = task_tree_rect.h_split(0.5);
                s.take_left(1);
                let ws = workspace.state();
                tui.task_tree.render_primary(&mut tui.frame, p, &ws);
                selection.render(&mut tui.frame, s, "profile> ", |out, rect, prof: usize, selected| {
                    let mut x = rect.with(Style::default());
                    if selected {
                        x = x.with(Color::LightSkyBlue1.with_fg(Color::Black)).fill(out)
                    }
                    x.text(out, &profiles[prof]);
                });
            }
            FocusOverlap::LogSearch { state } => {
                let logs = workspace.logs.read().unwrap();
                state.render(&mut tui.frame, task_tree_rect, &logs);
            }
            FocusOverlap::None => {
                let (p, mut s) = task_tree_rect.h_split(0.5);
                s.take_left(1);
                let ws = workspace.state();
                tui.task_tree.render_primary(&mut tui.frame, p, &ws);
                tui.task_tree.render_secondary(&mut tui.frame, s, &ws);
            }
        }
    }

    tui.frame.render_internal();

    pre_truncate(&mut tui.frame.buf)
}

fn process_key<'a>(tui: &'a mut TuiState, workspace: &Workspace, key_event: KeyEvent) -> bool {
    use KeyCode::*;
    const CTRL: KeyModifiers = KeyModifiers::CONTROL;
    match (key_event.modifiers, key_event.code) {
        (CTRL, Char('c')) => return true,
        _ => (),
    }
    match &mut tui.overlay {
        FocusOverlap::Group { selection } => {
            match selection.process_input(key_event) {
                select_search::Action::Cancel => {
                    tui.overlay = FocusOverlap::None;
                }
                select_search::Action::Enter => {
                    if let Some(group) = selection.selected::<usize>() {
                        // FIX: Handle cases where the config has changed since the selection
                        // was opened. Currently if the group indices change we may try to start
                        // the wronge group.
                        let mut ws1 = workspace.state.write().unwrap();
                        let ws = &mut *ws1;
                        if let Some((_, tasks)) = ws.config.current.groups.get(group) {
                            let mut new_tasks = Vec::new();
                            for task in *tasks {
                                if let Some(bti) = ws.base_index_by_name(&*task.name) {
                                    new_tasks.push((bti, task.vars.clone(), task.profile.unwrap_or_default()));
                                }
                            }
                            drop(ws1);
                            for (task, vars, profile) in new_tasks {
                                workspace.restart_task(BaseTaskIndex(task as u32), vars, profile);
                            }
                        }
                    }

                    tui.overlay = FocusOverlap::None;
                }
                select_search::Action::None => selection.flush(),
            }
            return false;
        }
        FocusOverlap::SpawnProfile { selection, bti, profiles } => {
            match selection.process_input(key_event) {
                select_search::Action::Cancel => {
                    tui.overlay = FocusOverlap::None;
                }
                select_search::Action::Enter => {
                    if let Some(pi) = selection.selected::<usize>() {
                        workspace.restart_task(*bti, ValueMap::new(), profiles[pi]);
                    }

                    tui.overlay = FocusOverlap::None;
                }
                select_search::Action::None => selection.flush(),
            }
            return false;
        }
        FocusOverlap::LogSearch { state } => {
            match state.process_input(key_event) {
                SearchAction::Cancel => {
                    tui.overlay = FocusOverlap::None;
                }
                SearchAction::Confirm(log_id) => {
                    tui.logs.scroll_to_log_id(log_id, workspace);
                    tui.overlay = FocusOverlap::None;
                }
                SearchAction::None => {
                    // Update index with any new logs
                    let logs = workspace.logs.read().unwrap();
                    state.update_index(&logs);
                    state.flush();

                    // If a match is selected, scroll to it
                    if let Some(log_id) = state.selected_log_id() {
                        drop(logs);
                        tui.logs.scroll_to_log_id(log_id, workspace);
                    }
                }
            }
            return false;
        }
        FocusOverlap::None => {}
    }
    match (key_event.modifiers, key_event.code) {
        (CTRL, Char('c')) => return true,
        (_, Char('/')) => {
            // Enter log search mode
            let ws_state = workspace.state();
            let filter = match tui.logs.mode() {
                log_stack::Mode::All => LogFilter::All,
                log_stack::Mode::OnlySelected(sel) | log_stack::Mode::Hybrid(sel) => {
                    if let Some(job) = sel.job {
                        LogFilter::IsJob(ws_state[job].job_id)
                    } else {
                        LogFilter::IsBaseTask(sel.base_task)
                    }
                }
            };
            let logs = workspace.logs.read().unwrap();
            let initial_view_pos = logs.tail();
            let state = LogSearchState::new(&logs, filter, initial_view_pos);
            drop(logs);
            tui.logs.enter_scroll_mode(workspace);
            tui.overlay = FocusOverlap::LogSearch { state };
        }
        (_, Char('g')) => {
            let ws = workspace.state();
            let entries = ws.config.current.groups.iter().enumerate().map(|(index, (name, _))| (index, name));
            tui.overlay = FocusOverlap::Group { selection: entries.collect() }
        }
        (_, Char('r')) => {
            if let Some(sel) = { tui.task_tree.selection_state(&workspace.state()) } {
                workspace.restart_task(sel.base_task, ValueMap::new(), "");
            }
        }
        (_, Char('d')) => {
            if let Some(sel) = { tui.task_tree.selection_state(&workspace.state()) } {
                workspace.terminate_tasks(sel.base_task);
            }
        }
        (_, Char('1')) => {
            tui.logs.set_mode(log_stack::Mode::All);
        }
        (_, Char('2')) => {
            if let Some(sel) = tui.task_tree.selection_state(&workspace.state()) {
                tui.logs.set_mode(log_stack::Mode::OnlySelected(sel));
            }
        }
        (_, Char('3')) => {
            if let Some(sel) = tui.task_tree.selection_state(&workspace.state()) {
                tui.logs.set_mode(log_stack::Mode::Hybrid(sel));
            }
        }
        (_, Char('p')) => {
            let ws = workspace.state();
            if let Some(sel) = tui.task_tree.selection_state(&ws) {
                let profiles = ws.base_tasks[sel.base_task.idx()].config.profiles;
                if profiles.is_empty() {
                    // todo add message
                    return false;
                }
                tui.overlay = FocusOverlap::SpawnProfile {
                    bti: sel.base_task,
                    profiles,
                    selection: profiles.into_iter().enumerate().collect(),
                }
            }
        }
        (_, Char('k')) => {
            tui.task_tree.move_cursor_up(&workspace.state());
        }
        (_, Char('j')) => {
            tui.task_tree.move_cursor_down(&workspace.state());
        }
        (_, Char('h')) => {
            tui.task_tree.exit_secondary();
        }
        (_, Char('l')) => {
            tui.task_tree.enter_secondary(&workspace.state());
        }
        _ => (),
    }
    false
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

#[derive(Debug)]
pub enum ScrollTarget {
    TopLog,
    BottomLog,
    TaskList,
    JobList,
    None,
}

fn scroll_target(w: u16, h: u16, tui: &TuiState, x: u16, y: u16) -> ScrollTarget {
    let menu_height = 10;
    let mut dest = Rect { x: 0, y: 0, w, h: h };
    let mut bot = dest.take_bottom(menu_height);
    let (tl, bl) = dest.v_split(0.5);
    bot.take_top(1);
    let task_tree_rect = bot.take_top(19);
    let (p, mut s) = task_tree_rect.h_split(0.5);
    s.take_left(1);
    if p.contains(x, y) {
        ScrollTarget::TaskList
    } else if tl.contains(x, y) {
        ScrollTarget::TopLog
    } else if bl.contains(x, y) {
        ScrollTarget::BottomLog
    } else if s.contains(x, y) {
        ScrollTarget::JobList
    } else {
        ScrollTarget::None
    }
}

pub fn run(
    stdin: OwnedFd,
    stdout: OwnedFd,
    workspace: &Workspace,
    vtui_channel: Arc<ClientChannel>,
) -> anyhow::Result<()> {
    let mode = TerminalFlags::RAW_MODE
        | TerminalFlags::ALT_SCREEN
        | TerminalFlags::HIDE_CURSOR
        | TerminalFlags::MOUSE_CAPTURE
        | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
    let mut terminal = vtui::Terminal::new(stdout.as_raw_fd(), mode)?;
    let mut events = vtui::event::parse::Events::default();
    use std::io::Write;
    {
        let mut buf = Vec::new();
        vt::move_cursor_to_origin(&mut buf);
        buf.extend_from_slice(vt::CLEAR_BELOW);
        terminal.write_all(&buf)?;
    }
    let (mut w, mut h) = terminal.size()?;
    let bh = 10;

    let mut previous = 0;
    let mut tui = TuiState {
        frame: DoubleBuffer::new(w, bh),
        logs: LogStack::default(),
        task_tree: TaskTreeState::default(),
        overlay: FocusOverlap::None,
    };

    let mut delta = Has(0);
    loop {
        if delta.any(Has::RESIZED) {
            (w, h) = terminal.size()?;
        }
        terminal.write_all(render(w, h, &mut tui, workspace, delta))?;
        delta = Has(0);

        {
            let ws = workspace.state();
            if let Some(sel) = tui.task_tree.selection_state(&ws) {
                tui.logs.update_selection(sel);
            }
        }

        match vtui::event::poll_with_custom_waker(&stdin, Some(&vtui_channel.waker), None)? {
            vtui::event::Polled::ReadReady => events.read_from(&stdin)?,
            vtui::event::Polled::Woken => {}
            vtui::event::Polled::TimedOut => {}
        }
        match vtui_channel.actions(&mut previous) {
            Some(Action::Resized) => delta |= Has::RESIZED,
            Some(Action::Terminated) => return Ok(()),
            None => (),
        }

        if vtui::event::polling::termination_requested() {
            return Ok(());
        }

        while let Some(event) = events.next(terminal.is_raw()) {
            match event {
                Event::Key(key_event) => {
                    if process_key(&mut tui, workspace, key_event) {
                        return Ok(());
                    }
                }
                Event::Resized => (),
                Event::Mouse(mouse) => {
                    let x = mouse.column;
                    let y = mouse.row;
                    let target = scroll_target(w, h, &tui, x, y);
                    println!("{} {} -> {:?}", x, y, target);
                    match mouse.kind {
                        vtui::event::MouseEventKind::ScrollDown => match target {
                            ScrollTarget::TopLog => tui.logs.pending_top_scroll -= 5,
                            ScrollTarget::BottomLog => tui.logs.pending_bottom_scroll -= 5,
                            ScrollTarget::TaskList => tui.task_tree.move_cursor_down(&workspace.state()),
                            ScrollTarget::JobList => tui.task_tree.move_cursor_down(&workspace.state()),
                            ScrollTarget::None => (),
                        },
                        vtui::event::MouseEventKind::ScrollUp => match target {
                            ScrollTarget::TopLog => tui.logs.pending_top_scroll += 5,
                            ScrollTarget::BottomLog => tui.logs.pending_bottom_scroll += 5,
                            ScrollTarget::TaskList => tui.task_tree.move_cursor_up(&workspace.state()),
                            ScrollTarget::JobList => tui.task_tree.move_cursor_up(&workspace.state()),
                            ScrollTarget::None => (),
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
