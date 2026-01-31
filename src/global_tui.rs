use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use extui::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use extui::{Color, DoubleBuffer, HAlign, Rect, Style, TerminalFlags, vt};

use crate::db::Db;
use crate::searcher::{Entry, FatSearch};
use crate::tui::constrain_scroll_offset;

struct WorkspaceItem {
    config_path: PathBuf,
    display: String,
}

pub enum Selection {
    Workspace(PathBuf),
    Quit,
}

pub fn run(stdin: File, stdout: File) -> anyhow::Result<Selection> {
    let db = Db::open();
    let records = db.workspaces();
    drop(db);

    let items: Vec<WorkspaceItem> = records
        .into_iter()
        .filter(|r| std::path::Path::new(&r.config_path).exists())
        .map(|r| {
            let display = r.config_path.strip_suffix("/devsm.toml").unwrap_or(&r.config_path).to_owned();
            WorkspaceItem { config_path: PathBuf::from(&r.config_path), display }
        })
        .collect();

    if items.is_empty() {
        anyhow::bail!("No known workspaces. Run devsm from a directory containing devsm.toml first.");
    }

    let mut searcher = FatSearch::default();
    for item in &items {
        searcher.insert(&item.display);
    }

    let mode = TerminalFlags::RAW_MODE
        | TerminalFlags::ALT_SCREEN
        | TerminalFlags::HIDE_CURSOR
        | TerminalFlags::EXTENDED_KEYBOARD_INPUTS;
    let mut terminal = extui::Terminal::new(stdout.as_raw_fd(), mode)?;
    terminal.write_all(&[vt::MOVE_CURSOR_TO_ORIGIN, vt::CLEAR_BELOW].concat())?;
    let (w, h) = terminal.size()?;

    let mut pattern = String::new();
    let mut cursor: usize = 0;
    let mut results: Vec<Entry> = Vec::new();
    let mut selected: usize = 0;
    let mut scroll_offset: usize = 0;
    let mut needs_query = true;
    let mut frame = DoubleBuffer::new(w, h);
    let mut events = extui::event::Events::default();

    loop {
        if needs_query {
            searcher.query(&pattern, &mut results);
            selected = selected.min(results.len().saturating_sub(1));
            scroll_offset = 0;
            needs_query = false;
        }

        let (new_w, new_h) = terminal.size()?;
        if new_w != frame.width() || new_h != frame.height() {
            frame = DoubleBuffer::new(new_w, new_h);
        }

        render(&mut frame, &pattern, cursor, &results, selected, scroll_offset, &items);
        frame.render(&mut terminal);

        match extui::event::poll_with_custom_waker(&stdin, None, None)? {
            extui::event::Polled::ReadReady => events.read_from(&stdin)?,
            _ => continue,
        }

        while let Some(event) = events.next(true) {
            match event {
                Event::Key(key) => {
                    match process_key(key, &mut pattern, &mut cursor, &mut selected, &results, &mut needs_query) {
                        KeyResult::None => {}
                        KeyResult::Quit => return Ok(Selection::Quit),
                        KeyResult::Enter => {
                            if let Some(entry) = results.get(selected) {
                                let item = &items[entry.index()];
                                return Ok(Selection::Workspace(item.config_path.clone()));
                            }
                        }
                    }
                }
                Event::Resized => {
                    let (rw, rh) = terminal.size()?;
                    if rw != frame.width() || rh != frame.height() {
                        frame = DoubleBuffer::new(rw, rh);
                    }
                }
                _ => {}
            }
        }

        scroll_offset =
            constrain_scroll_offset(frame.height().saturating_sub(2) as usize, selected, scroll_offset, results.len());
    }
}

enum KeyResult {
    None,
    Quit,
    Enter,
}

fn process_key(
    key: KeyEvent,
    pattern: &mut String,
    cursor: &mut usize,
    selected: &mut usize,
    results: &[Entry],
    needs_query: &mut bool,
) -> KeyResult {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') => return KeyResult::Quit,
            KeyCode::Char('l') => return KeyResult::Enter,
            KeyCode::Char('n') | KeyCode::Char('j') => {
                if *selected + 1 < results.len() {
                    *selected += 1;
                }
                return KeyResult::None;
            }
            KeyCode::Char('p') | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
                return KeyResult::None;
            }
            KeyCode::Char('u') => {
                pattern.clear();
                *cursor = 0;
                *needs_query = true;
                return KeyResult::None;
            }
            _ => return KeyResult::None,
        }
    }

    match key.code {
        KeyCode::Esc => KeyResult::Quit,
        KeyCode::Enter => KeyResult::Enter,
        KeyCode::Up => {
            *selected = selected.saturating_sub(1);
            KeyResult::None
        }
        KeyCode::Down => {
            if *selected + 1 < results.len() {
                *selected += 1;
            }
            KeyResult::None
        }
        KeyCode::Backspace => {
            if *cursor != 0 {
                pattern.remove(*cursor - 1);
                *cursor -= 1;
                *needs_query = true;
            }
            KeyResult::None
        }
        KeyCode::Char(ch) => {
            let len = pattern.len();
            pattern.insert(*cursor, ch);
            *cursor += pattern.len() - len;
            *needs_query = true;
            KeyResult::None
        }
        _ => KeyResult::None,
    }
}

fn render(
    frame: &mut DoubleBuffer,
    pattern: &str,
    cursor: usize,
    results: &[Entry],
    selected: usize,
    scroll_offset: usize,
    items: &[WorkspaceItem],
) {
    let label_style = Color::Grey[16].as_fg();
    let dim_style = Color::Grey[10].as_fg();

    let mut rect = frame.rect();
    rect.with(Style::DEFAULT).fill(frame);

    let label = "workspaces> ";
    let input_rect = rect.take_top(1);
    input_rect
        .with(label_style)
        .text(frame, label)
        .with(Style::DEFAULT)
        .text(frame, pattern)
        .with(HAlign::Right)
        .with(dim_style)
        .fmt(frame, format_args!(" {}/{} ", results.len(), items.len()));

    let cursor_rect = Rect {
        x: input_rect.x + label.len() as u16 + unicode_width::UnicodeWidthStr::width(&pattern[..cursor]) as u16,
        w: 1,
        ..input_rect
    };
    cursor_rect.with(Color::Grey[28].with_fg(Color::Grey[2])).fill(frame);

    if results.is_empty() {
        let msg = if pattern.is_empty() { "No workspaces found" } else { "No matches" };
        rect.take_top(1).with(dim_style).text(frame, msg);
        return;
    }

    for (i, entry) in results.iter().enumerate().skip(scroll_offset) {
        let row = rect.take_top(1);
        if row.is_empty() {
            break;
        }

        let item = &items[entry.index()];
        let is_selected = i == selected;
        let style = if is_selected { Color(153).with_fg(Color::Black) } else { Style::DEFAULT };
        if is_selected {
            row.with(style).fill(frame);
        }
        row.with(style).text(frame, &item.display);
    }
}
