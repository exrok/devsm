use extui::{AnsiColor, DoubleBuffer, Rect};

use crate::keybinds::{BindingEntry, Command, Keybinds, Mode};
use crate::tui::task_tree::{MetaGroupKind, SelectionState};

pub struct ShortcutEntry {
    pub key: String,
    pub label: &'static str,
}

impl ShortcutEntry {
    fn width(&self) -> usize {
        self.key.len() + 1 + self.label.len()
    }
}

pub fn render_shortcut_bar(frame: &mut DoubleBuffer, rect: Rect, entries: &[ShortcutEntry]) {
    let bar_bg = AnsiColor::Grey[3].with_fg(AnsiColor::Grey[3]);
    let key_style = AnsiColor::Grey[3].with_fg(AnsiColor::Grey[15]);
    let label_style = AnsiColor::Grey[3].with_fg(AnsiColor::Grey[9]);

    rect.with(bar_bg).fill(frame);

    let available = rect.w as usize;
    let mut used = 0;
    let mut r = rect.with(key_style);

    for entry in entries {
        let needed = 2 + entry.width();
        if used + needed > available {
            break;
        }
        r = r.with(key_style).text(frame, "  ");
        r = r.text(frame, &entry.key);
        r = r.with(label_style).text(frame, " ");
        r = r.text(frame, entry.label);
        used += needed;
    }
}

fn push_entries(
    entries: &mut Vec<ShortcutEntry>,
    keybinds: &Keybinds,
    mode: Mode,
    commands: &[(&Command, &'static str)],
) {
    for &(command, label) in commands {
        if let Some(key) = keybinds.key_for_command_in_mode(mode, command) {
            entries.push(ShortcutEntry { key: key.to_string(), label });
        }
    }
}

pub fn build_shortcut_entries(
    keybinds: &Keybinds,
    mode: Mode,
    chain_idx: Option<u32>,
    selection: Option<&SelectionState>,
    is_scrolled: bool,
    task_tree_hidden: bool,
) -> Vec<ShortcutEntry> {
    let mut entries = Vec::with_capacity(12);

    if let Some(group) = chain_idx.and_then(|idx| keybinds.chain(idx)) {
        for (input, entry) in &group.bindings {
            let label = match entry {
                BindingEntry::Command(cmd) => cmd.display_name(),
                BindingEntry::Chain(_) => "...",
            };
            entries.push(ShortcutEntry { key: input.to_string(), label });
        }
        return entries;
    }

    let m = mode;
    match mode {
        Mode::TaskTree | Mode::Global => {
            if task_tree_hidden {
                push_entries(&mut entries, keybinds, m, &[
                    (&Command::ToggleTaskTree, "Tasks"),
                    (&Command::SearchLogs, "Search"),
                    (&Command::LogModeAll, "All"),
                    (&Command::LogModeSelected, "Sel"),
                    (&Command::LogModeHybrid, "Hyb"),
                    (&Command::Quit, "Quit"),
                    (&Command::ToggleHelp, "Help"),
                ]);
            } else if is_scrolled {
                push_entries(&mut entries, keybinds, m, &[
                    (&Command::JumpToNewestLogs, "Newest"),
                    (&Command::JumpToOldestLogs, "Oldest"),
                    (&Command::LogScrollUp, "Up"),
                    (&Command::LogScrollDown, "Down"),
                    (&Command::SearchLogs, "Search"),
                ]);
                if selection.is_some_and(|s| s.base_task.is_some()) {
                    push_entries(&mut entries, keybinds, m, &[
                        (&Command::RestartTask, "Restart Selected"),
                    ]);
                }
                push_entries(&mut entries, keybinds, m, &[
                    (&Command::Quit, "Quit"),
                    (&Command::ToggleHelp, "Help"),
                ]);
            } else {
                let is_test_meta = selection.is_some_and(|s| s.meta_group == Some(MetaGroupKind::Tests));
                let is_action_meta = selection.is_some_and(|s| s.meta_group == Some(MetaGroupKind::Actions));
                let in_secondary = selection.is_some_and(|s| s.job.is_some());

                if is_test_meta {
                    push_entries(&mut entries, keybinds, m, &[
                        (&Command::LaunchTestFilter, "Filter"),
                        (&Command::RerunTestGroup, "Rerun"),
                        (&Command::NarrowTestGroup, "Narrow"),
                        (&Command::NextFailInTestGroup, "Next Fail"),
                    ]);
                } else if is_action_meta {
                    push_entries(&mut entries, keybinds, m, &[
                        (&Command::StartSelection, "Start Selected"),
                        (&Command::LaunchTask, "Task Launcher"),
                        (&Command::StartGroup, "Group Launcher"),
                    ]);
                } else if in_secondary {
                    push_entries(&mut entries, keybinds, m, &[
                        (&Command::RestartTask, "Restart Selected"),
                        (&Command::TerminateTask, "Kill Selected"),
                        (&Command::FocusPrimary, "Tasks"),
                    ]);
                } else {
                    push_entries(&mut entries, keybinds, m, &[
                        (&Command::RestartTask, "Restart Selected"),
                        (&Command::TerminateTask, "Kill Selected"),
                        (&Command::LaunchTask, "Task Launcher"),
                        (&Command::StartSelection, "Start Selected"),
                        (&Command::StartGroup, "Group Launcher"),
                        (&Command::LogModeAll, "All"),
                        (&Command::LogModeSelected, "Sel"),
                        (&Command::LogModeHybrid, "Hyb"),
                    ]);
                }
                push_entries(&mut entries, keybinds, m, &[
                    (&Command::SearchLogs, "Search"),
                    (&Command::Quit, "Quit"),
                    (&Command::ToggleHelp, "Help"),
                ]);
            }
        }
        Mode::LogSearch | Mode::SelectSearch | Mode::TaskLauncher
        | Mode::TestFilterLauncher | Mode::Input => {
            push_entries(&mut entries, keybinds, m, &[
                (&Command::OverlayCancel, "Cancel"),
                (&Command::OverlayConfirm, "Confirm"),
                (&Command::SelectPrev, "Prev"),
                (&Command::SelectNext, "Next"),
                (&Command::Quit, "Quit"),
            ]);
        }
        Mode::Pager => {
            push_entries(&mut entries, keybinds, m, &[
                (&Command::SelectPrev, "Up"),
                (&Command::SelectNext, "Down"),
                (&Command::JumpToOldestLogs, "Top"),
                (&Command::JumpToNewestLogs, "Bottom"),
                (&Command::Quit, "Quit"),
                (&Command::ToggleHelp, "Help"),
            ]);
        }
    }

    entries
}
