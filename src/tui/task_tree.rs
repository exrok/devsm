use extui::{Color, DoubleBuffer, HAlign, Rect};

use crate::{
    config::{Command, ServiceHidden, TaskKind},
    tui::constrain_scroll_offset,
    workspace::{BaseTaskIndex, JobIndex, JobStatus, WorkspaceState},
};

/// Represents a collapsible category for non-service tasks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MetaGroupKind {
    Tests,
    Actions,
}

impl MetaGroupKind {
    pub fn task_kind(self) -> TaskKind {
        match self {
            MetaGroupKind::Tests => TaskKind::Test,
            MetaGroupKind::Actions => TaskKind::Action,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            MetaGroupKind::Tests => "@tests",
            MetaGroupKind::Actions => "@actions",
        }
    }
}

/// An entry in the primary task list. In collapsed mode, tests and actions are
/// aggregated under meta-groups; in expanded mode, all base tasks are shown individually.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrimaryEntry {
    Task(BaseTaskIndex),
    MetaGroup(MetaGroupKind),
}

#[derive(Clone, Copy)]
enum StatusKind {
    Null,
    Wait,
    Live,
    Skip,
    Done,
    Dead,
    Fail,
}

impl StatusKind {
    fn of(status: &JobStatus, kind: TaskKind) -> StatusKind {
        use JobStatus::*;
        match status {
            Starting => StatusKind::Wait,
            Scheduled { .. } => StatusKind::Wait,
            Running { .. } => StatusKind::Live,
            Exited { status, .. } => {
                if *status == 0 {
                    match kind {
                        TaskKind::Service => StatusKind::Dead,
                        TaskKind::Action | TaskKind::Test => StatusKind::Done,
                    }
                } else {
                    StatusKind::Fail
                }
            }
            Cancelled => StatusKind::Skip,
        }
    }

    /// Returns a priority value for aggregating statuses.
    /// Higher priority means this status "wins" when aggregating.
    fn priority(self) -> u8 {
        match self {
            StatusKind::Null => 0,
            StatusKind::Skip => 1,
            StatusKind::Dead => 2,
            StatusKind::Done => 3,
            StatusKind::Wait => 4,
            StatusKind::Live => 5,
            StatusKind::Fail => 6,
        }
    }
    fn dark_bg(self) -> Color {
        use StatusKind::*;
        match self {
            Null => Color::Grey[17],
            Wait => Color::Violet,
            // Live => Color::SpringGreen,
            Live => Color::DarkOliveGreen,
            Skip => Color::LightGoldenrod2,
            Done => Color(110),
            // Dead => Color::LightGoldenrod2,
            Dead => Color(215),
            Fail => Color::NeonRed,
        }
    }
    fn light_bg(self) -> Color {
        use StatusKind::*;
        match self {
            Null => Color::Grey[22],
            Wait => Color::Thistle,
            Live => Color::LightSeaGreen,
            Skip => Color::Wheat1,
            Done => Color(153),
            Dead => Color(223),
            Fail => Color::MistyRose,
        }
    }
    fn padded_text(&self) -> &str {
        use StatusKind::*;
        match self {
            Null => " Null ",
            Wait => " Wait ",
            Live => " Live ",
            Skip => " Skip ",
            Done => " Done ",
            Fail => " Fail ",
            Dead => " Dead ",
        }
    }
}
pub struct TaskTreeState {
    /// Whether to show collapsed view (meta-groups) or expanded view (all tasks).
    collapsed: bool,
    /// The primary list entries (tasks or meta-groups).
    primary_list: Vec<PrimaryEntry>,
    change_number: u32,
    primary_index: usize,
    primary_scroll_offset: usize,
    /// The currently selected primary entry.
    selected_entry: Option<PrimaryEntry>,
    job_list_index: usize,
    job_list_scroll_offset: usize,
    job_index: Option<JobIndex>,
}

impl Default for TaskTreeState {
    fn default() -> Self {
        Self {
            collapsed: true,
            primary_list: Default::default(),
            change_number: u32::MAX,
            primary_index: Default::default(),
            selected_entry: Default::default(),
            job_list_index: Default::default(),
            primary_scroll_offset: Default::default(),
            job_list_scroll_offset: Default::default(),
            job_index: Default::default(),
        }
    }
}

/// Represents the current selection in the task tree.
///
/// When a specific task or job is selected, `base_task` contains the task index.
/// When a meta-group is selected without a specific job, `base_task` is `None`
/// and `meta_group` contains the group kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SelectionState {
    /// The selected base task. `None` when a meta-group is selected without a specific job.
    pub base_task: Option<BaseTaskIndex>,
    /// The selected job, if any.
    pub job: Option<JobIndex>,
    /// The selected meta-group, if any.
    pub meta_group: Option<MetaGroupKind>,
}

impl TaskTreeState {
    /// Toggles between collapsed and expanded view modes.
    pub fn toggle_collapsed(&mut self) {
        self.collapsed = !self.collapsed;
        self.change_number = u32::MAX; // Force rebuild of primary list
    }

    /// Returns whether the task tree is in collapsed mode.
    pub fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    fn normalize_secondary(&mut self, jobs: &[JobIndex]) -> Option<JobIndex> {
        let ji = self.job_index?;
        match jobs.get(self.job_list_index) {
            Some(i_ji) if *i_ji == ji => Some(ji),
            fallback => {
                for (i, job_ji) in jobs.iter().enumerate() {
                    if *job_ji == ji {
                        self.job_list_index = i;
                        return Some(ji);
                    }
                }
                if let Some(fallback) = fallback {
                    self.job_index = Some(*fallback);
                    self.job_list_index = jobs.iter().position(|j| j == fallback)?;
                    Some(*fallback)
                } else {
                    let last_ji = *jobs.last()?;
                    self.job_index = Some(last_ji);
                    self.job_list_index = jobs.len() - 1;
                    Some(last_ji)
                }
            }
        }
    }

    fn normalize_primary(&mut self) -> Option<PrimaryEntry> {
        let index_entry = self.primary_list.get(self.primary_index).copied();
        let initial_entry = self.selected_entry;
        let entry = match (index_entry, self.selected_entry) {
            (Some(index_entry), Some(current_entry)) if index_entry == current_entry => current_entry,
            (fallback, Some(current_entry)) => 'entry: {
                for (i, e) in self.primary_list.iter().enumerate() {
                    if *e == current_entry {
                        self.primary_index = i;
                        break 'entry current_entry;
                    }
                }
                if let Some(fallback) = fallback {
                    self.selected_entry = Some(fallback);
                    fallback
                } else {
                    let e = self.primary_list.last()?;
                    self.selected_entry = Some(*e);
                    *e
                }
            }
            (None, None) => {
                let e = self.primary_list.last()?;
                self.selected_entry = Some(*e);
                *e
            }
            (Some(index_entry), None) => {
                self.selected_entry = Some(index_entry);
                index_entry
            }
        };

        if initial_entry != Some(entry) {
            self.job_index = None;
            self.job_list_index = usize::MAX;
        }
        Some(entry)
    }

    fn rebuild_primary_list(&mut self, ws: &WorkspaceState) {
        self.primary_list.clear();

        if self.collapsed {
            for (i, bt) in ws.base_tasks.iter().enumerate() {
                if bt.removed {
                    continue;
                }
                if bt.config.kind == TaskKind::Service {
                    let should_display = match bt.config.hidden {
                        ServiceHidden::Never => true,
                        ServiceHidden::UntilRan => bt.has_run_this_session,
                    };
                    if should_display {
                        self.primary_list.push(PrimaryEntry::Task(BaseTaskIndex(i as u32)));
                    }
                }
            }

            let has_tests = ws.base_tasks.iter().any(|bt| !bt.removed && bt.config.kind == TaskKind::Test);
            let has_actions = ws.base_tasks.iter().any(|bt| !bt.removed && bt.config.kind == TaskKind::Action);

            if has_actions {
                self.primary_list.push(PrimaryEntry::MetaGroup(MetaGroupKind::Actions));
            }
            if has_tests {
                self.primary_list.push(PrimaryEntry::MetaGroup(MetaGroupKind::Tests));
            }
        } else {
            for (i, bt) in ws.base_tasks.iter().enumerate() {
                if bt.removed {
                    continue;
                }
                let should_display = match bt.config.kind {
                    TaskKind::Service => match bt.config.hidden {
                        ServiceHidden::Never => true,
                        ServiceHidden::UntilRan => bt.has_run_this_session,
                    },
                    TaskKind::Action | TaskKind::Test => true,
                };
                if should_display {
                    self.primary_list.push(PrimaryEntry::Task(BaseTaskIndex(i as u32)));
                }
            }
        }

        self.change_number = ws.change_number;
    }

    /// Normalizes the selection states preferring to keep the indices of the base task and
    /// job the same. Returns `None` if the filtered list of base tasks is empty.
    pub fn selection_state(&mut self, ws: &WorkspaceState) -> Option<SelectionState> {
        if self.change_number != ws.change_number {
            self.rebuild_primary_list(ws);
        }

        let entry = self.normalize_primary()?;
        match entry {
            PrimaryEntry::Task(bti) => {
                let job = self.normalize_secondary(ws.base_tasks[bti.idx()].jobs.all());
                Some(SelectionState { base_task: Some(bti), job, meta_group: None })
            }
            PrimaryEntry::MetaGroup(kind) => {
                let jobs = ws.jobs_by_kind(kind.task_kind());
                let job = self.normalize_secondary(jobs);
                let base_task = job.map(|ji| ws[ji].log_group.base_task_index());
                Some(SelectionState { base_task, job, meta_group: Some(kind) })
            }
        }
    }

    pub fn exit_secondary(&mut self) {
        self.job_index = None;
        self.job_list_index = usize::MAX;
    }

    pub fn enter_secondary(&mut self, ws: &WorkspaceState) {
        let entry = match self.normalize_primary() {
            Some(entry) => entry,
            None => return,
        };
        let jobs = self.get_job_list(ws, entry);
        let Some(last) = jobs.last() else {
            return;
        };
        self.job_list_index = jobs.len() - 1;
        self.job_index = Some(*last);
    }

    fn get_job_list<'a>(&self, ws: &'a WorkspaceState, entry: PrimaryEntry) -> &'a [JobIndex] {
        match entry {
            PrimaryEntry::Task(bti) => ws.base_tasks[bti.idx()].jobs.all(),
            PrimaryEntry::MetaGroup(kind) => ws.jobs_by_kind(kind.task_kind()),
        }
    }

    pub fn move_cursor_down(&mut self, ws: &WorkspaceState) {
        if self.job_index.is_some() {
            // Note since we always render the job list in reverse
            // moving the cursor down, looks more like moving the cursor up
            if self.job_list_index == 0 {
                return;
            }
            let jli = self.job_list_index - 1;
            self.job_list_index = jli;
            let entry = match self.normalize_primary() {
                Some(entry) => entry,
                None => return,
            };
            let jobs = self.get_job_list(ws, entry);
            self.job_index = Some(jobs[jli]);
        } else {
            if self.primary_index + 1 >= self.primary_list.len() {
                return;
            }
            let pti = self.primary_index + 1;
            self.primary_index = pti;
            self.selected_entry = Some(self.primary_list[pti]);
        }
    }

    pub fn move_cursor_up(&mut self, ws: &WorkspaceState) {
        if self.job_index.is_some() {
            // Note since we always render the job list in reverse
            // moving the cursor up, looks more like moving the cursor down
            let entry = match self.normalize_primary() {
                Some(entry) => entry,
                None => return,
            };
            let jobs = self.get_job_list(ws, entry);
            if self.job_list_index + 1 >= jobs.len() {
                return;
            }
            let jli = self.job_list_index + 1;
            self.job_list_index = jli;
            self.job_index = Some(jobs[jli]);
        } else {
            if self.primary_index == 0 {
                return;
            }
            let pti = self.primary_index - 1;
            self.primary_index = pti;
            self.selected_entry = Some(self.primary_list[pti]);
        }
    }

    fn is_entry_selected(&self, entry: PrimaryEntry, sel: &SelectionState) -> bool {
        match entry {
            PrimaryEntry::Task(bti) => sel.base_task == Some(bti) && sel.meta_group.is_none(),
            PrimaryEntry::MetaGroup(kind) => sel.meta_group == Some(kind),
        }
    }

    /// Computes the aggregated status for a meta-group (worst status among all jobs of that kind).
    fn meta_group_status(&self, ws: &WorkspaceState, kind: MetaGroupKind) -> StatusKind {
        let task_kind = kind.task_kind();
        let mut worst = StatusKind::Null;
        for bt in &ws.base_tasks {
            if bt.removed || bt.config.kind != task_kind {
                continue;
            }
            for ji in bt.jobs.all() {
                let status = StatusKind::of(&ws[*ji].process_status, task_kind);
                // Priority: Fail > Live > Wait > Done > Dead > Skip > Null
                if status.priority() > worst.priority() {
                    worst = status;
                }
            }
        }
        worst
    }

    /// Counts running and scheduled jobs across all tasks of the given kind.
    fn meta_group_counts(&self, ws: &WorkspaceState, kind: MetaGroupKind) -> (usize, usize) {
        let task_kind = kind.task_kind();
        let mut running = 0;
        let mut scheduled = 0;
        for bt in &ws.base_tasks {
            if bt.removed || bt.config.kind != task_kind {
                continue;
            }
            running += bt.jobs.running().len();
            scheduled += bt.jobs.scheduled().len();
        }
        (running, scheduled)
    }

    pub fn render_primary(&mut self, out: &mut DoubleBuffer, mut rect: Rect, ws: &WorkspaceState) {
        let sel = match self.selection_state(ws) {
            Some(sel) => sel,
            None => return,
        };
        self.primary_scroll_offset = constrain_scroll_offset(
            rect.h as usize,
            self.primary_index,
            self.primary_scroll_offset,
            self.primary_list.len(),
        );
        for &entry in &self.primary_list[self.primary_scroll_offset..] {
            let mut line = rect.take_top(1);
            if line.is_empty() {
                break;
            }

            let is_selected = self.is_entry_selected(entry, &sel);

            match entry {
                PrimaryEntry::Task(task_id) => {
                    let task = &ws.base_tasks[task_id.idx()];
                    let status = task
                        .jobs
                        .all()
                        .last()
                        .map(|job| StatusKind::of(&ws[*job].process_status, task.config.kind))
                        .unwrap_or(StatusKind::Null);

                    line.take_left(6)
                        .with(if is_selected {
                            status.dark_bg().with_fg(Color::Black)
                        } else {
                            status.dark_bg().with_bg(Color::Grey[4])
                        })
                        .text(out, status.padded_text());

                    line.with(if is_selected { status.light_bg().with_fg(Color(236)) } else { Color(248).as_fg() })
                        .fill(out)
                        .skip(1)
                        .fmt(
                            out,
                            format_args!(
                                "{} R:{} S:{}",
                                task.name,
                                task.jobs.running().len(),
                                task.jobs.scheduled().len()
                            ),
                        );
                }
                PrimaryEntry::MetaGroup(kind) => {
                    let status = self.meta_group_status(ws, kind);
                    let (running, scheduled) = self.meta_group_counts(ws, kind);

                    line.take_left(6)
                        .with(if is_selected {
                            status.dark_bg().with_fg(Color::Black)
                        } else {
                            status.dark_bg().with_bg(Color::Grey[4])
                        })
                        .text(out, status.padded_text());

                    line.with(if is_selected { status.light_bg().with_fg(Color(236)) } else { Color(248).as_fg() })
                        .fill(out)
                        .skip(1)
                        .fmt(out, format_args!("{} R:{} S:{}", kind.display_name(), running, scheduled));
                }
            }
        }
    }

    pub fn render_secondary(&mut self, out: &mut DoubleBuffer, mut rect: Rect, ws: &WorkspaceState) {
        let now = std::time::Instant::now();
        let sel = match self.selection_state(ws) {
            Some(sel) => sel,
            None => return,
        };

        let (jobs, show_task_name): (&[JobIndex], bool) = match (sel.base_task, sel.meta_group) {
            (Some(bti), None) => (ws.base_tasks[bti.idx()].jobs.all(), false),
            (_, Some(kind)) => (ws.jobs_by_kind(kind.task_kind()), true),
            (None, None) => return,
        };

        if self.job_index.is_some() {
            self.job_list_scroll_offset = constrain_scroll_offset(
                rect.h as usize,
                (jobs.len() - self.job_list_index).saturating_sub(1),
                self.job_list_scroll_offset,
                jobs.len(),
            );
        } else {
            self.job_list_scroll_offset = 0;
        }

        for &ji in jobs.iter().rev().skip(self.job_list_scroll_offset) {
            let mut line = rect.take_top(1);
            if line.is_empty() {
                break;
            }
            let job = &ws[ji];
            let bti = job.log_group.base_task_index();
            let bt = &ws.base_tasks[bti.idx()];

            let command = match &job.task.config().command {
                Command::Cmd(args) => args.join(" "),
                Command::Sh(script) => {
                    let prefix = if script.len() > 50 { format!("{}...", &script[..50]) } else { script.to_string() };
                    format!("sh: {}", prefix)
                }
            };

            let display_text = if show_task_name { format!("{}: {}", bt.name, command) } else { command };

            let status = StatusKind::of(&job.process_status, bt.config.kind);
            line.take_left(6)
                .with(if Some(ji) == sel.job {
                    status.dark_bg().with_fg(Color::Black)
                } else {
                    status.dark_bg().with_bg(Color::Grey[4])
                })
                .text(out, status.padded_text());
            let rem = line
                .with(if Some(ji) == sel.job { status.light_bg().with_fg(Color(236)) } else { Color(248).as_fg() })
                .fill(out)
                .skip(1)
                .text(out, &display_text)
                .skip(1)
                .with(HAlign::Right);

            match &job.process_status {
                JobStatus::Exited { finished_at, .. } => {
                    let elapsed = finished_at.saturating_duration_since(job.started_at);
                    rem.fmt(out, format_args!("{:.0?} ", elapsed));
                }
                JobStatus::Cancelled => (),
                _ => {
                    let elapsed = now.saturating_duration_since(job.started_at);
                    rem.fmt(out, format_args!("{:.0?} ", elapsed));
                }
            };
        }
    }
}
