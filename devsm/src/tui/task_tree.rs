use vtui::{Color, DoubleBuffer, HAlign, Rect};

use crate::{
    config::{Command, TaskKind},
    tui::constrain_scroll_offset,
    workspace::{BaseTaskIndex, JobIndex, JobStatus, WorkspaceState},
};

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
    primary_list: Vec<BaseTaskIndex>,
    change_number: u32,
    primary_index: usize,
    primary_scroll_offset: usize,
    base_task_index: Option<BaseTaskIndex>,
    job_list_index: usize,
    job_list_scroll_offset: usize,
    job_index: Option<JobIndex>,
}

impl Default for TaskTreeState {
    fn default() -> Self {
        Self {
            primary_list: Default::default(),
            change_number: u32::MAX,
            primary_index: Default::default(),
            base_task_index: Default::default(),
            job_list_index: Default::default(),
            primary_scroll_offset: Default::default(),
            job_list_scroll_offset: Default::default(),
            job_index: Default::default(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SelectionState {
    pub base_task: BaseTaskIndex,
    pub job: Option<JobIndex>,
}

impl TaskTreeState {
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
    fn normalize_primary(&mut self) -> Option<BaseTaskIndex> {
        let index_bti = self.primary_list.get(self.primary_index).copied();
        let initial_bti = self.base_task_index;
        let bti = match (index_bti, self.base_task_index) {
            (Some(index_bti), Some(current_bti)) if index_bti == current_bti => current_bti,
            (fallback, Some(current_bti)) => 'bti: {
                for (i, bti) in self.primary_list.iter().enumerate() {
                    if *bti == current_bti {
                        self.primary_index = i;
                        break 'bti current_bti;
                    }
                }
                if let Some(fallback) = fallback {
                    self.base_task_index = Some(fallback);
                    fallback
                } else {
                    let bti = self.primary_list.last()?;
                    self.base_task_index = Some(*bti);
                    *bti
                }
            }
            (None, None) => {
                let bti = self.primary_list.last()?;
                self.base_task_index = Some(*bti);
                *bti
            }
            (Some(index_bti), None) => {
                self.base_task_index = Some(index_bti);
                index_bti
            }
        };

        if initial_bti != Some(bti) {
            self.job_index = None;
            self.job_list_index = usize::MAX;
        }
        Some(bti)
    }
    /// normalizes the selection states perfering to keep the indices of the base task and
    /// job the same. Will only return None, if the filtered list of base tasks is empty.
    pub fn selection_state(&mut self, ws: &WorkspaceState) -> Option<SelectionState> {
        if self.change_number != ws.change_number {
            // In the future, we'll do filtering and sorting here.
            self.primary_list = ws.base_tasks.iter().enumerate().map(|(i, _)| BaseTaskIndex(i as u32)).collect();
            self.change_number = ws.change_number;
        }

        let bti = self.normalize_primary()?;
        Some(SelectionState { base_task: bti, job: self.normalize_secondary(&ws.base_tasks[bti.idx()].jobs.all()) })
    }
    pub fn exit_secondary(&mut self) {
        self.job_index = None;
        self.job_list_index = usize::MAX;
    }
    pub fn enter_secondary(&mut self, ws: &WorkspaceState) {
        let bti = match self.normalize_primary() {
            Some(bti) => bti,
            None => return,
        };
        let jobs = &ws.base_tasks[bti.idx()].jobs.all();
        let Some(last) = jobs.last() else {
            return;
        };
        self.job_list_index = jobs.len() - 1;
        self.job_index = Some(*last);
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
            let bti = match self.normalize_primary() {
                Some(bti) => bti,
                None => return,
            };
            let jobs = &ws.base_tasks[bti.idx()].jobs.all();
            self.job_index = Some(jobs[jli]);
        } else {
            if self.primary_index + 1 >= self.primary_list.len() {
                return;
            }
            let pti = self.primary_index + 1;
            self.primary_index = pti;
            self.base_task_index = Some(self.primary_list[pti]);
        }
    }
    pub fn move_cursor_up(&mut self, ws: &WorkspaceState) {
        if self.job_index.is_some() {
            // Note since we always render the job list in reverse
            // moving the cursor up, looks more like moving the cursor down

            let bti = match self.normalize_primary() {
                Some(bti) => bti,
                None => return,
            };
            let jobs = &ws.base_tasks[bti.idx()].jobs.all();
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
            self.base_task_index = Some(self.primary_list[pti]);
        }
    }

    pub fn render_primary(&mut self, out: &mut DoubleBuffer, mut rect: Rect, ws: &WorkspaceState) {
        let sel = match self.selection_state(ws) {
            Some(sel) => sel,
            None => return,
        };
        self.primary_scroll_offset =
            constrain_scroll_offset(rect.h as usize, self.primary_index, self.primary_scroll_offset);
        for &task_id in &self.primary_list[self.primary_scroll_offset..] {
            let mut line = rect.take_top(1);
            if line.is_empty() {
                break;
            }
            let task = &ws.base_tasks[task_id.idx()];
            let status = task
                .jobs
                .all()
                .last()
                .map(|job| StatusKind::of(&ws[*job].process_status, task.config.kind))
                .unwrap_or(StatusKind::Null);

            line.take_left(6)
                .with(if task_id == sel.base_task {
                    status.dark_bg().with_fg(Color::Black)
                } else {
                    status.dark_bg().with_bg(Color::Grey[4])
                })
                .text(out, status.padded_text());

            line.with(if task_id == sel.base_task {
                status.light_bg().with_fg(Color(236))
            } else {
                Color(248).as_fg()
            })
            .fill(out)
            .skip(1)
            .fmt(out, format_args!("{} R:{} S:{}", task.name, task.jobs.running().len(), task.jobs.scheduled().len()));
        }
    }
    pub fn render_secondary(&mut self, out: &mut DoubleBuffer, mut rect: Rect, ws: &WorkspaceState) {
        let now = std::time::Instant::now();
        let sel = match self.selection_state(ws) {
            Some(sel) => sel,
            None => return,
        };
        let bt = &ws.base_tasks[sel.base_task.idx()];
        let jobs = bt.jobs.all();
        if self.job_index.is_some() {
            self.job_list_scroll_offset = constrain_scroll_offset(
                rect.h as usize,
                (jobs.len() - self.job_list_index).saturating_sub(1),
                self.job_list_scroll_offset,
            );
        } else {
            self.job_list_scroll_offset = 0;
        }
        for &ji in bt.jobs.all().iter().rev().skip(self.job_list_scroll_offset) {
            let mut line = rect.take_top(1);
            if line.is_empty() {
                break;
            }
            let job = &ws[ji];
            let command = match &job.task.config().command {
                Command::Cmd(args) => args.join(" "),
                Command::Sh(script) => {
                    // Show "sh: " followed by a prefix of the script
                    let prefix = if script.len() > 50 { format!("{}...", &script[..50]) } else { script.to_string() };
                    format!("sh: {}", prefix)
                }
            };
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
                .text(out, &command)
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
