//! JSON-serializable form of a trace, used as a fixture format for
//! inference tests and as the on-disk format for the
//! `auto_dep_record` / `auto_dep_replay` example binaries.
//!
//! `ExitStatus` and the per-syscall histogram are dropped on the way
//! down: inference doesn't read them, and they're not portable across
//! machines.

use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use jsony::Jsony;

use super::event::{PathEvent, PathEventKind, TraceReport, TraceStatsSnapshot};

#[derive(Jsony, Debug, Clone, Copy, PartialEq, Eq)]
#[jsony(ToJson, FromJson)]
pub enum RecordedKind {
    Read,
    Write,
    Stat,
    ListDir,
    Exec,
    Unlink,
    Mkdir,
    ReadLink,
}

impl From<PathEventKind> for RecordedKind {
    fn from(k: PathEventKind) -> Self {
        match k {
            PathEventKind::Read => RecordedKind::Read,
            PathEventKind::Write => RecordedKind::Write,
            PathEventKind::Stat => RecordedKind::Stat,
            PathEventKind::ListDir => RecordedKind::ListDir,
            PathEventKind::Exec => RecordedKind::Exec,
            PathEventKind::Unlink => RecordedKind::Unlink,
            PathEventKind::Mkdir => RecordedKind::Mkdir,
            PathEventKind::ReadLink => RecordedKind::ReadLink,
        }
    }
}

impl From<RecordedKind> for PathEventKind {
    fn from(k: RecordedKind) -> Self {
        match k {
            RecordedKind::Read => PathEventKind::Read,
            RecordedKind::Write => PathEventKind::Write,
            RecordedKind::Stat => PathEventKind::Stat,
            RecordedKind::ListDir => PathEventKind::ListDir,
            RecordedKind::Exec => PathEventKind::Exec,
            RecordedKind::Unlink => PathEventKind::Unlink,
            RecordedKind::Mkdir => PathEventKind::Mkdir,
            RecordedKind::ReadLink => PathEventKind::ReadLink,
        }
    }
}

#[derive(Jsony, Debug, Clone)]
#[jsony(ToJson, FromJson)]
pub struct RecordedEvent {
    pub kind: RecordedKind,
    pub path: String,
    pub pid: i32,
    pub seq: u64,
}

/// Portable, on-disk form of a [`TraceReport`].
///
/// `project_root` is captured so the replay tool can re-run inference
/// without the caller having to remember it. Paths inside `events` stay
/// absolute, the same way the live tracer emits them.
#[derive(Jsony, Debug, Clone)]
#[jsony(ToJson, FromJson)]
pub struct RecordedTrace {
    pub project_root: String,
    pub root_pid: i32,
    pub exit_code: i32,
    pub truncated: bool,
    pub events: Vec<RecordedEvent>,
}

impl RecordedTrace {
    /// Rewrite `project_root` and every event path so the trace
    /// behaves as if it were captured against `new_root`. The original
    /// project root is stripped from each event path and `new_root` is
    /// joined back on; events whose path doesn't sit under the original
    /// root pass through unchanged.
    ///
    /// This is the seam fixture-based tests use to make recorded
    /// traces portable across machines: the events were captured with
    /// absolute paths under `/some/dev/box/repo`, and the test rebases
    /// them onto `CARGO_MANIFEST_DIR` so `path.exists()` checks inside
    /// inference resolve against the live checkout.
    pub fn rebase(mut self, new_root: &Path) -> Self {
        let old_root = PathBuf::from(&self.project_root);
        let new_root_str = new_root.to_string_lossy().into_owned();
        for ev in &mut self.events {
            let p = Path::new(&ev.path);
            if let Ok(rel) = p.strip_prefix(&old_root) {
                let mut joined = new_root.to_path_buf();
                joined.push(rel);
                ev.path = joined.to_string_lossy().into_owned();
            }
        }
        self.project_root = new_root_str;
        self
    }

    pub fn from_report(report: &TraceReport, project_root: &Path) -> Self {
        let events = report
            .events
            .iter()
            .map(|e| RecordedEvent {
                kind: e.kind.into(),
                path: e.path.to_string_lossy().into_owned(),
                pid: e.pid,
                seq: e.seq,
            })
            .collect();
        Self {
            project_root: project_root.to_string_lossy().into_owned(),
            root_pid: report.root_pid,
            exit_code: report.exit_status.code().unwrap_or(0),
            truncated: report.truncated,
            events,
        }
    }

    pub fn project_root_path(&self) -> PathBuf {
        PathBuf::from(&self.project_root)
    }

    pub fn into_report(self) -> TraceReport {
        let events = self
            .events
            .into_iter()
            .map(|e| PathEvent {
                kind: e.kind.into(),
                path: PathBuf::from(e.path),
                pid: e.pid,
                seq: e.seq,
            })
            .collect();
        TraceReport {
            events,
            root_pid: self.root_pid,
            exit_status: synthetic_exit_status(self.exit_code),
            truncated: self.truncated,
            stats: TraceStatsSnapshot::default(),
        }
    }
}

/// Replays don't have a real `wait4` status to surface, so synthesize
/// one from the recorded exit code. The inference pass ignores
/// `exit_status` outright; this is here purely so the public type
/// stays whole.
fn synthetic_exit_status(_code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}
