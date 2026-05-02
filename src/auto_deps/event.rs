use std::path::PathBuf;
use std::process::ExitStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathEventKind {
    Read,
    Write,
    Stat,
    ListDir,
    Exec,
    Unlink,
    Mkdir,
    ReadLink,
}

#[derive(Debug, Clone)]
pub struct PathEvent {
    pub kind: PathEventKind,
    pub path: PathBuf,
    pub pid: i32,
    pub seq: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TraceStatsSnapshot {
    pub status_total: u64,
    pub syscall_stops: u64,
    pub event_stops: u64,
    pub signal_stops: u64,
    pub exit_stops: u64,
    pub get_syscall_info_calls: u64,
    pub resume_calls: u64,
    pub read_cstr_calls: u64,
    pub fork_clones: u64,
}

#[derive(Debug)]
pub struct TraceReport {
    pub events: Vec<PathEvent>,
    pub root_pid: i32,
    pub exit_status: ExitStatus,
    pub truncated: bool,
    pub stats: TraceStatsSnapshot,
}
