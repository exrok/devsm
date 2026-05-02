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

#[derive(Debug)]
pub struct TraceReport {
    pub events: Vec<PathEvent>,
    pub root_pid: i32,
    pub exit_status: ExitStatus,
    pub truncated: bool,
}
