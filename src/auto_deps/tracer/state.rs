use crate::auto_deps::tracer::syscalls::Effect;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FdEntry {
    pub path: PathBuf,
    pub opened_write: bool,
    pub cloexec: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Stage {
    AwaitingEntry,
    InsideSyscall,
}

#[derive(Debug, Clone)]
pub struct PendingSyscall {
    pub effect: Effect,
    pub args: [u64; 6],
    pub resolved_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct TraceeState {
    pub stage: Stage,
    pub cwd: PathBuf,
    pub fds: HashMap<i32, FdEntry>,
    pub pending: Option<PendingSyscall>,
}

impl TraceeState {
    pub fn new(cwd: PathBuf) -> Self {
        Self { stage: Stage::AwaitingEntry, cwd, fds: HashMap::new(), pending: None }
    }
}
