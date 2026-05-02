//! Automatic file-dependency discovery.
//!
//! Two layers:
//! - [`trace_command`] runs a child process under ptrace and records every
//!   filesystem syscall it makes (and those of its descendants).
//! - [`infer`] reduces the raw event stream to a minimal set of input
//!   dependencies, applying language/framework heuristics.
//!
//! Linux-only; non-Linux targets get a stub that returns an error.

#![allow(dead_code, unused_imports)]

#[path = "auto_deps/event.rs"]
mod event;
#[path = "auto_deps/inference.rs"]
mod inference;
#[path = "auto_deps/tracer.rs"]
mod tracer;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub use event::{PathEvent, PathEventKind, TraceReport};
pub use inference::{FrameworkSignal, InferredDeps, InferredPath};
#[cfg(target_os = "linux")]
pub use tracer::{Tracer, install_ptrace_traceme};

#[derive(Debug, Clone)]
pub struct TraceOptions {
    /// Hard cap on the number of events recorded. When exceeded, the tracer
    /// detaches and returns a report with `truncated = true`.
    pub max_events: usize,
    pub timeout: Option<Duration>,
    pub follow_forks: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self { max_events: 1_000_000, timeout: None, follow_forks: true }
    }
}

/// Run `cmd` to completion under ptrace, capturing filesystem accesses.
pub fn trace_command(cmd: Command, opts: TraceOptions) -> anyhow::Result<TraceReport> {
    tracer::trace_command(cmd, opts)
}

/// Reduce a raw trace into a minimal set of input dependencies, rooted at
/// `project_root`.
pub fn infer(report: &TraceReport, project_root: &Path) -> InferredDeps {
    inference::infer(report, project_root)
}
