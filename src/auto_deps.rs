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
#[path = "auto_deps/toml_writer.rs"]
mod toml_writer;
#[path = "auto_deps/tracer.rs"]
mod tracer;

pub use toml_writer::{UpdateOutcome, group_modified_paths, update_cache_key};

use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub use event::{PathEvent, PathEventKind, TraceReport};
pub use inference::{FrameworkSignal, InferredDeps, InferredPath};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use tracer::install_seccomp_filter;
#[cfg(target_os = "linux")]
pub use tracer::{TRACED_SYSCALLS, Tracer, install_ptrace_traceme};

/// Owned, serializable form of an [`InferredDeps`] result for shipping
/// to the run client over RPC. Paths are project-root-relative strings
/// using forward slashes.
#[derive(Debug, Clone, Default)]
pub struct TraceReportPayload {
    pub paths: Vec<String>,
    pub ignore_per_path: Vec<Vec<String>>,
    pub framework_signals: Vec<String>,
    pub exit_code: i32,
    pub truncated: bool,
    pub dropped_outside_root: u64,
    pub dropped_intermediate: u64,
}

impl TraceReportPayload {
    /// Convert an `InferredDeps` together with the root process exit
    /// status and truncation flag into the wire-shaped payload.
    pub fn from_inferred(deps: InferredDeps, exit_code: i32, truncated: bool) -> Self {
        let mut paths = Vec::with_capacity(deps.paths.len());
        let mut ignore_per_path = Vec::with_capacity(deps.paths.len());
        for entry in deps.paths {
            paths.push(entry.path.to_string_lossy().into_owned());
            ignore_per_path.push(entry.ignore);
        }
        let framework_signals = deps.framework_signals.into_iter().map(|s| s.name.to_string()).collect();
        Self {
            paths,
            ignore_per_path,
            framework_signals,
            exit_code,
            truncated,
            dropped_outside_root: deps.dropped_outside_root as u64,
            dropped_intermediate: deps.dropped_intermediate as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceOptions {
    /// Hard cap on the number of events recorded. When exceeded, the tracer
    /// detaches and returns a report with `truncated = true`.
    pub max_events: usize,
    pub timeout: Option<Duration>,
    pub follow_forks: bool,
    /// Install a seccomp-BPF filter on traced children that promotes the
    /// classified syscalls (and only those) into `PTRACE_EVENT_SECCOMP`
    /// stops. Eliminates the per-syscall ENTRY stop on every uninteresting
    /// syscall, which is the dominant cost without seccomp.
    ///
    /// x86_64 only — silently ignored on other architectures, where the
    /// tracer falls back to the per-syscall path.
    pub use_seccomp: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self { max_events: 1_000_000, timeout: None, follow_forks: true, use_seccomp: true }
    }
}

/// Run `cmd` to completion under ptrace, capturing filesystem accesses.
pub fn trace_command(cmd: Command, opts: TraceOptions) -> anyhow::Result<TraceReport> {
    tracer::trace_command(cmd, opts)
}

/// Like [`trace_command`], but also returns a per-syscall-number histogram
/// (indexed by the raw syscall number; arch-specific). Used by the tracer
/// benchmark to identify pathological syscall floods.
#[cfg(target_os = "linux")]
pub fn trace_command_with_histogram(cmd: Command, opts: TraceOptions) -> anyhow::Result<(TraceReport, Vec<u64>)> {
    tracer::trace_command_with_histogram(cmd, opts)
}

/// Reduce a raw trace into a minimal set of input dependencies, rooted at
/// `project_root`.
pub fn infer(report: &TraceReport, project_root: &Path) -> InferredDeps {
    inference::infer(report, project_root)
}
