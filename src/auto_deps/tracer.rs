use crate::auto_deps::TraceOptions;
use crate::auto_deps::event::TraceReport;
use std::process::Command;

#[cfg(target_os = "linux")]
#[path = "tracer/linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
#[path = "tracer/mem_read.rs"]
mod mem_read;
#[cfg(target_os = "linux")]
#[path = "tracer/state.rs"]
mod state;
#[cfg(target_os = "linux")]
#[path = "tracer/syscalls.rs"]
mod syscalls;

#[cfg(target_os = "linux")]
pub use linux::{Tracer, install_ptrace_traceme};

#[cfg(target_os = "linux")]
pub fn trace_command(cmd: Command, opts: TraceOptions) -> anyhow::Result<TraceReport> {
    linux::trace_command(cmd, opts)
}

#[cfg(target_os = "linux")]
pub fn trace_command_with_histogram(
    cmd: Command,
    opts: TraceOptions,
) -> anyhow::Result<(TraceReport, Vec<u64>)> {
    linux::trace_command_with_histogram(cmd, opts)
}

#[cfg(not(target_os = "linux"))]
pub fn trace_command(_cmd: Command, _opts: TraceOptions) -> anyhow::Result<TraceReport> {
    anyhow::bail!("auto_deps tracing requires Linux")
}
