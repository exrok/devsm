//! Standalone benchmark for `auto_deps::trace_command`. Spawns an arbitrary
//! command under the same ptrace path the daemon uses, but driven by a tight
//! `waitpid(-1, blocking)` loop (the same shape `strace` uses). Prints wall
//! time, exit status, event count, and inferred-path count.
//!
//! Build & run:
//!   cargo run --release --example trace_bench -- cargo build
//!
//! Compare against `time strace -f cargo build 2>/dev/null` and against the
//! daemon path (`devsm --derive-cache-key cargo-build`).

#![cfg(target_os = "linux")]

#[path = "../src/auto_deps.rs"]
mod auto_deps;

use std::process::Command;
use std::time::Instant;

use auto_deps::{TraceOptions, infer, trace_command_with_histogram};
use syscalls::Sysno;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(prog) = args.next() else {
        eprintln!("usage: trace_bench <prog> [args...]");
        std::process::exit(2);
    };
    let argv: Vec<String> = args.collect();

    let cwd = std::env::current_dir().expect("cwd");

    let mut cmd = Command::new(&prog);
    cmd.args(&argv).current_dir(&cwd);

    let start = Instant::now();
    let (report, histogram) = trace_command_with_histogram(cmd, TraceOptions::default()).expect("trace_command");
    let trace_elapsed = start.elapsed();

    let infer_start = Instant::now();
    let deps = infer(&report, &cwd);
    let infer_elapsed = infer_start.elapsed();

    let s = report.stats;
    println!("---- trace_bench ----");
    println!("command:              {} {}", prog, argv.join(" "));
    println!("cwd:                  {}", cwd.display());
    println!("trace wall time:      {:.3}s", trace_elapsed.as_secs_f64());
    println!("infer wall time:      {:.3}s", infer_elapsed.as_secs_f64());
    println!("exit status:          {:?}", report.exit_status);
    println!("events recorded:      {}", report.events.len());
    println!("truncated:            {}", report.truncated);
    println!("inferred paths:       {}", deps.paths.len());
    println!("dropped outside:      {}", deps.dropped_outside_root);
    println!("dropped intermed.:    {}", deps.dropped_intermediate);
    println!();
    println!("---- tracer stats ----");
    println!("waitpid statuses:     {}", s.status_total);
    println!("  syscall stops:      {}", s.syscall_stops);
    println!("  ptrace event stops: {}", s.event_stops);
    println!("  signal stops:       {}", s.signal_stops);
    println!("  exit/signaled:      {}", s.exit_stops);
    println!("get_syscall_info:     {}", s.get_syscall_info_calls);
    println!("ptrace resume calls:  {}", s.resume_calls);
    println!("read_cstr calls:      {}", s.read_cstr_calls);
    println!("fork/clone events:    {}", s.fork_clones);
    let total_kernel_calls = s.status_total + s.get_syscall_info_calls + s.resume_calls + s.read_cstr_calls;
    println!(
        "approx kernel calls:  {} ({:.1} per syscall_stop)",
        total_kernel_calls,
        total_kernel_calls as f64 / s.syscall_stops.max(1) as f64,
    );
    let dur = trace_elapsed.as_secs_f64();
    println!(
        "stops/sec:            {:.0}, kernel calls/sec: {:.0}",
        s.status_total as f64 / dur.max(1e-9),
        total_kernel_calls as f64 / dur.max(1e-9),
    );

    println!();
    println!("---- top 25 tracee syscalls ----");
    let mut indexed: Vec<(usize, u64)> = histogram.iter().copied().enumerate().filter(|&(_, c)| c > 0).collect();
    indexed.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    let total_syscalls: u64 = histogram.iter().copied().sum();
    println!("(tracee total syscalls: {})", total_syscalls);
    for (nr, count) in indexed.iter().take(25) {
        let name = Sysno::new(*nr).map(|s| s.name()).unwrap_or("?");
        let pct = 100.0 * (*count as f64) / total_syscalls.max(1) as f64;
        println!("  {:>22}  {:>12}  {:>5.1}%", name, count, pct);
    }
}
