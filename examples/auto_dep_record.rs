//! Capture an `auto_deps` trace of a child command and dump it to a
//! JSON file. The output is a [`RecordedTrace`] suitable for
//! `auto_dep_replay` and for fixture-based inference tests.
//!
//! Usage:
//!     cargo run --example auto_dep_record -- [--root <repo-root>] [--cwd <command-cwd>] <output.json> -- <cmd> [args...]
//!
//! The trace is taken with the project root set to `--root`, or the
//! current directory when omitted. The child command runs in `--cwd`,
//! or the project root when omitted. Relative `--cwd` values resolve
//! under the project root.

#![cfg(target_os = "linux")]

#[path = "../src/auto_deps.rs"]
mod auto_deps;

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use auto_deps::recording::RecordedTrace;
use auto_deps::{TraceOptions, trace_command};

fn main() -> ExitCode {
    let cwd = match env::current_dir() {
        Ok(p) => p.canonicalize().unwrap_or(p),
        Err(e) => {
            eprintln!("auto_dep_record: cwd error: {e}");
            return ExitCode::from(1);
        }
    };
    let Some(args) = parse_args(&cwd) else {
        usage();
        return ExitCode::from(2);
    };

    let mut cmd = Command::new(&args.program);
    cmd.args(&args.argv).current_dir(&args.command_cwd);

    let report = match trace_command(cmd, TraceOptions::default()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("auto_dep_record: trace failed: {e:#}");
            return ExitCode::from(1);
        }
    };

    let recorded = RecordedTrace::from_report(&report, &args.project_root);
    let json = jsony::to_json(&recorded);

    let out = PathBuf::from(&args.out_path);
    if let Err(e) = std::fs::write(&out, json.as_bytes()) {
        eprintln!("auto_dep_record: write {}: {e}", out.display());
        return ExitCode::from(1);
    }

    eprintln!(
        "auto_dep_record: {} events, exit {} -> {}",
        report.events.len(),
        report.exit_status.code().unwrap_or(-1),
        out.display(),
    );

    let code = report.exit_status.code().unwrap_or(0);
    ExitCode::from(code as u8)
}

fn usage() {
    eprintln!(
        "usage: auto_dep_record [--root <repo-root>] [--cwd <command-cwd>] <output.json> -- <cmd> [args...]\n\
         \n\
         Runs <cmd> under the auto_deps tracer and writes the trace as\n\
         JSON to <output.json>. The project root is --root or the current\n\
         directory. The command cwd is --cwd or the project root."
    );
}

struct Args {
    out_path: String,
    project_root: PathBuf,
    command_cwd: PathBuf,
    program: String,
    argv: Vec<String>,
}

fn parse_args(process_cwd: &Path) -> Option<Args> {
    let mut iter = env::args().skip(1);
    let mut root_arg: Option<String> = None;
    let mut command_cwd_arg: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut command: Vec<String> = Vec::new();

    while let Some(arg) = iter.next() {
        if arg == "--root" {
            root_arg = iter.next();
            root_arg.as_ref()?;
        } else if let Some(value) = arg.strip_prefix("--root=") {
            root_arg = Some(value.to_string());
        } else if arg == "--cwd" {
            command_cwd_arg = iter.next();
            command_cwd_arg.as_ref()?;
        } else if let Some(value) = arg.strip_prefix("--cwd=") {
            command_cwd_arg = Some(value.to_string());
        } else {
            out_path = Some(arg);
            command.extend(iter);
            break;
        }
    }

    if command.first().map(|s| s.as_str()) == Some("--") {
        command.remove(0);
    }
    let program = command.first()?.clone();
    let argv = command.into_iter().skip(1).collect();

    let project_root =
        root_arg.as_deref().map(|p| resolve_path(process_cwd, p)).unwrap_or_else(|| process_cwd.to_path_buf());
    let command_cwd =
        command_cwd_arg.as_deref().map(|p| resolve_path(&project_root, p)).unwrap_or_else(|| project_root.clone());

    Some(Args { out_path: out_path?, project_root, command_cwd, program, argv })
}

fn resolve_path(base: &Path, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    let resolved = if p.is_absolute() { p } else { base.join(p) };
    resolved.canonicalize().unwrap_or(resolved)
}
