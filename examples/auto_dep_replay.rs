//! Re-run inference on a trace previously captured by
//! `auto_dep_record` and print the result. Decisions are explained
//! per-path so the inference rules can be iterated on without
//! re-running an expensive build.
//!
//! Usage:
//!     cargo run --example auto_dep_replay -- [--root <repo-root>] <trace.json> [--events]
//!
//! `--events` dumps every event after project-root filtering, sorted
//! by `(path, seq)`. Useful for understanding why a path made it into
//! (or got dropped from) the inferred set.

#![cfg(target_os = "linux")]

#[path = "../src/auto_deps.rs"]
mod auto_deps;

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use auto_deps::recording::{RecordedKind, RecordedTrace};
use auto_deps::{group_modified_paths, infer};

fn main() -> ExitCode {
    let Some(args) = parse_args() else {
        eprintln!("usage: auto_dep_replay [--root <repo-root>] <trace.json> [--events]");
        return ExitCode::from(2);
    };

    let bytes = match std::fs::read_to_string(&args.trace_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("auto_dep_replay: read {}: {e}", args.trace_path);
            return ExitCode::from(1);
        }
    };
    let recorded: RecordedTrace = match jsony::from_json(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("auto_dep_replay: parse {}: {e}", args.trace_path);
            return ExitCode::from(1);
        }
    };

    let project_root = args.root.unwrap_or_else(|| recorded.project_root_path());
    let project_root_canonical = project_root.canonicalize().unwrap_or_else(|_| project_root.clone());

    if args.dump_events {
        let mut grouped: BTreeMap<PathBuf, Vec<(u64, RecordedKind)>> = BTreeMap::new();
        for ev in &recorded.events {
            let p = PathBuf::from(&ev.path);
            if !p.starts_with(&project_root_canonical) && p != project_root_canonical {
                continue;
            }
            let rel = p.strip_prefix(&project_root_canonical).map(|r| r.to_path_buf()).unwrap_or(p);
            grouped.entry(rel).or_default().push((ev.seq, ev.kind));
        }
        println!("# events under project root, grouped by path");
        for (path, mut evs) in grouped {
            evs.sort_by_key(|(seq, _)| *seq);
            let label = if path.as_os_str().is_empty() { ".".into() } else { path.display().to_string() };
            println!("  {label}");
            for (seq, kind) in evs {
                println!("    seq={seq:<6} {kind:?}");
            }
        }
        println!();
    }

    let report = recorded.into_report();
    let deps = infer(&report, &project_root);

    println!("# inferred deps ({} events, root {})", report.events.len(), project_root.display());
    println!("modified = [");
    if deps.paths.iter().all(|p| p.ignore.is_empty()) {
        let paths = deps.paths.iter().map(|p| p.path.display().to_string()).collect::<Vec<_>>();
        for p in group_modified_paths(&paths) {
            println!("  {:?},", p);
        }
    } else {
        for p in &deps.paths {
            if p.ignore.is_empty() {
                println!("  {:?},", p.path.display().to_string());
            } else {
                println!("  {{ path = {:?}, ignore = {:?} }},", p.path.display().to_string(), p.ignore);
            }
        }
    }
    println!("]");
    println!();
    println!("frameworks: {:?}", deps.framework_signals.iter().map(|s| s.name).collect::<Vec<_>>());
    println!("dropped: outside_root={}, intermediate={}", deps.dropped_outside_root, deps.dropped_intermediate);

    ExitCode::SUCCESS
}

struct Args {
    trace_path: String,
    root: Option<PathBuf>,
    dump_events: bool,
}

fn parse_args() -> Option<Args> {
    let process_cwd = env::current_dir().ok()?;
    let mut trace_path: Option<String> = None;
    let mut root: Option<PathBuf> = None;
    let mut dump_events = false;
    let mut iter = env::args().skip(1);

    while let Some(arg) = iter.next() {
        if arg == "--events" {
            dump_events = true;
        } else if arg == "--root" {
            let value = iter.next()?;
            root = Some(resolve_path(&process_cwd, &value));
        } else if let Some(value) = arg.strip_prefix("--root=") {
            root = Some(resolve_path(&process_cwd, value));
        } else if trace_path.is_none() {
            trace_path = Some(arg);
        } else {
            return None;
        }
    }

    Some(Args { trace_path: trace_path?, root, dump_events })
}

fn resolve_path(base: &PathBuf, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    let resolved = if p.is_absolute() { p } else { base.join(p) };
    resolved.canonicalize().unwrap_or(resolved)
}
