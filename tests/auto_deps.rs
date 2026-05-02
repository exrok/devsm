//! Integration tests for the auto_deps tracer + inference engine.
//!
//! These tests pull the source modules in via `#[path]` so they can call into
//! `devsm`'s internal `auto_deps` module without going through the daemon.

#![cfg(target_os = "linux")]

#[path = "../src/auto_deps.rs"]
mod auto_deps;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use auto_deps::{InferredDeps, TraceOptions, TraceReport, infer, trace_command};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tmp {
    path: PathBuf,
}

impl Tmp {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("devsm-autodeps-p{pid}-{n}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path: path.canonicalize().expect("canonicalize") }
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sh(dir: &Path, script: &str) -> Command {
    let mut c = Command::new("/bin/sh");
    c.arg("-c").arg(script).current_dir(dir);
    c
}

fn run(setup: impl FnOnce(&Path), script: &str) -> (Tmp, TraceReport, InferredDeps) {
    let tmp = Tmp::new();
    setup(&tmp.path);
    let report = trace_command(sh(&tmp.path, script), TraceOptions::default()).expect("trace");
    assert!(report.exit_status.success(), "tracee failed: {:?}", report.exit_status);
    let deps = infer(&report, &tmp.path);
    (tmp, report, deps)
}

fn dep_paths(deps: &InferredDeps) -> BTreeSet<String> {
    deps.paths.iter().map(|p| p.path.to_string_lossy().into_owned()).collect()
}

fn assert_inputs(deps: &InferredDeps, expected: &[&str]) {
    let got = dep_paths(deps);
    let want: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "inferred inputs mismatch\ngot:    {got:?}\nwanted: {want:?}");
}

#[test]
fn single_file_read_is_kept() {
    let (_tmp, _r, deps) = run(
        |dir| {
            fs::write(dir.join("foo.txt"), b"hi").unwrap();
        },
        "cat foo.txt > /dev/null",
    );
    assert_inputs(&deps, &["foo.txt"]);
}

#[test]
fn directory_walk_collapses_to_parent() {
    let (_tmp, _r, deps) = run(
        |dir| {
            let src = dir.join("src");
            fs::create_dir(&src).unwrap();
            for i in 0..6 {
                fs::write(src.join(format!("f{i}.rs")), b"x").unwrap();
            }
        },
        "for f in src/*.rs; do cat \"$f\" > /dev/null; done",
    );
    assert_inputs(&deps, &["src"]);
}

#[test]
fn cargo_rule_adds_lockfile_and_src_dir() {
    let (_tmp, _r, deps) = run(
        |dir| {
            fs::write(dir.join("Cargo.toml"), b"[package]\nname = \"x\"\n").unwrap();
            fs::write(dir.join("Cargo.lock"), b"# auto\n").unwrap();
            fs::create_dir(dir.join("src")).unwrap();
            fs::write(dir.join("src/main.rs"), b"fn main(){}\n").unwrap();
        },
        "cat Cargo.toml > /dev/null; cat src/main.rs > /dev/null",
    );
    let got = dep_paths(&deps);
    assert!(got.contains("Cargo.toml"), "got {got:?}");
    assert!(got.contains("Cargo.lock"), "got {got:?}");
    assert!(got.contains("src"), "got {got:?}");
    assert!(deps.framework_signals.iter().any(|s| s.name == "cargo"));
}

#[test]
fn write_then_read_intermediate_is_dropped() {
    let (_tmp, _r, deps) = run(
        |_| {},
        "echo data > out.txt && cat out.txt > /dev/null",
    );
    let got = dep_paths(&deps);
    assert!(!got.contains("out.txt"), "out.txt should not be an input, got {got:?}");
    assert!(deps.dropped_intermediate >= 1, "expected at least one intermediate drop");
}

#[test]
fn fork_is_followed_into_child() {
    let (_tmp, _r, deps) = run(
        |dir| {
            fs::write(dir.join("parent.txt"), b"p").unwrap();
            fs::write(dir.join("child.txt"), b"c").unwrap();
        },
        "cat parent.txt > /dev/null; sh -c 'cat child.txt > /dev/null'",
    );
    let got = dep_paths(&deps);
    assert!(got.contains("parent.txt"), "got {got:?}");
    assert!(got.contains("child.txt"), "expected child.txt (follow-fork), got {got:?}");
}

#[test]
fn paths_outside_project_root_are_excluded() {
    let (_tmp, report, deps) = run(
        |dir| {
            fs::write(dir.join("proj.txt"), b"in").unwrap();
        },
        "cat /etc/hosts > /dev/null; cat proj.txt > /dev/null",
    );
    let got = dep_paths(&deps);
    assert_eq!(got, ["proj.txt"].iter().map(|s| s.to_string()).collect());
    let saw_etc_hosts = report.events.iter().any(|e| e.path == Path::new("/etc/hosts"));
    assert!(saw_etc_hosts, "tracer should still record /etc/hosts (inference drops it)");
    assert!(deps.dropped_outside_root > 0);
}
