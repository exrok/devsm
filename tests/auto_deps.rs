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

use auto_deps::{InferredDeps, TraceOptions, TraceReport, infer, trace_command, update_cache_key};

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
fn end_to_end_trace_writes_cache_key_into_devsm_toml() {
    // Full pipeline: trace a shell that reads a couple of files, infer
    // the dep set, then mutate a devsm.toml in-place. Exercises the
    // same code path the daemon takes after a `--derive-cache-key` run.
    let tmp = Tmp::new();
    fs::write(tmp.path.join("Cargo.toml"), b"[package]\nname=\"x\"\n").unwrap();
    fs::write(tmp.path.join("Cargo.lock"), b"# auto\n").unwrap();
    fs::create_dir(tmp.path.join("src")).unwrap();
    fs::write(tmp.path.join("src/main.rs"), b"fn main(){}\n").unwrap();
    let toml_path = tmp.path.join("devsm.toml");
    fs::write(
        &toml_path,
        "# header comment\n\
         [action.build]\n\
         sh = \"cat Cargo.toml > /dev/null\"\n",
    )
    .unwrap();

    let report = trace_command(
        sh(&tmp.path, "cat Cargo.toml > /dev/null; cat src/main.rs > /dev/null"),
        TraceOptions::default(),
    )
    .expect("trace");
    assert!(report.exit_status.success());
    let deps = infer(&report, &tmp.path);
    assert!(!deps.paths.is_empty());

    let modified: Vec<String> = deps.paths.iter().map(|p| p.path.to_string_lossy().into_owned()).collect();
    let ignore: Vec<Vec<String>> = deps.paths.iter().map(|p| p.ignore.clone()).collect();

    let outcome = update_cache_key(&toml_path, "build", &modified, &ignore).expect("update_cache_key");
    assert!(outcome.previous_cache_key.is_none(), "no prior cache.key expected");

    let written = fs::read_to_string(&toml_path).unwrap();
    assert!(written.contains("# header comment"), "comment lost:\n{written}");
    assert!(written.contains("modified"), "modified field missing:\n{written}");
    assert!(written.contains("Cargo.toml"), "Cargo.toml dep missing:\n{written}");
    assert!(written.contains("src"), "src dep missing:\n{written}");
    assert!(written.contains("[action.build]"), "task header lost:\n{written}");
}

#[test]
fn missing_ancestor_collapses_missing_descendant() {
    // `test -e` issues an `access` syscall, which the tracer records as
    // a Stat. Both `.cargo` and `.cargo/config.toml` end up as
    // stat-only-and-missing events; the descendant should collapse into
    // the ancestor instead of appearing alongside it.
    let (_tmp, _r, deps) = run(
        |dir| {
            fs::write(dir.join("anchor.txt"), b"a").unwrap();
        },
        "cat anchor.txt > /dev/null; \
         test -e .cargo/config.toml; \
         test -e .cargo; \
         true",
    );
    let got = dep_paths(&deps);
    assert!(
        !got.contains(".cargo/config.toml"),
        ".cargo/config.toml should collapse into .cargo, got {got:?}"
    );
}

#[test]
fn stat_only_existing_file_is_dropped() {
    // Mirrors cargo's `[package].readme` auto-detection: stat the file
    // to confirm it exists, never open it. Such probes should not
    // pollute the cache key.
    let (_tmp, _r, deps) = run(
        |dir| {
            fs::write(dir.join("README.md"), b"r").unwrap();
            fs::write(dir.join("data.txt"), b"d").unwrap();
        },
        "test -e README.md; cat data.txt > /dev/null",
    );
    let got = dep_paths(&deps);
    assert!(got.contains("data.txt"), "real read missing, got {got:?}");
    assert!(!got.contains("README.md"), "stat-only existing file should drop, got {got:?}");
}

#[test]
fn listed_dir_with_tracked_child_is_not_promoted() {
    // Models a cargo workspace member: cargo lists `member/`, opens
    // `member/Cargo.toml`, never touches anything else. We want the
    // specific file in the cache key, not the whole `member/` subtree.
    let (_tmp, _r, deps) = run(
        |dir| {
            let m = dir.join("member");
            fs::create_dir(&m).unwrap();
            fs::write(m.join("Cargo.toml"), b"[package]\nname=\"m\"\n").unwrap();
            fs::write(m.join("other.txt"), b"o").unwrap();
        },
        "ls member > /dev/null; cat member/Cargo.toml > /dev/null",
    );
    let got = dep_paths(&deps);
    assert!(
        got.contains("member/Cargo.toml"),
        "tracked child should appear, got {got:?}"
    );
    assert!(
        !got.contains("member"),
        "listed dir with tracked children should not promote to the dir, got {got:?}"
    );
}

#[test]
fn listed_dir_without_tracked_children_is_kept() {
    // The opposite case: cargo probes a dir for auto-detected targets
    // but doesn't open anything (because no target matches the build
    // request). The listing itself is still a dependency - adding a
    // file later would change behavior.
    let (_tmp, _r, deps) = run(
        |dir| {
            let e = dir.join("examples");
            fs::create_dir(&e).unwrap();
            fs::write(dir.join("anchor.txt"), b"a").unwrap();
        },
        "ls examples > /dev/null; cat anchor.txt > /dev/null",
    );
    let got = dep_paths(&deps);
    assert!(got.contains("examples"), "untouched listed dir should remain, got {got:?}");
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
