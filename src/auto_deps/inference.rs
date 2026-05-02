#[path = "inference/rules.rs"]
mod rules;

use crate::auto_deps::event::{PathEvent, PathEventKind, TraceReport};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct InferredPath {
    pub path: PathBuf,
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FrameworkSignal {
    pub name: &'static str,
    pub trigger: PathBuf,
}

#[derive(Debug, Default)]
pub struct InferredDeps {
    pub paths: Vec<InferredPath>,
    pub framework_signals: Vec<FrameworkSignal>,
    pub dropped_outside_root: usize,
    pub dropped_intermediate: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct PathFlags {
    read: bool,
    stat: bool,
    listdir: bool,
}

const SYSTEM_PREFIXES: &[&str] =
    &["/usr", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"];

pub fn infer(report: &TraceReport, project_root: &Path) -> InferredDeps {
    let project_root = project_root.canonicalize().unwrap_or_else(|_| project_root.to_path_buf());
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg_cache = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from);
    let user_excludes = build_user_excludes(home.as_deref(), xdg_cache.as_deref());

    // A system prefix that contains the project root is not a useful
    // exclusion (e.g. test fixtures rooted under /tmp). Skip such prefixes.
    let active_excludes: Vec<PathBuf> = SYSTEM_PREFIXES
        .iter()
        .map(|p| PathBuf::from(p))
        .chain(user_excludes)
        .filter(|prefix| !is_under(&project_root, prefix))
        .collect();

    let mut deps = InferredDeps::default();

    let mut kept: Vec<&PathEvent> = Vec::with_capacity(report.events.len());
    for ev in &report.events {
        if !is_under(&ev.path, &project_root) {
            deps.dropped_outside_root += 1;
            continue;
        }
        if active_excludes.iter().any(|prefix| is_under(&ev.path, prefix)) {
            deps.dropped_outside_root += 1;
            continue;
        }
        kept.push(ev);
    }

    let mut first_write: HashMap<&Path, u64> = HashMap::new();
    for ev in &kept {
        if matches!(ev.kind, PathEventKind::Write | PathEventKind::Mkdir | PathEventKind::Unlink) {
            first_write.entry(ev.path.as_path()).or_insert(ev.seq);
        }
    }
    let kept: Vec<&PathEvent> = kept
        .into_iter()
        .filter(|ev| {
            if matches!(ev.kind, PathEventKind::Read | PathEventKind::Stat | PathEventKind::ReadLink) {
                if let Some(&w) = first_write.get(ev.path.as_path()) {
                    if ev.seq > w {
                        deps.dropped_intermediate += 1;
                        return false;
                    }
                }
            }
            true
        })
        .collect();

    let mut path_kinds: HashMap<&Path, PathFlags> = HashMap::new();
    let mut listed_dirs: HashSet<PathBuf> = HashSet::new();
    for ev in &kept {
        match ev.kind {
            PathEventKind::ListDir => {
                listed_dirs.insert(ev.path.clone());
                path_kinds.entry(ev.path.as_path()).or_default().listdir = true;
            }
            PathEventKind::Read | PathEventKind::Exec => {
                path_kinds.entry(ev.path.as_path()).or_default().read = true;
            }
            PathEventKind::Stat | PathEventKind::ReadLink => {
                path_kinds.entry(ev.path.as_path()).or_default().stat = true;
            }
            _ => {}
        }
    }

    // A path is a real content dependency only when it was actually read
    // (`Read`/`Exec`). Bare `Stat` on an existing path is an existence
    // probe (e.g. cargo's `[package].readme` auto-detect) and gets
    // dropped. Bare `Stat` on a *missing* path is kept only when it
    // sits directly under the project root - top-level configs like
    // `.cargo` or `rust-toolchain.toml` whose absence really is the
    // dependency. Deeper missing-stats are cargo's per-package
    // auto-detect sweep (e.g. probing `<member>/build.rs`,
    // `<member>/README.md`); keeping them inflates `by_parent` and
    // would cause spurious whole-directory promotion.
    let mut input_paths: HashSet<PathBuf> = HashSet::new();
    for (path, flags) in &path_kinds {
        if *path == project_root {
            continue;
        }
        let depth_from_root = path
            .strip_prefix(&project_root)
            .map(|r| r.components().count())
            .unwrap_or(usize::MAX);
        let keep = flags.read
            || (flags.stat && !path.exists() && depth_from_root <= 1);
        if !keep {
            continue;
        }
        input_paths.insert(path.to_path_buf());
    }

    let mut by_parent: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    for p in &input_paths {
        if let Some(parent) = p.parent() {
            by_parent.entry(parent.to_path_buf()).or_default().push(p.clone());
        }
    }

    let mut final_paths: HashSet<PathBuf> = input_paths.clone();

    // A listed-but-untouched directory captures cargo's "did you add a
    // workspace member / example / test target here?" probes - the
    // listing itself is the dependency. When individual files inside it
    // already appear in `input_paths` we deliberately skip the broader
    // entry so the cache key stays narrow (e.g. don't promote `test-app`
    // just because cargo opened `test-app/Cargo.toml`).
    for ld in &listed_dirs {
        let has_tracked_child =
            by_parent.get(ld).map(|v| !v.is_empty()).unwrap_or(false);
        if !has_tracked_child {
            final_paths.insert(ld.clone());
        }
    }

    for parent in by_parent.keys() {
        if final_paths.contains(parent) {
            continue;
        }
        let files = &by_parent[parent];
        if files.len() < 4 {
            continue;
        }
        let actual = match std::fs::read_dir(parent) {
            Ok(rd) => rd.count(),
            Err(_) => continue,
        };
        if files.len() * 10 >= actual * 6 {
            final_paths.insert(parent.clone());
        }
    }

    collapse_under_directories(&mut final_paths);

    let surviving: Vec<PathBuf> = final_paths.iter().cloned().collect();
    let mut additions = Vec::new();
    for rule in rules::RULES {
        let mut matched = None;
        for trigger in rule.triggers {
            let abs = project_root.join(trigger);
            if surviving.contains(&abs) {
                matched = Some(PathBuf::from(*trigger));
                break;
            }
        }
        if let Some(trigger) = matched {
            deps.framework_signals.push(FrameworkSignal { name: rule.name, trigger });
            additions.extend((rule.additions)(&project_root, &surviving));
        }
    }
    for add in additions {
        final_paths.insert(add);
    }
    collapse_under_directories(&mut final_paths);

    let mut sorted: Vec<PathBuf> = final_paths.into_iter().collect();
    sorted.sort();
    for p in sorted {
        let rel = p.strip_prefix(&project_root).map(Path::to_path_buf).unwrap_or_else(|_| p.clone());
        deps.paths.push(InferredPath { path: rel, ignore: Vec::new() });
    }
    deps
}

fn build_user_excludes(home: Option<&Path>, xdg_cache: Option<&Path>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Some(h) = home {
        v.push(h.join(".cache"));
        v.push(h.join(".cargo/registry"));
        v.push(h.join(".cargo/git"));
        v.push(h.join(".rustup"));
    }
    if let Some(c) = xdg_cache {
        v.push(c.to_path_buf());
    }
    v
}

fn is_under(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

/// Drop any path that lives strictly under another path already in the
/// set. Pure structural collapse - we deliberately do not condition on
/// `is_dir()` because cargo emits stat events for ancestors that don't
/// exist on disk (e.g. `.cargo` while searching for
/// `.cargo/config.toml`), and we still want those to absorb their own
/// children.
fn collapse_under_directories(paths: &mut HashSet<PathBuf>) {
    let candidates: Vec<PathBuf> = paths.iter().cloned().collect();
    for d in candidates {
        if !paths.contains(&d) {
            continue;
        }
        paths.retain(|p| p == &d || !is_under(p, &d));
    }
}
