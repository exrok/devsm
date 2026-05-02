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

    let mut listed_dirs: HashSet<PathBuf> = HashSet::new();
    let mut input_paths: HashSet<PathBuf> = HashSet::new();
    for ev in &kept {
        match ev.kind {
            PathEventKind::ListDir => {
                listed_dirs.insert(ev.path.clone());
            }
            PathEventKind::Read
            | PathEventKind::Stat
            | PathEventKind::ReadLink
            | PathEventKind::Exec => {
                if ev.path != project_root {
                    input_paths.insert(ev.path.clone());
                }
            }
            _ => {}
        }
    }

    let mut by_parent: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    for p in &input_paths {
        if let Some(parent) = p.parent() {
            by_parent.entry(parent.to_path_buf()).or_default().push(p.clone());
        }
    }

    let mut final_paths: HashSet<PathBuf> = input_paths.clone();

    for ld in &listed_dirs {
        final_paths.insert(ld.clone());
    }

    for parent in by_parent.keys() {
        if listed_dirs.contains(parent) {
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

fn collapse_under_directories(paths: &mut HashSet<PathBuf>) {
    let dirs: Vec<PathBuf> = paths.iter().filter(|p| p.is_dir()).cloned().collect();
    for d in dirs {
        paths.retain(|p| p == &d || !is_under(p, &d));
    }
}
