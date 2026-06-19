//! Static-graph analysis of `require` edges.
//!
//! Builds a per-task `Result<(), String>` table once per config reload so
//! per-spawn callers (`spawn_task`, `run_test_batch`) can short-circuit with
//! an O(1) lookup instead of re-walking the whole require graph for every
//! matched test.
//!
//! Two problems are detected:
//!
//! - **Require cycle** — any back-edge over `Requirement::Task` makes the
//!   spawn impossible. The error is also surfaced for any task that *reaches*
//!   a cycle, matching the prior behavior where `detect_require_cycle(root)`
//!   errored on transitive cycle ancestors.
//! - **Resource deadlock** — when a task's own `Requirement::Resource` set
//!   intersects the union of resources required by any service transitively
//!   reachable through service-only `Requirement::Task` edges. Action edges
//!   are not propagated because actions release their hold before their
//!   dependants run.
//!
//! Algorithm: a single iterative DFS over the whole task graph. Cycles are
//! recorded at back-edge time and inherited up through post-order. Resource
//! sets are propagated up the same post-order, using a `u64` bitset (or a
//! `Box<[u64]>` for >64 distinct resource names — the analyzer's resource
//! interner is local to this module and unrelated to the daemon-wide
//! `ResourceSlab`).

use std::sync::Arc;

use crate::config::{Requirement, TaskKind};
use crate::workspace::{BaseTaskIndex, NameEntry, TaskEntry};

/// Static view of a single task as input to the analyzer. Both
/// [`crate::workspace::WorkspaceState`] and `devsm self validate` materialize a
/// `Vec<TaskInput>` from their respective sources.
pub struct TaskInput<'a> {
    pub name: &'a str,
    pub kind: TaskKind,
    pub require: &'a [Requirement<'a>],
}

pub struct RequireAnalysis {
    entries: Vec<AnalysisEntry>,
    profile_entries: hashbrown::HashMap<ProfileProblemKey, AnalysisEntry>,
    fallback_entries: Vec<AnalysisEntry>,
}

#[derive(Default, Clone)]
struct AnalysisEntry {
    cycle: Option<Arc<str>>,
    deadlock: Option<Arc<str>>,
}

#[derive(Hash, PartialEq, Eq)]
struct ProfileProblemKey {
    base: usize,
    profile: Box<str>,
}

pub struct ProfileTaskInput<'a> {
    pub base_task: BaseTaskIndex,
    pub profile: &'a str,
    pub fallback: bool,
    pub name: &'a str,
    pub kind: TaskKind,
    pub require: &'a [Requirement<'a>],
}

impl RequireAnalysis {
    pub fn empty() -> Self {
        Self { entries: Vec::new(), profile_entries: hashbrown::HashMap::new(), fallback_entries: Vec::new() }
    }

    #[cfg(test)]
    pub fn build(tasks: &[TaskInput<'_>], name_map: &dyn NameLookup) -> Self {
        if tasks.is_empty() {
            return Self::empty();
        }
        let mut analyzer = Analyzer::new(tasks, name_map);
        analyzer.run();
        Self { entries: analyzer.entries, profile_entries: hashbrown::HashMap::new(), fallback_entries: Vec::new() }
    }

    pub fn build_profiled(tasks: &[ProfileTaskInput<'_>], name_map: &dyn NameLookup) -> Self {
        if tasks.is_empty() {
            return Self::empty();
        }

        let flat: Vec<TaskInput<'_>> =
            tasks.iter().map(|t| TaskInput { name: t.name, kind: t.kind, require: t.require }).collect();
        let mut analyzer = Analyzer::new(&flat, name_map);
        analyzer.run();

        let n_base = tasks.iter().map(|t| t.base_task.idx()).max().map_or(0, |m| m + 1);
        let mut entries = vec![AnalysisEntry::default(); n_base];
        let mut fallback_entries = vec![AnalysisEntry::default(); n_base];
        let mut has_entry = vec![false; n_base];
        let mut has_fallback = vec![false; n_base];
        let mut profile_entries = hashbrown::HashMap::new();

        for (i, task) in tasks.iter().enumerate() {
            let base = task.base_task.idx();
            let entry = analyzer.entries[i].clone();
            if !has_entry[base] || task.fallback {
                entries[base] = entry.clone();
                has_entry[base] = true;
            }
            if task.fallback {
                fallback_entries[base] = entry;
                has_fallback[base] = true;
            } else {
                profile_entries.insert(ProfileProblemKey { base, profile: task.profile.into() }, entry);
            }
        }

        for base in 0..n_base {
            if !has_fallback[base] {
                fallback_entries[base] = entries[base].clone();
            }
        }

        Self { entries, profile_entries, fallback_entries }
    }

    /// O(1) lookup. Same `Err` strings as the previous on-demand detectors.
    /// Cycle errors take precedence over deadlock errors.
    pub fn problem(&self, root: BaseTaskIndex) -> Result<(), String> {
        Self::problem_for_entry(self.entries.get(root.idx()))
    }

    pub fn problem_for_profile(&self, root: BaseTaskIndex, profile: &str) -> Result<(), String> {
        if self.profile_entries.is_empty() {
            return self.problem(root);
        }
        let key = ProfileProblemKey { base: root.idx(), profile: profile.into() };
        if let Some(entry) = self.profile_entries.get(&key) {
            return Self::problem_for_entry(Some(entry));
        }
        Self::problem_for_entry(self.fallback_entries.get(root.idx()))
    }

    fn problem_for_entry(entry: Option<&AnalysisEntry>) -> Result<(), String> {
        let Some(entry) = entry else {
            return Ok(());
        };
        if let Some(s) = &entry.cycle {
            return Err(s.to_string());
        }
        if let Some(s) = &entry.deadlock {
            return Err(s.to_string());
        }
        Ok(())
    }

    /// Iterates `(task_name, error_message)` for every task with a problem.
    pub fn iter_problems<'a>(&'a self, tasks: &'a [TaskInput<'a>]) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        self.entries.iter().enumerate().filter_map(move |(i, e)| {
            let s = e.cycle.as_ref().or(e.deadlock.as_ref())?;
            let name = tasks.get(i).map(|t| t.name).unwrap_or("");
            Some((name, s.as_ref()))
        })
    }
}

/// Maps a require-target name back to its index in the `tasks` slice passed
/// to [`RequireAnalysis::build`]. Implemented for both the daemon-side
/// `name_map` and a transient `validate.rs` lookup.
pub trait NameLookup {
    fn lookup(&self, name: &str, profile: Option<&str>) -> Option<usize>;
}

impl NameLookup for hashbrown::HashMap<Box<str>, NameEntry> {
    fn lookup(&self, name: &str, _profile: Option<&str>) -> Option<usize> {
        let (kind_filter, short) = match name.split_once('.') {
            Some(("service", rest)) => (Some(TaskKind::Service), rest),
            Some(("action", rest)) => (Some(TaskKind::Action), rest),
            Some(("test", rest)) => (Some(TaskKind::Test), rest),
            _ => (None, name),
        };
        let entry = self.get(short)?;
        let bti = match kind_filter {
            Some(TaskKind::Service) => match entry.task {
                TaskEntry::Service(i) => Some(i),
                _ => None,
            },
            Some(TaskKind::Action) => match entry.task {
                TaskEntry::Action(i) => Some(i),
                _ => None,
            },
            Some(TaskKind::Test) => entry.test,
            None => entry.task.index().or(entry.test),
        }?;
        Some(bti.idx())
    }
}

const WHITE: u8 = 0;
const GRAY: u8 = 1;
const BLACK: u8 = 2;
const NO_POS: u32 = u32::MAX;

struct Analyzer<'a> {
    tasks: &'a [TaskInput<'a>],
    name_map: &'a dyn NameLookup,
    entries: Vec<AnalysisEntry>,

    resource_names: Vec<&'a str>,
    own_resources: Vec<ResourceSet>,
    desc_resources: Vec<ResourceSet>,

    color: Vec<u8>,
    path: Vec<usize>,
    path_pos: Vec<u32>,
}

impl<'a> Analyzer<'a> {
    fn new(tasks: &'a [TaskInput<'a>], name_map: &'a dyn NameLookup) -> Self {
        let n = tasks.len();

        let mut resource_ids: hashbrown::HashMap<&'a str, u32> = hashbrown::HashMap::new();
        let mut resource_names: Vec<&'a str> = Vec::new();
        for t in tasks {
            for r in t.require {
                let Requirement::Resource { name, .. } = r else { continue };
                if !resource_ids.contains_key(*name) {
                    let id = resource_names.len() as u32;
                    resource_ids.insert(*name, id);
                    resource_names.push(*name);
                }
            }
        }
        let n_resources = resource_names.len();

        let mut own_resources: Vec<ResourceSet> = (0..n).map(|_| ResourceSet::empty(n_resources)).collect();
        for (i, t) in tasks.iter().enumerate() {
            for r in t.require {
                let Requirement::Resource { name, .. } = r else { continue };
                let id = resource_ids[*name];
                own_resources[i].set(id);
            }
        }
        let desc_resources: Vec<ResourceSet> = (0..n).map(|_| ResourceSet::empty(n_resources)).collect();

        Self {
            tasks,
            name_map,
            entries: vec![AnalysisEntry::default(); n],
            resource_names,
            own_resources,
            desc_resources,
            color: vec![WHITE; n],
            path: Vec::new(),
            path_pos: vec![NO_POS; n],
        }
    }

    fn run(&mut self) {
        for start in 0..self.tasks.len() {
            if self.color[start] != WHITE {
                continue;
            }
            self.dfs(start);
        }
    }

    fn dfs(&mut self, start: usize) {
        let mut stack: Vec<(usize, usize)> = Vec::new();
        self.color[start] = GRAY;
        self.path_pos[start] = self.path.len() as u32;
        self.path.push(start);
        stack.push((start, 0));

        while let Some(&mut (v, ref mut ei)) = stack.last_mut() {
            let edges = self.tasks[v].require;
            let mut advanced = false;

            while *ei < edges.len() {
                let edge = &edges[*ei];
                *ei += 1;
                let Requirement::Task(call) = edge else { continue };
                let Some(w) = self.name_map.lookup(&call.name, call.profile) else { continue };

                match self.color[w] {
                    GRAY => {
                        let cycle_start = self.path_pos[w] as usize;
                        let mut names: Vec<&str> =
                            self.path[cycle_start..].iter().map(|&p| self.tasks[p].name).collect();
                        names.push(self.tasks[w].name);
                        let s: Arc<str> = format!("require cycle: {}", names.join(" -> ")).into();
                        for &node in &self.path[cycle_start..] {
                            if self.entries[node].cycle.is_none() {
                                self.entries[node].cycle = Some(s.clone());
                            }
                        }
                    }
                    WHITE => {
                        self.color[w] = GRAY;
                        self.path_pos[w] = self.path.len() as u32;
                        self.path.push(w);
                        stack.push((w, 0));
                        advanced = true;
                        break;
                    }
                    _ => {}
                }
            }

            if !advanced {
                self.post_order(v);
                self.color[v] = BLACK;
                self.path_pos[v] = NO_POS;
                self.path.pop();
                stack.pop();
            }
        }
    }

    fn post_order(&mut self, v: usize) {
        if self.entries[v].cycle.is_none() {
            for edge in self.tasks[v].require {
                let Requirement::Task(call) = edge else { continue };
                let Some(w) = self.name_map.lookup(&call.name, call.profile) else { continue };
                if self.color[w] == BLACK
                    && let Some(s) = &self.entries[w].cycle
                {
                    self.entries[v].cycle = Some(s.clone());
                    break;
                }
            }
        }

        let mut desc = ResourceSet::empty(self.resource_names.len());
        for edge in self.tasks[v].require {
            let Requirement::Task(call) = edge else { continue };
            let Some(w) = self.name_map.lookup(&call.name, call.profile) else { continue };
            if self.color[w] != BLACK {
                continue;
            }
            if self.tasks[w].kind != TaskKind::Service {
                continue;
            }
            desc.union_assign(&self.own_resources[w]);
            desc.union_assign(&self.desc_resources[w]);
        }

        if let Some(offending_id) = self.own_resources[v].intersection_first(&desc) {
            let resource_name = self.resource_names[offending_id as usize];
            let s = self.format_deadlock_path(v, offending_id, resource_name);
            self.entries[v].deadlock = Some(s);
        }

        self.desc_resources[v] = desc;
    }

    fn format_deadlock_path(&self, root: usize, offending_id: u32, resource_name: &str) -> Arc<str> {
        let n = self.tasks.len();
        let mut parent: Vec<u32> = vec![NO_POS; n];
        let mut visited = vec![false; n];
        let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
        visited[root] = true;
        queue.push_back(root);
        let mut found: Option<usize> = None;

        while let Some(v) = queue.pop_front() {
            if v != root && self.own_resources[v].is_set(offending_id) {
                found = Some(v);
                break;
            }
            for edge in self.tasks[v].require {
                let Requirement::Task(call) = edge else { continue };
                let Some(w) = self.name_map.lookup(&call.name, call.profile) else { continue };
                if self.tasks[w].kind != TaskKind::Service {
                    continue;
                }
                if visited[w] {
                    continue;
                }
                visited[w] = true;
                parent[w] = v as u32;
                queue.push_back(w);
            }
        }

        let names: Vec<&str> = if let Some(end) = found {
            let mut chain = vec![end];
            let mut cur = end;
            while parent[cur] != NO_POS {
                cur = parent[cur] as usize;
                chain.push(cur);
            }
            chain.reverse();
            chain.iter().map(|&i| self.tasks[i].name).collect()
        } else {
            vec![self.tasks[root].name]
        };

        format!("resource deadlock on '{}': {}", resource_name, names.join(" -> ")).into()
    }
}

enum ResourceSet {
    Small(u64),
    Large(Box<[u64]>),
}

impl ResourceSet {
    fn empty(n: usize) -> Self {
        if n <= 64 { Self::Small(0) } else { Self::Large(vec![0u64; n.div_ceil(64)].into_boxed_slice()) }
    }

    fn set(&mut self, id: u32) {
        match self {
            Self::Small(b) => *b |= 1u64 << id,
            Self::Large(words) => words[(id / 64) as usize] |= 1u64 << (id % 64),
        }
    }

    fn is_set(&self, id: u32) -> bool {
        match self {
            Self::Small(b) => (*b >> id) & 1 != 0,
            Self::Large(words) => (words[(id / 64) as usize] >> (id % 64)) & 1 != 0,
        }
    }

    fn union_assign(&mut self, other: &Self) {
        match (self, other) {
            (Self::Small(a), Self::Small(b)) => *a |= *b,
            (Self::Large(a), Self::Large(b)) => {
                for (x, y) in a.iter_mut().zip(b.iter()) {
                    *x |= *y;
                }
            }
            _ => panic!("ResourceSet size mismatch"),
        }
    }

    fn intersection_first(&self, other: &Self) -> Option<u32> {
        match (self, other) {
            (Self::Small(a), Self::Small(b)) => {
                let v = *a & *b;
                if v == 0 { None } else { Some(v.trailing_zeros()) }
            }
            (Self::Large(a), Self::Large(b)) => {
                for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                    let v = *x & *y;
                    if v != 0 {
                        return Some(i as u32 * 64 + v.trailing_zeros());
                    }
                }
                None
            }
            _ => panic!("ResourceSet size mismatch"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Alias, Requirement, TaskCall, TaskKind};
    use jsony_value::ValueMap;

    struct NameMap(hashbrown::HashMap<&'static str, usize>);
    impl NameLookup for NameMap {
        fn lookup(&self, name: &str, _profile: Option<&str>) -> Option<usize> {
            self.0.get(name).copied()
        }
    }

    fn task_call(name: &'static str) -> Requirement<'static> {
        Requirement::Task(TaskCall { name: Alias::new(name), profile: None, vars: ValueMap::new() })
    }

    fn resource(name: &'static str) -> Requirement<'static> {
        Requirement::Resource { name, priority: 0 }
    }

    fn analyze(tasks: Vec<TaskInput<'static>>, map: hashbrown::HashMap<&'static str, usize>) -> RequireAnalysis {
        let map = NameMap(map);
        RequireAnalysis::build(&tasks, &map)
    }

    #[test]
    fn no_problem_baseline() {
        let req_a: &[Requirement<'static>] = Box::leak(Box::new([task_call("b")]));
        let req_b: &[Requirement<'static>] = Box::leak(Box::new([]));
        let tasks = vec![
            TaskInput { name: "a", kind: TaskKind::Action, require: req_a },
            TaskInput { name: "b", kind: TaskKind::Action, require: req_b },
        ];
        let mut map = hashbrown::HashMap::new();
        map.insert("a", 0);
        map.insert("b", 1);
        let analysis = analyze(tasks, map);
        assert!(analysis.problem(BaseTaskIndex(0)).is_ok());
        assert!(analysis.problem(BaseTaskIndex(1)).is_ok());
    }

    #[test]
    fn simple_cycle_a_to_b_to_a() {
        let req_a: &[Requirement<'static>] = Box::leak(Box::new([task_call("b")]));
        let req_b: &[Requirement<'static>] = Box::leak(Box::new([task_call("a")]));
        let tasks = vec![
            TaskInput { name: "a", kind: TaskKind::Action, require: req_a },
            TaskInput { name: "b", kind: TaskKind::Action, require: req_b },
        ];
        let mut map = hashbrown::HashMap::new();
        map.insert("a", 0);
        map.insert("b", 1);
        let analysis = analyze(tasks, map);
        let err = analysis.problem(BaseTaskIndex(0)).unwrap_err();
        assert!(err.starts_with("require cycle:"), "{}", err);
        assert!(err.contains("a") && err.contains("b"));
        assert!(analysis.problem(BaseTaskIndex(1)).is_err());
    }

    #[test]
    fn self_loop() {
        let req_t: &[Requirement<'static>] = Box::leak(Box::new([task_call("t")]));
        let tasks = vec![TaskInput { name: "t", kind: TaskKind::Action, require: req_t }];
        let mut map = hashbrown::HashMap::new();
        map.insert("t", 0);
        let analysis = analyze(tasks, map);
        let err = analysis.problem(BaseTaskIndex(0)).unwrap_err();
        assert_eq!(err, "require cycle: t -> t");
    }

    #[test]
    fn unrelated_root_reaches_cycle() {
        let req_root: &[Requirement<'static>] = Box::leak(Box::new([task_call("mid")]));
        let req_mid: &[Requirement<'static>] = Box::leak(Box::new([task_call("a")]));
        let req_a: &[Requirement<'static>] = Box::leak(Box::new([task_call("b")]));
        let req_b: &[Requirement<'static>] = Box::leak(Box::new([task_call("a")]));
        let tasks = vec![
            TaskInput { name: "root", kind: TaskKind::Action, require: req_root },
            TaskInput { name: "mid", kind: TaskKind::Action, require: req_mid },
            TaskInput { name: "a", kind: TaskKind::Action, require: req_a },
            TaskInput { name: "b", kind: TaskKind::Action, require: req_b },
        ];
        let mut map = hashbrown::HashMap::new();
        map.insert("root", 0);
        map.insert("mid", 1);
        map.insert("a", 2);
        map.insert("b", 3);
        let analysis = analyze(tasks, map);
        assert!(analysis.problem(BaseTaskIndex(0)).is_err(), "root must inherit cycle error");
        assert!(analysis.problem(BaseTaskIndex(1)).is_err(), "mid must inherit cycle error");
    }

    #[test]
    fn simple_deadlock() {
        let req_svc: &[Requirement<'static>] = Box::leak(Box::new([resource("R")]));
        let req_user: &[Requirement<'static>] = Box::leak(Box::new([task_call("svc"), resource("R")]));
        let tasks = vec![
            TaskInput { name: "svc", kind: TaskKind::Service, require: req_svc },
            TaskInput { name: "user", kind: TaskKind::Action, require: req_user },
        ];
        let mut map = hashbrown::HashMap::new();
        map.insert("svc", 0);
        map.insert("user", 1);
        let analysis = analyze(tasks, map);
        assert!(analysis.problem(BaseTaskIndex(0)).is_ok(), "svc itself does not deadlock");
        let err = analysis.problem(BaseTaskIndex(1)).unwrap_err();
        assert_eq!(err, "resource deadlock on 'R': user -> svc");
    }

    #[test]
    fn action_chain_not_flagged() {
        let req_dep: &[Requirement<'static>] = Box::leak(Box::new([resource("R")]));
        let req_user: &[Requirement<'static>] = Box::leak(Box::new([task_call("dep"), resource("R")]));
        let tasks = vec![
            TaskInput { name: "dep", kind: TaskKind::Action, require: req_dep },
            TaskInput { name: "user", kind: TaskKind::Action, require: req_user },
        ];
        let mut map = hashbrown::HashMap::new();
        map.insert("dep", 0);
        map.insert("user", 1);
        let analysis = analyze(tasks, map);
        assert!(analysis.problem(BaseTaskIndex(0)).is_ok());
        assert!(analysis.problem(BaseTaskIndex(1)).is_ok(), "action chain releases resource between runs");
    }

    #[test]
    fn deadlock_via_three_hop_service_chain() {
        let req_a: &[Requirement<'static>] = Box::leak(Box::new([resource("R")]));
        let req_b: &[Requirement<'static>] = Box::leak(Box::new([task_call("a")]));
        let req_c: &[Requirement<'static>] = Box::leak(Box::new([task_call("b")]));
        let req_user: &[Requirement<'static>] = Box::leak(Box::new([task_call("c"), resource("R")]));
        let tasks = vec![
            TaskInput { name: "a", kind: TaskKind::Service, require: req_a },
            TaskInput { name: "b", kind: TaskKind::Service, require: req_b },
            TaskInput { name: "c", kind: TaskKind::Service, require: req_c },
            TaskInput { name: "user", kind: TaskKind::Action, require: req_user },
        ];
        let mut map = hashbrown::HashMap::new();
        map.insert("a", 0);
        map.insert("b", 1);
        map.insert("c", 2);
        map.insert("user", 3);
        let analysis = analyze(tasks, map);
        let err = analysis.problem(BaseTaskIndex(3)).unwrap_err();
        assert!(err.starts_with("resource deadlock on 'R':"), "{}", err);
        assert!(err.contains("user"));
        assert!(err.contains("a"));
    }

    #[test]
    fn over_64_resources_uses_large_path() {
        let names: Vec<&'static str> = (0..70)
            .map(|i| {
                let s: &'static str = Box::leak(format!("R{}", i).into_boxed_str());
                s
            })
            .collect();
        let svc_reqs: &[Requirement<'static>] =
            Box::leak(names.iter().map(|n| resource(n)).collect::<Vec<_>>().into_boxed_slice());
        let user_reqs: &[Requirement<'static>] = Box::leak(
            std::iter::once(task_call("svc"))
                .chain(std::iter::once(resource(names[65])))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        let tasks = vec![
            TaskInput { name: "svc", kind: TaskKind::Service, require: svc_reqs },
            TaskInput { name: "user", kind: TaskKind::Action, require: user_reqs },
        ];
        let mut map = hashbrown::HashMap::new();
        map.insert("svc", 0);
        map.insert("user", 1);
        let analysis = analyze(tasks, map);
        let err = analysis.problem(BaseTaskIndex(1)).unwrap_err();
        assert_eq!(err, "resource deadlock on 'R65': user -> svc");
    }
}
