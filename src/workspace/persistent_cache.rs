use std::{
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hashbrown::HashMap;
use jsony::Jsony;

use crate::config::TaskKind;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct PersistentCacheKey {
    kind: TaskKind,
    name: Box<str>,
    cache_key: Box<str>,
}

#[derive(Jsony, Clone)]
#[jsony(Binary)]
struct PersistentCacheRecord {
    kind: u8,
    name: String,
    cache_key: String,
    completed_ms: u64,
}

#[derive(Jsony, Default)]
#[jsony(Binary, version = 1)]
struct PersistentCacheContent {
    records: Vec<PersistentCacheRecord>,
}

pub(super) struct PersistentCache {
    path: Option<PathBuf>,
    records: HashMap<PersistentCacheKey, u64>,
}

impl PersistentCache {
    pub(super) fn new(config_path: &Path) -> Self {
        #[cfg(test)]
        if std::env::var_os("DEVSM_DB").is_none() {
            return Self::disabled();
        }

        let path = resolve_cache_path(config_path);
        let records = path.as_ref().map_or_else(HashMap::new, |path| load_records(path));
        Self { path, records }
    }

    pub(super) fn is_fresh(&self, kind: TaskKind, name: &str, cache_key: &str, max_age: Option<Duration>) -> bool {
        let key = PersistentCacheKey { kind, name: name.into(), cache_key: cache_key.into() };
        let Some(&completed_ms) = self.records.get(&key) else {
            return false;
        };
        completed_within_max_age(completed_ms, max_age)
    }

    pub(super) fn record_success(&mut self, kind: TaskKind, name: &str, cache_key: &str) {
        if self.path.is_none() {
            return;
        }
        let key = PersistentCacheKey { kind, name: name.into(), cache_key: cache_key.into() };
        self.records.insert(key, now_ms());
        self.save();
    }

    #[cfg(test)]
    fn disabled() -> Self {
        Self { path: None, records: HashMap::new() }
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let records = self
            .records
            .iter()
            .map(|(key, &completed_ms)| PersistentCacheRecord {
                kind: kind_to_u8(key.kind),
                name: key.name.to_string(),
                cache_key: key.cache_key.to_string(),
                completed_ms,
            })
            .collect();
        let content = PersistentCacheContent { records };
        let bytes = jsony::to_binary(&content);
        let _ = std::fs::write(path, bytes);
    }
}

fn load_records(path: &Path) -> HashMap<PersistentCacheKey, u64> {
    let Ok(bytes) = std::fs::read(path) else {
        return HashMap::new();
    };
    let Ok(content) = jsony::from_binary::<PersistentCacheContent>(&bytes) else {
        return HashMap::new();
    };

    let mut records: HashMap<PersistentCacheKey, u64> = HashMap::new();
    for record in content.records {
        let Some(kind) = u8_to_kind(record.kind) else {
            continue;
        };
        let key = PersistentCacheKey {
            kind,
            name: record.name.into_boxed_str(),
            cache_key: record.cache_key.into_boxed_str(),
        };
        records
            .entry(key)
            .and_modify(|existing| *existing = (*existing).max(record.completed_ms))
            .or_insert(record.completed_ms);
    }
    records
}

fn resolve_cache_path(config_path: &Path) -> Option<PathBuf> {
    let db_path = crate::db::resolve_db_path()?;
    let file_name = db_path.file_name().and_then(|name| name.to_str()).unwrap_or("devsm.db");
    let cache_dir = db_path.with_file_name(format!("{file_name}.cache"));
    Some(cache_dir.join(format!("{}.bin", workspace_hash(config_path))))
}

fn workspace_hash(config_path: &Path) -> String {
    let canonical = std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    let mut hash = blake3::hash(canonical.as_os_str().as_bytes()).to_hex().to_string();
    hash.truncate(32);
    hash
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn completed_within_max_age(completed_ms: u64, max_age: Option<Duration>) -> bool {
    let Some(max_age) = max_age else {
        return true;
    };
    let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
    now_ms().saturating_sub(completed_ms) <= max_age_ms
}

fn kind_to_u8(kind: TaskKind) -> u8 {
    match kind {
        TaskKind::Service => 0,
        TaskKind::Action => 1,
        TaskKind::Test => 2,
    }
}

fn u8_to_kind(kind: u8) -> Option<TaskKind> {
    match kind {
        0 => Some(TaskKind::Service),
        1 => Some(TaskKind::Action),
        2 => Some(TaskKind::Test),
        _ => None,
    }
}
