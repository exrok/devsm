use std::{
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hashbrown::HashMap;
use jsony::Jsony;

use crate::config::TaskKind;

/// Magic + format version prefixing the on-disk append log. A file that does
/// not start with this is treated as the legacy single-blob format and migrated
/// on the next compaction.
const CACHE_MAGIC: [u8; 8] = *b"DSMPCAC1";

/// Lower bound on the append count that triggers a compaction. Without a floor a
/// cache holding only a handful of keys would rewrite itself every few records.
const COMPACT_FLOOR: usize = 64;

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

/// Legacy on-disk format: the whole record set serialized as one blob. Kept only
/// to migrate caches written before the append log existed.
#[derive(Jsony, Default)]
#[jsony(Binary, version = 1)]
struct PersistentCacheContent {
    records: Vec<PersistentCacheRecord>,
}

struct LoadResult {
    records: HashMap<PersistentCacheKey, u64>,
    /// The on-disk file carried superseded entries (a bloated append log) or was
    /// in the legacy format, so it should be compacted to normalize it.
    needs_rewrite: bool,
}

pub(super) struct PersistentCache {
    path: Option<PathBuf>,
    records: HashMap<PersistentCacheKey, u64>,
    /// Records appended to the on-disk log since the last full rewrite. Bounds
    /// the log so it can't grow without limit under a long-lived daemon.
    appended_since_compaction: usize,
}

impl PersistentCache {
    pub(super) fn new(config_path: &Path) -> Self {
        #[cfg(test)]
        if std::env::var_os("DEVSM_DB").is_none() {
            return Self { path: None, records: HashMap::new(), appended_since_compaction: 0 };
        }

        let path = resolve_cache_path(config_path);
        let LoadResult { records, needs_rewrite } = match &path {
            Some(path) => load_records(path),
            None => LoadResult { records: HashMap::new(), needs_rewrite: false },
        };
        let mut cache = Self { path, records, appended_since_compaction: 0 };
        if needs_rewrite {
            cache.compact();
        }
        cache
    }

    pub(super) fn is_fresh(&self, kind: TaskKind, name: &str, cache_key: &str, max_age: Option<Duration>) -> bool {
        let key = PersistentCacheKey { kind, name: name.into(), cache_key: cache_key.into() };
        let Some(&completed_ms) = self.records.get(&key) else {
            return false;
        };
        completed_within_max_age(completed_ms, max_age)
    }

    pub(super) fn record_success(&mut self, kind: TaskKind, name: &str, cache_key: &str) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let key = PersistentCacheKey { kind, name: name.into(), cache_key: cache_key.into() };
        let completed_ms = now_ms();
        self.records.insert(key, completed_ms);

        let record = PersistentCacheRecord {
            kind: kind_to_u8(kind),
            name: name.to_string(),
            cache_key: cache_key.to_string(),
            completed_ms,
        };

        // Append a single record so the workspace lock is held only for an O(1)
        // write, not a full-file rewrite. The whole file is rebuilt (compacted)
        // only once the log outgrows the live key set, which amortizes to O(1)
        // per record and keeps the on-disk size bounded.
        if append_record(&path, &record).is_ok() {
            self.appended_since_compaction += 1;
            if self.appended_since_compaction > self.records.len().max(COMPACT_FLOOR) {
                self.compact();
            }
        } else {
            // The append target was missing or unwritable (e.g. the directory
            // was removed); a full rewrite recreates it with its header.
            self.compact();
        }
    }

    fn compact(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut buf = Vec::with_capacity(CACHE_MAGIC.len() + self.records.len() * 64);
        buf.extend_from_slice(&CACHE_MAGIC);
        for (key, &completed_ms) in &self.records {
            let record = PersistentCacheRecord {
                kind: kind_to_u8(key.kind),
                name: key.name.to_string(),
                cache_key: key.cache_key.to_string(),
                completed_ms,
            };
            write_framed_record(&mut buf, &record);
        }
        if std::fs::write(&path, buf).is_ok() {
            self.appended_since_compaction = 0;
        }
    }
}

fn write_framed_record(buf: &mut Vec<u8>, record: &PersistentCacheRecord) {
    let bytes = jsony::to_binary(record);
    let len = u32::try_from(bytes.len()).expect("cache record too large");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes);
}

fn append_record(path: &Path, record: &PersistentCacheRecord) -> std::io::Result<()> {
    let mut buf = Vec::new();
    write_framed_record(&mut buf, record);
    // No `create`: a missing file falls through to the caller's compaction path,
    // which writes the magic header an append alone would not.
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&buf)
}

fn insert_record(records: &mut HashMap<PersistentCacheKey, u64>, record: PersistentCacheRecord) {
    let Some(kind) = u8_to_kind(record.kind) else {
        return;
    };
    let key =
        PersistentCacheKey { kind, name: record.name.into_boxed_str(), cache_key: record.cache_key.into_boxed_str() };
    records
        .entry(key)
        .and_modify(|existing| *existing = (*existing).max(record.completed_ms))
        .or_insert(record.completed_ms);
}

fn load_records(path: &Path) -> LoadResult {
    let Ok(bytes) = std::fs::read(path) else {
        return LoadResult { records: HashMap::new(), needs_rewrite: false };
    };

    if let Some(body) = bytes.strip_prefix(&CACHE_MAGIC) {
        let mut records = HashMap::new();
        let mut raw = 0usize;
        let mut cursor = 0usize;
        let mut malformed = false;
        while cursor < body.len() {
            if body.len() - cursor < 4 {
                malformed = true;
                break;
            }
            let len = u32::from_le_bytes(body[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            let Some(end) = cursor.checked_add(len) else {
                malformed = true;
                break;
            };
            let Some(record_bytes) = body.get(cursor..end) else {
                malformed = true;
                break;
            };
            cursor = end;
            let Ok(record) = jsony::from_binary::<PersistentCacheRecord>(record_bytes) else {
                malformed = true;
                break;
            };
            raw += 1;
            insert_record(&mut records, record);
        }
        let needs_rewrite = malformed || raw > records.len();
        return LoadResult { records, needs_rewrite };
    }

    // Legacy single-blob format: load it so the cache survives an upgrade, and
    // flag a rewrite so the next compaction migrates it to the append log.
    let Ok(content) = jsony::from_binary::<PersistentCacheContent>(&bytes) else {
        return LoadResult { records: HashMap::new(), needs_rewrite: true };
    };
    let mut records = HashMap::new();
    for record in content.records {
        insert_record(&mut records, record);
    }
    LoadResult { records, needs_rewrite: true }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("devsm_pcache_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.join("cache.bin")
    }

    impl PersistentCache {
        fn with_path(path: PathBuf) -> Self {
            let LoadResult { records, needs_rewrite } = load_records(&path);
            let mut cache = Self { path: Some(path), records, appended_since_compaction: 0 };
            if needs_rewrite {
                cache.compact();
            }
            cache
        }
    }

    #[test]
    fn record_appends_incrementally_rather_than_rewriting() {
        let path = temp_path();
        let mut cache = PersistentCache::with_path(path.clone());

        cache.record_success(TaskKind::Action, "build", "k");
        let s1 = std::fs::metadata(&path).expect("file exists").len();

        // Re-recording the same key must not rewrite the entire file; an
        // append-structured store grows, a full-rewrite store stays flat.
        cache.record_success(TaskKind::Action, "build", "k");
        let s2 = std::fs::metadata(&path).expect("file exists").len();

        assert!(s2 > s1, "second record must append (s1={s1}, s2={s2}), not rewrite the whole file");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn records_survive_reload() {
        let path = temp_path();
        {
            let mut cache = PersistentCache::with_path(path.clone());
            cache.record_success(TaskKind::Action, "build", "key1");
            cache.record_success(TaskKind::Test, "suite", "key2");
            assert!(cache.is_fresh(TaskKind::Action, "build", "key1", None));
            assert!(!cache.is_fresh(TaskKind::Action, "build", "stale", None));
        }

        // A fresh instance over the same file models a daemon restart.
        let reloaded = PersistentCache::with_path(path.clone());
        assert!(reloaded.is_fresh(TaskKind::Action, "build", "key1", None));
        assert!(reloaded.is_fresh(TaskKind::Test, "suite", "key2", None));
        assert!(!reloaded.is_fresh(TaskKind::Service, "build", "key1", None));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compaction_bounds_file_and_preserves_latest() {
        let path = temp_path();
        let mut cache = PersistentCache::with_path(path.clone());

        // Hammer a tiny key set far past the compaction threshold.
        for i in 0..1000 {
            cache.record_success(TaskKind::Action, "build", &format!("key{}", i % 4));
        }
        let live_size = std::fs::metadata(&path).expect("file exists").len();
        assert!(live_size < 8 * 1024, "append log must stay compact, was {live_size} bytes");

        let reloaded = PersistentCache::with_path(path.clone());
        for k in 0..4 {
            assert!(reloaded.is_fresh(TaskKind::Action, "build", &format!("key{k}"), None));
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn legacy_blob_is_migrated_to_append_log() {
        let path = temp_path();
        let content = PersistentCacheContent {
            records: vec![PersistentCacheRecord {
                kind: kind_to_u8(TaskKind::Action),
                name: "build".to_string(),
                cache_key: "key1".to_string(),
                completed_ms: now_ms(),
            }],
        };
        std::fs::write(&path, jsony::to_binary(&content)).expect("write legacy blob");

        let cache = PersistentCache::with_path(path.clone());
        assert!(cache.is_fresh(TaskKind::Action, "build", "key1", None), "legacy record must load");

        let migrated = std::fs::read(&path).expect("file exists");
        assert!(migrated.starts_with(&CACHE_MAGIC), "file must be rewritten in the framed format");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_append_tail_is_compacted_before_future_appends() {
        let path = temp_path();
        let first = PersistentCacheRecord {
            kind: kind_to_u8(TaskKind::Action),
            name: "build".to_string(),
            cache_key: "key1".to_string(),
            completed_ms: now_ms(),
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CACHE_MAGIC);
        write_framed_record(&mut bytes, &first);
        bytes.extend_from_slice(&[0xff, 0xff]);
        std::fs::write(&path, &bytes).expect("write torn append log");

        let mut cache = PersistentCache::with_path(path.clone());
        assert!(cache.is_fresh(TaskKind::Action, "build", "key1", None), "valid prefix must survive");
        let compacted = std::fs::read(&path).expect("file exists");
        assert!(
            compacted.len() < bytes.len(),
            "malformed tail must be trimmed before later appends (before={}, after={})",
            bytes.len(),
            compacted.len()
        );

        cache.record_success(TaskKind::Action, "build", "key2");
        let reloaded = PersistentCache::with_path(path.clone());
        assert!(reloaded.is_fresh(TaskKind::Action, "build", "key1", None));
        assert!(reloaded.is_fresh(TaskKind::Action, "build", "key2", None));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn invalid_existing_file_is_normalized_before_append() {
        let path = temp_path();
        std::fs::write(&path, b"not a devsm persistent cache").expect("write invalid file");

        let mut cache = PersistentCache::with_path(path.clone());
        let rewritten = std::fs::read(&path).expect("file exists");
        assert!(rewritten.starts_with(&CACHE_MAGIC), "invalid file must be replaced with append-log header");

        cache.record_success(TaskKind::Action, "build", "key1");
        let reloaded = PersistentCache::with_path(path.clone());
        assert!(reloaded.is_fresh(TaskKind::Action, "build", "key1", None));

        let _ = std::fs::remove_file(&path);
    }
}
