use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use jsony::Jsony;

#[derive(Jsony, Clone)]
#[jsony(Binary)]
pub struct Timestamp {
    ms: u64,
}

impl Timestamp {
    pub fn now() -> Self {
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        Self { ms }
    }

    pub fn ms(&self) -> u64 {
        self.ms
    }
}

#[derive(Jsony, Clone)]
#[jsony(Binary)]
pub struct WorkspaceRecord {
    pub config_path: String,
    pub last_loaded: Timestamp,
}

#[derive(Jsony, Default)]
#[jsony(Binary, version = 1)]
struct Content {
    workspaces: Vec<WorkspaceRecord>,
}

impl Content {
    fn load(path: &Path) -> Content {
        let Ok(bytes) = std::fs::read(path) else {
            return Content::default();
        };
        jsony::from_binary(&bytes).unwrap_or_default()
    }

    fn record_workspace(&mut self, config_path: &str) {
        let now = Timestamp::now();
        if let Some(entry) = self.workspaces.iter_mut().find(|e| e.config_path == config_path) {
            entry.last_loaded = now;
        } else {
            self.workspaces.push(WorkspaceRecord { config_path: config_path.to_owned(), last_loaded: now });
        }
    }
}

struct DbInner {
    content: Content,
    dirty: bool,
    shutdown: bool,
}

pub struct Db {
    inner: Arc<Mutex<DbInner>>,
    saver: Option<JoinHandle<()>>,
    disabled: bool,
}

fn resolve_db_path() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("DEVSM_DB") {
        if env_path == "/dev/null" {
            return None;
        }
        return Some(PathBuf::from(env_path));
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return Some(PathBuf::from(home).join("Library/Application Support/devsm/devsm.db"));
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
            return Some(PathBuf::from(data_home).join("devsm/devsm.db"));
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Some(PathBuf::from(home).join(".local/share/devsm/devsm.db"));
        }
    }

    Some(PathBuf::from("/tmp/devsm.db"))
}

fn save_bytes(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, bytes);
}

impl Db {
    pub fn open() -> Self {
        let Some(path) = resolve_db_path() else {
            return Self {
                inner: Arc::new(Mutex::new(DbInner { content: Content::default(), dirty: false, shutdown: false })),
                saver: None,
                disabled: true,
            };
        };

        let content = Content::load(&path);
        let inner = Arc::new(Mutex::new(DbInner { content, dirty: false, shutdown: false }));

        let saver_inner = Arc::clone(&inner);
        let saver = thread::Builder::new()
            .name("db-saver".into())
            .spawn(move || {
                Self::saver_loop(&saver_inner, &path);
            })
            .expect("spawn db-saver thread");

        Self { inner, saver: Some(saver), disabled: false }
    }

    fn saver_loop(inner: &Mutex<DbInner>, path: &Path) {
        loop {
            thread::park();

            let mut guard = inner.lock().unwrap();
            let shutdown = guard.shutdown;
            let bytes = if guard.dirty {
                guard.dirty = false;
                let bytes = jsony::to_binary(&guard.content);
                drop(guard);
                Some(bytes)
            } else {
                drop(guard);
                None
            };

            if let Some(bytes) = bytes {
                save_bytes(path, &bytes);
            }

            if shutdown {
                return;
            }
        }
    }

    pub fn record_workspace(&self, config_path: &Path) {
        if self.disabled {
            return;
        }
        let path_str = config_path.to_string_lossy();
        let mut guard = self.inner.lock().unwrap();
        guard.content.record_workspace(&path_str);
        guard.dirty = true;
        drop(guard);
        self.saver.as_ref().unwrap().thread().unpark();
    }

    pub fn workspaces(&self) -> Vec<WorkspaceRecord> {
        let guard = self.inner.lock().unwrap();
        let mut ws = guard.content.workspaces.clone();
        ws.sort_by(|a, b| b.last_loaded.ms.cmp(&a.last_loaded.ms));
        ws
    }

    pub fn shutdown(&mut self) {
        if let Some(handle) = self.saver.take() {
            self.inner.lock().unwrap().shutdown = true;
            handle.thread().unpark();
            let _ = handle.join();
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        self.shutdown();
    }
}
