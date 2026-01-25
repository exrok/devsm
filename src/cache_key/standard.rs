use std::path::Path;
use std::time::SystemTime;

pub struct CacheKeyHasherStd {
    hasher: blake3::Hasher,
}

impl CacheKeyHasherStd {
    pub fn new() -> Self {
        Self { hasher: blake3::Hasher::new() }
    }

    pub fn reset(&mut self) {
        self.hasher.reset();
    }

    pub fn finalize_hex(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }

    pub fn hash_path(&mut self, path: &Path, ignore: &[&str]) {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() => {
                self.hash_directory(path, &[], ignore);
            }
            Ok(meta) => {
                self.hash_file(&meta);
            }
            Err(_) => {
                self.hasher.update(b"missing:");
                self.hasher.update(path.as_os_str().as_encoded_bytes());
            }
        }
    }

    fn hash_file(&mut self, meta: &std::fs::Metadata) {
        use std::os::unix::fs::MetadataExt;
        self.hasher.update(&meta.ino().to_le_bytes());
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0u128, |d| d.as_nanos());
        self.hasher.update(&mtime.to_le_bytes());
    }

    fn hash_directory(&mut self, dir: &Path, base_rel_path: &[u8], ignore: &[&str]) {
        use std::os::unix::fs::DirEntryExt;

        let mut entries: Vec<_> = match std::fs::read_dir(dir) {
            Ok(iter) => iter.filter_map(|e| e.ok()).collect(),
            Err(_) => {
                self.hasher.update(b"missing:");
                self.hasher.update(dir.as_os_str().as_encoded_bytes());
                return;
            }
        };
        entries.sort_by_key(|e| e.ino());

        for entry in entries {
            let file_name = entry.file_name();
            let file_name_bytes = file_name.as_encoded_bytes();
            let mut rel_path = Vec::with_capacity(base_rel_path.len() + 1 + file_name_bytes.len());
            if !base_rel_path.is_empty() {
                rel_path.extend_from_slice(base_rel_path);
                rel_path.push(b'/');
            }
            rel_path.extend_from_slice(file_name_bytes);

            // glob_match accepts AsRef<[u8]> for both arguments, so &str patterns
            // work directly with byte slice paths (handles non-UTF-8 filenames).
            if ignore.iter().any(|pattern| fast_glob::glob_match(pattern, &rel_path)) {
                continue;
            }

            let path = entry.path();
            match entry.metadata() {
                Ok(meta) if meta.is_dir() => {
                    self.hash_directory(&path, &rel_path, ignore);
                }
                Ok(meta) => {
                    self.hash_file(&meta);
                }
                Err(_) => {
                    self.hasher.update(b"missing:");
                    self.hasher.update(path.as_os_str().as_encoded_bytes());
                }
            }
        }
    }
}

impl Default for CacheKeyHasherStd {
    fn default() -> Self {
        Self::new()
    }
}
