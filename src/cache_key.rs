use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::SystemTime;

pub struct CacheKeyHasher {
    hasher: blake3::Hasher,
    rel_path_buf: Vec<u8>,
    names_buf: Vec<u8>,
    entries: Vec<Entry>,
}

#[derive(Clone, Copy)]
struct Entry {
    name_offset: u32,
    name_len: u16,
    d_type: u8,
    ino: u64,
}

const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_UNKNOWN: u8 = 0;

impl CacheKeyHasher {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            rel_path_buf: Vec::with_capacity(4096),
            names_buf: Vec::with_capacity(8192),
            entries: Vec::with_capacity(1024),
        }
    }

    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.hasher.reset();
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    #[inline]
    pub fn update_u32(&mut self, val: u32) {
        self.hasher.update(&val.to_le_bytes());
    }

    pub fn finalize_hex(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }

    pub fn hash_path(&mut self, path: &Path, ignore: &[&str]) {
        let path_bytes = path.as_os_str().as_bytes();

        self.rel_path_buf.clear();
        self.rel_path_buf.extend_from_slice(path_bytes);
        self.rel_path_buf.push(0);

        unsafe {
            let mut stat_buf: libc::stat = std::mem::zeroed();
            let ret = libc::fstatat(
                libc::AT_FDCWD,
                self.rel_path_buf.as_ptr() as *const libc::c_char,
                &mut stat_buf,
                0,
            );
            if ret != 0 {
                self.hasher.update(b"missing:");
                self.hasher.update(path_bytes);
                return;
            }

            if (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                let dirfd = libc::open(
                    self.rel_path_buf.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                );
                if dirfd >= 0 {
                    self.rel_path_buf.clear();
                    self.names_buf.clear();
                    self.entries.clear();
                    self.hash_directory(dirfd, ignore);
                    libc::close(dirfd);
                }
            } else {
                Self::hash_inode_mtime(&mut self.hasher, &stat_buf);
            }
        }
    }

    #[inline]
    fn hash_inode_mtime(hasher: &mut blake3::Hasher, stat_buf: &libc::stat) {
        hasher.update(&stat_buf.st_ino.to_le_bytes());
        #[cfg(target_os = "linux")]
        let mtime_ns = stat_buf.st_mtime as u128 * 1_000_000_000 + stat_buf.st_mtime_nsec as u128;
        #[cfg(target_os = "macos")]
        let mtime_ns = stat_buf.st_mtime as u128 * 1_000_000_000 + stat_buf.st_mtimespec.tv_nsec as u128;
        hasher.update(&mtime_ns.to_le_bytes());
    }

    fn hash_directory(&mut self, dirfd: libc::c_int, ignore: &[&str]) {
        let entries_start = self.entries.len();
        let names_start = self.names_buf.len();
        let rel_path_start = self.rel_path_buf.len();

        self.read_entries(dirfd);

        let entries_end = self.entries.len();
        if entries_end == entries_start {
            return;
        }

        self.entries[entries_start..entries_end].sort_unstable_by_key(|e| e.ino);

        for i in entries_start..entries_end {
            let entry = self.entries[i];
            let name_start = entry.name_offset as usize;
            let name_end = name_start + entry.name_len as usize;

            self.rel_path_buf.truncate(rel_path_start);
            if rel_path_start > 0 {
                self.rel_path_buf.push(b'/');
            }
            self.rel_path_buf.extend_from_slice(&self.names_buf[name_start..name_end]);

            if !ignore.is_empty() {
                let rel_path_str = unsafe { std::str::from_utf8_unchecked(&self.rel_path_buf) };
                if ignore.iter().any(|pattern| fast_glob::glob_match(pattern, rel_path_str)) {
                    continue;
                }
            }

            let name_ptr = self.names_buf[name_start..].as_ptr() as *const libc::c_char;

            unsafe {
                let mut stat_buf: libc::stat = std::mem::zeroed();
                let mut d_type = entry.d_type;

                if d_type == DT_UNKNOWN || d_type == DT_LNK {
                    let ret = libc::fstatat(dirfd, name_ptr, &mut stat_buf, 0);
                    if ret != 0 {
                        self.hasher.update(b"missing:");
                        self.hasher.update(&self.rel_path_buf);
                        continue;
                    }
                    d_type = if (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR { DT_DIR } else { DT_REG };
                } else {
                    let ret = libc::fstatat(dirfd, name_ptr, &mut stat_buf, libc::AT_SYMLINK_NOFOLLOW);
                    if ret != 0 {
                        self.hasher.update(b"missing:");
                        self.hasher.update(&self.rel_path_buf);
                        continue;
                    }
                }

                if d_type == DT_DIR {
                    let subdir_fd = libc::openat(dirfd, name_ptr, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
                    if subdir_fd >= 0 {
                        self.hash_directory(subdir_fd, ignore);
                        libc::close(subdir_fd);
                    } else {
                        self.hasher.update(b"missing:");
                        self.hasher.update(&self.rel_path_buf);
                    }
                } else {
                    Self::hash_inode_mtime(&mut self.hasher, &stat_buf);
                }
            }
        }

        self.entries.truncate(entries_start);
        self.names_buf.truncate(names_start);
    }

    fn read_entries(&mut self, dirfd: libc::c_int) {
        unsafe {
            let duped_fd = libc::fcntl(dirfd, libc::F_DUPFD_CLOEXEC, 0);
            if duped_fd < 0 {
                return;
            }

            let dir_ptr = libc::fdopendir(duped_fd);
            if dir_ptr.is_null() {
                libc::close(duped_fd);
                return;
            }

            loop {
                let entry = libc::readdir(dir_ptr);
                if entry.is_null() {
                    break;
                }

                let name_ptr = (*entry).d_name.as_ptr();
                let name_cstr = CStr::from_ptr(name_ptr);
                let name_bytes = name_cstr.to_bytes();

                if (name_bytes.len() == 1 && name_bytes[0] == b'.')
                    || (name_bytes.len() == 2 && name_bytes[0] == b'.' && name_bytes[1] == b'.')
                {
                    continue;
                }

                let name_offset = self.names_buf.len() as u32;
                self.names_buf.extend_from_slice(name_bytes);
                self.names_buf.push(0);

                self.entries.push(Entry {
                    name_offset,
                    name_len: name_bytes.len() as u16,
                    d_type: (*entry).d_type,
                    ino: (*entry).d_ino,
                });
            }

            libc::closedir(dir_ptr);
        }
    }
}

impl Default for CacheKeyHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
pub struct CacheKeyHasherStd {
    hasher: blake3::Hasher,
}

#[allow(dead_code)]
impl CacheKeyHasherStd {
    pub fn new() -> Self {
        Self { hasher: blake3::Hasher::new() }
    }

    pub fn reset(&mut self) {
        self.hasher.reset();
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    #[inline]
    pub fn update_u32(&mut self, val: u32) {
        self.hasher.update(&val.to_le_bytes());
    }

    pub fn finalize_hex(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }

    pub fn hash_path(&mut self, path: &Path, ignore: &[&str]) {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() => {
                self.hash_directory(path, "", ignore);
            }
            Ok(meta) => {
                self.hash_file(&meta);
            }
            Err(_) => {
                self.hasher.update(b"missing:");
                self.hasher.update(path.to_string_lossy().as_bytes());
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

    fn hash_directory(&mut self, dir: &Path, base_rel_path: &str, ignore: &[&str]) {
        use std::os::unix::fs::DirEntryExt;

        let mut entries: Vec<_> = match std::fs::read_dir(dir) {
            Ok(iter) => iter.filter_map(|e| e.ok()).collect(),
            Err(_) => {
                self.hasher.update(b"missing:");
                self.hasher.update(dir.to_string_lossy().as_bytes());
                return;
            }
        };
        entries.sort_by_key(|e| e.ino());

        for entry in entries {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            let rel_path = if base_rel_path.is_empty() {
                file_name_str.to_string()
            } else {
                format!("{}/{}", base_rel_path.trim_end_matches('/'), file_name_str)
            };

            if ignore.iter().any(|pattern| fast_glob::glob_match(*pattern, &rel_path)) {
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
                    self.hasher.update(path.to_string_lossy().as_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_tree(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cache_key_test_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn hash_single_file() {
        let dir = create_test_tree("single_file");
        let file = dir.join("test.txt");
        fs::write(&file, "hello").unwrap();

        let mut hasher = CacheKeyHasher::new();
        hasher.hash_path(&file, &[]);
        let hash1 = hasher.finalize_hex();

        hasher.reset();
        hasher.hash_path(&file, &[]);
        let hash2 = hasher.finalize_hex();

        assert_eq!(hash1, hash2);

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&file, "world").unwrap();

        hasher.reset();
        hasher.hash_path(&file, &[]);
        let hash3 = hasher.finalize_hex();

        assert_ne!(hash1, hash3);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hash_directory_sorted() {
        let dir = create_test_tree("sorted");
        fs::write(dir.join("b.txt"), "b").unwrap();
        fs::write(dir.join("a.txt"), "a").unwrap();
        fs::write(dir.join("c.txt"), "c").unwrap();

        let mut hasher = CacheKeyHasher::new();
        hasher.hash_path(&dir, &[]);
        let hash1 = hasher.finalize_hex();

        hasher.reset();
        hasher.hash_path(&dir, &[]);
        let hash2 = hasher.finalize_hex();

        assert_eq!(hash1, hash2);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hash_directory_with_ignore() {
        let dir = create_test_tree("ignore");
        fs::write(dir.join("main.rs"), "fn main() {}").unwrap();
        fs::write(dir.join("README.md"), "# Hello").unwrap();

        let mut hasher = CacheKeyHasher::new();
        hasher.hash_path(&dir, &["*.md"]);
        let hash1 = hasher.finalize_hex();

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(dir.join("README.md"), "# Updated").unwrap();

        hasher.reset();
        hasher.hash_path(&dir, &["*.md"]);
        let hash2 = hasher.finalize_hex();

        assert_eq!(hash1, hash2);

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(dir.join("main.rs"), "fn main() { println!(\"hi\"); }").unwrap();

        hasher.reset();
        hasher.hash_path(&dir, &["*.md"]);
        let hash3 = hasher.finalize_hex();

        assert_ne!(hash1, hash3);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hash_nested_directory() {
        let dir = create_test_tree("nested");
        fs::create_dir_all(dir.join("a/b/c")).unwrap();
        fs::write(dir.join("a/b/c/deep.txt"), "deep").unwrap();

        let mut hasher = CacheKeyHasher::new();
        hasher.hash_path(&dir, &[]);
        let hash1 = hasher.finalize_hex();

        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(dir.join("a/b/c/deep.txt"), "deeper").unwrap();

        hasher.reset();
        hasher.hash_path(&dir, &[]);
        let hash2 = hasher.finalize_hex();

        assert_ne!(hash1, hash2);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hash_missing_path() {
        let dir = std::env::temp_dir().join("cache_key_test_missing_nonexistent");

        let mut hasher = CacheKeyHasher::new();
        hasher.hash_path(&dir, &[]);
        let hash = hasher.finalize_hex();

        assert!(!hash.is_empty());
    }

    #[test]
    fn libc_and_std_produce_same_results() {
        let dir = create_test_tree("compare");
        fs::create_dir_all(dir.join("src/utils")).unwrap();
        fs::write(dir.join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(dir.join("src/lib.rs"), "pub fn lib() {}").unwrap();
        fs::write(dir.join("src/utils/helper.rs"), "pub fn help() {}").unwrap();
        fs::write(dir.join("README.md"), "# Readme").unwrap();

        let mut libc_hasher = CacheKeyHasher::new();
        let mut std_hasher = CacheKeyHasherStd::new();

        libc_hasher.hash_path(&dir, &[]);
        std_hasher.hash_path(&dir, &[]);

        let libc_hash = libc_hasher.finalize_hex();
        let std_hash = std_hasher.finalize_hex();

        assert_eq!(libc_hash, std_hash, "libc and std hashers should produce identical results");

        libc_hasher.reset();
        std_hasher.reset();

        libc_hasher.hash_path(&dir, &["*.md"]);
        std_hasher.hash_path(&dir, &["*.md"]);

        let libc_hash_ignore = libc_hasher.finalize_hex();
        let std_hash_ignore = std_hasher.finalize_hex();

        assert_eq!(
            libc_hash_ignore, std_hash_ignore,
            "libc and std hashers should produce identical results with ignore"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn benchmark_setup() {
        let dir = create_test_tree("bench_setup");
        for i in 0..100 {
            fs::write(dir.join(format!("file_{:03}.txt", i)), format!("content {}", i)).unwrap();
        }
        fs::create_dir_all(dir.join("subdir")).unwrap();
        for i in 0..50 {
            fs::write(dir.join(format!("subdir/nested_{:03}.txt", i)), format!("nested {}", i)).unwrap();
        }

        let mut hasher = CacheKeyHasher::new();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            hasher.reset();
            hasher.hash_path(&dir, &[]);
        }
        let elapsed = start.elapsed();
        eprintln!("100 iterations with libc hasher: {:?} {:?}", elapsed, hasher.finalize_hex());

        let mut hasher_std = CacheKeyHasherStd::new();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            hasher_std.reset();
            hasher_std.hash_path(&dir, &[]);
        }
        let elapsed = start.elapsed();
        eprintln!("100 iterations with std hasher: {:?} {:?}", elapsed, hasher_std.finalize_hex());

        fs::remove_dir_all(&dir).unwrap();
    }
}
