use std::ffi::CStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::Entry;

pub struct CacheKeyHasherPosix {
    hasher: blake3::Hasher,
    rel_path_buf: Vec<u8>,
    names_buf: Vec<u8>,
    entries: Vec<Entry>,
}

impl CacheKeyHasherPosix {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            rel_path_buf: Vec::with_capacity(4096),
            names_buf: Vec::with_capacity(8192),
            entries: Vec::with_capacity(1024),
        }
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
        let path_bytes = path.as_os_str().as_bytes();

        self.rel_path_buf.clear();
        self.rel_path_buf.extend_from_slice(path_bytes);
        self.rel_path_buf.push(0);

        // SAFETY: rel_path_buf is null-terminated. stat_buf is valid mutable memory.
        // fstatat with AT_FDCWD resolves the path relative to CWD.
        unsafe {
            let mut stat_buf: libc::stat = std::mem::zeroed();
            let ret =
                libc::fstatat(libc::AT_FDCWD, self.rel_path_buf.as_ptr() as *const libc::c_char, &mut stat_buf, 0);
            if ret != 0 {
                self.hasher.update(b"missing:");
                self.hasher.update(path_bytes);
                return;
            }

            if (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                // SAFETY: rel_path_buf is a valid null-terminated path. O_CLOEXEC prevents
                // fd leak to child processes. dirfd is closed via closedir or explicitly.
                let dirfd = libc::open(
                    self.rel_path_buf.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                );
                if dirfd >= 0 {
                    let dir_ptr = libc::fdopendir(dirfd);
                    if !dir_ptr.is_null() {
                        self.rel_path_buf.clear();
                        self.names_buf.clear();
                        self.entries.clear();
                        self.hash_directory(dir_ptr, ignore, 0);
                        libc::closedir(dir_ptr);
                    } else {
                        libc::close(dirfd);
                    }
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
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let mtime_ns = stat_buf.st_mtime as u128 * 1_000_000_000;
        hasher.update(&mtime_ns.to_le_bytes());
    }

    const MAX_RECURSION_DEPTH: u32 = 256;

    fn hash_directory(&mut self, dir_ptr: *mut libc::DIR, ignore: &[&str], depth: u32) {
        if depth >= Self::MAX_RECURSION_DEPTH {
            return;
        }

        let entries_start = self.entries.len();
        let names_start = self.names_buf.len();
        let rel_path_start = self.rel_path_buf.len();

        // SAFETY: dir_ptr is a valid DIR pointer from fdopendir.
        let dirfd = unsafe { libc::dirfd(dir_ptr) };
        self.read_entries(dir_ptr);

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

            // glob_match accepts AsRef<[u8]> for both arguments, so &str patterns
            // work directly with byte slice paths (handles non-UTF-8 filenames).
            if !ignore.is_empty() && ignore.iter().any(|pattern| fast_glob::glob_match(pattern, &self.rel_path_buf)) {
                continue;
            }

            // SAFETY: names_buf contains null-terminated strings copied from d_name.
            let name_ptr = self.names_buf[name_start..].as_ptr() as *const libc::c_char;

            // SAFETY: stat_buf is valid mutable memory. name_ptr is a valid null-terminated
            // filename within the directory referenced by dirfd.
            unsafe {
                let mut stat_buf: libc::stat = std::mem::zeroed();
                let mut d_type = entry.d_type;

                if d_type == libc::DT_UNKNOWN || d_type == libc::DT_LNK {
                    let ret = libc::fstatat(dirfd, name_ptr, &mut stat_buf, 0);
                    if ret != 0 {
                        self.hasher.update(b"missing:");
                        self.hasher.update(&self.rel_path_buf);
                        continue;
                    }
                    d_type =
                        if (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR { libc::DT_DIR } else { libc::DT_REG };
                } else {
                    let ret = libc::fstatat(dirfd, name_ptr, &mut stat_buf, libc::AT_SYMLINK_NOFOLLOW);
                    if ret != 0 {
                        self.hasher.update(b"missing:");
                        self.hasher.update(&self.rel_path_buf);
                        continue;
                    }
                }

                if d_type == libc::DT_DIR {
                    // SAFETY: name_ptr is valid null-terminated. O_NOFOLLOW prevents symlink
                    // traversal. O_CLOEXEC prevents fd leak. subdir_fd is closed via closedir
                    // or explicitly on fdopendir failure.
                    let subdir_fd = libc::openat(
                        dirfd,
                        name_ptr,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    );
                    if subdir_fd >= 0 {
                        let subdir_ptr = libc::fdopendir(subdir_fd);
                        if !subdir_ptr.is_null() {
                            self.hash_directory(subdir_ptr, ignore, depth + 1);
                            libc::closedir(subdir_ptr);
                        } else {
                            libc::close(subdir_fd);
                            self.hasher.update(b"missing:");
                            self.hasher.update(&self.rel_path_buf);
                        }
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

    fn read_entries(&mut self, dir_ptr: *mut libc::DIR) {
        // SAFETY: dir_ptr is a valid DIR pointer from fdopendir. readdir returns
        // entries sequentially until NULL (end of directory or error). Each entry
        // pointer is valid until the next readdir call or closedir.
        unsafe {
            loop {
                let entry = libc::readdir(dir_ptr);
                if entry.is_null() {
                    break;
                }

                // SAFETY: d_name is a null-terminated string within the dirent struct.
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
        }
    }
}

impl Default for CacheKeyHasherPosix {
    fn default() -> Self {
        Self::new()
    }
}
