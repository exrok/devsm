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

    let mut hasher = CacheKeyHasherPosix::new();
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

    let mut hasher = CacheKeyHasherPosix::new();
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

    let mut hasher = CacheKeyHasherPosix::new();
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

    let mut hasher = CacheKeyHasherPosix::new();
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

    let mut hasher = CacheKeyHasherPosix::new();
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

    let mut libc_hasher = CacheKeyHasherPosix::new();
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

    assert_eq!(libc_hash_ignore, std_hash_ignore, "libc and std hashers should produce identical results with ignore");

    fs::remove_dir_all(&dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn all_hashers_produce_same_results() {
    let dir = create_test_tree("compare_all");
    fs::create_dir_all(dir.join("src/utils")).unwrap();
    fs::write(dir.join("src/main.rs"), "fn main() {}").unwrap();
    fs::write(dir.join("src/lib.rs"), "pub fn lib() {}").unwrap();
    fs::write(dir.join("src/utils/helper.rs"), "pub fn help() {}").unwrap();
    fs::write(dir.join("README.md"), "# Readme").unwrap();

    let mut linux_hasher = CacheKeyHasherLinux::new();
    let mut posix_hasher = CacheKeyHasherPosix::new();
    let mut std_hasher = CacheKeyHasherStd::new();

    linux_hasher.hash_path(&dir, &[]);
    posix_hasher.hash_path(&dir, &[]);
    std_hasher.hash_path(&dir, &[]);

    let linux_hash = linux_hasher.finalize_hex();
    let posix_hash = posix_hasher.finalize_hex();
    let std_hash = std_hasher.finalize_hex();

    assert_eq!(linux_hash, posix_hash, "linux and posix hashers should produce identical results");
    assert_eq!(linux_hash, std_hash, "linux and std hashers should produce identical results");

    linux_hasher.reset();
    posix_hasher.reset();
    std_hasher.reset();

    linux_hasher.hash_path(&dir, &["*.md"]);
    posix_hasher.hash_path(&dir, &["*.md"]);
    std_hasher.hash_path(&dir, &["*.md"]);

    let linux_hash_ignore = linux_hasher.finalize_hex();
    let posix_hash_ignore = posix_hasher.finalize_hex();
    let std_hash_ignore = std_hasher.finalize_hex();

    assert_eq!(
        linux_hash_ignore, posix_hash_ignore,
        "linux and posix hashers should produce identical results with ignore"
    );
    assert_eq!(
        linux_hash_ignore, std_hash_ignore,
        "linux and std hashers should produce identical results with ignore"
    );

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn benchmark_setup() {
    let dir = create_test_tree("bench_setup");

    fn create_tree(path: &std::path::Path, depth: u32, file_counter: &mut u32) {
        for _ in 0..5 {
            let file_path = path.join(format!("file_{:04}.txt", *file_counter));
            fs::write(&file_path, format!("content {}", *file_counter)).unwrap();
            *file_counter += 1;
        }
        if depth < 4 {
            for branch in ["a", "b", "c"] {
                let subdir = path.join(branch);
                fs::create_dir_all(&subdir).unwrap();
                create_tree(&subdir, depth + 1, file_counter);
            }
        }
    }

    let mut file_counter = 0;
    create_tree(&dir, 0, &mut file_counter);
    eprintln!("Created {} files", file_counter);

    #[cfg(target_os = "linux")]
    {
        let mut hasher_linux = CacheKeyHasherLinux::new();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            hasher_linux.reset();
            hasher_linux.hash_path(&dir, &[]);
        }
        let elapsed = start.elapsed();
        eprintln!("100 iterations with linux (getdents64) hasher: {:?} {:?}", elapsed, hasher_linux.finalize_hex());
    }

    let mut hasher = CacheKeyHasherPosix::new();
    let start = std::time::Instant::now();
    for _ in 0..100 {
        hasher.reset();
        hasher.hash_path(&dir, &[]);
    }
    let elapsed = start.elapsed();
    eprintln!("100 iterations with posix (readdir) hasher: {:?} {:?}", elapsed, hasher.finalize_hex());

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
