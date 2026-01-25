#[cfg(target_os = "linux")]
mod linux;
#[cfg_attr(target_os = "linux", allow(dead_code))]
mod posix;
#[allow(dead_code)]
mod standard;

#[cfg(target_os = "linux")]
pub use linux::CacheKeyHasherLinux as CacheKeyHasher;

#[cfg(not(target_os = "linux"))]
pub use posix::CacheKeyHasherPosix as CacheKeyHasher;

#[cfg(all(test, target_os = "linux"))]
pub use linux::CacheKeyHasherLinux;
#[cfg(test)]
pub use posix::CacheKeyHasherPosix;
#[cfg(test)]
pub use standard::CacheKeyHasherStd;

#[derive(Clone, Copy)]
struct Entry {
    name_offset: u32,
    name_len: u16,
    d_type: u8,
    ino: u64,
}

#[cfg(test)]
mod tests;
