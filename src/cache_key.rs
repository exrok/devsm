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

pub(crate) fn expand_modified_path(path: &str) -> Vec<String> {
    match expand_modified_path_inner(path) {
        Some(paths) => paths,
        None => vec![path.to_string()],
    }
}

fn expand_modified_path_inner(path: &str) -> Option<Vec<String>> {
    let Some((open, close, alternatives)) = first_brace_group(path)? else {
        return Some(vec![path.to_string()]);
    };
    let prefix = &path[..open];
    let suffix = &path[close + 1..];
    let suffixes = expand_modified_path_inner(suffix)?;

    let mut out = Vec::with_capacity(alternatives.len() * suffixes.len());
    for alt in alternatives {
        for suffix in &suffixes {
            let mut expanded = String::with_capacity(prefix.len() + alt.len() + suffix.len());
            expanded.push_str(prefix);
            expanded.push_str(alt);
            expanded.push_str(suffix);
            out.push(expanded);
        }
    }
    Some(out)
}

fn first_brace_group(path: &str) -> Option<Option<(usize, usize, Vec<&str>)>> {
    let mut chars = path.char_indices();
    while let Some((open, ch)) = chars.next() {
        match ch {
            '{' => {
                let mut alternatives = Vec::new();
                let mut start = open + ch.len_utf8();
                for (idx, inner) in chars.by_ref() {
                    match inner {
                        '{' => return None,
                        ',' => {
                            alternatives.push(&path[start..idx]);
                            start = idx + inner.len_utf8();
                        }
                        '}' => {
                            alternatives.push(&path[start..idx]);
                            return Some(Some((open, idx, alternatives)));
                        }
                        _ => {}
                    }
                }
                return None;
            }
            '}' => return None,
            _ => {}
        }
    }
    Some(None)
}

#[derive(Clone, Copy)]
struct Entry {
    name_offset: u32,
    name_len: u16,
    d_type: u8,
    ino: u64,
}

#[cfg(test)]
mod tests;
