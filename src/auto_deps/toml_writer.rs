//! Format-preserving editor for the `cache.key` field of a task in
//! `devsm.toml`.
//!
//! The writer parses the source document with `toml_spanner`, locates
//! the target task's table (under `action`, `service`, or `test`) by
//! walking the same key shape `parse_workspace` does, builds a fresh
//! `cache.key = [{ modified = [...], ignore = [...] }]` value by
//! constructing `Item`/`Array`/`Table` directly, and emits the document
//! via `Formatting::preserved_from(...).with_span_projection_identity()`
//! so unrelated whitespace and comments survive untouched.

use std::path::Path;

use anyhow::{Context, anyhow, bail};
use toml_spanner::{Arena, ArrayStyle, Formatting, Item, Key, OwnedItem, TableStyle};

/// Outcome of an `update_cache_key` call.
#[derive(Debug)]
pub struct UpdateOutcome {
    /// The TOML rendering of the previous `cache.key` value, if one was
    /// present. The caller can show this to the user so they see what
    /// was overwritten.
    pub previous_cache_key: Option<String>,
}

/// Replace the `cache.key` field of the named task in `toml_path` with
/// a single `{ modified = [...], ignore = [...] }` entry containing the
/// inferred deps. Other fields under `cache` (notably `cache.never`)
/// are preserved.
///
/// `task_name` is the bare task name (no `kind.` prefix and no profile
/// suffix). The function searches `action`, `service`, and `test`
/// sub-tables in that order.
///
/// Writes are atomic: the new content is written to a temp file in the
/// same directory and renamed over `toml_path`.
pub fn update_cache_key(
    toml_path: &Path,
    task_name: &str,
    modified_paths: &[String],
    ignore_per_path: &[Vec<String>],
) -> anyhow::Result<UpdateOutcome> {
    let original = std::fs::read_to_string(toml_path)
        .with_context(|| format!("failed to read {}", toml_path.display()))?;

    let new_content = render_with_updated_cache_key(&original, task_name, modified_paths, ignore_per_path)?;

    let parent = toml_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = toml_path
        .file_name()
        .ok_or_else(|| anyhow!("invalid devsm.toml path: {}", toml_path.display()))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp_path = parent.join(&tmp_name);
    std::fs::write(&tmp_path, new_content.as_bytes())
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    if let Err(err) = std::fs::rename(&tmp_path, toml_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).with_context(|| format!("failed to rename {} to {}", tmp_path.display(), toml_path.display()));
    }

    let previous = previous_cache_key_string(&original, task_name)?;
    Ok(UpdateOutcome { previous_cache_key: previous })
}

/// Render an updated TOML string without touching the filesystem. Split
/// out so unit tests can exercise the format-preserving path directly.
pub fn render_with_updated_cache_key(
    source: &str,
    task_name: &str,
    modified_paths: &[String],
    ignore_per_path: &[Vec<String>],
) -> anyhow::Result<String> {
    let arena = Arena::new();
    let doc = toml_spanner::parse(source, &arena).map_err(|e| anyhow!("parse devsm.toml: {}", e))?;

    let mut table = doc.table().clone_in(&arena);
    let task_table = locate_task_table_mut(&mut table, task_name)?;

    let new_cache_value = build_cache_value(&arena, modified_paths, ignore_per_path, task_table.get("cache"));
    task_table.insert(Key::new(arena.alloc_str("cache")), new_cache_value, &arena);

    let bytes = Formatting::preserved_from(&doc)
        .with_span_projection_identity()
        .format_table_to_bytes(table, &arena);
    String::from_utf8(bytes).map_err(|_| anyhow!("emitted non-utf8 bytes"))
}

/// Render the existing `cache.key` value of the named task as a TOML
/// string, when present. Used to show the user what they're about to
/// overwrite. Returns `None` if the task has no `cache.key` set.
fn previous_cache_key_string(source: &str, task_name: &str) -> anyhow::Result<Option<String>> {
    let arena = Arena::new();
    let doc = toml_spanner::parse(source, &arena).map_err(|e| anyhow!("parse devsm.toml: {}", e))?;
    let mut clone = doc.table().clone_in(&arena);
    let task_table = match locate_task_table_mut(&mut clone, task_name) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let Some(cache) = task_table.get("cache") else { return Ok(None) };
    let Some(cache_table) = cache.as_table() else { return Ok(None) };
    let Some(key_item) = cache_table.get("key") else { return Ok(None) };

    Ok(Some(format!("{:?}", OwnedItem::from(key_item))))
}

/// Walk `root` to find the named task. devsm task tables live under
/// `action.<name>`, `service.<name>`, or `test.<name>`. `Table::get`
/// flattens dotted-key, separate-header, and nested-header layouts into
/// the same shape, so any of those source forms resolves here.
fn locate_task_table_mut<'a, 'de>(
    root: &'a mut toml_spanner::Table<'de>,
    task_name: &str,
) -> anyhow::Result<&'a mut toml_spanner::Table<'de>> {
    let kinds = ["action", "service", "test"];
    let mut found_kind: Option<&'static str> = None;
    for kind in kinds {
        if let Some(kind_item) = root.get(kind)
            && kind_item.as_table().is_some_and(|t| t.contains_key(task_name))
        {
            found_kind = Some(kind);
            break;
        }
    }
    let kind = found_kind
        .ok_or_else(|| anyhow!("task `{}` not found in devsm.toml under action/service/test", task_name))?;
    let kind_item = root.get_mut(kind).expect("located above");
    let kind_table = kind_item.as_table_mut().expect("checked above");
    let task_item = kind_table.get_mut(task_name).expect("contains_key just confirmed presence");
    task_item
        .as_table_mut()
        .ok_or_else(|| anyhow!("task `{}.{}` is not a table", kind, task_name))
}

/// Build the value for the `cache` key of the task. When the task
/// already has a `cache` table we keep its other fields (e.g.
/// `cache.never = true`) and replace only the `key` entry. Otherwise
/// emit a fresh inline `{ key = [...] }` table.
fn build_cache_value<'de>(
    arena: &'de Arena,
    modified_paths: &[String],
    ignore_per_path: &[Vec<String>],
    existing_cache: Option<&Item<'de>>,
) -> Item<'de> {
    let key_array_item = build_key_array(arena, modified_paths, ignore_per_path);

    let mut cache_table = if let Some(existing) = existing_cache.and_then(|i| i.as_table()) {
        existing.clone_in(arena)
    } else {
        toml_spanner::Table::try_with_capacity(1, arena).expect("capacity 1 within u32")
    };

    cache_table.insert(Key::new(arena.alloc_str("key")), key_array_item, arena);
    cache_table.set_style(TableStyle::Header);

    let mut item = cache_table.into_item();
    item.set_ignore_source_formatting_recursively();
    item
}

/// Build the `cache.key` array — exactly one inline table, optionally
/// with an `ignore` array, holding the inferred paths.
fn build_key_array<'de>(
    arena: &'de Arena,
    modified_paths: &[String],
    ignore_per_path: &[Vec<String>],
) -> Item<'de> {
    let mut paths_array = toml_spanner::Array::try_with_capacity(modified_paths.len(), arena)
        .expect("capacity within u32");
    for p in modified_paths {
        paths_array.push(Item::string(arena.alloc_str(p)), arena);
    }
    paths_array.set_style(ArrayStyle::Inline);

    // Collect any non-empty per-path ignore entries into a single flat
    // array. The `cache` schema permits one shared `ignore` list per
    // entry, so de-duplicate.
    let mut ignore_flat: Vec<&str> = Vec::new();
    for list in ignore_per_path {
        for s in list {
            if !ignore_flat.iter().any(|x| *x == s.as_str()) {
                ignore_flat.push(s);
            }
        }
    }

    let mut entry_table =
        toml_spanner::Table::try_with_capacity(if ignore_flat.is_empty() { 1 } else { 2 }, arena)
            .expect("capacity within u32");
    entry_table.insert(Key::new(arena.alloc_str("modified")), paths_array.into_item(), arena);
    if !ignore_flat.is_empty() {
        let mut ignore_array = toml_spanner::Array::try_with_capacity(ignore_flat.len(), arena)
            .expect("capacity within u32");
        for s in &ignore_flat {
            ignore_array.push(Item::string(arena.alloc_str(s)), arena);
        }
        ignore_array.set_style(ArrayStyle::Inline);
        entry_table.insert(Key::new(arena.alloc_str("ignore")), ignore_array.into_item(), arena);
    }
    entry_table.set_style(TableStyle::Inline);

    let mut outer = toml_spanner::Array::try_with_capacity(1, arena).expect("capacity within u32");
    outer.push(entry_table.into_item(), arena);
    outer.set_style(ArrayStyle::Inline);

    let mut item = outer.into_item();
    item.set_ignore_source_formatting_recursively();
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_header_layout_round_trips() {
        let src = "\
[action.foo]
sh = \"echo hi\"
";
        let out = render_with_updated_cache_key(src, "foo", &["src".into(), "Cargo.toml".into()], &[]).unwrap();
        assert!(out.contains("cache"), "missing cache section in:\n{out}");
        assert!(out.contains("modified"), "missing modified key in:\n{out}");
        assert!(out.contains("\"src\""), "missing src in:\n{out}");
        assert!(out.contains("\"Cargo.toml\""), "missing Cargo.toml in:\n{out}");
        assert!(out.contains("sh = \"echo hi\""), "original sh field lost:\n{out}");
    }

    #[test]
    fn separate_header_with_subkey_layout_round_trips() {
        let src = "\
[action]
foo = { sh = \"echo hi\" }
";
        let out = render_with_updated_cache_key(src, "foo", &["a".into()], &[]).unwrap();
        assert!(out.contains("\"a\""));
        assert!(out.contains("modified"));
    }

    #[test]
    fn dotted_key_layout_round_trips() {
        let src = "\
action.foo.sh = \"echo hi\"
";
        let out = render_with_updated_cache_key(src, "foo", &["x".into()], &[]).unwrap();
        assert!(out.contains("\"x\""));
        assert!(out.contains("modified"));
    }

    #[test]
    fn missing_task_returns_error() {
        let src = "[action.bar]\nsh = \"x\"\n";
        let res = render_with_updated_cache_key(src, "foo", &["a".into()], &[]);
        assert!(res.is_err(), "expected error for missing task, got {res:?}");
    }

    #[test]
    fn comment_near_target_survives() {
        let src = "\
# top of file
[action.foo]
# describes the task
sh = \"echo hi\"
";
        let out = render_with_updated_cache_key(src, "foo", &["a".into()], &[]).unwrap();
        assert!(out.contains("# top of file"), "top comment lost:\n{out}");
        assert!(out.contains("# describes the task"), "inline comment lost:\n{out}");
    }

    #[test]
    fn cache_never_preserved_when_only_key_changes() {
        let src = "\
[action.foo]
sh = \"echo hi\"
cache.never = true
";
        let out = render_with_updated_cache_key(src, "foo", &["a".into()], &[]).unwrap();
        assert!(out.contains("never = true") || out.contains("never=true"), "cache.never lost:\n{out}");
        assert!(out.contains("modified"));
    }

    #[test]
    fn ignore_lists_are_emitted_when_non_empty() {
        let src = "[action.foo]\nsh = \"x\"\n";
        let out = render_with_updated_cache_key(
            src,
            "foo",
            &["src".into()],
            &[vec!["target".to_string(), "build/".to_string()]],
        )
        .unwrap();
        assert!(out.contains("ignore"), "expected ignore key in:\n{out}");
        assert!(out.contains("\"target\""));
        assert!(out.contains("\"build/\""));
    }
}
