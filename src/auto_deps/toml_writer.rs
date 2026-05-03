//! Format-preserving editor for the `cache.key` field of a task in
//! `devsm.toml`.
//!
//! The writer parses the source document with `toml_spanner`, locates
//! the target task's table (under `action`, `service`, or `test`) by
//! walking the same key shape `parse_workspace` does, builds a fresh
//! `cache.key.modified = [...]` (with an optional `cache.key.ignore`)
//! value by constructing `Item`/`Table` directly, and emits the document
//! via `Formatting::preserved_from(...).with_span_projection_identity()`
//! so unrelated whitespace and comments survive untouched.

use std::collections::{BTreeMap, HashMap, HashSet};
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
/// a dotted-key form `cache.key.modified = [...]` (and `cache.key.ignore`
/// when ignore paths are present) containing the inferred deps. Other
/// fields under `cache` (notably `cache.never`) are preserved.
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
    let original =
        std::fs::read_to_string(toml_path).with_context(|| format!("failed to read {}", toml_path.display()))?;

    let new_content = render_with_updated_cache_key(&original, task_name, modified_paths, ignore_per_path)?;

    let parent = toml_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = toml_path.file_name().ok_or_else(|| anyhow!("invalid devsm.toml path: {}", toml_path.display()))?;
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

    let bytes = Formatting::preserved_from(&doc).with_span_projection_identity().format_table_to_bytes(table, &arena);
    String::from_utf8(bytes).map_err(|_| anyhow!("emitted non-utf8 bytes"))
}

pub fn group_modified_paths(modified_paths: &[String]) -> Vec<String> {
    let mut by_parent: BTreeMap<&str, Vec<(usize, &str)>> = BTreeMap::new();
    for (idx, path) in modified_paths.iter().enumerate() {
        let Some((parent, leaf)) = path.rsplit_once('/') else {
            continue;
        };
        if parent.is_empty() || leaf.is_empty() {
            continue;
        }
        by_parent.entry(parent).or_default().push((idx, leaf));
    }

    let mut replacements: HashMap<usize, String> = HashMap::new();
    let mut skip: HashSet<usize> = HashSet::new();
    for (parent, leaves) in by_parent {
        if leaves.len() < 2 {
            continue;
        }
        let leaf_list = leaves.iter().map(|(_, leaf)| *leaf).collect::<Vec<_>>().join(",");
        let grouped = format!("{parent}/{{{leaf_list}}}");
        let explicit_rendered_len = leaves.iter().map(|(_, leaf)| parent.len() + 1 + leaf.len() + 2).sum::<usize>()
            + leaves.len().saturating_sub(1) * 2;
        let grouped_rendered_len = grouped.len() + 2;
        if grouped_rendered_len >= explicit_rendered_len {
            continue;
        }
        let first_idx = leaves[0].0;
        replacements.insert(first_idx, grouped);
        for (idx, _) in leaves.iter().skip(1) {
            skip.insert(*idx);
        }
    }

    let mut out = Vec::with_capacity(modified_paths.len().saturating_sub(skip.len()));
    for (idx, path) in modified_paths.iter().enumerate() {
        if skip.contains(&idx) {
            continue;
        }
        if let Some(grouped) = replacements.remove(&idx) {
            out.push(grouped);
        } else {
            out.push(path.clone());
        }
    }
    out
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
    let kind =
        found_kind.ok_or_else(|| anyhow!("task `{}` not found in devsm.toml under action/service/test", task_name))?;
    let kind_item = root.get_mut(kind).expect("located above");
    let kind_table = kind_item.as_table_mut().expect("checked above");
    let task_item = kind_table.get_mut(task_name).expect("contains_key just confirmed presence");
    task_item.as_table_mut().ok_or_else(|| anyhow!("task `{}.{}` is not a table", kind, task_name))
}

/// Build the value for the `cache` key of the task. When the task
/// already has a `cache` table we keep its other fields (e.g.
/// `cache.never = true`) and replace only the `key` entry. Otherwise
/// emit a fresh inline `{ key = ... }` table.
///
/// Existing `cache.key` entries that aren't path-based (currently:
/// `profile_changed`) are carried over so that running `--derive-cache-key`
/// doesn't drop them. When any such entries survive, the value has to
/// stay an array-of-tables since dotted form can only express a single
/// entry. Otherwise we emit the more compact `cache.key.modified = [...]`
/// dotted form.
fn build_cache_value<'de>(
    arena: &'de Arena,
    modified_paths: &[String],
    ignore_per_path: &[Vec<String>],
    existing_cache: Option<&Item<'de>>,
) -> Item<'de> {
    let preserved = collect_preserved_key_entries(arena, existing_cache);

    let key_value = if preserved.is_empty() {
        build_modified_key_table(arena, modified_paths, ignore_per_path, TableStyle::Dotted).into_item()
    } else {
        build_key_array(arena, modified_paths, ignore_per_path, preserved)
    };

    let mut cache_table = if let Some(existing) = existing_cache.and_then(|i| i.as_table()) {
        existing.clone_in(arena)
    } else {
        toml_spanner::Table::try_with_capacity(1, arena).expect("capacity 1 within u32")
    };

    cache_table.insert(Key::new(arena.alloc_str("key")), key_value, arena);
    cache_table.set_style(TableStyle::Dotted);

    cache_table.into_item()
}

/// Collect existing `cache.key` entries that should survive the rewrite.
/// Path-based entries (`modified`/`ignore`) are dropped because the new
/// arguments are the source of truth. `profile_changed` entries (and any
/// other shape we don't recognize as path-based) are cloned through.
fn collect_preserved_key_entries<'de>(
    arena: &'de Arena,
    existing_cache: Option<&Item<'de>>,
) -> Vec<Item<'de>> {
    let mut preserved = Vec::new();
    let Some(cache_table) = existing_cache.and_then(|i| i.as_table()) else { return preserved };
    let Some(key_item) = cache_table.get("key") else { return preserved };

    let entries: &[Item<'de>] = match key_item.as_array() {
        Some(arr) => arr.as_slice(),
        None => std::slice::from_ref(key_item),
    };
    for entry in entries {
        if is_path_only_entry(entry) {
            continue;
        }
        preserved.push(entry.clone_in(arena));
    }
    preserved
}

/// Whether `entry` is a `{ modified = ..., ignore = ... }` shape, i.e.
/// fully owned by the new arguments and safe to drop.
fn is_path_only_entry(entry: &Item<'_>) -> bool {
    let Some(table) = entry.as_table() else { return false };
    for (key, _) in table {
        if key.name != "modified" && key.name != "ignore" {
            return false;
        }
    }
    true
}

/// Build a `{ modified = [...], ignore = [...] }` table for the inferred
/// paths. With `TableStyle::Dotted` it emits as the multi-line dotted
/// form when nested under `cache.key`. With `TableStyle::Inline` it emits
/// as `{ modified = [...], ignore = [...] }` for use inside an array.
fn build_modified_key_table<'de>(
    arena: &'de Arena,
    modified_paths: &[String],
    ignore_per_path: &[Vec<String>],
    style: TableStyle,
) -> toml_spanner::Table<'de> {
    let modified_paths = group_modified_paths(modified_paths);
    let mut paths_array =
        toml_spanner::Array::try_with_capacity(modified_paths.len(), arena).expect("capacity within u32");
    for p in &modified_paths {
        paths_array.push(Item::string(arena.alloc_str(p)), arena);
    }
    paths_array.set_style(ArrayStyle::Inline);

    // The `cache` schema permits one shared `ignore` list per entry, so
    // flatten and de-duplicate the per-path ignore entries.
    let mut ignore_flat: Vec<&str> = Vec::new();
    for list in ignore_per_path {
        for s in list {
            if !ignore_flat.iter().any(|x| *x == s.as_str()) {
                ignore_flat.push(s);
            }
        }
    }

    let mut key_table = toml_spanner::Table::try_with_capacity(if ignore_flat.is_empty() { 1 } else { 2 }, arena)
        .expect("capacity within u32");
    key_table.insert(Key::new(arena.alloc_str("modified")), paths_array.into_item(), arena);
    if !ignore_flat.is_empty() {
        let mut ignore_array =
            toml_spanner::Array::try_with_capacity(ignore_flat.len(), arena).expect("capacity within u32");
        for s in &ignore_flat {
            ignore_array.push(Item::string(arena.alloc_str(s)), arena);
        }
        ignore_array.set_style(ArrayStyle::Inline);
        key_table.insert(Key::new(arena.alloc_str("ignore")), ignore_array.into_item(), arena);
    }
    key_table.set_style(style);
    key_table
}

/// Build the `cache.key` value as an inline array of tables, with the
/// new modified entry first followed by the preserved entries.
fn build_key_array<'de>(
    arena: &'de Arena,
    modified_paths: &[String],
    ignore_per_path: &[Vec<String>],
    preserved: Vec<Item<'de>>,
) -> Item<'de> {
    let modified_table = build_modified_key_table(arena, modified_paths, ignore_per_path, TableStyle::Inline);

    let mut outer = toml_spanner::Array::try_with_capacity(1 + preserved.len(), arena).expect("capacity within u32");
    outer.push(modified_table.into_item(), arena);
    for entry in preserved {
        outer.push(entry, arena);
    }
    outer.set_style(ArrayStyle::Inline);

    let mut item = outer.into_item();
    item.set_ignore_source_formatting_recursively();
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_format_matches_dotted_modified_form() {
        let src = "\
[test.check]
cmd = [\"cargo\", \"check\"]
";
        let paths = vec![
            ".cargo".to_string(),
            "Cargo.lock".to_string(),
            "Cargo.toml".to_string(),
            "build.rs".to_string(),
            "test-app/Cargo.toml".to_string(),
        ];
        let out = render_with_updated_cache_key(src, "check", &paths, &[]).unwrap();
        let expected = "\
[test.check]
cmd = [\"cargo\", \"check\"]
cache.key.modified = [\".cargo\", \"Cargo.lock\", \"Cargo.toml\", \"build.rs\", \"test-app/Cargo.toml\"]
";
        assert_eq!(out, expected, "exact emit mismatch");
    }

    #[test]
    fn nested_header_layout_round_trips() {
        let src = "\
[action.foo]
sh = \"echo hi\"
";
        let out = render_with_updated_cache_key(src, "foo", &["src".into(), "Cargo.toml".into()], &[]).unwrap();
        assert!(out.contains("cache.key.modified"), "expected dotted cache.key.modified in:\n{out}");
        assert!(!out.contains("[{"), "should not emit array-of-tables form in:\n{out}");
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

    #[test]
    fn profile_changed_entry_is_preserved_and_forces_array() {
        let src = "\
[action.foo]
sh = \"echo hi\"
cache.key = [
  { modified = [\"old\"] },
  { profile_changed = \"backend\" },
]
";
        let out = render_with_updated_cache_key(src, "foo", &["new".into()], &[]).unwrap();
        assert!(
            out.contains("profile_changed") && out.contains("\"backend\""),
            "profile_changed entry lost:\n{out}"
        );
        assert!(out.contains("\"new\""), "new modified path missing:\n{out}");
        assert!(!out.contains("\"old\""), "old modified path should have been replaced:\n{out}");
        assert!(!out.contains("cache.key.modified"), "should fall back to array form:\n{out}");
    }

    #[test]
    fn single_profile_changed_only_value_is_preserved() {
        let src = "\
[action.foo]
sh = \"echo hi\"
cache.key = { profile_changed = \"backend\" }
";
        let out = render_with_updated_cache_key(src, "foo", &["new".into()], &[]).unwrap();
        assert!(out.contains("profile_changed"), "profile_changed entry lost:\n{out}");
        assert!(out.contains("\"backend\""), "profile_changed value lost:\n{out}");
        assert!(out.contains("\"new\""), "new modified path missing:\n{out}");
    }

    #[test]
    fn sibling_paths_are_grouped_with_braces() {
        let src = "[action.foo]\nsh = \"x\"\n";
        let out = render_with_updated_cache_key(
            src,
            "foo",
            &["lib/utc/Cargo.toml".to_string(), "lib/utc/src".to_string(), "Cargo.toml".to_string()],
            &[],
        )
        .unwrap();
        assert!(out.contains("\"lib/utc/{Cargo.toml,src}\""), "expected grouped path in:\n{out}");
        assert!(out.contains("\"Cargo.toml\""), "root path should stay ungrouped:\n{out}");
    }
}
