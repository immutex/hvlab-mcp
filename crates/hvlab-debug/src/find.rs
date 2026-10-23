//! Locating crash dumps on the local machine.
//!
//! A walk is cheap and read-only: `*.dmp` files (including
//! `MEMORY.DMP`), non-recursive per root, newest first, with an exact
//! count of what the limit skipped (H-13 spirit: report what was not
//! returned, never imply the list is complete).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// One discovered dump file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoundDump {
    /// Absolute path of the dump file.
    pub path: PathBuf,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Modification time.
    pub modified: Option<SystemTime>,
}

/// Result of a dump search.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FindResult {
    /// Up to `limit` newest dumps across all roots.
    pub dumps: Vec<FoundDump>,
    /// How many additional dumps exist beyond the limit.
    pub skipped_by_limit: usize,
    /// Roots that could not be read (missing, permission, not a dir).
    pub unreadable_roots: Vec<String>,
}

/// Is this file a dump candidate by name?
fn is_dump_file(name: &str) -> bool {
    name.eq_ignore_ascii_case("MEMORY.DMP")
        || (name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".dmp"))
}

/// Collect one root, which may be a directory or a single dump file.
fn collect_root(root: &Path, out: &mut Vec<FoundDump>, unreadable: &mut Vec<String>) {
    let Ok(meta) = std::fs::metadata(root) else {
        unreadable.push(root.display().to_string());
        return;
    };
    if meta.is_file() {
        let Some(name) = root.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        if is_dump_file(name) {
            out.push(FoundDump {
                path: root.to_path_buf(),
                size_bytes: meta.len(),
                modified: meta.modified().ok(),
            });
        }
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        unreadable.push(root.display().to_string());
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !is_dump_file(name) {
            continue;
        }
        out.push(FoundDump {
            path,
            size_bytes: meta.len(),
            modified: meta.modified().ok(),
        });
    }
}

/// Find dumps under `roots`, newest first, bounded by `limit`.
///
/// A root may be a directory (walked one level, non-recursive) or a
/// single dump file (`C:\Windows\MEMORY.DMP`). `limit == 0` returns no
/// dumps but still reports the full skip count. Roots are walked in
/// order; ties in mtime keep walk order.
#[must_use]
pub fn find_dumps(roots: &[PathBuf], limit: usize) -> FindResult {
    let mut all = Vec::new();
    let mut unreadable_roots = Vec::new();
    for root in roots {
        collect_root(root, &mut all, &mut unreadable_roots);
    }
    // Newest first; `None` mtime sorts last. Sort is stable so equal
    // mtimes keep walk order.
    all.sort_by_key(|d| std::cmp::Reverse(d.modified));
    let skipped_by_limit = all.len().saturating_sub(limit);
    all.truncate(limit);
    FindResult {
        dumps: all,
        skipped_by_limit,
        unreadable_roots,
    }
}

/// Default search roots for this machine.
#[must_use]
pub fn default_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from(r"C:\Windows\MEMORY.DMP"),
        PathBuf::from(r"C:\Windows\Minidump"),
    ];
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(&local).join("CrashDumps"));
    }
    roots
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::time::Duration;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hvlab-debug-find-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn set_mtime(p: &Path, age_secs: u64) {
        let t = SystemTime::now() - Duration::from_secs(age_secs);
        let f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
        f.set_modified(t).unwrap();
    }

    #[test]
    fn finds_dmps_newest_first_and_counts_skips() {
        let dir = temp_dir("sort");
        for (name, age) in [("old.dmp", 500u64), ("new.dmp", 10), ("mid.dmp", 100)] {
            let p = dir.join(name);
            std::fs::write(&p, b"PAGEDU64").unwrap();
            set_mtime(&p, age);
        }
        // Non-dump noise and a subdirectory that must be ignored.
        std::fs::write(dir.join("readme.txt"), b"x").unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("nested.dmp"), b"PAGEDU64").unwrap();

        let res = find_dumps(std::slice::from_ref(&dir), 2);
        assert_eq!(res.dumps.len(), 2);
        assert_eq!(res.skipped_by_limit, 1);
        assert_eq!(res.dumps[0].path.file_name().unwrap(), "new.dmp");
        assert_eq!(res.dumps[1].path.file_name().unwrap(), "mid.dmp");
        assert!(res.unreadable_roots.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_dmp_matches_by_exact_name() {
        let dir = temp_dir("memory");
        let p = dir.join("MEMORY.DMP");
        std::fs::write(&p, b"PAGEDU64").unwrap();
        let res = find_dumps(std::slice::from_ref(&dir), 10);
        assert_eq!(res.dumps.len(), 1);
        assert_eq!(res.dumps[0].size_bytes, 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_root_is_accepted() {
        let dir = temp_dir("fileroot");
        let p = dir.join("MEMORY.DMP");
        std::fs::write(&p, b"PAGEDU64").unwrap();
        let res = find_dumps(std::slice::from_ref(&p), 5);
        assert_eq!(res.dumps.len(), 1);
        assert_eq!(res.dumps[0].path, p);
        assert!(res.unreadable_roots.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_root_is_declared_not_fatal() {
        let res = find_dumps(&[PathBuf::from(r"C:\definitely-not-here-31337")], 5);
        assert!(res.dumps.is_empty());
        assert_eq!(res.unreadable_roots.len(), 1);
    }

    #[test]
    fn empty_roots_report_none_found() {
        let dir = temp_dir("empty");
        let res = find_dumps(&[dir], 5);
        assert!(res.dumps.is_empty());
        assert_eq!(res.skipped_by_limit, 0);
    }
}
