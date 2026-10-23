//! Locating `cdb.exe`, the command-line debugger shipped with the
//! Windows SDK Debuggers directory.
//!
//! Discovery happens once per process and is cached (H-26): the search
//! order is the `HVLAB_DBGENG_DIR` environment override, then the
//! standard Windows Kits install roots. A miss reports *every* path
//! searched, so an operator can see the discovery matrix instead of a
//! bare "not found" (H-29).

use std::path::PathBuf;
use std::sync::LazyLock;

use hvlab_core::error::{ErrorCode, HvError};

/// Environment variable that overrides the default search roots. Its
/// value is a directory (not a file path) that is expected to contain
/// `cdb.exe`.
pub const DBGENG_DIR_ENV: &str = "HVLAB_DBGENG_DIR";

/// Default debugger install roots, in search order.
pub const DEFAULT_SEARCH_ROOTS: &[&str] = &[
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\amd64",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64",
    r"C:\Program Files\Windows Kits\10\Debuggers\amd64",
];

/// A resolved `cdb.exe` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdbPath(pub PathBuf);

impl std::fmt::Display for CdbPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.display().fmt(f)
    }
}

/// What discovery searched and what it found. Cheap to log, cheap to
/// embed in an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The resolved executable, when found.
    pub path: Option<PathBuf>,
    /// Every directory considered, in search order.
    pub searched: Vec<PathBuf>,
}

impl Discovery {
    /// Consume the discovery into a path or an `Unsupported` error
    /// listing the full search matrix.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Unsupported`] when no candidate existed on disk.
    pub fn into_result(self) -> Result<CdbPath, HvError> {
        let Some(path) = self.path else {
            let searched: Vec<String> = self
                .searched
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            return Err(HvError::new(
                ErrorCode::Unsupported,
                "cdb.exe not found: install the Windows SDK Debuggers \
                 or set HVLAB_DBGENG_DIR to the directory containing cdb.exe",
            )
            .with_context("searched_paths", serde_json::json!(searched)));
        };
        Ok(CdbPath(path))
    }
}

/// Candidate `cdb.exe` locations for one root directory.
fn candidates_in(root: &std::path::Path) -> Vec<PathBuf> {
    vec![root.join("cdb.exe")]
}

/// Run discovery without caching: env override first, then defaults.
fn discover_uncached() -> Discovery {
    let mut searched = Vec::new();

    if let Ok(root) = std::env::var(DBGENG_DIR_ENV) {
        let root = PathBuf::from(root);
        searched.push(root.clone());
        for c in candidates_in(&root) {
            if c.is_file() {
                return Discovery {
                    path: Some(c),
                    searched,
                };
            }
        }
    }

    for root in DEFAULT_SEARCH_ROOTS {
        let root = PathBuf::from(root);
        searched.push(root.clone());
        for c in candidates_in(&root) {
            if c.is_file() {
                return Discovery {
                    path: Some(c),
                    searched,
                };
            }
        }
    }

    Discovery {
        path: None,
        searched,
    }
}

static CACHED: LazyLock<Discovery> = LazyLock::new(discover_uncached);

/// Locate `cdb.exe`, caching the result for the process lifetime.
#[must_use]
pub fn cdb_path() -> Discovery {
    CACHED.clone()
}

/// Run discovery once, ignoring the process cache. Exists for tests
/// that manipulate the environment; production code uses
/// [`cdb_path`].
#[must_use]
pub fn discover_now() -> Discovery {
    discover_uncached()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn missing_env_dir_yields_unsupported_with_matrix() {
        let d = Discovery {
            path: None,
            searched: vec![
                PathBuf::from(r"C:\nonexistent-a"),
                PathBuf::from(r"C:\nonexistent-b"),
            ],
        };
        let err = d.into_result().expect_err("must fail");
        assert_eq!(err.code, ErrorCode::Unsupported);
        let searched = err.context.get("searched_paths").expect("matrix present");
        assert_eq!(searched.as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn found_path_round_trips() {
        let d = Discovery {
            path: Some(PathBuf::from(r"C:\kits\cdb.exe")),
            searched: vec![PathBuf::from(r"C:\kits")],
        };
        assert!(d.into_result().is_ok());
    }

    #[test]
    fn real_discovery_returns_consistent_cached_result() {
        let a = cdb_path();
        let b = cdb_path();
        assert_eq!(a, b, "discovery must be cached (H-26)");
    }
}
