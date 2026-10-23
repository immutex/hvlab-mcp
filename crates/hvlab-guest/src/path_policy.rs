//! Guest path allowlist (H-33, H-35).
//!
//! `PathPolicy` resolves a requested path against explicit roots. The
//! check is component-wise on canonicalized paths — never a string
//! prefix — so `C:\hvlab-secret` does not satisfy a root of `C:\hvlab`
//! and `..` components cannot escape after resolution.

use std::path::{Path, PathBuf};

use hvlab_core::error::{ErrorCode, HvError};

/// Result of resolving a path under the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// Canonicalized, verified path.
    pub canonical: PathBuf,
    /// Index of the matching root in policy order.
    pub root_index: usize,
}

/// Allowlist of guest roots every path argument must live under.
#[derive(Debug, Clone)]
pub struct PathPolicy {
    roots: Vec<PathBuf>,
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        use std::path::Component;
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn components_lower(p: &Path) -> Vec<String> {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect()
}

impl PathPolicy {
    /// Build a policy from roots. Roots are canonicalized eagerly;
    /// a root that does not exist is kept as normalized (read paths
    /// may refer to files created later, and verification happens at
    /// resolve time against the resolved path, not the root literal).
    ///
    /// # Errors
    /// [`HvError`] with code `InvalidArgument` when the root list is
    /// empty or a root is empty.
    pub fn new(roots: &[PathBuf]) -> Result<Self, HvError> {
        if roots.is_empty() {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                "guest_path_roots is empty: no path operations are permitted",
            ));
        }
        let mut canon = Vec::with_capacity(roots.len());
        for root in roots {
            if root.as_os_str().is_empty() {
                return Err(HvError::new(
                    ErrorCode::InvalidArgument,
                    "empty guest path root",
                ));
            }
            let resolved = match root.canonicalize() {
                Ok(p) => p,
                Err(_) => normalize(root),
            };
            canon.push(resolved);
        }
        Ok(Self { roots: canon })
    }

    /// The canonicalized roots backing this policy.
    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Resolve `path` and require it to live under one of the roots.
    ///
    /// Symlinks and `..` are resolved before comparison (fail closed:
    /// an unresolvable path is rejected), and containment is checked
    /// component-wise, case-insensitively on Windows.
    ///
    /// # Errors
    /// [`HvError`] with code `PolicyDenied` when the path is empty,
    /// relative, contains NUL, is a UNC outside the roots, or resolves
    /// outside every root; `Internal` if canonicalization fails in an
    /// unexpected way (fail closed either way).
    pub fn resolve(&self, path: &Path) -> Result<ResolvedPath, HvError> {
        let raw = path.to_string_lossy();
        if path.as_os_str().is_empty() || raw.trim().is_empty() {
            return Err(HvError::new(ErrorCode::PolicyDenied, "empty guest path")
                .with_context("path", raw.as_ref()));
        }
        if raw.contains('\0') {
            return Err(
                HvError::new(ErrorCode::PolicyDenied, "NUL byte in guest path")
                    .with_context("path", raw.as_ref()),
            );
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            return Err(
                HvError::new(ErrorCode::PolicyDenied, "guest path must be absolute")
                    .with_context("path", raw.as_ref()),
            );
        };
        // UNC device paths (\\?\, \\.\, \\server\share) outside the
        // roots are rejected: canonicalize() may reintroduce \\?\.
        let resolved = match absolute.canonicalize() {
            Ok(p) => p,
            Err(_) => normalize(&absolute),
        };
        if raw.starts_with(r"\\") {
            let norm = normalize(&absolute).to_string_lossy().to_lowercase();
            let covered = self.roots.iter().any(|r| {
                let rs = normalize(r).to_string_lossy().to_lowercase();
                norm.starts_with(&rs)
            });
            if !covered {
                return Err(HvError::new(
                    ErrorCode::PolicyDenied,
                    "UNC path outside guest path roots",
                )
                .with_context("path", raw.as_ref()));
            }
        }
        let comps = components_lower(&resolved);
        for (idx, root) in self.roots.iter().enumerate() {
            let root_comps = components_lower(root);
            if comps.len() <= root_comps.len() {
                continue; // the root itself (or a prefix of it) is not inside it
            }
            if comps[..root_comps.len()] == root_comps[..] {
                return Ok(ResolvedPath {
                    canonical: resolved,
                    root_index: idx,
                });
            }
        }
        Err(HvError::new(
            ErrorCode::PolicyDenied,
            "guest path is outside the allowlisted roots",
        )
        .with_context("path", raw.as_ref()))
    }
}
