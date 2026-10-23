//! Disk cache for cdb analyses.
//!
//! Key: SHA-256 over dump path + file size + mtime, so editing or
//! regenerating a dump invalidates the entry. Value: the serialized
//! [`Analysis`]. Default TTL is one day; entries older than the TTL are
//! a miss and are removed on lookup.

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hvlab_core::error::{ErrorCode, HvError};
use sha2::{Digest, Sha256};

use crate::analyze::Analysis;

/// Environment variable overriding the cache root (tests set this).
pub const CACHE_DIR_ENV: &str = "HVLAB_CACHE_DIR";

/// Default cache location: `%LOCALAPPDATA%\hvlab\cache`.
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CACHE_DIR_ENV) {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("LOCALAPPDATA").map_or_else(std::env::temp_dir, PathBuf::from);
    base.join("hvlab").join("cache")
}

/// Cache entry wrapper: value plus the timestamp it was written.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    analysis: Analysis,
    written_at: u64,
}

/// `SystemTime` as unix seconds; times before the epoch clamp to zero.
fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Fingerprint a dump file: path, size, mtime.
///
/// # Errors
///
/// [`ErrorCode::NotFound`] when metadata cannot be read.
pub fn cache_key(dump_path: &Path) -> Result<String, HvError> {
    let meta = std::fs::metadata(dump_path).map_err(|e| {
        HvError::new(
            ErrorCode::NotFound,
            format!("cannot stat dump for cache key: {}", dump_path.display()),
        )
        .with_context("io_error", serde_json::json!(e.to_string()))
    })?;
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
    let fingerprint = format!(
        "{}|{}|{}",
        dump_path.display(),
        meta.len(),
        unix_secs(mtime)
    );
    let digest = Sha256::digest(fingerprint.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Where an entry for `key` lives on disk.
fn entry_path(cache_dir: &Path, key: &str) -> PathBuf {
    cache_dir.join(format!("{key}.json"))
}

/// Store an analysis. Best effort for the directory: a missing cache
/// root is created; an unwritable root is an error, not a silent skip.
///
/// # Errors
///
/// [`ErrorCode::Transport`] when the entry cannot be written.
pub fn store(
    cache_dir: &Path,
    dump_path: &Path,
    analysis: &Analysis,
    ttl: Duration,
) -> Result<(), HvError> {
    let key = cache_key(dump_path)?;
    std::fs::create_dir_all(cache_dir).map_err(|e| {
        HvError::new(
            ErrorCode::Transport,
            format!("cannot create cache dir {}", cache_dir.display()),
        )
        .with_context("io_error", serde_json::json!(e.to_string()))
    })?;
    let entry = CacheEntry {
        analysis: analysis.clone(),
        written_at: unix_secs(SystemTime::now()),
    };
    let json = serde_json::to_string(&entry).map_err(|e| {
        HvError::new(ErrorCode::Internal, "failed to serialize cache entry")
            .with_context("io_error", serde_json::json!(e.to_string()))
    })?;
    let tmp = entry_path(cache_dir, &format!("{key}.tmp"));
    let final_path = entry_path(cache_dir, &key);
    std::fs::write(&tmp, json).map_err(|e| {
        HvError::new(ErrorCode::Transport, "failed to write cache entry")
            .with_context("io_error", serde_json::json!(e.to_string()))
    })?;
    std::fs::rename(&tmp, &final_path).map_err(|e| {
        HvError::new(ErrorCode::Transport, "failed to finalize cache entry")
            .with_context("io_error", serde_json::json!(e.to_string()))
    })?;
    let _ = ttl; // TTL is applied at read time; stored for symmetry.
    Ok(())
}

/// Look up a cached analysis; `None` on miss, TTL expiry, or unreadable
/// entry. An expired entry is deleted as a side effect.
#[must_use]
pub fn lookup(cache_dir: &Path, dump_path: &Path, ttl: Duration) -> Option<(Analysis, SystemTime)> {
    let key = cache_key(dump_path).ok()?;
    let path = entry_path(cache_dir, &key);
    let text = std::fs::read_to_string(&path).ok()?;
    let entry: CacheEntry = serde_json::from_str(&text).ok()?;
    let written = UNIX_EPOCH + Duration::from_secs(entry.written_at);
    let age = SystemTime::now()
        .duration_since(written)
        .unwrap_or(Duration::ZERO);
    if age > ttl {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    Some((entry.analysis, written))
}

/// Default TTL: one day.
#[must_use]
pub fn default_ttl() -> Duration {
    Duration::from_secs(86_400)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hvlab-debug-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_dump(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"PAGEDU64fake").unwrap();
        p
    }

    fn sample_analysis() -> Analysis {
        let text =
            "BUGCHECK_CODE:  9f\nMODULE_NAME: mydrv\nSTACK_TEXT: \n00 fffff800`000 nt!KiBugCheck\n";
        Analysis {
            parsed: hvlab_dump::analyze::parse_analyze_text(text).unwrap(),
            raw_log: text.to_string(),
            truncation: crate::analyze::Truncation::default(),
            exit_code: Some(0),
            elapsed_secs: 1.0,
            cdb_path: r"C:\fake\cdb.exe".to_string(),
        }
    }

    #[test]
    fn store_and_lookup_round_trip() {
        let dir = temp_dir("roundtrip");
        let dump = fake_dump(&dir, "a.dmp");
        let a = sample_analysis();
        store(&dir, &dump, &a, default_ttl()).unwrap();
        let (got, written) = lookup(&dir, &dump, default_ttl()).expect("hit");
        assert_eq!(got.parsed, a.parsed);
        assert_eq!(got.raw_log, a.raw_log);
        assert!(written <= SystemTime::now());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_expiry_is_a_miss() {
        let dir = temp_dir("ttl");
        let dump = fake_dump(&dir, "b.dmp");
        let a = sample_analysis();
        store(&dir, &dump, &a, default_ttl()).unwrap();
        // Entry was written "now"; a zero TTL makes it immediately stale.
        assert!(lookup(&dir, &dump, Duration::ZERO).is_none());
        // The expired entry was removed.
        let key = cache_key(&dump).unwrap();
        assert!(!dir.join(format!("{key}.json")).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_file_invalidates_key() {
        let dir = temp_dir("invalidate");
        let dump = fake_dump(&dir, "c.dmp");
        let k1 = cache_key(&dump).unwrap();
        // Rewrite with a different size; mtime alone can be coarse.
        std::fs::write(&dump, b"PAGEDU64fake-and-longer").unwrap();
        let k2 = cache_key(&dump).unwrap();
        assert_ne!(k1, k2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_dump_is_not_found() {
        let err = cache_key(Path::new(r"C:\nope\x.dmp")).expect_err("must fail");
        assert_eq!(err.code, ErrorCode::NotFound);
    }
}
