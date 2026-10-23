//! Running `cdb.exe` against a dump and parsing its report.
//!
//! The engine's text output is the interchange format; the parse layer
//! is [`hvlab_dump::analyze`]. Success is never inferred from the exit
//! code alone (H-01): a run counts as analyzed only when the output
//! yielded a parsed report. cdb writes its failure banner to stdout and
//! still exits 0 in some failure modes, so the evidence is the text.

use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use hvlab_core::error::{ErrorCode, HvError};
use hvlab_dump::analyze::{ParsedAnalyze, parse_analyze_text};

use crate::cache;
use crate::cdb::cdb_path;

/// Options for a `cdb` analysis run.
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// Symbol path passed as `-y`. Empty means inherit cdb's default.
    pub symbol_path: Option<String>,
    /// Kill the child and fail if it runs longer than this. Default 300 s.
    pub timeout: Duration,
    /// Keep at most this many bytes of raw log around the tail;
    /// older bytes are dropped and declared (H-48).
    pub max_log_bytes: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            symbol_path: None,
            timeout: Duration::from_secs(300),
            max_log_bytes: 2_000_000,
        }
    }
}

/// Explicit truncation flags on the captured raw log (H-48): a silent
/// slice is never reported as the whole log.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Truncation {
    /// The log was shortened; bytes exist that are not in `raw_log`.
    pub truncated: bool,
    /// How many bytes at the head of the log were dropped.
    pub dropped_bytes: usize,
}

/// One completed cdb analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Analysis {
    /// Structured fields parsed from the `!analyze -v` report.
    pub parsed: ParsedAnalyze,
    /// Bounded raw debugger output, tail-kept.
    pub raw_log: String,
    /// Truncation declaration for `raw_log`.
    pub truncation: Truncation,
    /// cdb process exit code, when it exited on its own.
    pub exit_code: Option<i32>,
    /// Seconds the run took.
    pub elapsed_secs: f64,
    /// The debugger executable that produced this.
    pub cdb_path: String,
}

/// Result of spawning cdb: captured streams and exit status.
struct RunOutput {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed: Duration,
}

/// Keep the tail of `text`, declaring what was dropped.
fn bound_log(text: &str, max_bytes: usize) -> (String, Truncation) {
    let bytes = text.as_bytes();
    if bytes.len() <= max_bytes {
        return (text.to_string(), Truncation::default());
    }
    // Drop whole bytes from the head; never split a UTF-8 scalar at the
    // new head either.
    let dropped = bytes.len() - max_bytes;
    let mut start = dropped;
    while start < bytes.len() && (bytes[start] & 0xC0) == 0x80 {
        start += 1;
    }
    let kept = String::from_utf8_lossy(&bytes[start..]).into_owned();
    (
        kept,
        Truncation {
            truncated: true,
            dropped_bytes: dropped,
        },
    )
}

/// Build the cdb command line: `!analyze -v` first, then `kv` and `lm`.
fn command_script() -> &'static str {
    "!analyze -v; kv; lm; q"
}

/// Run cdb synchronously, reading both streams, with a hard timeout.
fn run_cdb(cdb: &Path, dump_path: &Path, opts: &AnalyzeOptions) -> Result<RunOutput, HvError> {
    let mut cmd = std::process::Command::new(cdb);
    cmd.arg("-z").arg(dump_path);
    if let Some(sym) = &opts.symbol_path {
        cmd.arg("-y").arg(sym);
    }
    cmd.arg("-c").arg(command_script());
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // No console window; this crate never shows the debugger UI.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| HvError::new(ErrorCode::Debugger, format!("failed to spawn cdb: {e}")))?;

    // Drain both streams concurrently so a full pipe cannot deadlock
    // the child; bounded buffers are enforced after the fact on the
    // joined log, not by losing data mid-read.
    let mut stdout_pipe = child.stdout.take().map(std::io::BufReader::new);
    let mut stderr_pipe = child.stderr.take().map(std::io::BufReader::new);
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(p) = stdout_pipe.as_mut() {
            let _ = p.read_to_string(&mut buf);
        }
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(p) = stderr_pipe.as_mut() {
            let _ = p.read_to_string(&mut buf);
        }
        buf
    });

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if start.elapsed() >= opts.timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(HvError::new(
                    ErrorCode::Debugger,
                    format!("cdb wait failed: {e}"),
                ));
            }
        }
    };

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();
    Ok(RunOutput {
        stdout,
        stderr,
        exit_code: status.and_then(|s| s.code()),
        timed_out,
        elapsed: start.elapsed(),
    })
}

/// Analyze a dump with `cdb` and parse the report.
///
/// The dump path is validated before the debugger is located (H-02
/// order: name the missing artifact, not the missing dependency).
///
/// # Errors
///
/// - [`ErrorCode::NotFound`] when the dump file does not exist.
/// - [`ErrorCode::Unsupported`] when no `cdb.exe` was discovered.
/// - [`ErrorCode::Timeout`] when the run exceeded `opts.timeout`; the
///   partial log is attached.
/// - [`ErrorCode::Debugger`] when cdb produced no parseable report
///   (H-01: exit code alone never confers success).
pub fn analyze(dump_path: &Path, opts: &AnalyzeOptions) -> Result<Analysis, HvError> {
    if !dump_path.is_file() {
        return Err(HvError::new(
            ErrorCode::NotFound,
            format!("dump file not found: {}", dump_path.display()),
        ));
    }

    let cdb = cdb_path().into_result()?;

    let run = run_cdb(cdb.0.as_path(), dump_path, opts)?;
    let mut combined = run.stdout.clone();
    if !run.stderr.trim().is_empty() {
        combined.push_str("\n--- stderr ---\n");
        combined.push_str(&run.stderr);
    }

    if run.timed_out {
        let (log, trunc) = bound_log(&combined, opts.max_log_bytes);
        return Err(HvError::new(
            ErrorCode::Timeout,
            format!("cdb analysis exceeded timeout of {:?}", opts.timeout),
        )
        .with_partial(serde_json::json!({ "raw_log": log, "truncation": trunc })));
    }

    let parsed = match parse_analyze_text(&combined) {
        Ok(p) => p,
        Err(e) => {
            let (log, trunc) = bound_log(&combined, opts.max_log_bytes);
            return Err(HvError::new(
                ErrorCode::Debugger,
                format!("cdb output was not an !analyze report: {e}"),
            )
            .with_context("exit_code", serde_json::json!(run.exit_code))
            .with_partial(serde_json::json!({ "raw_log": log, "truncation": trunc })));
        }
    };

    let (raw_log, truncation) = bound_log(&combined, opts.max_log_bytes);
    Ok(Analysis {
        parsed,
        raw_log,
        truncation,
        exit_code: run.exit_code,
        elapsed_secs: run.elapsed.as_secs_f64(),
        cdb_path: cdb.0.display().to_string(),
    })
}

/// Analyze a dump, reusing a fresh cache entry when one exists.
///
/// A cache write failure is not fatal — the analysis itself succeeded
/// and is returned — but a cache *read* failure is indistinguishable
/// from a miss by design, so it simply re-runs the debugger.
///
/// # Errors
///
/// Same as [`analyze`].
pub fn analyze_cached(
    dump_path: &Path,
    opts: &AnalyzeOptions,
    cache_dir: &Path,
    ttl: std::time::Duration,
) -> Result<(Analysis, bool), HvError> {
    if let Some((analysis, _)) = cache::lookup(cache_dir, dump_path, ttl) {
        return Ok((analysis, true));
    }
    let analysis = analyze(dump_path, opts)?;
    let _ = cache::store(cache_dir, dump_path, &analysis, ttl);
    Ok((analysis, false))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn bound_log_keeps_tail_and_declares_drop() {
        let text = "abcdefghij".repeat(100); // 1000 bytes ascii
        let (log, t) = bound_log(&text, 100);
        assert!(t.truncated);
        assert_eq!(t.dropped_bytes, 900);
        assert_eq!(log.len(), 100);
        assert!(text.ends_with(&log));
    }

    #[test]
    fn bound_log_noop_under_limit() {
        let (log, t) = bound_log("hello", 100);
        assert!(!t.truncated);
        assert_eq!(t.dropped_bytes, 0);
        assert_eq!(log, "hello");
    }

    #[test]
    fn bound_log_does_not_split_utf8() {
        let text = "é".repeat(50); // 100 bytes
        let (log, t) = bound_log(&text, 99);
        assert!(t.truncated);
        assert!(log.starts_with('é') || log.is_empty());
        assert_eq!(log.chars().count(), 49);
    }

    #[test]
    fn missing_dump_errors_before_dependency_check() {
        let err = analyze(
            Path::new(r"C:\nope\missing.dmp"),
            &AnalyzeOptions::default(),
        )
        .expect_err("must fail");
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(!err.context.contains_key("searched_paths"));
    }

    #[test]
    fn command_puts_analyze_first() {
        let script = command_script();
        assert!(script.starts_with("!analyze -v"));
        assert!(script.ends_with('q'));
    }
}
