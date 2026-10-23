//! `hvlab-debug`: debugger-driven crash dump analysis for hvlab.
//!
//! Bridges the debugger engine's text output to hvlab's structured
//! world. The engine (`cdb.exe`) is located once per process, spawned
//! with a hard timeout, and its `!analyze -v` report is parsed by
//! [`hvlab_dump`]. Results are cached on disk keyed by the dump's
//! fingerprint.
//!
//! No FFI, no `unsafe`, no dbgeng COM — the subprocess boundary is the
//! isolation layer. Live KD attach is a later milestone.

// `unwrap`/`expect` are legitimate in tests; production code denies them
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod analyze;
pub mod cache;
pub mod cdb;
pub mod find;
pub mod stack;

pub use analyze::{Analysis, AnalyzeOptions, analyze_cached};
pub use cache::{default_cache_dir, default_ttl, lookup, store};
pub use cdb::{CdbPath, DBGENG_DIR_ENV, cdb_path};
pub use find::{FindResult, FoundDump, default_roots, find_dumps};
pub use stack::{StackLine, extract_stack};
