//! # hvlab-dump
//!
//! Parsing and triage for Windows crash dumps — pure Rust, no FFI, no
//! debugger engine required for the fast path.
//!
//! Two layers:
//!
//! 1. [`header`] reads the `DUMP_HEADER64` struct directly from the file.
//!    That is the sub-5-millisecond path: signature, dump kind, bugcheck
//!    code and its four parameters, before any mapping or symbol work.
//! 2. [`analyze`] parses the textual output of `!analyze -v` into
//!    structured fields, for cases where the text is already available
//!    (pasted into an agent transcript, saved from a debugger session).
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let header = hvlab_dump::header::DumpHeader64::read_from("C:/Windows/MEMORY.DMP")?;
//! println!("bugcheck: {:#x}", header.bug_check_code);
//! # Ok(())
//! # }
//! ```
//!
//! The offset constants in [`header`] are validated against `kdmp-parser`
//! by `offsets_match_kdmp_parser` in the test suite so a format change
//! upstream cannot desync this crate silently.

// `unwrap`/`expect` are legitimate in tests; production code denies them
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod analyze;
pub mod bugcheck;
pub mod header;

pub use analyze::{AnalyzeReport, ParsedAnalyze};
pub use bugcheck::{BugcheckInfo, bugcheck_name, format_bugcheck_code};
pub use header::{DumpHeader64, DumpKind, HeaderError};

#[cfg(test)]
mod tests;
