//! # hvlab-guest
//!
//! Guest execution over PowerShell Direct: a persistent sidecar child
//! process speaking length-prefixed JSON over stdin/stdout, with a
//! mandatory identity assertion (nonce echo) before any payload is
//! sent (H-36), out-of-band exit codes (H-05), SHA-256-verified file
//! transfer (H-08), and a component-wise guest path allowlist (H-33).

// `unwrap`/`expect` are legitimate in tests; production code denies them
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod path_policy;
pub mod protocol;
pub mod psdirect;
pub mod sidecar;

pub use path_policy::{PathPolicy, ResolvedPath};
pub use protocol::{FrameError, MAX_FRAME_LEN, read_frame, write_frame};
pub use psdirect::{ExecResult, ExecSpec, PsDirectSession, b64_decode, b64_encode, sha256_hex};
pub use sidecar::{SIDECAR_SCRIPT, sidecar_command, sidecar_script};

#[cfg(test)]
mod tests;
