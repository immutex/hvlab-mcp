//! # hvlab-core
//!
//! Domain types shared by every `hvlab` crate: identifiers, the error
//! taxonomy, VM state decoding, and plan-token digests.
//!
//! This crate is pure Rust with no Windows dependencies, so the whole
//! core tests on any OS.

// `unwrap`/`expect` are legitimate in tests; production code denies them
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod error;
pub mod ids;
pub mod plan;
pub mod vm_state;

pub use error::{ErrorCode, HvError};
pub use ids::{JobId, PlanId, VmId};
pub use plan::{Plan, PlanError, PlanStep};
pub use vm_state::VmState;
