//! # hvlab-host
//!
//! Hyper-V WMI v2 management plane: VM inventory, lifecycle, and job
//! polling through `ROOT\virtualization\v2`.
//!
//! All WMI access is confined to this crate. Higher layers see plain
//! Rust types ([`VmSummary`], [`hvlab_core::vm_state::VmState`]) and [`hvlab_core::HvError`].

// `unwrap`/`expect` are legitimate in tests; production code denies them
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod job;
pub mod vm;

pub use job::{JobOutcome, WmiJobError};
pub use vm::{VmService, VmSummary};

#[cfg(test)]
mod tests;
