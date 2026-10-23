//! # hvlab-host
//!
//! Hyper-V WMI v2 management plane: VM inventory, lifecycle, and job
//! polling through `ROOT\virtualization\v2`.
//!
//! All WMI access is confined to this crate. Higher layers see plain
//! Rust types ([`VmSummary`], [`hvlab_core::vm_state::VmState`]) and [`hvlab_core::HvError`].

// `unwrap`/`expect` are legitimate in tests; production code denies them
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod checkpoint;
pub mod job;
pub mod network;
pub mod storage;
pub mod vm;
pub mod wmi_util;

pub use checkpoint::{Checkpoint, CheckpointKind, CheckpointService};
pub use job::{JobOutcome, WmiJobError};
pub use network::{NetworkService, Switch, SwitchKind, SwitchPort};
pub use storage::{DiskAttachment, DiskFormat, DiskInfo, DiskState, StorageService};
pub use vm::{VmService, VmSummary};

#[cfg(test)]
mod tests;
