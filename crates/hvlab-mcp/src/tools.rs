//! Tool implementations. All tools live on [`crate::HvlabServer`] so
//! the registry is one `ToolRouter<HvlabServer>` — rmcp's composition
//! story for multiple families — with per-family argument/result types
//! kept here.

use rmcp::schemars;
use serde::{Deserialize, Serialize};

// ── Dump family types ────────────────────────────────────────────────────

/// Input for `hv_dump_inspect`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DumpInspectArgs {
    /// Path to the crash dump file.
    pub path: String,
}

/// Header fields of a crash dump.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DumpInspectResult {
    /// OS build that wrote the dump (major.minor).
    pub os_version: String,
    /// Decoded dump kind; `unknown(n)` for unrecognized types.
    pub dump_kind: String,
    /// Bugcheck code, padded to eight hex digits, as the debugger prints it.
    pub bugcheck_code: String,
    /// Documented symbolic name, when the code is in the public catalog.
    pub bugcheck_name: Option<String>,
    /// One-line meaning from the public catalog.
    pub description: Option<String>,
    /// Microsoft documentation link.
    pub reference: Option<String>,
    /// The four bugcheck parameters.
    pub args: [String; 4],
    /// Kernel CR3 at crash time.
    pub directory_table_base: String,
}

// ── VM family types ──────────────────────────────────────────────────────

/// Input for `hv_vm_list` (reserved for future filters).
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct VmListArgs {}

/// One VM in the inventory.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VmEntry {
    /// Stable identifier (WMI `Name` GUID).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Decoded power state.
    pub state: String,
}

/// Input for `hv_vm_get`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmGetArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
}

// ── Checkpoint family types ──────────────────────────────────────────────

/// Input for `hv_checkpoint_list`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointListArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
}

/// One checkpoint.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CheckpointEntry {
    /// `ConfigurationID`.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Creation time (RFC 3339) when the provider supplied one.
    pub created: Option<String>,
    /// Parent checkpoint id, when nested.
    pub parent: Option<String>,
    /// True for host-taken automatic checkpoints.
    pub automatic: bool,
}

/// Input for `hv_checkpoint_create`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointCreateArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Name for the new checkpoint.
    pub name: String,
    /// `standard` (memory + disk), `production` (VSS, disk only), or
    /// `disk_only`. Defaults to `standard`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Seconds to wait for the job. Defaults to 300.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_checkpoint_delete`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointDeleteArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Checkpoint name or `ConfigurationID`.
    pub checkpoint: String,
    /// Delete the checkpoint and everything below it.
    #[serde(default)]
    pub include_subtree: bool,
    /// Seconds to wait for the job. Defaults to 300.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_checkpoint_restore`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CheckpointRestoreArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Checkpoint name or `ConfigurationID`.
    pub checkpoint: String,
    /// Seconds to wait for the job. Defaults to 600.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Result of a checkpoint mutation.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CheckpointMutationResult {
    /// `created`, `deleted`, or `restored`.
    pub action: String,
    /// The checkpoint as observed after the operation, when it still exists.
    pub checkpoint: Option<CheckpointEntry>,
}
