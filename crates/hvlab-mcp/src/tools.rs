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
