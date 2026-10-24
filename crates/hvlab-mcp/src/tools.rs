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
    /// Plan confirmation from `hv_plan`, bound to these arguments.
    pub confirm: ConfirmArgs,
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
    /// Plan confirmation from `hv_plan`, bound to these arguments.
    pub confirm: ConfirmArgs,
}

/// Result of a checkpoint mutation.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CheckpointMutationResult {
    /// `created`, `deleted`, or `restored`.
    pub action: String,
    /// The checkpoint as observed after the operation, when it still exists.
    pub checkpoint: Option<CheckpointEntry>,
}

// ── Plan family types ────────────────────────────────────────────────────

/// Input for `hv_plan`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanArgs {
    /// Name of the plan-gated tool to authorize (class D or X).
    pub action: String,
    /// The exact arguments that call will be made with.
    pub args: serde_json::Value,
}

/// Result of `hv_plan`: a token bound to `action` + `args`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct PlanResult {
    /// Plan identifier to echo back in `confirm`.
    pub plan_id: String,
    /// Hex digest binding the token to the action and arguments.
    pub digest: String,
    /// When the token expires (RFC 3339, five minutes from minting).
    pub expires_at: String,
    /// One-line description of the authorized operation.
    pub summary: String,
}

// ── Host family types ────────────────────────────────────────────────────

/// Result of `hv_host_info`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct HostInfoResult {
    /// Host computer system name.
    pub name: String,
    /// Logical CPU count.
    pub cpu_count: u32,
    /// Physical memory in bytes.
    pub ram_bytes: u64,
    /// Host computer system state.
    pub state: String,
}

/// One service's state.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ServiceEntry {
    /// Service name.
    pub name: String,
    /// `Running`, `Stopped`, and friends.
    pub state: String,
    /// `Auto`, `Manual`, `Disabled`.
    pub start_mode: String,
}

/// Result of `hv_host_services`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct HostServicesResult {
    /// Hyper-V-related services.
    pub services: Vec<ServiceEntry>,
}

/// Result of `hv_host_storage_roots`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct StorageRootsResult {
    /// Default VHD folder; `None` when the VMMS settings are not visible
    /// to this caller (UAC token filtering) — never an empty string.
    pub default_vhd_path: Option<String>,
    /// Default VM configuration folder, when configured and visible.
    pub default_vm_path: Option<String>,
}

/// Result of `hv_host_default_switch`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DefaultSwitchResult {
    /// Name of the first virtual switch, when one exists.
    pub switch: Option<String>,
}

// ── VM lifecycle types ───────────────────────────────────────────────────

/// Input for `hv_vm_start`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmStartArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Seconds to wait for the transition. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_vm_stop`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmStopArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// `shutdown` (graceful via integration services), `save`, or `turnoff`.
    pub mode: String,
    /// Seconds to wait for the transition. Defaults to 180.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_vm_restart`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmRestartArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Seconds to wait for the transition. Defaults to 180.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_vm_wait_state`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmWaitStateArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Acceptable terminal states: `off`, `running`, `paused`, `saved`.
    pub states: Vec<String>,
    /// Seconds to keep polling. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_vm_rename`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmRenameArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// New display name.
    pub new_name: String,
}

// ── VM config types ──────────────────────────────────────────────────────

/// Result of `hv_vm_get_config`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VmConfigResult {
    /// Startup memory in MB.
    pub memory_mb: u64,
    /// Whether dynamic memory is enabled.
    pub dynamic_memory: bool,
    /// Dynamic memory buffer percentage, when set.
    pub buffer_pct: Option<u8>,
    /// Virtual processor count.
    pub processor_count: u32,
    /// Notes field, when set.
    pub notes: Option<String>,
    /// Whether nested virtualization extensions are exposed.
    pub nested_virt: bool,
}

/// Diff of one configuration field.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ConfigDiff {
    /// Field that changed (or would change).
    pub field: String,
    /// Value before (or current, for a dry run).
    pub before: serde_json::Value,
    /// Value after (or proposed, for a dry run).
    pub after: serde_json::Value,
}

/// Input for `hv_vm_set_notes`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmSetNotesArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// New notes text.
    pub notes: String,
    /// Preview the diff without applying. Defaults to true.
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

/// Input for `hv_vm_set_memory`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmSetMemoryArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Startup memory in MB.
    pub memory_mb: u64,
    /// Enable dynamic memory. Defaults to false.
    #[serde(default)]
    pub dynamic: bool,
    /// Dynamic memory buffer percentage (5–95).
    #[serde(default)]
    pub buffer_pct: Option<u8>,
    /// Preview the diff without applying. Defaults to true.
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

/// Input for `hv_vm_set_processor`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VmSetProcessorArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Virtual processor count.
    pub count: u32,
    /// Preview the diff without applying. Defaults to true.
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

fn default_true() -> bool {
    true
}

// ── VHD family types ─────────────────────────────────────────────────────

/// Input for `hv_vhd_create`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VhdCreateArgs {
    /// Destination path for the new disk.
    pub path: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// `vhd` or `vhdx`. Defaults to `vhdx`.
    #[serde(default)]
    pub format: Option<String>,
    /// Block size in bytes, when the format supports it.
    #[serde(default)]
    pub block_size: Option<u32>,
    /// Seconds to wait for the job. Defaults to 300.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_vhd_inspect` / `hv_vhd_get`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VhdInspectArgs {
    /// Path to the disk file.
    pub path: String,
}

/// Disk inspection result.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VhdInfoResult {
    /// Disk file path.
    pub path: String,
    /// `vhd`, `vhdx`, `vhdx-set`.
    pub format: String,
    /// Virtual (guest-visible) size in bytes.
    pub size_bytes: u64,
    /// Size on disk in bytes, when reported.
    pub file_size_bytes: Option<u64>,
    /// Block size in bytes, when reported.
    pub block_size: Option<u64>,
    /// Parent disk path for a differencing disk.
    pub parent_path: Option<String>,
}

/// Live state of a disk file.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VhdStateResult {
    /// Disk file path.
    pub path: String,
    /// Whether the provider considers the file attached/in use.
    pub in_use: bool,
    /// Size on disk in bytes, when reported.
    pub file_size_bytes: Option<u64>,
    /// Free space inside the disk, when the provider reports it.
    pub free_space_bytes: Option<u64>,
}

/// Input for `hv_vhd_resize`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VhdResizeArgs {
    /// Path to the disk file.
    pub path: String,
    /// New virtual size in bytes.
    pub size_bytes: u64,
    /// Seconds to wait for the job. Defaults to 300.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_vhd_compact`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VhdCompactArgs {
    /// Path to the disk file.
    pub path: String,
    /// Seconds to wait for the job. Defaults to 600.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

// ── Switch family types ──────────────────────────────────────────────────

/// Result of `hv_switch_list`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SwitchListResult {
    /// Switch names.
    pub switches: Vec<String>,
}

/// Input for `hv_switch_create`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SwitchCreateArgs {
    /// Name for the new switch.
    pub name: String,
    /// `internal` or `private`. `external` exists in the backend but is
    /// never exposed here: binding a physical NIC can take the host offline.
    pub kind: String,
    /// Seconds to wait for the job. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_switch_remove`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SwitchRemoveArgs {
    /// Switch name.
    pub name: String,
    /// Seconds to wait for the job. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Result of `hv_switch_remove`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SwitchRemoveResult {
    /// Whether removal completed.
    pub removed: bool,
}

// ── NIC / device family types ────────────────────────────────────────────

/// Input for `hv_nic_connect`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NicConnectArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Switch name to connect to.
    pub switch: String,
    /// Seconds to wait for the job. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_nic_disconnect`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NicDisconnectArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Seconds to wait for the job. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_device_add_disk`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AddDiskArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Path to the VHD/VHDX file to attach.
    pub path: String,
    /// Seconds to wait for the job. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Input for `hv_device_remove_disk`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoveDiskArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Path of the attached disk to detach.
    pub path: String,
    /// Seconds to wait for the job. Defaults to 120.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// Result of a device mutation.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DeviceMutationResult {
    /// `attached` or `detached`.
    pub action: String,
}

// ── Guest family types ───────────────────────────────────────────────────

/// The `confirm` argument D/X tools carry, bound to the other arguments.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfirmArgs {
    /// Plan id from `hv_plan`.
    pub plan_id: String,
    /// Digest from `hv_plan`.
    pub digest: String,
}

/// Input for `hv_guest_ping`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestPingArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
}

/// Result of `hv_guest_ping`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct GuestPingResult {
    /// Hostname the guest reports, verified by the identity assertion.
    pub hostname: String,
}

/// Input for `hv_guest_exec`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestExecArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// Program to run, absolute path preferred. No shell.
    pub program: String,
    /// Argument vector.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Seconds to allow the program to run. Defaults to 60.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Plan confirmation from `hv_plan`, bound to these arguments.
    pub confirm: ConfirmArgs,
}

/// Result of a guest execution.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct GuestExecResult {
    /// Process exit code.
    pub exit_code: i64,
    /// Standard output (UTF-8 lossy).
    pub stdout: String,
    /// Standard error (UTF-8 lossy).
    pub stderr: String,
}

/// Input for `hv_guest_powershell`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GuestPowershellArgs {
    /// VM identifier (GUID) or display name.
    pub vm: String,
    /// PowerShell script text, encoded before sending; never interpolated.
    pub script: String,
    /// Seconds to allow the script to run. Defaults to 60.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Plan confirmation from `hv_plan`, bound to these arguments.
    pub confirm: ConfirmArgs,
}

// ── Dump find/analyze types ──────────────────────────────────────────────

/// Input for `hv_dump_find`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DumpFindArgs {
    /// Maximum number of dumps to return. Defaults to 25.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One discovered dump file.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DumpEntry {
    /// Absolute path.
    pub path: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Modification time (RFC 3339), when readable.
    pub modified: Option<String>,
}

/// Result of `hv_dump_find`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DumpFindResult {
    /// Newest dumps first.
    pub dumps: Vec<DumpEntry>,
    /// Dumps beyond the limit.
    pub skipped_by_limit: u64,
    /// Roots that could not be read.
    pub unreadable_roots: Vec<String>,
}

/// Input for `hv_dump_analyze`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DumpAnalyzeArgs {
    /// Path to the crash dump.
    pub path: String,
}

/// Structured result of a cdb `!analyze -v` run.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DumpAnalyzeResult {
    /// Bugcheck code, when the dump carries one.
    pub bugcheck_code: Option<String>,
    /// Module the analysis blames.
    pub module_name: Option<String>,
    /// Image file name.
    pub image_name: Option<String>,
    /// The engine's own classification bucket.
    pub failure_bucket_id: Option<String>,
    /// Process name in the faulting context, when present.
    pub process_name: Option<String>,
    /// Stack frame summaries.
    pub stack: Vec<String>,
    /// Whether the raw log was truncated (older bytes dropped, declared).
    pub truncated: bool,
    /// Bytes dropped from the head of the raw log.
    pub dropped_bytes: u64,
    /// Whether the result came from the on-disk cache.
    pub cached: bool,
    /// Bounded raw debugger log.
    pub raw_log: String,
}

/// Result of `hv_capabilities`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CapabilitiesResult {
    /// Server crate version.
    pub version: String,
    /// MCP protocol version served.
    pub protocol_version: String,
    /// Number of registered tools.
    pub tool_count: u64,
    /// Whether the Hyper-V WMI namespace answered a cheap probe.
    pub hyper_v_present: bool,
}

/// Result of `hv_tools_list`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolListResult {
    /// Registered tool names with safety classes.
    pub tools: Vec<ToolEntry>,
    /// Total registered tools, before any filter or profile is applied.
    pub total_registered: u64,
    /// The advertisement profile this server is running (`core`, `full`,
    /// `readonly`, `custom`). Tools outside it are still callable by
    /// name; use `hv_tools_search` to find them.
    pub profile: String,
}

/// One tool name + class.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolEntry {
    /// Tool name.
    pub name: String,
    /// Safety class: `R`, `M`, `D`, or `X`.
    pub class: String,
    /// Family, for grouping and filtering (`vm`, `guest`, `dump`, ...).
    pub family: String,
    /// Whether this tool appears in `tools/list` under the active profile.
    pub advertised: bool,
}

/// Input for `hv_tools_search`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct ToolSearchArgs {
    /// Case-insensitive substring to match against tool names, families,
    /// or classes. Empty returns the whole catalogue.
    #[serde(default)]
    pub query: Option<String>,
    /// Restrict to one family: meta, host, vm, checkpoint, storage,
    /// network, device, guest, dump.
    #[serde(default)]
    pub family: Option<String>,
    /// Restrict to one safety class: R, M, D, or X.
    #[serde(default)]
    pub class: Option<String>,
    /// Only tools advertised under the active profile.
    #[serde(default)]
    pub advertised_only: bool,
}

/// Result of `hv_tools_search`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolSearchResult {
    /// Matching tools, name + class + family + one-line purpose.
    pub tools: Vec<ToolSummary>,
    /// How many matched in total (before any display cap).
    pub matched: u64,
}

/// A tool as returned by search: enough to choose it, without schemas.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolSummary {
    /// Tool name — pass this to `hv_tools_describe` for its full schema.
    pub name: String,
    /// Safety class: `R`, `M`, `D`, or `X`.
    pub class: String,
    /// Family.
    pub family: String,
    /// First sentence of the tool's description.
    pub purpose: String,
    /// Whether it is advertised under the active profile.
    pub advertised: bool,
}

/// Input for `hv_tools_describe`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ToolDescribeArgs {
    /// Tool name, as returned by `hv_tools_search` or `hv_tools_list`.
    pub name: String,
}

/// Result of `hv_tools_describe`: the full definition for one tool.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolDescribeResult {
    /// Tool name.
    pub name: String,
    /// Safety class.
    pub class: String,
    /// Family.
    pub family: String,
    /// Full description.
    pub description: String,
    /// Whether it requires a plan token (classes D and X do).
    pub needs_plan: bool,
    /// The exact JSON Schema for this tool's arguments.
    pub input_schema: serde_json::Value,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// The `confirm` args for a D/X call must be the tool's args minus
    /// `confirm`; mirror the server's `authorize` stripping here so the
    /// store test stays honest about what is digested.
    fn args_without_confirm(json: &str) -> serde_json::Value {
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        v.as_object_mut().unwrap().remove("confirm");
        v
    }

    #[test]
    fn confirm_args_roundtrip() {
        let c: ConfirmArgs =
            serde_json::from_str(r#"{"plan_id": "abc", "digest": "def"}"#).unwrap();
        assert_eq!(c.plan_id, "abc");
        assert_eq!(c.digest, "def");
    }

    #[test]
    fn delete_args_strip_to_minted_digest_input() {
        let raw = r#"{"vm":"v","checkpoint":"c","include_subtree":false,"timeout_secs":null,"confirm":{"plan_id":"p","digest":"d"}}"#;
        let stripped = args_without_confirm(raw);
        let obj = stripped.as_object().unwrap();
        assert!(!obj.contains_key("confirm"));
        assert_eq!(obj.get("vm").unwrap(), "v");
    }
}
