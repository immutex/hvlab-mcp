//! # hvlab-mcp
//!
//! MCP server: tool registry, schemas, transports. Tools are thin
//! adapters over the backend crates; each carries an output schema and
//! a safety class. All `#[tool]` methods live on [`HvlabServer`] so the
//! registry is a single `ToolRouter<HvlabServer>`.
//!
//! Plan-gated tools are authorized centrally in
//! [`rmcp::ServerHandler::call_tool`] — before the router sees the call —
//! so the token digest is taken over the exact JSON the client sent.

use std::future::Future;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hvlab_core::error::ErrorCode;
use rmcp::{
    handler::server::wrapper::{Json, Parameters},
    model::ServerConfig,
    service::ServiceExt,
    tool, tool_handler, tool_router,
    transport::stdio,
};

pub mod plans;
pub mod profile;
pub mod registry;
pub mod tools;
pub use plans::{PlanConfirm, PlanMintResult, PlanStore};
pub use tools::{
    CheckpointCreateArgs, CheckpointDeleteArgs, CheckpointEntry, CheckpointListArgs,
    CheckpointMutationResult, CheckpointRestoreArgs, DumpInspectArgs, DumpInspectResult, VmEntry,
    VmGetArgs,
};
// Tool bodies reference the wide wire-type surface directly.
#[allow(
    clippy::wildcard_imports,
    reason = "the wide tool-body wire-type surface is the point"
)]
use tools::*;

/// Map a typed [`HvError`] onto the MCP wire (H-38: one error channel).
///
/// The JSON-RPC code distinguishes the coarse failure class, and the
/// `data` payload carries the full structured error — code, message,
/// retryability, correlation id, context, and any partial results — so
/// a client can machine-read failures instead of parsing message text.
fn mcp_err(e: &HvError) -> rmcp::ErrorData {
    use rmcp::ErrorData;
    let code = match e.code {
        // A malformed request or an unknown target is the client's
        // fault, not the server's: JSON-RPC invalid-params.
        ErrorCode::InvalidArgument | ErrorCode::NotFound => rmcp::model::ErrorCode::INVALID_PARAMS,
        // Every other hvlab code is a server-side outcome, not a
        // malformed client request; JSON-RPC has one bucket for that.
        _ => rmcp::model::ErrorCode::INTERNAL_ERROR,
    };
    let structured = serde_json::to_value(e).unwrap_or_else(|_| {
        serde_json::json!({
            "code": e.code.as_str(),
            "message": e.message,
        })
    });
    ErrorData::new(
        code,
        format!("{}: {}", e.code.as_str(), e.message),
        Some(structured),
    )
}

use hvlab_core::HvError;

fn io_err(path: &str, e: &std::io::Error) -> HvError {
    HvError::new(ErrorCode::Transport, format!("io error on {path}: {e}"))
}

/// The assembled hvlab server. Holds the plan-token store so D/X
/// authorizations survive across calls on the same server instance.
#[derive(Clone)]
pub struct HvlabServer {
    plans: std::sync::Arc<std::sync::Mutex<plans::PlanStore>>,
    profile: profile::Profile,
}

impl HvlabServer {
    /// Build the server with the `core` profile.
    #[must_use]
    pub fn new() -> Self {
        Self::with_profile(profile::Profile::Core)
    }

    /// Build the server with an explicit advertisement profile.
    ///
    /// The profile only decides what `tools/list` advertises; every
    /// registered tool stays callable by name under every profile.
    #[must_use]
    pub fn with_profile(profile: profile::Profile) -> Self {
        Self {
            plans: std::sync::Arc::new(std::sync::Mutex::new(plans::PlanStore::default())),
            profile,
        }
    }

    /// The active advertisement profile.
    #[must_use]
    pub fn profile(&self) -> &profile::Profile {
        &self.profile
    }

    /// Serve over stdio with the profile chosen by `HVLAB_TOOLS`.
    ///
    /// # Errors
    ///
    /// Transport or serve failures.
    pub async fn serve_stdio_with_env_profile(
        self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.serve_stdio().await
    }

    /// Lock the plan store, mapping a poisoned lock to an internal error.
    fn lock_plans(&self) -> std::sync::MutexGuard<'_, plans::PlanStore> {
        self.plans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Test seam: authorize from a raw JSON args value.
    #[cfg(test)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "test seam mirrors the JSON call shape"
    )]
    pub(crate) fn authorize_args(
        &self,
        action: &str,
        args: serde_json::Value,
    ) -> Result<(), rmcp::ErrorData> {
        self.authorize_value(action, &args)
    }

    /// Verify and consume a plan token for `action` from raw args.
    ///
    /// `args` must carry a `confirm` object (`{plan_id, digest}`); the
    /// remaining keys must be exactly what the token was minted for.
    fn authorize_value(
        &self,
        action: &str,
        args: &serde_json::Value,
    ) -> Result<(), rmcp::ErrorData> {
        let mut obj = match args {
            serde_json::Value::Object(o) => o.clone(),
            _ => {
                return Err(mcp_err(&HvError::new(
                    ErrorCode::Internal,
                    "args not an object",
                )));
            }
        };
        let confirm: plans::PlanConfirm = match obj.remove("confirm") {
            Some(c) => match serde_json::from_value(c) {
                Ok(c) => c,
                Err(e) => {
                    return Err(mcp_err(&HvError::invalid_argument(
                        "confirm",
                        &format!(
                            "plan confirmation is required and must be {{plan_id, digest}}: {e}"
                        ),
                    )));
                }
            },
            None => {
                return Err(mcp_err(&HvError::policy_denied(
                    "plan",
                    "this call requires a plan token: mint one with hv_plan for these exact arguments",
                )));
            }
        };
        self.lock_plans()
            .verify_and_consume(&confirm, action, &serde_json::Value::Object(obj))
            .map_err(|e| mcp_err(&e))
    }

    /// Authorize a plan-gated call and hand back the args to run with.
    ///
    /// The digest is taken over the **raw JSON** the client sent, because
    /// that is the only representation identical at mint time (`hv_plan`
    /// receives `arguments` verbatim) and at call time. Re-serializing
    /// the typed struct would inject serde defaults the client never
    /// wrote — which is exactly how a correctly minted token used to be
    /// rejected (see `plans::digest_for`).
    fn authorize_call(
        &self,
        action: &str,
        arguments: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, rmcp::ErrorData> {
        let value = serde_json::Value::Object(arguments.unwrap_or_default());
        self.authorize_value(action, &value)?;
        match value {
            serde_json::Value::Object(mut m) => {
                m.remove("confirm");
                Ok(m)
            }
            _ => Ok(serde_json::Map::new()),
        }
    }

    /// Classify a registered tool by name: `R`, `M`, `D`, or `X`.
    ///
    /// Delegates to [`registry`], which is the single source of truth for
    /// classes; an unknown name comes back class D (fail closed).
    #[must_use]
    pub fn tool_class(name: &str) -> &'static str {
        registry::class_of(name).as_str()
    }

    /// Run over stdio until the client disconnects.
    ///
    /// # Errors
    ///
    /// Transport or serve failures.
    pub async fn serve_stdio(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let service = self.serve(stdio()).await?;
        service.waiting().await?;
        Ok(())
    }
}

impl Default for HvlabServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
#[allow(clippy::unused_self, reason = "rmcp tool fns require a &self receiver")]
impl HvlabServer {
    /// The registered tool router: names, descriptions, and schemas for
    /// every tool this server exposes.
    #[must_use]
    pub fn router() -> rmcp::handler::server::router::tool::ToolRouter<Self> {
        Self::tool_router()
    }
    /// `hv_dump_inspect`.
    #[tool(
        description = "Inspect a Windows crash dump header: bugcheck code, its documented name, and parameters. Fast (< 5 ms), no debugger required."
    )]
    fn hv_dump_inspect(
        &self,
        Parameters(args): Parameters<DumpInspectArgs>,
    ) -> Result<Json<DumpInspectResult>, rmcp::ErrorData> {
        let header = hvlab_dump::DumpHeader64::read_from(&args.path).map_err(|e| {
            mcp_err(&match e {
                hvlab_dump::HeaderError::Io { source, .. } => io_err(&args.path, &source),
                other => HvError::new(ErrorCode::InvalidArgument, other.to_string()),
            })
        })?;
        // An unreadable extended header is a data problem worth
        // reporting, not an "unknown kind" to paper over (M-1: no
        // success-shaped lies about the file).
        let kind = header.read_kind(&args.path).map_err(|e| {
            mcp_err(&HvError::new(
                hvlab_core::error::ErrorCode::Transport,
                format!("reading dump kind from {}: {e}", args.path),
            ))
        })?;
        let info = hvlab_dump::bugcheck_name(header.bug_check_code);
        Ok(Json(DumpInspectResult {
            os_version: format!("{}.{}", header.os_version.0, header.os_version.1),
            dump_kind: kind.to_string(),
            bugcheck_code: hvlab_dump::format_bugcheck_code(header.bug_check_code),
            bugcheck_name: info.as_ref().map(|i| i.name.to_owned()),
            description: info.as_ref().map(|i| i.description.to_owned()),
            reference: info.as_ref().map(|i| i.doc_path.to_owned()),
            args: std::array::from_fn(|i| format!("{:#x}", header.bug_check_parameters[i])),
            directory_table_base: format!("{:#x}", header.directory_table_base),
        }))
    }

    /// `hv_vm_list`.
    #[tool(description = "List all Hyper-V VMs on the host with their states.")]
    fn hv_vm_list(&self) -> Result<Json<Vec<VmEntry>>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let vms = svc.list_vms().map_err(|e| mcp_err(&e))?;
        Ok(Json(
            vms.iter()
                .map(|v| VmEntry {
                    id: v.id.to_string(),
                    name: v.name.clone(),
                    state: v.state.to_string(),
                })
                .collect(),
        ))
    }

    /// `hv_vm_get`.
    #[tool(description = "Get one VM's state by GUID or display name.")]
    fn hv_vm_get(
        &self,
        Parameters(args): Parameters<VmGetArgs>,
    ) -> Result<Json<VmEntry>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let vm = resolve_vm(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        Ok(Json(VmEntry {
            id: vm.id.to_string(),
            name: vm.name,
            state: vm.state.to_string(),
        }))
    }

    /// `hv_checkpoint_list`.
    #[tool(description = "List a VM's checkpoints, newest first.")]
    fn hv_checkpoint_list(
        &self,
        Parameters(args): Parameters<CheckpointListArgs>,
    ) -> Result<Json<Vec<CheckpointEntry>>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let cps = hvlab_host::CheckpointService::connect()
            .map_err(|e| mcp_err(&e))?
            .list(id)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(cps.into_iter().map(entry).collect()))
    }

    /// `hv_checkpoint_create`.
    #[tool(
        description = "Take a checkpoint of a VM and name it. Kinds: standard (memory + disk), production (VSS, disk only), disk_only. Waits for the job and returns the checkpoint as observed on the host."
    )]
    fn hv_checkpoint_create(
        &self,
        Parameters(args): Parameters<CheckpointCreateArgs>,
    ) -> Result<Json<CheckpointMutationResult>, rmcp::ErrorData> {
        let kind = match args.kind.as_deref() {
            None => hvlab_host::CheckpointKind::Standard,
            Some(k) => k.parse().map_err(|e| mcp_err(&e))?,
        };
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let cp = hvlab_host::CheckpointService::connect()
            .map_err(|e| mcp_err(&e))?
            .create(id, &args.name, kind, args.timeout_secs.unwrap_or(300))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(CheckpointMutationResult {
            action: "created".into(),
            checkpoint: Some(entry(cp)),
        }))
    }

    /// `hv_checkpoint_delete`.
    #[tool(
        description = "Delete a checkpoint (class D). Mint a plan token with hv_plan for these exact arguments first, then pass confirm. Set include_subtree to remove every checkpoint below it too."
    )]
    fn hv_checkpoint_delete(
        &self,
        Parameters(args): Parameters<CheckpointDeleteArgs>,
    ) -> Result<Json<CheckpointMutationResult>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        hvlab_host::CheckpointService::connect()
            .map_err(|e| mcp_err(&e))?
            .delete(
                id,
                &args.checkpoint,
                args.include_subtree,
                args.timeout_secs.unwrap_or(300),
            )
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(CheckpointMutationResult {
            action: "deleted".into(),
            checkpoint: None,
        }))
    }

    /// `hv_checkpoint_restore`.
    #[tool(
        description = "Restore a checkpoint, discarding all state after it. Destructive (class D): mint a plan token with hv_plan for these exact arguments, then pass confirm."
    )]
    fn hv_checkpoint_restore(
        &self,
        Parameters(args): Parameters<CheckpointRestoreArgs>,
    ) -> Result<Json<CheckpointMutationResult>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        hvlab_host::CheckpointService::connect()
            .map_err(|e| mcp_err(&e))?
            .restore(id, &args.checkpoint, args.timeout_secs.unwrap_or(600))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(CheckpointMutationResult {
            action: "restored".into(),
            checkpoint: None,
        }))
    }

    /// `hv_plan`.
    #[tool(
        description = "Mint a plan token for one class-D or class-X call. Pass action (tool name) and the exact args the call will use; the returned digest is bound to them. Tokens expire in five minutes and are single-use."
    )]
    fn hv_plan(
        &self,
        Parameters(args): Parameters<PlanArgs>,
    ) -> Result<Json<PlanResult>, rmcp::ErrorData> {
        let (minted, _confirm) = self
            .lock_plans()
            .mint(&args.action, &args.args)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(PlanResult {
            plan_id: minted.plan_id,
            digest: minted.digest,
            expires_at: minted.expires_at,
            summary: minted.summary,
        }))
    }

    /// `hv_host_info`.
    #[tool(description = "Host computer system info: name, logical CPU count, RAM, state.")]
    fn hv_host_info(&self) -> Result<Json<HostInfoResult>, rmcp::ErrorData> {
        let svc = hvlab_host::HostService::connect().map_err(|e| mcp_err(&e))?;
        let info = svc.host_info().map_err(|e| mcp_err(&e))?;
        Ok(Json(HostInfoResult {
            name: info.name,
            cpu_count: info.cpu_count,
            ram_bytes: info.ram_bytes,
            state: info.state.to_string(),
        }))
    }

    /// `hv_host_services`.
    #[tool(
        description = "Hyper-V-related host services (vmms, vmicheartbeat, ...) with state and start mode."
    )]
    fn hv_host_services(&self) -> Result<Json<HostServicesResult>, rmcp::ErrorData> {
        let svc = hvlab_host::HostService::connect().map_err(|e| mcp_err(&e))?;
        let services = svc.host_services().map_err(|e| mcp_err(&e))?;
        Ok(Json(HostServicesResult {
            services: services
                .into_iter()
                .map(|s| ServiceEntry {
                    name: s.name,
                    state: s.state,
                    start_mode: s.start_mode,
                })
                .collect(),
        }))
    }

    /// `hv_host_storage_roots`.
    #[tool(description = "Default VHD and VM configuration folders from the VMMS settings.")]
    fn hv_host_storage_roots(&self) -> Result<Json<StorageRootsResult>, rmcp::ErrorData> {
        let svc = hvlab_host::HostService::connect().map_err(|e| mcp_err(&e))?;
        let roots = svc.host_storage_roots().map_err(|e| mcp_err(&e))?;
        Ok(Json(StorageRootsResult {
            default_vhd_path: roots.as_ref().map(|r| r.default_vhd_path.clone()),
            default_vm_path: roots.map(|r| r.default_vm_path),
        }))
    }

    /// `hv_host_default_switch`.
    #[tool(description = "Name of the first virtual switch on the host, when one exists.")]
    fn hv_host_default_switch(&self) -> Result<Json<DefaultSwitchResult>, rmcp::ErrorData> {
        let svc = hvlab_host::HostService::connect().map_err(|e| mcp_err(&e))?;
        let sw = svc.host_default_switch().map_err(|e| mcp_err(&e))?;
        Ok(Json(DefaultSwitchResult { switch: sw }))
    }

    /// `hv_vm_start`.
    #[tool(description = "Start a VM and wait until it reaches Running (or the deadline).")]
    fn hv_vm_start(
        &self,
        Parameters(args): Parameters<VmStartArgs>,
    ) -> Result<Json<VmEntry>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let deadline = Instant::now() + Duration::from_secs(args.timeout_secs.unwrap_or(120));
        let vm = svc
            .request_state(id, hvlab_host::REQUESTED_RUNNING, deadline)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(VmEntry {
            id: vm.id.to_string(),
            name: vm.name,
            state: vm.state.to_string(),
        }))
    }

    /// `hv_vm_stop`.
    #[tool(
        description = "Stop a VM: shutdown (graceful, needs integration services), save, or turnoff. Polls to a terminal state."
    )]
    fn hv_vm_stop(
        &self,
        Parameters(args): Parameters<VmStopArgs>,
    ) -> Result<Json<VmEntry>, rmcp::ErrorData> {
        let requested = match args.mode.as_str() {
            "shutdown" => hvlab_host::REQUESTED_SHUTDOWN,
            "turnoff" => hvlab_host::REQUESTED_OFF,
            "save" => hvlab_host::REQUESTED_SAVED,
            other => {
                return Err(mcp_err(&HvError::invalid_argument(
                    "mode",
                    &format!("unknown stop mode {other:?}; use shutdown, save, or turnoff"),
                )));
            }
        };
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let deadline = Instant::now() + Duration::from_secs(args.timeout_secs.unwrap_or(180));
        let vm = svc
            .request_state(id, requested, deadline)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(VmEntry {
            id: vm.id.to_string(),
            name: vm.name,
            state: vm.state.to_string(),
        }))
    }

    /// `hv_vm_restart`.
    #[tool(description = "Reboot a VM: requests the Reboot state and waits for it to settle.")]
    fn hv_vm_restart(
        &self,
        Parameters(args): Parameters<VmRestartArgs>,
    ) -> Result<Json<VmEntry>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let deadline = Instant::now() + Duration::from_secs(args.timeout_secs.unwrap_or(180));
        let vm = svc
            .request_state(id, hvlab_host::REQUESTED_REBOOT, deadline)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(VmEntry {
            id: vm.id.to_string(),
            name: vm.name,
            state: vm.state.to_string(),
        }))
    }

    /// `hv_vm_wait_state`.
    #[tool(
        description = "Poll a VM's EnabledState until it reaches one of the requested states or the deadline. Useful after lifecycle calls and boots."
    )]
    fn hv_vm_wait_state(
        &self,
        Parameters(args): Parameters<VmWaitStateArgs>,
    ) -> Result<Json<VmEntry>, rmcp::ErrorData> {
        let mut targets = Vec::with_capacity(args.states.len());
        for s in &args.states {
            targets.push(parse_state(s).ok_or_else(|| {
                mcp_err(&HvError::invalid_argument(
                    "states",
                    &format!("unknown state {s:?}; use off, running, paused, or saved"),
                ))
            })?);
        }
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let deadline = Instant::now() + Duration::from_secs(args.timeout_secs.unwrap_or(120));
        let vm = svc
            .wait_state(id, &targets, deadline)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(VmEntry {
            id: vm.id.to_string(),
            name: vm.name,
            state: vm.state.to_string(),
        }))
    }

    /// `hv_vm_rename`.
    #[tool(description = "Rename a VM (display name change; the GUID is stable).")]
    fn hv_vm_rename(
        &self,
        Parameters(args): Parameters<VmRenameArgs>,
    ) -> Result<Json<VmEntry>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let vm = svc.rename(id, &args.new_name).map_err(|e| mcp_err(&e))?;
        Ok(Json(VmEntry {
            id: vm.id.to_string(),
            name: vm.name,
            state: vm.state.to_string(),
        }))
    }

    /// `hv_vm_get_config`.
    #[tool(
        description = "Read a VM's memory (MB, dynamic flag, buffer), processor count, notes, and nested-virtualization flag."
    )]
    fn hv_vm_get_config(
        &self,
        Parameters(args): Parameters<VmGetArgs>,
    ) -> Result<Json<VmConfigResult>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let cfg = hvlab_host::config::get_config(id).map_err(|e| mcp_err(&e))?;
        Ok(Json(VmConfigResult {
            memory_mb: cfg.memory_mb,
            dynamic_memory: cfg.dynamic_memory,
            buffer_pct: cfg.buffer_pct,
            processor_count: cfg.processor_count,
            notes: cfg.notes,
            nested_virt: cfg.nested_virt,
        }))
    }

    /// `hv_vm_set_notes`.
    #[tool(
        description = "Set a VM's notes field. dry_run (default true) returns the diff without applying."
    )]
    fn hv_vm_set_notes(
        &self,
        Parameters(args): Parameters<VmSetNotesArgs>,
    ) -> Result<Json<Vec<ConfigDiff>>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let diffs = hvlab_host::config::set_notes(id, &args.notes, args.dry_run)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(diffs.into_iter().map(diff_entry).collect()))
    }

    /// `hv_vm_set_memory`.
    #[tool(
        description = "Set VM memory: startup MB, optional dynamic memory with buffer percentage. dry_run (default true) returns the diff without applying."
    )]
    fn hv_vm_set_memory(
        &self,
        Parameters(args): Parameters<VmSetMemoryArgs>,
    ) -> Result<Json<Vec<ConfigDiff>>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let diffs = hvlab_host::config::set_memory(
            id,
            args.memory_mb,
            args.dynamic,
            args.buffer_pct,
            args.dry_run,
        )
        .map_err(|e| mcp_err(&e))?;
        Ok(Json(diffs.into_iter().map(diff_entry).collect()))
    }

    /// `hv_vm_set_processor`.
    #[tool(
        description = "Set a VM's virtual processor count. dry_run (default true) returns the diff without applying."
    )]
    fn hv_vm_set_processor(
        &self,
        Parameters(args): Parameters<VmSetProcessorArgs>,
    ) -> Result<Json<Vec<ConfigDiff>>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        let diffs = hvlab_host::config::set_processor(id, args.count, args.dry_run)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(diffs.into_iter().map(diff_entry).collect()))
    }

    /// `hv_vhd_create`.
    #[tool(
        description = "Create a VHD or VHDX at a path with a given size. Never touches an existing file."
    )]
    fn hv_vhd_create(
        &self,
        Parameters(args): Parameters<VhdCreateArgs>,
    ) -> Result<Json<VhdInfoResult>, rmcp::ErrorData> {
        let format = match args.format.as_deref() {
            None | Some("vhdx") => hvlab_host::DiskFormat::Vhdx,
            Some("vhd") => hvlab_host::DiskFormat::Vhd,
            Some(other) => {
                return Err(mcp_err(&HvError::invalid_argument(
                    "format",
                    &format!("unknown format {other:?}; use vhd or vhdx"),
                )));
            }
        };
        let disk = hvlab_host::StorageService::connect()
            .map_err(|e| mcp_err(&e))?
            .create(
                &args.path,
                args.size_bytes,
                format,
                args.block_size,
                args.timeout_secs.unwrap_or(300),
            )
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(vhd_info(&args.path, &disk)))
    }

    /// `hv_vhd_inspect`.
    #[tool(
        description = "Inspect a VHD/VHDX: format, virtual size, block size, parent chain head. Fast, no VM contact."
    )]
    fn hv_vhd_inspect(
        &self,
        Parameters(args): Parameters<VhdInspectArgs>,
    ) -> Result<Json<VhdInfoResult>, rmcp::ErrorData> {
        let disk = hvlab_host::StorageService::connect()
            .map_err(|e| mcp_err(&e))?
            .inspect(&args.path)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(vhd_info(&args.path, &disk)))
    }

    /// `hv_vhd_get`.
    #[tool(
        description = "Read a disk's live state (attached/in-use flag, size on disk, free space)."
    )]
    fn hv_vhd_get(
        &self,
        Parameters(args): Parameters<VhdInspectArgs>,
    ) -> Result<Json<VhdStateResult>, rmcp::ErrorData> {
        let st = hvlab_host::StorageService::connect()
            .map_err(|e| mcp_err(&e))?
            .state(&args.path)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(VhdStateResult {
            path: args.path,
            in_use: st.in_use,
            file_size_bytes: st.file_size,
            free_space_bytes: st.free_space,
        }))
    }

    /// `hv_vhd_resize`.
    #[tool(description = "Resize a VHD/VHDX's virtual size and wait for the job.")]
    fn hv_vhd_resize(
        &self,
        Parameters(args): Parameters<VhdResizeArgs>,
    ) -> Result<Json<VhdInfoResult>, rmcp::ErrorData> {
        let disk = hvlab_host::StorageService::connect()
            .map_err(|e| mcp_err(&e))?
            .resize(
                &args.path,
                args.size_bytes,
                args.timeout_secs.unwrap_or(300),
            )
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(vhd_info(&args.path, &disk)))
    }

    /// `hv_vhd_compact`.
    #[tool(description = "Compact a VHD/VHDX to reclaim unused space; waits for the job.")]
    fn hv_vhd_compact(
        &self,
        Parameters(args): Parameters<VhdCompactArgs>,
    ) -> Result<Json<VhdInfoResult>, rmcp::ErrorData> {
        let disk = hvlab_host::StorageService::connect()
            .map_err(|e| mcp_err(&e))?
            .compact(&args.path, args.timeout_secs.unwrap_or(600))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(vhd_info(&args.path, &disk)))
    }

    /// `hv_switch_list`.
    #[tool(
        description = "List virtual switch names. Requires Hyper-V Administrators; an un-elevated caller sees an empty list rather than an error."
    )]
    fn hv_switch_list(&self) -> Result<Json<SwitchListResult>, rmcp::ErrorData> {
        let svc = hvlab_host::NetworkService::connect().map_err(|e| mcp_err(&e))?;
        let switches = svc.list_switches().map_err(|e| mcp_err(&e))?;
        Ok(Json(SwitchListResult {
            switches: switches.into_iter().map(|s| s.name).collect(),
        }))
    }

    /// `hv_switch_create`.
    #[tool(
        description = "Create an internal or private virtual switch. External switches are deliberately not offered: binding a physical NIC can take the host offline."
    )]
    fn hv_switch_create(
        &self,
        Parameters(args): Parameters<SwitchCreateArgs>,
    ) -> Result<Json<SwitchListResult>, rmcp::ErrorData> {
        let kind = match args.kind.as_str() {
            "internal" => hvlab_host::SwitchKind::Internal,
            "private" => hvlab_host::SwitchKind::Private,
            other => {
                return Err(mcp_err(&HvError::invalid_argument(
                    "kind",
                    &format!(
                        "unknown kind {other:?}; use internal or private (external is never offered)"
                    ),
                )));
            }
        };
        let created = hvlab_host::NetworkService::connect()
            .map_err(|e| mcp_err(&e))?
            .create_switch(&args.name, kind, None, args.timeout_secs.unwrap_or(120))
            .map_err(|e| mcp_err(&e))?;
        // Observed state, not the request (H-11): the provider may have
        // normalized the name.
        Ok(Json(SwitchListResult {
            switches: vec![created.name],
        }))
    }

    /// `hv_switch_remove`.
    #[tool(description = "Remove a virtual switch by name.")]
    fn hv_switch_remove(
        &self,
        Parameters(args): Parameters<SwitchRemoveArgs>,
    ) -> Result<Json<SwitchRemoveResult>, rmcp::ErrorData> {
        hvlab_host::NetworkService::connect()
            .map_err(|e| mcp_err(&e))?
            .remove_switch(&args.name, args.timeout_secs.unwrap_or(120))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(SwitchRemoveResult { removed: true }))
    }

    /// `hv_nic_connect`.
    #[tool(description = "Connect a VM's first NIC to a switch.")]
    fn hv_nic_connect(
        &self,
        Parameters(args): Parameters<NicConnectArgs>,
    ) -> Result<Json<DeviceMutationResult>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        hvlab_host::NetworkService::connect()
            .map_err(|e| mcp_err(&e))?
            .connect_adapter(id, &args.switch, args.timeout_secs.unwrap_or(120))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(DeviceMutationResult {
            action: "connected".into(),
        }))
    }

    /// `hv_nic_disconnect`.
    #[tool(description = "Disconnect a VM's NIC(s) from their switches.")]
    fn hv_nic_disconnect(
        &self,
        Parameters(args): Parameters<NicDisconnectArgs>,
    ) -> Result<Json<DeviceMutationResult>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        hvlab_host::NetworkService::connect()
            .map_err(|e| mcp_err(&e))?
            .disconnect_adapters(id, args.timeout_secs.unwrap_or(120))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(DeviceMutationResult {
            action: "disconnected".into(),
        }))
    }

    /// `hv_device_add_disk`.
    #[tool(description = "Attach a VHD/VHDX file to a VM as a new disk.")]
    fn hv_device_add_disk(
        &self,
        Parameters(args): Parameters<AddDiskArgs>,
    ) -> Result<Json<DeviceMutationResult>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        hvlab_host::StorageService::connect()
            .map_err(|e| mcp_err(&e))?
            .attach_disk(id, &args.path, true, 0, 0, args.timeout_secs.unwrap_or(120))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(DeviceMutationResult {
            action: "attached".into(),
        }))
    }

    /// `hv_device_remove_disk`.
    #[tool(description = "Detach a disk (by its VHD path) from a VM. The file is not deleted.")]
    fn hv_device_remove_disk(
        &self,
        Parameters(args): Parameters<RemoveDiskArgs>,
    ) -> Result<Json<DeviceMutationResult>, rmcp::ErrorData> {
        let svc = hvlab_host::VmService::connect().map_err(|e| mcp_err(&e))?;
        let id = resolve_vm_id(&svc, &args.vm).map_err(|e| mcp_err(&e))?;
        hvlab_host::StorageService::connect()
            .map_err(|e| mcp_err(&e))?
            .detach_disk(id, &args.path, args.timeout_secs.unwrap_or(120))
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(DeviceMutationResult {
            action: "detached".into(),
        }))
    }

    /// `hv_guest_ping`.
    #[tool(
        description = "Probe a guest over PowerShell Direct: returns the verified guest hostname. Read-only."
    )]
    fn hv_guest_ping(
        &self,
        Parameters(args): Parameters<GuestPingArgs>,
    ) -> Result<Json<GuestPingResult>, rmcp::ErrorData> {
        let mut session =
            hvlab_guest::PsDirectSession::open(&args.vm, None).map_err(|e| mcp_err(&e))?;
        let hostname = session.ping().map_err(|e| mcp_err(&e))?;
        Ok(Json(GuestPingResult { hostname }))
    }

    /// `hv_guest_exec`.
    #[tool(
        description = "Run a program in a guest via PowerShell Direct. argv form, no shell. Requires a plan token: mint one with hv_plan for these exact arguments, then pass confirm. Class X."
    )]
    fn hv_guest_exec(
        &self,
        Parameters(args): Parameters<GuestExecArgs>,
    ) -> Result<Json<GuestExecResult>, rmcp::ErrorData> {
        let mut session =
            hvlab_guest::PsDirectSession::open(&args.vm, None).map_err(|e| mcp_err(&e))?;
        // The authorized timeout is enforced, not advisory (H-39: no
        // parameter is accepted and ignored).
        let timeout = Duration::from_secs(args.timeout_secs.unwrap_or(60));
        let out = session
            .exec_with_timeout(
                &hvlab_guest::ExecSpec {
                    program: args.program,
                    argv: args.argv,
                },
                timeout,
            )
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(GuestExecResult {
            exit_code: i64::from(out.exit_code),
            stdout: out.stdout_text(),
            stderr: out.stderr_text(),
        }))
    }

    /// `hv_guest_powershell`.
    #[tool(
        description = "Run a PowerShell script in a guest via PowerShell Direct; the script is encoded before sending and never string-interpolated. Requires a plan token bound to these exact arguments. Class X."
    )]
    fn hv_guest_powershell(
        &self,
        Parameters(args): Parameters<GuestPowershellArgs>,
    ) -> Result<Json<GuestExecResult>, rmcp::ErrorData> {
        let mut session =
            hvlab_guest::PsDirectSession::open(&args.vm, None).map_err(|e| mcp_err(&e))?;
        let timeout = Duration::from_secs(args.timeout_secs.unwrap_or(60));
        let out = session
            .powershell_with_timeout(&args.script, timeout)
            .map_err(|e| mcp_err(&e))?;
        Ok(Json(GuestExecResult {
            exit_code: i64::from(out.exit_code),
            stdout: out.stdout_text(),
            stderr: out.stderr_text(),
        }))
    }

    /// `hv_dump_find`.
    #[tool(
        description = "Find crash dumps in the standard roots (C:\\Windows\\MEMORY.DMP, Minidump, %LOCALAPPDATA%\\CrashDumps), newest first, with an explicit count of what was skipped."
    )]
    #[allow(clippy::unnecessary_wraps, reason = "rmcp tool fns all return Result")]
    fn hv_dump_find(
        &self,
        Parameters(args): Parameters<DumpFindArgs>,
    ) -> Result<Json<DumpFindResult>, rmcp::ErrorData> {
        let found = hvlab_debug::find_dumps(
            &hvlab_debug::default_roots(),
            usize::try_from(args.limit.unwrap_or(25)).unwrap_or(25),
        );
        Ok(Json(DumpFindResult {
            dumps: found
                .dumps
                .into_iter()
                .map(|d| DumpEntry {
                    path: d.path.display().to_string(),
                    size_bytes: d.size_bytes,
                    modified: d.modified.map(format_rfc3339),
                })
                .collect(),
            skipped_by_limit: found.skipped_by_limit as u64,
            unreadable_roots: found.unreadable_roots,
        }))
    }

    /// `hv_dump_analyze`.
    #[tool(
        description = "Run cdb !analyze -v, kv, lm against a dump and return structured fields (bugcheck, module, bucket, stack) plus the bounded raw log. Slower than hv_dump_inspect; results are cached on disk keyed by the dump fingerprint."
    )]
    fn hv_dump_analyze(
        &self,
        Parameters(args): Parameters<DumpAnalyzeArgs>,
    ) -> Result<Json<DumpAnalyzeResult>, rmcp::ErrorData> {
        let path = std::path::PathBuf::from(&args.path);
        let cache_dir = hvlab_debug::default_cache_dir();
        let (analysis, cached) = hvlab_debug::analyze_cached(
            &path,
            &hvlab_debug::AnalyzeOptions::default(),
            &cache_dir,
            hvlab_debug::default_ttl(),
        )
        .map_err(|e| mcp_err(&e))?;
        let p = &analysis.parsed;
        Ok(Json(DumpAnalyzeResult {
            bugcheck_code: p.bugcheck_code.map(hvlab_dump::format_bugcheck_code),
            module_name: p.module_name.clone(),
            image_name: p.image_name.clone(),
            failure_bucket_id: p.failure_bucket_id.clone(),
            process_name: p.process_name.clone(),
            stack: p
                .stack_frames
                .iter()
                .map(|f| match &f.ret_addr {
                    Some(addr) => format!("{} {} {}", f.number, addr, f.symbol),
                    None => format!("{} {}", f.number, f.symbol),
                })
                .collect(),
            truncated: analysis.truncation.truncated,
            dropped_bytes: analysis.truncation.dropped_bytes as u64,
            cached,
            raw_log: analysis.raw_log,
        }))
    }

    /// `hv_capabilities`.
    #[tool(
        description = "Static server info: version, protocol, registered tool count, and whether the Hyper-V WMI namespace answers."
    )]
    #[allow(clippy::unnecessary_wraps, reason = "rmcp tool fns all return Result")]
    fn hv_capabilities(&self) -> Result<Json<CapabilitiesResult>, rmcp::ErrorData> {
        // `vmms` state is the project's designated liveness probe (never
        // UAC-filtered); an inventory query can be filtered to empty and
        // would make a filtered host look like "Hyper-V absent".
        let hyper_v_present = hvlab_host::HostService::connect()
            .and_then(|s| s.host_services())
            .is_ok_and(|svcs| {
                svcs.iter()
                    .any(|s| s.name == "vmms" && s.state == "Running")
            });
        Ok(Json(CapabilitiesResult {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: rmcp::model::ProtocolVersion::V_2025_03_26.to_string(),
            tool_count: Self::tool_router().list_all().len() as u64,
            hyper_v_present,
        }))
    }

    /// `hv_tools_list`.
    #[tool(
        description = "List every registered tool with its safety class (R read-only, M mutating, D destructive, X guest code execution) and family. Cheap: names only, no schemas. Use hv_tools_describe for one tool's arguments."
    )]
    #[allow(clippy::unnecessary_wraps, reason = "rmcp tool fns all return Result")]
    fn hv_tools_list(&self) -> Result<Json<ToolListResult>, rmcp::ErrorData> {
        let mut tools: Vec<ToolEntry> = registry::REGISTRY
            .iter()
            .map(|m| ToolEntry {
                name: m.name.to_owned(),
                class: m.class.as_str().to_owned(),
                family: m.family.as_str().to_owned(),
                advertised: self.profile.advertises(m.name),
            })
            .collect();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Json(ToolListResult {
            total_registered: registry::REGISTRY.len() as u64,
            profile: self.profile.name().to_owned(),
            tools,
        }))
    }

    /// `hv_tools_search`.
    #[tool(
        description = "Search the tool catalogue by name, family, or class. Returns names and one-line purposes; follow up with hv_tools_describe to get a tool's arguments. Use this to reach tools that are not advertised in tools/list."
    )]
    #[allow(clippy::unnecessary_wraps, reason = "rmcp tool fns all return Result")]
    fn hv_tools_search(
        &self,
        Parameters(args): Parameters<ToolSearchArgs>,
    ) -> Result<Json<ToolSearchResult>, rmcp::ErrorData> {
        let family = match args.family.as_deref() {
            None | Some("") => None,
            Some(f) => Some(registry::Family::parse(&f.to_lowercase()).ok_or_else(|| {
                mcp_err(&HvError::invalid_argument(
                    "family",
                    &format!("unknown family {f:?}; known: {:?}", registry::families()),
                ))
            })?),
        };
        let class = match args.class.as_deref() {
            None | Some("") => None,
            Some(c) => {
                let up = c.to_uppercase();
                if !matches!(up.as_str(), "R" | "M" | "D" | "X") {
                    return Err(mcp_err(&HvError::invalid_argument(
                        "class",
                        &format!("unknown class {c:?}; use one of R, M, D, X"),
                    )));
                }
                Some(up)
            }
        };

        let hits: Vec<&registry::ToolMeta> = registry::search(args.query.as_deref().unwrap_or(""))
            .into_iter()
            .filter(|m| family.is_none_or(|f| m.family == f))
            .filter(|m| class.as_ref().is_none_or(|c| m.class.as_str() == c))
            .filter(|m| !args.advertised_only || self.profile.advertises(m.name))
            .collect();

        let matched = hits.len() as u64;
        let tools = hits
            .into_iter()
            .map(|m| ToolSummary {
                name: m.name.to_owned(),
                class: m.class.as_str().to_owned(),
                family: m.family.as_str().to_owned(),
                purpose: self.purpose_of(m.name),
                advertised: self.profile.advertises(m.name),
            })
            .collect();
        Ok(Json(ToolSearchResult { tools, matched }))
    }

    /// `hv_tools_describe`.
    #[tool(
        description = "Get one tool's full definition: description, safety class, whether it needs a plan token, and the exact JSON Schema for its arguments. Call this before invoking a tool that is not in tools/list."
    )]
    fn hv_tools_describe(
        &self,
        Parameters(args): Parameters<ToolDescribeArgs>,
    ) -> Result<Json<ToolDescribeResult>, rmcp::ErrorData> {
        let meta = registry::get(&args.name)
            .ok_or_else(|| mcp_err(&HvError::not_found("tool", &args.name)))?;
        let router = Self::tool_router();
        let defined = router
            .get(&args.name)
            .ok_or_else(|| mcp_err(&HvError::not_found("tool", &args.name)))?;
        Ok(Json(ToolDescribeResult {
            name: meta.name.to_owned(),
            class: meta.class.as_str().to_owned(),
            family: meta.family.as_str().to_owned(),
            description: defined.description.as_deref().unwrap_or("").to_owned(),
            needs_plan: meta.class.needs_plan(),
            input_schema: serde_json::Value::Object((*defined.input_schema).clone()),
        }))
    }
}

impl HvlabServer {
    /// First sentence of a tool's built-in description.
    #[allow(
        clippy::unused_self,
        reason = "kept as a method for call-site symmetry"
    )]
    fn purpose_of(&self, name: &str) -> String {
        let router = Self::tool_router();
        router
            .get(name)
            .and_then(|t| t.description.as_deref())
            .map(profile::first_sentence_public)
            .unwrap_or_default()
    }
}

/// Project a host checkpoint into the wire shape.
fn entry(cp: hvlab_host::Checkpoint) -> CheckpointEntry {
    CheckpointEntry {
        id: cp.id,
        name: cp.name,
        created: cp.created,
        parent: cp.parent,
        automatic: cp.automatic,
    }
}

/// Parse a user-facing state name into its `EnabledState` value.
fn parse_state(name: &str) -> Option<u16> {
    match name.to_ascii_lowercase().as_str() {
        "off" | "enabled" => Some(3),
        "running" => Some(2),
        "paused" => Some(6),
        "saved" => Some(12),
        _ => None,
    }
}

/// Project a storage inspection result into the wire shape.
fn vhd_info(path: &str, disk: &hvlab_host::DiskInfo) -> VhdInfoResult {
    VhdInfoResult {
        path: path.to_owned(),
        format: format_disk(disk.format),
        size_bytes: disk.max_internal_size,
        file_size_bytes: disk.file_size,
        block_size: disk.block_size.map(u64::from),
        parent_path: disk.parent.clone(),
    }
}

/// Decode the numeric `Format` of `Msvm_VirtualHardDiskSettingData`.
fn format_disk(format: u16) -> String {
    match format {
        2 => "vhd".to_owned(),
        3 => "vhdx".to_owned(),
        4 => "vhdx-set".to_owned(),
        other => format!("unknown({other})"),
    }
}

/// Project a backend config diff into the wire shape.
fn diff_entry(d: hvlab_host::ConfigDiff) -> ConfigDiff {
    ConfigDiff {
        field: d.field,
        before: d.before,
        after: d.after,
    }
}

/// RFC 3339 for a system time, falling back to epoch seconds.
fn format_rfc3339(t: SystemTime) -> String {
    time::OffsetDateTime::from_unix_timestamp(
        t.duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs().cast_signed()),
    )
    .ok()
    .and_then(|dt| {
        dt.format(&time::format_description::well_known::Rfc3339)
            .ok()
    })
    .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

/// Resolve a VM argument (GUID or display name) to its id.
fn resolve_vm_id(
    svc: &hvlab_host::VmService,
    name_or_id: &str,
) -> Result<hvlab_core::ids::VmId, HvError> {
    if let Ok(id) = hvlab_core::ids::VmId::from_str_guid(name_or_id) {
        return svc.get_vm(id).map(|v| v.id);
    }
    svc.list_vms()?
        .into_iter()
        .find(|v| v.name.eq_ignore_ascii_case(name_or_id))
        .map(|v| v.id)
        .ok_or_else(|| HvError::not_found("vm", name_or_id))
}

fn resolve_vm(
    svc: &hvlab_host::VmService,
    name_or_id: &str,
) -> Result<hvlab_host::VmSummary, HvError> {
    if let Ok(id) = hvlab_core::ids::VmId::from_str_guid(name_or_id) {
        return svc.get_vm(id);
    }
    let vms = svc.list_vms()?;
    vms.into_iter()
        .find(|v| v.name.eq_ignore_ascii_case(name_or_id))
        .ok_or_else(|| HvError::not_found("vm", name_or_id))
}

#[tool_handler]
impl rmcp::ServerHandler for HvlabServer {
    /// Authorize plan-gated tools from the client's *raw* arguments
    /// before the router runs them.
    ///
    /// Doing this here — rather than inside each tool body — means the
    /// digest covers exactly the JSON the client sent, which is the same
    /// JSON `hv_plan` hashed. A tool body only ever sees arguments that
    /// already passed the gate.
    fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::CallToolResponse, rmcp::ErrorData>> + '_ {
        let name = request.name.clone();
        let arguments = request.arguments.clone();
        // Gate plan-gated tools from the raw JSON before dispatch. The
        // authorization runs synchronously so the returned future is
        // `Send` on this feature set.
        let gate = plans::is_plan_gated(name.as_ref())
            .then(|| self.authorize_call(name.as_ref(), arguments));
        async move {
            if let Some(result) = gate {
                result?;
            }
            let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
            Self::tool_router().call(tcc).await
        }
    }

    /// Advertise the profile's tools, in the lean shape.
    ///
    /// This is the *discovery* surface, and the only place context cost
    /// is decided. Tools outside the active profile are still fully
    /// callable — `call_tool` resolves by name through the router, and
    /// argument validation comes from the handler's own type, neither of
    /// which consults this list. Dropping `outputSchema` and the
    /// description tail halves the payload without removing anything a
    /// caller needs in order to choose a tool.
    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::ListToolsResult, rmcp::ErrorData>> + '_ {
        let supports_cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        let active = self.profile.clone();
        let tools: Vec<rmcp::model::Tool> = Self::tool_router()
            .list_all()
            .iter()
            .filter(|t| active.advertises(&t.name))
            .map(profile::lean)
            .collect();
        async move {
            Ok(rmcp::model::ListToolsResult {
                result_type: Some(rmcp::model::ResultType::COMPLETE),
                tools,
                meta: None,
                next_cursor: None,
                ttl_ms: supports_cache_hints.then_some(0),
                cache_scope: supports_cache_hints.then_some(rmcp::model::CacheScope::Public),
            })
        }
    }

    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.server_info.name = "hvlab".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.instructions = Some(format!(
            "Hyper-V control plane on this host. tools/list advertises the \"{}\" profile \
             to keep the context cost low; it is not the whole API. Use hv_tools_search to find \
             any tool by name or family and hv_tools_describe to read its arguments before \
             calling it — every registered tool is callable by name whatever the profile. \
             Destructive (D) and guest-execution (X) tools require a plan token from hv_plan.",
            self.profile.name()
        ));
        info
    }
}

#[cfg(test)]
mod conformance {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn registry_count_is_exact_and_names_match() {
        // H-53: an exact count plus the full name set. A count that can
        // only ratchet up tells you nothing; this fails when a tool is
        // accidentally added, removed, or renamed.
        const EXPECTED: &[&str] = &[
            "hv_capabilities",
            "hv_checkpoint_create",
            "hv_checkpoint_delete",
            "hv_checkpoint_list",
            "hv_checkpoint_restore",
            "hv_device_add_disk",
            "hv_device_remove_disk",
            "hv_dump_analyze",
            "hv_dump_find",
            "hv_dump_inspect",
            "hv_guest_exec",
            "hv_guest_ping",
            "hv_guest_powershell",
            "hv_host_default_switch",
            "hv_host_info",
            "hv_host_services",
            "hv_host_storage_roots",
            "hv_nic_connect",
            "hv_nic_disconnect",
            "hv_plan",
            "hv_switch_create",
            "hv_switch_list",
            "hv_switch_remove",
            "hv_tools_describe",
            "hv_tools_list",
            "hv_tools_search",
            "hv_vhd_compact",
            "hv_vhd_create",
            "hv_vhd_get",
            "hv_vhd_inspect",
            "hv_vhd_resize",
            "hv_vm_get",
            "hv_vm_get_config",
            "hv_vm_list",
            "hv_vm_rename",
            "hv_vm_restart",
            "hv_vm_set_memory",
            "hv_vm_set_notes",
            "hv_vm_set_processor",
            "hv_vm_start",
            "hv_vm_stop",
            "hv_vm_wait_state",
        ];
        let mut names: Vec<String> = HvlabServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.into_owned())
            .collect();
        names.sort();
        let mut expected: Vec<&str> = EXPECTED.to_vec();
        expected.sort_unstable();
        assert_eq!(
            names, expected,
            "tool registry changed; update EXPECTED deliberately"
        );
    }

    /// The property the whole context strategy rests on: dropping a tool
    /// from `tools/list` must not remove it from the API. Dispatch
    /// resolves names through the router and validates arguments from the
    /// handler's type; only `list_all()` is filtered.
    #[test]
    fn unlisted_tools_still_dispatch() {
        // A tool deliberately outside the core profile.
        let name = "hv_vhd_resize";
        assert!(
            !crate::profile::Profile::Core.advertises(name),
            "{name} must be outside core for this test to mean anything"
        );
        // It is nevertheless registered and callable: ask the router for
        // it directly, the same lookup `call_tool` performs.
        let router = HvlabServer::tool_router();
        assert!(
            router.get(name).is_some(),
            "{name} must remain dispatchable while unlisted"
        );
        // And its argument schema is intact.
        let tool = router.get(name).expect("registered");
        assert!(tool.input_schema.contains_key("properties"));
    }

    /// `tools/list` must stay cheap. This is the guard that keeps the
    /// server from silently re-bloating a harness's context window as
    /// tools are added: it fails if the advertised payload grows past a
    /// budget, which is a real constraint rather than a style note.
    #[test]
    fn advertised_listing_stays_within_its_context_budget() {
        const CORE_BUDGET_BYTES: usize = 12_000;

        let advertised: Vec<rmcp::model::Tool> = HvlabServer::tool_router()
            .list_all()
            .iter()
            .filter(|t| crate::profile::Profile::Core.advertises(&t.name))
            .map(crate::profile::lean)
            .collect();

        assert!(
            advertised.iter().any(|t| t.name.starts_with("hv_")),
            "the core profile must advertise at least one real tool"
        );
        let bytes: usize = advertised
            .iter()
            .map(|t| serde_json::to_string(t).map_or(0, |s| s.len()))
            .sum();
        assert!(
            bytes <= CORE_BUDGET_BYTES,
            "advertised tools/list is {bytes} bytes (~{} tokens), over the {CORE_BUDGET_BYTES}-byte budget; \
             move a tool out of core, or trim its schema",
            bytes / 4
        );

        // Sanity: the lean form is materially smaller than the full form.
        let full: usize = HvlabServer::tool_router()
            .list_all()
            .iter()
            .filter(|t| crate::profile::Profile::Core.advertises(&t.name))
            .map(|t| serde_json::to_string(t).map_or(0, |s| s.len()))
            .sum();
        assert!(
            bytes * 2 < full,
            "lean projection should roughly halve the payload: {bytes} vs {full}"
        );
    }

    /// Every registered tool must be described in the registry, and every
    /// registry entry must exist in the router: one source of truth.
    #[test]
    fn registry_and_router_agree() {
        let router = HvlabServer::tool_router();
        let registered: std::collections::BTreeSet<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.into_owned())
            .collect();
        let described: std::collections::BTreeSet<String> = crate::registry::REGISTRY
            .iter()
            .map(|m| m.name.to_owned())
            .collect();
        assert_eq!(
            registered, described,
            "a tool exists in one place but not the other"
        );
    }

    #[test]
    fn profile_decides_listing_but_not_reachability() {
        let full = HvlabServer::tool_router().list_all().len();
        let core = HvlabServer::tool_router()
            .list_all()
            .iter()
            .filter(|t| crate::profile::Profile::Core.advertises(&t.name))
            .count();
        assert!(core < full, "core must advertise a subset");
        // Every non-core tool is still in the router.
        for t in HvlabServer::tool_router().list_all() {
            if !crate::profile::Profile::Core.advertises(&t.name) {
                assert!(
                    HvlabServer::tool_router().get(&t.name).is_some(),
                    "{} became unreachable",
                    t.name
                );
            }
        }
    }

    #[test]
    fn discovery_tools_are_always_advertised() {
        for name in crate::profile::DISCOVERY_TOOLS {
            assert!(
                crate::profile::Profile::Core.advertises(name),
                "{name} must be advertised or the long tail is unreachable"
            );
        }
    }

    #[test]
    fn every_tool_has_a_description() {
        for t in HvlabServer::tool_router().list_all() {
            let d = t.description.as_ref().unwrap_or_else(|| {
                panic!("tool {} has no description", t.name);
            });
            assert!(
                !d.trim().is_empty(),
                "tool {} has an empty description",
                t.name
            );
        }
    }

    #[test]
    fn classes_are_assigned() {
        assert_eq!(HvlabServer::tool_class("hv_checkpoint_delete"), "D");
        assert_eq!(HvlabServer::tool_class("hv_checkpoint_restore"), "D");
        assert_eq!(HvlabServer::tool_class("hv_guest_exec"), "X");
        assert_eq!(HvlabServer::tool_class("hv_guest_powershell"), "X");
        assert_eq!(HvlabServer::tool_class("hv_vm_list"), "R");
    }

    #[test]
    fn plan_gated_tools_reject_missing_confirm() {
        // Mirrors the tool impls: a D/X call without a confirm arg must
        // be refused before any backend call happens.
        let server = HvlabServer::new();
        let err = server
            .authorize_args(
                "hv_checkpoint_delete",
                serde_json::json!({
                    "vm": "x", "checkpoint": "c"
                }),
            )
            .expect_err("missing confirm must be refused");
        assert!(err.message.contains("plan token"), "{err:?}");
    }

    #[test]
    fn mint_verify_consume_roundtrip_through_authorize() {
        let server = HvlabServer::new();
        let call_args = serde_json::json!({"vm": "x", "checkpoint": "c"});
        let (_, confirm) = server
            .lock_plans()
            .mint("hv_checkpoint_delete", &call_args)
            .expect("mint");
        // The authorize path strips confirm, digests the rest, and must
        // accept the minted token for the same args.
        server
            .authorize_args(
                "hv_checkpoint_delete",
                serde_json::json!({"vm": "x", "checkpoint": "c",
                    "confirm": {"plan_id": confirm.plan_id, "digest": confirm.digest}}),
            )
            .expect("authorized");
        // Single-use: second call with the same token is refused.
        let err = server
            .authorize_args(
                "hv_checkpoint_delete",
                serde_json::json!({"vm": "x", "checkpoint": "c",
                    "confirm": {"plan_id": confirm.plan_id, "digest": confirm.digest}}),
            )
            .expect_err("reused token");
        assert!(err.message.contains("consumed"), "{err:?}");
    }

    #[test]
    fn token_bound_to_args_h30() {
        let server = HvlabServer::new();
        let (_, confirm) = server
            .lock_plans()
            .mint(
                "hv_guest_exec",
                &serde_json::json!({"vm": "a", "program": "cmd.exe", "argv": []}),
            )
            .expect("mint");
        // Same token, different args: refused, token NOT consumed
        // (digest check precedes consumption).
        let err = server
            .authorize_args(
                "hv_guest_exec",
                serde_json::json!({"vm": "b", "program": "cmd.exe", "argv": [],
                    "confirm": {"plan_id": confirm.plan_id, "digest": confirm.digest}}),
            )
            .expect_err("wrong args");
        assert!(err.message.contains("does not match"), "{err:?}");
    }

    #[test]
    fn hv_plan_tool_rejects_non_gated_action() {
        let server = HvlabServer::new();
        let err = server
            .lock_plans()
            .mint("hv_vm_list", &serde_json::json!({}))
            .expect_err("R tools need no plan");
        assert_eq!(err.code, hvlab_core::ErrorCode::InvalidArgument);
    }

    #[test]
    fn expired_token_is_refused() {
        let server = HvlabServer::new();
        let call_args = serde_json::json!({"vm": "x", "checkpoint": "c"});
        let (_, confirm) = server
            .lock_plans()
            .mint("hv_checkpoint_restore", &call_args)
            .expect("mint");
        server.lock_plans().expire_for_test(&confirm.plan_id);
        let err = server
            .authorize_args(
                "hv_checkpoint_restore",
                serde_json::json!({"vm": "x", "checkpoint": "c",
                    "confirm": {"plan_id": confirm.plan_id, "digest": confirm.digest}}),
            )
            .expect_err("expired");
        assert!(err.message.contains("expired"), "{err:?}");
    }
}
