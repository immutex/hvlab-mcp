//! # hvlab-mcp
//!
//! MCP server: tool registry, schemas, transports. Tools are thin
//! adapters over the backend crates; each carries an output schema and
//! a safety class. All `#[tool]` methods live on [`HvlabServer`] so the
//! registry is a single `ToolRouter<HvlabServer>`.

use rmcp::{
    handler::server::wrapper::{Json, Parameters},
    model::ServerConfig,
    service::ServiceExt,
    tool, tool_handler, tool_router,
    transport::stdio,
};

pub mod tools;
pub use tools::{
    CheckpointCreateArgs, CheckpointDeleteArgs, CheckpointEntry, CheckpointListArgs,
    CheckpointMutationResult, CheckpointRestoreArgs, DumpInspectArgs, DumpInspectResult, VmEntry,
    VmGetArgs, VmListArgs,
};

fn mcp_err(e: &HvError) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(format!("{}: {}", e.code.as_str(), e.message), None)
}

use hvlab_core::error::{ErrorCode, HvError};

fn io_err(path: &str, e: &std::io::Error) -> HvError {
    HvError::new(ErrorCode::Transport, format!("io error on {path}: {e}"))
}

/// The assembled hvlab server.
#[derive(Clone)]
pub struct HvlabServer;

impl HvlabServer {
    /// Build the server.
    #[must_use]
    pub fn new() -> Self {
        Self
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
#[allow(clippy::unused_self)] // rmcp tool fns require a &self receiver
impl HvlabServer {
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
        let kind = header
            .read_kind(&args.path)
            .unwrap_or(hvlab_dump::DumpKind::Unknown(0));
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
        description = "Delete a checkpoint. Set include_subtree to remove every checkpoint below it too."
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
        description = "Restore a checkpoint, discarding all state after it. Destructive: the VM is reverted."
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
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.server_info.name = "hvlab".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.instructions = Some(
            "Hyper-V control plane. Tools: dump inspection (fast, no debugger), \
             VM inventory via WMI v2. Destructive operations require a plan token."
                .into(),
        );
        info
    }
}
