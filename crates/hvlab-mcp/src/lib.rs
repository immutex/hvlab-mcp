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
pub use tools::{DumpInspectArgs, DumpInspectResult, VmEntry, VmGetArgs, VmListArgs};

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
