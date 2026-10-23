//! VM inventory and lifecycle via WMI v2.

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use hvlab_core::vm_state::VmState;
use serde::{Deserialize, Serialize};
use wmi::WMIConnection;

use crate::job::{JobOutcome, await_wmi_job};

/// `Msvm_ComputerSystem` restricted to the fields we expose.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename = "Msvm_ComputerSystem")]
pub struct RawComputerSystem {
    /// Instance GUID — stable across renames; this is [`VmId`]'s source.
    #[serde(rename = "Name")]
    pub name: String,
    /// Display name.
    #[serde(rename = "ElementName")]
    pub element_name: String,
    /// CIM `EnabledState`.
    #[serde(rename = "EnabledState")]
    pub enabled_state: u16,
    /// Free-form status string from the provider.
    #[serde(rename = "StatusDescriptions")]
    pub status_descriptions: Option<Vec<String>>,
}

/// The inventory view of one VM.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmSummary {
    /// Stable identifier (the WMI `Name` GUID).
    pub id: VmId,
    /// Display name (changes with renames).
    pub name: String,
    /// Decoded power state.
    pub state: VmState,
}

impl TryFrom<&RawComputerSystem> for VmSummary {
    type Error = HvError;

    fn try_from(raw: &RawComputerSystem) -> Result<Self> {
        Ok(Self {
            id: VmId::from_str_guid(&raw.name).map_err(|e| {
                HvError::new(
                    ErrorCode::Internal,
                    format!("bad VM GUID {}: {e}", raw.name),
                )
            })?,
            name: raw.element_name.clone(),
            state: VmState::from_enabled_state(raw.enabled_state),
        })
    }
}

/// The WMI connection + operations. One connection, reused; the `wmi`
/// crate types are `!Send`, so this owns the thread it is used from.
pub struct VmService {
    namespace: String,
}

impl VmService {
    /// Connect to `ROOT\virtualization\v2` on the local host.
    ///
    /// # Errors
    ///
    /// COM initialization or namespace connect failure maps to
    /// `ErrorCode::Transport`; a missing Hyper-V role surfaces as
    /// `ErrorCode::Unsupported` via the provider's absence.
    pub fn connect() -> Result<Self> {
        Self::connect_to("ROOT\\virtualization\\v2")
    }

    /// Connect to an explicit namespace (tests, alternate hosts).
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::connect`].
    pub fn connect_to(namespace: &str) -> Result<Self> {
        // `WMIConnection::with_namespace_path` initializes COM via
        // `CoIncrementMTAUsage` on first use; the crate handles that.
        let probe = WMIConnection::with_namespace_path(namespace)
            .map_err(|e| HvError::new(ErrorCode::Transport, format!("WMI connect failed: {e}")))?;
        drop(probe);
        Ok(Self {
            namespace: namespace.to_owned(),
        })
    }

    /// Test hook: a fresh connection for job-level tests.
    ///
    /// # Errors
    ///
    /// Same as [`Self::connect`].
    #[doc(hidden)]
    pub fn connection_for_test(&self) -> Result<WMIConnection> {
        self.connection()
    }

    fn connection(&self) -> Result<WMIConnection> {
        WMIConnection::with_namespace_path(&self.namespace)
            .map_err(|e| HvError::new(ErrorCode::Transport, format!("WMI connect failed: {e}")))
    }

    /// List every VM (not the host computer system) on this machine.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn list_vms(&self) -> Result<Vec<VmSummary>> {
        let conn = self.connection()?;
        let raw: Vec<RawComputerSystem> = conn
            .raw_query("SELECT Name, ElementName, EnabledState, StatusDescriptions FROM Msvm_ComputerSystem WHERE Caption = 'Virtual Machine'")
            .map_err(|e| wmi_err(&e))?;
        raw.iter().map(VmSummary::try_from).collect()
    }

    /// Fetch one VM by GUID.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when the GUID is not a VM on this host.
    pub fn get_vm(&self, id: VmId) -> Result<VmSummary> {
        let conn = self.connection()?;
        let query = format!(
            "SELECT Name, ElementName, EnabledState, StatusDescriptions FROM Msvm_ComputerSystem WHERE Name = '{}' AND Caption = 'Virtual Machine'",
            id.0
        );
        let raw: Vec<RawComputerSystem> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        match raw.first() {
            Some(r) => VmSummary::try_from(r),
            None => Err(HvError::not_found("vm", &id.to_string())),
        }
    }

    /// Request a state change (`RequestStateChange`), polling the
    /// returned `Msvm_ConcreteJob` to a terminal state.
    ///
    /// A `4096` return means *asynchronous job started*, not success;
    /// completion is `JobState == 7`. Completed jobs are retained only
    /// ~5 minutes, so a vanished job is checked against VM state before
    /// being called a failure.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` for a rejected state transition,
    /// `ErrorCode::Timeout` when the job exceeds `deadline`, and
    /// `ErrorCode::Transport` for WMI failures.
    pub fn request_state(
        &self,
        id: VmId,
        requested: u16,
        deadline: std::time::Instant,
    ) -> Result<VmSummary> {
        #[derive(serde::Deserialize)]
        #[serde(rename = "Msvm_ComputerSystem")]
        struct Target {
            #[serde(rename = "__PATH")]
            path: String,
        }

        let conn = self.connection()?;
        let query = format!(
            "SELECT __PATH FROM Msvm_ComputerSystem WHERE Name = '{}' AND Caption = 'Virtual Machine'",
            id.0
        );
        let targets: Vec<Target> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        let target = targets
            .first()
            .ok_or_else(|| HvError::not_found("vm", &id.to_string()))?;

        // RequestStateChange: (RequestedState) -> {ReturnValue, Job}
        let out: StateChangeOut = conn
            .exec_instance_method::<Target, StateChangeOut>(
                target.path.as_str(),
                "RequestStateChange",
                serde_json::json!({ "RequestedState": requested }),
            )
            .map_err(|e| {
                HvError::new(
                    ErrorCode::Transport,
                    format!("RequestStateChange failed: {e}"),
                )
            })?;

        match out.return_value {
            0 => { /* completed synchronously */ }
            4096 => {
                let job_path = out.job.unwrap_or_default();
                // Completed and Vanished both mean "trust the read-back":
                // jobs are retained only ~5 minutes, so a vanished job is
                // not evidence of failure.
                if let JobOutcome::Failed(code, desc) = await_wmi_job(&conn, &job_path, deadline)? {
                    return Err(HvError::new(
                        ErrorCode::Precondition,
                        format!("state change job failed: {desc} ({code})"),
                    ));
                }
            }
            other => {
                return Err(HvError::precondition(
                    "a legal RequestStateChange return (0 or 4096)",
                    &format!("ReturnValue={other}"),
                ));
            }
        }

        // Always return the observed state (H-11), never the request.
        self.get_vm(id)
    }
}

/// Output of `Msvm_ComputerSystem.RequestStateChange`.
#[derive(serde::Deserialize)]
struct StateChangeOut {
    /// 0 = synchronous success; 4096 = async job created.
    #[serde(rename = "ReturnValue")]
    return_value: u32,
    /// Object path of the async job, when `ReturnValue` is 4096.
    #[serde(rename = "Job", default)]
    job: Option<String>,
}

fn wmi_err(e: &wmi::WMIError) -> HvError {
    HvError::new(ErrorCode::Transport, format!("WMI query failed: {e}"))
}
