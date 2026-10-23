//! Shared WMI plumbing: object-path lookup, method invocation, and the
//! `ReturnValue`/`Job` protocol every Hyper-V method speaks.
//!
//! Hyper-V WMI methods return a `ReturnValue`: `0` means the call
//! finished synchronously, `4096` means *an asynchronous job was
//! created* whose object path arrives in the `Job` out-parameter. Every
//! caller must poll that job; treating `4096` as success is the single
//! most common Hyper-V automation bug.

use std::time::{Duration, Instant};

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use serde::Serialize;
use serde::de::DeserializeOwned;
use wmi::WMIConnection;

use crate::job::{JobOutcome, await_wmi_job};

/// `ReturnValue` meaning "asynchronous job created".
pub const RETURN_ASYNC: u32 = 4096;

/// Default deadline for a management operation.
#[must_use]
pub fn deadline_in(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

/// Escape a string for embedding in a WQL single-quoted literal.
///
/// WQL escapes a backslash and a single quote with a backslash.
#[must_use]
pub fn escape_wql(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Map a WMI transport error.
#[must_use]
pub fn wmi_err(e: &wmi::WMIError) -> HvError {
    HvError::new(ErrorCode::Transport, format!("WMI query failed: {e}"))
}

/// The `ReturnValue`/`Job` pair present on every Hyper-V method result.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct JobHandle {
    /// `0` = synchronous success, `4096` = job created, else an error.
    #[serde(rename = "ReturnValue")]
    pub return_value: u32,
    /// Object path of the created job (only when `ReturnValue == 4096`).
    #[serde(rename = "Job", default)]
    pub job: Option<String>,
}

impl JobHandle {
    /// Interpret the return value, polling any created job to a
    /// terminal state.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` for a non-zero, non-`4096` return or a
    /// failed job; `ErrorCode::Timeout` when the job outlives `deadline`.
    pub fn finish(self, conn: &WMIConnection, what: &str, deadline: Instant) -> Result<()> {
        match self.return_value {
            0 => Ok(()),
            RETURN_ASYNC => {
                let job_path = self.job.unwrap_or_default();
                match await_wmi_job(conn, &job_path, deadline)? {
                    JobOutcome::Completed | JobOutcome::Vanished => Ok(()),
                    JobOutcome::Failed(code, desc) => Err(HvError::new(
                        ErrorCode::Precondition,
                        format!("{what} failed: {desc} ({code})"),
                    )),
                }
            }
            other => Err(HvError::new(
                ErrorCode::Precondition,
                format!("{what} rejected the request (ReturnValue={other})"),
            )),
        }
    }
}

/// `__PATH` of the single instance of a singleton service class.
///
/// Every path lookup in this module uses `SELECT *` rather than
/// `SELECT __PATH`: the Hyper-V provider returns `0x80041001` (generic
/// failure) for `SELECT __PATH` against the singleton service classes and
/// silently returns zero rows for `Msvm_ComputerSystem`. `SELECT *`
/// exposes the same `__PATH` property and works for both.
///
/// # Errors
///
/// `ErrorCode::NotFound` when the provider exposes no instance (role
/// not installed), `ErrorCode::Transport` on WMI failure.
pub fn service_path(conn: &WMIConnection, class: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct PathOnly {
        #[serde(rename = "__PATH")]
        path: String,
    }
    // `SELECT __PATH` fails with 0x80041001 on the singleton service
    // classes (verified on Hyper-V 26200); `SELECT *` returns the same
    // `__PATH` property and works.
    let query = format!("SELECT * FROM {class}");
    let rows: Vec<PathOnly> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
    rows.into_iter().next().map(|r| r.path).ok_or_else(|| {
        HvError::new(
            ErrorCode::Unsupported,
            format!("{class} is unavailable; is the Hyper-V role installed?"),
        )
    })
}

/// `__PATH` of a VM's `Msvm_ComputerSystem` instance.
///
/// # Errors
///
/// `ErrorCode::NotFound` for an unknown GUID.
pub fn vm_path(conn: &WMIConnection, id: VmId) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct PathOnly {
        #[serde(rename = "__PATH")]
        path: String,
    }
    let query = format!(
        "SELECT * FROM Msvm_ComputerSystem WHERE Name = '{}' AND Caption = 'Virtual Machine'",
        escape_wql(&id.0.to_string())
    );
    let rows: Vec<PathOnly> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
    rows.into_iter()
        .next()
        .map(|r| r.path)
        .ok_or_else(|| HvError::not_found("vm", &id.to_string()))
}

/// `__PATH` of a VM's realized settings (`Msvm_VirtualSystemSettingData`).
///
/// `current_only` selects the live configuration; `false` includes
/// checkpoint settings, which is what restore paths need.
///
/// # Errors
///
/// `ErrorCode::NotFound` when the VM has no realized settings.
pub fn vm_settings_path(conn: &WMIConnection, id: VmId, current_only: bool) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct PathOnly {
        #[serde(rename = "__PATH")]
        path: String,
    }
    let filter = if current_only {
        "VirtualSystemType = 'Microsoft:Hyper-V:System:Realized'"
    } else {
        "VirtualSystemType LIKE 'Microsoft:Hyper-V:%'"
    };
    let query = format!(
        "SELECT * FROM Msvm_VirtualSystemSettingData WHERE {filter} AND \
         VirtualSystemIdentifier = '{}'",
        escape_wql(&id.0.to_string())
    );
    let rows: Vec<PathOnly> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
    rows.into_iter()
        .next()
        .map(|r| r.path)
        .ok_or_else(|| HvError::not_found("vm settings", &id.to_string()))
}

/// Invoke a method on a class instance and deserialize its full
/// out-parameters. `Class` is a marker whose `#[serde(rename)]` names the
/// WMI class the method is defined on.
///
/// # Errors
///
/// `ErrorCode::Transport` when the provider rejects the invocation.
pub fn call_method<Class, Out>(
    conn: &WMIConnection,
    path: &str,
    method: &str,
    params: impl Serialize,
) -> Result<Out>
where
    Class: DeserializeOwned,
    Out: DeserializeOwned,
{
    conn.exec_instance_method::<Class, Out>(path, method, params)
        .map_err(|e| {
            HvError::new(
                ErrorCode::Transport,
                format!("{method} invocation failed: {e}"),
            )
        })
}

/// Marker types: one per WMI class whose methods we invoke.
pub mod class {
    /// `Msvm_ComputerSystem` (VM state changes, config application).
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_ComputerSystem")]
    pub struct ComputerSystem;

    /// `Msvm_VirtualSystemManagementService` (define/create/modify).
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_VirtualSystemManagementService")]
    pub struct ManagementService;

    /// `Msvm_VirtualSystemSnapshotService` (checkpoints).
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_VirtualSystemSnapshotService")]
    pub struct SnapshotService;

    /// `Msvm_ImageManagementService` (VHD/VHDX operations).
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_ImageManagementService")]
    pub struct ImageManagementService;

    /// `Msvm_VirtualEthernetSwitchManagementService` (switch create/remove).
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_VirtualEthernetSwitchManagementService")]
    pub struct SwitchManagementService;

    /// `Msvm_VirtualSystemManagementService` configuration setters share
    /// the class; kept separate for readability at call sites.
    #[derive(serde::Deserialize)]
    #[serde(rename = "Msvm_VirtualSystemManagementService")]
    pub struct SettingsService;
}
