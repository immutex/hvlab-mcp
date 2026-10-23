//! VM lifecycle: named state transitions, wait-for-state, rename, and
//! delete.
//!
//! `Msvm_ComputerSystem.RequestStateChange` takes a CIM
//! `RequestedState` whose `ValueMap` — verified with `Get-CimClass`
//! against `root\virtualization\v2` on Windows 26200 — is
//! `2,3,4,6,7,8,9,10,11,..` in the DMTF range plus `32768..65535`
//! vendor-reserved, with the qualifier `Values` reading
//! `Enabled,Disabled,Shut Down,Offline,Test,Defer,Quiesce,Reboot,
//! Reset`. Hyper-V implements:
//!
//! | `RequestedState` | Meaning                       | PowerShell verb    |
//! |------------------|-------------------------------|--------------------|
//! | 2                | Enabled — running             | `Start-VM` / `Resume` |
//! | 3                | Disabled — hard power-off     | `Stop-VM -TurnOff`   |
//! | 4                | Shut Down — graceful, via the | `Stop-VM` (default)  |
//! |                  | integration services in-guest |                    |
//! | 6                | Offline — state saved to disk | `Save-VM`            |
//! | 10               | Reboot — guest restarts       | `Restart-VM`         |
//! | 11               | Reset — hard reset            | `Restart-VM -Force`  |
//! | 32768            | vendor range — paused         | `Suspend-VM`         |
//!
//! `EnabledState` (what you *observe*) uses a different table again:
//! 2 = running, 3 = off, 6 = paused, 8 = saving, 12 = saved,
//! 13 = stopping. Decoding lives in [`hvlab_core::VmState`]; this
//! module deals in raw codes so a caller can wait on the exact value
//! its transition targets.

use std::time::{Duration, Instant};

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use serde::{Deserialize, Serialize};

use crate::vm::{VmService, VmSummary};
use crate::wmi_util::{
    JobHandle, call_method, class::ManagementService, deadline_in, escape_wql, service_path,
    vm_path, vm_settings_path, wmi_err,
};

/// `RequestedState` 2 — running (start, or resume from pause/saved).
pub const REQUESTED_RUNNING: u16 = 2;
/// `RequestedState` 3 — hard power-off.
pub const REQUESTED_OFF: u16 = 3;
/// `RequestedState` 4 — graceful shutdown through the guest's
/// integration services; fails when the guest has none.
pub const REQUESTED_SHUTDOWN: u16 = 4;
/// `RequestedState` 6 — save state to disk (CIM "Offline").
pub const REQUESTED_SAVED: u16 = 6;
/// `RequestedState` 10 — reboot: the guest restarts itself.
pub const REQUESTED_REBOOT: u16 = 10;
/// `RequestedState` 11 — reset: hard reset of the virtual hardware.
pub const REQUESTED_RESET: u16 = 11;
/// `RequestedState` 32768 — pause (Hyper-V vendor range).
pub const REQUESTED_PAUSED: u16 = 32768;

/// How [`VmService::stop`] stops a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopMode {
    /// Graceful shutdown via the integration services (`RequestedState`
    /// 4). Fails on guests without integration services.
    Shutdown,
    /// Save state to disk (`RequestedState` 6).
    Save,
    /// Hard power-off (`RequestedState` 3) — like pulling the cable.
    TurnOff,
}

impl StopMode {
    /// The `RequestedState` this mode maps to.
    #[must_use]
    pub const fn requested_state(self) -> u16 {
        match self {
            Self::Shutdown => REQUESTED_SHUTDOWN,
            Self::Save => REQUESTED_SAVED,
            Self::TurnOff => REQUESTED_OFF,
        }
    }
}

/// Poll cadence for [`VmService::wait_state`].
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ModifySystemIn {
    system_settings: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DestroySystemIn {
    affected_system: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_VirtualSystemManagementService")]
struct ManagementJobOut {
    #[serde(rename = "ReturnValue")]
    return_value: u32,
    #[serde(rename = "Job", default)]
    job: Option<String>,
}

impl From<ManagementJobOut> for JobHandle {
    fn from(out: ManagementJobOut) -> Self {
        Self {
            return_value: out.return_value,
            job: out.job,
        }
    }
}

/// An embedded `Msvm_VirtualSystemSettingData` patch carrying only the
/// properties being changed (same shape a checkpoint rename uses).
fn settings_patch_xml(instance_id: &str, element_name: &str) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    };
    format!(
        "<INSTANCE CLASSNAME=\"Msvm_VirtualSystemSettingData\">\
         <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
         <PROPERTY NAME=\"ElementName\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
         </INSTANCE>",
        esc(instance_id),
        esc(element_name)
    )
}

/// `InstanceID` of a VM's realized `Msvm_VirtualSystemSettingData`,
/// which `ModifySystemSettings` patches address by.
fn realized_instance_id(conn: &wmi::WMIConnection, id: VmId) -> Result<String> {
    #[derive(Deserialize)]
    #[serde(rename = "Msvm_VirtualSystemSettingData")]
    struct IdOnly {
        #[serde(rename = "InstanceID")]
        instance_id: String,
    }
    let query = format!(
        "SELECT InstanceID FROM Msvm_VirtualSystemSettingData \
         WHERE VirtualSystemType = 'Microsoft:Hyper-V:System:Realized' \
         AND VirtualSystemIdentifier = '{}'",
        escape_wql(&id.0.to_string())
    );
    let rows: Vec<IdOnly> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
    rows.into_iter()
        .next()
        .map(|r| r.instance_id)
        .ok_or_else(|| HvError::not_found("vm settings", &id.to_string()))
}

impl VmService {
    /// Start a VM (`RequestedState` 2).
    ///
    /// # Errors
    ///
    /// Same as [`VmService::request_state`].
    pub fn start(&self, id: VmId, deadline: Instant) -> Result<VmSummary> {
        self.request_state(id, REQUESTED_RUNNING, deadline)
    }

    /// Resume a paused or saved VM (`RequestedState` 2).
    ///
    /// # Errors
    ///
    /// Same as [`VmService::request_state`].
    pub fn resume(&self, id: VmId, deadline: Instant) -> Result<VmSummary> {
        self.request_state(id, REQUESTED_RUNNING, deadline)
    }

    /// Pause a running VM (`RequestedState` 32768).
    ///
    /// # Errors
    ///
    /// Same as [`VmService::request_state`].
    pub fn pause(&self, id: VmId, deadline: Instant) -> Result<VmSummary> {
        self.request_state(id, REQUESTED_PAUSED, deadline)
    }

    /// Reboot a VM through the guest OS (`RequestedState` 10).
    ///
    /// # Errors
    ///
    /// Same as [`VmService::request_state`].
    pub fn restart(&self, id: VmId, deadline: Instant) -> Result<VmSummary> {
        self.request_state(id, REQUESTED_REBOOT, deadline)
    }

    /// Hard-reset the virtual hardware (`RequestedState` 11).
    ///
    /// # Errors
    ///
    /// Same as [`VmService::request_state`].
    pub fn reset(&self, id: VmId, deadline: Instant) -> Result<VmSummary> {
        self.request_state(id, REQUESTED_RESET, deadline)
    }

    /// Stop a VM in the requested mode.
    ///
    /// # Errors
    ///
    /// Same as [`VmService::request_state`]; graceful shutdown fails
    /// when the guest lacks integration services.
    pub fn stop(&self, id: VmId, mode: StopMode, deadline: Instant) -> Result<VmSummary> {
        self.request_state(id, mode.requested_state(), deadline)
    }

    /// Current raw `EnabledState` of a VM.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM.
    pub fn enabled_state(&self, id: VmId) -> Result<u16> {
        #[derive(Deserialize)]
        #[serde(rename = "Msvm_ComputerSystem")]
        struct StateOnly {
            #[serde(rename = "EnabledState")]
            enabled_state: u16,
        }
        let conn = self.connection()?;
        let query = format!(
            "SELECT EnabledState FROM Msvm_ComputerSystem WHERE Name = '{}' \
             AND Caption = 'Virtual Machine'",
            escape_wql(&id.0.to_string())
        );
        let rows: Vec<StateOnly> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .map(|r| r.enabled_state)
            .ok_or_else(|| HvError::not_found("vm", &id.to_string()))
    }

    /// Poll `EnabledState` every 200 ms until it is one of `targets`
    /// or `deadline` passes. Requests no transition — a pure
    /// observation loop. Returns the VM once the target is reached.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM, `ErrorCode::Timeout`
    /// when the deadline passes first.
    pub fn wait_state(&self, id: VmId, targets: &[u16], deadline: Instant) -> Result<VmSummary> {
        loop {
            let current = self.enabled_state(id)?;
            if targets.contains(&current) {
                return self.get_vm(id);
            }
            if Instant::now() >= deadline {
                return Err(HvError::new(
                    ErrorCode::Timeout,
                    format!(
                        "VM {id} did not reach one of {targets:?} before the deadline \
                         (last observed EnabledState={current})"
                    ),
                ));
            }
            std::thread::sleep(STATE_POLL_INTERVAL);
        }
    }

    /// The transition set the VM currently offers
    /// (`Msvm_ComputerSystem.AvailableRequestedStates`), or `None`
    /// when the provider does not report one.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM.
    pub fn available_requested_states(&self, id: VmId) -> Result<Option<Vec<u16>>> {
        #[derive(Deserialize)]
        #[serde(rename = "Msvm_ComputerSystem")]
        struct States {
            #[serde(rename = "AvailableRequestedStates", default)]
            available: Option<Vec<u16>>,
        }
        let conn = self.connection()?;
        let query = format!(
            "SELECT AvailableRequestedStates FROM Msvm_ComputerSystem \
             WHERE Name = '{}' AND Caption = 'Virtual Machine'",
            escape_wql(&id.0.to_string())
        );
        let rows: Vec<States> = conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        Ok(rows.into_iter().next().and_then(|r| r.available))
    }

    /// Rename a VM (display name only; the GUID and configuration
    /// files stay). Patches the realized
    /// `Msvm_VirtualSystemSettingData` with `ModifySystemSettings` —
    /// the same mechanism Hyper-V Manager uses.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM, `ErrorCode::Precondition`
    /// when the provider refuses the rename.
    pub fn rename(&self, id: VmId, new_name: &str) -> Result<VmSummary> {
        let conn = self.connection()?;
        // Resolved eagerly so an unknown VM fails before any mutation.
        let settings = vm_settings_path(&conn, id, true)?;
        let instance_id = realized_instance_id(&conn, id)?;
        let svc = service_path(&conn, "Msvm_VirtualSystemManagementService")?;
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &conn,
            &svc,
            "ModifySystemSettings",
            ModifySystemIn {
                system_settings: settings_patch_xml(&instance_id, new_name),
            },
        )?;
        JobHandle::from(out).finish(&conn, "ModifySystemSettings", deadline_in(30))?;
        drop(settings);
        self.get_vm(id)
    }

    /// Delete a VM: `DestroySystem` on
    /// `Msvm_VirtualSystemManagementService`. The configuration is
    /// destroyed and the operation is not reversible; callers gate it
    /// behind a plan token.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM, `ErrorCode::Precondition`
    /// when the provider refuses (VM running, files locked).
    pub fn delete(&self, id: VmId, timeout_secs: u64) -> Result<()> {
        let conn = self.connection()?;
        let path = vm_path(&conn, id)?;
        let svc = service_path(&conn, "Msvm_VirtualSystemManagementService")?;
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &conn,
            &svc,
            "DestroySystem",
            DestroySystemIn {
                affected_system: path,
            },
        )?;
        JobHandle::from(out).finish(&conn, "DestroySystem", deadline_in(timeout_secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_state_constants_match_cim_valuemap() {
        // Pinned against the ValueMap qualifier verified on 26200:
        // 2,3,4,6,7,8,9,10,11 DMTF; 32768.. vendor.
        assert_eq!(REQUESTED_RUNNING, 2);
        assert_eq!(REQUESTED_OFF, 3);
        assert_eq!(REQUESTED_SHUTDOWN, 4);
        assert_eq!(REQUESTED_SAVED, 6);
        assert_eq!(REQUESTED_REBOOT, 10);
        assert_eq!(REQUESTED_RESET, 11);
        assert_eq!(REQUESTED_PAUSED, 32768);
    }

    #[test]
    fn stop_modes_map_to_verified_states() {
        assert_eq!(StopMode::Shutdown.requested_state(), 4);
        assert_eq!(StopMode::Save.requested_state(), 6);
        assert_eq!(StopMode::TurnOff.requested_state(), 3);
    }

    #[test]
    fn stop_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&StopMode::TurnOff).expect("serialize"),
            "\"turn_off\""
        );
        assert_eq!(
            serde_json::to_string(&StopMode::Shutdown).expect("serialize"),
            "\"shutdown\""
        );
    }

    #[test]
    fn settings_patch_xml_escapes_values() {
        let xml = settings_patch_xml("Microsoft:abc", r#"renamed<>"&"#);
        assert!(xml.contains("<VALUE>Microsoft:abc</VALUE>"));
        assert!(xml.contains("renamed&lt;&gt;&quot;&amp;"));
        assert!(xml.contains("NAME=\"ElementName\""));
    }
}
