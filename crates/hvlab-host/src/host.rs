//! Host facts: computer system, default storage roots, default switch,
//! and the Hyper-V service states.
//!
//! All queries are read-only. The host's own `Msvm_ComputerSystem`
//! instance is captioned `Hosting Computer System`, which is how it is
//! told apart from VMs (`Virtual Machine`).
//!
//! A non-elevated caller sees a subset of the `root\virtualization\v2`
//! namespace: instances of `Msvm_VirtualSystemManagementServiceSettingData`
//! and `Msvm_VirtualEthernetSwitch` are UAC-filtered out entirely (zero
//! rows, no error). Those queries therefore return `None`/empty rather
//! than failing — the caller cannot distinguish "role absent" from
//! "not elevated". `host_services` reads `root\cimv2\Win32_Service`,
//! which is never filtered, and is the reliable probe for "is Hyper-V
//! management alive".

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::vm_state::VmState;
use serde::{Deserialize, Serialize};
use wmi::WMIConnection;

use crate::wmi_util::wmi_err;

/// The host's `Msvm_ComputerSystem` instance, restricted to what we use.
#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_ComputerSystem")]
struct RawHostSystem {
    /// Display name of the host.
    #[serde(rename = "ElementName")]
    element_name: String,
    /// CIM `EnabledState` (2 = enabled/running).
    #[serde(rename = "EnabledState")]
    enabled_state: u16,
}

/// `Win32_ComputerSystem` in `root\cimv2`, restricted to what we use.
#[derive(Debug, Deserialize)]
#[serde(rename = "Win32_ComputerSystem")]
struct RawMachineFacts {
    /// Logical processors (hyperthreads included).
    #[serde(rename = "NumberOfLogicalProcessors")]
    number_of_logical_processors: u32,
    /// Physical memory in bytes.
    #[serde(rename = "TotalPhysicalMemory")]
    total_physical_memory: u64,
}

/// The singleton `Msvm_VirtualSystemManagementServiceSettingData`.
#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_VirtualSystemManagementServiceSettingData")]
struct RawServiceSettings {
    /// Default folder for new virtual disks.
    #[serde(rename = "DefaultVirtualHardDiskPath")]
    default_virtual_hard_disk_path: String,
    /// Default folder for VM configuration files.
    #[serde(rename = "DefaultExternalDataRoot")]
    default_external_data_root: String,
}

/// The first virtual switch, if one is visible.
#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_VirtualEthernetSwitch")]
struct RawSwitch {
    /// Switch display name.
    #[serde(rename = "ElementName")]
    element_name: String,
}

/// `Win32_Service` row, restricted to what we use.
#[derive(Debug, Deserialize)]
#[serde(rename = "Win32_Service")]
struct RawService {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "State", default)]
    state: Option<String>,
    #[serde(rename = "StartMode", default)]
    start_mode: Option<String>,
}

/// The host's identity and capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostInfo {
    /// Host display name (`Msvm_ComputerSystem.ElementName`).
    pub name: String,
    /// Logical processor count (`Win32_ComputerSystem`).
    pub cpu_count: u32,
    /// Physical RAM in bytes (`Win32_ComputerSystem`).
    pub ram_bytes: u64,
    /// CIM `EnabledState` of the host computer system, decoded.
    pub state: VmState,
    /// Raw `EnabledState`, carried for the vendor range.
    pub enabled_state: u16,
}

/// Default storage locations reported by the management service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorageRoots {
    /// `DefaultVirtualHardDiskPath` — where new VHDs land.
    pub default_vhd_path: String,
    /// `DefaultExternalDataRoot` — where VM configuration lands.
    pub default_vm_path: String,
}

/// One Windows service relevant to Hyper-V.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceState {
    /// Service short name (`vmms`, `vmicheartbeat`, …).
    pub name: String,
    /// `Win32_Service.State` (`Running`, `Stopped`, …).
    pub state: String,
    /// `Win32_Service.StartMode` (`Auto`, `Manual`, …).
    pub start_mode: String,
}

/// Read-only host queries.
pub struct HostService {
    conn: WMIConnection,
}

impl HostService {
    /// Open a connection to `ROOT\virtualization\v2`.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` when WMI cannot be reached.
    pub fn connect() -> Result<Self> {
        let conn = WMIConnection::with_namespace_path("ROOT\\virtualization\\v2")
            .map_err(|e| HvError::new(ErrorCode::Transport, format!("WMI connect failed: {e}")))?;
        Ok(Self { conn })
    }

    /// Host name, CPU count, RAM, and power state.
    ///
    /// CPU and RAM come from `root\cimv2\Win32_ComputerSystem`; the
    /// name and power state from the Hyper-V namespace.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Unsupported` when the host computer system instance
    /// is not exposed (Hyper-V role missing); `ErrorCode::Transport`
    /// on WMI failure.
    pub fn host_info(&self) -> Result<HostInfo> {
        let hosts: Vec<RawHostSystem> = self
            .conn
            .raw_query(
                "SELECT ElementName, EnabledState FROM Msvm_ComputerSystem \
                 WHERE Caption = 'Hosting Computer System'",
            )
            .map_err(|e| wmi_err(&e))?;
        let host = hosts.into_iter().next().ok_or_else(|| {
            HvError::new(
                ErrorCode::Unsupported,
                "host computer system not found; is the Hyper-V role installed?",
            )
        })?;
        let facts: Vec<RawMachineFacts> = WMIConnection::with_namespace_path("ROOT\\cimv2")
            .map_err(|e| HvError::new(ErrorCode::Transport, format!("WMI connect failed: {e}")))?
            .raw_query(
                "SELECT NumberOfLogicalProcessors, TotalPhysicalMemory \
                 FROM Win32_ComputerSystem",
            )
            .map_err(|e| wmi_err(&e))?;
        let facts = facts.into_iter().next().ok_or_else(|| {
            HvError::new(
                ErrorCode::Unsupported,
                "Win32_ComputerSystem returned no rows",
            )
        })?;
        Ok(HostInfo {
            name: host.element_name,
            cpu_count: facts.number_of_logical_processors,
            ram_bytes: facts.total_physical_memory,
            state: VmState::from_enabled_state(host.enabled_state),
            enabled_state: host.enabled_state,
        })
    }

    /// Default VHD and VM configuration folders.
    ///
    /// The singleton settings class is UAC-filtered for non-elevated
    /// callers (zero rows, no error), which is reported as `None`.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn host_storage_roots(&self) -> Result<Option<StorageRoots>> {
        let rows: Vec<RawServiceSettings> = self
            .conn
            .raw_query(
                "SELECT DefaultVirtualHardDiskPath, DefaultExternalDataRoot \
                 FROM Msvm_VirtualSystemManagementServiceSettingData",
            )
            .map_err(|e| wmi_err(&e))?;
        Ok(rows.into_iter().next().map(|r| StorageRoots {
            default_vhd_path: r.default_virtual_hard_disk_path,
            default_vm_path: r.default_external_data_root,
        }))
    }

    /// Name of the first virtual switch, when one is visible.
    ///
    /// Switch enumeration is UAC-filtered for non-elevated callers;
    /// `None` then means "none visible", not "none exist".
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn host_default_switch(&self) -> Result<Option<String>> {
        let rows: Vec<RawSwitch> = self
            .conn
            .raw_query("SELECT ElementName FROM Msvm_VirtualEthernetSwitch")
            .map_err(|e| wmi_err(&e))?;
        Ok(rows.into_iter().next().map(|r| r.element_name))
    }

    /// States of `vmms` and the `vmic*` integration services.
    ///
    /// Reads `root\cimv2\Win32_Service`, which is never UAC-filtered —
    /// this is the reliable probe for "is Hyper-V management alive".
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn host_services(&self) -> Result<Vec<ServiceState>> {
        let rows: Vec<RawService> = WMIConnection::with_namespace_path("ROOT\\cimv2")
            .map_err(|e| HvError::new(ErrorCode::Transport, format!("WMI connect failed: {e}")))?
            .raw_query(
                "SELECT Name, State, StartMode FROM Win32_Service \
                 WHERE Name = 'vmms' OR Name LIKE 'vmic%'",
            )
            .map_err(|e| wmi_err(&e))?;
        Ok(rows
            .into_iter()
            .map(|r| ServiceState {
                name: r.name,
                state: r.state.unwrap_or_default(),
                start_mode: r.start_mode.unwrap_or_default(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_info_json_shape_is_stable() {
        // The MCP layer serializes these; pin the wire contract.
        let info = HostInfo {
            name: "h".into(),
            cpu_count: 8,
            ram_bytes: 1 << 30,
            state: VmState::Running,
            enabled_state: 2,
        };
        let json = serde_json::to_string(&info).expect("serialize");
        assert!(json.contains("\"cpu_count\":8"));
        assert!(json.contains("\"ram_bytes\":"));
        assert!(json.contains("\"state\":\"running\""));
        assert!(json.contains("\"enabled_state\":2"));
    }

    #[test]
    fn service_state_json_shape_is_stable() {
        let svc = ServiceState {
            name: "vmms".into(),
            state: "Running".into(),
            start_mode: "Auto".into(),
        };
        let json = serde_json::to_string(&svc).expect("serialize");
        assert_eq!(
            json,
            r#"{"name":"vmms","state":"Running","start_mode":"Auto"}"#
        );
    }

    #[test]
    fn storage_roots_json_shape_is_stable() {
        let roots = StorageRoots {
            default_vhd_path: r"C:\VHDs".into(),
            default_vm_path: r"C:\VMs".into(),
        };
        let json = serde_json::to_string(&roots).expect("serialize");
        assert_eq!(
            json,
            r#"{"default_vhd_path":"C:\\VHDs","default_vm_path":"C:\\VMs"}"#
        );
    }
}
