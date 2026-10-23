//! Networking: virtual switches and the adapters bound to them.
//!
//! Switch creation goes through
//! `Msvm_VirtualEthernetSwitchManagementService::DefineSystem` with an
//! embedded `Msvm_VirtualEthernetSwitchSettingData` plus an array of
//! `Msvm_EthernetPortAllocationSettingData` resources. The switch kind is
//! not a property — it is *which port the resource array binds*:
//!
//! | Kind     | `HostResource` of the connection resource        |
//! |----------|--------------------------------------------------|
//! | internal | the host `Msvm_ComputerSystem` path               |
//! | external | the `Msvm_ExternalEthernetPort` path              |
//! | private  | no resources at all                               |
//!
//! Two wire-format details are easy to get wrong and both were verified
//! against a live host:
//!
//! * `HostResource` is a **string array**, so the embedded instance needs
//!   `<PROPERTY.ARRAY NAME="HostResource">` with a `<VALUE.ARRAY>`. A
//!   scalar `<PROPERTY>` makes the provider fail the job with
//!   "Failed while creating virtual Ethernet switch" (32768).
//! * The connection resource is `ResourceType` 33
//!   (`Microsoft:Hyper-V:Ethernet Connection`), not the port type 10.

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use serde::{Deserialize, Serialize};
use wmi::WMIConnection;

use crate::wmi_util::{
    JobHandle, call_method,
    class::{ManagementService, SwitchManagementService},
    deadline_in, escape_wql, service_path, vm_settings_path, wmi_err,
};

/// Resource type for an Ethernet port.
const RESOURCE_TYPE_ETHERNET_PORT: u16 = 10;
/// Resource type for an Ethernet connection.
const RESOURCE_TYPE_ETHERNET_CONNECTION: u16 = 33;

/// Which kind of switch to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchKind {
    /// VMs and the host share a physical NIC.
    External,
    /// VMs and the host talk to each other; no physical NIC.
    Internal,
    /// VMs talk to each other only; the host is not attached.
    Private,
}

impl std::str::FromStr for SwitchKind {
    type Err = HvError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "external" => Ok(Self::External),
            "internal" => Ok(Self::Internal),
            "private" => Ok(Self::Private),
            other => Err(HvError::new(
                ErrorCode::InvalidArgument,
                format!("switch kind must be external|internal|private, got {other}"),
            )),
        }
    }
}

/// One virtual switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Switch {
    /// Switch name (`ElementName`).
    pub name: String,
    /// `Name` GUID.
    pub id: String,
    /// `external`, `internal`, or `private`, derived from the ports.
    pub kind: String,
    /// Physical NIC bound to the switch, for external switches.
    pub external_adapter: Option<String>,
    /// Number of ports on the switch.
    pub port_count: usize,
}

/// A switch port (`Msvm_EthernetSwitchPort`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwitchPort {
    /// `ElementName` (`Host Vnic <switch>` for the host's own port).
    pub name: String,
    /// `Name` GUID of the port.
    pub id: String,
    /// GUID of the switch the port belongs to.
    pub switch: String,
}

/// In-parameters for `DefineSystem`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DefineSystemIn {
    system_settings: String,
    resource_settings: Vec<String>,
}

/// Out-parameters for `DefineSystem`.
#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_VirtualEthernetSwitchManagementService")]
struct DefineSystemOut {
    #[serde(rename = "ReturnValue")]
    return_value: u32,
    #[serde(rename = "Job", default)]
    job: Option<String>,
}

impl From<DefineSystemOut> for JobHandle {
    fn from(out: DefineSystemOut) -> Self {
        Self {
            return_value: out.return_value,
            job: out.job,
        }
    }
}

/// In-parameters for `AddResourceSettings`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct AddResourcesIn {
    affected_configuration: String,
    resource_settings: Vec<String>,
}

/// In-parameters for `RemoveResourceSettings`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct RemoveResourcesIn {
    resource_settings: Vec<String>,
}

/// In-parameters for `DestroySystem`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DestroyIn {
    affected_system: String,
}

/// Out-parameters shared by the job-returning management methods.
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

/// XML text escaping for embedded-instance property values.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// An embedded switch settings instance.
fn switch_settings_xml(name: &str) -> String {
    format!(
        "<INSTANCE CLASSNAME=\"Msvm_VirtualEthernetSwitchSettingData\">\
         <PROPERTY NAME=\"ElementName\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
         <PROPERTY NAME=\"VirtualSystemType\" TYPE=\"string\">\
         <VALUE>DMTF:Virtual Ethernet Switch</VALUE></PROPERTY>\
         </INSTANCE>",
        xml_escape(name)
    )
}

/// An embedded switch-port connection bound to `target` (a host computer
/// system or a physical adapter).
fn connection_xml(name: &str, target: &str) -> String {
    format!(
        "<INSTANCE CLASSNAME=\"Msvm_EthernetPortAllocationSettingData\">\
         <PROPERTY NAME=\"ElementName\" TYPE=\"string\"><VALUE>{name}</VALUE></PROPERTY>\
         <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\">\
         <VALUE>{RESOURCE_TYPE_ETHERNET_CONNECTION}</VALUE></PROPERTY>\
         <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\">\
         <VALUE>Microsoft:Hyper-V:Ethernet Connection</VALUE></PROPERTY>\
         <PROPERTY.ARRAY NAME=\"HostResource\" TYPE=\"string\">\
         <VALUE.ARRAY><VALUE>{target}</VALUE></VALUE.ARRAY></PROPERTY.ARRAY>\
         </INSTANCE>",
        name = xml_escape(name),
        target = xml_escape(target),
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_VirtualEthernetSwitch")]
struct RawSwitch {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ElementName")]
    element_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_EthernetPortAllocationSettingData")]
struct RawAllocation {
    #[serde(rename = "InstanceID")]
    instance_id: String,
    #[serde(rename = "HostResource", default)]
    host_resource: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_EthernetSwitchPort")]
struct RawPort {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ElementName", default)]
    element_name: Option<String>,
    #[serde(rename = "SystemName", default)]
    system_name: Option<String>,
}

/// Switch and adapter operations.
pub struct NetworkService {
    conn: WMIConnection,
}

impl NetworkService {
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

    /// Confirm the switch management service is reachable.
    ///
    /// Switch *management* (as opposed to switch enumeration) is
    /// UAC-filtered: a non-elevated caller sees no
    /// `Msvm_VirtualEthernetSwitchManagementService` instance at all.
    /// Callers that mutate switches should call this first so they fail
    /// with a clear message instead of a confusing provider error, and
    /// so a dry run does not create half a switch.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Unsupported` when the service is absent (role missing
    /// or caller not elevated).
    pub fn check_available(&self) -> Result<()> {
        service_path(&self.conn, "Msvm_VirtualEthernetSwitchManagementService").map(|_| ())
    }

    /// Every virtual switch on the host.
    ///
    /// Switch kind is derived, not stored. Each switch owns one
    /// `Msvm_EthernetPortAllocationSettingData` whose `HostResource`
    /// names what the switch is attached to — exactly the resource this
    /// module passes to `DefineSystem` when creating it:
    ///
    /// * `Msvm_ComputerSystem` (the host) → internal
    /// * `Msvm_ExternalEthernetPort` → external
    /// * no allocation at all → private
    ///
    /// Two queries total, regardless of how many switches exist.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn list_switches(&self) -> Result<Vec<Switch>> {
        let switches: Vec<RawSwitch> = self
            .conn
            .raw_query("SELECT Name, ElementName FROM Msvm_VirtualEthernetSwitch")
            .map_err(|e| wmi_err(&e))?;
        let allocations: Vec<RawAllocation> = self
            .conn
            .raw_query(
                "SELECT InstanceID, HostResource FROM Msvm_EthernetPortAllocationSettingData \
                 WHERE ResourceType = 33",
            )
            .map_err(|e| wmi_err(&e))?;
        let ports: Vec<RawPort> = self
            .conn
            .raw_query("SELECT Name, ElementName, SystemName FROM Msvm_EthernetSwitchPort")
            .map_err(|e| wmi_err(&e))?;

        Ok(switches
            .into_iter()
            .map(|s| {
                let own: Vec<&RawAllocation> = allocations
                    .iter()
                    .filter(|a| {
                        a.instance_id
                            .starts_with(&format!("Microsoft:{}\\", s.name.to_uppercase()))
                            || a.instance_id
                                .starts_with(&format!("Microsoft:{}\\", s.name))
                    })
                    .collect();
                let target = own.first().and_then(|a| a.host_resource.first());
                let (kind, external_adapter) = match target {
                    Some(t) if t.contains("Msvm_ExternalEthernetPort") => {
                        // The element name is not in the path; look it up
                        // from the physical port list by DeviceID match.
                        let device = t
                            .split_once("DeviceID=\"Microsoft:{")
                            .and_then(|(_, rest)| rest.split('}').next())
                            .map(str::to_lowercase);
                        let adapter = device.and_then(|d| {
                            ports
                                .iter()
                                .find(|p| p.name.to_lowercase().contains(&d))
                                .and_then(|p| p.element_name.clone())
                        });
                        ("external", adapter)
                    }
                    Some(_) => ("internal", None),
                    None => ("private", None),
                };
                Switch {
                    name: s.element_name,
                    id: s.name.clone(),
                    kind: kind.to_owned(),
                    external_adapter,
                    port_count: ports
                        .iter()
                        .filter(|p| p.system_name.as_deref() == Some(s.name.as_str()))
                        .count(),
                }
            })
            .collect())
    }

    /// One switch by name or GUID.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when no switch matches.
    pub fn get_switch(&self, name_or_id: &str) -> Result<Switch> {
        self.list_switches()?
            .into_iter()
            .find(|s| {
                s.id.eq_ignore_ascii_case(name_or_id) || s.name.eq_ignore_ascii_case(name_or_id)
            })
            .ok_or_else(|| HvError::not_found("switch", name_or_id))
    }

    /// Create a virtual switch.
    ///
    /// `adapter_name` is required for [`SwitchKind::External`] and
    /// rejected for the other kinds.
    ///
    /// # Errors
    ///
    /// `ErrorCode::InvalidArgument` for a mismatched adapter argument,
    /// `ErrorCode::NotFound` for an unknown physical adapter,
    /// `ErrorCode::Precondition` when the provider refuses the request.
    pub fn create_switch(
        &self,
        name: &str,
        kind: SwitchKind,
        adapter_name: Option<&str>,
        timeout_secs: u64,
    ) -> Result<Switch> {
        let resources = match kind {
            SwitchKind::Private => Vec::new(),
            SwitchKind::Internal => vec![connection_xml(name, &self.host_path()?)],
            SwitchKind::External => {
                let adapter = adapter_name.ok_or_else(|| {
                    HvError::new(
                        ErrorCode::InvalidArgument,
                        "an external switch needs the name of a physical adapter",
                    )
                })?;
                let path = self.external_port_path(adapter)?;
                vec![connection_xml(name, &path)]
            }
        };
        if kind != SwitchKind::External && adapter_name.is_some() {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                "only an external switch binds a physical adapter",
            ));
        }

        let svc = service_path(&self.conn, "Msvm_VirtualEthernetSwitchManagementService")?;
        let out: DefineSystemOut = call_method::<SwitchManagementService, _>(
            &self.conn,
            &svc,
            "DefineSystem",
            DefineSystemIn {
                system_settings: switch_settings_xml(name),
                resource_settings: resources,
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "DefineSystem", deadline_in(timeout_secs))?;
        self.get_switch(name)
    }

    /// Remove a virtual switch.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown switch,
    /// `ErrorCode::Precondition` when VMs are still attached.
    pub fn remove_switch(&self, name_or_id: &str, timeout_secs: u64) -> Result<()> {
        let sw = self.get_switch(name_or_id)?;
        let svc = service_path(&self.conn, "Msvm_VirtualEthernetSwitchManagementService")?;
        let out: DefineSystemOut = call_method::<SwitchManagementService, _>(
            &self.conn,
            &svc,
            "DestroySystem",
            DestroyIn {
                affected_system: self.switch_path(&sw.id)?,
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "DestroySystem", deadline_in(timeout_secs))
    }

    /// Ports belonging to a switch.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn ports_for(&self, switch_id: &str) -> Result<Vec<SwitchPort>> {
        let query = format!(
            "SELECT Name, ElementName, SystemName FROM Msvm_EthernetSwitchPort \
             WHERE SystemName = '{}'",
            escape_wql(switch_id)
        );
        let rows: Vec<RawPort> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        Ok(rows
            .into_iter()
            .map(|p| SwitchPort {
                name: p.element_name.unwrap_or_default(),
                id: p.name,
                switch: p.system_name.unwrap_or_else(|| switch_id.to_owned()),
            })
            .collect())
    }

    /// Names of the host's physical adapters, in the order the provider
    /// lists them.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn physical_adapters(&self) -> Result<Vec<String>> {
        #[derive(Debug, Deserialize)]
        #[serde(rename = "Msvm_ExternalEthernetPort")]
        struct Raw {
            #[serde(rename = "ElementName", default)]
            element_name: Option<String>,
            #[serde(rename = "IsBound", default)]
            is_bound: Option<bool>,
        }
        let rows: Vec<Raw> = self
            .conn
            .raw_query("SELECT ElementName, IsBound FROM Msvm_ExternalEthernetPort")
            .map_err(|e| wmi_err(&e))?;
        // An adapter already bound to another switch cannot be bound twice.
        Ok(rows
            .into_iter()
            .filter(|r| !r.is_bound.unwrap_or(false))
            .filter_map(|r| r.element_name)
            .collect())
    }

    /// Connect a VM's network adapter to a switch.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM or switch,
    /// `ErrorCode::Precondition` when the VM refuses the device.
    pub fn connect_adapter(
        &self,
        vm: VmId,
        switch_name_or_id: &str,
        timeout_secs: u64,
    ) -> Result<()> {
        let switch = self.get_switch(switch_name_or_id)?;
        let settings = vm_settings_path(&self.conn, vm, true)?;
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;

        let adapter = format!(
            "<INSTANCE CLASSNAME=\"Msvm_SyntheticEthernetPortSettingData\">\
             <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\">\
             <VALUE>{RESOURCE_TYPE_ETHERNET_PORT}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\">\
             <VALUE>Microsoft:Hyper-V:Synthetic Ethernet Port</VALUE></PROPERTY>\
             </INSTANCE>"
        );
        let connection = format!(
            "<INSTANCE CLASSNAME=\"Msvm_EthernetPortAllocationSettingData\">\
             <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\">\
             <VALUE>{RESOURCE_TYPE_ETHERNET_CONNECTION}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\">\
             <VALUE>Microsoft:Hyper-V:Ethernet Connection</VALUE></PROPERTY>\
             <PROPERTY.ARRAY NAME=\"HostResource\" TYPE=\"string\">\
             <VALUE.ARRAY><VALUE>{sw}</VALUE></VALUE.ARRAY></PROPERTY.ARRAY>\
             </INSTANCE>",
            sw = xml_escape(&self.switch_path(&switch.id)?),
        );

        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "AddResourceSettings",
            AddResourcesIn {
                affected_configuration: settings,
                resource_settings: vec![adapter, connection],
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "AddResourceSettings", deadline_in(timeout_secs))
    }

    /// Disconnect every adapter of a VM from its switch.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM.
    pub fn disconnect_adapters(&self, vm: VmId, timeout_secs: u64) -> Result<usize> {
        let connections = self.connections_for(vm)?;
        if connections.is_empty() {
            return Ok(0);
        }
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let count = connections.len();
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "RemoveResourceSettings",
            RemoveResourcesIn {
                resource_settings: connections,
            },
        )?;
        JobHandle::from(out).finish(
            &self.conn,
            "RemoveResourceSettings",
            deadline_in(timeout_secs),
        )?;
        Ok(count)
    }

    /// Object paths of a VM's Ethernet connections.
    fn connections_for(&self, vm: VmId) -> Result<Vec<String>> {
        #[derive(Debug, Deserialize)]
        #[serde(rename = "Msvm_EthernetPortAllocationSettingData")]
        struct Raw {
            #[serde(rename = "__PATH")]
            path: String,
        }
        let query = format!(
            "SELECT * FROM Msvm_EthernetPortAllocationSettingData \
             WHERE ResourceType = {RESOURCE_TYPE_ETHERNET_CONNECTION} \
             AND InstanceID LIKE 'Microsoft:{}\\%%'",
            escape_wql(&vm.0.to_string())
        );
        let rows: Vec<Raw> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        Ok(rows.into_iter().map(|r| r.path).collect())
    }

    /// Object path of the host `Msvm_ComputerSystem` (the internal-switch
    /// attachment target).
    fn host_path(&self) -> Result<String> {
        #[derive(Debug, Deserialize)]
        #[serde(rename = "Msvm_ComputerSystem")]
        struct Raw {
            #[serde(rename = "__PATH")]
            path: String,
        }
        // The host's own instance is captioned "Hosting Computer System";
        // VMs are "Virtual Machine".
        let query = "SELECT * FROM Msvm_ComputerSystem WHERE Caption = 'Hosting Computer System'";
        let rows: Vec<Raw> = self.conn.raw_query(query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .map(|r| r.path)
            .ok_or_else(|| HvError::new(ErrorCode::Unsupported, "host computer system not found"))
    }

    /// Object path of a physical adapter.
    fn external_port_path(&self, adapter_name: &str) -> Result<String> {
        #[derive(Debug, Deserialize)]
        #[serde(rename = "Msvm_ExternalEthernetPort")]
        struct Raw {
            #[serde(rename = "__PATH")]
            path: String,
        }
        let query = format!(
            "SELECT * FROM Msvm_ExternalEthernetPort WHERE ElementName = '{}'",
            escape_wql(adapter_name)
        );
        let rows: Vec<Raw> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .map(|r| r.path)
            .ok_or_else(|| HvError::not_found("physical adapter", adapter_name))
    }

    /// Object path of a switch's `Msvm_VirtualEthernetSwitch` instance.
    fn switch_path(&self, switch_id: &str) -> Result<String> {
        #[derive(Debug, Deserialize)]
        #[serde(rename = "Msvm_VirtualEthernetSwitch")]
        struct Raw {
            #[serde(rename = "__PATH")]
            path: String,
        }
        let query = format!(
            "SELECT * FROM Msvm_VirtualEthernetSwitch WHERE Name = '{}'",
            escape_wql(switch_id)
        );
        let rows: Vec<Raw> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .map(|r| r.path)
            .ok_or_else(|| HvError::not_found("switch", switch_id))
    }
}
