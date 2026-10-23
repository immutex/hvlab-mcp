//! Device manipulation: DVD drives and ISO media, NIC VLAN tags.
//!
//! Disk attach/detach lives in [`crate::storage`] (drive + file
//! backing) and NIC connect/disconnect in [`crate::network`]; this
//! module covers the rest of the device surface.
//!
//! Hyper-V splits a DVD the same way it splits a disk — into a *device*
//! and its *media* — and the resource types are nowhere near each other
//! in the CIM enumeration:
//!
//! | Part              | `ResourceType` | `ResourceSubType`                     |
//! |-------------------|----------------|---------------------------------------|
//! | DVD drive device  | 16             | `Microsoft:Hyper-V:Synthetic DVD Drive` |
//! | ISO media backing | 31             | `Microsoft:Hyper-V:Virtual CD/DVD Disk` |
//!
//! (15 = CD drive, 16 = DVD drive, 21 = serial port, 17 = disk drive.
//! Media is `Msvm_StorageAllocationSettingData`, and `HostResource` on
//! it is the documented *writable* property for exactly the subtypes
//! `Virtual Hard Disk`, `Virtual CD/DVD Disk`, and `Virtual Floppy
//! Disk` — which is why swapping an ISO is a `ModifyResourceSettings`
//! on the media, not an add/remove of the drive.)
//!
//! A VLAN is a *feature* of the adapter's Ethernet connection:
//! `AddFeatureSettings` with an embedded
//! `Msvm_EthernetSwitchPortVlanSettingData` (`OperationMode` 1 =
//! access, 2 = trunk, 3 = private).
//!
//! Everything here goes through `Msvm_VirtualSystemManagementService`,
//! which is invisible to non-elevated callers; those see the lookup
//! fail before any mutation is attempted.

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use serde::{Deserialize, Serialize};
use wmi::WMIConnection;

use crate::wmi_util::{
    JobHandle, call_method, class::ManagementService, deadline_in, escape_wql, service_path,
    vm_settings_path, wmi_err,
};

/// `ResourceType` of a DVD drive device.
const RESOURCE_TYPE_DVD: u16 = 16;
/// `ResourceType` of a logical disk: the media behind a drive.
const RESOURCE_TYPE_ISO_MEDIA: u16 = 31;
/// `ResourceType` of an Ethernet connection (the port allocation).
const RESOURCE_TYPE_ETHERNET_CONNECTION: u16 = 33;
/// `ResourceSubType` of the synthetic DVD drive device.
const SUBTYPE_DVD_DRIVE: &str = "Microsoft:Hyper-V:Synthetic DVD Drive";
/// `ResourceSubType` of ISO media attached to a DVD drive.
const SUBTYPE_ISO_MEDIA: &str = "Microsoft:Hyper-V:Virtual CD/DVD Disk";
/// `OperationMode` 1 — access VLAN (one tagged VLAN + untagged).
const VLAN_OPERATION_ACCESS: u32 = 1;
/// `OperationMode` 2 — trunk VLAN (many tagged VLANs, a native one).
const VLAN_OPERATION_TRUNK: u32 = 2;

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct AddIn {
    affected_configuration: String,
    resource_settings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct RemoveIn {
    resource_settings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ModifyResourcesIn {
    resource_settings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct AddFeatureIn {
    affected_configuration: String,
    feature_settings: Vec<String>,
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

/// XML text escaping for embedded-instance property values.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One DVD drive of a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DvdDrive {
    /// Object path of the drive resource setting.
    pub path: String,
    /// Slot on the parent controller (`AddressOnParent`).
    pub address_on_parent: Option<String>,
    /// Mounted ISO path, when media is attached.
    pub iso: Option<String>,
}

/// One ISO media backing attached to a VM.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IsoBacking {
    /// `InstanceID` of the media resource.
    instance_id: String,
    /// `Parent` reference: the drive the media belongs to.
    parent: Option<String>,
    /// Media path (`HostResource[0]`).
    media: String,
}

/// Device operations (DVD, ISO, VLAN).
pub struct DeviceService {
    conn: WMIConnection,
}

impl DeviceService {
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

    /// Add a DVD drive on the SCSI controller (Gen2) or IDE (Gen1).
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM, `ErrorCode::Precondition`
    /// when the provider refuses the device.
    pub fn dvd_add(&self, vm: VmId, scsi: bool, timeout_secs: u64) -> Result<()> {
        let settings = vm_settings_path(&self.conn, vm, true)?;
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        // The `Parent` reference is the controller class name; the
        // provider picks the slot, exactly as it does for a disk.
        let parent = if scsi {
            "Microsoft:Hyper-V:Synthetic SCSI Controller"
        } else {
            "Microsoft:Hyper-V:Emulated IDE Controller"
        };
        let drive = format!(
            "<INSTANCE CLASSNAME=\"Msvm_ResourceAllocationSettingData\">\
             <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\"><VALUE>{RESOURCE_TYPE_DVD}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\"><VALUE>{SUBTYPE_DVD_DRIVE}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Parent\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
             </INSTANCE>",
            xml_escape(parent),
        );
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "AddResourceSettings",
            AddIn {
                affected_configuration: settings,
                resource_settings: vec![drive],
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "AddResourceSettings", deadline_in(timeout_secs))
    }

    /// Mount an ISO into the VM's first DVD drive.
    ///
    /// Media is created with `AddResourceSettings` when the drive is
    /// empty and swapped with `ModifyResourceSettings` when it is not:
    /// a drive holds at most one media resource, so adding a second one
    /// is refused by the provider.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when the ISO file or a DVD drive is
    /// missing, `ErrorCode::Precondition` when the provider refuses.
    pub fn dvd_set_iso(&self, vm: VmId, iso_path: &str, timeout_secs: u64) -> Result<()> {
        if !std::path::Path::new(iso_path).is_file() {
            return Err(HvError::not_found("iso file", iso_path));
        }
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;

        if let Some(existing) = self.iso_resources(vm)?.into_iter().next() {
            // `HostResource` is writable for this subtype; the patch
            // carries identity plus the new media path.
            let media = format!(
                "<INSTANCE CLASSNAME=\"Msvm_StorageAllocationSettingData\">\
                 <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
                 <PROPERTY.ARRAY NAME=\"HostResource\" TYPE=\"string\">\
                 <VALUE.ARRAY><VALUE>{}</VALUE></VALUE.ARRAY></PROPERTY.ARRAY>\
                 </INSTANCE>",
                xml_escape(&existing.instance_id),
                xml_escape(iso_path),
            );
            let out: ManagementJobOut = call_method::<ManagementService, _>(
                &self.conn,
                &svc,
                "ModifyResourceSettings",
                ModifyResourcesIn {
                    resource_settings: vec![media],
                },
            )?;
            return JobHandle::from(out).finish(
                &self.conn,
                "ModifyResourceSettings",
                deadline_in(timeout_secs),
            );
        }

        let drive = self.dvd_drives(vm)?.into_iter().next().ok_or_else(|| {
            HvError::new(
                ErrorCode::NotFound,
                format!("VM {vm} has no DVD drive to mount an ISO into"),
            )
        })?;
        let settings = vm_settings_path(&self.conn, vm, true)?;
        // `HostResource` is a string array on the wire; a scalar
        // `<PROPERTY>` is rejected by the provider.
        let media = format!(
            "<INSTANCE CLASSNAME=\"Msvm_StorageAllocationSettingData\">\
             <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\"><VALUE>{RESOURCE_TYPE_ISO_MEDIA}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\"><VALUE>{SUBTYPE_ISO_MEDIA}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Parent\" TYPE=\"string\"><VALUE>{parent}</VALUE></PROPERTY>\
             <PROPERTY.ARRAY NAME=\"HostResource\" TYPE=\"string\">\
             <VALUE.ARRAY><VALUE>{iso}</VALUE></VALUE.ARRAY></PROPERTY.ARRAY>\
             </INSTANCE>",
            parent = xml_escape(&path_reference(&drive.path)),
            iso = xml_escape(iso_path),
        );
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "AddResourceSettings",
            AddIn {
                affected_configuration: settings,
                resource_settings: vec![media],
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "AddResourceSettings", deadline_in(timeout_secs))
    }

    /// Dismount the ISO media from a VM's DVD drive, leaving the drive.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when no ISO is mounted.
    pub fn dvd_clear_iso(&self, vm: VmId, timeout_secs: u64) -> Result<()> {
        let existing = self
            .iso_resources(vm)?
            .into_iter()
            .next()
            .ok_or_else(|| HvError::not_found("iso media", &format!("any media of VM {vm}")))?;
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "RemoveResourceSettings",
            RemoveIn {
                resource_settings: vec![self.media_path(&existing.instance_id)?],
            },
        )?;
        JobHandle::from(out).finish(
            &self.conn,
            "RemoveResourceSettings",
            deadline_in(timeout_secs),
        )
    }

    /// Every DVD drive of a VM, with mounted ISOs.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn dvd_drives(&self, vm: VmId) -> Result<Vec<DvdDrive>> {
        #[derive(Deserialize)]
        #[serde(rename = "Msvm_ResourceAllocationSettingData")]
        struct RawDrive {
            #[serde(rename = "__PATH")]
            path: String,
            #[serde(rename = "AddressOnParent", default)]
            address_on_parent: Option<String>,
        }
        let query = format!(
            "SELECT * FROM Msvm_ResourceAllocationSettingData \
             WHERE ResourceType = {RESOURCE_TYPE_DVD} \
             AND InstanceID LIKE 'Microsoft:{}\\%%'",
            escape_wql(&vm.0.to_string())
        );
        let drives: Vec<RawDrive> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        let media = self.iso_resources(vm)?;
        Ok(drives
            .into_iter()
            .map(|d| {
                let reference = path_reference(&d.path);
                let iso = media
                    .iter()
                    .find(|m| {
                        m.parent
                            .as_deref()
                            .is_some_and(|p| same_resource(&reference, p))
                    })
                    .map(|m| m.media.clone());
                DvdDrive {
                    path: d.path,
                    address_on_parent: d.address_on_parent,
                    iso,
                }
            })
            .collect())
    }

    /// Set an 802.1Q VLAN on the VM's first network adapter.
    ///
    /// `native` selects trunk mode, whose native VLAN is left untagged;
    /// otherwise access mode tags the port with `vlan_id`.
    ///
    /// # Errors
    ///
    /// `ErrorCode::InvalidArgument` for VLAN 0 or above 4094,
    /// `ErrorCode::NotFound` for an unknown VM or an adapter with no
    /// switch connection, `ErrorCode::Precondition` when the provider
    /// refuses the setting.
    pub fn nic_set_vlan(
        &self,
        vm: VmId,
        vlan_id: u16,
        native: bool,
        timeout_secs: u64,
    ) -> Result<()> {
        if !(1..=4094).contains(&vlan_id) {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                format!("vlan_id must be 1-4094, got {vlan_id}"),
            ));
        }
        // Addressed by the adapter's Ethernet *connection*, which is
        // the setting data the switch features attach to — not the VM's
        // `Msvm_VirtualSystemSettingData` and not the switch itself.
        let connection = self.first_connection(vm)?;
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let (mode, id_property) = if native {
            (VLAN_OPERATION_TRUNK, "NativeVlanId")
        } else {
            (VLAN_OPERATION_ACCESS, "AccessVlanId")
        };
        let vlan_xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_EthernetSwitchPortVlanSettingData\">\
             <PROPERTY NAME=\"OperationMode\" TYPE=\"uint32\"><VALUE>{mode}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"{id_property}\" TYPE=\"uint16\"><VALUE>{vlan_id}</VALUE></PROPERTY>\
             </INSTANCE>"
        );
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "AddFeatureSettings",
            AddFeatureIn {
                affected_configuration: connection,
                feature_settings: vec![vlan_xml],
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "AddFeatureSettings", deadline_in(timeout_secs))
    }

    /// ISO media resources of a VM.
    fn iso_resources(&self, vm: VmId) -> Result<Vec<IsoBacking>> {
        #[derive(Deserialize)]
        #[serde(rename = "Msvm_StorageAllocationSettingData")]
        struct RawIso {
            #[serde(rename = "InstanceID")]
            instance_id: String,
            #[serde(rename = "HostResource", default)]
            host_resource: Vec<String>,
            #[serde(rename = "Parent", default)]
            parent: Option<String>,
        }
        let query = format!(
            "SELECT InstanceID, HostResource, Parent FROM Msvm_StorageAllocationSettingData \
             WHERE ResourceType = {RESOURCE_TYPE_ISO_MEDIA} \
             AND ResourceSubType = '{SUBTYPE_ISO_MEDIA}' \
             AND InstanceID LIKE 'Microsoft:{}\\%%'",
            escape_wql(&vm.0.to_string())
        );
        let rows: Vec<RawIso> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        Ok(rows
            .into_iter()
            .map(|r| IsoBacking {
                instance_id: r.instance_id,
                parent: r.parent,
                media: r.host_resource.into_iter().next().unwrap_or_default(),
            })
            .collect())
    }

    /// Object path of media addressed by `InstanceID` (what
    /// `RemoveResourceSettings` needs).
    fn media_path(&self, instance_id: &str) -> Result<String> {
        #[derive(Deserialize)]
        #[serde(rename = "Msvm_StorageAllocationSettingData")]
        struct PathOnly {
            #[serde(rename = "__PATH")]
            path: String,
        }
        let query = format!(
            "SELECT * FROM Msvm_StorageAllocationSettingData WHERE InstanceID = '{}'",
            escape_wql(instance_id)
        );
        let rows: Vec<PathOnly> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .map(|r| r.path)
            .ok_or_else(|| HvError::not_found("iso media", instance_id))
    }

    /// Object path of the VM's first Ethernet connection (the port
    /// allocation a VLAN feature attaches to).
    fn first_connection(&self, vm: VmId) -> Result<String> {
        #[derive(Deserialize)]
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
        rows.into_iter()
            .next()
            .map(|r| r.path)
            .ok_or_else(|| HvError::not_found("network adapter", &vm.to_string()))
    }
}

/// Class-plus-key portion of a resource object path (the form `Parent`
/// references use).
fn path_reference(path: &str) -> String {
    path.rsplit(':').next().unwrap_or(path).to_owned()
}

/// Compare two resource references modulo server/namespace prefix.
fn same_resource(a: &str, b: &str) -> bool {
    fn tail(p: &str) -> &str {
        p.rsplit(':').next().unwrap_or(p)
    }
    tail(a).eq_ignore_ascii_case(tail(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_reference_strips_namespace() {
        assert_eq!(
            path_reference(
                r#"\\.\root\virtualization\v2:Msvm_ResourceAllocationSettingData.InstanceID="x""#
            ),
            r#"Msvm_ResourceAllocationSettingData.InstanceID="x""#
        );
    }

    #[test]
    fn same_resource_ignores_prefix_and_case() {
        assert!(same_resource(
            r#"\\.\root\v2:Msvm_R.InstanceID="a""#,
            r#"Msvm_R.InstanceID="A""#
        ));
        assert!(!same_resource(
            r#"Msvm_R.InstanceID="a""#,
            r#"Msvm_R.InstanceID="b""#
        ));
    }

    #[test]
    fn resource_types_are_the_documented_values() {
        // From Msvm_ResourceAllocationSettingData.ResourceType:
        // 15 = CD drive, 16 = DVD drive, 17 = disk drive,
        // 21 = serial port, 31 = logical disk, 33 = Ethernet connection.
        assert_eq!(RESOURCE_TYPE_DVD, 16);
        assert_eq!(RESOURCE_TYPE_ISO_MEDIA, 31);
        assert_eq!(RESOURCE_TYPE_ETHERNET_CONNECTION, 33);
    }

    #[test]
    fn vlan_operation_modes_are_the_documented_values() {
        // Access = 1, Trunk = 2, Private = 3.
        assert_eq!(VLAN_OPERATION_ACCESS, 1);
        assert_eq!(VLAN_OPERATION_TRUNK, 2);
    }

    #[test]
    fn vlan_xml_access_mode_carries_access_id() {
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_EthernetSwitchPortVlanSettingData\">\
             <PROPERTY NAME=\"OperationMode\" TYPE=\"uint32\"><VALUE>{VLAN_OPERATION_ACCESS}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"AccessVlanId\" TYPE=\"uint16\"><VALUE>42</VALUE></PROPERTY>\
             </INSTANCE>"
        );
        assert!(xml.contains("<VALUE>42</VALUE>"));
        assert!(xml.contains("<VALUE>1</VALUE>"));
        assert!(!xml.contains("NativeVlanId"));
    }

    #[test]
    fn vlan_xml_trunk_mode_carries_native_id() {
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_EthernetSwitchPortVlanSettingData\">\
             <PROPERTY NAME=\"OperationMode\" TYPE=\"uint32\"><VALUE>{VLAN_OPERATION_TRUNK}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"NativeVlanId\" TYPE=\"uint16\"><VALUE>7</VALUE></PROPERTY>\
             </INSTANCE>"
        );
        assert!(xml.contains("NativeVlanId"));
        assert!(xml.contains("<VALUE>2</VALUE>"));
    }

    #[test]
    fn iso_media_xml_uses_host_resource_array() {
        // `HostResource` must be an array property; a scalar one is
        // rejected by the provider. `Parent` is the drive reference.
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_StorageAllocationSettingData\">\
             <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\"><VALUE>{RESOURCE_TYPE_ISO_MEDIA}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\"><VALUE>{SUBTYPE_ISO_MEDIA}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Parent\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
             <PROPERTY.ARRAY NAME=\"HostResource\" TYPE=\"string\">\
             <VALUE.ARRAY><VALUE>{}</VALUE></VALUE.ARRAY></PROPERTY.ARRAY>\
             </INSTANCE>",
            xml_escape("Msvm_ResourceAllocationSettingData.InstanceID=\"d\""),
            xml_escape(r"C:\media\install.iso"),
        );
        assert!(xml.contains("PROPERTY.ARRAY NAME=\"HostResource\""));
        assert!(xml.contains("<VALUE.ARRAY>"));
        assert!(xml.contains(r"C:\media\install.iso"));
        assert!(xml.contains("Virtual CD/DVD Disk"));
    }
}
