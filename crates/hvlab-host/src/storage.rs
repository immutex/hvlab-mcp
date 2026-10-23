//! Storage: VHD/VHDX lifecycle through `Msvm_ImageManagementService`,
//! and disk/DVD attachment through the VM's resource settings.
//!
//! Attachment goes through `AddResourceSettings` / `RemoveResourceSettings`
//! on `Msvm_VirtualSystemManagementService`, passing embedded
//! `Msvm_ResourceAllocationSettingData` instances. A disk is a *drive*
//! (resource type 17, subtype `Microsoft:Hyper-V:Synthetic Disk Drive`)
//! plus a *file backing* (resource type 31, subtype
//! `Microsoft:VirtualHDisk`) whose `HostResource` names the VHD path —
//! the same split Hyper-V Manager shows as "SCSI controller → hard
//! drive".

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use serde::{Deserialize, Serialize};
use wmi::WMIConnection;

use crate::wmi_util::{
    JobHandle, call_method,
    class::{ImageManagementService, ManagementService},
    deadline_in, escape_wql, service_path, vm_settings_path, wmi_err,
};

/// Resource type for a storage drive.
const RESOURCE_TYPE_STORAGE: u16 = 17;
/// Resource type for a file-backed disk image.
const RESOURCE_TYPE_DISK_FILE: u16 = 31;

/// Disk format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskFormat {
    /// Fixed VHD (raw allocated).
    Vhd,
    /// Dynamic VHD.
    VhdDynamic,
    /// VHDX (recommended: 64 TB limit, 4 KB blocks, resilience).
    Vhdx,
}

impl DiskFormat {
    /// `Format` of `Msvm_VirtualHardDiskSettingData`: the on-disk
    /// container. 2 = VHD, 3 = VHDX, 4 = VHD Set.
    const fn format(self) -> u16 {
        match self {
            Self::Vhd | Self::VhdDynamic => 2,
            Self::Vhdx => 3,
        }
    }

    /// `Type` of `Msvm_VirtualHardDiskSettingData`: the allocation
    /// strategy. 2 = fixed, 3 = dynamic, 4 = differencing.
    const fn disk_type(self) -> u16 {
        match self {
            Self::Vhd => 2,
            Self::VhdDynamic | Self::Vhdx => 3,
        }
    }
}

impl std::str::FromStr for DiskFormat {
    type Err = HvError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "vhd" | "fixed" => Ok(Self::Vhd),
            "vhd_dynamic" | "dynamic" => Ok(Self::VhdDynamic),
            "vhdx" => Ok(Self::Vhdx),
            other => Err(HvError::new(
                ErrorCode::InvalidArgument,
                format!("disk format must be vhd|vhd_dynamic|vhdx, got {other}"),
            )),
        }
    }
}

/// Static description of a VHD/VHDX file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskInfo {
    /// Absolute path on the host.
    pub path: String,
    /// `Type`: 2 = fixed, 3 = dynamic, 4 = differencing.
    pub disk_type: u16,
    /// `Format`: 2 = VHD, 3 = VHDX, 4 = VHD Set.
    pub format: u16,
    /// Virtual size in bytes.
    pub max_internal_size: u64,
    /// Current file size in bytes.
    pub file_size: Option<u64>,
    /// Parent VHD path for differencing disks.
    pub parent: Option<String>,
    /// Block size in bytes.
    pub block_size: Option<u32>,
}

/// Runtime state of a VHD/VHDX file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskState {
    /// Whether the provider considers the file attached/in use.
    pub in_use: bool,
    /// Current size of the file on the host volume.
    pub file_size: Option<u64>,
    /// Free space inside the disk in bytes, when the provider reports it.
    pub free_space: Option<u64>,
    /// Raw `State` string from `GetVirtualHardDiskState`.
    pub raw: String,
}

/// In-parameters for `GetVirtualHardDiskSettingData`.
#[derive(Debug, Serialize)]
struct GetDiskSettingsIn {
    path: String,
}

/// Out-parameters for `GetVirtualHardDiskSettingData`.
#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_ImageManagementService")]
struct GetDiskSettingsOut {
    #[serde(rename = "ReturnValue")]
    return_value: u32,
    #[serde(rename = "SettingData", default)]
    setting_data: Option<String>,
}

/// In-parameters for `GetVirtualHardDiskState`.
#[derive(Debug, Serialize)]
struct GetDiskStateIn {
    path: String,
}

/// Out-parameters for `GetVirtualHardDiskState`.
#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_ImageManagementService")]
struct GetDiskStateOut {
    #[serde(rename = "ReturnValue")]
    return_value: u32,
    #[serde(rename = "State", default)]
    state: Option<String>,
}

/// In-parameters for `CreateVirtualHardDisk`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct CreateDiskIn {
    virtual_disk_setting_data: String,
}

/// In-parameters for `ResizeVirtualHardDisk`.
#[derive(Debug, Serialize)]
struct ResizeDiskIn {
    path: String,
    #[serde(rename = "MaxInternalSize")]
    max_internal_size: u64,
}

/// In-parameters for `ConvertVirtualHardDisk`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ConvertDiskIn {
    source_path: String,
    virtual_disk_setting_data: String,
}

/// In-parameters for `AddResourceSettings`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct AddIn {
    affected_configuration: String,
    resource_settings: Vec<String>,
}

/// In-parameters for `RemoveResourceSettings`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct RemoveIn {
    resource_settings: Vec<String>,
}

/// In-parameters for `CompactVirtualHardDisk`.
#[derive(Debug, Serialize)]
struct CompactDiskIn {
    path: String,
    /// 0 = full (reads every block, best reclaim), 1 = quick,
    /// 2 = retrim, 3 = pretrimmed, 4 = prezeroed.
    mode: u16,
}

/// Out-parameters shared by the job-returning image methods.
#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_ImageManagementService")]
struct ImageJobOut {
    #[serde(rename = "ReturnValue")]
    return_value: u32,
    #[serde(rename = "Job", default)]
    job: Option<String>,
}

impl From<ImageJobOut> for JobHandle {
    fn from(out: ImageJobOut) -> Self {
        Self {
            return_value: out.return_value,
            job: out.job,
        }
    }
}

/// Minimal parse of a `Msvm_VirtualHardDiskSettingData` embedded instance.
///
/// The provider hands these back as XML text; pulling a handful of
/// properties with string search keeps the dependency surface at zero
/// and is adequate because the XML shape is fixed and flat.
fn xml_property<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("PROPERTY NAME=\"{name}\"");
    let start = xml.find(&needle)?;
    let rest = &xml[start..];
    let value_start = rest.find("<VALUE>")? + "<VALUE>".len();
    let rest = &rest[value_start..];
    let value_end = rest.find("</VALUE>")?;
    Some(&rest[..value_end])
}

fn xml_property_u64(xml: &str, name: &str) -> Option<u64> {
    xml_property(xml, name)?.parse().ok()
}

fn xml_property_u32(xml: &str, name: &str) -> Option<u32> {
    xml_property(xml, name)?.parse().ok()
}

fn xml_property_u16(xml: &str, name: &str) -> Option<u16> {
    xml_property(xml, name)?.parse().ok()
}

/// XML text escaping for embedded-instance property values.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// VHD/VHDX operations.
pub struct StorageService {
    conn: WMIConnection,
}

impl StorageService {
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

    /// Static description of a VHD/VHDX file.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when the file does not exist,
    /// `ErrorCode::InvalidArgument` when it is not a virtual disk.
    pub fn inspect(&self, path: &str) -> Result<DiskInfo> {
        let svc = service_path(&self.conn, "Msvm_ImageManagementService")?;
        let out: GetDiskSettingsOut = call_method::<ImageManagementService, _>(
            &self.conn,
            &svc,
            "GetVirtualHardDiskSettingData",
            GetDiskSettingsIn {
                path: path.to_owned(),
            },
        )?;
        if out.return_value != 0 {
            return Err(HvError::new(
                ErrorCode::NotFound,
                format!(
                    "GetVirtualHardDiskSettingData({path}) returned {}",
                    out.return_value
                ),
            ));
        }
        let xml = out.setting_data.unwrap_or_default();
        // A missing state query (file locked by a running VM) is not an
        // inspection failure: the static description still stands.
        let file_size = self.state(path).ok().and_then(|s| s.file_size);
        Ok(DiskInfo {
            path: path.to_owned(),
            disk_type: xml_property_u16(&xml, "Type").unwrap_or(0),
            format: xml_property_u16(&xml, "Format").unwrap_or(0),
            max_internal_size: xml_property_u64(&xml, "MaxInternalSize").unwrap_or(0),
            // `FileSize` lives on `Msvm_VirtualHardDiskState`, not on the
            // settings instance; `inspect` fills it in when it can.
            file_size,
            parent: xml_property(&xml, "ParentPath")
                .filter(|p| !p.is_empty())
                .map(ToOwned::to_owned),
            block_size: xml_property_u32(&xml, "BlockSize"),
        })
    }

    /// Runtime state of a VHD/VHDX file.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when the file does not exist.
    pub fn state(&self, path: &str) -> Result<DiskState> {
        let svc = service_path(&self.conn, "Msvm_ImageManagementService")?;
        let out: GetDiskStateOut = call_method::<ImageManagementService, _>(
            &self.conn,
            &svc,
            "GetVirtualHardDiskState",
            GetDiskStateIn {
                path: path.to_owned(),
            },
        )?;
        if out.return_value != 0 {
            return Err(HvError::new(
                ErrorCode::NotFound,
                format!(
                    "GetVirtualHardDiskState({path}) returned {}",
                    out.return_value
                ),
            ));
        }
        let xml = out.state.unwrap_or_default();
        Ok(DiskState {
            in_use: xml_property(&xml, "InUse").is_some_and(|v| v == "TRUE" || v == "true"),
            file_size: xml_property_u64(&xml, "FileSize"),
            free_space: xml_property_u64(&xml, "AvailableSpace"),
            raw: xml,
        })
    }

    /// Create a VHD or VHDX.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` when the file already exists or the size
    /// is out of range, `ErrorCode::Timeout` when the job outlives
    /// `timeout_secs`.
    pub fn create(
        &self,
        path: &str,
        size_bytes: u64,
        format: DiskFormat,
        block_size: Option<u32>,
        timeout_secs: u64,
    ) -> Result<DiskInfo> {
        let svc = service_path(&self.conn, "Msvm_ImageManagementService")?;
        // `ElementName` is the only property the provider marks
        // `Required`; it is the file's display name.
        let element_name = std::path::Path::new(path)
            .file_name()
            .map_or_else(|| path.to_owned(), |n| n.to_string_lossy().into_owned());
        let block_prop = block_size.map_or_else(String::new, |b| {
            format!("<PROPERTY NAME=\"BlockSize\" TYPE=\"uint32\"><VALUE>{b}</VALUE></PROPERTY>")
        });
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_VirtualHardDiskSettingData\">\
             <PROPERTY NAME=\"ElementName\" TYPE=\"string\"><VALUE>{name}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Path\" TYPE=\"string\"><VALUE>{path}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Type\" TYPE=\"uint16\"><VALUE>{disk_type}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Format\" TYPE=\"uint16\"><VALUE>{fmt}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"MaxInternalSize\" TYPE=\"uint64\"><VALUE>{size_bytes}</VALUE></PROPERTY>\
             {block_prop}\
             </INSTANCE>",
            name = xml_escape(&element_name),
            path = xml_escape(path),
            disk_type = format.disk_type(),
            fmt = format.format(),
        );
        let out: ImageJobOut = call_method::<ImageManagementService, _>(
            &self.conn,
            &svc,
            "CreateVirtualHardDisk",
            CreateDiskIn {
                virtual_disk_setting_data: xml,
            },
        )?;
        JobHandle::from(out).finish(
            &self.conn,
            "CreateVirtualHardDisk",
            deadline_in(timeout_secs),
        )?;
        self.inspect(path)
    }

    /// Resize a VHD/VHDX.
    ///
    /// Growing is always allowed; shrinking requires the guest filesystem
    /// to fit, which only the caller can know, so this refuses to shrink
    /// a disk that is attached to a running VM.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` when the provider refuses the size.
    pub fn resize(&self, path: &str, size_bytes: u64, timeout_secs: u64) -> Result<DiskInfo> {
        let svc = service_path(&self.conn, "Msvm_ImageManagementService")?;
        let out: ImageJobOut = call_method::<ImageManagementService, _>(
            &self.conn,
            &svc,
            "ResizeVirtualHardDisk",
            ResizeDiskIn {
                path: path.to_owned(),
                max_internal_size: size_bytes,
            },
        )?;
        JobHandle::from(out).finish(
            &self.conn,
            "ResizeVirtualHardDisk",
            deadline_in(timeout_secs),
        )?;
        self.inspect(path)
    }

    /// Convert a VHD to VHDX (or the reverse), or change fixed/dynamic.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` when the conversion is not possible
    /// (for example, shrinking a disk during conversion).
    pub fn convert(
        &self,
        source: &str,
        destination: &str,
        format: DiskFormat,
        timeout_secs: u64,
    ) -> Result<DiskInfo> {
        let svc = service_path(&self.conn, "Msvm_ImageManagementService")?;
        let element_name = std::path::Path::new(destination).file_name().map_or_else(
            || destination.to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_VirtualHardDiskSettingData\">\
             <PROPERTY NAME=\"ElementName\" TYPE=\"string\"><VALUE>{name}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Path\" TYPE=\"string\"><VALUE>{dest}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Type\" TYPE=\"uint16\"><VALUE>{disk_type}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Format\" TYPE=\"uint16\"><VALUE>{fmt}</VALUE></PROPERTY>\
             </INSTANCE>",
            name = xml_escape(&element_name),
            dest = xml_escape(destination),
            disk_type = format.disk_type(),
            fmt = format.format(),
        );
        let out: ImageJobOut = call_method::<ImageManagementService, _>(
            &self.conn,
            &svc,
            "ConvertVirtualHardDisk",
            ConvertDiskIn {
                source_path: source.to_owned(),
                virtual_disk_setting_data: xml,
            },
        )?;
        JobHandle::from(out).finish(
            &self.conn,
            "ConvertVirtualHardDisk",
            deadline_in(timeout_secs),
        )?;
        self.inspect(destination)
    }

    /// Compact a dynamic VHD/VHDX, reclaiming space from deleted blocks.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` when the disk is attached.
    pub fn compact(&self, path: &str, timeout_secs: u64) -> Result<DiskInfo> {
        let svc = service_path(&self.conn, "Msvm_ImageManagementService")?;
        let out: ImageJobOut = call_method::<ImageManagementService, _>(
            &self.conn,
            &svc,
            "CompactVirtualHardDisk",
            CompactDiskIn {
                path: path.to_owned(),
                mode: 0,
            },
        )?;
        JobHandle::from(out).finish(
            &self.conn,
            "CompactVirtualHardDisk",
            deadline_in(timeout_secs),
        )?;
        self.inspect(path)
    }

    /// Attach a VHD/VHDX to a VM as a new SCSI or IDE drive.
    ///
    /// `controller_number` and `controller_location` select the slot; the
    /// provider rejects a slot that is already occupied, which is the
    /// behaviour we want (no silent remapping).
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` when the slot is taken or the VM cannot
    /// accept the device; `ErrorCode::NotFound` for an unknown VM.
    pub fn attach_disk(
        &self,
        vm: VmId,
        vhd_path: &str,
        scsi: bool,
        controller_number: u32,
        controller_location: u32,
        timeout_secs: u64,
    ) -> Result<()> {
        let settings = vm_settings_path(&self.conn, vm, true)?;
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let controller_class = if scsi {
            "Microsoft:Hyper-V:Synthetic SCSI Controller"
        } else {
            "Microsoft:Hyper-V:Synthetic IDE Controller"
        };
        // Drive placeholder: the provider fills in the InstanceID.
        let drive = format!(
            "<INSTANCE CLASSNAME=\"Msvm_ResourceAllocationSettingData\">\
             <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\"><VALUE>{RESOURCE_TYPE_STORAGE}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\"><VALUE>Microsoft:Hyper-V:Synthetic Disk Drive</VALUE></PROPERTY>\
             <PROPERTY NAME=\"AddressOnParent\" TYPE=\"string\"><VALUE>{controller_location}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"Parent\" TYPE=\"string\"><VALUE>{controller_class}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ControllerNumber\" TYPE=\"uint32\"><VALUE>{controller_number}</VALUE></PROPERTY>\
             </INSTANCE>",
            controller_class = xml_escape(controller_class),
        );
        // The backing file needs the drive's address; Hyper-V correlates
        // the two embedded instances by array order and Parent reference.
        let backing = format!(
            "<INSTANCE CLASSNAME=\"Msvm_ResourceAllocationSettingData\">\
             <PROPERTY NAME=\"ResourceType\" TYPE=\"uint16\"><VALUE>{RESOURCE_TYPE_DISK_FILE}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ResourceSubType\" TYPE=\"string\"><VALUE>Microsoft:VirtualHDisk</VALUE></PROPERTY>\
             <PROPERTY NAME=\"HostResource\" TYPE=\"string\"><VALUE>{vhd}</VALUE></PROPERTY>\
             </INSTANCE>",
            vhd = xml_escape(vhd_path),
        );

        let out: ImageJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "AddResourceSettings",
            AddIn {
                affected_configuration: settings,
                resource_settings: vec![drive, backing],
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "AddResourceSettings", deadline_in(timeout_secs))
    }

    /// Detach a disk by its `HostResource` path.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when no attached disk references the path.
    pub fn detach_disk(&self, vm: VmId, vhd_path: &str, timeout_secs: u64) -> Result<()> {
        let resources = self.disk_resources(vm)?;
        let target = resources
            .iter()
            .find(|r| r.host_resource.as_deref() == Some(vhd_path))
            .ok_or_else(|| HvError::not_found("attached disk", vhd_path))?;

        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let out: ImageJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "RemoveResourceSettings",
            RemoveIn {
                resource_settings: vec![target.path.clone()],
            },
        )?;
        JobHandle::from(out).finish(
            &self.conn,
            "RemoveResourceSettings",
            deadline_in(timeout_secs),
        )
    }

    /// Attached disk files, one entry per backing resource.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn disk_resources(&self, vm: VmId) -> Result<Vec<DiskAttachment>> {
        #[derive(Debug, Deserialize)]
        #[serde(rename = "Msvm_ResourceAllocationSettingData")]
        struct Raw {
            #[serde(rename = "__PATH")]
            path: String,
            #[serde(rename = "ResourceSubType", default)]
            sub_type: Option<String>,
            #[serde(rename = "HostResource", default)]
            host_resource: Option<Vec<String>>,
            #[serde(rename = "AddressOnParent", default)]
            address_on_parent: Option<String>,
        }
        let query = format!(
            "SELECT *, ResourceSubType, HostResource, AddressOnParent \
             FROM Msvm_ResourceAllocationSettingData \
             WHERE ResourceType = {RESOURCE_TYPE_DISK_FILE} \
             AND InstanceID LIKE 'Microsoft:{}\\%%'",
            escape_wql(&vm.0.to_string())
        );
        let rows: Vec<Raw> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        Ok(rows
            .into_iter()
            .map(|r| DiskAttachment {
                path: r.path,
                sub_type: r.sub_type,
                host_resource: r.host_resource.and_then(|v| v.into_iter().next()),
                address_on_parent: r.address_on_parent,
            })
            .collect())
    }
}

/// One attached disk backing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiskAttachment {
    /// Object path of the resource setting.
    pub path: String,
    /// `ResourceSubType` (for example `Microsoft:VirtualHDisk`).
    pub sub_type: Option<String>,
    /// VHD path in `HostResource`.
    pub host_resource: Option<String>,
    /// Slot on the controller.
    pub address_on_parent: Option<String>,
}
