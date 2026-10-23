//! Checkpoints: `Msvm_VirtualSystemSnapshotService` and the
//! `Msvm_VirtualSystemSettingData` tree.
//!
//! Three enums govern a checkpoint and they are easy to confuse:
//!
//! * `CreateSnapshot.SnapshotType` — `2` = full (memory + device state +
//!   disk), `3` = disk-only.
//! * `Msvm_VirtualSystemSnapshotSettingData.ConsistencyLevel` — `1` =
//!   application-consistent (VSS inside the guest), `2` = crash-consistent.
//! * `Msvm_VirtualSystemSettingData.UserSnapshotType` on the VM — `2`
//!   disabled, `3` production-with-fallback, `4` production-only, `5`
//!   standard. This is the VM-level *default* kind, not a property of an
//!   individual checkpoint.
//!
//! Verified against a live host: `CreateSnapshot` **ignores**
//! `SnapshotSettings.ElementName` and always auto-names the checkpoint
//! (`<VM> - (<timestamp>)`). Naming therefore requires a follow-up
//! `ModifySystemSettings` on the new snapshot's settings object, which is
//! also how Hyper-V Manager does it. [`CheckpointService::create`] does
//! the create-then-rename dance and identifies the new checkpoint by
//! set difference, never by name matching.

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use serde::{Deserialize, Serialize};
use wmi::WMIConnection;

use crate::wmi_util::{
    JobHandle, call_method,
    class::{ManagementService, SnapshotService},
    deadline_in, escape_wql, service_path, wmi_err,
};

/// Which kind of checkpoint to take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    /// Memory + device state + disk (Hyper-V "Standard").
    Standard,
    /// Disk-only, VSS-consistent when the guest supports it (Hyper-V
    /// "Production").
    Production,
    /// Disk-only, crash-consistent.
    DiskOnly,
}

impl CheckpointKind {
    /// `SnapshotType` for `CreateSnapshot`.
    const fn snapshot_type(self) -> u16 {
        match self {
            Self::Standard => 2,                    // Full Snapshot
            Self::Production | Self::DiskOnly => 3, // Disk Snapshot
        }
    }

    /// `ConsistencyLevel` for `Msvm_VirtualSystemSnapshotSettingData`.
    const fn consistency_level(self) -> u8 {
        match self {
            Self::Production => 1,                // Application Consistent
            Self::Standard | Self::DiskOnly => 2, // Crash Consistent
        }
    }
}

impl std::str::FromStr for CheckpointKind {
    type Err = HvError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "standard" => Ok(Self::Standard),
            "production" => Ok(Self::Production),
            "disk_only" | "disk-only" => Ok(Self::DiskOnly),
            other => Err(HvError::new(
                ErrorCode::InvalidArgument,
                format!("checkpoint kind must be standard|production|disk_only, got {other}"),
            )),
        }
    }
}

/// One checkpoint in a VM's tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    /// `ConfigurationID` — the checkpoint's stable identifier.
    pub id: String,
    /// Display name (`ElementName`).
    pub name: String,
    /// `CreationTime` in CIM datetime form (`yyyymmddHHMMSS.ffffff+OOO`).
    ///
    /// Kept verbatim: the provider reports `-000`, which means "offset
    /// unknown, time is host-local", so converting it to UTC would
    /// invent an offset and shift the instant.
    pub created: Option<String>,
    /// `UserSnapshotType` inherited from the VM at creation time.
    pub snapshot_type: Option<u16>,
    /// `ConfigurationID` of the parent checkpoint, when nested.
    pub parent: Option<String>,
    /// True for checkpoints the host took on its own.
    pub automatic: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_VirtualSystemSettingData")]
struct RawCheckpoint {
    #[serde(rename = "ConfigurationID")]
    configuration_id: String,
    #[serde(rename = "ElementName")]
    element_name: String,
    #[serde(rename = "CreationTime", default)]
    creation_time: Option<wmi::WMIDateTime>,
    #[serde(rename = "UserSnapshotType", default)]
    user_snapshot_type: Option<u16>,
    #[serde(rename = "Parent", default)]
    parent: Option<String>,
    #[serde(rename = "IsAutomaticSnapshot", default)]
    is_automatic_snapshot: Option<bool>,
}

impl RawCheckpoint {
    fn into_checkpoint(self) -> Checkpoint {
        Checkpoint {
            id: self.configuration_id,
            name: self.element_name,
            created: self
                .creation_time
                .map(|t| t.0.format("%Y%m%d%H%M%S%.6f%z").to_string()),
            snapshot_type: self.user_snapshot_type,
            parent: self.parent.as_deref().map(parent_id),
            automatic: self.is_automatic_snapshot.unwrap_or(false),
        }
    }
}

/// Pull the `ConfigurationID` out of a settings reference path.
///
/// The provider emits `...Msvm_VirtualSystemSettingData.InstanceID="Microsoft:<guid>"`
/// for `Parent`, and `ConfigurationID="<guid>"` in other references.
fn parent_id(reference: &str) -> String {
    let raw = reference
        .rsplit_once("ConfigurationID=\"")
        .or_else(|| reference.rsplit_once("InstanceID=\""))
        .and_then(|(_, rest)| rest.split('"').next())
        .unwrap_or(reference);
    raw.strip_prefix("Microsoft:").unwrap_or(raw).to_owned()
}

/// Minimal XML text escaping for embedded-instance property values.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// An embedded `Msvm_VirtualSystemSnapshotSettingData` instance.
fn snapshot_settings_xml(name: &str, consistency: u8) -> String {
    format!(
        "<INSTANCE CLASSNAME=\"Msvm_VirtualSystemSnapshotSettingData\">\
         <PROPERTY NAME=\"ElementName\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
         <PROPERTY NAME=\"ConsistencyLevel\" TYPE=\"uint8\"><VALUE>{consistency}</VALUE></PROPERTY>\
         </INSTANCE>",
        xml_escape(name)
    )
}

/// An embedded `Msvm_VirtualSystemSettingData` instance that only carries
/// identity plus the properties being changed.
fn settings_patch_xml(instance_id: &str, name: &str) -> String {
    format!(
        "<INSTANCE CLASSNAME=\"Msvm_VirtualSystemSettingData\">\
         <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
         <PROPERTY NAME=\"ElementName\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
         </INSTANCE>",
        xml_escape(instance_id),
        xml_escape(name)
    )
}

/// Return value of a Hyper-V method that creates an async job.
#[derive(Debug, Deserialize)]
struct JobOut {
    #[serde(rename = "ReturnValue")]
    return_value: u32,
    #[serde(rename = "Job", default)]
    job: Option<String>,
}

impl From<JobOut> for JobHandle {
    fn from(out: JobOut) -> Self {
        Self {
            return_value: out.return_value,
            job: out.job,
        }
    }
}

/// In-parameters of `CreateSnapshot`. Field names must match the MOF
/// exactly; the `wmi` serializer maps struct fields to WMI properties.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct CreateSnapshotIn {
    affected_system: String,
    snapshot_settings: String,
    snapshot_type: u16,
}

/// In-parameters of `DestroySnapshot`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DestroySnapshotIn {
    affected_snapshot: String,
}

/// In-parameters of `DestroySnapshotTree`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DestroyTreeIn {
    snapshot_setting_data: String,
}

/// In-parameters of `ApplySnapshot`.
#[derive(Debug, Serialize)]
struct ApplySnapshotIn {
    snapshot: String,
}

/// In-parameters of `ModifySystemSettings`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ModifySettingsIn {
    system_settings: String,
}

/// Checkpoint operations against the local host.
pub struct CheckpointService {
    conn: WMIConnection,
}

impl CheckpointService {
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

    /// Every checkpoint of a VM, newest first.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Transport` on WMI failure.
    pub fn list(&self, vm: VmId) -> Result<Vec<Checkpoint>> {
        let query = format!(
            "SELECT ConfigurationID, ElementName, CreationTime, UserSnapshotType, Parent, \
             IsAutomaticSnapshot FROM Msvm_VirtualSystemSettingData \
             WHERE VirtualSystemType = 'Microsoft:Hyper-V:Snapshot:Realized' \
             AND VirtualSystemIdentifier = '{}'",
            escape_wql(&vm.0.to_string())
        );
        let mut rows: Vec<RawCheckpoint> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        // Newest first. `creation_time` is `Option<WMIDateTime>`; the
        // provider always sets it, so `None` only appears on odd hosts.
        rows.sort_by_key(|b| std::cmp::Reverse(b.creation_time));
        Ok(rows
            .into_iter()
            .map(RawCheckpoint::into_checkpoint)
            .collect())
    }

    /// One checkpoint by `ConfigurationID` or display name.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` when the VM has no such checkpoint.
    pub fn get(&self, vm: VmId, name_or_id: &str) -> Result<Checkpoint> {
        self.list(vm)?
            .into_iter()
            .find(|c| c.id.eq_ignore_ascii_case(name_or_id) || c.name == name_or_id)
            .ok_or_else(|| HvError::not_found("checkpoint", name_or_id))
    }

    /// Take a checkpoint, name it, and return it once the job completes.
    ///
    /// The provider auto-names checkpoints and ignores
    /// `SnapshotSettings.ElementName`, so the new checkpoint is found by
    /// comparing the checkpoint set before and after the job, then
    /// renamed if the caller asked for a different name.
    ///
    /// # Errors
    ///
    /// `ErrorCode::Precondition` when the VM refuses the request (for
    /// example, checkpoints disabled via `UserSnapshotType = 2`),
    /// `ErrorCode::Timeout` when the job outlives `timeout_secs`.
    pub fn create(
        &self,
        vm: VmId,
        name: &str,
        kind: CheckpointKind,
        timeout_secs: u64,
    ) -> Result<Checkpoint> {
        let before: Vec<String> = self.list(vm)?.into_iter().map(|c| c.id).collect();

        let svc_path = service_path(&self.conn, "Msvm_VirtualSystemSnapshotService")?;
        let affected = crate::wmi_util::vm_path(&self.conn, vm)?;
        let out: JobOut = call_method::<SnapshotService, JobOut>(
            &self.conn,
            &svc_path,
            "CreateSnapshot",
            CreateSnapshotIn {
                affected_system: affected,
                snapshot_settings: snapshot_settings_xml(name, kind.consistency_level()),
                snapshot_type: kind.snapshot_type(),
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "CreateSnapshot", deadline_in(timeout_secs))?;

        let after = self.list(vm)?;
        let fresh: Vec<&Checkpoint> = after.iter().filter(|c| !before.contains(&c.id)).collect();
        let created = match fresh.as_slice() {
            [one] => (*one).clone(),
            [] => {
                return Err(HvError::new(
                    ErrorCode::Internal,
                    "CreateSnapshot reported success but no new checkpoint appeared",
                ));
            }
            many => {
                return Err(HvError::new(
                    ErrorCode::Internal,
                    format!(
                        "CreateSnapshot produced {} new checkpoints: {}",
                        many.len(),
                        many.iter()
                            .map(|c| c.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        };

        if created.name == name {
            return Ok(created);
        }
        self.rename(vm, &created.id, name)?;
        self.get(vm, &created.id)
    }

    /// Rename a checkpoint.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound`, `Precondition` for a refused request.
    pub fn rename(&self, vm: VmId, name_or_id: &str, new_name: &str) -> Result<()> {
        let cp = self.get(vm, name_or_id)?;
        let instance_id = self.instance_id(&cp.id)?;
        let svc_path = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;

        let out: JobOut = call_method::<ManagementService, JobOut>(
            &self.conn,
            &svc_path,
            "ModifySystemSettings",
            ModifySettingsIn {
                system_settings: settings_patch_xml(&instance_id, new_name),
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "ModifySystemSettings", deadline_in(30))
    }

    /// Delete one checkpoint, or its whole subtree.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound`, `Precondition` for a refused request.
    pub fn delete(
        &self,
        vm: VmId,
        name_or_id: &str,
        include_subtree: bool,
        timeout_secs: u64,
    ) -> Result<()> {
        let cp = self.get(vm, name_or_id)?;
        let path = self.settings_path(&cp.id)?;
        let svc_path = service_path(&self.conn, "Msvm_VirtualSystemSnapshotService")?;
        let out: JobOut = if include_subtree {
            call_method::<SnapshotService, JobOut>(
                &self.conn,
                &svc_path,
                "DestroySnapshotTree",
                DestroyTreeIn {
                    snapshot_setting_data: path,
                },
            )?
        } else {
            call_method::<SnapshotService, JobOut>(
                &self.conn,
                &svc_path,
                "DestroySnapshot",
                DestroySnapshotIn {
                    affected_snapshot: path,
                },
            )?
        };
        let what = if include_subtree {
            "DestroySnapshotTree"
        } else {
            "DestroySnapshot"
        };
        JobHandle::from(out).finish(&self.conn, what, deadline_in(timeout_secs))
    }

    /// Restore a checkpoint, discarding everything after it.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound`, `Precondition` for a refused request.
    pub fn restore(&self, vm: VmId, name_or_id: &str, timeout_secs: u64) -> Result<()> {
        let cp = self.get(vm, name_or_id)?;
        let path = self.settings_path(&cp.id)?;
        let svc_path = service_path(&self.conn, "Msvm_VirtualSystemSnapshotService")?;
        let out: JobOut = call_method::<SnapshotService, JobOut>(
            &self.conn,
            &svc_path,
            "ApplySnapshot",
            ApplySnapshotIn { snapshot: path },
        )?;
        JobHandle::from(out).finish(&self.conn, "ApplySnapshot", deadline_in(timeout_secs))
    }

    /// The checkpoint's `InstanceID` (`Microsoft:<ConfigurationID>`), which
    /// `ModifySystemSettings` needs to address it.
    fn instance_id(&self, configuration_id: &str) -> Result<String> {
        #[derive(Deserialize)]
        #[serde(rename = "Msvm_VirtualSystemSettingData")]
        struct IdOnly {
            #[serde(rename = "InstanceID")]
            instance_id: String,
        }
        let query = format!(
            "SELECT InstanceID FROM Msvm_VirtualSystemSettingData WHERE ConfigurationID = '{}'",
            escape_wql(configuration_id)
        );
        let rows: Vec<IdOnly> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .map(|r| r.instance_id)
            .ok_or_else(|| HvError::not_found("checkpoint settings", configuration_id))
    }

    /// Object path of a checkpoint's `Msvm_VirtualSystemSettingData`.
    fn settings_path(&self, configuration_id: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct PathOnly {
            #[serde(rename = "__PATH")]
            path: String,
        }
        let query = format!(
            "SELECT * FROM Msvm_VirtualSystemSettingData WHERE ConfigurationID = '{}'",
            escape_wql(configuration_id)
        );
        let rows: Vec<PathOnly> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .map(|r| r.path)
            .ok_or_else(|| HvError::not_found("checkpoint settings", configuration_id))
    }
}
