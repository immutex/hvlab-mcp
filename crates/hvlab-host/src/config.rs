//! VM configuration: memory, processor, notes, nested virtualization.
//!
//! Getters read `Msvm_MemorySettingData`, `Msvm_ProcessorSettingData`,
//! and the realized `Msvm_VirtualSystemSettingData`. Setters patch the
//! same classes via `ModifyResourceSettings` /
//! `ModifySystemSettings` on `Msvm_VirtualSystemManagementService`,
//! passing embedded-instance XML (same wire format as the checkpoint
//! and storage modules). Every setter takes a `dry_run` flag that
//! returns the diff without touching WMI.
//!
//! `Notes` is a `StringArray` on the settings class; this module
//! flattens it to one string (lines joined by `\n`) because the field
//! is treated as one text block everywhere else in the stack.
//!
//! Memory quantities (`VirtualQuantity`, `Reservation`, `Limit`) are
//! reported in MiB units by the provider — 2048 means 2 GiB.

use hvlab_core::error::{ErrorCode, HvError, Result};
use hvlab_core::ids::VmId;
use serde::{Deserialize, Serialize};
use wmi::WMIConnection;

use crate::wmi_util::{
    JobHandle, call_method, class::ManagementService, deadline_in, escape_wql, service_path,
    wmi_err,
};

/// A VM's memory/processor/notes configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmConfig {
    /// Startup RAM in MB (`VirtualQuantity` of the memory setting).
    pub memory_mb: u64,
    /// Whether dynamic memory is enabled.
    pub dynamic_memory: bool,
    /// Dynamic memory buffer percentage (5–95), when dynamic.
    pub buffer_pct: Option<u8>,
    /// Minimum RAM in MB under dynamic memory, when dynamic.
    pub memory_min_mb: Option<u64>,
    /// Maximum RAM in MB under dynamic memory, when dynamic.
    pub memory_max_mb: Option<u64>,
    /// Virtual processor count.
    pub processor_count: u32,
    /// Notes text, when set.
    pub notes: Option<String>,
    /// Whether nested virtualization extensions are exposed.
    pub nested_virt: bool,
}

/// Diff of one configuration field: what changed (or would change).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigDiff {
    /// Field that changed (or would change).
    pub field: String,
    /// Value before (or current, for a dry run).
    pub before: serde_json::Value,
    /// Value after (or proposed, for a dry run).
    pub after: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_MemorySettingData")]
struct RawMemory {
    #[serde(rename = "InstanceID")]
    instance_id: String,
    #[serde(rename = "VirtualQuantity")]
    virtual_quantity: u64,
    #[serde(rename = "Reservation")]
    reservation: u64,
    #[serde(rename = "Limit")]
    limit: u64,
    #[serde(rename = "DynamicMemoryEnabled")]
    dynamic_memory_enabled: bool,
    #[serde(rename = "TargetMemoryBuffer")]
    target_memory_buffer: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_ProcessorSettingData")]
struct RawProcessor {
    #[serde(rename = "InstanceID")]
    instance_id: String,
    #[serde(rename = "VirtualQuantity")]
    virtual_quantity: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Msvm_VirtualSystemSettingData")]
struct RawSettings {
    #[serde(rename = "InstanceID")]
    instance_id: String,
    #[serde(rename = "Notes", default)]
    notes: Option<Vec<String>>,
    #[serde(rename = "ExposeVirtualizationExtensions", default)]
    expose_virtualization_extensions: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ModifyResourcesIn {
    resource_settings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ModifySystemIn {
    system_settings: String,
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

/// Property XML for a scalar uint64.
fn prop_u64(name: &str, value: u64) -> String {
    format!("<PROPERTY NAME=\"{name}\" TYPE=\"uint64\"><VALUE>{value}</VALUE></PROPERTY>")
}

/// Property XML for a scalar uint32.
fn prop_u32(name: &str, value: u32) -> String {
    format!("<PROPERTY NAME=\"{name}\" TYPE=\"uint32\"><VALUE>{value}</VALUE></PROPERTY>")
}

/// Property XML for a boolean.
fn prop_bool(name: &str, value: bool) -> String {
    format!(
        "<PROPERTY NAME=\"{name}\" TYPE=\"boolean\"><VALUE>{}</VALUE></PROPERTY>",
        if value { "TRUE" } else { "FALSE" }
    )
}

/// Configuration read/patch operations.
pub struct ConfigService {
    conn: WMIConnection,
}

impl ConfigService {
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

    fn memory_of(&self, vm: VmId) -> Result<RawMemory> {
        let query = format!(
            "SELECT InstanceID, VirtualQuantity, Reservation, Limit, DynamicMemoryEnabled, \
             TargetMemoryBuffer FROM Msvm_MemorySettingData \
             WHERE InstanceID LIKE 'Microsoft:{}\\%%'",
            escape_wql(&vm.0.to_string())
        );
        let rows: Vec<RawMemory> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .ok_or_else(|| HvError::not_found("memory settings", &vm.to_string()))
    }

    fn processor_of(&self, vm: VmId) -> Result<RawProcessor> {
        let query = format!(
            "SELECT InstanceID, VirtualQuantity FROM Msvm_ProcessorSettingData \
             WHERE InstanceID LIKE 'Microsoft:{}\\%%'",
            escape_wql(&vm.0.to_string())
        );
        let rows: Vec<RawProcessor> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .ok_or_else(|| HvError::not_found("processor settings", &vm.to_string()))
    }

    fn settings_of(&self, vm: VmId) -> Result<RawSettings> {
        let query = format!(
            "SELECT InstanceID, Notes, ExposeVirtualizationExtensions \
             FROM Msvm_VirtualSystemSettingData \
             WHERE VirtualSystemType = 'Microsoft:Hyper-V:System:Realized' \
             AND VirtualSystemIdentifier = '{}'",
            escape_wql(&vm.0.to_string())
        );
        let rows: Vec<RawSettings> = self.conn.raw_query(&query).map_err(|e| wmi_err(&e))?;
        rows.into_iter()
            .next()
            .ok_or_else(|| HvError::not_found("vm settings", &vm.to_string()))
    }

    /// Read the VM's memory/processor/notes configuration.
    ///
    /// # Errors
    ///
    /// `ErrorCode::NotFound` for an unknown VM, `ErrorCode::Transport`
    /// on WMI failure.
    pub fn get_config(&self, vm: VmId) -> Result<VmConfig> {
        let memory = self.memory_of(vm)?;
        let processor = self.processor_of(vm)?;
        let settings = self.settings_of(vm)?;
        let dynamic = memory.dynamic_memory_enabled;
        Ok(VmConfig {
            memory_mb: memory.virtual_quantity,
            dynamic_memory: dynamic,
            buffer_pct: dynamic.then(|| u8::try_from(memory.target_memory_buffer).unwrap_or(0)),
            memory_min_mb: dynamic.then_some(memory.reservation),
            memory_max_mb: dynamic.then_some(memory.limit),
            processor_count: u32::try_from(processor.virtual_quantity).unwrap_or(0),
            notes: settings.notes.as_ref().map(|lines| lines.join("\n")),
            nested_virt: settings.expose_virtualization_extensions.unwrap_or(false),
        })
    }

    /// Set memory: startup MB, dynamic flag, buffer percentage.
    ///
    /// With `dry_run` the diff is computed against the live
    /// configuration and nothing is sent to the provider.
    ///
    /// # Errors
    ///
    /// `ErrorCode::InvalidArgument` for a zero size or a buffer outside
    /// 5–95, `ErrorCode::NotFound` for an unknown VM,
    /// `ErrorCode::Precondition` when the provider refuses the change.
    pub fn set_memory(
        &self,
        vm: VmId,
        memory_mb: u64,
        dynamic: bool,
        buffer_pct: Option<u8>,
        dry_run: bool,
    ) -> Result<Vec<ConfigDiff>> {
        if memory_mb == 0 {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                "memory_mb must be greater than zero",
            ));
        }
        if let Some(b) = buffer_pct
            && !(5..=95).contains(&b)
        {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                format!("buffer_pct must be 5-95, got {b}"),
            ));
        }
        let current = self.memory_of(vm)?;
        let buffer =
            buffer_pct.unwrap_or_else(|| u8::try_from(current.target_memory_buffer).unwrap_or(20));
        let before = serde_json::json!({
            "memory_mb": current.virtual_quantity,
            "dynamic": current.dynamic_memory_enabled,
            "buffer_pct": current
                .dynamic_memory_enabled
                .then(|| u8::try_from(current.target_memory_buffer).unwrap_or(0)),
        });
        let after = serde_json::json!({
            "memory_mb": memory_mb,
            "dynamic": dynamic,
            "buffer_pct": dynamic.then_some(buffer),
        });
        let diffs = diff_of("memory", &before, &after);
        if diffs.is_empty() || dry_run {
            return Ok(diffs);
        }
        let mut xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_MemorySettingData\">\
             <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>",
            xml_escape(&current.instance_id)
        );
        xml.push_str(&prop_u64("VirtualQuantity", memory_mb));
        xml.push_str(&prop_bool("DynamicMemoryEnabled", dynamic));
        if dynamic {
            xml.push_str(&prop_u32("TargetMemoryBuffer", u32::from(buffer)));
        }
        xml.push_str("</INSTANCE>");
        self.modify_resource(&xml, "ModifyResourceSettings (memory)")?;
        Ok(diffs)
    }

    /// Set the virtual processor count.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::set_memory`].
    pub fn set_processor(&self, vm: VmId, count: u32, dry_run: bool) -> Result<Vec<ConfigDiff>> {
        if count == 0 {
            return Err(HvError::new(
                ErrorCode::InvalidArgument,
                "processor count must be greater than zero",
            ));
        }
        let current = self.processor_of(vm)?;
        let before = serde_json::json!(u32::try_from(current.virtual_quantity).unwrap_or(0));
        let diffs = diff_of("processor_count", &before, &serde_json::json!(count));
        if diffs.is_empty() || dry_run {
            return Ok(diffs);
        }
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_ProcessorSettingData\">\
             <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"VirtualQuantity\" TYPE=\"uint64\"><VALUE>{count}</VALUE></PROPERTY>\
             </INSTANCE>",
            xml_escape(&current.instance_id)
        );
        self.modify_resource(&xml, "ModifyResourceSettings (processor)")?;
        Ok(diffs)
    }

    /// Set the VM's notes text (empty string clears it).
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::set_memory`].
    pub fn set_notes(&self, vm: VmId, notes: &str, dry_run: bool) -> Result<Vec<ConfigDiff>> {
        let current = self.settings_of(vm)?;
        let before = serde_json::json!(
            current
                .notes
                .as_ref()
                .map(|lines| lines.join("\n"))
                .unwrap_or_default()
        );
        let diffs = diff_of("notes", &before, &serde_json::json!(notes));
        if diffs.is_empty() || dry_run {
            return Ok(diffs);
        }
        // Notes is a string array on the wire; a single-element array
        // is what Hyper-V Manager writes.
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_VirtualSystemSettingData\">\
             <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
             <PROPERTY.ARRAY NAME=\"Notes\" TYPE=\"string\">\
             <VALUE.ARRAY><VALUE>{}</VALUE></VALUE.ARRAY></PROPERTY.ARRAY>\
             </INSTANCE>",
            xml_escape(&current.instance_id),
            xml_escape(notes),
        );
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "ModifySystemSettings",
            ModifySystemIn {
                system_settings: xml,
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "ModifySystemSettings", deadline_in(30))?;
        Ok(diffs)
    }

    /// Enable or disable nested virtualization
    /// (`ExposeVirtualizationExtensions`). The provider applies it
    /// only while the VM is off.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::set_memory`].
    pub fn set_nested_virt(
        &self,
        vm: VmId,
        enable: bool,
        dry_run: bool,
    ) -> Result<Vec<ConfigDiff>> {
        let current = self.settings_of(vm)?;
        let before = serde_json::json!(current.expose_virtualization_extensions.unwrap_or(false));
        let diffs = diff_of("nested_virt", &before, &serde_json::json!(enable));
        if diffs.is_empty() || dry_run {
            return Ok(diffs);
        }
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_VirtualSystemSettingData\">\
             <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>{}</VALUE></PROPERTY>\
             <PROPERTY NAME=\"ExposeVirtualizationExtensions\" TYPE=\"boolean\"><VALUE>{}</VALUE></PROPERTY>\
             </INSTANCE>",
            xml_escape(&current.instance_id),
            if enable { "TRUE" } else { "FALSE" },
        );
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "ModifySystemSettings",
            ModifySystemIn {
                system_settings: xml,
            },
        )?;
        JobHandle::from(out).finish(&self.conn, "ModifySystemSettings", deadline_in(30))?;
        Ok(diffs)
    }

    /// Send a resource patch through `ModifyResourceSettings`.
    fn modify_resource(&self, xml: &str, what: &str) -> Result<()> {
        let svc = service_path(&self.conn, "Msvm_VirtualSystemManagementService")?;
        let out: ManagementJobOut = call_method::<ManagementService, _>(
            &self.conn,
            &svc,
            "ModifyResourceSettings",
            ModifyResourcesIn {
                resource_settings: vec![xml.to_owned()],
            },
        )?;
        JobHandle::from(out).finish(&self.conn, what, deadline_in(30))
    }
}

/// Diff helper: an empty vec when values are equal.
fn diff_of(field: &str, before: &serde_json::Value, after: &serde_json::Value) -> Vec<ConfigDiff> {
    if before == after {
        Vec::new()
    } else {
        vec![ConfigDiff {
            field: field.to_owned(),
            before: before.clone(),
            after: after.clone(),
        }]
    }
}

/// Read a VM's configuration (connect-per-call convenience for the
/// MCP layer; `wmi` connections are `!Send`).
///
/// # Errors
///
/// Same as [`ConfigService::get_config`].
pub fn get_config(vm: VmId) -> Result<VmConfig> {
    ConfigService::connect()?.get_config(vm)
}

/// Set memory; see [`ConfigService::set_memory`].
///
/// # Errors
///
/// Same as [`ConfigService::set_memory`].
pub fn set_memory(
    vm: VmId,
    memory_mb: u64,
    dynamic: bool,
    buffer_pct: Option<u8>,
    dry_run: bool,
) -> Result<Vec<ConfigDiff>> {
    ConfigService::connect()?.set_memory(vm, memory_mb, dynamic, buffer_pct, dry_run)
}

/// Set processor count; see [`ConfigService::set_processor`].
///
/// # Errors
///
/// Same as [`ConfigService::set_processor`].
pub fn set_processor(vm: VmId, count: u32, dry_run: bool) -> Result<Vec<ConfigDiff>> {
    ConfigService::connect()?.set_processor(vm, count, dry_run)
}

/// Set notes; see [`ConfigService::set_notes`].
///
/// # Errors
///
/// Same as [`ConfigService::set_notes`].
pub fn set_notes(vm: VmId, notes: &str, dry_run: bool) -> Result<Vec<ConfigDiff>> {
    ConfigService::connect()?.set_notes(vm, notes, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_of_is_empty_for_equal_values() {
        let v = serde_json::json!(5);
        let same = diff_of("x", &v, &v);
        assert!(
            same.is_empty(),
            "equal values must produce no diff, got {same:?}"
        );
        let d = diff_of("x", &serde_json::json!(5), &serde_json::json!(6));
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "x");
        assert_eq!(d[0].before, serde_json::json!(5));
        assert_eq!(d[0].after, serde_json::json!(6));
    }

    #[test]
    fn memory_validation_rejects_out_of_range_dry_run() {
        let svc = ConfigService::connect().expect("connect");
        let bogus = VmId(uuid::Uuid::nil());
        let err = svc
            .set_memory(bogus, 0, false, None, true)
            .expect_err("zero memory rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let err = svc
            .set_memory(bogus, 1024, true, Some(4), true)
            .expect_err("buffer 4 rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let err = svc
            .set_memory(bogus, 1024, true, Some(96), true)
            .expect_err("buffer 96 rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn processor_validation_rejects_zero_dry_run() {
        let svc = ConfigService::connect().expect("connect");
        let bogus = VmId(uuid::Uuid::nil());
        let err = svc
            .set_processor(bogus, 0, true)
            .expect_err("zero cpus rejected");
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn memory_xml_carries_instance_id_and_values() {
        // Shape check via the same builders set_memory uses.
        let xml = format!(
            "<INSTANCE CLASSNAME=\"Msvm_MemorySettingData\">\
             <PROPERTY NAME=\"InstanceID\" TYPE=\"string\"><VALUE>Microsoft:abc</VALUE></PROPERTY>{}{}</INSTANCE>",
            prop_u64("VirtualQuantity", 2048),
            prop_bool("DynamicMemoryEnabled", true),
        );
        assert!(xml.contains(r"<VALUE>2048</VALUE>"));
        assert!(xml.contains(r"<VALUE>TRUE</VALUE>"));
        assert!(xml.find("InstanceID").unwrap() < xml.find("VirtualQuantity").unwrap());
    }
}
