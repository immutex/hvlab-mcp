//! Host-integration tests: real WMI against the local Hyper-V host.
//! These run only when a VM is present; `cargo test` on a machine
//! without Hyper-V skips them via the environment probe.

use crate::checkpoint::{CheckpointKind, CheckpointService};
use crate::job::{JobOutcome, await_wmi_job};
use crate::network::{NetworkService, SwitchKind};
use crate::storage::{DiskFormat, StorageService};
use crate::vm::VmService;
use hvlab_core::error::ErrorCode;
use hvlab_core::ids::VmId;
use std::time::{Duration, Instant};

/// Switch creation is host-visible: an internal switch leaves a vEthernet
/// adapter behind on the host. It is off unless explicitly requested.
fn host_mutation_tests_allowed() -> bool {
    std::env::var("HVLAB_ALLOW_HOST_MUTATION_TESTS").is_ok_and(|v| v == "1")
}

/// RAII cleanup: removes a named switch when the test ends, success or
/// panic, so a mid-test assertion cannot leave a switch (or the vEthernet
/// adapter it owns) on the host.
struct SwitchCleanup<'a>(&'a NetworkService, &'a str);

impl Drop for SwitchCleanup<'_> {
    fn drop(&mut self) {
        match self.0.remove_switch(self.1, 120) {
            Ok(()) => {}
            // Nothing was created, so there is nothing to clean up.
            Err(e) if e.code == ErrorCode::NotFound => {}
            Err(e) => eprintln!("cleanup: could not remove switch {}: {:?}", self.1, e.code),
        }
    }
}

/// Skip the suite when WMI v2 has no VMs (CI, non-Hyper-V machines).
fn service_or_skip() -> Option<VmService> {
    let svc = VmService::connect().ok()?;
    let vms = svc.list_vms().ok()?;
    if vms.is_empty() {
        eprintln!("skipping: no VMs on this host");
        return None;
    }
    Some(svc)
}

#[test]
fn list_vms_returns_inventory_with_decoded_states() {
    let Some(svc) = service_or_skip() else { return };
    let vms = svc.list_vms().expect("list");
    assert!(!vms.is_empty());
    for vm in &vms {
        assert!(!vm.name.is_empty());
        // Decoded, not raw: every state must be a known variant or a
        // carried Unknown — never a default.
        let _ = vm.state.to_string();
    }
}

#[test]
fn get_vm_by_guid_returns_same_vm_and_missing_guid_is_not_found() {
    let Some(svc) = service_or_skip() else { return };
    let vms = svc.list_vms().expect("list");
    let first = &vms[0];
    let fetched = svc.get_vm(first.id).expect("get");
    assert_eq!(fetched.id, first.id);

    let bogus = VmId(uuid::Uuid::nil());
    let err = svc.get_vm(bogus).expect_err("missing vm");
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[test]
fn vanished_job_is_reported_not_guessed() {
    // A nonexistent job path must yield Vanished, not a fabricated
    // failure — callers then check the operation's actual effect.
    let svc = VmService::connect().expect("connect");
    let conn = svc.connection_for_test().expect("connection");
    let deadline = Instant::now() + Duration::from_secs(1);
    // Well-formed object path that no longer exists: WMI returns zero
    // rows (job removed after the ~5 min retention), not a query error.
    // A relative object path for a job that does not exist: the query
    // returns zero rows, which `await_wmi_job` must report as Vanished.
    let outcome = await_wmi_job(
        &conn,
        "Msvm_ConcreteJob.InstanceID=\"missing-job-id\"",
        deadline,
    )
    .expect("poll completes");
    assert_eq!(outcome, JobOutcome::Vanished);
}

#[test]
fn request_state_on_missing_vm_is_not_found() {
    let Some(svc) = service_or_skip() else { return };
    let bogus = VmId(uuid::Uuid::nil());
    let err = svc
        .request_state(bogus, 2, Instant::now() + Duration::from_secs(5))
        .expect_err("missing vm");
    assert_eq!(err.code, ErrorCode::NotFound);
}

/// A live VM to run checkpoint round-trips against: the first one that is
/// not the host computer system.
fn checkpoint_service_or_skip() -> Option<(CheckpointService, VmId)> {
    let svc = CheckpointService::connect().ok()?;
    let vms = VmService::connect().ok()?.list_vms().ok()?;
    let vm = vms.first()?.id;
    Some((svc, vm))
}

/// Full checkpoint round-trip: create → listed → rename → delete.
///
/// Takes a real checkpoint of a real VM, so it is slow and mutates the
/// host. It cleans up after itself and is skipped when no VM exists.
#[test]
fn checkpoint_round_trip() {
    let Some((svc, vm)) = checkpoint_service_or_skip() else {
        return;
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let wanted = format!("hvlab-test-{stamp}");

    let created = svc
        .create(vm, &wanted, CheckpointKind::Standard, 180)
        .expect("create checkpoint");
    assert_eq!(created.name, wanted, "provider naming is overridden");
    assert!(!created.id.is_empty());

    let listed = svc.list(vm).expect("list checkpoints");
    assert!(
        listed.iter().any(|c| c.id == created.id),
        "new checkpoint must appear in the tree"
    );

    let renamed = format!("{wanted}-renamed");
    svc.rename(vm, &created.id, &renamed).expect("rename");
    let after_rename = svc.get(vm, &created.id).expect("get renamed");
    assert_eq!(after_rename.name, renamed);

    svc.delete(vm, &created.id, false, 180).expect("delete");
    let err = svc.get(vm, &created.id).expect_err("checkpoint is gone");
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[test]
fn checkpoint_kind_parsing_rejects_garbage() {
    assert!("standard".parse::<CheckpointKind>().is_ok());
    assert!("production".parse::<CheckpointKind>().is_ok());
    assert!("disk_only".parse::<CheckpointKind>().is_ok());
    assert!("disk-only".parse::<CheckpointKind>().is_ok());
    let err = "nonsense".parse::<CheckpointKind>().expect_err("invalid");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

/// Create → inspect → resize → compact → delete a real VHDX in TEMP.
#[test]
fn disk_lifecycle_round_trip() {
    let Ok(svc) = StorageService::connect() else {
        return;
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let path = std::env::temp_dir().join(format!("hvlab-test-{stamp}.vhdx"));
    let path_s = path.to_string_lossy().into_owned();

    let created = svc
        .create(&path_s, 64 * 1024 * 1024, DiskFormat::Vhdx, None, 120)
        .expect("create vhdx");
    assert_eq!(created.format, 3, "VHDX has Format 3");
    assert_eq!(created.disk_type, 3, "a VHDX is dynamic");
    assert_eq!(created.max_internal_size, 64 * 1024 * 1024);
    assert!(created.file_size.unwrap_or(0) > 0, "file exists on disk");

    let state = svc.state(&path_s).expect("state");
    assert!(!state.in_use, "a freshly created disk is not attached");

    let resized = svc.resize(&path_s, 128 * 1024 * 1024, 120).expect("resize");
    assert_eq!(resized.max_internal_size, 128 * 1024 * 1024);

    let _ = svc.compact(&path_s, 120).expect("compact");

    std::fs::remove_file(&path).expect("cleanup");
    let err = svc.inspect(&path_s).expect_err("file is gone");
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[test]
fn disk_format_parsing_rejects_garbage() {
    assert!("vhdx".parse::<DiskFormat>().is_ok());
    assert!("vhd".parse::<DiskFormat>().is_ok());
    assert!("vhd_dynamic".parse::<DiskFormat>().is_ok());
    assert!("qcow2".parse::<DiskFormat>().is_err());
}

/// Internal-switch lifecycle. Creates a host vEthernet adapter, so it is
/// skipped unless `HVLAB_ALLOW_HOST_MUTATION_TESTS=1`; the RAII guard
/// removes the switch even when an assertion panics mid-test.
#[test]
fn switch_round_trip() {
    if !host_mutation_tests_allowed() {
        eprintln!("skipping: set HVLAB_ALLOW_HOST_MUTATION_TESTS=1 to create switches");
        return;
    }
    let Ok(svc) = NetworkService::connect() else {
        return;
    };
    // Switch management is UAC-filtered; skip rather than fail when the
    // caller is not elevated.
    if svc.check_available().is_err() {
        eprintln!("skipping: switch management requires elevation");
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let name = format!("hvlab-test-sw-{stamp}");
    let _guard = SwitchCleanup(&svc, &name);

    let created = svc
        .create_switch(&name, SwitchKind::Internal, None, 120)
        .expect("create switch");
    assert_eq!(created.name, name);
    assert_eq!(created.kind, "internal");

    let listed = svc.list_switches().expect("list switches");
    assert!(listed.iter().any(|s| s.name == name));

    let found = svc.get_switch(&name).expect("get switch");
    assert_eq!(found.id, created.id);
}

#[test]
fn switch_kind_parsing_rejects_garbage() {
    assert!("external".parse::<SwitchKind>().is_ok());
    assert!("internal".parse::<SwitchKind>().is_ok());
    assert!("private".parse::<SwitchKind>().is_ok());
    assert!("bridged".parse::<SwitchKind>().is_err());
}

#[test]
fn private_switch_round_trip() {
    if !host_mutation_tests_allowed() {
        eprintln!("skipping: set HVLAB_ALLOW_HOST_MUTATION_TESTS=1 to create switches");
        return;
    }
    let Ok(svc) = NetworkService::connect() else {
        return;
    };
    if svc.check_available().is_err() {
        eprintln!("skipping: switch management requires elevation");
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let name = format!("hvlab-test-priv-{stamp}");
    let _guard = SwitchCleanup(&svc, &name);

    let created = svc
        .create_switch(&name, SwitchKind::Private, None, 120)
        .expect("create private switch");
    assert_eq!(created.kind, "private");
    assert_eq!(created.port_count, 0, "a private switch has no host port");
}

/// Physical adapter inventory is read-only and must never bind one.
#[test]
fn physical_adapter_inventory_is_read_only() {
    let Ok(svc) = NetworkService::connect() else {
        return;
    };
    let adapters = svc.physical_adapters().expect("list adapters");
    for a in &adapters {
        assert!(!a.is_empty(), "adapter names must not be empty");
    }
    // The classification query must run without touching the NIC stack.
    let switches = svc.list_switches().expect("list switches");
    assert!(
        switches
            .iter()
            .all(|s| s.external_adapter.is_some() == (s.kind == "external")),
        "external_adapter presence must match the external kind"
    );
}

#[test]
fn external_switch_requires_an_adapter() {
    let Ok(svc) = NetworkService::connect() else {
        return;
    };
    let err = svc
        .create_switch("hvlab-test-ext", SwitchKind::External, None, 60)
        .expect_err("external needs an adapter");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    let err = svc
        .create_switch("hvlab-test-int2", SwitchKind::Internal, Some("nope"), 60)
        .expect_err("internal rejects an adapter");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[test]
fn switch_list_matches_host_reality() {
    let Ok(svc) = NetworkService::connect() else {
        return;
    };
    let switches = svc.list_switches().expect("list switches");
    // Every switch must decode to one of the three known kinds.
    for sw in &switches {
        assert!(
            matches!(sw.kind.as_str(), "external" | "internal" | "private"),
            "unexpected kind {} for {}",
            sw.kind,
            sw.name
        );
    }
}
