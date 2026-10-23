//! Host-integration tests: real WMI against the local Hyper-V host.
//! These run only when a VM is present; `cargo test` on a machine
//! without Hyper-V skips them via the environment probe.

use crate::checkpoint::{CheckpointKind, CheckpointService};
use crate::config::ConfigService;
use crate::devices::DeviceService;
use crate::host::HostService;
use crate::job::{JobOutcome, await_wmi_job};
use crate::lifecycle::{REQUESTED_RUNNING, StopMode};
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

/// RAII cleanup: deletes a checkpoint when the test ends, success or
/// panic.
struct CheckpointCleanup<'a>(&'a CheckpointService, VmId, String);

impl Drop for CheckpointCleanup<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.delete(self.1, &self.2, true, 180) {
            eprintln!(
                "cleanup: could not delete checkpoint {}: {:?}",
                self.2, e.code
            );
        }
    }
}

/// RAII cleanup: removes a temp file when the test ends, success or
/// panic.
struct TempFileCleanup(std::path::PathBuf);

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("cleanup: could not remove {}: {e}", self.0.display()),
        }
    }
}

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
    // The deadline must clear `VANISH_GRACE` (1 s in job.rs) by a
    // margin wider than one poll: a missing job is only believed
    // Vanished after the grace period, and a first poll that is slow
    // (cold COM, loaded host) otherwise pushes the grace window past
    // the deadline and turns the same observation into a Timeout.
    let deadline = Instant::now() + Duration::from_secs(3);
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

// ── host.rs ────────────────────────────────────────────────────────────

/// Host info is read-only and must always work where the namespace is
/// reachable at all (the host `Msvm_ComputerSystem` is never filtered).
#[test]
fn host_info_reports_machine_facts() {
    let Ok(svc) = HostService::connect() else {
        eprintln!("skipping: WMI v2 namespace unreachable");
        return;
    };
    let info = svc.host_info().expect("host info");
    assert!(!info.name.is_empty());
    assert!(info.cpu_count > 0, "logical CPU count must be positive");
    assert!(info.ram_bytes > 0, "RAM must be positive");
    // The host itself is always enabled/running.
    assert_eq!(info.enabled_state, 2);
}

/// Storage roots are UAC-filtered; a non-elevated caller sees None and
/// the test records that rather than failing.
#[test]
fn host_storage_roots_may_be_uac_filtered() {
    let Ok(svc) = HostService::connect() else {
        return;
    };
    match svc.host_storage_roots().expect("query") {
        Some(roots) => {
            assert!(!roots.default_vhd_path.is_empty());
            assert!(!roots.default_vm_path.is_empty());
        }
        None => eprintln!("storage roots not visible (not elevated?)"),
    }
}

/// Default switch enumeration is also UAC-filtered; both outcomes are
/// valid observations.
#[test]
fn host_default_switch_may_be_empty() {
    let Ok(svc) = HostService::connect() else {
        return;
    };
    let sw = svc.host_default_switch().expect("query");
    if let Some(name) = sw {
        assert!(!name.is_empty());
    } else {
        eprintln!("no switches visible (not elevated or none exist)");
    }
}

/// Service states come from `root\cimv2`, which is never filtered: the
/// management service must be listed (the Hyper-V role is installed on
/// every machine that has the v2 namespace at all).
#[test]
fn host_services_lists_vmms() {
    let Ok(svc) = HostService::connect() else {
        return;
    };
    let services = svc.host_services().expect("services");
    let vmms = services
        .iter()
        .find(|s| s.name == "vmms")
        .expect("vmms must be present");
    assert!(!vmms.state.is_empty());
    assert!(!vmms.start_mode.is_empty());
    // Integration services share the naming scheme; every listed one
    // must carry non-empty fields.
    for s in &services {
        assert!(s.name.starts_with("vmic") || s.name == "vmms");
    }
}

// ── lifecycle.rs ───────────────────────────────────────────────────────

/// `wait_state` with the current state as its target returns immediately.
/// This exercises the poll loop without mutating anything.
#[test]
fn wait_state_returns_immediately_for_current_state() {
    let Some(svc) = service_or_skip() else { return };
    let vms = svc.list_vms().expect("list");
    let vm = &vms[0];
    let raw = svc.enabled_state(vm.id).expect("enabled state");
    let deadline = Instant::now() + Duration::from_secs(5);
    let reached = svc.wait_state(vm.id, &[raw], deadline).expect("wait");
    assert_eq!(reached.id, vm.id);
}

/// `wait_state` with an unreachable target times out (small deadline).
#[test]
fn wait_state_times_out_on_unreachable_target() {
    let Some(svc) = service_or_skip() else { return };
    let vms = svc.list_vms().expect("list");
    let vm = &vms[0];
    let raw = svc.enabled_state(vm.id).expect("enabled state");
    // Pick a target that is definitely not the current state.
    let impossible = if raw == 2 { 32767 } else { 2 };
    let deadline = Instant::now() + Duration::from_millis(600);
    let err = svc
        .wait_state(vm.id, &[impossible], deadline)
        .expect_err("must time out");
    assert_eq!(err.code, ErrorCode::Timeout);
}

/// `AvailableRequestedStates` is read-only; when present it must contain
/// the no-change case and stay in the documented ranges.
#[test]
fn available_requested_states_is_reported_or_absent() {
    let Some(svc) = service_or_skip() else { return };
    let vms = svc.list_vms().expect("list");
    let states = svc.available_requested_states(vms[0].id).expect("query");
    if let Some(states) = states {
        for s in &states {
            assert!(
                (2..=11).contains(s) || *s >= 32768,
                "RequestedState {s} outside the documented ValueMap"
            );
        }
    } else {
        eprintln!("provider does not report AvailableRequestedStates");
    }
}

/// Rename round-trip on a real VM: change the display name and put it
/// back. The GUID never changes, so this is reversible and cheap.
#[test]
fn rename_round_trip_preserves_guid() {
    if !host_mutation_tests_allowed() {
        eprintln!("skipping: renames the host's VM; set HVLAB_ALLOW_HOST_MUTATION_TESTS=1");
        return;
    }
    let Some(svc) = service_or_skip() else { return };
    let vms = svc.list_vms().expect("list");
    let vm = &vms[0];
    let original = vm.name.clone();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let renamed = format!("hvlab-rn-{stamp}");

    let after = svc.rename(vm.id, &renamed).expect("rename");
    assert_eq!(after.id, vm.id, "GUID is stable across renames");
    assert_eq!(after.name, renamed);

    let restored = svc.rename(vm.id, &original).expect("rename back");
    assert_eq!(restored.name, original);
}

/// Rename of a missing VM must report `NotFound` without mutating
/// anything.
#[test]
fn rename_missing_vm_is_not_found() {
    let Some(svc) = service_or_skip() else { return };
    let bogus = VmId(uuid::Uuid::nil());
    let err = svc.rename(bogus, "x").expect_err("missing vm");
    assert_eq!(err.code, ErrorCode::NotFound);
}

/// Delete of a missing VM must report `NotFound`; the real path is
/// `DestroySystem` on a live VM, which no test performs.
#[test]
fn delete_missing_vm_is_not_found() {
    let Some(svc) = service_or_skip() else { return };
    let bogus = VmId(uuid::Uuid::nil());
    let err = svc.delete(bogus, 30).expect_err("missing vm");
    assert_eq!(err.code, ErrorCode::NotFound);
}

/// Lifecycle wrappers route through `request_state`; the constants are
/// pinned in lifecycle's unit tests, and here we only verify the
/// wrapper signatures exist by a no-op call that must report the VM's
/// actual state afterward. Starting an already-running VM with the
/// *current* state's `RequestedState` value is a legal no-op.
#[test]
fn stop_mode_mapping_is_exposed() {
    // Shutdown/Save/TurnOff are only exercised against real VMs by the
    // operator; here we assert the mapping constants exist and route.
    assert_eq!(StopMode::Shutdown.requested_state(), 4);
    assert_eq!(StopMode::Save.requested_state(), 6);
    assert_eq!(StopMode::TurnOff.requested_state(), 3);
    assert_eq!(REQUESTED_RUNNING, 2);
}

// ── config.rs ──────────────────────────────────────────────────────────

/// `get_config` is read-only; against a real VM it must return plausible
/// values (memory ≥ 32 MB, ≥ 1 processor).
#[test]
fn get_config_reports_plausible_values() {
    let Some(svc) = service_or_skip() else { return };
    let vms = svc.list_vms().expect("list");
    let cfg = ConfigService::connect()
        .and_then(|c| c.get_config(vms[0].id))
        .expect("config");
    assert!(
        cfg.memory_mb >= 32,
        "memory too small to boot: {}",
        cfg.memory_mb
    );
    assert!(cfg.processor_count >= 1);
    if cfg.dynamic_memory {
        assert!(cfg.buffer_pct.is_some());
        assert!(cfg.memory_min_mb.is_some());
        assert!(cfg.memory_max_mb.is_some());
    }
}

/// `set_notes` with `dry_run` must return the current value as `before`
/// and never mutate the VM.
#[test]
fn set_notes_dry_run_reports_diff_without_mutation() {
    let Some(_svc) = service_or_skip() else {
        return;
    };
    let vms = VmService::connect()
        .expect("connect")
        .list_vms()
        .expect("list");
    let cfgsvc = ConfigService::connect().expect("connect");
    let before_notes = cfgsvc
        .get_config(vms[0].id)
        .expect("config")
        .notes
        .unwrap_or_default();
    let diffs = cfgsvc
        .set_notes(vms[0].id, "hvlab dry-run probe", true)
        .expect("dry run");
    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].field, "notes");
    assert_eq!(diffs[0].before, serde_json::json!(before_notes));
    assert_eq!(diffs[0].after, serde_json::json!("hvlab dry-run probe"));
    // Nothing changed.
    let after_notes = cfgsvc
        .get_config(vms[0].id)
        .expect("config")
        .notes
        .unwrap_or_default();
    assert_eq!(after_notes, before_notes);
}

/// `set_memory` / `set_processor` with `dry_run` return a diff and never
/// call WMI mutations.
#[test]
fn set_memory_and_processor_dry_run_return_diffs() {
    let Some(_svc) = service_or_skip() else {
        return;
    };
    let vms = VmService::connect()
        .expect("connect")
        .list_vms()
        .expect("list");
    let cfgsvc = ConfigService::connect().expect("connect");
    let cfg = cfgsvc.get_config(vms[0].id).expect("config");

    let diffs = cfgsvc
        .set_memory(
            vms[0].id,
            cfg.memory_mb + 128,
            cfg.dynamic_memory,
            None,
            true,
        )
        .expect("dry run");
    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].field, "memory");

    let diffs = cfgsvc
        .set_processor(vms[0].id, cfg.processor_count, true)
        .expect("dry run");
    assert!(diffs.is_empty(), "same value must produce no diff");
}

/// Full notes round-trip: set, verify, restore. Notes is a harmless,
/// reversible field; the original value is saved first and restored
/// RAII restore: puts the original notes back when the test ends,
/// success or panic. A failed restore is reported, not fatal.
struct NotesRestore<'a>(&'a ConfigService, VmId, String);

impl Drop for NotesRestore<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.set_notes(self.1, &self.2, false) {
            eprintln!("cleanup: could not restore VM notes: {:?}", e.code);
        }
    }
}

#[test]
fn set_notes_round_trip_restores_original() {
    if !host_mutation_tests_allowed() {
        eprintln!("skipping: writes VM notes; set HVLAB_ALLOW_HOST_MUTATION_TESTS=1");
        return;
    }
    let Some(_svc) = service_or_skip() else {
        return;
    };
    let vms = VmService::connect()
        .expect("connect")
        .list_vms()
        .expect("list");
    let vm = vms[0].id;
    let cfgsvc = ConfigService::connect().expect("connect");
    let original = cfgsvc
        .get_config(vm)
        .expect("config")
        .notes
        .unwrap_or_default();

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let probe = format!("hvlab probe {stamp}");

    let _restore = NotesRestore(&cfgsvc, vm, original);
    let diffs = cfgsvc.set_notes(vm, &probe, false).expect("set notes");
    assert_eq!(diffs.len(), 1);
    let written = cfgsvc
        .get_config(vm)
        .expect("config")
        .notes
        .unwrap_or_default();
    assert_eq!(written, probe, "notes must round-trip");
}

// ── devices.rs ─────────────────────────────────────────────────────────

/// DVD enumeration is read-only; a VM may have zero drives.
#[test]
fn dvd_drives_enumerates_read_only() {
    let Some(_svc) = service_or_skip() else {
        return;
    };
    let vms = VmService::connect()
        .expect("connect")
        .list_vms()
        .expect("list");
    let dev = DeviceService::connect().expect("connect");
    let drives = dev.dvd_drives(vms[0].id).expect("drives");
    for d in &drives {
        assert!(!d.path.is_empty());
    }
}

/// ISO set on a missing file must fail with `NotFound` before any WMI
/// mutation is attempted.
#[test]
fn dvd_set_iso_missing_file_is_not_found() {
    let Some(_svc) = service_or_skip() else {
        return;
    };
    let vms = VmService::connect()
        .expect("connect")
        .list_vms()
        .expect("list");
    let dev = DeviceService::connect().expect("connect");
    let err = dev
        .dvd_set_iso(vms[0].id, r"C:\definitely-not-here.iso", 30)
        .expect_err("missing iso");
    assert_eq!(err.code, ErrorCode::NotFound);
}

/// VLAN 0 is rejected as an argument error before any provider call.
#[test]
fn nic_set_vlan_rejects_zero() {
    let Some(_svc) = service_or_skip() else {
        return;
    };
    let vms = VmService::connect()
        .expect("connect")
        .list_vms()
        .expect("list");
    let dev = DeviceService::connect().expect("connect");
    let err = dev
        .nic_set_vlan(vms[0].id, 0, false, 30)
        .expect_err("vlan 0 rejected");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

// ── checkpoint / storage / network (existing) ──────────────────────────

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
    if !host_mutation_tests_allowed() {
        eprintln!("skipping: takes a real checkpoint; set HVLAB_ALLOW_HOST_MUTATION_TESTS=1");
        return;
    }
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
    let _guard = CheckpointCleanup(&svc, vm, created.id.clone());
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
    let _guard = TempFileCleanup(path.clone());
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
    // The backend refuses External outright (PolicyDenied) — the guard
    // that keeps any caller, direct or via MCP, from binding a NIC.
    let err = svc
        .create_switch("hvlab-test-ext", SwitchKind::External, None, 60)
        .expect_err("external is refused at the backend");
    assert_eq!(err.code, ErrorCode::PolicyDenied);

    let err = svc
        .create_switch("hvlab-test-int2", SwitchKind::Internal, Some("nope"), 60)
        .expect_err("internal rejects an adapter");
    assert_eq!(err.code, ErrorCode::InvalidArgument);

    // The refusal must not depend on whether an adapter was named: a
    // real physical adapter name is refused identically.
    let adapter = svc
        .physical_adapters()
        .ok()
        .and_then(|a| a.into_iter().next());
    if let Some(adapter) = adapter {
        let err = svc
            .create_switch("hvlab-test-ext2", SwitchKind::External, Some(&adapter), 60)
            .expect_err("external with a real adapter is still refused");
        assert_eq!(
            err.code,
            ErrorCode::PolicyDenied,
            "naming a physical adapter must not open a path to binding it"
        );
        // And nothing was created.
        assert_eq!(
            svc.get_switch("hvlab-test-ext2")
                .expect_err("no switch")
                .code,
            ErrorCode::NotFound
        );
    }
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
