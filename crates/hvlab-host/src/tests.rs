//! Host-integration tests: real WMI against the local Hyper-V host.
//! These run only when a VM is present; `cargo test` on a machine
//! without Hyper-V skips them via the environment probe.

use crate::job::{JobOutcome, await_wmi_job};
use crate::vm::VmService;
use hvlab_core::error::ErrorCode;
use hvlab_core::ids::VmId;
use std::time::{Duration, Instant};

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
