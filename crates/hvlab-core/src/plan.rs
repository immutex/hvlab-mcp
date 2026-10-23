//! Plan tokens: digest-bound, single-use, expiring authorization for
//! destructive and guest-execution operations.
//!
//! A boolean `confirm` flag is not accepted anywhere in the API: a flag
//! can be set once and reused, or globally neutered by an env var. A
//! plan token is bound to the exact canonicalized arguments of one call,
//! expires, and is consumed on use.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{HvError, Result};
use crate::ids::{PlanId, VmId};

/// How long a plan token stays valid from creation.
pub const DEFAULT_PLAN_TTL: Duration = Duration::from_secs(300);

/// One step in a composite plan. A composite tool takes a single plan
/// whose steps enumerate every mutating sub-operation, so a caller can
/// see the whole effect before authorizing it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    /// Tool or operation name, e.g. `hv_vm_stop`.
    pub tool: String,
    /// Arguments for this step, canonicalized.
    pub args: BTreeMap<String, serde_json::Value>,
    /// Short description shown in the plan summary.
    pub description: String,
}

impl PlanStep {
    /// A step for one tool call with key-value args.
    #[must_use]
    pub fn new(tool: &str, description: &str, args: &[(&str, serde_json::Value)]) -> Self {
        Self {
            tool: tool.to_owned(),
            args: args
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
            description: description.to_owned(),
        }
    }
}

/// A pending destructive operation awaiting authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    /// Identifier for the plan.
    pub id: PlanId,
    /// SHA-256 over [`Plan::canonical_input`]. The token the caller must
    /// echo back is the first 32 hex chars of this.
    pub digest: [u8; 32],
    /// Tool being authorized.
    pub tool: String,
    /// Target VM, when the operation is per-VM.
    pub target: Option<VmId>,
    /// Steps for composites; single-operation plans have exactly one.
    pub steps: Vec<PlanStep>,
    /// When this plan expires.
    pub expires_at: SystemTime,
    /// Policy revision at mint time. A policy change invalidates all
    /// outstanding plans.
    pub policy_revision: u64,
}

impl Plan {
    /// Mint a plan for one tool call.
    ///
    /// `args` must already be canonicalized (sorted keys, no whitespace).
    #[must_use]
    pub fn mint(
        tool: &str,
        target: Option<VmId>,
        steps: Vec<PlanStep>,
        policy_revision: u64,
        ttl: Duration,
    ) -> Self {
        let id = PlanId(uuid::Uuid::now_v7());
        let mut plan = Self {
            id,
            digest: [0; 32],
            tool: tool.to_owned(),
            target,
            steps,
            expires_at: SystemTime::now() + ttl,
            policy_revision,
        };
        plan.digest = Sha256::digest(plan.canonical_input()).into();
        plan
    }

    /// The token the caller echoes back: first 32 hex chars of the digest.
    #[must_use]
    pub fn token(&self) -> String {
        hex_short(&self.digest)
    }

    /// The byte string the digest covers. Any argument change, tool
    /// change, target change, or policy revision changes the digest.
    #[must_use]
    pub fn canonical_input(&self) -> Vec<u8> {
        let steps_json: Vec<serde_json::Value> = self
            .steps
            .iter()
            .map(|s| {
                serde_json::json!({
                    "tool": s.tool,
                    "args": serde_json::Value::String(
                        canonical_json(&serde_json::to_value(&s.args).unwrap_or_default()),
                    ),
                    "description": s.description,
                })
            })
            .collect();
        let input = serde_json::json!({
            "tool": self.tool,
            "target": self.target.as_ref().map(|t| t.0.to_string()),
            "steps": steps_json,
            "policy_revision": self.policy_revision,
        });
        canonical_json(&input).into_bytes()
    }

    /// Verify that `presented_token` authorizes exactly this plan, that
    /// the plan has not expired, and that the policy has not changed.
    ///
    /// # Errors
    ///
    /// `ErrorCode::PolicyDenied` with a reason specific to the
    /// failure: expired, wrong token, or policy revision moved.
    pub fn authorize(&self, presented_token: &str, current_policy_revision: u64) -> Result<()> {
        let now = SystemTime::now();
        if now >= self.expires_at {
            return Err(HvError::policy_denied(
                "plan",
                "plan token expired; mint a new one with hv_plan",
            )
            .with_context("plan_id", self.id.to_string()));
        }
        if self.policy_revision != current_policy_revision {
            return Err(HvError::policy_denied(
                "plan",
                "policy changed since this plan was minted",
            )
            .with_context("minted_revision", self.policy_revision)
            .with_context("current_revision", current_policy_revision));
        }
        let expected = self.token();
        if !constant_time_eq(presented_token.as_bytes(), expected.as_bytes()) {
            return Err(HvError::policy_denied(
                "plan",
                "plan token does not match arguments; token is bound to the exact call",
            )
            .with_context("plan_id", self.id.to_string()));
        }
        Ok(())
    }

    /// One-line human summary of what this plan would do.
    #[must_use]
    pub fn summary(&self) -> String {
        let target = self
            .target
            .as_ref()
            .map_or_else(|| "host".to_owned(), std::string::ToString::to_string);
        if self.steps.len() == 1 {
            format!(
                "{} on {}: {}",
                self.steps[0].tool, target, self.steps[0].description
            )
        } else {
            format!("{} ({} steps) on {}", self.tool, self.steps.len(), target)
        }
    }
}

/// Canonical JSON: sorted object keys, no insignificant whitespace.
/// Two logically identical requests produce identical digests.
#[must_use]
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, &serde_json::Value> = map.iter().collect();
            let inner = sorted
                .iter()
                .map(|(k, v)| {
                    let key = serde_json::to_string(k).unwrap_or_default();
                    let value = canonical_json(v);
                    format!("{key}:{value}")
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inner}}}")
        }
        serde_json::Value::Array(items) => {
            let inner = items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{inner}]")
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn hex_short(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes
        .iter()
        .take(16)
        .fold(String::with_capacity(32), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Errors from plan construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// A plan must reference at least one step.
    #[error("a plan requires at least one step")]
    NoSteps,
}

/// Build a plan, validating structure.
///
/// # Errors
///
/// [`PlanError::NoSteps`] when `steps` is empty.
pub fn build_plan(
    tool: &str,
    target: Option<VmId>,
    steps: Vec<PlanStep>,
    policy_revision: u64,
) -> std::result::Result<Plan, PlanError> {
    if steps.is_empty() {
        return Err(PlanError::NoSteps);
    }
    Ok(Plan::mint(
        tool,
        target,
        steps,
        policy_revision,
        DEFAULT_PLAN_TTL,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod canonical_json {
        use super::*;

        #[test]
        fn sorts_object_keys() {
            let a = serde_json::json!({"vm": "x", "method": "off"});
            let b = serde_json::json!({"method": "off", "vm": "x"});
            assert_eq!(canonical_json(&a), canonical_json(&b));
        }

        #[test]
        fn sorts_nested_keys() {
            let a = serde_json::json!({"outer": {"b": 1, "a": 2}});
            let b = serde_json::json!({"outer": {"a": 2, "b": 1}});
            assert_eq!(canonical_json(&a), canonical_json(&b));
        }

        #[test]
        fn different_values_differ() {
            let a = serde_json::json!({"vm": "x"});
            let b = serde_json::json!({"vm": "y"});
            assert_ne!(canonical_json(&a), canonical_json(&b));
        }

        #[test]
        fn arrays_keep_order() {
            let a = serde_json::json!([1, 2]);
            let b = serde_json::json!([2, 1]);
            assert_ne!(canonical_json(&a), canonical_json(&b));
        }
    }

    mod plan {
        use super::*;
        use crate::error::ErrorCode;

        #[test]
        fn token_is_bound_to_arguments() {
            let p1 = build_plan(
                "hv_vm_stop",
                None,
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "hard power-off",
                    &[("vm", serde_json::json!("x"))],
                )],
                1,
            )
            .expect("valid");
            let p2 = build_plan(
                "hv_vm_stop",
                None,
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "hard power-off",
                    &[("vm", serde_json::json!("y"))],
                )],
                1,
            )
            .expect("valid");
            assert_ne!(p1.token(), p2.token());
        }

        #[test]
        fn token_changes_with_policy_revision() {
            let steps = vec![PlanStep::new(
                "hv_vm_stop",
                "stop",
                &[("vm", serde_json::json!("x"))],
            )];
            let p1 = build_plan("hv_vm_stop", None, steps.clone(), 1).expect("valid");
            let p2 = build_plan("hv_vm_stop", None, steps, 2).expect("valid");
            assert_ne!(p1.token(), p2.token());
        }

        #[test]
        fn identical_requests_get_identical_digests() {
            let steps = || {
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "hard power-off",
                    &[
                        ("vm", serde_json::json!("x")),
                        ("method", serde_json::json!("turnoff")),
                    ],
                )]
            };
            let p1 = build_plan("hv_vm_stop", None, steps(), 1).expect("valid");
            let p2 = build_plan("hv_vm_stop", None, steps(), 1).expect("valid");
            assert_eq!(p1.digest, p2.digest);
        }

        #[test]
        fn authorize_accepts_correct_token() {
            let plan = build_plan(
                "hv_vm_stop",
                None,
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "stop",
                    &[("vm", serde_json::json!("x"))],
                )],
                1,
            )
            .expect("valid");
            plan.authorize(&plan.token(), 1).expect("authorized");
        }

        #[test]
        fn authorize_rejects_wrong_token() {
            let plan = build_plan(
                "hv_vm_stop",
                None,
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "stop",
                    &[("vm", serde_json::json!("x"))],
                )],
                1,
            )
            .expect("valid");
            let err = plan
                .authorize("00000000000000000000000000000000", 1)
                .expect_err("wrong token");
            assert_eq!(err.code, ErrorCode::PolicyDenied);
            assert!(err.message.contains("does not match"), "{err}");
        }

        #[test]
        fn authorize_rejects_after_policy_change() {
            let plan = build_plan(
                "hv_vm_stop",
                None,
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "stop",
                    &[("vm", serde_json::json!("x"))],
                )],
                1,
            )
            .expect("valid");
            let err = plan.authorize(&plan.token(), 2).expect_err("policy moved");
            assert_eq!(err.code, ErrorCode::PolicyDenied);
            assert!(err.message.contains("policy changed"), "{err}");
        }

        #[test]
        fn expired_plan_is_refused() {
            let mut plan = build_plan(
                "hv_vm_stop",
                None,
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "stop",
                    &[("vm", serde_json::json!("x"))],
                )],
                1,
            )
            .expect("valid");
            plan.expires_at = SystemTime::now() - Duration::from_secs(1);
            let err = plan.authorize(&plan.token(), 1).expect_err("expired");
            assert!(err.message.contains("expired"), "{err}");
        }

        #[test]
        fn build_rejects_empty_step_list() {
            let err = build_plan("hv_vm_stop", None, vec![], 1).expect_err("no steps");
            assert_eq!(err, PlanError::NoSteps);
        }

        #[test]
        fn summary_lists_composite_steps() {
            let plan = build_plan(
                "hv_recover",
                None,
                vec![
                    PlanStep::new(
                        "hv_vm_stop",
                        "hard power-off",
                        &[("vm", serde_json::json!("x"))],
                    ),
                    PlanStep::new("hv_vm_start", "start", &[("vm", serde_json::json!("x"))]),
                ],
                1,
            )
            .expect("valid");
            let summary = plan.summary();
            assert!(summary.contains("2 steps"), "{summary}");
        }

        #[test]
        fn token_is_32_hex_chars() {
            let plan = build_plan(
                "hv_vm_stop",
                None,
                vec![PlanStep::new(
                    "hv_vm_stop",
                    "stop",
                    &[("vm", serde_json::json!("x"))],
                )],
                1,
            )
            .expect("valid");
            let token = plan.token();
            assert_eq!(token.len(), 32);
            assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    mod constant_time_eq {
        use super::*;

        #[test]
        fn equal_slices_match() {
            assert!(constant_time_eq(b"abc", b"abc"));
        }

        #[test]
        fn different_slices_do_not() {
            assert!(!constant_time_eq(b"abc", b"abd"));
        }

        #[test]
        fn length_mismatch_does_not() {
            assert!(!constant_time_eq(b"abc", b"ab"));
        }
    }
}
