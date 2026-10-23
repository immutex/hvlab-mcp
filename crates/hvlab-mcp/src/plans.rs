//! In-memory plan-token store binding `hv_plan` mints to the exact
//! canonicalized arguments of the call they authorize.
//!
//! Built on [`hvlab_core::plan`]: a minted plan's digest covers the
//! action name plus a canonicalization of the tool's arguments, so a
//! token minted for one call is refused for any other (H-30). Tokens
//! expire after [`PLAN_TTL`] and are consumed on successful verification.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use hvlab_core::error::{HvError, Result as HvResult};
use hvlab_core::plan::{Plan, PlanStep, canonical_json};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How long a minted token stays valid (PLAN.md §7.1: five minutes).
pub const PLAN_TTL: Duration = Duration::from_secs(300);

/// Digest of a minted plan, hex-encoded for the wire.
///
/// A plan token is the first 32 hex chars of this (the same value
/// [`Plan::token`] returns), so the caller can echo either form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanDigest(pub String);

/// The `confirm` argument D/X tools require: `{plan_id, digest}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanConfirm {
    /// Plan id returned by `hv_plan`.
    pub plan_id: String,
    /// Digest returned by `hv_plan`, bound to the exact arguments.
    pub digest: String,
}

/// Result of a successful `hv_plan` mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct PlanMintResult {
    /// Identifier of the minted plan.
    pub plan_id: String,
    /// Hex digest binding the token to the action and arguments.
    pub digest: String,
    /// When the token expires (RFC 3339).
    pub expires_at: String,
    /// One-line description of the authorized operation.
    pub summary: String,
}

/// Compute the digest over `action` plus the canonicalized tool
/// arguments. Stable across key order in `args`.
///
/// Keys whose value is `null` are dropped on both the mint and the
/// verify path. A typed Rust struct re-serializes absent `Option`
/// fields as explicit `null`s, while a client minting `hv_plan` omits
/// them entirely; treating the two as the same commitment is what makes
/// "mint for these arguments, then make the call" work end to end
/// without the client having to guess the server's serde layout.
#[must_use]
pub fn digest_for(action: &str, args: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_json(&serde_json::json!({
        "action": action,
        "args": drop_nulls(args),
    })));
    hex_32(&hasher.finalize())
}

/// Recursively remove object keys with `null` values.
fn drop_nulls(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), drop_nulls(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(drop_nulls).collect()),
        other => other.clone(),
    }
}

fn hex_32(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Policy revision stamped into every minted plan; there is one policy.
pub const POLICY_REVISION: u64 = 1;

/// Tools that require a plan token (classes D and X).
pub const PLAN_GATED_TOOLS: &[&str] = &[
    "hv_checkpoint_delete",
    "hv_checkpoint_restore",
    "hv_guest_exec",
    "hv_guest_powershell",
];

/// Whether `action` names a plan-gated tool.
#[must_use]
pub fn is_plan_gated(action: &str) -> bool {
    PLAN_GATED_TOOLS.contains(&action)
}

/// In-memory store of minted plans.
#[derive(Debug, Default)]
pub struct PlanStore {
    plans: Mutex<HashMap<String, Stored>>,
}

/// A pending plan's authorization state: what call it binds to and when
/// it stops being valid.
#[derive(Debug, Clone)]
struct Stored {
    expires_at: SystemTime,
    args_digest: String,
}

impl PlanStore {
    /// Mint a token authorizing `action` with exactly these arguments.
    ///
    /// # Errors
    ///
    /// `ErrorCode::InvalidArgument` when `action` does not name a
    /// plan-gated tool or `args` is not an object.
    pub fn mint(
        &self,
        action: &str,
        args: &serde_json::Value,
    ) -> HvResult<(PlanMintResult, PlanConfirm)> {
        if !is_plan_gated(action) {
            return Err(HvError::invalid_argument(
                "action",
                &format!("{action} is not a plan-gated tool; known: {PLAN_GATED_TOOLS:?}"),
            ));
        }
        if !args.is_object() {
            return Err(HvError::invalid_argument(
                "args",
                "plan arguments must be a JSON object",
            ));
        }
        let args_digest = digest_for(action, args);
        let plan = Plan::mint(
            action,
            None,
            vec![PlanStep::new(action, action, &[])],
            POLICY_REVISION,
            PLAN_TTL,
        );
        let plan_id = plan.id.to_string();
        let confirm = PlanConfirm {
            plan_id: plan_id.clone(),
            digest: args_digest.clone(),
        };
        let minted = PlanMintResult {
            plan_id: plan_id.clone(),
            digest: args_digest.clone(),
            expires_at: expires_rfc3339(plan.expires_at),
            summary: format!("{action} — arguments are digest-bound; echo confirm to execute"),
        };
        {
            let mut plans = self.plans.lock().map_err(|e| poissoned(&e))?;
            Self::sweep_expired(&mut plans, SystemTime::now());
            plans.insert(
                plan_id,
                Stored {
                    expires_at: plan.expires_at,
                    args_digest,
                },
            );
        }
        Ok((minted, confirm))
    }

    /// Drop entries whose deadline has passed. Called under the lock on
    /// both mint and verify paths, so an abandoned token cannot
    /// accumulate in a long-lived server.
    fn sweep_expired(plans: &mut HashMap<String, Stored>, now: SystemTime) {
        plans.retain(|_, stored| stored.expires_at > now);
    }

    /// Verify and consume a token. Single-use: removed on success.
    ///
    /// `action` and `args` must be the same values the token was minted
    /// for; a mismatch is refused without consuming the token.
    ///
    /// # Errors
    ///
    /// `ErrorCode::PolicyDenied` for unknown, expired, or
    /// already-consumed tokens and for digest mismatches.
    pub fn verify_and_consume(
        &self,
        confirm: &PlanConfirm,
        action: &str,
        args: &serde_json::Value,
    ) -> HvResult<()> {
        let mut plans = self.plans.lock().map_err(|e| poissoned(&e))?;
        // Look the presented id up before sweeping so an expired token
        // gets the precise "expired" message rather than "unknown".
        let stored = plans.get(&confirm.plan_id).cloned().ok_or_else(|| {
            HvError::policy_denied("plan", "unknown or already-consumed plan id")
                .with_context("plan_id", confirm.plan_id.clone())
        })?;
        if SystemTime::now() >= stored.expires_at {
            plans.remove(&confirm.plan_id);
            Self::sweep_expired(&mut plans, SystemTime::now());
            return Err(HvError::policy_denied(
                "plan",
                "plan token expired; mint a new one with hv_plan",
            )
            .with_context("plan_id", confirm.plan_id.clone()));
        }
        // `digest_for` covers the action too, so this one comparison
        // binds both the tool name and every argument (H-30).
        if !constant_time_eq(
            digest_for(action, args).as_bytes(),
            stored.args_digest.as_bytes(),
        ) {
            return Err(HvError::policy_denied(
                "plan",
                "plan token does not match arguments; token is bound to the exact call (H-30)",
            )
            .with_context("plan_id", confirm.plan_id.clone()));
        }
        if !constant_time_eq(confirm.digest.as_bytes(), stored.args_digest.as_bytes()) {
            return Err(HvError::policy_denied(
                "plan",
                "plan token does not match arguments; token is bound to the exact call (H-30)",
            )
            .with_context("plan_id", confirm.plan_id.clone()));
        }
        plans.remove(&confirm.plan_id);
        Ok(())
    }

    /// Shrink an entry's expiry for tests, without holding the lock.
    #[cfg(test)]
    pub(crate) fn expire_for_test(&self, plan_id: &str) {
        let mut plans = self.plans.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(stored) = plans.get_mut(plan_id) {
            stored.expires_at = SystemTime::now() - Duration::from_secs(1);
        }
    }
}

fn poissoned<T>(e: &PoisonError<T>) -> HvError {
    HvError::new(
        hvlab_core::ErrorCode::Internal,
        format!("plan store lock poisoned: {e}"),
    )
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

fn expires_rfc3339(t: SystemTime) -> String {
    match time::OffsetDateTime::from_unix_timestamp(
        t.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs().cast_signed()),
    ) {
        Ok(dt) => dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        Err(_) => "1970-01-01T00:00:00Z".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn args() -> serde_json::Value {
        serde_json::json!({"vm": "driver-testing", "checkpoint": "before-crash"})
    }

    #[test]
    fn mint_then_verify_succeeds() {
        let store = PlanStore::default();
        let (_, confirm) = store.mint("hv_checkpoint_delete", &args()).unwrap();
        store
            .verify_and_consume(&confirm, "hv_checkpoint_delete", &args())
            .unwrap();
    }

    #[test]
    fn wrong_digest_is_refused() {
        let store = PlanStore::default();
        let (_, mut confirm) = store.mint("hv_checkpoint_delete", &args()).unwrap();
        confirm.digest = "0".repeat(64);
        let err = store
            .verify_and_consume(&confirm, "hv_checkpoint_delete", &args())
            .unwrap_err();
        assert!(err.message.contains("does not match"), "{err}");
    }

    #[test]
    fn different_args_are_refused_h30() {
        let store = PlanStore::default();
        let (_, confirm) = store.mint("hv_checkpoint_delete", &args()).unwrap();
        let other = serde_json::json!({"vm": "other-vm", "checkpoint": "before-crash"});
        let err = store
            .verify_and_consume(&confirm, "hv_checkpoint_delete", &other)
            .unwrap_err();
        assert!(err.message.contains("does not match"), "{err}");
    }

    #[test]
    fn wrong_action_is_refused() {
        let store = PlanStore::default();
        let (_, confirm) = store.mint("hv_checkpoint_delete", &args()).unwrap();
        // The action is part of the digest, so a token minted for a
        // different tool cannot authorize this one.
        let err = store
            .verify_and_consume(&confirm, "hv_guest_exec", &args())
            .unwrap_err();
        assert!(err.message.contains("does not match"), "{err}");
    }

    #[test]
    fn expired_token_is_refused() {
        let store = PlanStore::default();
        let (_, confirm) = store.mint("hv_guest_exec", &args()).unwrap();
        store.expire_for_test(&confirm.plan_id);
        let err = store
            .verify_and_consume(&confirm, "hv_guest_exec", &args())
            .unwrap_err();
        assert!(err.message.contains("expired"), "{err}");
    }

    #[test]
    fn token_is_single_use() {
        let store = PlanStore::default();
        let (_, confirm) = store.mint("hv_checkpoint_restore", &args()).unwrap();
        store
            .verify_and_consume(&confirm, "hv_checkpoint_restore", &args())
            .unwrap();
        let err = store
            .verify_and_consume(&confirm, "hv_checkpoint_restore", &args())
            .unwrap_err();
        assert!(err.message.contains("unknown or already-consumed"), "{err}");
    }

    #[test]
    fn digest_is_key_order_insensitive() {
        let a = serde_json::json!({"vm": "x", "checkpoint": "c"});
        let b = serde_json::json!({"checkpoint": "c", "vm": "x"});
        assert_eq!(
            digest_for("hv_checkpoint_delete", &a),
            digest_for("hv_checkpoint_delete", &b)
        );
    }

    #[test]
    fn non_gated_action_is_refused() {
        let store = PlanStore::default();
        let err = store
            .mint("hv_vm_list", &serde_json::json!({}))
            .unwrap_err();
        assert_eq!(err.code, hvlab_core::ErrorCode::InvalidArgument);
    }

    #[test]
    fn non_object_args_are_refused() {
        let store = PlanStore::default();
        let err = store
            .mint("hv_guest_exec", &serde_json::json!("cmd"))
            .unwrap_err();
        assert_eq!(err.code, hvlab_core::ErrorCode::InvalidArgument);
    }
}

#[cfg(test)]
mod null_normalization {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// The end-to-end contract: a token minted for the raw JSON a client
    /// sends must verify for the typed struct the tool deserializes that
    /// JSON into (whose absent `Option` fields re-serialize as `null`).
    #[test]
    fn minted_without_optional_fields_verifies_for_typed_reserialization() {
        let raw = serde_json::json!({"vm": "v", "checkpoint": "c"});
        let store = PlanStore::default();
        let (_, confirm) = store.mint("hv_checkpoint_delete", &raw).expect("mint");

        // What `serde_json::to_value(CheckpointDeleteArgs)` produces when
        // the client omitted the Option fields.
        let typed = serde_json::json!({
            "vm": "v", "checkpoint": "c",
            "include_subtree": null, "timeout_secs": null,
        });
        store
            .verify_and_consume(&confirm, "hv_checkpoint_delete", &typed)
            .expect("typed form must match the raw mint form");
    }

    #[test]
    fn explicit_null_and_absent_field_mint_identically() {
        let absent = serde_json::json!({"vm": "v", "checkpoint": "c"});
        let nulls = serde_json::json!({"vm": "v", "checkpoint": "c", "include_subtree": null});
        let store = PlanStore::default();
        let (_, confirm) = store.mint("hv_checkpoint_delete", &nulls).expect("mint");
        store
            .verify_and_consume(&confirm, "hv_checkpoint_delete", &absent)
            .expect("null must equal absent");
    }

    #[test]
    fn null_normalization_does_not_weaken_binding() {
        // A null can never stand in for a real value.
        let store = PlanStore::default();
        let (_, confirm) = store
            .mint(
                "hv_checkpoint_delete",
                &serde_json::json!({"vm": "v", "checkpoint": null}),
            )
            .expect("mint");
        assert!(
            store
                .verify_and_consume(
                    &confirm,
                    "hv_checkpoint_delete",
                    &serde_json::json!({"vm": "v", "checkpoint": "c"})
                )
                .is_err()
        );
    }
}
