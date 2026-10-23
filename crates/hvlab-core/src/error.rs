//! The error taxonomy: one channel, stable machine-readable codes.
//!
//! Rules:
//! - A failing operation returns [`HvError`], never a success-shaped
//!   object carrying a failure.
//! - Partial results are always attached ([`HvError::partial`]); output
//!   truncation is declared, never a silent slice.
//! - Every error carries a correlation id so an audit line and the
//!   response to the caller can be joined.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::JobId;

/// Stable machine-readable failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// VM, checkpoint, dump, device, or path is missing.
    NotFound,
    /// Schema-valid but semantically wrong.
    InvalidArgument,
    /// Allowlist, path root, command class, or plan token refused it.
    PolicyDenied,
    /// Wrong VM state, job running, guest not ready.
    Precondition,
    /// Not in Hyper-V Administrators, ACL, or elevation missing.
    Permission,
    /// Queue full, session in use, port taken.
    Busy,
    /// Deadline exceeded; partial output is attached.
    Timeout,
    /// The caller cancelled.
    Cancelled,
    /// WMI/COM HRESULT, `VMBus`, SSH, or HTTP failure.
    Transport,
    /// Channel down, guest not booted, or credentials rejected.
    GuestUnreachable,
    /// Guest process exited nonzero; carries code and streams.
    GuestFailed,
    /// Identity assertion failed; the payload was never sent.
    GuestIdentity,
    /// `DbgEng` failure, symbol load failure, target not broken in.
    Debugger,
    /// Feature absent on this Windows build or guest OS.
    Unsupported,
    /// A bug. Carries a correlation id and a redacted context bundle.
    Internal,
}

impl ErrorCode {
    /// The canonical `snake_case` string used on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "hv.not_found",
            Self::InvalidArgument => "hv.invalid_argument",
            Self::PolicyDenied => "hv.policy_denied",
            Self::Precondition => "hv.precondition",
            Self::Permission => "hv.permission",
            Self::Busy => "hv.busy",
            Self::Timeout => "hv.timeout",
            Self::Cancelled => "hv.cancelled",
            Self::Transport => "hv.transport",
            Self::GuestUnreachable => "hv.guest_unreachable",
            Self::GuestFailed => "hv.guest_failed",
            Self::GuestIdentity => "hv.guest_identity",
            Self::Debugger => "hv.debugger",
            Self::Unsupported => "hv.unsupported",
            Self::Internal => "hv.internal",
        }
    }

    /// Whether retrying the same call with the same arguments could
    /// succeed without operator intervention.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Busy | Self::Timeout | Self::Transport | Self::GuestUnreachable
        )
    }
}

/// The single error type carried by every fallible operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HvError {
    /// The failure class.
    pub code: ErrorCode,
    /// Human-readable summary. Never contains secrets.
    pub message: String,
    /// Duplicate of `code.is_retryable()` for wire convenience.
    pub retryable: bool,
    /// Structured context. Redacted before serialization to logs.
    pub context: serde_json::Map<String, serde_json::Value>,
    /// Correlation id shared with the audit record for this operation.
    pub correlation_id: uuid::Uuid,
    /// Job handling this work, when one was created.
    pub job: Option<JobId>,
    /// Whatever was produced before the failure, so the caller never
    /// loses work to a late error.
    pub partial: Option<serde_json::Value>,
}

impl HvError {
    /// Build an error of the given code with a correlation id.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: code.is_retryable(),
            context: serde_json::Map::new(),
            correlation_id: uuid::Uuid::now_v7(),
            job: None,
            partial: None,
        }
    }

    /// Attach structured context.
    #[must_use]
    pub fn with_context<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Attach partial output.
    #[must_use]
    pub fn with_partial(mut self, partial: serde_json::Value) -> Self {
        self.partial = Some(partial);
        self
    }

    /// Attach a job id.
    #[must_use]
    pub fn with_job(mut self, job: JobId) -> Self {
        self.job = Some(job);
        self
    }

    /// Declare whether this specific instance is retryable (overriding
    /// the class default).
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// `not_found` for a named artifact.
    #[must_use]
    pub fn not_found(kind: &str, name: &str) -> Self {
        Self::new(ErrorCode::NotFound, format!("{kind} not found: {name}"))
            .with_context("kind", kind)
            .with_context("name", name)
    }

    /// `invalid_argument` with the offending field.
    #[must_use]
    pub fn invalid_argument(field: &str, reason: &str) -> Self {
        Self::new(
            ErrorCode::InvalidArgument,
            format!("invalid `{field}`: {reason}"),
        )
        .with_context("field", field)
    }

    /// `policy_denied` naming the gate that refused.
    #[must_use]
    pub fn policy_denied(gate: &str, reason: &str) -> Self {
        Self::new(
            ErrorCode::PolicyDenied,
            format!("refused by policy ({gate}): {reason}"),
        )
        .with_context("gate", gate)
    }

    /// `precondition` describing the required state.
    #[must_use]
    pub fn precondition(required: &str, actual: &str) -> Self {
        Self::new(
            ErrorCode::Precondition,
            format!("requires {required}, got {actual}"),
        )
        .with_context("required", required)
        .with_context("actual", actual)
    }
}

impl fmt::Display for HvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)?;
        if !self.context.is_empty() {
            write!(f, " ({self:?})")?;
        }
        Ok(())
    }
}

impl std::error::Error for HvError {}

/// Shorthand: any fallible operation in the codebase, with the crate's
/// [`HvError`] as the default error type.
pub type Result<T, E = HvError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    mod error_code {
        use super::*;

        #[test]
        fn strings_are_snake_case_and_prefixed() {
            assert_eq!(ErrorCode::NotFound.as_str(), "hv.not_found");
            assert_eq!(ErrorCode::GuestIdentity.as_str(), "hv.guest_identity");
        }

        #[test]
        fn only_transient_classes_are_retryable() {
            assert!(ErrorCode::Busy.is_retryable());
            assert!(ErrorCode::Timeout.is_retryable());
            assert!(ErrorCode::Transport.is_retryable());
            assert!(ErrorCode::GuestUnreachable.is_retryable());
            assert!(!ErrorCode::PolicyDenied.is_retryable());
            assert!(!ErrorCode::NotFound.is_retryable());
            assert!(!ErrorCode::Internal.is_retryable());
        }
    }

    mod hv_error {
        use super::*;

        #[test]
        fn carries_code_message_and_correlation() {
            let e = HvError::not_found("dump", "MEMORY.DMP");
            assert_eq!(e.code, ErrorCode::NotFound);
            assert!(e.message.contains("MEMORY.DMP"));
            assert!(!e.retryable);
            assert_eq!(e.context.get("kind").and_then(|v| v.as_str()), Some("dump"));
        }

        #[test]
        fn builders_compose() {
            let partial = serde_json::json!({"lines": 42});
            let e = HvError::new(ErrorCode::Timeout, "analyze exceeded deadline")
                .with_context("timeout_s", 120)
                .with_partial(partial.clone());
            assert!(e.retryable);
            assert_eq!(e.partial, Some(partial));
            assert_eq!(
                e.context
                    .get("timeout_s")
                    .and_then(serde_json::Value::as_i64),
                Some(120)
            );
        }

        #[test]
        fn display_includes_code() {
            let e = HvError::policy_denied("confirm", "no plan token");
            let s = e.to_string();
            assert!(s.starts_with("hv.policy_denied"), "{s}");
            assert!(s.contains("no plan token"));
        }

        #[test]
        fn precondition_names_required_and_actual() {
            let e = HvError::precondition("vm running", "vm off");
            assert_eq!(e.code, ErrorCode::Precondition);
            assert!(e.message.contains("vm running"));
            assert!(e.message.contains("vm off"));
        }

        #[test]
        fn serializes_roundtrip() {
            let e = HvError::new(ErrorCode::Debugger, "target not broken in");
            let json = serde_json::to_string(&e).expect("serializes");
            let back: HvError = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(e, back);
        }
    }
}
