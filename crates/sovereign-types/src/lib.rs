//! Shared, authority-neutral foundational types for Sovereign.
//!
//! This crate intentionally contains no Controller behavior.  It gives the
//! rest of the workspace stable opaque identifiers, versioned error codes and
//! a small wall-clock value type without coupling any caller to storage or a
//! model provider.

pub mod interface_contracts;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

/// Error returned when an opaque Sovereign identifier cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdParseError {
    expected_prefix: &'static str,
    value: String,
}

impl IdParseError {
    #[must_use]
    pub fn expected_prefix(&self) -> &'static str {
        self.expected_prefix
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Display for IdParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid Sovereign id {:?}; expected {}_<opaque>",
            self.value, self.expected_prefix
        )
    }
}

impl Error for IdParseError {}

fn validate_id(value: &str, prefix: &'static str) -> Result<(), IdParseError> {
    let expected = format!("{prefix}_");
    let suffix = value.strip_prefix(&expected).ok_or_else(|| IdParseError {
        expected_prefix: prefix,
        value: value.to_owned(),
    })?;

    let valid_len = !suffix.is_empty() && value.len() <= 128;
    let valid_chars = suffix
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));

    if valid_len && valid_chars {
        Ok(())
    } else {
        Err(IdParseError {
            expected_prefix: prefix,
            value: value.to_owned(),
        })
    }
}

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            /// Parses an opaque identifier of this concrete ID type.
            ///
            /// # Errors
            ///
            /// Returns [`IdParseError`] when the prefix, length, or opaque
            /// suffix characters do not satisfy the stable ID contract.
            pub fn parse(value: impl Into<String>) -> Result<Self, IdParseError> {
                let value = value.into();
                validate_id(&value, Self::PREFIX)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

opaque_id!(ProjectId, "prj");
opaque_id!(GoalId, "goal");
opaque_id!(PlanId, "plan");
opaque_id!(TaskId, "task");
opaque_id!(AttemptId, "attempt");
opaque_id!(ActionId, "action");
opaque_id!(EvidenceId, "evidence");
opaque_id!(CheckpointId, "checkpoint");

/// Stable error identifiers may be persisted in state/evidence while their
/// human-readable messages continue to evolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    InvalidId,
    InvalidState,
    Persistence,
    Integrity,
    PolicyDenied,
    ResourceDenied,
    VerificationFailed,
    ExternalDependency,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidId => "SOV-E001",
            Self::InvalidState => "SOV-E002",
            Self::Persistence => "SOV-E003",
            Self::Integrity => "SOV-E004",
            Self::PolicyDenied => "SOV-E005",
            Self::ResourceDenied => "SOV-E006",
            Self::VerificationFailed => "SOV-E007",
            Self::ExternalDependency => "SOV-E008",
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// UTC wall-clock milliseconds since Unix epoch, used only where persisted
/// event ordering also has a separate authoritative sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixMillis(i64);

impl UnixMillis {
    #[must_use]
    pub const fn from_millis(value: i64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Captures the current wall-clock time as milliseconds since Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`SystemTimeError`] when the host wall clock is earlier than
    /// the Unix epoch.
    pub fn now() -> Result<Self, SystemTimeError> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let millis = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
        Ok(Self(millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_ids_round_trip_through_display_and_parse() {
        let cases = [
            (
                ProjectId::parse("prj_alpha").map(|v| v.to_string()),
                "prj_alpha",
            ),
            (
                GoalId::parse("goal_alpha-1").map(|v| v.to_string()),
                "goal_alpha-1",
            ),
            (
                PlanId::parse("plan_a.b:c").map(|v| v.to_string()),
                "plan_a.b:c",
            ),
            (TaskId::parse("task_001").map(|v| v.to_string()), "task_001"),
            (
                AttemptId::parse("attempt_001").map(|v| v.to_string()),
                "attempt_001",
            ),
            (
                ActionId::parse("action_001").map(|v| v.to_string()),
                "action_001",
            ),
            (
                EvidenceId::parse("evidence_001").map(|v| v.to_string()),
                "evidence_001",
            ),
            (
                CheckpointId::parse("checkpoint_001").map(|v| v.to_string()),
                "checkpoint_001",
            ),
        ];

        for (actual, expected) in cases {
            assert_eq!(actual.as_deref(), Ok(expected));
        }
    }

    #[test]
    fn opaque_ids_reject_wrong_prefix_empty_suffix_and_unsafe_chars() {
        assert!(ProjectId::parse("goal_alpha").is_err());
        assert!(ProjectId::parse("prj_").is_err());
        assert!(ProjectId::parse("prj_alpha/beta").is_err());
        assert!(ProjectId::parse(format!("prj_{}", "x".repeat(125))).is_err());
    }

    #[test]
    fn versioned_error_codes_are_stable() {
        assert_eq!(ErrorCode::Integrity.as_str(), "SOV-E004");
        assert_eq!(ErrorCode::VerificationFailed.to_string(), "SOV-E007");
    }
}
