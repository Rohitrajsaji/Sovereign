//! Service status values shown by the consumer control API.
//!
//! This module does not write execution state. The Controller remains the authority.

/// Coarse status of `sovereign serve --execute`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ServicePhase {
    Idle,
    Running,
    Paused,
    WaitingForApproval,
    DeferredResource,
    RecoveryBlocked,
    Error,
}

impl ServicePhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::WaitingForApproval => "waiting_for_approval",
            Self::DeferredResource => "deferred_resource",
            Self::RecoveryBlocked => "recovery_blocked",
            Self::Error => "error",
        }
    }
}
