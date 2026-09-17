//! Deterministic minimum security and resource policy kernel for Sovereign M1.
//!
//! This crate owns admission policy only. It does not execute tools and it does
//! not grant itself authority from repository/model/tool text.

mod resources;

pub use resources::{
    AUTONOMY_BUDGET_SCHEMA_VERSION, AdmissionStatus, AutonomyBudgetV1, ConditionalLeaseContextV1,
    HARDWARE_PROFILE_SCHEMA_VERSION, HardwareProfileV1, HeavyLeaseClass, HeavyLeasePairPolicyV1,
    LeasePairRule, LeaseStateV1, M6_RESOURCE_GOVERNOR_SNAPSHOT_SCHEMA_VERSION, M6ResourceGovernor,
    M6ResourceGovernorSnapshotV1, OsMemoryPressure, PlanHeavyLeaseClass, PressureBand,
    RESOURCE_LEASE_SCHEMA_VERSION, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
    ResourceAdmissionDecisionV1, ResourceCapabilityCycleSnapshotV1, ResourceGovernorRestoreError,
    ResourceLeaseOwnerV1, ResourceLeaseRequestV1, ResourceLeaseV1, ResourcePolicyEventV1,
    ResourcePressureEventV1, ResourcePressureSnapshotV1, TaskResourceBudgetV1, ThermalPressure,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter, Write as _};
use std::fs::{self, OpenOptions};
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub const CAPABILITY_SET_SCHEMA_VERSION: u32 = 1;
pub const PERMISSION_DECISION_SCHEMA_VERSION: u32 = 1;
pub const APPROVAL_CLAIM_SCHEMA_VERSION: u32 = 1;
pub const RECONCILIATION_POLICY_SCHEMA_VERSION: u32 = 1;
pub const TRUST_LABEL_SCHEMA_VERSION: u32 = 1;
pub const POLICY_VIOLATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const EXTERNAL_PAYLOAD_POLICY_SCHEMA_VERSION: u32 = 1;
pub const EXTERNAL_ESCALATION_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Security-relevant provenance for one piece of model-visible evidence.
///
/// A source tag is descriptive provenance only. It never grants a capability, changes policy, or
/// authorizes a Controller transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSource {
    Controller,
    GovernedArtifact,
    Verification,
    Source,
    RepositoryInstruction,
    ToolOutput,
    ToolMetadata,
    Web,
    Browser,
    Download,
    Memory,
    Model,
    ExternalModel,
    Skill,
    Derived,
}

impl TrustSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::GovernedArtifact => "governed_artifact",
            Self::Verification => "verification",
            Self::Source => "source",
            Self::RepositoryInstruction => "repository_instruction",
            Self::ToolOutput => "tool_output",
            Self::ToolMetadata => "tool_metadata",
            Self::Web => "web",
            Self::Browser => "browser",
            Self::Download => "download",
            Self::Memory => "memory",
            Self::Model => "model",
            Self::ExternalModel => "external_model",
            Self::Skill => "skill",
            Self::Derived => "derived",
        }
    }

    #[must_use]
    pub const fn is_untrusted_origin(self) -> bool {
        matches!(
            self,
            Self::Source
                | Self::RepositoryInstruction
                | Self::ToolOutput
                | Self::ToolMetadata
                | Self::Web
                | Self::Browser
                | Self::Download
                | Self::Memory
                | Self::Model
                | Self::ExternalModel
                | Self::Skill
        )
    }
}

/// Control-plane trust state. This is intentionally distinct from capability/permission state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Governed,
    Validated,
    Observed,
    Untrusted,
}

impl TrustLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Governed => "governed",
            Self::Validated => "validated",
            Self::Observed => "observed",
            Self::Untrusted => "untrusted",
        }
    }
}

/// Typed trust label v1 attached to evidence at ingress.
///
/// The valid combinations are deliberately narrow: only Controller/governed-artifact origins may
/// be `Governed`, only verification may be `Validated`, derived facts may be `Observed`, and every
/// repository/web/tool/memory/model/skill origin is always `Untrusted` until a Controller-owned
/// governed artifact is created separately. Merely editing this label never changes authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustLabel {
    pub schema_version: u32,
    pub source: TrustSource,
    pub level: TrustLevel,
}

impl TrustLabel {
    #[must_use]
    pub const fn controller() -> Self {
        Self {
            schema_version: TRUST_LABEL_SCHEMA_VERSION,
            source: TrustSource::Controller,
            level: TrustLevel::Governed,
        }
    }

    #[must_use]
    pub const fn governed_artifact() -> Self {
        Self {
            schema_version: TRUST_LABEL_SCHEMA_VERSION,
            source: TrustSource::GovernedArtifact,
            level: TrustLevel::Governed,
        }
    }

    #[must_use]
    pub const fn verification() -> Self {
        Self {
            schema_version: TRUST_LABEL_SCHEMA_VERSION,
            source: TrustSource::Verification,
            level: TrustLevel::Validated,
        }
    }

    #[must_use]
    pub const fn observed_derived() -> Self {
        Self {
            schema_version: TRUST_LABEL_SCHEMA_VERSION,
            source: TrustSource::Derived,
            level: TrustLevel::Observed,
        }
    }

    /// Labels evidence from a source that architecture treats as untrusted data.
    ///
    /// # Errors
    /// Returns a denial if a caller tries to use this constructor for a governed/validated source.
    pub fn untrusted(source: TrustSource) -> Result<Self, PolicyError> {
        if !source.is_untrusted_origin() {
            return Err(PolicyError::Denied(
                "untrusted TrustLabel requires an untrusted evidence origin".to_owned(),
            ));
        }
        Ok(Self {
            schema_version: TRUST_LABEL_SCHEMA_VERSION,
            source,
            level: TrustLevel::Untrusted,
        })
    }

    /// Validates that provenance cannot self-promote its control trust.
    ///
    /// # Errors
    /// Returns a denial for unsupported schema versions or invalid source/level combinations.
    pub fn validate(self) -> Result<(), PolicyError> {
        if self.schema_version != TRUST_LABEL_SCHEMA_VERSION {
            return Err(PolicyError::Denied(
                "unsupported trust-label schema version".to_owned(),
            ));
        }
        let valid = match self.source {
            TrustSource::Controller | TrustSource::GovernedArtifact => {
                self.level == TrustLevel::Governed
            }
            TrustSource::Verification => self.level == TrustLevel::Validated,
            TrustSource::Derived => self.level == TrustLevel::Observed,
            source if source.is_untrusted_origin() => self.level == TrustLevel::Untrusted,
            _ => false,
        };
        if !valid {
            return Err(PolicyError::Denied(
                "trust-label source cannot self-promote its control trust".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn is_untrusted(self) -> bool {
        self.level == TrustLevel::Untrusted
    }

    #[must_use]
    pub fn digest(self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(TRUST_LABEL_SCHEMA_VERSION.to_be_bytes());
        digest_policy_field(&mut hasher, self.source.as_str());
        digest_policy_field(&mut hasher, self.level.as_str());
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// Typed class of an attempted trust-boundary violation. These values describe a denied attempt;
/// they are not commands and carry no execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyViolationKind {
    PolicyMutation,
    CapabilitySelfGrant,
    VerificationSuppression,
    AcceptanceMutation,
    CompletionMutation,
    ApprovalMasquerade,
    ControllerMasquerade,
    ToolMasquerade,
    ToolRiskDowngrade,
    FreeFormDispatch,
}

impl PolicyViolationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyMutation => "policy_mutation",
            Self::CapabilitySelfGrant => "capability_self_grant",
            Self::VerificationSuppression => "verification_suppression",
            Self::AcceptanceMutation => "acceptance_mutation",
            Self::CompletionMutation => "completion_mutation",
            Self::ApprovalMasquerade => "approval_masquerade",
            Self::ControllerMasquerade => "controller_masquerade",
            Self::ToolMasquerade => "tool_masquerade",
            Self::ToolRiskDowngrade => "tool_risk_downgrade",
            Self::FreeFormDispatch => "free_form_dispatch",
        }
    }
}

/// Authority-bearing surface an untrusted input attempted to influence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedPolicyEffect {
    Policy,
    CapabilitySet,
    VerificationContract,
    AcceptanceContract,
    CompletionState,
    ApprovalAuthority,
    ToolAvailability,
    ToolRisk,
    Dispatch,
}

impl ProtectedPolicyEffect {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::CapabilitySet => "capability_set",
            Self::VerificationContract => "verification_contract",
            Self::AcceptanceContract => "acceptance_contract",
            Self::CompletionState => "completion_state",
            Self::ApprovalAuthority => "approval_authority",
            Self::ToolAvailability => "tool_availability",
            Self::ToolRisk => "tool_risk",
            Self::Dispatch => "dispatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyViolationDecision {
    Denied,
}

/// Sanitized, denial-only audit evidence for one prompt/tool-injection boundary violation.
///
/// Raw malicious text is intentionally absent. The record binds only digests, typed provenance,
/// attempted capability names and the authoritative policy/permission state that remained in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolationEvidence {
    pub schema_version: u32,
    pub violation_id: String,
    pub kind: PolicyViolationKind,
    pub source_evidence_id: String,
    pub source_content_digest: String,
    pub source_trust: TrustLabel,
    pub protected_effect: ProtectedPolicyEffect,
    pub attempted_capabilities: BTreeSet<String>,
    pub policy_digest: String,
    pub permission_decision_digest: Option<String>,
    pub decision: PolicyViolationDecision,
    pub reason_code: String,
}

impl PolicyViolationEvidence {
    /// Constructs a sanitized denial record after deterministic policy has rejected an attempt.
    ///
    /// # Errors
    /// Returns a policy denial for malformed digests, untrusted provenance that self-promotes, or
    /// unknown capability names.
    #[allow(clippy::too_many_arguments)]
    pub fn denied(
        violation_id: impl Into<String>,
        kind: PolicyViolationKind,
        source_evidence_id: impl Into<String>,
        source_content_digest: impl Into<String>,
        source_trust: TrustLabel,
        protected_effect: ProtectedPolicyEffect,
        attempted_capabilities: impl IntoIterator<Item = String>,
        policy_digest: impl Into<String>,
        permission_decision_digest: Option<String>,
        reason_code: impl Into<String>,
    ) -> Result<Self, PolicyError> {
        let evidence = Self {
            schema_version: POLICY_VIOLATION_EVIDENCE_SCHEMA_VERSION,
            violation_id: violation_id.into(),
            kind,
            source_evidence_id: source_evidence_id.into(),
            source_content_digest: source_content_digest.into(),
            source_trust,
            protected_effect,
            attempted_capabilities: attempted_capabilities.into_iter().collect(),
            policy_digest: policy_digest.into(),
            permission_decision_digest,
            decision: PolicyViolationDecision::Denied,
            reason_code: reason_code.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Revalidates the denial record without interpreting any source text as authority.
    ///
    /// # Errors
    /// Returns a denial for malformed bindings or invalid trust/capability values.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.source_trust.validate()?;
        if self.schema_version != POLICY_VIOLATION_EVIDENCE_SCHEMA_VERSION
            || self.violation_id.trim().is_empty()
            || self.source_evidence_id.trim().is_empty()
            || !is_sha256_binding(&self.source_content_digest)
            || !is_sha256_binding(&self.policy_digest)
            || self
                .permission_decision_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256_binding(digest))
            || self.reason_code.trim().is_empty()
            || self
                .attempted_capabilities
                .iter()
                .any(|capability| Capability::from_plan_ir_str(capability).is_none())
        {
            return Err(PolicyError::Denied(
                "policy-violation evidence has malformed denial bindings".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(POLICY_VIOLATION_EVIDENCE_SCHEMA_VERSION.to_be_bytes());
        digest_policy_field(&mut hasher, &self.violation_id);
        digest_policy_field(&mut hasher, self.kind.as_str());
        digest_policy_field(&mut hasher, &self.source_evidence_id);
        digest_policy_field(&mut hasher, &self.source_content_digest);
        digest_policy_field(&mut hasher, &self.source_trust.digest());
        digest_policy_field(&mut hasher, self.protected_effect.as_str());
        for capability in &self.attempted_capabilities {
            digest_policy_field(&mut hasher, capability);
        }
        digest_policy_field(&mut hasher, &self.policy_digest);
        digest_policy_field(
            &mut hasher,
            self.permission_decision_digest.as_deref().unwrap_or("none"),
        );
        digest_policy_field(&mut hasher, "denied");
        digest_policy_field(&mut hasher, &self.reason_code);
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// Canonical Plan IR v1 capability vocabulary.
///
/// Existing `sovereign-tools::PermissionClass` callers keep their Rust variant names through a
/// type alias; the wire names here are the twelve frozen Plan IR permission strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    Read,
    SandboxWrite,
    RepositoryWrite,
    ProcessExec,
    PackageInstall,
    NetworkRead,
    NetworkWrite,
    BrowserInteractive,
    SecretUse,
    ExternalSideEffect,
    ExternalIntelligence,
    Destructive,
}

impl Capability {
    pub const ALL: [Self; 12] = [
        Self::Read,
        Self::SandboxWrite,
        Self::RepositoryWrite,
        Self::ProcessExec,
        Self::PackageInstall,
        Self::NetworkRead,
        Self::NetworkWrite,
        Self::BrowserInteractive,
        Self::SecretUse,
        Self::ExternalSideEffect,
        Self::ExternalIntelligence,
        Self::Destructive,
    ];

    #[must_use]
    pub const fn as_plan_ir_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::SandboxWrite => "sandbox_write",
            Self::RepositoryWrite => "repo_write",
            Self::ProcessExec => "process_exec",
            Self::PackageInstall => "package_install",
            Self::NetworkRead => "network_read",
            Self::NetworkWrite => "network_write",
            Self::BrowserInteractive => "browser_interactive",
            Self::SecretUse => "secret_use",
            Self::ExternalSideEffect => "external_side_effect",
            Self::ExternalIntelligence => "external_intelligence",
            Self::Destructive => "destructive",
        }
    }

    #[must_use]
    pub fn from_plan_ir_str(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "sandbox_write" => Some(Self::SandboxWrite),
            "repo_write" => Some(Self::RepositoryWrite),
            "process_exec" => Some(Self::ProcessExec),
            "package_install" => Some(Self::PackageInstall),
            "network_read" => Some(Self::NetworkRead),
            "network_write" => Some(Self::NetworkWrite),
            "browser_interactive" => Some(Self::BrowserInteractive),
            "secret_use" => Some(Self::SecretUse),
            "external_side_effect" => Some(Self::ExternalSideEffect),
            "external_intelligence" => Some(Self::ExternalIntelligence),
            "destructive" => Some(Self::Destructive),
            _ => None,
        }
    }
}

/// Frozen Plan IR data classes that may be selected for an external-intelligence packet.
///
/// This enum is intentionally closed. Raw logs, resolved secrets, unrestricted CAS data, hidden
/// reasoning, and whole-repository bytes have no representable ordinary data class here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDataClass {
    Contract,
    Requirement,
    SourceSlice,
    Diff,
    ToolSynopsis,
    Verification,
    MemorySynopsis,
    ArchitectureDoc,
}

impl ExternalDataClass {
    #[must_use]
    pub const fn as_plan_ir_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Requirement => "requirement",
            Self::SourceSlice => "source_slice",
            Self::Diff => "diff",
            Self::ToolSynopsis => "tool_synopsis",
            Self::Verification => "verification",
            Self::MemorySynopsis => "memory_synopsis",
            Self::ArchitectureDoc => "architecture_doc",
        }
    }

    #[must_use]
    pub fn from_plan_ir_str(value: &str) -> Option<Self> {
        match value {
            "contract" => Some(Self::Contract),
            "requirement" => Some(Self::Requirement),
            "source_slice" => Some(Self::SourceSlice),
            "diff" => Some(Self::Diff),
            "tool_synopsis" => Some(Self::ToolSynopsis),
            "verification" => Some(Self::Verification),
            "memory_synopsis" => Some(Self::MemorySynopsis),
            "architecture_doc" => Some(Self::ArchitectureDoc),
            _ => None,
        }
    }
}

/// Global/task whole-repository export ceiling mirrored from Plan IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalRepositoryExport {
    Deny,
    ExplicitGrantOnly,
}

/// Typed allow/deny state for sensitive external payload classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSensitiveDataAccess {
    Deny,
    Allow,
}

/// External-provider tool authority is intentionally a single-state contract in the local profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalToolAuthority {
    None,
}

/// Pure, typed effective payload policy derived by the Controller from active Plan IR.
///
/// This value never grants authority on its own. The Controller must separately prove the exact
/// `ExternalIntelligence` capability grant and every configured authority ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalPayloadPolicy {
    pub schema_version: u32,
    pub enabled: bool,
    pub requires_explicit_grant: bool,
    pub allowed_providers: BTreeSet<String>,
    pub allowed_data_classes: BTreeSet<ExternalDataClass>,
    pub resolved_secrets: ExternalSensitiveDataAccess,
    pub repository_export: ExternalRepositoryExport,
    pub raw_logs: ExternalSensitiveDataAccess,
    pub tool_authority: ExternalToolAuthority,
    pub max_payload_bytes: u64,
}

impl ExternalPayloadPolicy {
    /// Validates the effective policy shape without granting any capability.
    ///
    /// # Errors
    /// Returns a denial when an enabled policy would permit unsafe baseline exports or when a
    /// disabled policy retains provider/data/payload scope.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != EXTERNAL_PAYLOAD_POLICY_SCHEMA_VERSION {
            return Err(PolicyError::Denied(format!(
                "unsupported external payload policy schema {}",
                self.schema_version
            )));
        }
        if !self.enabled {
            if !self.allowed_providers.is_empty()
                || !self.allowed_data_classes.is_empty()
                || self.max_payload_bytes != 0
            {
                return Err(PolicyError::Denied(
                    "disabled external intelligence retains provider/data/payload scope".to_owned(),
                ));
            }
            return Ok(());
        }
        if !self.requires_explicit_grant {
            return Err(PolicyError::Denied(
                "external intelligence requires an explicit capability grant".to_owned(),
            ));
        }
        if self.allowed_providers.is_empty()
            || self.allowed_data_classes.is_empty()
            || self.max_payload_bytes == 0
        {
            return Err(PolicyError::Denied(
                "enabled external intelligence requires bounded provider/data/payload scope"
                    .to_owned(),
            ));
        }
        if self.resolved_secrets != ExternalSensitiveDataAccess::Deny
            || self.raw_logs != ExternalSensitiveDataAccess::Deny
            || self.tool_authority != ExternalToolAuthority::None
        {
            return Err(PolicyError::Denied(
                "external payload policy exceeds the safe local-profile export boundary".to_owned(),
            ));
        }
        Ok(())
    }

    /// Checks one already-minimized packet against the exact effective provider/data/byte scope.
    ///
    /// # Errors
    /// Returns a deterministic denial for a disabled policy, undeclared provider/data class, an
    /// empty packet, or a payload that exceeds the active byte ceiling.
    pub fn authorize_packet(
        &self,
        provider_id: &str,
        data_classes: &BTreeSet<ExternalDataClass>,
        payload_bytes: u64,
    ) -> Result<(), PolicyError> {
        self.validate()?;
        if !self.enabled {
            return Err(PolicyError::Denied(
                "external intelligence is disabled for this task".to_owned(),
            ));
        }
        if provider_id.trim().is_empty() || !self.allowed_providers.contains(provider_id) {
            return Err(PolicyError::Denied(
                "external provider is not in the exact active allowlist".to_owned(),
            ));
        }
        if data_classes.is_empty() || !data_classes.is_subset(&self.allowed_data_classes) {
            return Err(PolicyError::Denied(
                "external data-class selection exceeds the active allowlist".to_owned(),
            ));
        }
        if payload_bytes == 0 || payload_bytes > self.max_payload_bytes {
            return Err(PolicyError::Denied(format!(
                "external payload bytes {payload_bytes} exceed active ceiling {}",
                self.max_payload_bytes
            )));
        }
        Ok(())
    }
}

/// Digest-only provenance for one selected evidence item in an external escalation packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceBinding {
    pub evidence_id: String,
    pub data_class: ExternalDataClass,
    pub source_digest: String,
    pub content_digest: String,
    pub redacted_content_digest: String,
}

impl ExternalEvidenceBinding {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.evidence_id.trim().is_empty()
            || !is_sha256_binding(&self.source_digest)
            || !is_sha256_binding(&self.content_digest)
            || !is_sha256_binding(&self.redacted_content_digest)
        {
            return Err(PolicyError::Denied(
                "external evidence binding requires exact evidence and digest provenance"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exact, reviewable authorization manifest constructed before any external provider dispatch.
///
/// The manifest contains only typed identities, digests, byte/token estimates and redaction event
/// identifiers. Redacted packet bytes remain ephemeral and are bound by `payload_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEscalationManifest {
    pub schema_version: u32,
    pub provider_id: String,
    pub model_id: String,
    pub model_version: String,
    pub purpose: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub policy_digest: String,
    pub execution_epoch: i64,
    pub selected_evidence: Vec<ExternalEvidenceBinding>,
    pub data_classes: BTreeSet<ExternalDataClass>,
    pub redaction_event_ids: BTreeSet<String>,
    pub redaction_result_digest: String,
    pub payload_digest: String,
    pub payload_bytes: u64,
    pub estimated_tokens: u32,
    pub deadline_ms: u64,
    pub expires_at_ms: i64,
    pub nonce: String,
}

impl ExternalEscalationManifest {
    /// Validates exact manifest shape and internally redundant data-class bindings.
    ///
    /// # Errors
    /// Returns a denial for malformed identities/digests, duplicate evidence, non-canonical
    /// evidence order, inconsistent data classes, or non-positive deadline/expiry fields.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema_version != EXTERNAL_ESCALATION_MANIFEST_SCHEMA_VERSION
            || self.provider_id.trim().is_empty()
            || self.model_id.trim().is_empty()
            || self.model_version.trim().is_empty()
            || self.purpose.trim().is_empty()
            || self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || !is_sha256_binding(&self.task_contract_digest)
            || !is_sha256_binding(&self.policy_digest)
            || self.execution_epoch < 0
            || !is_sha256_binding(&self.redaction_result_digest)
            || !is_sha256_binding(&self.payload_digest)
            || self.payload_bytes == 0
            || self.deadline_ms == 0
            || self.expires_at_ms <= 0
            || self.nonce.trim().is_empty()
            || self.selected_evidence.is_empty()
        {
            return Err(PolicyError::Denied(
                "external escalation manifest has incomplete exact-binding fields".to_owned(),
            ));
        }
        let mut previous_key: Option<(&str, ExternalDataClass)> = None;
        let mut derived_classes = BTreeSet::new();
        for binding in &self.selected_evidence {
            binding.validate()?;
            let key = (binding.evidence_id.as_str(), binding.data_class);
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(PolicyError::Denied(
                    "external evidence bindings must be unique and canonically ordered".to_owned(),
                ));
            }
            previous_key = Some(key);
            derived_classes.insert(binding.data_class);
        }
        if derived_classes != self.data_classes {
            return Err(PolicyError::Denied(
                "external manifest data classes do not match selected evidence".to_owned(),
            ));
        }
        if self
            .redaction_event_ids
            .iter()
            .any(|event_id| event_id.trim().is_empty())
        {
            return Err(PolicyError::Denied(
                "external manifest contains an empty redaction event identity".to_owned(),
            ));
        }
        Ok(())
    }

    /// Stable exact-manifest digest used as the approval payload binding.
    ///
    /// # Errors
    /// Returns the same fail-closed validation error as [`Self::validate`].
    pub fn digest(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(EXTERNAL_ESCALATION_MANIFEST_SCHEMA_VERSION.to_be_bytes());
        digest_policy_field(&mut hasher, &self.provider_id);
        digest_policy_field(&mut hasher, &self.model_id);
        digest_policy_field(&mut hasher, &self.model_version);
        digest_policy_field(&mut hasher, &self.purpose);
        digest_policy_field(&mut hasher, &self.plan_id);
        hasher.update(self.plan_revision.to_be_bytes());
        digest_policy_field(&mut hasher, &self.task_id);
        digest_policy_field(&mut hasher, &self.task_contract_digest);
        digest_policy_field(&mut hasher, &self.policy_digest);
        hasher.update(self.execution_epoch.to_be_bytes());
        hasher.update((self.selected_evidence.len() as u64).to_be_bytes());
        for binding in &self.selected_evidence {
            digest_policy_field(&mut hasher, &binding.evidence_id);
            digest_policy_field(&mut hasher, binding.data_class.as_plan_ir_str());
            digest_policy_field(&mut hasher, &binding.source_digest);
            digest_policy_field(&mut hasher, &binding.content_digest);
            digest_policy_field(&mut hasher, &binding.redacted_content_digest);
        }
        for data_class in &self.data_classes {
            digest_policy_field(&mut hasher, data_class.as_plan_ir_str());
        }
        for event_id in &self.redaction_event_ids {
            digest_policy_field(&mut hasher, event_id);
        }
        digest_policy_field(&mut hasher, &self.redaction_result_digest);
        digest_policy_field(&mut hasher, &self.payload_digest);
        hasher.update(self.payload_bytes.to_be_bytes());
        hasher.update(self.estimated_tokens.to_be_bytes());
        hasher.update(self.deadline_ms.to_be_bytes());
        hasher.update(self.expires_at_ms.to_be_bytes());
        digest_policy_field(&mut hasher, &self.nonce);
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

/// Exact Controller-issued approval for one immutable action payload.
///
/// The claim deliberately contains no free-form approval text: authority is only the typed,
/// exact action binding below. Resolved secrets, provider locators, prompts, and model output are
/// never approval fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalClaim {
    pub schema_version: u32,
    pub claim_id: String,
    pub action_id: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub permission_class: String,
    pub payload_digest: String,
    pub destination_digest: Option<String>,
    pub executable_digest: String,
    pub policy_digest: String,
    pub execution_epoch: i64,
    pub nonce: String,
    pub issued_by: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Frozen v1 name for callers that prefer version-suffixed authority types.
pub type ApprovalClaimV1 = ApprovalClaim;

impl ApprovalClaim {
    /// Validates claim shape and expiry without consulting tool/action state.
    ///
    /// # Errors
    /// Returns a policy denial for malformed bindings, future-issued claims, or expiration.
    pub fn validate(&self, now_ms: i64) -> Result<(), PolicyError> {
        if self.schema_version != APPROVAL_CLAIM_SCHEMA_VERSION
            || self.claim_id.trim().is_empty()
            || self.action_id.trim().is_empty()
            || self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || Capability::from_plan_ir_str(&self.permission_class).is_none()
            || !is_sha256_binding(&self.payload_digest)
            || self
                .destination_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256_binding(digest))
            || !is_sha256_binding(&self.executable_digest)
            || !is_sha256_binding(&self.policy_digest)
            || self.execution_epoch < 0
            || self.nonce.trim().is_empty()
            || self.issued_by.trim().is_empty()
            || self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
        {
            return Err(PolicyError::Denied(
                "approval claim has incomplete exact-binding fields".to_owned(),
            ));
        }
        if self.issued_at_ms > now_ms {
            return Err(PolicyError::Denied(
                "approval claim was issued in the future".to_owned(),
            ));
        }
        if self.expires_at_ms <= now_ms {
            return Err(PolicyError::Denied("approval claim expired".to_owned()));
        }
        Ok(())
    }

    /// Stable digest used by Controller audit/checkpoint provenance.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(APPROVAL_CLAIM_SCHEMA_VERSION.to_be_bytes());
        digest_policy_field(&mut hasher, &self.claim_id);
        digest_policy_field(&mut hasher, &self.action_id);
        digest_policy_field(&mut hasher, &self.plan_id);
        hasher.update(self.plan_revision.to_be_bytes());
        digest_policy_field(&mut hasher, &self.task_id);
        digest_policy_field(&mut hasher, &self.permission_class);
        digest_policy_field(&mut hasher, &self.payload_digest);
        digest_policy_field(
            &mut hasher,
            self.destination_digest.as_deref().unwrap_or("none"),
        );
        digest_policy_field(&mut hasher, &self.executable_digest);
        digest_policy_field(&mut hasher, &self.policy_digest);
        hasher.update(self.execution_epoch.to_be_bytes());
        digest_policy_field(&mut hasher, &self.nonce);
        digest_policy_field(&mut hasher, &self.issued_by);
        hasher.update(self.issued_at_ms.to_be_bytes());
        hasher.update(self.expires_at_ms.to_be_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }
}

/// Deterministic unknown-outcome policy declared by a tool/adapter.
///
/// Ordering is intentionally monotonic: callers may make an action stricter than the adapter's
/// minimum but may never downgrade it. Only `IdempotentLocal` permits retry without proof that the
/// prior effect is present/absent. Consequential local and external actions require outcome proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationClass {
    IdempotentLocal,
    ProofRequiredLocal,
    ConsequentialExternal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationPolicy {
    pub schema_version: u32,
    pub class: ReconciliationClass,
}

/// Frozen v1 name for callers that prefer version-suffixed policy types.
pub type ReconciliationPolicyV1 = ReconciliationPolicy;

impl ReconciliationPolicy {
    #[must_use]
    pub const fn idempotent_local() -> Self {
        Self {
            schema_version: RECONCILIATION_POLICY_SCHEMA_VERSION,
            class: ReconciliationClass::IdempotentLocal,
        }
    }

    #[must_use]
    pub const fn proof_required_local() -> Self {
        Self {
            schema_version: RECONCILIATION_POLICY_SCHEMA_VERSION,
            class: ReconciliationClass::ProofRequiredLocal,
        }
    }

    #[must_use]
    pub const fn consequential_external() -> Self {
        Self {
            schema_version: RECONCILIATION_POLICY_SCHEMA_VERSION,
            class: ReconciliationClass::ConsequentialExternal,
        }
    }

    /// Returns whether `candidate` is at least as strict as this adapter/tool floor.
    #[must_use]
    pub const fn permits_candidate(self, candidate: Self) -> bool {
        self.schema_version == RECONCILIATION_POLICY_SCHEMA_VERSION
            && candidate.schema_version == RECONCILIATION_POLICY_SCHEMA_VERSION
            && reconciliation_rank(candidate.class) >= reconciliation_rank(self.class)
    }

    #[must_use]
    pub const fn allows_unproven_retry(self) -> bool {
        self.schema_version == RECONCILIATION_POLICY_SCHEMA_VERSION
            && matches!(self.class, ReconciliationClass::IdempotentLocal)
    }

    /// # Errors
    /// Returns a policy denial for unsupported schema versions.
    pub fn validate(self) -> Result<(), PolicyError> {
        if self.schema_version != RECONCILIATION_POLICY_SCHEMA_VERSION {
            return Err(PolicyError::Denied(
                "unsupported reconciliation policy schema".to_owned(),
            ));
        }
        Ok(())
    }
}

const fn reconciliation_rank(class: ReconciliationClass) -> u8 {
    match class {
        ReconciliationClass::IdempotentLocal => 0,
        ReconciliationClass::ProofRequiredLocal => 1,
        ReconciliationClass::ConsequentialExternal => 2,
    }
}

/// Deterministic capability set used at every permission-intersection layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    capabilities: BTreeSet<Capability>,
}

impl CapabilitySet {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            capabilities: capabilities.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn all() -> Self {
        Self::new(Capability::ALL)
    }

    #[must_use]
    pub fn contains(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    #[must_use]
    pub fn is_subset_of(&self, ceiling: &Self) -> bool {
        self.capabilities.is_subset(&ceiling.capabilities)
    }

    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self::new(self.capabilities.intersection(&other.capabilities).copied())
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.capabilities.iter().copied()
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CAPABILITY_SET_SCHEMA_VERSION.to_be_bytes());
        for capability in &self.capabilities {
            digest_policy_field(&mut hasher, capability.as_plan_ir_str());
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

impl From<BTreeSet<Capability>> for CapabilitySet {
    fn from(value: BTreeSet<Capability>) -> Self {
        Self {
            capabilities: value,
        }
    }
}

impl From<CapabilitySet> for BTreeSet<Capability> {
    fn from(value: CapabilitySet) -> Self {
        value.capabilities
    }
}

/// Explicit capability grant bound to one exact Plan revision and task contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCapabilityGrant {
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub policy_digest: String,
    pub issued_by: String,
    pub capabilities: CapabilitySet,
}

impl TaskCapabilityGrant {
    /// Returns the grant only for its exact task scope. Sibling tasks and stale contracts fail
    /// closed instead of receiving an empty or partially matching grant.
    ///
    /// # Errors
    /// Returns a policy denial when any scope component differs or the grant is malformed.
    pub fn capabilities_for_scope(
        &self,
        plan_id: &str,
        plan_revision: u32,
        task_id: &str,
        task_contract_digest: &str,
        policy_digest: &str,
    ) -> Result<&CapabilitySet, PolicyError> {
        self.validate()?;
        if self.plan_id != plan_id
            || self.plan_revision != plan_revision
            || self.task_id != task_id
            || self.task_contract_digest != task_contract_digest
            || self.policy_digest != policy_digest
        {
            return Err(PolicyError::Denied(
                "task capability grant scope does not match exact task contract/policy".to_owned(),
            ));
        }
        Ok(&self.capabilities)
    }

    /// # Errors
    /// Returns a policy denial for incomplete exact scope fields.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || !is_sha256_binding(&self.task_contract_digest)
            || !is_sha256_binding(&self.policy_digest)
            || self.issued_by.trim().is_empty()
        {
            return Err(PolicyError::Denied(
                "task capability grant requires exact plan/task/contract/policy scope and issuer"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// The six deterministic capability ceilings whose intersection is effective authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLayers {
    pub global: CapabilitySet,
    pub project: CapabilitySet,
    pub task: CapabilitySet,
    pub role: CapabilitySet,
    pub tool: CapabilitySet,
    pub user: CapabilitySet,
}

impl CapabilityLayers {
    #[must_use]
    pub fn effective(&self) -> CapabilitySet {
        self.global
            .intersection(&self.project)
            .intersection(&self.task)
            .intersection(&self.role)
            .intersection(&self.tool)
            .intersection(&self.user)
    }
}

/// Frozen permission decision bound to an exact task contract, policy, and tool identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDecision {
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub policy_digest: String,
    pub tool_id: String,
    pub tool_version: String,
    pub tool_digest: String,
    pub layers: CapabilityLayers,
    pub effective: CapabilitySet,
}

impl PermissionDecision {
    /// Constructs a deterministic v1 decision from the six frozen authority layers.
    ///
    /// # Errors
    /// Returns a policy denial when any exact identity binding is incomplete.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: impl Into<String>,
        plan_revision: u32,
        task_id: impl Into<String>,
        task_contract_digest: impl Into<String>,
        policy_digest: impl Into<String>,
        tool_id: impl Into<String>,
        tool_version: impl Into<String>,
        tool_digest: impl Into<String>,
        layers: CapabilityLayers,
    ) -> Result<Self, PolicyError> {
        let decision = Self {
            plan_id: plan_id.into(),
            plan_revision,
            task_id: task_id.into(),
            task_contract_digest: task_contract_digest.into(),
            policy_digest: policy_digest.into(),
            tool_id: tool_id.into(),
            tool_version: tool_version.into(),
            tool_digest: tool_digest.into(),
            effective: layers.effective(),
            layers,
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Revalidates exact bindings and proves the stored effective set is the layer intersection.
    ///
    /// # Errors
    /// Returns a policy denial for malformed bindings or a mutated/inconsistent effective set.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || self.tool_id.trim().is_empty()
            || self.tool_version.trim().is_empty()
            || !is_sha256_binding(&self.task_contract_digest)
            || !is_sha256_binding(&self.policy_digest)
            || !is_sha256_binding(&self.tool_digest)
        {
            return Err(PolicyError::Denied(
                "permission decision has incomplete exact-binding fields".to_owned(),
            ));
        }
        if self.effective != self.layers.effective() {
            return Err(PolicyError::Denied(
                "permission decision effective capabilities do not match layer intersection"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(PERMISSION_DECISION_SCHEMA_VERSION.to_be_bytes());
        digest_policy_field(&mut hasher, &self.plan_id);
        hasher.update(self.plan_revision.to_be_bytes());
        digest_policy_field(&mut hasher, &self.task_id);
        digest_policy_field(&mut hasher, &self.task_contract_digest);
        digest_policy_field(&mut hasher, &self.policy_digest);
        digest_policy_field(&mut hasher, &self.tool_id);
        digest_policy_field(&mut hasher, &self.tool_version);
        digest_policy_field(&mut hasher, &self.tool_digest);
        for layer in [
            &self.layers.global,
            &self.layers.project,
            &self.layers.task,
            &self.layers.role,
            &self.layers.tool,
            &self.layers.user,
            &self.effective,
        ] {
            digest_policy_field(&mut hasher, &layer.digest());
        }
        format!("sha256:{:x}", hasher.finalize())
    }

    #[must_use]
    pub fn matches_task_scope(
        &self,
        plan_id: &str,
        plan_revision: u32,
        task_id: &str,
        task_contract_digest: &str,
    ) -> bool {
        self.plan_id == plan_id
            && self.plan_revision == plan_revision
            && self.task_id == task_id
            && self.task_contract_digest == task_contract_digest
    }

    #[must_use]
    pub fn matches_tool(&self, tool_id: &str, tool_version: &str, tool_digest: &str) -> bool {
        self.tool_id == tool_id
            && self.tool_version == tool_version
            && self.tool_digest == tool_digest
    }
}

fn is_sha256_binding(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[derive(Debug)]
pub enum PolicyError {
    Io(std::io::Error),
    Denied(String),
    IsolationUnavailable(String),
    ResourceDenied(String),
}

impl Display for PolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "policy I/O error: {error}"),
            Self::Denied(message) => write!(f, "policy denied: {message}"),
            Self::IsolationUnavailable(message) => write!(f, "isolation unavailable: {message}"),
            Self::ResourceDenied(message) => write!(f, "resource denied: {message}"),
        }
    }
}

impl Error for PolicyError {}

impl From<std::io::Error> for PolicyError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub const SECRET_REF_SCHEMA_VERSION: u32 = 1;

/// Controller-visible provider class for a durable/model-visible secret handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretProviderKind {
    MacosKeychain,
    Environment,
    ExternalBroker,
}

/// Narrow injection channel selected by Controller policy. Resolved values are never serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretInjection {
    Environment,
    Stdin,
    TemporaryFile,
    AdapterHandle,
}

/// Durable/model-visible handle metadata. This type intentionally contains no lookup locator or
/// secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub secret_ref_id: String,
    pub provider: SecretProviderKind,
    pub purpose: String,
    pub injection: SecretInjection,
    pub target: String,
}

impl SecretRef {
    /// Validates only the durable handle metadata. Provider lookup locators are Controller-owned
    /// broker configuration and are deliberately absent from this structure.
    ///
    /// # Errors
    /// Returns a denial for empty handle metadata.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.secret_ref_id.trim().is_empty()
            || self.purpose.trim().is_empty()
            || self.target.trim().is_empty()
        {
            return Err(PolicyError::Denied(
                "invalid SecretRef v1 handle metadata".to_owned(),
            ));
        }
        Ok(())
    }

    /// Computes the deterministic authority-binding digest of the exact durable five-field
    /// `SecretRef` metadata. Provider locators and resolved values are deliberately absent.
    ///
    /// # Errors
    /// Returns a denial when the durable handle metadata is malformed.
    pub fn binding_digest(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let provider = match self.provider {
            SecretProviderKind::MacosKeychain => "macos_keychain",
            SecretProviderKind::Environment => "environment",
            SecretProviderKind::ExternalBroker => "external_broker",
        };
        let injection = match self.injection {
            SecretInjection::Environment => "environment",
            SecretInjection::Stdin => "stdin",
            SecretInjection::TemporaryFile => "temporary_file",
            SecretInjection::AdapterHandle => "adapter_handle",
        };
        let mut hasher = Sha256::new();
        digest_policy_field(&mut hasher, "SecretRef:v1");
        digest_policy_field(&mut hasher, &self.secret_ref_id);
        digest_policy_field(&mut hasher, provider);
        digest_policy_field(&mut hasher, &self.purpose);
        digest_policy_field(&mut hasher, injection);
        digest_policy_field(&mut hasher, &self.target);
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

/// Exact Controller authority scope for one resolved secret lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretScope {
    pub plan_id: String,
    pub plan_revision: u32,
    pub task_id: String,
    pub task_contract_digest: String,
    pub action_id: String,
    pub permission_decision_digest: String,
    pub execution_epoch: i64,
}

impl SecretScope {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.plan_id.trim().is_empty()
            || self.task_id.trim().is_empty()
            || self.action_id.trim().is_empty()
            || self.execution_epoch < 0
            || !is_sha256_binding(&self.task_contract_digest)
            || !is_sha256_binding(&self.permission_decision_digest)
        {
            return Err(PolicyError::Denied(
                "secret scope has incomplete exact authority bindings".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Provider lookup metadata that only Controller configuration supplies to a [`SecretBroker`].
/// It is intentionally not serializable and never belongs in Plan IR, model context, or durable
/// action state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerSecretLocator {
    MacosKeychain {
        service: String,
        account: Option<String>,
    },
    EnvironmentVariable(String),
    ExternalBrokerKey(String),
    FakeKey {
        provider: SecretProviderKind,
        key: String,
    },
}

impl ControllerSecretLocator {
    fn provider(&self) -> SecretProviderKind {
        match self {
            Self::MacosKeychain { .. } => SecretProviderKind::MacosKeychain,
            Self::EnvironmentVariable(_) => SecretProviderKind::Environment,
            Self::ExternalBrokerKey(_) => SecretProviderKind::ExternalBroker,
            Self::FakeKey { provider, .. } => *provider,
        }
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let valid = match self {
            Self::MacosKeychain { service, account } => {
                !service.trim().is_empty()
                    && account
                        .as_ref()
                        .is_none_or(|value| !value.trim().is_empty())
            }
            Self::EnvironmentVariable(name) | Self::ExternalBrokerKey(name) => {
                !name.trim().is_empty()
            }
            Self::FakeKey { key, .. } => !key.trim().is_empty(),
        };
        if valid {
            Ok(())
        } else {
            Err(PolicyError::Denied(
                "Controller secret locator is empty or malformed".to_owned(),
            ))
        }
    }
}

/// Opaque resolved bytes. The type cannot be serialized or cloned and its `Debug` output never
/// reveals the underlying value. Bytes are zeroed when the value is dropped.
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Creates a provider-owned opaque value. Callers should keep this value inside broker/lease
    /// scope and expose it only through [`SecretLease::with_value`].
    #[must_use]
    pub fn from_provider_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Provider seam owned by the broker. Repository/model text never receives this interface.
pub trait SecretProviderBackend: Send + Sync {
    fn kind(&self) -> SecretProviderKind;

    /// Resolves one Controller-configured locator to opaque bytes.
    ///
    /// # Errors
    /// Returns a fail-closed policy/provider error without exposing resolved bytes in the error.
    fn resolve(&self, locator: &ControllerSecretLocator) -> Result<SecretValue, PolicyError>;
}

/// Deterministic provider used by policy tests and higher-layer fake-broker tests.
#[derive(Debug)]
pub struct FakeSecretProvider {
    kind: SecretProviderKind,
    values: BTreeMap<String, Vec<u8>>,
}

impl FakeSecretProvider {
    #[must_use]
    pub fn new(
        kind: SecretProviderKind,
        values: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Self {
        Self {
            kind,
            values: values.into_iter().collect(),
        }
    }
}

impl SecretProviderBackend for FakeSecretProvider {
    fn kind(&self) -> SecretProviderKind {
        self.kind
    }

    fn resolve(&self, locator: &ControllerSecretLocator) -> Result<SecretValue, PolicyError> {
        let ControllerSecretLocator::FakeKey { provider, key } = locator else {
            return Err(PolicyError::Denied(
                "fake secret provider received a locator for another provider".to_owned(),
            ));
        };
        if *provider != self.kind() {
            return Err(PolicyError::Denied(
                "fake secret provider kind does not match Controller locator".to_owned(),
            ));
        }
        self.values
            .get(key)
            .cloned()
            .map(SecretValue::from_provider_bytes)
            .ok_or_else(|| {
                PolicyError::Denied("configured secret handle is unavailable".to_owned())
            })
    }
}

/// macOS Keychain provider seam. It is reachable only through a Controller-configured broker
/// registration; repository/model strings cannot supply service/account lookup fields at resolve
/// time. Tests must not invoke this provider against real credentials.
#[derive(Debug, Default)]
pub struct MacOsKeychainProvider;

impl SecretProviderBackend for MacOsKeychainProvider {
    fn kind(&self) -> SecretProviderKind {
        SecretProviderKind::MacosKeychain
    }

    fn resolve(&self, locator: &ControllerSecretLocator) -> Result<SecretValue, PolicyError> {
        let ControllerSecretLocator::MacosKeychain { service, account } = locator else {
            return Err(PolicyError::Denied(
                "macOS Keychain provider received a locator for another provider".to_owned(),
            ));
        };
        if !cfg!(target_os = "macos") || !Path::new("/usr/bin/security").is_file() {
            return Err(PolicyError::IsolationUnavailable(
                "macOS Keychain provider is unavailable on this host".to_owned(),
            ));
        }
        let mut command = Command::new("/usr/bin/security");
        command
            .args(["find-generic-password", "-w", "-s", service])
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        if let Some(account) = account {
            command.args(["-a", account]);
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(PolicyError::Denied(
                "Controller-configured Keychain secret could not be resolved".to_owned(),
            ));
        }
        let mut bytes = output.stdout;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        if bytes.is_empty() {
            return Err(PolicyError::Denied(
                "Controller-configured Keychain secret resolved to an empty value".to_owned(),
            ));
        }
        Ok(SecretValue::from_provider_bytes(bytes))
    }
}

#[derive(Debug, Clone)]
struct RegisteredSecret {
    secret_ref: SecretRef,
    locator: ControllerSecretLocator,
}

/// Controller-owned broker registry. Only exact preconfigured handles can be resolved; there is no
/// API that accepts an arbitrary provider lookup string from repository/model content.
#[derive(Default)]
pub struct SecretBroker {
    providers: BTreeMap<SecretProviderKind, Arc<dyn SecretProviderBackend>>,
    registrations: BTreeMap<String, RegisteredSecret>,
}

impl SecretBroker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one Controller-owned provider implementation.
    ///
    /// # Errors
    /// Returns a denial instead of silently replacing an existing provider binding.
    pub fn register_provider(
        &mut self,
        provider: Arc<dyn SecretProviderBackend>,
    ) -> Result<(), PolicyError> {
        let kind = provider.kind();
        if self.providers.contains_key(&kind) {
            return Err(PolicyError::Denied(
                "secret provider kind is already Controller-configured".to_owned(),
            ));
        }
        self.providers.insert(kind, provider);
        Ok(())
    }

    /// Registers one exact durable handle to a private provider locator.
    ///
    /// # Errors
    /// Returns a denial for malformed metadata, provider mismatch, missing provider, or rebinding.
    pub fn register_secret(
        &mut self,
        secret_ref: SecretRef,
        locator: ControllerSecretLocator,
    ) -> Result<(), PolicyError> {
        secret_ref.validate()?;
        locator.validate()?;
        if secret_ref.provider != locator.provider() {
            return Err(PolicyError::Denied(
                "SecretRef provider does not match Controller locator provider".to_owned(),
            ));
        }
        if !self.providers.contains_key(&secret_ref.provider) {
            return Err(PolicyError::Denied(
                "SecretRef provider has not been Controller-configured".to_owned(),
            ));
        }
        if self.registrations.contains_key(&secret_ref.secret_ref_id) {
            return Err(PolicyError::Denied(
                "SecretRef id is already registered and cannot be rebound".to_owned(),
            ));
        }
        self.registrations.insert(
            secret_ref.secret_ref_id.clone(),
            RegisteredSecret {
                secret_ref,
                locator,
            },
        );
        Ok(())
    }

    /// Resolves one exact preconfigured handle into an ephemeral exact-scope lease.
    ///
    /// # Errors
    /// Returns a denial for unknown/modified handles, missing `secret_use`, stale scope, expiry, or
    /// provider failure.
    pub fn resolve(
        &self,
        secret_ref: &SecretRef,
        scope: SecretScope,
        effective_capabilities: &CapabilitySet,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<SecretLease, PolicyError> {
        secret_ref.validate()?;
        scope.validate()?;
        if !effective_capabilities.contains(Capability::SecretUse) {
            return Err(PolicyError::Denied(
                "secret resolution requires effective secret_use capability".to_owned(),
            ));
        }
        if now_ms < 0 || expires_at_ms <= now_ms {
            return Err(PolicyError::Denied(
                "secret lease is already expired or has invalid time bounds".to_owned(),
            ));
        }
        let registration = self
            .registrations
            .get(&secret_ref.secret_ref_id)
            .ok_or_else(|| PolicyError::Denied("unknown SecretRef handle".to_owned()))?;
        if &registration.secret_ref != secret_ref {
            return Err(PolicyError::Denied(
                "SecretRef metadata does not match Controller configuration".to_owned(),
            ));
        }
        let provider = self.providers.get(&secret_ref.provider).ok_or_else(|| {
            PolicyError::Denied("SecretRef provider is no longer configured".to_owned())
        })?;
        let value = provider.resolve(&registration.locator)?;
        Ok(SecretLease {
            secret_ref: secret_ref.clone(),
            scope,
            issued_at_ms: now_ms,
            expires_at_ms,
            value: Some(value),
            closed: false,
            temp_cleanup: None,
        })
    }
}

/// Ephemeral resolved secret authority. This type is intentionally neither serializable nor
/// clonable; its `Debug` output exposes metadata only.
pub struct SecretLease {
    secret_ref: SecretRef,
    scope: SecretScope,
    issued_at_ms: i64,
    expires_at_ms: i64,
    value: Option<SecretValue>,
    closed: bool,
    temp_cleanup: Option<Arc<AtomicBool>>,
}

impl std::fmt::Debug for SecretLease {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretLease")
            .field("secret_ref", &self.secret_ref)
            .field("scope", &self.scope)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl SecretLease {
    #[must_use]
    pub fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    fn validate_use(
        &self,
        scope: &SecretScope,
        effective_capabilities: &CapabilitySet,
        now_ms: i64,
    ) -> Result<(), PolicyError> {
        scope.validate()?;
        if !effective_capabilities.contains(Capability::SecretUse) {
            return Err(PolicyError::Denied(
                "secret value use requires current effective secret_use capability".to_owned(),
            ));
        }
        if self.closed || self.value.is_none() {
            return Err(PolicyError::Denied("secret lease is closed".to_owned()));
        }
        if scope != &self.scope {
            return Err(PolicyError::Denied(
                "secret lease scope does not match exact Controller authority".to_owned(),
            ));
        }
        if now_ms < self.issued_at_ms || now_ms >= self.expires_at_ms {
            return Err(PolicyError::Denied("secret lease expired".to_owned()));
        }
        Ok(())
    }

    /// Exposes resolved bytes only inside one exact-scope ephemeral injection closure.
    ///
    /// # Errors
    /// Returns a denial for closed, expired, or mismatched scope.
    pub fn with_value<T>(
        &self,
        scope: &SecretScope,
        effective_capabilities: &CapabilitySet,
        now_ms: i64,
        use_value: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, PolicyError> {
        self.validate_use(scope, effective_capabilities, now_ms)?;
        let value = self
            .value
            .as_ref()
            .ok_or_else(|| PolicyError::Denied("secret lease is closed".to_owned()))?;
        Ok(use_value(&value.0))
    }

    /// Creates a private, exact-task/action temporary secret file. The returned guard must prove
    /// deletion before this lease can close successfully.
    ///
    /// # Errors
    /// Returns a denial for a non-temporary-file handle, stale scope, unsafe private directory, or
    /// any file creation/write/permission failure.
    pub fn inject_temporary_file(
        &mut self,
        scope: &SecretScope,
        effective_capabilities: &CapabilitySet,
        now_ms: i64,
        controller_private_root: impl AsRef<Path>,
    ) -> Result<TempSecretFileGuard, PolicyError> {
        self.validate_use(scope, effective_capabilities, now_ms)?;
        if self.secret_ref.injection != SecretInjection::TemporaryFile {
            return Err(PolicyError::Denied(
                "SecretRef is not authorized for temporary_file injection".to_owned(),
            ));
        }
        if self.temp_cleanup.is_some() {
            return Err(PolicyError::Denied(
                "secret lease already owns a temporary injection lifecycle".to_owned(),
            ));
        }
        let root = controller_private_root.as_ref();
        ensure_private_directory(root)?;
        let task_dir = root.join(format!("task-{}", secret_scope_fragment(&scope.task_id)));
        ensure_private_directory(&task_dir)?;
        let action_dir = task_dir.join(format!(
            "action-{}",
            secret_scope_fragment(&format!("{}:{}", scope.action_id, scope.execution_epoch))
        ));
        ensure_private_directory(&action_dir)?;
        let path = action_dir.join(format!(
            "secret-{}",
            secret_scope_fragment(&self.secret_ref.secret_ref_id)
        ));
        let cleanup_proven = Arc::new(AtomicBool::new(false));

        let write_result = self.with_value(scope, effective_capabilities, now_ms, |bytes| {
            create_private_secret_file(&path, bytes)
        })?;
        if let Err(error) = write_result {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        self.temp_cleanup = Some(Arc::clone(&cleanup_proven));
        Ok(TempSecretFileGuard {
            path,
            action_dir,
            task_dir,
            cleanup_proven,
            explicitly_closed: false,
        })
    }

    /// Closes an exact-scope lease and destroys the in-memory value. A temporary-file injection
    /// cannot close until explicit deletion has been proven by its guard.
    ///
    /// # Errors
    /// Returns a denial for scope mismatch, double-close, or unproven temporary-file cleanup.
    pub fn close(&mut self, scope: &SecretScope) -> Result<(), PolicyError> {
        scope.validate()?;
        if scope != &self.scope {
            return Err(PolicyError::Denied(
                "secret lease close scope does not match exact authority".to_owned(),
            ));
        }
        if self.closed {
            return Err(PolicyError::Denied(
                "secret lease is already closed".to_owned(),
            ));
        }
        if self
            .temp_cleanup
            .as_ref()
            .is_some_and(|proof| !proof.load(Ordering::Acquire))
        {
            return Err(PolicyError::Denied(
                "temporary secret file deletion is not proven".to_owned(),
            ));
        }
        self.value.take();
        self.closed = true;
        Ok(())
    }
}

/// Exact private temporary-file lifecycle for one secret-use action.
pub struct TempSecretFileGuard {
    path: PathBuf,
    action_dir: PathBuf,
    task_dir: PathBuf,
    cleanup_proven: Arc<AtomicBool>,
    explicitly_closed: bool,
}

impl std::fmt::Debug for TempSecretFileGuard {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempSecretFileGuard")
            .field("path", &self.path)
            .field("explicitly_closed", &self.explicitly_closed)
            .finish_non_exhaustive()
    }
}

impl TempSecretFileGuard {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly deletes the secret file and verifies `NotFound` before publishing cleanup proof.
    ///
    /// # Errors
    /// Returns fail-closed if deletion or absence verification cannot be proven.
    pub fn close(&mut self) -> Result<(), PolicyError> {
        if self.explicitly_closed {
            return Err(PolicyError::Denied(
                "temporary secret file guard is already closed".to_owned(),
            ));
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(PolicyError::Denied(
                    "temporary secret file still exists after deletion".to_owned(),
                ));
            }
            Err(error) => return Err(error.into()),
        }
        self.cleanup_proven.store(true, Ordering::Release);
        self.explicitly_closed = true;
        let _ = fs::remove_dir(&self.action_dir);
        let _ = fs::remove_dir(&self.task_dir);
        Ok(())
    }
}

impl Drop for TempSecretFileGuard {
    fn drop(&mut self) {
        if !self.explicitly_closed {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.action_dir);
            let _ = fs::remove_dir(&self.task_dir);
        }
    }
}

fn secret_scope_fragment(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())[..20].to_owned()
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<(), PolicyError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PolicyError::Denied(
            "secret injection directory must be a real directory".to_owned(),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.permissions().mode() & 0o777 != 0o700 {
        return Err(PolicyError::Denied(
            "secret injection directory privacy could not be proven".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(_path: &Path) -> Result<(), PolicyError> {
    Err(PolicyError::IsolationUnavailable(
        "private secret-file permission proof requires Unix mode semantics".to_owned(),
    ))
}

#[cfg(unix)]
fn create_private_secret_file(path: &Path, bytes: &[u8]) -> Result<(), PolicyError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    IoWrite::write_all(&mut file, bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(PolicyError::Denied(
            "temporary secret file privacy could not be proven".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_secret_file(_path: &Path, _bytes: &[u8]) -> Result<(), PolicyError> {
    Err(PolicyError::IsolationUnavailable(
        "private secret-file permission proof requires Unix mode semantics".to_owned(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandRisk {
    ReadOnly,
    RepositoryMutation,
    UntrustedCode,
    PackageInstall,
    Destructive,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandMode {
    Direct,
    Shell,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub mode: CommandMode,
    pub declared_risk: CommandRisk,
    pub timeout_ms: u64,
    pub output_limit_bytes: u64,
    pub disk_write_limit_bytes: u64,
    pub subprocess_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedExecutable {
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}

impl PinnedExecutable {
    /// Creates a digest-pinned executable record from an existing file.
    ///
    /// # Errors
    /// Returns an I/O error when the executable cannot be canonicalized or read.
    pub fn from_path(
        path: impl AsRef<Path>,
        version: impl Into<String>,
    ) -> Result<Self, PolicyError> {
        let path = path.as_ref().canonicalize()?;
        let bytes = fs::read(&path)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(Self {
            path,
            sha256: format!("sha256:{:x}", hasher.finalize()),
            version: version.into(),
        })
    }

    /// Re-hashes the pinned executable and validates its non-empty version label.
    ///
    /// # Errors
    /// Returns a policy error when the executable changed or provenance is incomplete.
    pub fn verify(&self) -> Result<(), PolicyError> {
        let actual = Self::from_path(&self.path, self.version.clone())?;
        if actual.sha256 != self.sha256 {
            return Err(PolicyError::Denied(format!(
                "executable digest mismatch for {}",
                self.path.display()
            )));
        }
        if self.version.trim().is_empty() {
            return Err(PolicyError::Denied(
                "pinned executable version is empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PathPolicy {
    repository_root: PathBuf,
    protected_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCommitMode {
    AtomicReplace,
    InPlace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAuthorizationTicket {
    repository_root: PathBuf,
    relative_path: PathBuf,
    authorized_target: PathBuf,
    parent_path: PathBuf,
    parent_identity: FileIdentity,
    target_identity: Option<FileIdentity>,
    target_link_count: Option<u64>,
}

impl PathAuthorizationTicket {
    #[must_use]
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    #[must_use]
    pub fn authorized_target(&self) -> &Path {
        &self.authorized_target
    }

    #[must_use]
    pub const fn parent_identity(&self) -> FileIdentity {
        self.parent_identity
    }

    #[must_use]
    pub const fn target_identity(&self) -> Option<FileIdentity> {
        self.target_identity
    }

    #[must_use]
    pub const fn target_link_count(&self) -> Option<u64> {
        self.target_link_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRepositoryScope {
    registered_repository_ids: BTreeSet<String>,
    writable_repository_ids: BTreeSet<String>,
}

impl ActiveRepositoryScope {
    /// Builds an exact task repository-write scope from the project registry snapshot.
    ///
    /// # Errors
    /// Returns a denial if task scope names an unregistered repository.
    pub fn new(
        registered_repository_ids: impl IntoIterator<Item = String>,
        writable_repository_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, PolicyError> {
        let registered_repository_ids = registered_repository_ids.into_iter().collect();
        let writable_repository_ids: BTreeSet<_> = writable_repository_ids.into_iter().collect();
        if !writable_repository_ids.is_subset(&registered_repository_ids) {
            return Err(PolicyError::Denied(
                "active repository scope contains an unregistered repository".to_owned(),
            ));
        }
        Ok(Self {
            registered_repository_ids,
            writable_repository_ids,
        })
    }

    /// Authorizes one registered repository for mutation under the exact active task scope.
    ///
    /// # Errors
    /// Returns a denial for unknown repositories and registered siblings outside task scope.
    pub fn authorize_write(&self, repository_id: &str) -> Result<(), PolicyError> {
        if !self.registered_repository_ids.contains(repository_id) {
            return Err(PolicyError::Denied(format!(
                "repository is not registered: {repository_id}"
            )));
        }
        if !self.writable_repository_ids.contains(repository_id) {
            return Err(PolicyError::Denied(format!(
                "registered sibling repository is outside exact active task scope: {repository_id}"
            )));
        }
        Ok(())
    }
}

impl PathPolicy {
    /// Builds a canonical repository jail and protected-root set.
    ///
    /// # Errors
    /// Returns an I/O or policy error for unresolved roots.
    pub fn new(
        repository_root: impl AsRef<Path>,
        protected_roots: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, PolicyError> {
        let repository_root = repository_root.as_ref().canonicalize()?;
        let protected_roots = protected_roots
            .into_iter()
            .map(|root| canonicalize_existing_or_parent(&root))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            repository_root,
            protected_roots,
        })
    }

    #[must_use]
    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    /// Resolves and authorizes an existing repository-relative path.
    ///
    /// # Errors
    /// Returns a policy error for traversal, symlink escape, or protected roots.
    pub fn authorize_existing(&self, relative: impl AsRef<Path>) -> Result<PathBuf, PolicyError> {
        validate_relative(relative.as_ref())?;
        let candidate = self
            .repository_root
            .join(relative.as_ref())
            .canonicalize()?;
        self.authorize_canonical(&candidate)?;
        Ok(candidate)
    }

    /// Resolves an authorized parent for a not-yet-existing repository path.
    ///
    /// # Errors
    /// Returns a policy error for traversal, symlink escape, or protected roots.
    pub fn authorize_create(&self, relative: impl AsRef<Path>) -> Result<PathBuf, PolicyError> {
        let relative = relative.as_ref();
        validate_relative(relative)?;
        let candidate = self.repository_root.join(relative);
        let parent = candidate.parent().ok_or_else(|| {
            PolicyError::Denied("create path has no authorized parent".to_owned())
        })?;
        let canonical_parent = parent.canonicalize()?;
        self.authorize_canonical(&canonical_parent)?;
        let file_name = candidate
            .file_name()
            .ok_or_else(|| PolicyError::Denied("create path has no final component".to_owned()))?;
        Ok(canonical_parent.join(file_name))
    }

    /// Creates an immutable mutation ticket bound to the authorized parent and target identity.
    ///
    /// The ticket is intentionally separate from the eventual write. Call
    /// [`PathPolicy::revalidate_for_commit`] immediately before the filesystem commit.
    ///
    /// # Errors
    /// Returns a denial for traversal, symlinks, non-regular existing targets, protected roots,
    /// or targets outside the repository jail.
    pub fn authorize_mutation(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<PathAuthorizationTicket, PolicyError> {
        let relative = relative.as_ref();
        validate_relative(relative)?;
        let candidate = self.repository_root.join(relative);
        let parent = candidate.parent().ok_or_else(|| {
            PolicyError::Denied("mutation path has no authorized parent".to_owned())
        })?;
        let canonical_parent = parent.canonicalize()?;
        self.authorize_canonical(&canonical_parent)?;
        let parent_metadata = fs::symlink_metadata(&canonical_parent)?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(PolicyError::Denied(
                "mutation parent must remain a real directory".to_owned(),
            ));
        }
        let file_name = candidate.file_name().ok_or_else(|| {
            PolicyError::Denied("mutation path has no final component".to_owned())
        })?;
        let authorized_target = canonical_parent.join(file_name);
        self.authorize_canonical(&authorized_target)?;
        let (target_identity, target_link_count) = match fs::symlink_metadata(&authorized_target) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(PolicyError::Denied(
                        "mutation target must be a regular non-symlink file".to_owned(),
                    ));
                }
                (
                    Some(file_identity(&metadata)),
                    Some(file_link_count(&metadata)),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (None, None),
            Err(error) => return Err(error.into()),
        };
        Ok(PathAuthorizationTicket {
            repository_root: self.repository_root.clone(),
            relative_path: relative.to_path_buf(),
            authorized_target,
            parent_path: canonical_parent,
            parent_identity: file_identity(&parent_metadata),
            target_identity,
            target_link_count,
        })
    }

    /// Revalidates a mutation ticket immediately before commit.
    ///
    /// Atomic replacement is permitted for a hard-linked existing target because the operation
    /// replaces the authorized directory entry rather than mutating the shared inode. In-place
    /// mutation of a multiply-linked inode is always denied.
    ///
    /// # Errors
    /// Returns a denial if repository, parent, target identity, symlink state, or hard-link safety
    /// differs from the immutable authorization ticket.
    pub fn revalidate_for_commit(
        &self,
        ticket: &PathAuthorizationTicket,
        mode: PathCommitMode,
    ) -> Result<PathBuf, PolicyError> {
        if ticket.repository_root != self.repository_root {
            return Err(PolicyError::Denied(
                "path authorization ticket belongs to another repository root".to_owned(),
            ));
        }
        validate_relative(&ticket.relative_path)?;
        let candidate = self.repository_root.join(&ticket.relative_path);
        let parent = candidate.parent().ok_or_else(|| {
            PolicyError::Denied("mutation path has no authorized parent".to_owned())
        })?;
        let canonical_parent = parent.canonicalize()?;
        self.authorize_canonical(&canonical_parent)?;
        if canonical_parent != ticket.parent_path {
            return Err(PolicyError::Denied(
                "mutation parent path changed after authorization".to_owned(),
            ));
        }
        let parent_metadata = fs::symlink_metadata(&canonical_parent)?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || file_identity(&parent_metadata) != ticket.parent_identity
        {
            return Err(PolicyError::Denied(
                "mutation parent identity changed after authorization".to_owned(),
            ));
        }
        let file_name = candidate.file_name().ok_or_else(|| {
            PolicyError::Denied("mutation path has no final component".to_owned())
        })?;
        let target = canonical_parent.join(file_name);
        if target != ticket.authorized_target {
            return Err(PolicyError::Denied(
                "mutation target path changed after authorization".to_owned(),
            ));
        }
        self.authorize_canonical(&target)?;
        match (ticket.target_identity, fs::symlink_metadata(&target)) {
            (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            (None, Ok(_)) => {
                return Err(PolicyError::Denied(
                    "mutation target appeared after authorization".to_owned(),
                ));
            }
            (Some(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PolicyError::Denied(
                    "mutation target disappeared after authorization".to_owned(),
                ));
            }
            (None | Some(_), Err(error)) => return Err(error.into()),
            (Some(expected), Ok(metadata)) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(PolicyError::Denied(
                        "mutation target changed to a non-regular or symlink entry".to_owned(),
                    ));
                }
                if file_identity(&metadata) != expected {
                    return Err(PolicyError::Denied(
                        "mutation target identity changed after authorization".to_owned(),
                    ));
                }
                if mode == PathCommitMode::InPlace && file_link_count(&metadata) > 1 {
                    return Err(PolicyError::Denied(
                        "in-place mutation of a multiply-linked inode is forbidden; use atomic replacement"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(target)
    }

    fn authorize_canonical(&self, candidate: &Path) -> Result<(), PolicyError> {
        if !candidate.starts_with(&self.repository_root) {
            return Err(PolicyError::Denied(format!(
                "path escapes repository root: {}",
                candidate.display()
            )));
        }
        if self
            .protected_roots
            .iter()
            .any(|protected| candidate.starts_with(protected))
        {
            return Err(PolicyError::Denied(format!(
                "path intersects protected root: {}",
                candidate.display()
            )));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: metadata.len(),
    }
}

#[cfg(unix)]
fn file_link_count(metadata: &fs::Metadata) -> u64 {
    metadata.nlink()
}

#[cfg(not(unix))]
fn file_link_count(_metadata: &fs::Metadata) -> u64 {
    1
}

fn validate_relative(path: &Path) -> Result<(), PolicyError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(PolicyError::Denied(
            "path must be a non-empty repository-relative selector".to_owned(),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(PolicyError::Denied(
            "path traversal is forbidden".to_owned(),
        ));
    }
    Ok(())
}

fn canonicalize_existing_or_parent(path: &Path) -> Result<PathBuf, PolicyError> {
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let Some(parent) = path.parent() else {
        return Err(PolicyError::Denied(format!(
            "protected root has no parent: {}",
            path.display()
        )));
    };
    Ok(parent.canonicalize()?.join(
        path.file_name().ok_or_else(|| {
            PolicyError::Denied("protected root has no final component".to_owned())
        })?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDestination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default)]
pub struct MinimalNetworkPolicy {
    allowed: BTreeSet<(String, String, u16)>,
}

impl MinimalNetworkPolicy {
    #[must_use]
    pub fn offline() -> Self {
        Self::default()
    }

    /// Adds one exact normalized network destination to the task allowlist.
    ///
    /// # Errors
    /// Returns a policy error when the destination is not already normalized safely.
    pub fn allow(&mut self, scheme: &str, host: &str, port: u16) -> Result<(), PolicyError> {
        self.allowed
            .insert(normalize_destination(scheme, host, port)?);
        Ok(())
    }

    /// Checks one network destination against the exact task allowlist.
    ///
    /// # Errors
    /// Returns a policy denial when the destination is absent or malformed.
    pub fn authorize(&self, destination: &NetworkDestination) -> Result<(), PolicyError> {
        let key = normalize_destination(&destination.scheme, &destination.host, destination.port)?;
        if self.allowed.contains(&key) {
            Ok(())
        } else {
            Err(PolicyError::Denied(format!(
                "network destination not task-authorized: {}://{}:{}",
                destination.scheme, destination.host, destination.port
            )))
        }
    }

    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.allowed.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAuthorization {
    destination: (String, String, u16),
    resolved_ips: BTreeSet<IpAddr>,
}

impl NetworkAuthorization {
    #[must_use]
    pub fn destination(&self) -> NetworkDestination {
        NetworkDestination {
            scheme: self.destination.0.clone(),
            host: self.destination.1.clone(),
            port: self.destination.2,
        }
    }

    pub fn resolved_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.resolved_ips.iter().copied()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkPolicy {
    allowed: BTreeSet<(String, String, u16)>,
}

impl NetworkPolicy {
    #[must_use]
    pub fn offline() -> Self {
        Self::default()
    }

    /// Adds one exact normalized destination to the governed network allowlist.
    ///
    /// # Errors
    /// Returns a denial for malformed or directly unsafe IP-literal destinations.
    pub fn allow(&mut self, scheme: &str, host: &str, port: u16) -> Result<(), PolicyError> {
        let key = normalize_destination(scheme, host, port)?;
        reject_unsafe_host_literal(&key.1)?;
        self.allowed.insert(key);
        Ok(())
    }

    /// Performs the governed destination check before any DNS or network I/O occurs.
    ///
    /// The returned destination is canonical and must be used for DNS and later resolved/peer
    /// authorization so allowlist comparison and resolution use the same hostname identity.
    ///
    /// # Errors
    /// Returns a denial for malformed/unsafe destinations or destinations absent from the active
    /// task allowlist.
    pub fn authorize_destination(
        &self,
        destination: &NetworkDestination,
    ) -> Result<NetworkDestination, PolicyError> {
        let key = normalize_destination(&destination.scheme, &destination.host, destination.port)?;
        reject_unsafe_host_literal(&key.1)?;
        if !self.allowed.contains(&key) {
            return Err(PolicyError::Denied(format!(
                "network destination not task-authorized: {}://{}:{}",
                destination.scheme, destination.host, destination.port
            )));
        }
        Ok(NetworkDestination {
            scheme: key.0,
            host: key.1,
            port: key.2,
        })
    }

    /// Authorizes one destination together with caller-supplied DNS resolution results.
    ///
    /// This method performs no DNS or network I/O. The caller must supply the complete set it
    /// intends to connect to, and every address must be public and policy-safe.
    ///
    /// # Errors
    /// Returns a denial for absent allowlist authority, empty resolution, or any unsafe address.
    pub fn authorize_resolved(
        &self,
        destination: &NetworkDestination,
        resolved_ips: impl IntoIterator<Item = IpAddr>,
    ) -> Result<NetworkAuthorization, PolicyError> {
        let destination = self.authorize_destination(destination)?;
        let key = (destination.scheme, destination.host, destination.port);
        let resolved_ips: BTreeSet<_> = resolved_ips.into_iter().collect();
        if resolved_ips.is_empty() {
            return Err(PolicyError::Denied(
                "network authorization requires caller-supplied resolved IPs".to_owned(),
            ));
        }
        for address in &resolved_ips {
            reject_unsafe_network_ip(*address)?;
        }
        Ok(NetworkAuthorization {
            destination: key,
            resolved_ips,
        })
    }

    /// Validates the actual connected peer against the exact previously authorized DNS set.
    ///
    /// # Errors
    /// Returns a denial for private/special peers or DNS-rebinding/peer mismatch.
    pub fn authorize_connected_peer(
        &self,
        authorization: &NetworkAuthorization,
        peer: IpAddr,
    ) -> Result<(), PolicyError> {
        if !self.allowed.contains(&authorization.destination) {
            return Err(PolicyError::Denied(
                "network authorization no longer matches the active allowlist".to_owned(),
            ));
        }
        reject_unsafe_network_ip(peer)?;
        if !authorization.resolved_ips.contains(&peer) {
            return Err(PolicyError::Denied(
                "connected peer differs from the authorized DNS result".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reauthorizes an HTTP/package/browser redirect as a new exact destination and DNS set.
    ///
    /// # Errors
    /// Returns a denial unless the redirect target is independently allowlisted and resolves
    /// exclusively to policy-safe addresses.
    pub fn authorize_redirect(
        &self,
        destination: &NetworkDestination,
        resolved_ips: impl IntoIterator<Item = IpAddr>,
    ) -> Result<NetworkAuthorization, PolicyError> {
        self.authorize_resolved(destination, resolved_ips)
    }

    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.allowed.is_empty()
    }
}

fn normalize_destination(
    scheme: &str,
    host: &str,
    port: u16,
) -> Result<(String, String, u16), PolicyError> {
    if scheme.is_empty() || host.is_empty() || port == 0 {
        return Err(PolicyError::Denied(
            "invalid network destination".to_owned(),
        ));
    }
    if !scheme
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(PolicyError::Denied("invalid network scheme".to_owned()));
    }
    let host = canonicalize_network_host(host)?;
    Ok((scheme.to_ascii_lowercase(), host, port))
}

fn canonicalize_network_host(host: &str) -> Result<String, PolicyError> {
    if host.is_empty() {
        return Err(PolicyError::Denied("invalid network host".to_owned()));
    }

    let literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = literal.parse::<IpAddr>() {
        return Ok(match address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) if host.starts_with('[') => format!("[{address}]"),
            IpAddr::V6(address) => address.to_string(),
        });
    }
    if host.contains(['[', ']', ':']) {
        return Err(PolicyError::Denied("invalid network host".to_owned()));
    }
    if host.len() > 4_096 {
        return Err(PolicyError::Denied(
            "network host exceeds IDNA input bound".to_owned(),
        ));
    }

    let canonical = canonicalize_idna_uts46(host)?;
    let canonical = canonical.strip_suffix('.').unwrap_or(&canonical).to_owned();
    if canonical.len() > 253 {
        return Err(PolicyError::Denied(
            "network host exceeds DNS name bound".to_owned(),
        ));
    }
    for label in canonical.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(PolicyError::Denied("invalid DNS label".to_owned()));
        }
    }
    Ok(canonical)
}

fn canonicalize_idna_uts46(host: &str) -> Result<String, PolicyError> {
    const MAX_OUTPUT_BYTES: usize = 253;
    const HELPER_TIMEOUT: Duration = Duration::from_secs(2);

    let helper = Path::new(env!("SOVEREIGN_IDNA_UTS46_HELPER"));
    if !helper.is_absolute() || !helper.is_file() {
        return Err(PolicyError::Denied(
            "standards IDNA canonicalizer is unavailable on this target".to_owned(),
        ));
    }

    let deadline = Instant::now() + HELPER_TIMEOUT;
    let mut child = Command::new(helper)
        .env_clear()
        .arg(host)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            PolicyError::Denied(format!(
                "failed to launch standards IDNA canonicalizer: {error}"
            ))
        })?;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(PolicyError::Denied(
                    "standards IDNA canonicalizer timed out".to_owned(),
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(1)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(PolicyError::Io(error));
            }
        }
    };

    let mut stdout = child.stdout.take().ok_or_else(|| {
        PolicyError::Denied("standards IDNA canonicalizer stdout was unavailable".to_owned())
    })?;
    let mut output = Vec::with_capacity(MAX_OUTPUT_BYTES + 1);
    stdout
        .by_ref()
        .take(u64::try_from(MAX_OUTPUT_BYTES + 1).map_err(|_| {
            PolicyError::Denied("IDNA output bound is not representable".to_owned())
        })?)
        .read_to_end(&mut output)?;
    if !status.success() {
        return Err(PolicyError::Denied(
            "invalid hostname under UTS #46/IDNA rules".to_owned(),
        ));
    }
    if output.is_empty() || output.len() > MAX_OUTPUT_BYTES {
        return Err(PolicyError::Denied(
            "standards IDNA canonicalizer exceeded DNS output bound".to_owned(),
        ));
    }
    let canonical = String::from_utf8(output).map_err(|_| {
        PolicyError::Denied("IDNA canonicalizer returned non-ASCII output".to_owned())
    })?;
    if !canonical.is_ascii() {
        return Err(PolicyError::Denied(
            "IDNA canonicalizer returned non-ASCII output".to_owned(),
        ));
    }
    Ok(canonical.to_ascii_lowercase())
}

fn reject_unsafe_host_literal(host: &str) -> Result<(), PolicyError> {
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = host.parse::<IpAddr>() {
        reject_unsafe_network_ip(address)?;
    }
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "metadata.google.internal" | "metadata" | "instance-data"
    ) {
        return Err(PolicyError::Denied(
            "metadata service destination is forbidden".to_owned(),
        ));
    }
    Ok(())
}

fn reject_unsafe_network_ip(address: IpAddr) -> Result<(), PolicyError> {
    let unsafe_address = match address {
        IpAddr::V4(address) => unsafe_ipv4(address),
        IpAddr::V6(address) => unsafe_ipv6(address),
    };
    if unsafe_address {
        return Err(PolicyError::Denied(format!(
            "private, loopback, link-local, multicast, unspecified, or metadata network destination is forbidden: {address}"
        )));
    }
    Ok(())
}

fn unsafe_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || octets == [100, 100, 100, 200]
        || octets == [169, 254, 169, 254]
        || octets == [169, 254, 170, 2]
}

fn unsafe_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return unsafe_ipv4(mapped);
    }
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct CommandPolicy {
    pinned: BTreeMap<PathBuf, PinnedExecutable>,
    toolchain_roots: Vec<PathBuf>,
    package_install_root: Option<PathBuf>,
    pub allow_shell: bool,
    pub allow_package_install: bool,
    pub allow_package_lifecycle_scripts: bool,
    pub allow_destructive: bool,
}

impl CommandPolicy {
    /// Creates a deterministic command policy from pinned tools and toolchain roots.
    ///
    /// # Errors
    /// Returns a policy error for invalid pins or roots.
    pub fn new(
        pinned: impl IntoIterator<Item = PinnedExecutable>,
        toolchain_roots: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, PolicyError> {
        let mut pinned_map = BTreeMap::new();
        for executable in pinned {
            executable.verify()?;
            pinned_map.insert(executable.path.clone(), executable);
        }
        let toolchain_roots = toolchain_roots
            .into_iter()
            .map(|path| path.canonicalize().map_err(PolicyError::from))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            pinned: pinned_map,
            toolchain_roots,
            package_install_root: None,
            allow_shell: false,
            allow_package_install: false,
            allow_package_lifecycle_scripts: false,
            allow_destructive: false,
        })
    }

    /// Grants package installation only into one explicit project-local root.
    ///
    /// The root is canonicalized and must already exist. This does not grant lifecycle scripts;
    /// callers must separately opt into those untrusted execution semantics.
    ///
    /// # Errors
    /// Returns an I/O error when the project-local root cannot be canonicalized.
    pub fn allow_project_local_package_install(
        &mut self,
        root: impl AsRef<Path>,
    ) -> Result<(), PolicyError> {
        self.package_install_root = Some(root.as_ref().canonicalize()?);
        self.allow_package_install = true;
        Ok(())
    }

    /// Validates an exact structured command and returns its deterministic risk floor.
    ///
    /// # Errors
    /// Returns a denial for unpinned executables or unauthorized risk classes.
    pub fn authorize(&self, spec: &CommandSpec) -> Result<CommandRisk, PolicyError> {
        if spec.timeout_ms == 0 || spec.output_limit_bytes == 0 || spec.disk_write_limit_bytes == 0
        {
            return Err(PolicyError::Denied(
                "command resource ceilings must be positive".to_owned(),
            ));
        }
        let executable = spec.executable.canonicalize()?;
        if command_requests_keychain_access(&executable, &spec.args) {
            return Err(PolicyError::Denied(
                "generic process_exec cannot invoke macOS Keychain/securityd; use SecretBroker"
                    .to_owned(),
            ));
        }
        let Some(pin) = self.pinned.get(&executable) else {
            return Err(PolicyError::Denied(format!(
                "executable is not digest/version pinned: {}",
                executable.display()
            )));
        };
        pin.verify()?;
        if !self
            .toolchain_roots
            .iter()
            .any(|root| executable.starts_with(root))
        {
            return Err(PolicyError::Denied(format!(
                "executable is outside approved toolchain roots: {}",
                executable.display()
            )));
        }
        let risk = deterministic_risk_floor(spec, &spec.executable);
        if risk == CommandRisk::Shell && !self.allow_shell {
            return Err(PolicyError::Denied(
                "shell execution is not authorized".to_owned(),
            ));
        }
        if risk == CommandRisk::PackageInstall && !self.allow_package_install {
            return Err(PolicyError::Denied(
                "package installation is not authorized".to_owned(),
            ));
        }
        if risk == CommandRisk::PackageInstall {
            self.authorize_package_install(spec)?;
        }
        if risk == CommandRisk::Destructive && !self.allow_destructive {
            return Err(PolicyError::Denied(
                "destructive command is not authorized".to_owned(),
            ));
        }
        if spec.mode == CommandMode::Shell && !self.allow_shell {
            return Err(PolicyError::Denied(
                "shell mode is not authorized".to_owned(),
            ));
        }
        Ok(risk.max(spec.declared_risk))
    }

    fn authorize_package_install(&self, spec: &CommandSpec) -> Result<(), PolicyError> {
        let root = self.package_install_root.as_ref().ok_or_else(|| {
            PolicyError::Denied(
                "package installation requires an explicit project-local install root".to_owned(),
            )
        })?;
        let working_directory = spec.working_directory.canonicalize()?;
        if !working_directory.starts_with(root) {
            return Err(PolicyError::Denied(
                "package installation working directory is outside the explicit project-local root"
                    .to_owned(),
            ));
        }

        let name = spec
            .executable
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !is_recognized_package_manager(name) {
            return Err(PolicyError::Denied(format!(
                "unrecognized package installer cannot inherit package_install authority: {name}"
            )));
        }
        if package_args_request_global_install(name, &spec.args) {
            return Err(PolicyError::Denied(
                "global/system package installation is forbidden".to_owned(),
            ));
        }
        validate_package_target(name, &spec.args, root, &working_directory)?;
        if !self.allow_package_lifecycle_scripts
            && !package_scripts_are_suppressed(name, &spec.args)
        {
            return Err(PolicyError::Denied(
                "package lifecycle/build scripts are denied by default".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn approved_path(&self) -> String {
        self.toolchain_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Returns the verified pin for one exact executable path.
    ///
    /// # Errors
    /// Returns a denial when the executable is not pinned or its digest changed.
    pub fn pinned_executable(&self, path: &Path) -> Result<&PinnedExecutable, PolicyError> {
        let canonical = path.canonicalize()?;
        let pin = self.pinned.get(&canonical).ok_or_else(|| {
            PolicyError::Denied(format!(
                "executable is not digest/version pinned: {}",
                canonical.display()
            ))
        })?;
        pin.verify()?;
        Ok(pin)
    }

    /// Resolves one basename-only program name against the configured executable pins.
    ///
    /// Resolution never consults ambient `PATH`: exactly one configured pin must have the
    /// requested file name. The selected executable is re-hashed before it is returned so a pin
    /// whose bytes changed after [`Self::new`] fails closed.
    ///
    /// # Errors
    /// Returns a denial for path-like input, a missing or ambiguous configured basename, or a pin
    /// whose current executable digest/version provenance no longer verifies.
    pub fn resolve_pinned_program(&self, program: &str) -> Result<&PinnedExecutable, PolicyError> {
        if program.is_empty()
            || program == "."
            || program == ".."
            || program.contains('/')
            || program.contains('\\')
            || program.contains(':')
        {
            return Err(PolicyError::Denied(
                "program resolution requires a basename-only executable name".to_owned(),
            ));
        }

        let mut matches = self.pinned.values().filter(|pin| {
            pin.path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == program)
        });
        let pin = matches.next().ok_or_else(|| {
            PolicyError::Denied(format!(
                "program is not configured as a pinned executable: {program}"
            ))
        })?;
        if matches.next().is_some() {
            return Err(PolicyError::Denied(format!(
                "program basename resolves to multiple configured executable pins: {program}"
            )));
        }
        pin.verify()?;
        Ok(pin)
    }
}

fn command_requests_keychain_access(executable: &Path, args: &[String]) -> bool {
    if executable == Path::new("/usr/bin/security") {
        return true;
    }
    let joined = args.join(" ").to_ascii_lowercase();
    joined.contains("/usr/bin/security")
        || joined.contains("security find-generic-password")
        || joined.contains("security find-internet-password")
        || joined.contains("security dump-keychain")
        || joined.contains("security list-keychains")
        || joined.contains("security unlock-keychain")
        || joined.contains("security export")
}

fn deterministic_risk_floor(spec: &CommandSpec, executable: &Path) -> CommandRisk {
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if spec.mode == CommandMode::Shell || matches!(name, "sh" | "bash" | "zsh" | "fish") {
        return CommandRisk::Shell;
    }
    if is_destructive(name, &spec.args) {
        return CommandRisk::Destructive;
    }
    if is_package_install(name, &spec.args) {
        return CommandRisk::PackageInstall;
    }
    spec.declared_risk
}

fn is_package_install(name: &str, args: &[String]) -> bool {
    match name {
        "npm" | "pnpm" | "yarn" => args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "install" | "add" | "update" | "ci" | "up")),
        "pip" | "pip3" => args.first().is_some_and(|arg| arg == "install"),
        "uv" => args.first().is_some_and(|arg| {
            matches!(arg.as_str(), "add" | "sync" | "install")
                || (arg == "pip" && args.get(1).is_some_and(|next| next == "install"))
        }),
        "cargo" => args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "install" | "add" | "update")),
        "gem" | "brew" => args.first().is_some_and(|arg| arg == "install"),
        _ => false,
    }
}

fn is_recognized_package_manager(name: &str) -> bool {
    matches!(
        name,
        "npm" | "pnpm" | "yarn" | "pip" | "pip3" | "uv" | "cargo" | "gem" | "brew"
    )
}

fn package_args_request_global_install(name: &str, args: &[String]) -> bool {
    if name == "brew" {
        return true;
    }
    args.iter().any(|arg| {
        matches!(arg.as_str(), "-g" | "--global" | "--user" | "--system")
            || arg.eq_ignore_ascii_case("--location=global")
            || arg.starts_with("--global-dir=")
            || arg.starts_with("--globalconfig=")
    })
}

fn validate_package_target(
    name: &str,
    args: &[String],
    root: &Path,
    working_directory: &Path,
) -> Result<(), PolicyError> {
    let (target_flags, required) = match name {
        "npm" | "pnpm" => (Some(["--prefix", "--dir", "-C"].as_slice()), false),
        "yarn" => (Some(["--cwd"].as_slice()), false),
        "pip" | "pip3" => (Some(["--target", "--prefix"].as_slice()), true),
        "uv" if args.first().is_some_and(|arg| arg == "pip") => {
            (Some(["--target", "--prefix"].as_slice()), true)
        }
        "cargo" if args.first().is_some_and(|arg| arg == "install") => {
            (Some(["--root"].as_slice()), true)
        }
        "gem" => (Some(["--install-dir"].as_slice()), true),
        _ => (None, false),
    };
    let Some(flags) = target_flags else {
        return Ok(());
    };
    let Some(target) = package_target_argument(args, flags) else {
        if required {
            return Err(PolicyError::Denied(
                "package manager requires an explicit project-local target".to_owned(),
            ));
        }
        return Ok(());
    };
    let target = canonicalize_future_path(&target, working_directory)?;
    if !target.starts_with(root) {
        return Err(PolicyError::Denied(
            "package manager target escapes the explicit project-local root".to_owned(),
        ));
    }
    Ok(())
}

fn package_target_argument(args: &[String], flags: &[&str]) -> Option<PathBuf> {
    for (index, arg) in args.iter().enumerate() {
        for flag in flags {
            if arg == flag {
                return args.get(index + 1).map(PathBuf::from);
            }
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                return Some(PathBuf::from(value));
            }
        }
    }
    None
}

fn package_scripts_are_suppressed(name: &str, args: &[String]) -> bool {
    match name {
        "npm" | "pnpm" | "yarn" => args.iter().any(|arg| arg == "--ignore-scripts"),
        "pip" | "pip3" => args
            .iter()
            .any(|arg| arg == "--only-binary=:all:" || arg == "--only-binary=all"),
        "uv" if args.first().is_some_and(|arg| arg == "pip") => args
            .iter()
            .any(|arg| arg == "--only-binary=:all:" || arg == "--only-binary=all"),
        "cargo" => args.first().is_none_or(|arg| arg != "install"),
        "gem" | "brew" => false,
        _ => true,
    }
}

fn canonicalize_future_path(path: &Path, working_directory: &Path) -> Result<PathBuf, PolicyError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_directory.join(path)
    };
    let mut cursor = absolute.as_path();
    let mut missing = Vec::new();
    while !cursor.exists() {
        let file_name = cursor.file_name().ok_or_else(|| {
            PolicyError::Denied("package target has no existing ancestor".to_owned())
        })?;
        missing.push(file_name.to_os_string());
        cursor = cursor.parent().ok_or_else(|| {
            PolicyError::Denied("package target has no existing ancestor".to_owned())
        })?;
    }
    let mut canonical = cursor.canonicalize()?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn is_destructive(name: &str, args: &[String]) -> bool {
    if name == "rm"
        && args
            .iter()
            .any(|arg| arg.contains('r') || arg.contains('f'))
    {
        return true;
    }
    if name != "git" {
        return false;
    }
    let joined = args.join(" ");
    joined.contains("reset --hard")
        || joined.contains("clean -fd")
        || joined.contains("clean -df")
        || joined.contains("push --force")
        || joined.contains("push -f")
}

const AMBIENT_DENY_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_ASKPASS",
    "SSH_AUTH_SOCK",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "GIT_PAGER",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "NPM_CONFIG_USERCONFIG",
    "NPM_CONFIG_REGISTRY",
    "YARN_RC_FILENAME",
    "PNPM_HOME",
    "PIP_CONFIG_FILE",
    "PIP_INDEX_URL",
    "PIP_EXTRA_INDEX_URL",
    "UV_INDEX_URL",
    "TWINE_PASSWORD",
    "CARGO_HOME",
    "CARGO_REGISTRIES_CRATES_IO_TOKEN",
    "GEM_HOME",
    "GEM_PATH",
    "GRADLE_USER_HOME",
];

/// Constructs a cleared child environment from explicitly requested entries only.
///
/// # Errors
/// Returns a denial for dangerous ambient-capability variables unless individually authorized.
pub fn sanitized_environment(
    requested: &BTreeMap<String, String>,
    individually_authorized: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, PolicyError> {
    let mut result = BTreeMap::new();
    for (name, value) in requested {
        if name.contains('=') || name.as_bytes().contains(&0) || value.as_bytes().contains(&0) {
            return Err(PolicyError::Denied("invalid environment entry".to_owned()));
        }
        let upper = name.to_ascii_uppercase();
        if upper == "PATH" {
            return Err(PolicyError::Denied(
                "action-supplied PATH is forbidden; Controller constructs toolchain PATH"
                    .to_owned(),
            ));
        }
        let forbidden = AMBIENT_DENY_NAMES.iter().any(|entry| upper == *entry)
            || upper.starts_with("GIT_CONFIG_KEY_")
            || upper.starts_with("GIT_CONFIG_VALUE_")
            || upper.starts_with("GIT_")
            || upper.starts_with("SSH_")
            || upper.starts_with("XDG_")
            || upper.starts_with("LD_")
            || upper.starts_with("DYLD_")
            || upper.starts_with("NPM_CONFIG_")
            || upper.starts_with("YARN_")
            || upper.starts_with("PNPM_")
            || upper.starts_with("PIP_")
            || upper.starts_with("UV_")
            || upper.starts_with("CARGO_")
            || upper.starts_with("BUNDLE_")
            || upper.starts_with("GEM_")
            || upper.starts_with("MAVEN_")
            || upper.starts_with("GRADLE_")
            || upper.ends_with("_TOKEN")
            || upper.ends_with("_PASSWORD")
            || upper.ends_with("_SECRET")
            || upper.starts_with("AWS_")
            || upper.starts_with("GOOGLE_APPLICATION_");
        if forbidden && !individually_authorized.contains(name) {
            return Err(PolicyError::Denied(format!(
                "ambient-capability environment variable requires individual authorization: {name}"
            )));
        }
        result.insert(name.clone(), value.clone());
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitConfigKeyClass {
    Safe,
    HookOrProgram,
    Credential,
    RemoteOrTransport,
    FilterOrDiff,
    IncludeOrAlias,
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct GitPolicy {
    allow_destructive: bool,
    allow_remote_read: bool,
    allow_remote_write: bool,
    allow_helper_execution: bool,
    allow_submodule: bool,
    allow_lfs: bool,
    allow_filter_execution: bool,
}

impl GitPolicy {
    #[must_use]
    pub fn deny_by_default() -> Self {
        Self::default()
    }

    pub fn set_allow_destructive(&mut self, allow: bool) {
        self.allow_destructive = allow;
    }

    pub fn set_allow_remote_read(&mut self, allow: bool) {
        self.allow_remote_read = allow;
    }

    pub fn set_allow_remote_write(&mut self, allow: bool) {
        self.allow_remote_write = allow;
    }

    pub fn set_allow_helper_execution(&mut self, allow: bool) {
        self.allow_helper_execution = allow;
    }

    pub fn set_allow_submodule(&mut self, allow: bool) {
        self.allow_submodule = allow;
    }

    pub fn set_allow_lfs(&mut self, allow: bool) {
        self.allow_lfs = allow;
    }

    pub fn set_allow_filter_execution(&mut self, allow: bool) {
        self.allow_filter_execution = allow;
    }

    /// Classifies a repository-local Git config key by hidden authority surface.
    #[must_use]
    pub fn classify_local_config_key(key: &str) -> GitConfigKeyClass {
        let lower = key.trim().to_ascii_lowercase();
        if lower == "core.hookspath"
            || lower == "core.fsmonitor"
            || lower == "core.editor"
            || lower == "core.pager"
            || lower == "sequence.editor"
            || lower == "gpg.program"
            || lower.starts_with("pager.")
            || lower.starts_with("mergetool.")
            || (lower.starts_with("merge.") && lower.ends_with(".driver"))
        {
            return GitConfigKeyClass::HookOrProgram;
        }
        if lower.starts_with("credential.")
            || lower == "credential.helper"
            || lower == "core.askpass"
        {
            return GitConfigKeyClass::Credential;
        }
        if lower.starts_with("remote.")
            || lower.starts_with("url.")
            || lower.starts_with("http.")
            || lower.starts_with("https.")
            || lower.starts_with("submodule.")
            || lower.starts_with("lfs.")
            || lower == "core.sshcommand"
        {
            return GitConfigKeyClass::RemoteOrTransport;
        }
        if lower.starts_with("filter.")
            || lower == "core.attributesfile"
            || lower == "interactive.difffilter"
            || (lower.starts_with("diff.")
                && (lower.ends_with(".external") || lower.ends_with(".textconv")))
        {
            return GitConfigKeyClass::FilterOrDiff;
        }
        if lower.starts_with("include.")
            || lower.starts_with("includeif.")
            || lower.starts_with("alias.")
        {
            return GitConfigKeyClass::IncludeOrAlias;
        }
        GitConfigKeyClass::Safe
    }

    /// Denies repository-local config keys that can introduce hidden execution, credentials,
    /// helpers, filters, aliases/includes, or remote transport behavior.
    ///
    /// # Errors
    /// Returns a denial for any non-safe config class unless a matching explicit policy switch
    /// permits that governed capability.
    pub fn authorize_local_config_key(&self, key: &str) -> Result<(), PolicyError> {
        let class = Self::classify_local_config_key(key);
        let allowed = match class {
            GitConfigKeyClass::Safe => true,
            GitConfigKeyClass::HookOrProgram | GitConfigKeyClass::IncludeOrAlias => {
                self.allow_helper_execution
            }
            GitConfigKeyClass::Credential => false,
            GitConfigKeyClass::RemoteOrTransport => self.allow_remote_read,
            GitConfigKeyClass::FilterOrDiff => self.allow_filter_execution,
        };
        if allowed {
            Ok(())
        } else {
            Err(PolicyError::Denied(format!(
                "Git config key requires explicit governed capability: {key}"
            )))
        }
    }

    /// Authorizes one normalized Git argument vector under deny-by-default local/remote policy.
    ///
    /// # Errors
    /// Returns a denial for destructive operations, remote access, helper execution, submodule,
    /// LFS, or filter-style execution absent the corresponding explicit policy grant.
    pub fn authorize_args(&self, args: &[String]) -> Result<(), PolicyError> {
        let subcommand = git_subcommand(args)?;
        let destructive = git_args_are_destructive(args);
        if destructive && !self.allow_destructive {
            return Err(PolicyError::Denied(
                "destructive Git operation is denied by default".to_owned(),
            ));
        }
        let remote_write = subcommand == "push";
        let remote_read = matches!(
            subcommand,
            "fetch" | "pull" | "clone" | "ls-remote" | "archive"
        );
        if remote_write && !self.allow_remote_write {
            return Err(PolicyError::Denied(
                "remote Git mutation requires explicit network/external authority".to_owned(),
            ));
        }
        if remote_read && !self.allow_remote_read {
            return Err(PolicyError::Denied(
                "remote Git access requires explicit network authority".to_owned(),
            ));
        }
        if subcommand == "submodule" && !self.allow_submodule {
            return Err(PolicyError::Denied(
                "Git submodule execution requires an explicit governed action".to_owned(),
            ));
        }
        if subcommand == "lfs" && !self.allow_lfs {
            return Err(PolicyError::Denied(
                "Git LFS execution requires an explicit governed action".to_owned(),
            ));
        }
        if matches!(subcommand, "credential" | "difftool" | "mergetool")
            && !self.allow_helper_execution
        {
            return Err(PolicyError::Denied(
                "Git helper execution requires an explicit governed action".to_owned(),
            ));
        }
        if git_args_request_filter_execution(args) && !self.allow_filter_execution {
            return Err(PolicyError::Denied(
                "Git filter/external-diff execution requires an explicit governed action"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

fn git_subcommand(args: &[String]) -> Result<&str, PolicyError> {
    let Some(subcommand) = args.first() else {
        return Err(PolicyError::Denied(
            "Git command is missing a normalized subcommand".to_owned(),
        ));
    };
    if subcommand.starts_with('-') || subcommand.contains('=') {
        return Err(PolicyError::Denied(
            "Git global/config overrides are forbidden; the governed wrapper supplies them"
                .to_owned(),
        ));
    }
    Ok(subcommand)
}

fn git_args_are_destructive(args: &[String]) -> bool {
    let Some(subcommand) = args.first().map(|value| value.to_ascii_lowercase()) else {
        return false;
    };
    let tail = &args[1..];
    (subcommand == "reset" && tail.iter().any(|arg| arg.eq_ignore_ascii_case("--hard")))
        || (subcommand == "clean"
            && tail.iter().any(|arg| {
                let lower = arg.to_ascii_lowercase();
                lower.starts_with('-') && lower.contains('f') && lower.contains('d')
            }))
        || (subcommand == "push"
            && tail.iter().any(|arg| {
                arg.eq_ignore_ascii_case("--force")
                    || arg.eq_ignore_ascii_case("-f")
                    || arg.to_ascii_lowercase().starts_with("--force-with-lease")
            }))
        || (subcommand == "branch"
            && tail
                .iter()
                .any(|arg| matches!(arg.as_str(), "-d" | "-D" | "--delete")))
        || (subcommand == "tag"
            && tail
                .iter()
                .any(|arg| matches!(arg.as_str(), "-d" | "--delete")))
        || subcommand == "rebase"
        || subcommand == "filter-branch"
        || (subcommand == "commit" && tail.iter().any(|arg| arg == "--amend"))
}

fn git_args_request_filter_execution(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let lower = arg.to_ascii_lowercase();
        lower.contains("textconv")
            || lower.contains("ext-diff")
            || lower.contains("filter.")
            || lower.contains("fsmonitor")
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsolationCapability {
    NetworkDeny,
    ProtectedHomeReadDeny,
    RepositoryWriteJail,
    FullFilesystemReadJail,
    SecretProviderDeny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationCapabilities {
    supported: BTreeSet<IsolationCapability>,
}

impl IsolationCapabilities {
    #[must_use]
    pub fn supports(&self, capability: IsolationCapability) -> bool {
        self.supported.contains(&capability)
    }
}

#[derive(Debug, Clone)]
pub struct IsolationRequest {
    pub repository_root: PathBuf,
    pub user_home_root: PathBuf,
    pub extra_protected_read_roots: Vec<PathBuf>,
    pub network_offline: bool,
    pub allow_repository_write: bool,
    pub require_full_filesystem_read_jail: bool,
}

impl IsolationRequest {
    /// Computes a canonical digest of the exact enforceable isolation request.
    ///
    /// # Errors
    /// Returns an I/O/policy error when roots cannot be canonicalized.
    pub fn digest(&self) -> Result<String, PolicyError> {
        let repo = self.repository_root.canonicalize()?;
        let home = self.user_home_root.canonicalize()?;
        let mut protected = self
            .extra_protected_read_roots
            .iter()
            .map(|root| canonicalize_existing_or_parent(root))
            .collect::<Result<Vec<_>, _>>()?;
        protected.sort();
        let mut hasher = Sha256::new();
        digest_policy_field(&mut hasher, &repo.display().to_string());
        digest_policy_field(&mut hasher, &home.display().to_string());
        for root in protected {
            digest_policy_field(&mut hasher, &root.display().to_string());
        }
        hasher.update([u8::from(self.network_offline)]);
        hasher.update([u8::from(self.allow_repository_write)]);
        hasher.update([u8::from(self.require_full_filesystem_read_jail)]);
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

fn digest_policy_field(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedCommand {
    pub executable: PathBuf,
    pub args: Vec<String>,
}

pub trait ExecutionIsolationBackend {
    fn capabilities(&self) -> IsolationCapabilities;
    /// Wraps a structured command in an enforceable local isolation boundary.
    ///
    /// # Errors
    /// Returns fail-closed when the requested boundary is stronger than host capability.
    fn isolate(
        &self,
        spec: &CommandSpec,
        request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError>;
}

#[derive(Debug, Clone)]
pub struct MacSandboxExecBackend {
    sandbox_exec: PathBuf,
}

impl MacSandboxExecBackend {
    /// Detects the macOS Seatbelt command used by the minimum M1 backend.
    ///
    /// # Errors
    /// Returns fail-closed when `sandbox-exec` is unavailable.
    pub fn detect() -> Result<Self, PolicyError> {
        let path = PathBuf::from("/usr/bin/sandbox-exec");
        if !path.is_file() {
            return Err(PolicyError::IsolationUnavailable(
                "macOS sandbox-exec is unavailable".to_owned(),
            ));
        }
        let backend = Self { sandbox_exec: path };
        backend.self_test()?;
        Ok(backend)
    }

    #[must_use]
    pub fn sandbox_exec_path(&self) -> &Path {
        &self.sandbox_exec
    }

    fn self_test(&self) -> Result<(), PolicyError> {
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| PolicyError::IsolationUnavailable(error.to_string()))?
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("sovereign-seatbelt-selftest-{nonce}"));
        fs::create_dir_all(&root)?;
        let root = root.canonicalize()?;
        let secret = root.join("secret");
        let writable = root.join("writable");
        fs::create_dir_all(&writable)?;
        fs::write(&secret, b"secret")?;
        let profile = format!(
            "(version 1)(allow default)(deny file-read* (subpath {}))(deny network*)",
            seatbelt_string(&root)
        );
        let denied_read = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &profile, "/bin/cat"])
            .arg(&secret)
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let network_probe = format!(
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.2); s.connect(('127.0.0.1', {}))",
            address.port()
        );
        let denied_network = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &profile, "/usr/bin/python3", "-c", &network_probe])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let secret_provider_support_profile = format!(
            "(version 1)(allow default){}",
            secret_provider_mach_lookup_rules()
        );
        let secret_provider_rules_supported = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &secret_provider_support_profile, "/usr/bin/true"])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let process_exec_deny_profile = format!(
            "(version 1)(allow default)(deny process-exec (literal {})){}",
            seatbelt_string(Path::new("/usr/bin/true")),
            secret_provider_mach_lookup_rules()
        );
        let process_exec_denied = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &process_exec_deny_profile, "/usr/bin/true"])
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let write_profile = format!(
            "(version 1)(allow default)(deny file-write* (subpath \"/\"))(allow file-write* (subpath {}))",
            seatbelt_string(&writable)
        );
        let inside_write = writable.join("inside");
        let outside_write = root.join("outside");
        let allowed_write = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &write_profile, "/bin/sh", "-c"])
            .arg(format!("printf ok > '{}'", inside_write.display()))
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        let denied_write = std::process::Command::new(&self.sandbox_exec)
            .args(["-p", &write_profile, "/bin/sh", "-c"])
            .arg(format!("printf no > '{}'", outside_write.display()))
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        drop(listener);
        let _ = fs::remove_dir_all(&root);
        if denied_read.success()
            || denied_network.success()
            || !secret_provider_rules_supported.success()
            || process_exec_denied.success()
            || !allowed_write.success()
            || denied_write.success()
        {
            return Err(PolicyError::IsolationUnavailable(
                "sandbox-exec runtime self-test did not enforce required read/network/secret-provider denial"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl ExecutionIsolationBackend for MacSandboxExecBackend {
    fn capabilities(&self) -> IsolationCapabilities {
        IsolationCapabilities {
            supported: BTreeSet::from([
                IsolationCapability::NetworkDeny,
                IsolationCapability::ProtectedHomeReadDeny,
                IsolationCapability::RepositoryWriteJail,
                IsolationCapability::SecretProviderDeny,
            ]),
        }
    }

    fn isolate(
        &self,
        spec: &CommandSpec,
        request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        if request.require_full_filesystem_read_jail {
            return Err(PolicyError::IsolationUnavailable(
                "host Seatbelt profile cannot truthfully prove a complete read namespace jail"
                    .to_owned(),
            ));
        }
        if !request.network_offline {
            return Err(PolicyError::IsolationUnavailable(
                "M1 macOS isolation can prove offline execution only; selective network scopes are unavailable"
                    .to_owned(),
            ));
        }
        let repo = request.repository_root.canonicalize()?;
        let home = request.user_home_root.canonicalize()?;
        if !repo.starts_with(&home) {
            return Err(PolicyError::IsolationUnavailable(
                "M1 Seatbelt profile requires repository under the declared user home so home can be denied then repo re-allowed"
                    .to_owned(),
            ));
        }
        let mut profile = String::from("(version 1)(allow default)");
        write!(
            &mut profile,
            "(deny file-read* (subpath {}))(allow file-read* (subpath {}))",
            seatbelt_string(&home),
            seatbelt_string(&repo)
        )
        .map_err(|_| PolicyError::Denied("failed to build isolation profile".to_owned()))?;
        profile.push_str("(deny file-write* (subpath \"/\"))");
        if request.allow_repository_write {
            write!(
                &mut profile,
                "(allow file-write* (subpath {}))",
                seatbelt_string(&repo)
            )
            .map_err(|_| PolicyError::Denied("failed to build isolation profile".to_owned()))?;
        }
        for root in &request.extra_protected_read_roots {
            let root = canonicalize_existing_or_parent(root)?;
            write!(
                &mut profile,
                "(deny file-read* (subpath {}))",
                seatbelt_string(&root)
            )
            .map_err(|_| PolicyError::Denied("failed to build isolation profile".to_owned()))?;
        }
        profile.push_str("(deny process-exec (literal \"/usr/bin/security\"))");
        profile.push_str(secret_provider_mach_lookup_rules());
        profile.push_str("(deny network*)");
        if spec.subprocess_limit == 0 {
            profile.push_str("(deny process-fork)");
        }
        let mut args = vec![
            "-p".to_owned(),
            profile,
            spec.executable.display().to_string(),
        ];
        args.extend(spec.args.clone());
        Ok(IsolatedCommand {
            executable: self.sandbox_exec.clone(),
            args,
        })
    }
}

fn secret_provider_mach_lookup_rules() -> &'static str {
    "(deny mach-lookup (global-name \"com.apple.securityd\"))(deny mach-lookup (global-name \"com.apple.securityd.xpc\"))(deny mach-lookup (global-name \"com.apple.securityd.system\"))"
}

fn seatbelt_string(path: &Path) -> String {
    let value = path
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{value}\"")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPressureSnapshot {
    pub controlled_working_set_mib: u64,
    pub host_headroom_mib: u64,
    pub swap_out_growth_mib_per_min: u64,
    pub compressor_growth_mib_per_min: u64,
    pub os_pressure_warning: bool,
    pub recent_pressure_event: bool,
    pub thermal_serious: bool,
}

impl HostPressureSnapshot {
    #[must_use]
    pub const fn classify(self) -> PressureBand {
        if self.os_pressure_warning
            || self.thermal_serious
            || self.swap_out_growth_mib_per_min > 256
            || self.compressor_growth_mib_per_min > 256
            || self.controlled_working_set_mib > 5_376
            || self.host_headroom_mib < 1_280
        {
            PressureBand::Constrained
        } else if self.recent_pressure_event
            || self.swap_out_growth_mib_per_min >= 64
            || self.compressor_growth_mib_per_min >= 64
            || self.controlled_working_set_mib >= 4_864
            || self.host_headroom_mib < 1_536
        {
            PressureBand::Guarded
        } else {
            PressureBand::Green
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLease {
    pub lease_id: String,
    pub class: HeavyLeaseClass,
}

#[derive(Debug, Default)]
pub struct MinimalResourceLeaseAuthority {
    active: BTreeMap<String, HeavyLeaseClass>,
}

impl MinimalResourceLeaseAuthority {
    /// Acquires one heavy-capability lease under the M1 exclusion matrix.
    ///
    /// # Errors
    /// Returns a resource denial when the lease conflicts or duplicates an active lease.
    pub fn acquire(
        &mut self,
        lease_id: impl Into<String>,
        class: HeavyLeaseClass,
    ) -> Result<ResourceLease, PolicyError> {
        let lease_id = lease_id.into();
        if lease_id.is_empty() || self.active.contains_key(&lease_id) {
            return Err(PolicyError::ResourceDenied(
                "lease id is empty or already active".to_owned(),
            ));
        }
        let conflict = self.active.values().any(|active| {
            *active == class
                || matches!(
                    (*active, class),
                    (HeavyLeaseClass::Model, HeavyLeaseClass::BuildHeavy)
                        | (HeavyLeaseClass::BuildHeavy, HeavyLeaseClass::Model)
                )
        });
        if conflict {
            return Err(PolicyError::ResourceDenied(format!(
                "baseline M1 profile forbids overlapping heavy lease {class:?}"
            )));
        }
        self.active.insert(lease_id.clone(), class);
        Ok(ResourceLease { lease_id, class })
    }

    /// Releases one exact active heavy-capability lease.
    ///
    /// # Errors
    /// Returns a resource denial for unknown or mismatched leases.
    pub fn release(&mut self, lease: &ResourceLease) -> Result<(), PolicyError> {
        match self.active.remove(&lease.lease_id) {
            Some(class) if class == lease.class => Ok(()),
            Some(class) => {
                self.active.insert(lease.lease_id.clone(), class);
                Err(PolicyError::ResourceDenied(
                    "lease class mismatch".to_owned(),
                ))
            }
            None => Err(PolicyError::ResourceDenied(
                "lease is not active".to_owned(),
            )),
        }
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }
}

pub trait ResourceGovernor {
    /// Admits one heavy lease only when both the exclusion matrix and live pressure permit it.
    ///
    /// # Errors
    /// Returns a resource denial when pressure or lease conflicts require serialization/deferral.
    fn acquire(
        &mut self,
        lease_id: String,
        class: HeavyLeaseClass,
        pressure: HostPressureSnapshot,
    ) -> Result<ResourceLease, PolicyError>;

    /// Releases one exact heavy lease.
    ///
    /// # Errors
    /// Returns a resource denial for an unknown or mismatched lease.
    fn release(&mut self, lease: &ResourceLease) -> Result<(), PolicyError>;
}

#[derive(Debug, Default)]
pub struct M1ResourceGovernor {
    leases: MinimalResourceLeaseAuthority,
}

impl ResourceGovernor for M1ResourceGovernor {
    fn acquire(
        &mut self,
        lease_id: String,
        class: HeavyLeaseClass,
        pressure: HostPressureSnapshot,
    ) -> Result<ResourceLease, PolicyError> {
        if pressure.classify() == PressureBand::Constrained {
            return Err(PolicyError::ResourceDenied(
                "live host pressure forbids a new heavy lease".to_owned(),
            ));
        }
        self.leases.acquire(lease_id, class)
    }

    fn release(&mut self, lease: &ResourceLease) -> Result<(), PolicyError> {
        self.leases.release(lease)
    }
}

/// Controller-owned outer budget for model provider calls. Provider code cannot refill it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelCallBudget {
    remaining_calls: u32,
    max_call_ms: u64,
}

impl ModelCallBudget {
    #[must_use]
    pub const fn new(remaining_calls: u32, max_call_ms: u64) -> Self {
        Self {
            remaining_calls,
            max_call_ms,
        }
    }

    /// Consumes one outer call budget unit before dispatch and validates the deadline.
    ///
    /// # Errors
    /// Returns a resource denial when the outer counter is exhausted or the requested
    /// provider deadline exceeds the Controller ceiling.
    pub fn consume_call(&mut self, requested_deadline_ms: u64) -> Result<(), PolicyError> {
        if self.remaining_calls == 0 {
            return Err(PolicyError::ResourceDenied(
                "model call budget exhausted".to_owned(),
            ));
        }
        if requested_deadline_ms == 0 || requested_deadline_ms > self.max_call_ms {
            return Err(PolicyError::ResourceDenied(format!(
                "model call deadline {requested_deadline_ms} exceeds outer ceiling {}",
                self.max_call_ms
            )));
        }
        self.remaining_calls -= 1;
        Ok(())
    }

    #[must_use]
    pub const fn remaining_calls(self) -> u32 {
        self.remaining_calls
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointIntegrityFloor {
    pub latest_valid_checkpoint_action_sequence: i64,
    pub authoritative_action_sequence: i64,
}

impl CheckpointIntegrityFloor {
    /// Requires the checkpoint floor to bind the exact authoritative journal sequence.
    ///
    /// # Errors
    /// Returns a denial when checkpoint and journal sequences differ.
    pub fn admit_mutation(self) -> Result<(), PolicyError> {
        if self.latest_valid_checkpoint_action_sequence != self.authoritative_action_sequence {
            return Err(PolicyError::Denied(format!(
                "checkpoint/action-journal sequence mismatch: checkpoint={}, journal={}",
                self.latest_valid_checkpoint_action_sequence, self.authoritative_action_sequence
            )));
        }
        Ok(())
    }
}
