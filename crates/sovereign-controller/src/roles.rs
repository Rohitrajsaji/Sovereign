use super::{ControllerError, PermissionContext, sha256_prefixed};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sovereign_context::{ContextPacket, EvidenceKind};
use sovereign_model::{
    MODEL_SCHEMA_VERSION, ModelBackend, ModelFinishReason, ModelMessage, ModelMessageRole,
    ModelOutputContract, ModelRequest,
};
use sovereign_tools::PermissionClass;
use std::collections::{BTreeMap, BTreeSet};

pub const ROLE_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const ROLE_OUTPUT_SCHEMA_VERSION: u32 = 1;
const ROLE_OUTPUT_TOKEN_CEILING: u32 = 512;
const MAX_ROLE_FINDINGS: usize = 32;
const MAX_ROLE_EVIDENCE_IDS: usize = 64;

/// Stable logical role identity. Roles are profiles over one model backend, not
/// additional model processes or capability grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleId {
    Explorer,
    Planner,
    Implementer,
    Debugger,
    Reviewer,
    SecurityReviewer,
    Verifier,
}

/// Serializable tool-class ceiling used by [`RoleProfile`]. The Controller
/// intersects this ceiling with its existing permission context before use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleToolClass {
    ProcessExec,
    RepositoryWrite,
    PackageInstall,
    NetworkRead,
    NetworkWrite,
    Destructive,
    ExternalSideEffect,
}

impl From<RoleToolClass> for PermissionClass {
    fn from(value: RoleToolClass) -> Self {
        match value {
            RoleToolClass::ProcessExec => Self::ProcessExec,
            RoleToolClass::RepositoryWrite => Self::RepositoryWrite,
            RoleToolClass::PackageInstall => Self::PackageInstall,
            RoleToolClass::NetworkRead => Self::NetworkRead,
            RoleToolClass::NetworkWrite => Self::NetworkWrite,
            RoleToolClass::Destructive => Self::Destructive,
            RoleToolClass::ExternalSideEffect => Self::ExternalSideEffect,
        }
    }
}

/// Typed advisory result produced by a logical role. No disposition in this
/// contract authorizes execution, grants permissions, or marks a task complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleDisposition {
    Proposed,
    Approve,
    ChangesRequired,
    Pass,
    Fail,
    Inconclusive,
}

/// Canonical `RoleProfile` v1. It deliberately contains no credentials, grants,
/// task-state transition authority, or completion authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleProfile {
    pub schema_version: u32,
    pub role: RoleId,
    pub reasoning_objective: String,
    pub default_evidence_types: BTreeSet<EvidenceKind>,
    pub allowed_tool_classes_ceiling: BTreeSet<RoleToolClass>,
    pub output_schema: String,
    pub allowed_dispositions: BTreeSet<RoleDisposition>,
    pub completion_contract: String,
}

impl RoleProfile {
    /// Returns the deterministic digest of the canonical serialized profile.
    ///
    /// # Errors
    /// Returns a JSON error if serialization of the typed profile fails.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        serde_json::to_vec(self).map(|bytes| sha256_prefixed(&bytes))
    }

    fn validate(&self) -> Result<(), ControllerError> {
        if self.schema_version != ROLE_PROFILE_SCHEMA_VERSION
            || self.reasoning_objective.trim().is_empty()
            || self.output_schema != "RoleOutputV1"
            || self.allowed_dispositions.is_empty()
            || self.completion_contract.trim().is_empty()
        {
            return Err(ControllerError::InvalidPlan(format!(
                "invalid canonical role profile for {:?}",
                self.role
            )));
        }
        Ok(())
    }
}

/// Typed advisory role output v1. Evidence IDs are references only; the
/// Controller remains responsible for validating any evidence before authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOutputV1 {
    pub schema_version: u32,
    pub role: RoleId,
    pub disposition: RoleDisposition,
    pub summary: String,
    pub findings: Vec<String>,
    pub evidence_ids: Vec<String>,
}

/// Small canonical logical-role registry. It is immutable and owns no model,
/// credentials, permission grants, or execution state.
#[derive(Debug, Clone)]
pub struct RoleRegistry {
    profiles: BTreeMap<RoleId, RoleProfile>,
}

impl Default for RoleRegistry {
    fn default() -> Self {
        Self::canonical()
    }
}

impl RoleRegistry {
    #[must_use]
    pub fn canonical() -> Self {
        let profiles = [
            explorer_profile(),
            planner_profile(),
            implementer_profile(),
            debugger_profile(),
            reviewer_profile(),
            security_reviewer_profile(),
            verifier_profile(),
        ]
        .into_iter()
        .map(|profile| (profile.role, profile))
        .collect();
        Self { profiles }
    }

    #[must_use]
    pub fn profile(&self, role: RoleId) -> &RoleProfile {
        self.profiles
            .get(&role)
            .unwrap_or_else(|| unreachable!("canonical role registry is complete"))
    }

    /// Produces a deterministic role -> profile digest manifest suitable for
    /// evidence without exposing credentials or grants (neither exists here).
    ///
    /// # Errors
    /// Returns a JSON error if profile serialization fails.
    pub fn digest_manifest(&self) -> Result<BTreeMap<RoleId, String>, serde_json::Error> {
        self.profiles
            .iter()
            .map(|(role, profile)| profile.digest().map(|digest| (*role, digest)))
            .collect()
    }

    /// Runs one logical role over an already-loaded model backend. Calls are
    /// serial and reuse the supplied physical backend; this method never loads,
    /// unloads, clones, or otherwise acquires a second model residency lease.
    /// The returned output is advisory and cannot mutate Controller state.
    ///
    /// # Errors
    /// Returns a Controller/model/JSON error for invalid profiles, provider
    /// failures, malformed structured output, or output/profile mismatches.
    pub fn invoke(
        &self,
        role: RoleId,
        backend: &dyn ModelBackend,
        context: &ContextPacket,
        request_id: &str,
        deadline_ms: u64,
    ) -> Result<RoleOutputV1, ControllerError> {
        let profile = self.profile(role);
        profile.validate()?;
        if request_id.trim().is_empty() || deadline_ms == 0 {
            return Err(ControllerError::ProposalRejected(
                "role invocation requires request id and deadline".to_owned(),
            ));
        }
        let request = ModelRequest {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: request_id.to_owned(),
            messages: vec![
                ModelMessage {
                    role: ModelMessageRole::System,
                    content: role_system_message(profile),
                    tool_call_id: None,
                },
                ModelMessage {
                    role: ModelMessageRole::User,
                    content: context.serialized_input.clone(),
                    tool_call_id: None,
                },
            ],
            tools: Vec::new(),
            output_contract: ModelOutputContract::JsonSchema {
                name: "RoleOutputV1".to_owned(),
                schema: role_output_schema(),
            },
            input_token_ceiling: context.budget.max_input_tokens,
            max_output_tokens: ROLE_OUTPUT_TOKEN_CEILING,
            deadline_ms,
            temperature_milli: 0,
        };
        let response = backend.complete(&request)?;
        if response.finish_reason != ModelFinishReason::Stop || !response.tool_calls.is_empty() {
            return Err(ControllerError::ProposalRejected(
                "role output must finish normally without model tool calls".to_owned(),
            ));
        }
        let output: RoleOutputV1 = serde_json::from_str(&response.content)?;
        validate_role_output(profile, &output)?;
        Ok(output)
    }
}

impl PermissionContext {
    /// Applies a role as an additional ceiling. It can only remove permissions
    /// from the pre-existing Controller/project/grant intersection; it cannot
    /// manufacture a permission that was absent from the current role ceiling.
    #[must_use]
    pub fn narrow_for_role(&self, profile: &RoleProfile) -> Self {
        let profile_ceiling = profile
            .allowed_tool_classes_ceiling
            .iter()
            .copied()
            .map(PermissionClass::from)
            .collect::<BTreeSet<_>>();
        let role_ceiling = self
            .role_ceiling
            .intersection(&profile_ceiling)
            .copied()
            .collect();
        Self {
            controller_ceiling: self.controller_ceiling.clone(),
            project_ceiling: self.project_ceiling.clone(),
            role_ceiling,
            persisted_grants: self.persisted_grants.clone(),
        }
    }
}

fn explorer_profile() -> RoleProfile {
    RoleProfile {
        schema_version: ROLE_PROFILE_SCHEMA_VERSION,
        role: RoleId::Explorer,
        reasoning_objective:
            "Inspect bounded repository evidence and report the smallest relevant scope without mutation authority."
                .to_owned(),
        default_evidence_types: BTreeSet::from([
            EvidenceKind::TaskContract,
            EvidenceKind::SourceSlice,
            EvidenceKind::SearchHit,
            EvidenceKind::Instruction,
            EvidenceKind::ToolSchema,
        ]),
        allowed_tool_classes_ceiling: BTreeSet::from([RoleToolClass::ProcessExec]),
        output_schema: "RoleOutputV1".to_owned(),
        allowed_dispositions: BTreeSet::from([
            RoleDisposition::Proposed,
            RoleDisposition::Inconclusive,
        ]),
        completion_contract:
            "Return an advisory evidence map or scope proposal; do not authorize mutation or completion."
                .to_owned(),
    }
}

fn planner_profile() -> RoleProfile {
    RoleProfile {
        schema_version: ROLE_PROFILE_SCHEMA_VERSION,
        role: RoleId::Planner,
        reasoning_objective: "Propose the smallest evidence-backed plan shape without execution authority."
            .to_owned(),
        default_evidence_types: BTreeSet::from([
            EvidenceKind::TaskContract,
            EvidenceKind::SourceSlice,
            EvidenceKind::SearchHit,
            EvidenceKind::Instruction,
        ]),
        allowed_tool_classes_ceiling: BTreeSet::new(),
        output_schema: "RoleOutputV1".to_owned(),
        allowed_dispositions: BTreeSet::from([
            RoleDisposition::Proposed,
            RoleDisposition::Inconclusive,
        ]),
        completion_contract:
            "Return an advisory proposal grounded in cited evidence; do not claim execution or task completion."
                .to_owned(),
    }
}

fn implementer_profile() -> RoleProfile {
    RoleProfile {
        schema_version: ROLE_PROFILE_SCHEMA_VERSION,
        role: RoleId::Implementer,
        reasoning_objective:
            "Propose the smallest implementation consistent with the active task contract and supplied evidence."
                .to_owned(),
        default_evidence_types: BTreeSet::from([
            EvidenceKind::TaskContract,
            EvidenceKind::SourceSlice,
            EvidenceKind::SearchHit,
            EvidenceKind::Instruction,
            EvidenceKind::ToolSchema,
        ]),
        allowed_tool_classes_ceiling: BTreeSet::from([
            RoleToolClass::ProcessExec,
            RoleToolClass::RepositoryWrite,
        ]),
        output_schema: "RoleOutputV1".to_owned(),
        allowed_dispositions: BTreeSet::from([
            RoleDisposition::Proposed,
            RoleDisposition::Inconclusive,
        ]),
        completion_contract:
            "Return an advisory implementation assessment; Controller policy owns all mutation and completion authority."
                .to_owned(),
    }
}

fn debugger_profile() -> RoleProfile {
    RoleProfile {
        schema_version: ROLE_PROFILE_SCHEMA_VERSION,
        role: RoleId::Debugger,
        reasoning_objective:
            "Diagnose the current bounded failure and propose the smallest evidence-backed repair without execution authority."
                .to_owned(),
        default_evidence_types: BTreeSet::from([
            EvidenceKind::TaskContract,
            EvidenceKind::Diff,
            EvidenceKind::SourceSlice,
            EvidenceKind::SearchHit,
            EvidenceKind::Instruction,
            EvidenceKind::FailureSynopsis,
            EvidenceKind::Verification,
            EvidenceKind::ToolSchema,
        ]),
        allowed_tool_classes_ceiling: BTreeSet::from([
            RoleToolClass::ProcessExec,
            RoleToolClass::RepositoryWrite,
        ]),
        output_schema: "RoleOutputV1".to_owned(),
        allowed_dispositions: BTreeSet::from([
            RoleDisposition::Proposed,
            RoleDisposition::Inconclusive,
        ]),
        completion_contract:
            "Return an advisory repair diagnosis grounded in current failure evidence; Controller owns repair execution and completion."
                .to_owned(),
    }
}

fn reviewer_profile() -> RoleProfile {
    RoleProfile {
        schema_version: ROLE_PROFILE_SCHEMA_VERSION,
        role: RoleId::Reviewer,
        reasoning_objective:
            "Independently review the contract, final diff, current source evidence, and verification results without implementer trajectory."
                .to_owned(),
        default_evidence_types: BTreeSet::from([
            EvidenceKind::Diff,
            EvidenceKind::SourceSlice,
            EvidenceKind::SearchHit,
            EvidenceKind::Instruction,
            EvidenceKind::Verification,
            EvidenceKind::ToolSchema,
        ]),
        allowed_tool_classes_ceiling: BTreeSet::from([RoleToolClass::ProcessExec]),
        output_schema: "RoleOutputV1".to_owned(),
        allowed_dispositions: BTreeSet::from([
            RoleDisposition::Approve,
            RoleDisposition::ChangesRequired,
            RoleDisposition::Inconclusive,
        ]),
        completion_contract:
            "Return an independent advisory review with evidence IDs; approval is not Controller completion authority."
                .to_owned(),
    }
}

fn security_reviewer_profile() -> RoleProfile {
    RoleProfile {
        schema_version: ROLE_PROFILE_SCHEMA_VERSION,
        role: RoleId::SecurityReviewer,
        reasoning_objective:
            "Independently review the acceptance contract, final diff, affected source, verification, and supplied security evidence without implementer trajectory."
                .to_owned(),
        default_evidence_types: BTreeSet::from([
            EvidenceKind::Diff,
            EvidenceKind::SourceSlice,
            EvidenceKind::SearchHit,
            EvidenceKind::Instruction,
            EvidenceKind::Verification,
            EvidenceKind::ToolSchema,
        ]),
        allowed_tool_classes_ceiling: BTreeSet::from([RoleToolClass::ProcessExec]),
        output_schema: "RoleOutputV1".to_owned(),
        allowed_dispositions: BTreeSet::from([
            RoleDisposition::Approve,
            RoleDisposition::ChangesRequired,
            RoleDisposition::Inconclusive,
        ]),
        completion_contract:
            "Return an independent advisory security review with evidence IDs; it cannot grant permission or completion authority."
                .to_owned(),
    }
}

fn verifier_profile() -> RoleProfile {
    RoleProfile {
        schema_version: ROLE_PROFILE_SCHEMA_VERSION,
        role: RoleId::Verifier,
        reasoning_objective:
            "Assess deterministic verification evidence against the active acceptance contract without granting completion."
                .to_owned(),
        default_evidence_types: BTreeSet::from([
            EvidenceKind::TaskContract,
            EvidenceKind::Diff,
            EvidenceKind::SourceSlice,
            EvidenceKind::Verification,
            EvidenceKind::ToolSchema,
        ]),
        allowed_tool_classes_ceiling: BTreeSet::from([RoleToolClass::ProcessExec]),
        output_schema: "RoleOutputV1".to_owned(),
        allowed_dispositions: BTreeSet::from([
            RoleDisposition::Pass,
            RoleDisposition::Fail,
            RoleDisposition::Inconclusive,
        ]),
        completion_contract:
            "Return an advisory verification assessment; only Controller-owned deterministic verification may mark success."
                .to_owned(),
    }
}

fn role_system_message(profile: &RoleProfile) -> String {
    format!(
        "Logical role: {:?}\nObjective: {}\nCompletion contract: {}\nReturn only RoleOutputV1 JSON. The role is advisory: never claim permission grants, action authorization, or Controller task completion.",
        profile.role, profile.reasoning_objective, profile.completion_contract
    )
}

fn validate_role_output(
    profile: &RoleProfile,
    output: &RoleOutputV1,
) -> Result<(), ControllerError> {
    if output.schema_version != ROLE_OUTPUT_SCHEMA_VERSION
        || output.role != profile.role
        || !profile.allowed_dispositions.contains(&output.disposition)
        || output.summary.trim().is_empty()
        || output.findings.len() > MAX_ROLE_FINDINGS
        || output.evidence_ids.len() > MAX_ROLE_EVIDENCE_IDS
        || output.evidence_ids.iter().any(|id| id.trim().is_empty())
    {
        return Err(ControllerError::ProposalRejected(format!(
            "role output violates {:?} profile contract",
            profile.role
        )));
    }
    Ok(())
}

fn role_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "role", "disposition", "summary", "findings", "evidence_ids"],
        "properties": {
            "schema_version": {"type": "integer", "const": ROLE_OUTPUT_SCHEMA_VERSION},
            "role": {"type": "string", "enum": ["explorer", "planner", "implementer", "debugger", "reviewer", "security_reviewer", "verifier"]},
            "disposition": {"type": "string", "enum": ["proposed", "approve", "changes_required", "pass", "fail", "inconclusive"]},
            "summary": {"type": "string", "minLength": 1},
            "findings": {"type": "array", "maxItems": MAX_ROLE_FINDINGS, "items": {"type": "string"}},
            "evidence_ids": {"type": "array", "maxItems": MAX_ROLE_EVIDENCE_IDS, "items": {"type": "string", "minLength": 1}}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sovereign_context::{
        ContextBudget, ContextLevel, ContextMode, ContextPacketInput, ContextPlanner, EvidenceItem,
        PacketSection, TrustClass,
    };
    use sovereign_model::{
        DeterministicFakeBackend, ModelCapabilities, ModelLoadProfile, ModelResponse, ModelUsage,
    };

    fn role_response(role: &str, disposition: &str, summary: &str) -> ModelResponse {
        ModelResponse {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: "template".to_owned(),
            content: serde_json::to_string(&json!({
                "schema_version": ROLE_OUTPUT_SCHEMA_VERSION,
                "role": role,
                "disposition": disposition,
                "summary": summary,
                "findings": [],
                "evidence_ids": ["final-diff"]
            }))
            .unwrap_or_else(|error| panic!("role response JSON: {error}")),
            structured: None,
            tool_calls: Vec::new(),
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage {
                input_tokens: 64,
                output_tokens: 32,
            },
            elapsed_ms: 1,
            peak_rss_kb_during_call: None,
        }
    }

    fn loaded_backend(responses: Vec<ModelResponse>) -> DeterministicFakeBackend {
        let backend = DeterministicFakeBackend::new(
            ModelCapabilities {
                schema_version: MODEL_SCHEMA_VERSION,
                model_id: "roles-one-physical-model".to_owned(),
                parameter_class: "fixture".to_owned(),
                quantization: "fixture".to_owned(),
                max_context_tokens: 16_384,
                supports_tools: false,
                supports_json_schema: true,
                local: true,
            },
            responses,
        )
        .unwrap_or_else(|error| panic!("fake backend: {error}"));
        backend
            .load(ModelLoadProfile {
                context_tokens: 8_000,
                output_reserve_tokens: 1_024,
                startup_timeout_ms: 1_000,
                provider_call_timeout_ms: 1_000,
            })
            .unwrap_or_else(|error| panic!("load fake backend once: {error}"));
        backend
    }

    fn budget() -> ContextBudget {
        ContextBudget {
            max_input_tokens: 2_000,
            c0_tokens: 600,
            tool_schema_tokens: 200,
            c1_tokens: 600,
            routed_expansion_tokens: 200,
            tool_failure_tokens: 100,
            serialization_reserve_tokens: 300,
        }
    }

    fn evidence(id: &str, kind: EvidenceKind, text: &str) -> EvidenceItem {
        EvidenceItem::new(
            id,
            PacketSection::DirectEvidence,
            ContextLevel::C1,
            kind,
            format!("fixture://{id}"),
            format!("sha256:source-{id}"),
            "roles fixture",
            TrustClass::Repository,
            "roles fixture",
            text,
        )
    }

    fn input(candidates: Vec<EvidenceItem>) -> ContextPacketInput {
        ContextPacketInput {
            controller_prefix: "Controller remains the only authority.".to_owned(),
            task_contract: "review the exact task contract".to_owned(),
            current_state: "attempt verified; no unknown actions".to_owned(),
            candidates,
            output_schema: "RoleOutputV1".to_owned(),
        }
    }

    #[test]
    fn roles_same_model_serial_switching_uses_one_loaded_backend() {
        let registry = RoleRegistry::canonical();
        let planner = ContextPlanner::default();
        let implementer_context = planner
            .build(ContextMode::Implementation, budget(), input(Vec::new()))
            .unwrap_or_else(|error| panic!("implementer context: {error}"));
        let reviewer_context = planner
            .build_reviewer(
                budget(),
                input(vec![
                    evidence("final-diff", EvidenceKind::Diff, "+ exact change"),
                    evidence(
                        "verification",
                        EvidenceKind::Verification,
                        "focused verification passed",
                    ),
                    evidence(
                        "hidden-trajectory",
                        EvidenceKind::HiddenReasoning,
                        "implementer private trajectory",
                    ),
                ]),
            )
            .unwrap_or_else(|error| panic!("reviewer context: {error}"));
        let backend = loaded_backend(vec![
            role_response("implementer", "proposed", "implementation proposal"),
            role_response("reviewer", "approve", "independent review"),
        ]);

        let implementer = registry
            .invoke(
                RoleId::Implementer,
                &backend,
                &implementer_context,
                "roles.implementer",
                1_000,
            )
            .unwrap_or_else(|error| panic!("implementer role: {error}"));
        let reviewer = registry
            .invoke(
                RoleId::Reviewer,
                &backend,
                &reviewer_context,
                "roles.reviewer",
                1_000,
            )
            .unwrap_or_else(|error| panic!("reviewer role: {error}"));

        assert_eq!(implementer.role, RoleId::Implementer);
        assert_eq!(reviewer.role, RoleId::Reviewer);
        assert_eq!(backend.capabilities().model_id, "roles-one-physical-model");
        assert!(
            backend
                .health()
                .unwrap_or_else(|error| panic!("backend health: {error}"))
                .loaded
        );
    }

    #[test]
    fn roles_reviewer_context_is_fresh_and_excludes_implementer_trajectory() {
        let packet = ContextPlanner::default()
            .build_reviewer(
                budget(),
                input(vec![
                    evidence("final-diff", EvidenceKind::Diff, "+ exact change"),
                    evidence("verification", EvidenceKind::Verification, "tests passed"),
                    evidence(
                        "hidden-reasoning",
                        EvidenceKind::HiddenReasoning,
                        "private chain",
                    ),
                    evidence(
                        "prior-transcript",
                        EvidenceKind::PriorAttemptTranscript,
                        "old model transcript",
                    ),
                ]),
            )
            .unwrap_or_else(|error| panic!("reviewer packet: {error}"));
        let ids = packet
            .items
            .iter()
            .map(|item| item.evidence_id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(packet.mode, ContextMode::Reviewer);
        assert!(ids.contains("final-diff"));
        assert!(ids.contains("verification"));
        assert!(!ids.contains("hidden-reasoning"));
        assert!(!ids.contains("prior-transcript"));
    }

    #[test]
    fn roles_verifier_context_is_fresh_and_excludes_implementer_trajectory() {
        let packet = ContextPlanner::default()
            .build_verifier(
                budget(),
                input(vec![
                    evidence("final-diff", EvidenceKind::Diff, "+ exact change"),
                    evidence("verification", EvidenceKind::Verification, "tests passed"),
                    evidence(
                        "hidden-reasoning",
                        EvidenceKind::HiddenReasoning,
                        "private chain",
                    ),
                    evidence(
                        "prior-transcript",
                        EvidenceKind::PriorAttemptTranscript,
                        "old model transcript",
                    ),
                ]),
            )
            .unwrap_or_else(|error| panic!("verifier packet: {error}"));
        let ids = packet
            .items
            .iter()
            .map(|item| item.evidence_id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(packet.mode, ContextMode::Verifier);
        assert!(ids.contains("final-diff"));
        assert!(ids.contains("verification"));
        assert!(!ids.contains("hidden-reasoning"));
        assert!(!ids.contains("prior-transcript"));
    }

    #[test]
    fn roles_cannot_elevate_existing_permission_context() {
        let registry = RoleRegistry::canonical();
        let base = PermissionContext::read_only();
        assert!(base.permits(PermissionClass::ProcessExec));
        assert!(!base.permits(PermissionClass::RepositoryWrite));

        let implementer = base.narrow_for_role(registry.profile(RoleId::Implementer));
        assert!(implementer.permits(PermissionClass::ProcessExec));
        assert!(!implementer.permits(PermissionClass::RepositoryWrite));
        assert!(!implementer.permits(PermissionClass::NetworkRead));

        let reviewer = PermissionContext::m1_local_autonomous()
            .narrow_for_role(registry.profile(RoleId::Reviewer));
        assert!(reviewer.permits(PermissionClass::ProcessExec));
        assert!(!reviewer.permits(PermissionClass::RepositoryWrite));
    }

    #[test]
    fn roles_profile_digest_manifest_is_stable_unique_and_contains_no_grants() {
        let registry = RoleRegistry::canonical();
        let first = registry
            .digest_manifest()
            .unwrap_or_else(|error| panic!("first manifest: {error}"));
        let second = RoleRegistry::canonical()
            .digest_manifest()
            .unwrap_or_else(|error| panic!("second manifest: {error}"));
        assert_eq!(first, second);
        assert_eq!(first.len(), 7);
        assert_eq!(first.values().collect::<BTreeSet<_>>().len(), 7);

        for role in [
            RoleId::Explorer,
            RoleId::Planner,
            RoleId::Implementer,
            RoleId::Debugger,
            RoleId::Reviewer,
            RoleId::SecurityReviewer,
            RoleId::Verifier,
        ] {
            let value = serde_json::to_value(registry.profile(role))
                .unwrap_or_else(|error| panic!("serialize profile: {error}"));
            let object = value
                .as_object()
                .unwrap_or_else(|| panic!("role profile must serialize as an object"));
            assert!(!object.contains_key("credentials"));
            assert!(!object.contains_key("grants"));
            assert!(!object.contains_key("permissions"));
        }
    }
}
