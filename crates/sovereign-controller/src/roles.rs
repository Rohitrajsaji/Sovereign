use super::{ControllerError, PermissionContext, sha256_prefixed};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use sovereign_context::{ContextPacket, EvidenceKind};
use sovereign_model::{
    MODEL_SCHEMA_VERSION, ModelBackend, ModelFinishReason, ModelMessage, ModelMessageRole,
    ModelOutputContract, ModelRequest,
};
use sovereign_policy::{Capability, CapabilitySet};
use std::collections::{BTreeMap, BTreeSet};

pub const ROLE_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const ROLE_PROFILE_VERSION: &str = "1.3.0";
const PREVIOUS_ROLE_PROFILE_VERSION: &str = "1.2.0";
const PRE_BROWSER_ROLE_PROFILE_VERSION: &str = "1.1.0";
const LEGACY_ROLE_PROFILE_VERSION: &str = "1.0.0";
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

impl RoleId {
    #[must_use]
    pub const fn plan_ir_id(self) -> &'static str {
        match self {
            Self::Explorer => "role.explorer",
            Self::Planner => "role.planner",
            Self::Implementer => "role.implementer",
            Self::Debugger => "role.debugger",
            Self::Reviewer => "role.reviewer",
            Self::SecurityReviewer => "role.security_reviewer",
            Self::Verifier => "role.verifier",
        }
    }

    #[must_use]
    pub fn from_plan_ir_id(value: &str) -> Option<Self> {
        match value {
            "role.explorer" => Some(Self::Explorer),
            "role.planner" => Some(Self::Planner),
            "role.implementer" => Some(Self::Implementer),
            "role.debugger" => Some(Self::Debugger),
            "role.reviewer" => Some(Self::Reviewer),
            "role.security_reviewer" => Some(Self::SecurityReviewer),
            "role.verifier" => Some(Self::Verifier),
            _ => None,
        }
    }
}

/// Exact Plan IR role pin resolved against the canonical in-process role registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePin {
    pub id: String,
    pub version: String,
    pub digest: String,
}

/// Backwards-compatible public name for the canonical Plan IR capability domain.
///
/// Role authority no longer owns a divergent seven-value enum. Every role ceiling is expressed
/// directly in [`sovereign_policy::Capability`], so newly defined Plan IR capabilities cannot be
/// accidentally omitted from the role authority type.
pub type RoleToolClass = Capability;

fn serialize_role_capability_ceiling<S>(
    capabilities: &BTreeSet<Capability>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Keep the v1 RoleProfile wire form stable for the seven values that existed before the
    // authority type was unified. This preserves existing canonical role digests/pins while the
    // in-memory authority domain is the canonical twelve-value Capability enum.
    let mut values = capabilities.iter().copied().collect::<Vec<_>>();
    values.sort_by_key(|capability| match capability {
        Capability::ProcessExec => 0,
        Capability::RepositoryWrite => 1,
        Capability::PackageInstall => 2,
        Capability::NetworkRead => 3,
        Capability::NetworkWrite => 4,
        Capability::Destructive => 5,
        Capability::ExternalSideEffect => 6,
        Capability::Read => 7,
        Capability::SandboxWrite => 8,
        Capability::BrowserInteractive => 9,
        Capability::SecretUse => 10,
        Capability::ExternalIntelligence => 11,
    });
    values
        .into_iter()
        .map(|capability| match capability {
            Capability::RepositoryWrite => "repository_write",
            other => other.as_plan_ir_str(),
        })
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn deserialize_role_capability_ceiling<'de, D>(
    deserializer: D,
) -> Result<BTreeSet<Capability>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            if value == "repository_write" {
                return Ok(Capability::RepositoryWrite);
            }
            Capability::from_plan_ir_str(&value).ok_or_else(|| {
                serde::de::Error::custom(format!("unknown canonical role capability {value}"))
            })
        })
        .collect()
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
    #[serde(
        serialize_with = "serialize_role_capability_ceiling",
        deserialize_with = "deserialize_role_capability_ceiling"
    )]
    pub allowed_tool_classes_ceiling: BTreeSet<Capability>,
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

    /// Returns this role ceiling in the canonical deterministic capability-set representation.
    #[must_use]
    pub fn capability_ceiling(&self) -> CapabilitySet {
        CapabilitySet::new(self.allowed_tool_classes_ceiling.iter().copied())
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
    previous_profiles: BTreeMap<RoleId, RoleProfile>,
    pre_browser_profiles: BTreeMap<RoleId, RoleProfile>,
    legacy_profiles: BTreeMap<RoleId, RoleProfile>,
}

impl Default for RoleRegistry {
    fn default() -> Self {
        Self::canonical()
    }
}

impl RoleRegistry {
    #[must_use]
    pub fn canonical() -> Self {
        let previous_profiles: BTreeMap<RoleId, RoleProfile> = [
            explorer_profile(true),
            planner_profile(),
            implementer_profile(true, true),
            debugger_profile(true, true),
            reviewer_profile(),
            security_reviewer_profile(),
            verifier_profile(),
        ]
        .into_iter()
        .map(|profile| (profile.role, profile))
        .collect();
        let mut profiles = previous_profiles.clone();
        profiles
            .get_mut(&RoleId::Implementer)
            .unwrap_or_else(|| unreachable!("canonical role registry is complete"))
            .allowed_tool_classes_ceiling
            .insert(Capability::Read);
        let pre_browser_profiles = [
            explorer_profile(false),
            planner_profile(),
            implementer_profile(true, false),
            debugger_profile(true, false),
            reviewer_profile(),
            security_reviewer_profile(),
            verifier_profile(),
        ]
        .into_iter()
        .map(|profile| (profile.role, profile))
        .collect();
        let legacy_profiles = [
            explorer_profile(false),
            planner_profile(),
            implementer_profile(false, false),
            debugger_profile(false, false),
            reviewer_profile(),
            security_reviewer_profile(),
            verifier_profile(),
        ]
        .into_iter()
        .map(|profile| (profile.role, profile))
        .collect();
        Self {
            profiles,
            previous_profiles,
            pre_browser_profiles,
            legacy_profiles,
        }
    }

    #[must_use]
    pub fn profile(&self, role: RoleId) -> &RoleProfile {
        self.profiles
            .get(&role)
            .unwrap_or_else(|| unreachable!("canonical role registry is complete"))
    }

    /// Returns the exact canonical Plan IR pin for one logical role profile.
    ///
    /// # Errors
    /// Returns a JSON error if the canonical profile cannot be serialized for digesting.
    pub fn canonical_pin(&self, role: RoleId) -> Result<RolePin, serde_json::Error> {
        Ok(RolePin {
            id: role.plan_ir_id().to_owned(),
            version: ROLE_PROFILE_VERSION.to_owned(),
            digest: self.profile(role).digest()?,
        })
    }

    /// Resolves only an exact canonical `{id, version, digest}` Plan IR role pin.
    /// Role text alone is never enough to select an authority-relevant ceiling.
    ///
    /// # Errors
    /// Returns an invalid-plan error for unknown IDs, unsupported versions, or digest mismatch.
    pub fn resolve_pin(
        &self,
        id: &str,
        version: &str,
        digest: &str,
    ) -> Result<&RoleProfile, ControllerError> {
        let role = RoleId::from_plan_ir_id(id).ok_or_else(|| {
            ControllerError::InvalidPlan(format!("unknown canonical role pin id {id}"))
        })?;
        let profile = match version {
            ROLE_PROFILE_VERSION => self.profile(role),
            PREVIOUS_ROLE_PROFILE_VERSION => self
                .previous_profiles
                .get(&role)
                .unwrap_or_else(|| unreachable!("previous role registry is complete")),
            PRE_BROWSER_ROLE_PROFILE_VERSION => self
                .pre_browser_profiles
                .get(&role)
                .unwrap_or_else(|| unreachable!("pre-browser role registry is complete")),
            LEGACY_ROLE_PROFILE_VERSION => self
                .legacy_profiles
                .get(&role)
                .unwrap_or_else(|| unreachable!("legacy role registry is complete")),
            _ => {
                return Err(ControllerError::InvalidPlan(format!(
                    "unsupported canonical role pin version {version}"
                )));
            }
        };
        let expected = profile.digest()?;
        if digest != expected {
            return Err(ControllerError::InvalidPlan(format!(
                "role pin digest does not match canonical profile for {id}"
            )));
        }
        Ok(profile)
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
    /// Explicit opt-in local profile for deterministic browser execution.
    ///
    /// This profile is a user/Controller ceiling only. Effective browser/network authority still
    /// requires the active global/task Plan IR request, canonical role ceiling, exact tool manifest,
    /// and persisted task grant to independently contain the same capability. The M1 profile is not
    /// widened by this constructor.
    #[must_use]
    pub fn m7_local_browser_execution() -> Self {
        let granted = BTreeSet::from([
            Capability::ProcessExec,
            Capability::RepositoryWrite,
            Capability::NetworkRead,
            Capability::NetworkWrite,
            Capability::BrowserInteractive,
            Capability::ExternalSideEffect,
        ]);
        Self {
            controller_ceiling: granted.clone(),
            project_ceiling: granted.clone(),
            role_ceiling: granted.clone(),
            persisted_grants: granted,
            persisted_grant_issuer: "user:local-browser-execution-profile".to_owned(),
        }
    }

    /// Applies a role as an additional ceiling. It can only remove permissions
    /// from the pre-existing Controller/project/grant intersection; it cannot
    /// manufacture a permission that was absent from the current role ceiling.
    #[must_use]
    pub fn narrow_for_role(&self, profile: &RoleProfile) -> Self {
        let role_ceiling: BTreeSet<_> = self
            .role_capabilities()
            .intersection(&profile.capability_ceiling())
            .into();
        Self {
            controller_ceiling: self.controller_ceiling.clone(),
            project_ceiling: self.project_ceiling.clone(),
            role_ceiling,
            persisted_grants: self.persisted_grants.clone(),
            persisted_grant_issuer: self.persisted_grant_issuer.clone(),
        }
    }
}

fn explorer_profile(browser_read_ceiling: bool) -> RoleProfile {
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
        allowed_tool_classes_ceiling: if browser_read_ceiling {
            BTreeSet::from([
                Capability::ProcessExec,
                Capability::NetworkRead,
                Capability::BrowserInteractive,
            ])
        } else {
            BTreeSet::from([Capability::ProcessExec])
        },
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

fn implementer_profile(secret_use_ceiling: bool, browser_ceiling: bool) -> RoleProfile {
    let mut allowed_tool_classes_ceiling =
        BTreeSet::from([Capability::ProcessExec, Capability::RepositoryWrite]);
    if secret_use_ceiling {
        allowed_tool_classes_ceiling.insert(Capability::SecretUse);
    }
    if browser_ceiling {
        allowed_tool_classes_ceiling.extend([
            Capability::NetworkRead,
            Capability::NetworkWrite,
            Capability::BrowserInteractive,
            Capability::ExternalSideEffect,
        ]);
    }
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
        allowed_tool_classes_ceiling,
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

fn debugger_profile(secret_use_ceiling: bool, browser_ceiling: bool) -> RoleProfile {
    let mut allowed_tool_classes_ceiling =
        BTreeSet::from([Capability::ProcessExec, Capability::RepositoryWrite]);
    if secret_use_ceiling {
        allowed_tool_classes_ceiling.insert(Capability::SecretUse);
    }
    if browser_ceiling {
        allowed_tool_classes_ceiling.extend([
            Capability::NetworkRead,
            Capability::NetworkWrite,
            Capability::BrowserInteractive,
            Capability::ExternalSideEffect,
        ]);
    }
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
        allowed_tool_classes_ceiling,
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
        allowed_tool_classes_ceiling: BTreeSet::from([Capability::ProcessExec]),
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
        allowed_tool_classes_ceiling: BTreeSet::from([Capability::ProcessExec]),
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
        allowed_tool_classes_ceiling: BTreeSet::from([Capability::ProcessExec]),
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
            authorized_tool_schemas: Vec::new(),
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
        assert!(base.permits(Capability::ProcessExec));
        assert!(!base.permits(Capability::RepositoryWrite));

        let implementer = base.narrow_for_role(registry.profile(RoleId::Implementer));
        assert!(implementer.permits(Capability::ProcessExec));
        assert!(!implementer.permits(Capability::RepositoryWrite));
        assert!(!implementer.permits(Capability::NetworkRead));

        let reviewer = PermissionContext::m1_local_autonomous()
            .narrow_for_role(registry.profile(RoleId::Reviewer));
        assert!(reviewer.permits(Capability::ProcessExec));
        assert!(!reviewer.permits(Capability::RepositoryWrite));

        let broad = BTreeSet::from([
            Capability::ProcessExec,
            Capability::RepositoryWrite,
            Capability::Destructive,
        ]);
        let broad_context = PermissionContext {
            controller_ceiling: broad.clone(),
            project_ceiling: broad.clone(),
            role_ceiling: broad.clone(),
            persisted_grants: broad,
            persisted_grant_issuer: "user:test".to_owned(),
        };
        let implementer = broad_context.narrow_for_role(registry.profile(RoleId::Implementer));
        assert!(implementer.permits(Capability::RepositoryWrite));
        assert!(!implementer.permits(Capability::Destructive));
    }

    #[test]
    fn secret_use_is_an_opt_in_ceiling_for_implementer_and_debugger_only() {
        let registry = RoleRegistry::canonical();
        for role in [RoleId::Implementer, RoleId::Debugger] {
            assert!(
                registry
                    .profile(role)
                    .capability_ceiling()
                    .contains(Capability::SecretUse)
            );
        }
        for role in [
            RoleId::Explorer,
            RoleId::Planner,
            RoleId::Reviewer,
            RoleId::SecurityReviewer,
            RoleId::Verifier,
        ] {
            assert!(
                !registry
                    .profile(role)
                    .capability_ceiling()
                    .contains(Capability::SecretUse)
            );
        }

        let base = PermissionContext::m1_local_autonomous();
        assert!(!base.permits(Capability::SecretUse));
        let secret = PermissionContext::m6_local_secret_execution();
        assert!(secret.permits(Capability::SecretUse));
        assert!(
            secret
                .narrow_for_role(registry.profile(RoleId::Implementer))
                .permits(Capability::SecretUse)
        );
        assert!(
            !secret
                .narrow_for_role(registry.profile(RoleId::Reviewer))
                .permits(Capability::SecretUse)
        );
    }

    #[test]
    fn browser_execution_profile_and_role_ceiling_are_explicit_and_non_elevating() {
        let registry = RoleRegistry::canonical();
        let m1 = PermissionContext::m1_local_autonomous();
        for capability in [
            Capability::BrowserInteractive,
            Capability::NetworkRead,
            Capability::NetworkWrite,
            Capability::ExternalSideEffect,
        ] {
            assert!(!m1.permits(capability));
        }

        let browser = PermissionContext::m7_local_browser_execution();
        for capability in [
            Capability::BrowserInteractive,
            Capability::NetworkRead,
            Capability::NetworkWrite,
            Capability::ExternalSideEffect,
        ] {
            assert!(browser.permits(capability));
        }
        let implementer = browser.narrow_for_role(registry.profile(RoleId::Implementer));
        assert!(implementer.permits(Capability::BrowserInteractive));
        assert!(implementer.permits(Capability::NetworkRead));
        assert!(implementer.permits(Capability::NetworkWrite));
        assert!(implementer.permits(Capability::ExternalSideEffect));

        let explorer = browser.narrow_for_role(registry.profile(RoleId::Explorer));
        assert!(explorer.permits(Capability::BrowserInteractive));
        assert!(explorer.permits(Capability::NetworkRead));
        assert!(!explorer.permits(Capability::NetworkWrite));
        assert!(!explorer.permits(Capability::ExternalSideEffect));

        let reviewer = browser.narrow_for_role(registry.profile(RoleId::Reviewer));
        assert!(!reviewer.permits(Capability::BrowserInteractive));
        assert!(!reviewer.permits(Capability::NetworkRead));
    }

    #[test]
    fn role_ceiling_accepts_the_full_canonical_twelve_capability_domain() {
        let mut profile = RoleRegistry::canonical()
            .profile(RoleId::Implementer)
            .clone();
        profile.allowed_tool_classes_ceiling = Capability::ALL.into_iter().collect();

        assert_eq!(profile.capability_ceiling(), CapabilitySet::all());
        assert_eq!(profile.capability_ceiling().iter().count(), 12);

        let encoded = serde_json::to_vec(&profile)
            .unwrap_or_else(|error| panic!("serialize canonical capability role profile: {error}"));
        let decoded: RoleProfile = serde_json::from_slice(&encoded).unwrap_or_else(|error| {
            panic!("deserialize canonical capability role profile: {error}")
        });
        assert_eq!(decoded.capability_ceiling(), CapabilitySet::all());
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

    #[test]
    fn exact_plan_ir_role_pin_resolves_only_canonical_profile() {
        let registry = RoleRegistry::canonical();
        let pin = registry
            .canonical_pin(RoleId::Implementer)
            .unwrap_or_else(|error| panic!("canonical pin: {error}"));
        let profile = registry
            .resolve_pin(&pin.id, &pin.version, &pin.digest)
            .unwrap_or_else(|error| panic!("resolve canonical pin: {error}"));
        assert_eq!(profile.role, RoleId::Implementer);
        assert!(
            registry
                .resolve_pin(
                    &pin.id,
                    &pin.version,
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .is_err()
        );
        assert!(registry.resolve_pin(&pin.id, "0.9.0", &pin.digest).is_err());

        let implementer_v13 = registry.profile(RoleId::Implementer);
        assert!(
            implementer_v13
                .capability_ceiling()
                .contains(Capability::Read)
        );
        let implementer_v12 = registry
            .resolve_pin(
                RoleId::Implementer.plan_ir_id(),
                PREVIOUS_ROLE_PROFILE_VERSION,
                &registry
                    .previous_profiles
                    .get(&RoleId::Implementer)
                    .unwrap_or_else(|| unreachable!("previous implementer profile exists"))
                    .digest()
                    .unwrap_or_else(|error| panic!("previous implementer digest: {error}")),
            )
            .unwrap_or_else(|error| panic!("resolve previous implementer pin: {error}"));
        assert!(
            !implementer_v12
                .capability_ceiling()
                .contains(Capability::Read)
        );

        let pre_browser = implementer_profile(true, false);
        let pre_browser_digest = pre_browser
            .digest()
            .unwrap_or_else(|error| panic!("pre-browser implementer digest: {error}"));
        let resolved_pre_browser = registry
            .resolve_pin(
                RoleId::Implementer.plan_ir_id(),
                PRE_BROWSER_ROLE_PROFILE_VERSION,
                &pre_browser_digest,
            )
            .unwrap_or_else(|error| panic!("resolve pre-browser implementer pin: {error}"));
        assert!(
            resolved_pre_browser
                .capability_ceiling()
                .contains(Capability::SecretUse)
        );
        assert!(
            !resolved_pre_browser
                .capability_ceiling()
                .contains(Capability::BrowserInteractive)
        );

        let legacy = implementer_profile(false, false);
        let legacy_digest = legacy
            .digest()
            .unwrap_or_else(|error| panic!("legacy implementer digest: {error}"));
        let resolved_legacy = registry
            .resolve_pin(
                RoleId::Implementer.plan_ir_id(),
                LEGACY_ROLE_PROFILE_VERSION,
                &legacy_digest,
            )
            .unwrap_or_else(|error| panic!("resolve legacy implementer pin: {error}"));
        assert!(
            !resolved_legacy
                .capability_ceiling()
                .contains(Capability::SecretUse)
        );
        assert!(
            registry
                .resolve_pin(
                    RoleId::Implementer.plan_ir_id(),
                    LEGACY_ROLE_PROFILE_VERSION,
                    &pin.digest,
                )
                .is_err()
        );
    }
}
