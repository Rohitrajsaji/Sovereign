//! Canonical bounded M1 Plan Compiler.
//!
//! The compiler is intentionally a proposal normalizer, not an authority
//! surface. It consumes an already-bounded [`ContextPacket`], performs bounded
//! calls through only [`ModelBackend::complete`], deterministically constructs
//! a Plan IR candidate under caller-owned policy ceilings, and requires the
//! existing [`PlanValidator`] to accept that candidate before returning it.

use super::{PlanIr, PlanValidator, ValidationDiagnostic, canonicalize};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{ContextLevel, ContextPacket, EvidenceKind};
use sovereign_model::{
    M1_HARD_INPUT_CONTEXT_TOKENS, MODEL_SCHEMA_VERSION, ModelBackend, ModelError,
    ModelFinishReason, ModelMessage, ModelMessageRole, ModelOutputContract, ModelRequest,
    ModelResponse,
};
use sovereign_policy::{ModelCallBudget, PolicyError};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Component, Path};

/// Stable schema version for compiler input/result/evidence records.
pub const PLAN_COMPILATION_SCHEMA_VERSION: u32 = 1;
const MAX_COMPILER_MODEL_CALLS: u8 = 2;
const MAX_PROPOSAL_TASKS: usize = 2;
const MAX_PROPOSAL_FILES: usize = 16;
const MAX_PROPOSAL_SYMBOLS: usize = 16;
const MAX_PROPOSAL_EVIDENCE_QUERIES: usize = 8;
const MAX_PROPOSAL_TEXT_BYTES: usize = 2_048;

/// Exact repository baseline supplied by deterministic repository/controller
/// code. Model output never authors or widens these values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCompilationRepository {
    pub repository_id: String,
    pub root: String,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub dirty_digest: String,
    pub protected_changes_present: bool,
    pub languages: Vec<String>,
}

/// Canonical bounded compiler input v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanCompilationInput {
    pub schema_version: u32,
    pub compilation_id: String,
    pub compiled_at: String,
    pub project_id: String,
    pub project_name: String,
    pub workspace_roots: Vec<String>,
    pub goal_id: String,
    pub goal_statement: String,
    pub goal_invariants: Vec<String>,
    pub goal_non_goals: Vec<String>,
    pub repository: PlanCompilationRepository,
    /// Authoritative Plan IR global policy envelope. The compiler copies this
    /// value exactly and may only narrow task-level authority beneath it.
    pub policy: Value,
    /// Controller-supplied digest-pinned identities. Model output cannot
    /// introduce or replace these execution/evaluation contracts.
    pub role: Value,
    pub skills: Vec<Value>,
    pub tools: Vec<Value>,
    pub write_tool_id: String,
    pub read_tool_id: String,
    pub diff_evaluator: String,
    pub rollback_diff_evaluator: String,
    pub context_packet: ContextPacket,
    pub max_model_calls: u8,
    pub model_input_token_ceiling: u32,
    pub max_output_tokens: u32,
    pub model_deadline_ms: u64,
}

/// Digest-only evidence handle proving which bounded source-bearing facts were
/// available to compilation. No full repository or raw tool stream is stored
/// here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationEvidenceHandle {
    pub evidence_id: String,
    pub kind: String,
    pub source_uri: String,
    pub source_digest: String,
    pub content_digest: String,
    pub locator: Option<String>,
}

/// One bounded planning-model attempt in the compiler evidence trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAttemptEvidence {
    pub attempt: u8,
    pub request_digest: String,
    pub response_digest: Option<String>,
    pub accepted: bool,
    pub rejection_reason: Option<String>,
}

/// Immutable provenance record for a successful compilation candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationEvidence {
    schema: String,
    compilation_id: String,
    compiler_version: String,
    context_packet_digest: String,
    exact_evidence: Vec<CompilationEvidenceHandle>,
    model_attempts: Vec<ModelAttemptEvidence>,
    validator_passed: bool,
    plan_digest: String,
}

impl CompilationEvidence {
    #[must_use]
    pub fn compilation_id(&self) -> &str {
        &self.compilation_id
    }

    #[must_use]
    pub fn compiler_version(&self) -> &str {
        &self.compiler_version
    }

    #[must_use]
    pub fn context_packet_digest(&self) -> &str {
        &self.context_packet_digest
    }

    #[must_use]
    pub fn exact_evidence(&self) -> &[CompilationEvidenceHandle] {
        &self.exact_evidence
    }

    #[must_use]
    pub fn model_attempts(&self) -> &[ModelAttemptEvidence] {
        &self.model_attempts
    }

    #[must_use]
    pub const fn validator_passed(&self) -> bool {
        self.validator_passed
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }
}

/// Validated, digest-addressed Plan IR candidate. This type intentionally has
/// no activation or authorization API; the future Controller owns that step.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanCompilationResult {
    plan: PlanIr,
    plan_digest: String,
    compilation_evidence: CompilationEvidence,
    compilation_evidence_digest: String,
}

impl PlanCompilationResult {
    #[must_use]
    pub const fn plan(&self) -> &PlanIr {
        &self.plan
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    #[must_use]
    pub const fn compilation_evidence(&self) -> &CompilationEvidence {
        &self.compilation_evidence
    }

    #[must_use]
    pub fn compilation_evidence_digest(&self) -> &str {
        &self.compilation_evidence_digest
    }
}

/// Deterministic compiler failures. Validation rejection never returns a
/// candidate that could be mistaken for active execution state.
#[derive(Debug)]
pub enum PlanCompilationError {
    InvalidInput(String),
    Model(ModelError),
    Policy(PolicyError),
    ProposalRejected { attempts: u8, reason: String },
    ValidationRejected(Vec<ValidationDiagnostic>),
    Serialization(serde_json::Error),
}

impl Display for PlanCompilationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid PlanCompiler input: {message}"),
            Self::Model(error) => write!(f, "PlanCompiler model call failed: {error}"),
            Self::Policy(error) => write!(f, "PlanCompiler outer budget rejected call: {error}"),
            Self::ProposalRejected { attempts, reason } => write!(
                f,
                "planning proposal rejected after {attempts} bounded attempt(s): {reason}"
            ),
            Self::ValidationRejected(diagnostics) => write!(
                f,
                "compiled Plan IR candidate failed PlanValidator with {} diagnostic(s)",
                diagnostics.len()
            ),
            Self::Serialization(error) => write!(f, "PlanCompiler serialization failed: {error}"),
        }
    }
}

impl Error for PlanCompilationError {}

impl From<serde_json::Error> for PlanCompilationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl From<PolicyError> for PlanCompilationError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}

/// The one canonical M1 compiler authority. It can propose and validate a Plan
/// IR candidate but cannot activate plans or authorize actions.
pub struct PlanCompiler<'a> {
    backend: &'a dyn ModelBackend,
    validator: &'a PlanValidator,
    compiler_version: String,
}

impl<'a> PlanCompiler<'a> {
    /// Constructs the canonical compiler around provider-neutral contracts.
    ///
    /// # Errors
    /// Returns [`PlanCompilationError::InvalidInput`] for an empty version.
    pub fn new(
        backend: &'a dyn ModelBackend,
        validator: &'a PlanValidator,
        compiler_version: impl Into<String>,
    ) -> Result<Self, PlanCompilationError> {
        let compiler_version = compiler_version.into();
        if compiler_version.trim().is_empty() {
            return Err(PlanCompilationError::InvalidInput(
                "compiler_version must be non-empty".to_owned(),
            ));
        }
        Ok(Self {
            backend,
            validator,
            compiler_version,
        })
    }

    /// Compiles one simple bounded engineering goal into an immutable validated
    /// Plan IR v1.2 candidate.
    ///
    /// The only model operation used here is [`ModelBackend::complete`]. Model
    /// loading, tokenization, health, leases, activation, authorization, and
    /// execution remain outside this interface.
    ///
    /// # Errors
    /// Returns a deterministic input/proposal/validation error, or the provider
    /// error from a non-malformed model failure.
    pub fn compile(
        &self,
        input: &PlanCompilationInput,
        model_call_budget: &mut ModelCallBudget,
    ) -> Result<PlanCompilationResult, PlanCompilationError> {
        validate_compilation_input(input)?;
        let context_digest = canonical_digest(&input.context_packet)?;
        let exact_evidence = evidence_handles(&input.context_packet);
        let known_paths =
            known_repository_paths(&input.context_packet, &input.repository.repository_id);
        let mut attempts = Vec::new();
        let mut last_rejection = "model returned no acceptable proposal".to_owned();

        for attempt in 1..=input.max_model_calls {
            let request = Self::model_request(input, attempt);
            let request_digest = canonical_digest(&request)?;
            model_call_budget.consume_call(request.deadline_ms)?;
            let response = match self.backend.complete(&request) {
                Ok(response) => response,
                Err(error) if malformed_model_error(&error) => {
                    last_rejection = error.to_string();
                    attempts.push(ModelAttemptEvidence {
                        attempt,
                        request_digest,
                        response_digest: None,
                        accepted: false,
                        rejection_reason: Some(last_rejection.clone()),
                    });
                    continue;
                }
                Err(error) => return Err(PlanCompilationError::Model(error)),
            };
            let response_digest = semantic_response_digest(&response)?;
            match parse_and_bound_proposal(&response, &known_paths) {
                Ok(proposal) => {
                    let plan =
                        self.normalize(input, &proposal, &context_digest, &response_digest)?;
                    let diagnostics = self.validator.validate(&plan);
                    if !diagnostics.is_empty() {
                        return Err(PlanCompilationError::ValidationRejected(diagnostics));
                    }
                    let plan_digest = plan.canonical_digest()?;
                    attempts.push(ModelAttemptEvidence {
                        attempt,
                        request_digest,
                        response_digest: Some(response_digest),
                        accepted: true,
                        rejection_reason: None,
                    });
                    let evidence = CompilationEvidence {
                        schema: "sovereign-plan-compilation-evidence-v1".to_owned(),
                        compilation_id: input.compilation_id.clone(),
                        compiler_version: self.compiler_version.clone(),
                        context_packet_digest: context_digest,
                        exact_evidence,
                        model_attempts: attempts,
                        validator_passed: true,
                        plan_digest: plan_digest.clone(),
                    };
                    let evidence_digest = canonical_digest(&evidence)?;
                    return Ok(PlanCompilationResult {
                        plan,
                        plan_digest,
                        compilation_evidence: evidence,
                        compilation_evidence_digest: evidence_digest,
                    });
                }
                Err(reason) => {
                    last_rejection.clone_from(&reason);
                    attempts.push(ModelAttemptEvidence {
                        attempt,
                        request_digest,
                        response_digest: Some(response_digest),
                        accepted: false,
                        rejection_reason: Some(reason),
                    });
                }
            }
        }

        Err(PlanCompilationError::ProposalRejected {
            attempts: input.max_model_calls,
            reason: last_rejection,
        })
    }

    fn model_request(input: &PlanCompilationInput, attempt: u8) -> ModelRequest {
        let repair_note = if attempt == 1 {
            String::new()
        } else {
            "\nPrevious proposal was malformed or outside the bounded compiler contract. Return only a corrected proposal."
                .to_owned()
        };
        ModelRequest {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: format!("{}.proposal.{attempt}", input.compilation_id),
            messages: vec![
                ModelMessage {
                    role: ModelMessageRole::System,
                    content: concat!(
                        "You are a bounded PlanCompiler proposal helper. Return only the requested JSON. ",
                        "Use only supplied bounded evidence. Never invent permissions, authority, paths, ",
                        "repository facts, tool authorization, or plan activation. One task is preferred. ",
                        "Two tasks are allowed only when an explicit evidence query justifies the linear split."
                    )
                    .to_owned(),
                    tool_call_id: None,
                },
                ModelMessage {
                    role: ModelMessageRole::User,
                    content: format!(
                        "goal={}\nbounded_context:\n{}{}",
                        input.goal_statement, input.context_packet.serialized_input, repair_note
                    ),
                    tool_call_id: None,
                },
            ],
            tools: Vec::new(),
            output_contract: ModelOutputContract::JsonSchema {
                name: "sovereign_minimal_plan_proposal_v1".to_owned(),
                schema: proposal_schema(),
            },
            input_token_ceiling: input.model_input_token_ceiling,
            max_output_tokens: input.max_output_tokens,
            deadline_ms: input.model_deadline_ms,
            temperature_milli: 0,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn normalize(
        &self,
        input: &PlanCompilationInput,
        proposal: &MinimalPlanProposal,
        context_digest: &str,
        response_digest: &str,
    ) -> Result<PlanIr, PlanCompilationError> {
        let seed = sha256_hex(
            format!(
                "{}\0{}\0{}\0{}",
                input.goal_id, input.goal_statement, input.repository.repository_id, context_digest
            )
            .as_bytes(),
        );
        let stem = &seed[..20];
        let plan_id = format!("plan.{stem}");
        let requirement_id = format!("REQ.{stem}");
        let known_paths =
            known_repository_paths(&input.context_packet, &input.repository.repository_id);
        let mut tasks = Vec::new();
        let mut prior_binding: Option<(String, String, String)> = None;
        let mut evidence_types = BTreeSet::new();

        for (index, proposed) in proposal.tasks.iter().enumerate() {
            let ordinal = index + 1;
            let task_id = format!("task.{stem}.{ordinal:02}");
            let task = build_task(
                input,
                proposed,
                &task_id,
                &requirement_id,
                ordinal,
                &known_paths,
                prior_binding.as_ref(),
            )?;
            let artifact_id = task
                .get("expected_artifacts")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| item.get("artifact_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PlanCompilationError::InvalidInput(
                        "normalized task is missing its primary artifact".to_owned(),
                    )
                })?
                .to_owned();
            let criterion_id = task
                .get("acceptance_criteria")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| item.get("criterion_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PlanCompilationError::InvalidInput(
                        "normalized task is missing its primary acceptance criterion".to_owned(),
                    )
                })?
                .to_owned();
            for evidence_type in task
                .pointer("/verification/required_evidence_types")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                evidence_types.insert(evidence_type.to_owned());
            }
            prior_binding = Some((task_id, artifact_id, criterion_id));
            tasks.push(task);
        }

        let instructions = instruction_refs(
            &input.context_packet,
            &input.repository.repository_id,
            &input.compiled_at,
        );
        let edges = if tasks.len() == 2 {
            json!([{
                "edge_id": format!("edge.{stem}.01"),
                "from": tasks[0]["task_id"],
                "to": tasks[1]["task_id"],
                "kind": "produces_for",
                "contract": "Linear M1 split justified by explicit evidence acquisition."
            }])
        } else {
            json!([])
        };
        let required_evidence_types = evidence_types.into_iter().collect::<Vec<_>>();
        let mut plan = json!({
            "ir_version": "1.2",
            "plan_id": plan_id,
            "revision": 1,
            "supersedes_revision": Value::Null,
            "compiled_at": input.compiled_at,
            "compiler_version": self.compiler_version,
            "project": {
                "project_id": input.project_id,
                "name": input.project_name,
                "workspace_roots": input.workspace_roots,
            },
            "goal": {
                "goal_id": input.goal_id,
                "statement": input.goal_statement,
                "source": {"kind": "user", "locator": format!("compilation:{}", input.compilation_id)},
                "invariants": input.goal_invariants,
                "non_goals": input.goal_non_goals,
            },
            "requirements": [{
                "requirement_id": requirement_id,
                "priority": "must",
                "kind": "functional",
                "text": input.goal_statement,
                "source": {"kind": "user", "locator": format!("compilation:{}", input.compilation_id)},
                "evidence_expectations": required_evidence_types,
            }],
            "repositories": [{
                "repository_id": input.repository.repository_id,
                "root": input.repository.root,
                "baseline": {
                    "vcs": "git",
                    "head": input.repository.head,
                    "branch": input.repository.branch,
                    "dirty_digest": input.repository.dirty_digest,
                    "protected_changes_present": input.repository.protected_changes_present,
                },
                "instructions": instructions,
                "index_snapshot_id": Value::Null,
                "languages": input.repository.languages,
            }],
            "depth": {
                "mode": if tasks.len() == 1 { "D1" } else { "D2" },
                "reason": if tasks.len() == 1 {
                    "Bounded M1 compiler resolved a single task from exact C0/C1 evidence."
                } else {
                    "Explicit evidence acquisition requires one short linear split before implementation."
                },
                "features": {
                    "repository_count": 1,
                    "task_count": tasks.len(),
                    "semantic_retrieval": false,
                }
            },
            "policy": input.policy,
            "tasks": tasks,
            "edges": edges,
            "completion_gate": {
                "require_all_must_requirements": true,
                "require_fresh_acceptance": true,
                "require_all_required_tasks_resolved": true,
                "require_no_unknown_actions": true,
                "require_artifact_digests": true,
                "require_scope_audit": true,
                "require_final_checkpoint": true,
                "require_final_repository_revisions": true,
                "checks": [{
                    "check_id": format!("check.{stem}.acceptance"),
                    "kind": "acceptance",
                    "required_evidence_types": required_evidence_types,
                }]
            },
            "provenance": [
                {
                    "source": {"kind": "user", "locator": format!("compilation:{}:goal", input.compilation_id)},
                    "observed_at": input.compiled_at,
                    "notes": "Natural-language goal supplied by the caller."
                },
                {
                    "source": {"kind": "generated", "locator": format!("context-packet:{context_digest}"), "digest": context_digest},
                    "observed_at": input.compiled_at,
                    "notes": "Bounded C0/C1 ContextPacket; repository dumps and raw logs are excluded."
                },
                {
                    "source": {"kind": "model", "locator": format!("model-proposal:{}", input.compilation_id), "digest": response_digest},
                    "observed_at": input.compiled_at,
                    "notes": "Untrusted bounded proposal normalized under deterministic policy ceilings."
                }
            ]
        });
        plan = canonicalize(&plan);
        Ok(PlanIr::from_value(plan))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MinimalPlanProposal {
    tasks: Vec<MinimalTaskProposal>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MinimalTaskProposal {
    title: String,
    objective: String,
    rationale: String,
    files: Vec<String>,
    symbols: Vec<String>,
    evidence_queries: Vec<String>,
    expected_change: String,
}

fn validate_compilation_input(input: &PlanCompilationInput) -> Result<(), PlanCompilationError> {
    if input.schema_version != PLAN_COMPILATION_SCHEMA_VERSION {
        return Err(PlanCompilationError::InvalidInput(format!(
            "unsupported input schema version {}",
            input.schema_version
        )));
    }
    if input.compilation_id.trim().is_empty()
        || input.compiled_at.trim().is_empty()
        || input.project_id.trim().is_empty()
        || input.project_name.trim().is_empty()
        || input.workspace_roots.is_empty()
        || input.goal_id.trim().is_empty()
        || input.goal_statement.trim().is_empty()
        || input.repository.repository_id.trim().is_empty()
        || input.repository.root.trim().is_empty()
        || input.repository.dirty_digest.trim().is_empty()
        || input.write_tool_id.trim().is_empty()
        || input.read_tool_id.trim().is_empty()
        || input.diff_evaluator.trim().is_empty()
        || input.rollback_diff_evaluator.trim().is_empty()
    {
        return Err(PlanCompilationError::InvalidInput(
            "identity, goal, workspace, repository baseline and timestamp fields are required"
                .to_owned(),
        ));
    }
    if input.max_model_calls == 0 || input.max_model_calls > MAX_COMPILER_MODEL_CALLS {
        return Err(PlanCompilationError::InvalidInput(format!(
            "max_model_calls must be between 1 and {MAX_COMPILER_MODEL_CALLS}"
        )));
    }
    if input.model_input_token_ceiling == 0
        || input.model_input_token_ceiling > M1_HARD_INPUT_CONTEXT_TOKENS
        || input.context_packet.metrics.final_serialized_input_tokens
            > input.model_input_token_ceiling
        || input.max_output_tokens < 128
        || input.model_deadline_ms == 0
    {
        return Err(PlanCompilationError::InvalidInput(
            "model context/output/deadline budget is invalid or smaller than the bounded ContextPacket"
                .to_owned(),
        ));
    }
    if input.context_packet.schema != "sovereign-context-packet-v1" {
        return Err(PlanCompilationError::InvalidInput(
            "compiler requires sovereign-context-packet-v1".to_owned(),
        ));
    }
    if input.context_packet.items.iter().any(|item| {
        matches!(
            item.kind,
            EvidenceKind::FullRepository
                | EvidenceKind::RawToolLog
                | EvidenceKind::PriorAttemptTranscript
                | EvidenceKind::HiddenReasoning
        )
    }) {
        return Err(PlanCompilationError::InvalidInput(
            "compiler ContextPacket contains a forbidden bulk/transcript evidence kind".to_owned(),
        ));
    }
    let capabilities = string_set(input.policy.pointer("/capability_ceiling"));
    if !capabilities.contains("read") {
        return Err(PlanCompilationError::InvalidInput(
            "minimal compiler requires read within the authoritative capability ceiling".to_owned(),
        ));
    }
    if input.policy.pointer("/resources").is_none() {
        return Err(PlanCompilationError::InvalidInput(
            "authoritative policy is missing its resource ceiling".to_owned(),
        ));
    }
    validate_versioned_capability(&input.role, "role")?;
    for skill in &input.skills {
        validate_versioned_capability(skill, "skill")?;
    }
    for tool in &input.tools {
        validate_versioned_capability(tool, "tool")?;
    }
    if capability_by_id(&input.tools, &input.write_tool_id).is_none()
        || capability_by_id(&input.tools, &input.read_tool_id).is_none()
    {
        return Err(PlanCompilationError::InvalidInput(
            "Controller-supplied read/write tool ids must resolve to pinned tools".to_owned(),
        ));
    }
    Ok(())
}

fn proposal_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["tasks"],
        "properties": {
            "tasks": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_PROPOSAL_TASKS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["title", "objective", "rationale", "files", "symbols", "evidence_queries", "expected_change"],
                    "properties": {
                        "title": {"type": "string", "minLength": 1, "maxLength": 200},
                        "objective": {"type": "string", "minLength": 1, "maxLength": MAX_PROPOSAL_TEXT_BYTES},
                        "rationale": {"type": "string", "minLength": 1, "maxLength": MAX_PROPOSAL_TEXT_BYTES},
                        "files": {"type": "array", "maxItems": MAX_PROPOSAL_FILES, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                        "symbols": {"type": "array", "maxItems": MAX_PROPOSAL_SYMBOLS, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 256}},
                        "evidence_queries": {"type": "array", "maxItems": MAX_PROPOSAL_EVIDENCE_QUERIES, "uniqueItems": true, "items": {"type": "string", "minLength": 1, "maxLength": 512}},
                        "expected_change": {"type": "string", "minLength": 1, "maxLength": MAX_PROPOSAL_TEXT_BYTES}
                    }
                }
            }
        }
    })
}

fn parse_and_bound_proposal(
    response: &ModelResponse,
    known_paths: &BTreeSet<String>,
) -> Result<MinimalPlanProposal, String> {
    if !response.tool_calls.is_empty() {
        return Err("planning proposal attempted a tool call".to_owned());
    }
    if matches!(response.finish_reason, ModelFinishReason::Length) {
        return Err("planning proposal was truncated by the model".to_owned());
    }
    let value = match response.structured.clone() {
        Some(value) => value,
        None => serde_json::from_str(&response.content)
            .map_err(|error| format!("planning proposal is not JSON: {error}"))?,
    };
    let proposal: MinimalPlanProposal = serde_json::from_value(value)
        .map_err(|error| format!("planning proposal violates compiler shape: {error}"))?;
    if proposal.tasks.is_empty() || proposal.tasks.len() > MAX_PROPOSAL_TASKS {
        return Err("planning proposal must contain one or two tasks".to_owned());
    }
    for task in &proposal.tasks {
        if task.title.is_empty()
            || task.objective.is_empty()
            || task.rationale.is_empty()
            || task.expected_change.is_empty()
            || task.title.len() > 200
            || task.objective.len() > MAX_PROPOSAL_TEXT_BYTES
            || task.rationale.len() > MAX_PROPOSAL_TEXT_BYTES
            || task.expected_change.len() > MAX_PROPOSAL_TEXT_BYTES
            || task.files.len() > MAX_PROPOSAL_FILES
            || task.symbols.len() > MAX_PROPOSAL_SYMBOLS
            || task.evidence_queries.len() > MAX_PROPOSAL_EVIDENCE_QUERIES
            || task.files.iter().any(|path| !valid_relative_path(path))
        {
            return Err("planning proposal exceeds deterministic M1 bounds".to_owned());
        }
    }
    if proposal.tasks.len() == 2 {
        let explicit_evidence = proposal
            .tasks
            .iter()
            .any(|task| !task.evidence_queries.is_empty());
        let unresolved_path = proposal
            .tasks
            .iter()
            .flat_map(|task| &task.files)
            .any(|path| !known_paths.contains(path));
        if !explicit_evidence && !unresolved_path {
            return Err(
                "two-task split is not justified by an explicit evidence requirement".to_owned(),
            );
        }
    }
    Ok(proposal)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_task(
    input: &PlanCompilationInput,
    proposal: &MinimalTaskProposal,
    task_id: &str,
    requirement_id: &str,
    ordinal: usize,
    known_paths: &BTreeSet<String>,
    upstream: Option<&(String, String, String)>,
) -> Result<Value, PlanCompilationError> {
    let known_files = proposal
        .files
        .iter()
        .filter(|path| known_paths.contains(path.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let unknown_files = proposal
        .files
        .iter()
        .filter(|path| !known_paths.contains(path.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let global_capabilities = string_set(input.policy.pointer("/capability_ceiling"));
    let write_capable = !known_files.is_empty() && global_capabilities.contains("repo_write");
    let discovery_only = !unknown_files.is_empty() && known_files.is_empty();
    let permissions = if write_capable {
        json!(["read", "repo_write"])
    } else {
        json!(["read"])
    };
    let evidence_requirements = build_evidence_requirements(proposal, &unknown_files, task_id);
    let artifact_id = format!("artifact.{}.result", sanitize_id_fragment(task_id));
    let criterion_id = format!("AC.{}.result", sanitize_id_fragment(task_id));
    let verify_id = format!("verify.{}.result", sanitize_id_fragment(task_id));
    let evidence_type = if discovery_only || !write_capable {
        "evidence_result"
    } else {
        "diff_result"
    };
    let verification_kind = if evidence_type == "diff_result" {
        "diff"
    } else {
        "artifact"
    };
    let artifact_kind = if evidence_type == "diff_result" {
        "patch"
    } else {
        "evidence"
    };
    let verification_step = if verification_kind == "diff" {
        json!({
            "step_id": verify_id,
            "criterion_ids": [criterion_id],
            "kind": "diff",
            "evidence_type": evidence_type,
            "evaluator": input.diff_evaluator
        })
    } else {
        json!({
            "step_id": verify_id,
            "criterion_ids": [criterion_id],
            "kind": "artifact",
            "evidence_type": evidence_type,
            "artifact_id": artifact_id
        })
    };
    let acceptance_kind = verification_kind;
    let write_roots = if write_capable {
        write_roots(&known_files, &input.repository.repository_id)
    } else {
        Vec::new()
    };
    let resources = narrowed_resource_budget(&input.policy, input.max_model_calls)?;
    let dependencies = upstream.map_or_else(|| json!([]), |(task, _, _)| json!([task]));
    let dependency_bindings = upstream.map_or_else(
        || json!([]),
        |(task, artifact, criterion)| {
            json!([{
                "upstream_task_id": task,
                "required_artifact_ids": [artifact],
                "required_acceptance_criterion_ids": [criterion],
                "freshness": "same_plan_revision"
            }])
        },
    );
    let rollback = if write_capable {
        json!({
            "mode": "patch_reverse",
            "procedure": "Reverse only the Controller-owned patch for this task.",
            "preconditions": ["Current repository baseline and Controller patch digest still match."],
            "verification_steps": [{
                "step_id": format!("rollback.{}.diff", sanitize_id_fragment(task_id)),
                "kind": "diff",
                "evidence_type": "rollback_diff_result",
                "evaluator": input.rollback_diff_evaluator
            }]
        })
    } else {
        json!({
            "mode": "none",
            "procedure": "No repository mutation is authorized for this evidence-only task.",
            "reason_no_rollback": "Task is deterministically read-only until exact scope evidence exists."
        })
    };
    let invariants = input
        .goal_invariants
        .iter()
        .enumerate()
        .map(|(index, text)| {
            json!({
                "clause_id": format!("INV.{}.{}", sanitize_id_fragment(task_id), index + 1),
                "text": text,
            })
        })
        .collect::<Vec<_>>();
    let inputs = evidence_handles(&input.context_packet)
        .into_iter()
        .take(16)
        .map(|handle| format!("{} {}", handle.evidence_id, handle.source_digest))
        .collect::<Vec<_>>();
    let max_evidence_items =
        u64::try_from(input.context_packet.items.len().clamp(1, 200)).unwrap_or(200);
    let reserve_output_tokens = input.max_output_tokens.max(128);
    let scope_resolution = if unknown_files.is_empty() {
        "exact"
    } else {
        "bounded_discovery"
    };
    let tool_id = if write_capable {
        &input.write_tool_id
    } else {
        &input.read_tool_id
    };
    let tool = capability_by_id(&input.tools, tool_id).ok_or_else(|| {
        PlanCompilationError::InvalidInput(format!(
            "Controller-supplied tool id {tool_id} no longer resolves"
        ))
    })?;
    let task = json!({
        "task_id": task_id,
        "title": proposal.title,
        "objective": input.goal_statement,
        "rationale": proposal.rationale,
        "requirement_ids": [requirement_id],
        "dependencies": dependencies,
        "dependency_bindings": dependency_bindings,
        "scope": {
            "repositories": [input.repository.repository_id],
            "files": known_files,
            "symbols": proposal.symbols,
            "allow_create": [],
            "allow_delete": [],
            "scope_resolution": scope_resolution
        },
        "evidence_requirements": evidence_requirements,
        "role": input.role,
        "skills": input.skills,
        "tools": [tool],
        "permissions": permissions,
        "action_policy": {
            "write_roots": write_roots,
            "network": offline_network_policy(),
            "packages": {
                "allowed": false,
                "allowed_registries": [],
                "lockfile_required": true,
                "integrity_required": true,
                "lifecycle_scripts": "deny",
                "global_install": false,
                "isolated_target_required": true
            },
            "browser": {
                "allowed": false,
                "allowed_domains": [],
                "max_tabs": 1,
                "downloads": "deny",
                "persistent_profile": false,
                "auto_open_downloads": false,
                "allow_local_file_navigation": false,
                "download_root": Value::Null
            },
            "external_intelligence": {
                "allowed": false,
                "allowed_providers": [],
                "allowed_data_classes": [],
                "whole_repository_export": "deny",
                "raw_logs": false,
                "resolved_secrets": false,
                "tool_authority": "none",
                "max_payload_bytes": 0
            },
            "secret_refs": [],
            "approval_required_permissions": []
        },
        "implementation_contract": {
            "preconditions": [],
            "assumptions": [],
            "inputs": inputs,
            "outputs": [proposal.expected_change, input.goal_statement],
            "invariants": invariants,
            "non_goals": input.goal_non_goals
        },
        "constraints": [
            "Use only current bounded source evidence and preserve pre-existing user hunks.",
            if discovery_only {
                "Do not mutate until the explicit scope evidence requirement is satisfied and the plan is revalidated."
            } else {
                "Do not widen task scope beyond exact current evidence."
            }
        ],
        "expected_artifacts": [{
            "artifact_id": artifact_id,
            "kind": artifact_kind,
            "locator": if write_capable { "controller-change-set" } else { "controller-evidence-set" },
            "required": true
        }],
        "acceptance_criteria": [{
            "criterion_id": criterion_id,
            "description": if write_capable {
                "The exact scoped diff satisfies the task objective without widening scope."
            } else {
                "Required exact scope evidence is retained for deterministic replanning/execution."
            },
            "kind": acceptance_kind,
            "verification_step_ids": [verify_id],
            "evidence_type": evidence_type,
            "evidence_freshness": "current_attempt",
            "required": true
        }],
        "verification": {
            "steps": [verification_step],
            "required_evidence_types": [evidence_type],
            "fresh_reviewer_role": Value::Null
        },
        "failure_policy": {
            "max_attempts": 2,
            "same_failure_limit": 2,
            "resource_retry_limit": 1,
            "on_execution_failure": "repair",
            "on_plan_failure": "replan_smallest_scope",
            "on_resource_failure": "checkpoint_defer",
            "on_unknown_action": "reconcile",
            "on_attempts_exhausted": "block",
            "on_same_failure_exhausted": "block"
        },
        "rollback": rollback,
        "resource_budget": resources,
        "context_budget": {
            "max_input_tokens": input.context_packet.budget.max_input_tokens,
            "reserve_output_tokens": reserve_output_tokens,
            "max_evidence_items": max_evidence_items,
            "levels": ["C0", "C1"]
        },
        "checkpoint_policy": {
            "before_mutation": true,
            "after_mutation": true,
            "on_attempt_end": true,
            "on_verification": true,
            "generation_required": true,
            "verify_references": true,
            "integrity": "hash_chain",
            "on_corruption": "fallback_last_valid_or_block"
        },
        "next_state_rules": [
            {
                "event": "execution_complete",
                "guards": [
                    "dependencies_satisfied",
                    "dependency_bindings_satisfied",
                    "execution_evidence_satisfied",
                    "baseline_fresh",
                    "task_contract_current",
                    "checkpoint_reconciled",
                    "permission_granted",
                    "plan_revision_active"
                ],
                "transition": "verify"
            },
            {
                "event": "verification_passed",
                "guards": [
                    "all_required_acceptance_passed",
                    "no_unknown_actions",
                    "baseline_fresh",
                    "task_contract_current",
                    "plan_revision_active"
                ],
                "transition": "succeed"
            },
            {
                "event": "execution_failure",
                "guards": ["retry_budget_remaining", "plan_revision_active"],
                "transition": "repair"
            }
        ]
    });
    let _ = ordinal;
    Ok(task)
}

fn build_evidence_requirements(
    proposal: &MinimalTaskProposal,
    unknown_files: &[String],
    task_id: &str,
) -> Vec<Value> {
    let stem = sanitize_id_fragment(task_id);
    let mut result = Vec::new();
    for (index, query) in proposal.evidence_queries.iter().enumerate() {
        result.push(json!({
            "requirement_id": format!("EVID.{stem}.query.{}", index + 1),
            "kind": "exact",
            "query": query,
            "required_before": "execution",
            "satisfaction": "at_least_one",
            "freshness": "current_repository_snapshot",
            "max_items": 8
        }));
    }
    for (index, path) in unknown_files.iter().enumerate() {
        result.push(json!({
            "requirement_id": format!("EVID.{stem}.path.{}", index + 1),
            "kind": "exact",
            "query": format!("Resolve proposed path {path} on the current repository snapshot before mutation."),
            "required_before": "execution",
            "satisfaction": "exactly_one",
            "freshness": "current_repository_snapshot",
            "max_items": 4
        }));
    }
    result
}

fn narrowed_resource_budget(
    policy: &Value,
    compiler_model_calls: u8,
) -> Result<Value, PlanCompilationError> {
    let mut resources = policy
        .pointer("/resources")
        .cloned()
        .ok_or_else(|| PlanCompilationError::InvalidInput("policy.resources missing".to_owned()))?;
    let Some(object) = resources.as_object_mut() else {
        return Err(PlanCompilationError::InvalidInput(
            "policy.resources must be an object".to_owned(),
        ));
    };
    object.insert("max_network_bytes".to_owned(), json!(0));
    if let Some(global_calls) = object.get("max_model_calls").and_then(Value::as_u64) {
        object.insert(
            "max_model_calls".to_owned(),
            json!(global_calls.min(u64::from(compiler_model_calls).max(1))),
        );
    }
    let model_allowed = object
        .get("heavy_leases")
        .and_then(Value::as_array)
        .is_some_and(|leases| leases.iter().any(|lease| lease.as_str() == Some("MODEL")));
    object.insert(
        "heavy_leases".to_owned(),
        if model_allowed {
            json!(["MODEL"])
        } else {
            json!([])
        },
    );
    Ok(resources)
}

fn offline_network_policy() -> Value {
    json!({
        "default": "offline",
        "allowed_hosts": [],
        "allowed_schemes": [],
        "allowed_ports": [],
        "allowed_methods": [],
        "follow_redirects": false,
        "max_redirects": 0,
        "allow_private_ranges": false,
        "dns_revalidation": true,
        "connected_peer_validation": true,
        "ambient_proxy": "deny",
        "allow_task_loopback": false
    })
}

fn write_roots(files: &[String], repository_id: &str) -> Vec<Value> {
    let mut roots = BTreeSet::new();
    for file in files {
        let parent = Path::new(file)
            .parent()
            .and_then(Path::to_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(".");
        roots.insert(parent.to_owned());
    }
    roots
        .into_iter()
        .map(|path| json!({"repository_id": repository_id, "path": path}))
        .collect()
}

fn evidence_handles(packet: &ContextPacket) -> Vec<CompilationEvidenceHandle> {
    packet
        .items
        .iter()
        .filter(|item| item.level != ContextLevel::C0 && item.kind != EvidenceKind::ToolSchema)
        .map(|item| CompilationEvidenceHandle {
            evidence_id: item.evidence_id.clone(),
            kind: format!("{:?}", item.kind).to_ascii_lowercase(),
            source_uri: item.source_uri.clone(),
            source_digest: item.source_digest.clone(),
            content_digest: item.content_digest.clone(),
            locator: item.locator.clone(),
        })
        .collect()
}

fn instruction_refs(packet: &ContextPacket, repository_id: &str, freshness: &str) -> Vec<Value> {
    packet
        .items
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Instruction
                && item.repository_id.as_deref() == Some(repository_id)
        })
        .map(|item| {
            json!({
                "evidence_id": stable_id("ev", &item.content_digest),
                "digest": item.source_digest,
                "locator": item.source_uri,
                "trust": "observed",
                "freshness": freshness
            })
        })
        .collect()
}

fn known_repository_paths(packet: &ContextPacket, repository_id: &str) -> BTreeSet<String> {
    let prefix = format!("repo://{repository_id}/");
    packet
        .items
        .iter()
        .filter(|item| {
            item.repository_id.as_deref() == Some(repository_id)
                && matches!(
                    item.kind,
                    EvidenceKind::SourceSlice | EvidenceKind::SearchHit
                )
        })
        .filter_map(|item| item.source_uri.strip_prefix(&prefix))
        .filter(|path| valid_relative_path(path))
        .map(str::to_owned)
        .collect()
}

fn valid_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn string_set(value: Option<&Value>) -> BTreeSet<&str> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn validate_versioned_capability(value: &Value, label: &str) -> Result<(), PlanCompilationError> {
    let valid = value.as_object().is_some_and(|object| {
        object.len() == 3
            && object
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
            && object
                .get("version")
                .and_then(Value::as_str)
                .is_some_and(|version| !version.is_empty())
            && object
                .get("digest")
                .and_then(Value::as_str)
                .is_some_and(|digest| digest.len() >= 16)
    });
    if valid {
        Ok(())
    } else {
        Err(PlanCompilationError::InvalidInput(format!(
            "Controller-supplied {label} pin is not a versioned capability"
        )))
    }
}

fn capability_by_id<'a>(capabilities: &'a [Value], id: &str) -> Option<&'a Value> {
    capabilities
        .iter()
        .find(|value| value.get("id").and_then(Value::as_str) == Some(id))
}

fn malformed_model_error(error: &ModelError) -> bool {
    matches!(error, ModelError::InvalidResponse(_) | ModelError::Json(_))
}

fn semantic_response_digest(response: &ModelResponse) -> Result<String, PlanCompilationError> {
    canonical_digest(&json!({
        "schema_version": response.schema_version,
        "request_id": response.request_id,
        "content": response.content,
        "structured": response.structured,
        "tool_calls": response.tool_calls,
        "finish_reason": response.finish_reason,
        "usage": response.usage,
    }))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, PlanCompilationError> {
    let raw = serde_json::to_value(value)?;
    let bytes = serde_json::to_vec(&canonicalize(&raw))?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

fn stable_id(prefix: &str, digest: &str) -> String {
    let hash = sha256_hex(digest.as_bytes());
    format!("{prefix}.{}", &hash[..20])
}

fn sanitize_id_fragment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
