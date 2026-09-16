//! Bounded, deterministic context packets over exact current and routed evidence.
//!
//! This crate deliberately does not own repository truth, model state, or
//! semantic retrieval. It projects already-governed C0-C3 facts into a small,
//! stable weak-model packet and records reproducible token accounting.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sovereign_evidence::ToolEvidence;
use sovereign_model::{
    ExternalIntelligenceError, ExternalIntelligenceRequest, ExternalIntelligenceResponse,
};
pub use sovereign_policy::{TrustLabel, TrustLevel, TrustSource};
use sovereign_repo::{ExactDiffEvidence, ExactFileEvidence, ExactSearchHit, InstructionDocument};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};

mod memory;
mod routing;
mod telemetry;

pub use memory::MemoryHistoryProvider;
pub use routing::{
    Channel, ChannelResult, ContextLevelPolicy, DiffResult, EvidenceChannelLink, FailureHistoryKey,
    HistoryProvider, RepositoryRetrievalBackend, RetrievalBackend, RetrievalIntent,
    RetrievalOutcome, RetrievalRouter, RetrievalTrace, RouteBoundFact, RouteStep, StopCondition,
};
pub use telemetry::{
    AccountedTokens, AttemptContextMetrics, AttemptOutcomeFacts, ContextTelemetry,
    EvidenceUseFacts, MemoryTelemetryFacts, MetricRatio, ProviderTokenUsage, RetrievalRouteKind,
    RouteContextMetrics, TokenAccountingSource, ToolCompressionFact,
};

/// Progressive context levels implemented through M2; broader semantic/project-plan levels remain
/// outside this crate's current routing surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextLevel {
    C0,
    C1,
    C2,
    C3,
}

/// Stable packet section order for weak local models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketSection {
    ControllerPrefix,
    TaskContract,
    CurrentState,
    DirectEvidence,
    RoutedExpansion,
    ToolEvidence,
    OutputSchema,
}

/// Typed context item kinds used for selection, accounting, and audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ControllerPrefix,
    ToolSchema,
    TaskContract,
    CurrentState,
    SourceSlice,
    SearchHit,
    Instruction,
    Diff,
    RoutedExpansion,
    ToolSynopsis,
    FailureSynopsis,
    ExternalAdvisory,
    Verification,
    OutputSchema,
    PriorAttemptTranscript,
    RawToolLog,
    FullRepository,
    HiddenReasoning,
}

/// Legacy coarse provenance class retained for compatibility and routing metrics.
///
/// Security-sensitive ingress trust is carried separately by [`TrustLabel`]. Neither field grants
/// authority; policy, permissions and Controller state live outside model-visible context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    Controller,
    Repository,
    Tool,
    Verification,
    Derived,
    Untrusted,
}

/// Handle for deliberately expanding evidence without rerunning its producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpansionHandle {
    pub source_uri: String,
    pub source_digest: String,
    pub offset: u64,
    pub retained_length: u64,
    pub total_length: u64,
}

/// One typed fact selected (or considered) for a context packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub evidence_id: String,
    pub section: PacketSection,
    pub level: ContextLevel,
    pub kind: EvidenceKind,
    pub source_uri: String,
    pub repository_id: Option<String>,
    pub source_digest: String,
    pub content_digest: String,
    pub locator: Option<String>,
    pub provenance: String,
    pub trust_class: TrustClass,
    pub trust_label: TrustLabel,
    pub routing_reason: String,
    pub token_cost: u32,
    pub text: String,
    pub expansion_handle: Option<ExpansionHandle>,
    pub relevant: bool,
    pub implicated: bool,
    pub reused: bool,
}

impl EvidenceItem {
    /// Builds a typed item and computes its immutable content digest.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: impl Into<String>,
        section: PacketSection,
        level: ContextLevel,
        kind: EvidenceKind,
        source_uri: impl Into<String>,
        source_digest: impl Into<String>,
        provenance: impl Into<String>,
        trust_class: TrustClass,
        routing_reason: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        let text = text.into();
        let trust_label = legacy_trust_label(kind, trust_class);
        Self {
            evidence_id: evidence_id.into(),
            section,
            level,
            kind,
            source_uri: source_uri.into(),
            repository_id: None,
            source_digest: source_digest.into(),
            content_digest: sha256_prefixed(text.as_bytes()),
            locator: None,
            provenance: provenance.into(),
            trust_class,
            trust_label,
            routing_reason: routing_reason.into(),
            token_cost: 0,
            text,
            expansion_handle: None,
            relevant: true,
            implicated: false,
            reused: false,
        }
    }

    #[must_use]
    pub fn with_repository(mut self, repository_id: impl Into<String>) -> Self {
        self.repository_id = Some(repository_id.into());
        self
    }

    #[must_use]
    pub fn with_locator(mut self, locator: impl Into<String>) -> Self {
        self.locator = Some(locator.into());
        self
    }

    #[must_use]
    pub const fn with_relevance(mut self, relevant: bool) -> Self {
        self.relevant = relevant;
        self
    }

    #[must_use]
    pub const fn with_implicated(mut self, implicated: bool) -> Self {
        self.implicated = implicated;
        self
    }

    #[must_use]
    pub const fn with_reused(mut self, reused: bool) -> Self {
        self.reused = reused;
        self
    }

    /// Replaces the descriptive ingress trust label. Context construction still normalizes any
    /// caller-provided governed/controller label outside mandatory C0, so this cannot mint policy
    /// authority.
    #[must_use]
    pub const fn with_trust_label(mut self, trust_label: TrustLabel) -> Self {
        self.trust_label = trust_label;
        self
    }

    #[must_use]
    pub fn with_expansion_handle(mut self, handle: ExpansionHandle) -> Self {
        self.expansion_handle = Some(handle);
        self
    }

    /// Converts exact current-file evidence into a C1 source item.
    #[must_use]
    pub fn from_exact_file(evidence: &ExactFileEvidence, routing_reason: &str) -> Self {
        Self::new(
            format!(
                "file:{}:{}",
                evidence.repository_id,
                evidence.relative_path.display()
            ),
            PacketSection::DirectEvidence,
            ContextLevel::C1,
            EvidenceKind::SourceSlice,
            format!(
                "repo://{}/{}",
                evidence.repository_id,
                evidence.relative_path.display()
            ),
            evidence.digest.clone(),
            "exact_path",
            TrustClass::Repository,
            routing_reason,
            evidence.content.clone(),
        )
        .with_repository(evidence.repository_id.clone())
        .with_locator(format!("path:{}", evidence.relative_path.display()))
        .with_trust_label(untrusted_label(TrustSource::Source))
    }

    /// Converts one bounded exact-search hit into C1 evidence.
    #[must_use]
    pub fn from_search_hit(hit: &ExactSearchHit, routing_reason: &str) -> Self {
        Self::new(
            format!(
                "search:{}:{}:{}",
                hit.repository_id,
                hit.relative_path.display(),
                hit.line_number
            ),
            PacketSection::DirectEvidence,
            ContextLevel::C1,
            EvidenceKind::SearchHit,
            format!(
                "repo://{}/{}",
                hit.repository_id,
                hit.relative_path.display()
            ),
            hit.source_digest.clone(),
            "exact_literal_search",
            TrustClass::Repository,
            routing_reason,
            hit.line.clone(),
        )
        .with_repository(hit.repository_id.clone())
        .with_locator(format!("line:{}", hit.line_number))
        .with_trust_label(untrusted_label(TrustSource::Source))
    }

    /// Converts scoped repository instructions to C1 evidence.
    #[must_use]
    pub fn from_instruction(
        repository_id: &str,
        instruction: &InstructionDocument,
        routing_reason: &str,
    ) -> Self {
        Self::new(
            format!(
                "instruction:{repository_id}:{}",
                instruction.relative_path.display()
            ),
            PacketSection::DirectEvidence,
            ContextLevel::C1,
            EvidenceKind::Instruction,
            format!(
                "repo://{repository_id}/{}",
                instruction.relative_path.display()
            ),
            instruction.digest.clone(),
            "scoped_instruction",
            TrustClass::Repository,
            routing_reason,
            instruction.content.clone(),
        )
        .with_repository(repository_id.to_owned())
        .with_locator(format!("path:{}", instruction.relative_path.display()))
        .with_trust_label(untrusted_label(TrustSource::RepositoryInstruction))
    }

    /// Converts the exact current tracked diff into C1 evidence.
    #[must_use]
    pub fn from_diff(diff: &ExactDiffEvidence, routing_reason: &str) -> Self {
        Self::new(
            format!("diff:{}", diff.repository_id),
            PacketSection::DirectEvidence,
            ContextLevel::C1,
            EvidenceKind::Diff,
            format!("git://{}/working-diff", diff.repository_id),
            diff.digest.clone(),
            "git_diff",
            TrustClass::Repository,
            routing_reason,
            diff.content.clone(),
        )
        .with_repository(diff.repository_id.clone())
        .with_implicated(true)
        .with_trust_label(untrusted_label(TrustSource::Source))
    }

    /// Converts retained M1 `ToolEvidence` into its compact synopsis only. Raw
    /// tool bytes remain in CAS and are reachable solely through the handle.
    #[must_use]
    pub fn from_tool_evidence(evidence: &ToolEvidence, routing_reason: &str) -> Self {
        let kind = if evidence.failure_signature.is_some() {
            EvidenceKind::FailureSynopsis
        } else {
            EvidenceKind::ToolSynopsis
        };
        Self::new(
            format!(
                "tool:{}:{}",
                evidence.action_id, evidence.synopsis_artifact_digest
            ),
            PacketSection::ToolEvidence,
            ContextLevel::C1,
            kind,
            format!("cas://{}", evidence.synopsis_artifact_digest),
            evidence.synopsis_artifact_digest.clone(),
            format!(
                "tool_evidence:{}:v{}",
                evidence.compressor_id, evidence.compressor_version
            ),
            TrustClass::Tool,
            routing_reason,
            evidence.synopsis.clone(),
        )
        .with_expansion_handle(ExpansionHandle {
            source_uri: format!("cas://{}", evidence.raw_artifact_digest),
            source_digest: evidence.raw_artifact_digest.clone(),
            offset: 0,
            retained_length: evidence.retained_bytes,
            total_length: evidence.post_ingress_bytes,
        })
        .with_implicated(evidence.failure_signature.is_some())
        .with_trust_label(untrusted_label(TrustSource::ToolOutput))
    }

    /// Imports one optional external-model response as untrusted advisory evidence.
    ///
    /// Provider/model/version identity and full request/response digests are retained in provenance.
    /// The returned item deliberately carries no tool-schema role and no expansion handle.
    ///
    /// # Errors
    /// Returns [`ExternalIntelligenceError`] when request/response identity is invalid or either
    /// contract cannot be serialized for deterministic provenance hashing.
    pub fn from_external_model(
        request: &ExternalIntelligenceRequest,
        response: &ExternalIntelligenceResponse,
        routing_reason: &str,
    ) -> Result<Self, ExternalIntelligenceError> {
        response.validate_for(request)?;
        let request_bytes = serde_json::to_vec(request).map_err(|error| {
            ExternalIntelligenceError::invalid_contract(format!(
                "cannot serialize external intelligence request for provenance: {error}"
            ))
        })?;
        let response_bytes = serde_json::to_vec(response).map_err(|error| {
            ExternalIntelligenceError::invalid_response(format!(
                "cannot serialize external intelligence response for provenance: {error}"
            ))
        })?;
        let request_digest = sha256_prefixed(&request_bytes);
        let response_digest = sha256_prefixed(&response_bytes);
        Ok(Self::new(
            format!(
                "external-model:{}:{}",
                response.provider_id, response.request_id
            ),
            PacketSection::RoutedExpansion,
            ContextLevel::C3,
            EvidenceKind::ExternalAdvisory,
            format!(
                "external-model://{}/{}/{}",
                response.provider_id, response.model_id, response.model_version
            ),
            response_digest.clone(),
            format!(
                "external_model;provider={};model={};version={};request_digest={request_digest};response_digest={response_digest}",
                response.provider_id, response.model_id, response.model_version
            ),
            TrustClass::Untrusted,
            routing_reason,
            response.content.clone(),
        )
        .with_locator(format!("request_id:{}", response.request_id))
        .with_implicated(true)
        .with_trust_label(untrusted_label(TrustSource::ExternalModel)))
    }
}

/// Token ceilings for one bounded weak-model packet. Ceilings are not fill targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBudget {
    pub max_input_tokens: u32,
    pub c0_tokens: u32,
    pub tool_schema_tokens: u32,
    pub c1_tokens: u32,
    pub routed_expansion_tokens: u32,
    pub tool_failure_tokens: u32,
    pub serialization_reserve_tokens: u32,
}

impl ContextBudget {
    /// Default 8k weak-model profile from the frozen architecture.
    #[must_use]
    pub const fn m1_8k() -> Self {
        Self {
            max_input_tokens: 8_000,
            c0_tokens: 1_000,
            tool_schema_tokens: 800,
            c1_tokens: 3_200,
            routed_expansion_tokens: 1_500,
            tool_failure_tokens: 1_000,
            serialization_reserve_tokens: 500,
        }
    }

    fn validate(self) -> Result<(), ContextError> {
        let allocated = self
            .c0_tokens
            .saturating_add(self.tool_schema_tokens)
            .saturating_add(self.c1_tokens)
            .saturating_add(self.routed_expansion_tokens)
            .saturating_add(self.tool_failure_tokens)
            .saturating_add(self.serialization_reserve_tokens);
        if self.max_input_tokens == 0 || allocated > self.max_input_tokens {
            return Err(ContextError::InvalidBudget {
                allocated,
                maximum: self.max_input_tokens,
            });
        }
        Ok(())
    }
}

/// Invocation-specific selection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextMode {
    Implementation,
    Repair,
    Reviewer,
    Verifier,
}

/// Required canonical inputs plus already-routed candidate evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPacketInput {
    pub controller_prefix: String,
    pub task_contract: String,
    pub current_state: String,
    /// Tool schemas already validated and authorized for this invocation.
    /// Generic candidate evidence cannot grant itself tool-schema visibility.
    pub authorized_tool_schemas: Vec<EvidenceItem>,
    pub candidates: Vec<EvidenceItem>,
    pub output_schema: String,
}

/// Reproducible per-packet token accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextMetrics {
    pub tokenizer_id: String,
    pub candidate_tokens_before_dedupe: u32,
    pub evidence_candidate_tokens_before_dedupe: u32,
    pub selected_tokens_after_dedupe: u32,
    pub duplicate_tokens_removed: u32,
    pub tokens_by_level: BTreeMap<String, u32>,
    pub tokens_by_kind: BTreeMap<String, u32>,
    pub tokens_by_section: BTreeMap<String, u32>,
    pub stable_prefix_tokens: u32,
    pub reused_evidence_tokens: u32,
    pub tool_schema_tokens: u32,
    pub final_serialized_input_tokens: u32,
}

/// Stable, typed context packet sent to the model backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPacket {
    pub schema: String,
    pub mode: ContextMode,
    pub budget: ContextBudget,
    pub items: Vec<EvidenceItem>,
    pub metrics: ContextMetrics,
    pub serialized_input: String,
}

/// Failure-focused M1 repair packet. This is a bounded projection over the same immutable
/// task contract; it never carries a prior-attempt transcript or authority of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairPacket {
    pub schema_version: u32,
    pub plan_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub task_id: String,
    pub task_contract_digest: String,
    pub acceptance_contract_digest: String,
    pub prior_attempt_id: String,
    pub failure_signature: String,
    pub failure_record_digest: String,
    pub failure_evidence_refs: Vec<String>,
    pub context: ContextPacket,
}

/// Inputs used to construct one repair packet through the canonical context planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPacketInput {
    pub plan_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub task_id: String,
    pub task_contract_digest: String,
    pub acceptance_contract_digest: String,
    pub prior_attempt_id: String,
    pub failure_signature: String,
    pub failure_record_digest: String,
    pub failure_evidence_refs: Vec<String>,
    pub controller_prefix: String,
    pub task_contract: String,
    pub current_state: String,
    /// Tool schemas already validated and authorized for this repair invocation.
    pub authorized_tool_schemas: Vec<EvidenceItem>,
    pub candidates: Vec<EvidenceItem>,
    pub output_schema: String,
}

/// Deterministic token counter interface. M1 ships a pinned local fallback;
/// model-provider authoritative usage may replace it at the integration layer.
pub trait TokenCounter {
    fn tokenizer_id(&self) -> &'static str;
    fn count(&self, text: &str) -> u32;
}

/// Pinned zero-dependency local accounting fallback: ceil(UTF-8 bytes / 4).
#[derive(Debug, Clone, Copy, Default)]
pub struct Utf8FourByteTokenCounter;

impl TokenCounter for Utf8FourByteTokenCounter {
    fn tokenizer_id(&self) -> &'static str {
        "utf8-ceil4-v1"
    }

    fn count(&self, text: &str) -> u32 {
        let bytes = u32::try_from(text.len()).unwrap_or(u32::MAX);
        bytes.saturating_add(3) / 4
    }
}

/// Context planning failures are deterministic and fail closed for mandatory C0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    InvalidBudget { allocated: u32, maximum: u32 },
    RequiredC0TooLarge { required: u32, maximum: u32 },
    FinalPacketTooLarge { actual: u32, maximum: u32 },
}

impl Display for ContextError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBudget { allocated, maximum } => write!(
                f,
                "context budget allocations {allocated} exceed max input {maximum}"
            ),
            Self::RequiredC0TooLarge { required, maximum } => write!(
                f,
                "required C0/controller/output-schema tokens {required} exceed C0 ceiling {maximum}"
            ),
            Self::FinalPacketTooLarge { actual, maximum } => write!(
                f,
                "serialized context packet tokens {actual} exceed max input {maximum}"
            ),
        }
    }
}

impl Error for ContextError {}

/// Deterministic projection builder. It does not retrieve broadly or backfill
/// unused budgets with unrelated evidence.
#[derive(Debug, Clone)]
pub struct ContextPlanner<C = Utf8FourByteTokenCounter> {
    counter: C,
}

impl Default for ContextPlanner<Utf8FourByteTokenCounter> {
    fn default() -> Self {
        Self {
            counter: Utf8FourByteTokenCounter,
        }
    }
}

impl<C: TokenCounter> ContextPlanner<C> {
    #[must_use]
    pub const fn new(counter: C) -> Self {
        Self { counter }
    }

    /// Builds one bounded packet in stable weak-model order.
    ///
    /// # Errors
    /// Returns [`ContextError`] if mandatory C0 cannot fit or the final stable
    /// serialization exceeds the global packet ceiling.
    #[allow(clippy::too_many_lines)]
    pub fn build(
        &self,
        mode: ContextMode,
        budget: ContextBudget,
        input: ContextPacketInput,
    ) -> Result<ContextPacket, ContextError> {
        budget.validate()?;

        let mut prefix = required_item(
            "controller.prefix",
            PacketSection::ControllerPrefix,
            EvidenceKind::ControllerPrefix,
            "controller://prefix",
            &input.controller_prefix,
        );
        let mut contract = required_item(
            "task.contract",
            PacketSection::TaskContract,
            EvidenceKind::TaskContract,
            "plan://active-task",
            &input.task_contract,
        );
        let mut state = required_item(
            "controller.current-state",
            PacketSection::CurrentState,
            EvidenceKind::CurrentState,
            "controller://current-state",
            &input.current_state,
        );
        let mut output_schema = required_item(
            "proposal.output-schema",
            PacketSection::OutputSchema,
            EvidenceKind::OutputSchema,
            "schema://requested-proposal",
            &input.output_schema,
        );
        for item in [&mut prefix, &mut contract, &mut state, &mut output_schema] {
            item.token_cost = self.counter.count(&item.text);
        }
        let required_c0 = prefix
            .token_cost
            .saturating_add(contract.token_cost)
            .saturating_add(state.token_cost)
            .saturating_add(output_schema.token_cost);
        if required_c0 > budget.c0_tokens {
            return Err(ContextError::RequiredC0TooLarge {
                required: required_c0,
                maximum: budget.c0_tokens,
            });
        }

        let mut candidates = input
            .candidates
            .into_iter()
            .map(normalize_candidate_trust)
            .filter(|item| {
                item.kind != EvidenceKind::ToolSchema
                    && item.relevant
                    && allowed_in_mode(mode, item)
            })
            .chain(
                input
                    .authorized_tool_schemas
                    .into_iter()
                    .map(normalize_candidate_trust)
                    .filter(|item| {
                        item.kind == EvidenceKind::ToolSchema
                            && item.relevant
                            && allowed_in_mode(mode, item)
                    }),
            )
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            (left.section, left.kind, &left.evidence_id).cmp(&(
                right.section,
                right.kind,
                &right.evidence_id,
            ))
        });
        let evidence_candidate_tokens = candidates.iter().fold(0_u32, |sum, item| {
            sum.saturating_add(self.counter.count(&item.text))
        });
        let candidate_tokens = required_c0.saturating_add(evidence_candidate_tokens);

        let mut seen = BTreeSet::new();
        let mut deduped = Vec::new();
        let mut duplicate_tokens_removed = 0_u32;
        for item in candidates {
            let tokens = self.counter.count(&item.text);
            if !seen.insert(item.content_digest.clone()) {
                duplicate_tokens_removed = duplicate_tokens_removed.saturating_add(tokens);
                continue;
            }
            deduped.push(item);
        }

        let mut tool_schemas = Vec::new();
        let mut direct = Vec::new();
        let mut routed = Vec::new();
        let mut tool_evidence = Vec::new();
        for item in deduped {
            match item.kind {
                EvidenceKind::ToolSchema => tool_schemas.push(item),
                _ => match item.section {
                    PacketSection::RoutedExpansion => routed.push(item),
                    PacketSection::ToolEvidence => tool_evidence.push(item),
                    _ => direct.push(item),
                },
            }
        }

        let tool_schemas = self.select_bounded(tool_schemas, budget.tool_schema_tokens);
        let direct = self.select_bounded(direct, budget.c1_tokens);
        let routed = self.select_bounded(routed, budget.routed_expansion_tokens);
        let tool_evidence = self.select_bounded(tool_evidence, budget.tool_failure_tokens);

        let mut items = Vec::new();
        items.push(prefix);
        items.extend(tool_schemas);
        items.push(contract);
        items.push(state);
        items.extend(direct);
        items.extend(routed);
        items.extend(tool_evidence);
        items.push(output_schema);

        let serialized_input = serialize_items(&items);
        let final_tokens = self.counter.count(&serialized_input);
        if final_tokens > budget.max_input_tokens {
            return Err(ContextError::FinalPacketTooLarge {
                actual: final_tokens,
                maximum: budget.max_input_tokens,
            });
        }

        let selected_tokens = items
            .iter()
            .fold(0_u32, |sum, item| sum.saturating_add(item.token_cost));
        let mut tokens_by_level = BTreeMap::new();
        let mut tokens_by_kind = BTreeMap::new();
        let mut tokens_by_section = BTreeMap::new();
        let mut stable_prefix_tokens = 0_u32;
        let mut reused_evidence_tokens = 0_u32;
        let mut tool_schema_tokens = 0_u32;
        for item in &items {
            add_tokens(
                &mut tokens_by_level,
                format!("{:?}", item.level).to_ascii_lowercase(),
                item.token_cost,
            );
            add_tokens(
                &mut tokens_by_kind,
                format!("{:?}", item.kind).to_ascii_lowercase(),
                item.token_cost,
            );
            add_tokens(
                &mut tokens_by_section,
                format!("{:?}", item.section).to_ascii_lowercase(),
                item.token_cost,
            );
            if item.section == PacketSection::ControllerPrefix {
                stable_prefix_tokens = stable_prefix_tokens.saturating_add(item.token_cost);
            }
            if item.kind == EvidenceKind::ToolSchema {
                tool_schema_tokens = tool_schema_tokens.saturating_add(item.token_cost);
            }
            if item.reused {
                reused_evidence_tokens = reused_evidence_tokens.saturating_add(item.token_cost);
            }
        }

        Ok(ContextPacket {
            schema: "sovereign-context-packet-v1".to_owned(),
            mode,
            budget,
            items,
            metrics: ContextMetrics {
                tokenizer_id: self.counter.tokenizer_id().to_owned(),
                candidate_tokens_before_dedupe: candidate_tokens,
                evidence_candidate_tokens_before_dedupe: evidence_candidate_tokens,
                selected_tokens_after_dedupe: selected_tokens,
                duplicate_tokens_removed,
                tokens_by_level,
                tokens_by_kind,
                tokens_by_section,
                stable_prefix_tokens,
                reused_evidence_tokens,
                tool_schema_tokens,
                final_serialized_input_tokens: final_tokens,
            },
            serialized_input,
        })
    }

    /// Builds a fresh independent reviewer packet from current typed evidence.
    /// Reviewer mode excludes prior-attempt transcripts, raw tool logs, full
    /// repository payloads, and hidden implementer reasoning by construction.
    ///
    /// # Errors
    /// Returns [`ContextError`] under the same bounded-packet conditions as
    /// [`Self::build`].
    pub fn build_reviewer(
        &self,
        budget: ContextBudget,
        input: ContextPacketInput,
    ) -> Result<ContextPacket, ContextError> {
        self.build(ContextMode::Reviewer, budget, input)
    }

    /// Builds a fresh verifier packet from the same bounded independent-review evidence surface.
    /// Verifier mode is distinct in the typed packet while excluding implementer trajectory, raw
    /// tool logs, and full-repository payloads by construction.
    ///
    /// # Errors
    /// Returns [`ContextError`] under the same bounded-packet conditions as [`Self::build`].
    pub fn build_verifier(
        &self,
        budget: ContextBudget,
        input: ContextPacketInput,
    ) -> Result<ContextPacket, ContextError> {
        self.build(ContextMode::Verifier, budget, input)
    }

    /// Builds a failure-focused packet using the same bounded projection machinery as normal
    /// execution. Repair mode excludes prior-attempt transcript/hidden reasoning and admits only
    /// the current diff, failure evidence, tool schema, and explicitly implicated evidence.
    ///
    /// # Errors
    /// Returns [`ContextError`] when mandatory repair C0 or the final serialized packet exceeds
    /// the supplied budget.
    pub fn build_repair(
        &self,
        budget: ContextBudget,
        input: RepairPacketInput,
    ) -> Result<RepairPacket, ContextError> {
        let context = self.build(
            ContextMode::Repair,
            budget,
            ContextPacketInput {
                controller_prefix: input.controller_prefix,
                task_contract: input.task_contract,
                current_state: input.current_state,
                authorized_tool_schemas: input.authorized_tool_schemas,
                candidates: input.candidates,
                output_schema: input.output_schema,
            },
        )?;
        Ok(RepairPacket {
            schema_version: 1,
            plan_id: input.plan_id,
            plan_revision: input.plan_revision,
            plan_digest: input.plan_digest,
            task_id: input.task_id,
            task_contract_digest: input.task_contract_digest,
            acceptance_contract_digest: input.acceptance_contract_digest,
            prior_attempt_id: input.prior_attempt_id,
            failure_signature: input.failure_signature,
            failure_record_digest: input.failure_record_digest,
            failure_evidence_refs: input.failure_evidence_refs,
            context,
        })
    }

    fn select_bounded(&self, candidates: Vec<EvidenceItem>, ceiling: u32) -> Vec<EvidenceItem> {
        let mut selected = Vec::new();
        let mut remaining = ceiling;
        for mut item in candidates {
            if remaining == 0 {
                break;
            }
            let full_tokens = self.counter.count(&item.text);
            if full_tokens <= remaining {
                item.token_cost = full_tokens;
                remaining -= full_tokens;
                selected.push(item);
                continue;
            }
            let original_len = u64::try_from(item.text.len()).unwrap_or(u64::MAX);
            let truncated = truncate_for_tokens(&item.text, remaining);
            if truncated.is_empty() {
                break;
            }
            let retained_len = u64::try_from(truncated.len()).unwrap_or(u64::MAX);
            if item.expansion_handle.is_none() && item.kind != EvidenceKind::ExternalAdvisory {
                item.expansion_handle = Some(ExpansionHandle {
                    source_uri: item.source_uri.clone(),
                    source_digest: item.source_digest.clone(),
                    offset: 0,
                    retained_length: retained_len,
                    total_length: original_len,
                });
            }
            item.text = truncated;
            item.content_digest = sha256_prefixed(item.text.as_bytes());
            item.token_cost = self.counter.count(&item.text);
            selected.push(item);
            break;
        }
        selected
    }
}

fn required_item(
    id: &str,
    section: PacketSection,
    kind: EvidenceKind,
    source_uri: &str,
    text: &str,
) -> EvidenceItem {
    EvidenceItem::new(
        id,
        section,
        ContextLevel::C0,
        kind,
        source_uri,
        sha256_prefixed(text.as_bytes()),
        "authoritative_controller_state",
        TrustClass::Controller,
        "mandatory_c0",
        text,
    )
    .with_trust_label(TrustLabel::controller())
}

fn legacy_trust_label(kind: EvidenceKind, trust_class: TrustClass) -> TrustLabel {
    match trust_class {
        TrustClass::Controller => TrustLabel::controller(),
        TrustClass::Verification => TrustLabel::verification(),
        TrustClass::Repository => {
            if kind == EvidenceKind::Instruction {
                untrusted_label(TrustSource::RepositoryInstruction)
            } else {
                untrusted_label(TrustSource::Source)
            }
        }
        TrustClass::Tool => {
            if kind == EvidenceKind::ToolSchema {
                untrusted_label(TrustSource::ToolMetadata)
            } else {
                untrusted_label(TrustSource::ToolOutput)
            }
        }
        TrustClass::Derived => TrustLabel::observed_derived(),
        TrustClass::Untrusted if kind == EvidenceKind::ExternalAdvisory => {
            untrusted_label(TrustSource::ExternalModel)
        }
        TrustClass::Untrusted => untrusted_label(TrustSource::Source),
    }
}

fn untrusted_label(source: TrustSource) -> TrustLabel {
    TrustLabel::untrusted(source).unwrap_or_else(|_| TrustLabel::observed_derived())
}

/// Mandatory C0 is constructed by this planner and is the only model-visible context lane that may
/// retain Controller/governed trust. Every caller-supplied candidate is evidence only. Invalid or
/// self-promoted labels are deterministically demoted rather than interpreted as policy.
fn normalize_candidate_trust(mut item: EvidenceItem) -> EvidenceItem {
    if item.kind == EvidenceKind::ExternalAdvisory {
        item.trust_class = TrustClass::Untrusted;
        item.trust_label = untrusted_label(TrustSource::ExternalModel);
        item.expansion_handle = None;
        return item;
    }
    let invalid = item.trust_label.validate().is_err();
    if invalid
        || item.trust_class == TrustClass::Controller
        || item.trust_label.level != TrustLevel::Untrusted
        || matches!(
            item.trust_label.source,
            TrustSource::Controller | TrustSource::GovernedArtifact
        )
    {
        item.trust_class = TrustClass::Untrusted;
        item.trust_label = match item.kind {
            EvidenceKind::Instruction => untrusted_label(TrustSource::RepositoryInstruction),
            EvidenceKind::ToolSchema => untrusted_label(TrustSource::ToolMetadata),
            EvidenceKind::ToolSynopsis
            | EvidenceKind::FailureSynopsis
            | EvidenceKind::RawToolLog => untrusted_label(TrustSource::ToolOutput),
            _ => untrusted_label(TrustSource::Source),
        };
    }
    item
}

fn allowed_in_mode(mode: ContextMode, item: &EvidenceItem) -> bool {
    if matches!(
        item.kind,
        EvidenceKind::PriorAttemptTranscript
            | EvidenceKind::RawToolLog
            | EvidenceKind::FullRepository
            | EvidenceKind::HiddenReasoning
    ) {
        return false;
    }
    match mode {
        ContextMode::Implementation => true,
        ContextMode::Repair => match item.kind {
            EvidenceKind::Diff | EvidenceKind::FailureSynopsis | EvidenceKind::ToolSchema => true,
            EvidenceKind::SourceSlice
            | EvidenceKind::SearchHit
            | EvidenceKind::Instruction
            | EvidenceKind::RoutedExpansion
            | EvidenceKind::ToolSynopsis
            | EvidenceKind::ExternalAdvisory => item.implicated,
            _ => false,
        },
        ContextMode::Reviewer | ContextMode::Verifier => matches!(
            item.kind,
            EvidenceKind::Diff
                | EvidenceKind::SourceSlice
                | EvidenceKind::SearchHit
                | EvidenceKind::Instruction
                | EvidenceKind::Verification
                | EvidenceKind::ToolSchema
        ),
    }
}

fn serialize_items(items: &[EvidenceItem]) -> String {
    let mut output = String::new();
    for item in items {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str("[[");
        output.push_str(section_name(item.section));
        output.push('|');
        output.push_str(kind_name(item.kind));
        output.push('|');
        output.push_str(&item.evidence_id);
        output.push('|');
        output.push_str(item.trust_label.source.as_str());
        output.push('|');
        output.push_str(item.trust_label.level.as_str());
        output.push_str("]]\n");
        output.push_str(&item.text);
    }
    output
}

fn section_name(section: PacketSection) -> &'static str {
    match section {
        PacketSection::ControllerPrefix => "controller_prefix",
        PacketSection::TaskContract => "task_contract",
        PacketSection::CurrentState => "current_state",
        PacketSection::DirectEvidence => "c1_direct_evidence",
        PacketSection::RoutedExpansion => "routed_expansion",
        PacketSection::ToolEvidence => "tool_failure_evidence",
        PacketSection::OutputSchema => "output_schema",
    }
}

fn kind_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::ControllerPrefix => "controller_prefix",
        EvidenceKind::ToolSchema => "tool_schema",
        EvidenceKind::TaskContract => "task_contract",
        EvidenceKind::CurrentState => "current_state",
        EvidenceKind::SourceSlice => "source_slice",
        EvidenceKind::SearchHit => "search_hit",
        EvidenceKind::Instruction => "instruction",
        EvidenceKind::Diff => "diff",
        EvidenceKind::RoutedExpansion => "routed_expansion",
        EvidenceKind::ToolSynopsis => "tool_synopsis",
        EvidenceKind::FailureSynopsis => "failure_synopsis",
        EvidenceKind::ExternalAdvisory => "external_advisory",
        EvidenceKind::Verification => "verification",
        EvidenceKind::OutputSchema => "output_schema",
        EvidenceKind::PriorAttemptTranscript => "prior_attempt_transcript",
        EvidenceKind::RawToolLog => "raw_tool_log",
        EvidenceKind::FullRepository => "full_repository",
        EvidenceKind::HiddenReasoning => "hidden_reasoning",
    }
}

fn add_tokens(map: &mut BTreeMap<String, u32>, key: String, tokens: u32) {
    let entry = map.entry(key).or_default();
    *entry = entry.saturating_add(tokens);
}

fn truncate_for_tokens(value: &str, tokens: u32) -> String {
    let max_bytes = usize::try_from(tokens.saturating_mul(4)).unwrap_or(usize::MAX);
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}
