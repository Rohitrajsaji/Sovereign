#![allow(clippy::too_many_lines)]

use crate::{
    Channel, ContextLevel, ContextPacket, EvidenceItem, EvidenceKind, PacketSection,
    RetrievalTrace, TokenCounter, Utf8FourByteTokenCounter,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const RATIO_SCALE_PPM: u64 = 1_000_000;

/// Stable retrieval taxonomy used by M2 telemetry and later evaluation aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalRouteKind {
    Exact,
    Lexical,
    Symbol,
    Dependency,
    Diff,
    Episodic,
    Semantic,
}

impl RetrievalRouteKind {
    pub const ALL: [Self; 7] = [
        Self::Exact,
        Self::Lexical,
        Self::Symbol,
        Self::Dependency,
        Self::Diff,
        Self::Episodic,
        Self::Semantic,
    ];
}

impl From<Channel> for RetrievalRouteKind {
    fn from(value: Channel) -> Self {
        match value {
            Channel::Exact => Self::Exact,
            Channel::Lexical => Self::Lexical,
            Channel::Symbol => Self::Symbol,
            Channel::Structural => Self::Dependency,
            Channel::Diff => Self::Diff,
            Channel::History => Self::Episodic,
            Channel::Semantic => Self::Semantic,
        }
    }
}

/// Integer ratio with a reproducible fixed-point rendering. A zero denominator is never reported
/// as a synthetic zero rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricRatio {
    pub numerator: u64,
    pub denominator: u64,
    pub parts_per_million: Option<u64>,
}

impl MetricRatio {
    #[must_use]
    pub fn new(numerator: u64, denominator: u64) -> Self {
        Self::conditional(numerator, denominator, true)
    }

    #[must_use]
    pub fn conditional(numerator: u64, denominator: u64, applicable: bool) -> Self {
        let parts_per_million = if applicable && denominator != 0 {
            let scaled = u128::from(numerator).saturating_mul(u128::from(RATIO_SCALE_PPM));
            Some(u64::try_from(scaled / u128::from(denominator)).unwrap_or(u64::MAX))
        } else {
            None
        };
        Self {
            numerator,
            denominator,
            parts_per_million,
        }
    }
}

/// Origin of a model-token count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAccountingSource {
    ProviderAuthoritative,
    PinnedFallback,
}

/// One input or output token count and the tokenizer identity used to obtain it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountedTokens {
    pub tokens: u64,
    pub source: TokenAccountingSource,
    pub tokenizer_id: Option<String>,
}

/// Provider token usage is authoritative when present. Missing sides fall back independently.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProviderTokenUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub tokenizer_id: Option<String>,
}

/// Typed evidence-use reasons. Evidence usage is never inferred by scraping model prose.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvidenceUseFacts {
    pub cited_evidence_ids: BTreeSet<String>,
    pub authorized_action_evidence_ids: BTreeSet<String>,
    pub expanded_evidence_ids: BTreeSet<String>,
    pub verification_evidence_ids: BTreeSet<String>,
    pub failure_evidence_ids: BTreeSet<String>,
    pub raw_drilldown_evidence_ids: BTreeSet<String>,
}

impl EvidenceUseFacts {
    fn used_ids(&self) -> BTreeSet<&str> {
        self.cited_evidence_ids
            .iter()
            .chain(&self.authorized_action_evidence_ids)
            .chain(&self.expanded_evidence_ids)
            .chain(&self.verification_evidence_ids)
            .chain(&self.failure_evidence_ids)
            .map(String::as_str)
            .collect()
    }
}

/// Compression inputs are supplied from already-recorded tool evidence; telemetry never fetches
/// raw artifacts again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCompressionFact {
    pub evidence_id: String,
    pub raw_output_bytes: u64,
    pub synopsis_bytes: u64,
}

/// Optional memory metrics remain zero-denominator/not-applicable throughout M2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MemoryTelemetryFacts {
    pub candidate_count: u64,
    pub conflict_count: u64,
    pub revalidated_count: u64,
}

/// Immutable typed attempt facts consumed by context telemetry after the attempt ends.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttemptOutcomeFacts {
    pub verified_success: bool,
    pub accepted_change_set: bool,
    /// Serialized model output is used only by the pinned token counter when provider usage is
    /// absent. No evidence-use decision is derived from this string.
    pub model_output_for_token_fallback: String,
    pub evidence_use: EvidenceUseFacts,
    pub tool_compression: Vec<ToolCompressionFact>,
    pub memory: MemoryTelemetryFacts,
}

/// Per-route telemetry for one completed model attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteContextMetrics {
    pub attempts: u64,
    pub steps: u64,
    pub candidates: u64,
    pub selected: u64,
    pub injected_items: u64,
    pub injected_tokens: u64,
    pub useful_selected: u64,
    pub stale_rejected: Option<u64>,
    pub refreshes: u64,
    pub expansions: u64,
    pub retrieval_hit_quality: MetricRatio,
}

impl Default for RouteContextMetrics {
    fn default() -> Self {
        Self {
            attempts: 0,
            steps: 0,
            candidates: 0,
            selected: 0,
            injected_items: 0,
            injected_tokens: 0,
            useful_selected: 0,
            stale_rejected: None,
            refreshes: 0,
            expansions: 0,
            retrieval_hit_quality: MetricRatio::conditional(0, 0, false),
        }
    }
}

/// Context/token telemetry v1 for one immutable packet + final retrieval trace + typed outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptContextMetrics {
    pub schema: String,
    pub trace_id: String,
    pub verified_success: bool,
    pub accepted_change_set: bool,
    pub input_tokens: AccountedTokens,
    pub output_tokens: AccountedTokens,
    pub total_model_tokens: u64,
    pub injected_evidence_items: u64,
    pub injected_evidence_tokens: u64,
    pub used_evidence_items: u64,
    pub used_evidence_tokens: u64,
    pub context_precision: MetricRatio,
    pub context_waste: MetricRatio,
    pub duplicate_context_ratio: MetricRatio,
    pub context_reuse: MetricRatio,
    pub cross_attempt_context_carry: MetricRatio,
    pub packet_fill: MetricRatio,
    pub tool_schema_ratio: MetricRatio,
    pub evidence_expansion_rate: MetricRatio,
    pub raw_drilldown_rate: MetricRatio,
    pub tool_compression_ratio: MetricRatio,
    pub memory_conflict_surface_rate: MetricRatio,
    pub memory_revalidation_rate: MetricRatio,
    pub retrieval_attempts: u64,
    pub semantic_escalation_rate: MetricRatio,
    pub semantic_incremental_hit_rate: MetricRatio,
    pub max_context_level: ContextLevel,
    pub routes: BTreeMap<RetrievalRouteKind, RouteContextMetrics>,
}

/// Pure telemetry projector. It has no repository/index/history handles and therefore cannot
/// re-query retrieval sources while computing attempt metrics.
#[derive(Debug, Clone)]
pub struct ContextTelemetry<C = Utf8FourByteTokenCounter> {
    counter: C,
}

impl Default for ContextTelemetry<Utf8FourByteTokenCounter> {
    fn default() -> Self {
        Self {
            counter: Utf8FourByteTokenCounter,
        }
    }
}

impl<C: TokenCounter> ContextTelemetry<C> {
    #[must_use]
    pub const fn new(counter: C) -> Self {
        Self { counter }
    }

    #[must_use]
    pub fn measure(
        &self,
        packet: &ContextPacket,
        trace: &RetrievalTrace,
        provider_usage: &ProviderTokenUsage,
        outcome: &AttemptOutcomeFacts,
    ) -> AttemptContextMetrics {
        let input_tokens = account_tokens(
            provider_usage.input_tokens,
            provider_usage.tokenizer_id.as_deref(),
            &self.counter,
            &packet.serialized_input,
        );
        let output_tokens = account_tokens(
            provider_usage.output_tokens,
            provider_usage.tokenizer_id.as_deref(),
            &self.counter,
            &outcome.model_output_for_token_fallback,
        );
        let total_model_tokens = input_tokens.tokens.saturating_add(output_tokens.tokens);

        let injected = packet
            .items
            .iter()
            .filter(|item| is_injected_evidence(item))
            .fold(BTreeMap::<&str, &EvidenceItem>::new(), |mut items, item| {
                items.entry(item.evidence_id.as_str()).or_insert(item);
                items
            });
        let injected_evidence_items = usize_u64(injected.len());
        let injected_evidence_tokens = injected.values().fold(0_u64, |sum, item| {
            sum.saturating_add(u64::from(item.token_cost))
        });

        let used_ids = outcome.evidence_use.used_ids();
        let used_evidence_items = injected.keys().filter(|id| used_ids.contains(**id)).count();
        let used_evidence_tokens = injected
            .iter()
            .filter(|(id, _)| used_ids.contains(**id))
            .fold(0_u64, |sum, (_, item)| {
                sum.saturating_add(u64::from(item.token_cost))
            });
        let wasted_tokens = injected_evidence_tokens.saturating_sub(used_evidence_tokens);

        let reused_evidence_tokens = injected.values().fold(0_u64, |sum, item| {
            if item.reused {
                sum.saturating_add(u64::from(item.token_cost))
            } else {
                sum
            }
        });

        let expanded_items = outcome
            .evidence_use
            .expanded_evidence_ids
            .iter()
            .filter(|id| injected.contains_key(id.as_str()))
            .count();
        let raw_drilldown_items = outcome
            .evidence_use
            .raw_drilldown_evidence_ids
            .iter()
            .filter(|id| injected.contains_key(id.as_str()))
            .count();

        let (compression_raw, compression_synopsis) = compression_bytes(outcome, &injected);
        let mut routes = route_step_metrics(trace, outcome.verified_success);
        let owner = route_owners(trace, &injected);
        for (evidence_id, route) in &owner {
            let Some(item) = injected.get(evidence_id.as_str()) else {
                continue;
            };
            let route_metrics = routes.entry(*route).or_default();
            route_metrics.injected_items = route_metrics.injected_items.saturating_add(1);
            route_metrics.injected_tokens = route_metrics
                .injected_tokens
                .saturating_add(u64::from(item.token_cost));
            if outcome.verified_success && used_ids.contains(evidence_id.as_str()) {
                route_metrics.useful_selected = route_metrics.useful_selected.saturating_add(1);
            }
        }
        for metrics in routes.values_mut() {
            metrics.retrieval_hit_quality = MetricRatio::conditional(
                metrics.useful_selected,
                metrics.selected,
                outcome.verified_success,
            );
        }

        let retrieval_attempts = u64::from(routes.values().any(|metrics| metrics.attempts != 0));
        let semantic_attempted = routes
            .get(&RetrievalRouteKind::Semantic)
            .is_some_and(|metrics| metrics.attempts != 0);
        let semantic_escalation_rate =
            MetricRatio::new(u64::from(semantic_attempted), retrieval_attempts);

        let semantic_ids = owner
            .iter()
            .filter_map(|(id, route)| {
                (*route == RetrievalRouteKind::Semantic).then_some(id.as_str())
            })
            .collect::<BTreeSet<_>>();
        let cheaper_digests = owner
            .iter()
            .filter(|(_, route)| **route != RetrievalRouteKind::Semantic)
            .filter_map(|(id, _)| {
                injected
                    .get(id.as_str())
                    .map(|item| item.content_digest.as_str())
            })
            .collect::<BTreeSet<_>>();
        let semantic_incremental_useful = semantic_ids
            .iter()
            .filter(|id| {
                outcome.verified_success
                    && used_ids.contains(**id)
                    && injected
                        .get(**id)
                        .is_some_and(|item| !cheaper_digests.contains(item.content_digest.as_str()))
            })
            .count();

        let max_context_level = packet
            .items
            .iter()
            .map(|item| item.level)
            .max()
            .unwrap_or(ContextLevel::C0);

        AttemptContextMetrics {
            schema: "sovereign-context-metrics-v1".to_owned(),
            trace_id: trace.trace_id.clone(),
            verified_success: outcome.verified_success,
            accepted_change_set: outcome.accepted_change_set,
            input_tokens,
            output_tokens,
            total_model_tokens,
            injected_evidence_items,
            injected_evidence_tokens,
            used_evidence_items: usize_u64(used_evidence_items),
            used_evidence_tokens,
            context_precision: MetricRatio::new(used_evidence_tokens, injected_evidence_tokens),
            context_waste: MetricRatio::new(wasted_tokens, injected_evidence_tokens),
            duplicate_context_ratio: MetricRatio::new(
                u64::from(packet.metrics.duplicate_tokens_removed),
                u64::from(packet.metrics.candidate_tokens_before_dedupe),
            ),
            context_reuse: MetricRatio::new(reused_evidence_tokens, injected_evidence_tokens),
            cross_attempt_context_carry: MetricRatio::new(
                reused_evidence_tokens,
                injected_evidence_tokens,
            ),
            packet_fill: MetricRatio::new(
                u64::from(packet.metrics.final_serialized_input_tokens),
                u64::from(packet.budget.max_input_tokens),
            ),
            tool_schema_ratio: MetricRatio::new(
                u64::from(packet.metrics.tool_schema_tokens),
                u64::from(packet.metrics.final_serialized_input_tokens),
            ),
            evidence_expansion_rate: MetricRatio::new(
                usize_u64(expanded_items),
                injected_evidence_items,
            ),
            raw_drilldown_rate: MetricRatio::new(
                usize_u64(raw_drilldown_items),
                injected_evidence_items,
            ),
            tool_compression_ratio: MetricRatio::new(compression_raw, compression_synopsis),
            memory_conflict_surface_rate: MetricRatio::new(
                outcome.memory.conflict_count,
                outcome.memory.candidate_count,
            ),
            memory_revalidation_rate: MetricRatio::new(
                outcome.memory.revalidated_count,
                outcome.memory.candidate_count,
            ),
            retrieval_attempts,
            semantic_escalation_rate,
            semantic_incremental_hit_rate: MetricRatio::conditional(
                usize_u64(semantic_incremental_useful),
                usize_u64(semantic_ids.len()),
                outcome.verified_success,
            ),
            max_context_level,
            routes,
        }
    }
}

fn account_tokens<C: TokenCounter>(
    provider_tokens: Option<u64>,
    provider_tokenizer_id: Option<&str>,
    counter: &C,
    fallback_text: &str,
) -> AccountedTokens {
    provider_tokens.map_or_else(
        || AccountedTokens {
            tokens: u64::from(counter.count(fallback_text)),
            source: TokenAccountingSource::PinnedFallback,
            tokenizer_id: Some(counter.tokenizer_id().to_owned()),
        },
        |tokens| AccountedTokens {
            tokens,
            source: TokenAccountingSource::ProviderAuthoritative,
            tokenizer_id: provider_tokenizer_id.map(str::to_owned),
        },
    )
}

fn is_injected_evidence(item: &EvidenceItem) -> bool {
    item.level != ContextLevel::C0
        && item.kind != EvidenceKind::ToolSchema
        && matches!(
            item.section,
            PacketSection::DirectEvidence
                | PacketSection::RoutedExpansion
                | PacketSection::ToolEvidence
        )
}

fn is_actual_retrieval_step(step: &crate::RouteStep) -> bool {
    step.freshness_checked
        || step.candidate_count != 0
        || step.selected_count != 0
        || step.source_snapshot.is_some()
        || step.source_fingerprint.is_some()
        || step.bound.is_some()
}

fn route_step_metrics(
    trace: &RetrievalTrace,
    verified_success: bool,
) -> BTreeMap<RetrievalRouteKind, RouteContextMetrics> {
    let mut routes = RetrievalRouteKind::ALL
        .into_iter()
        .map(|kind| (kind, RouteContextMetrics::default()))
        .collect::<BTreeMap<_, _>>();
    let mut actual_seen = BTreeMap::<RetrievalRouteKind, bool>::new();
    let mut stale_known = BTreeMap::<RetrievalRouteKind, Option<u64>>::new();

    for step in &trace.route {
        let kind = RetrievalRouteKind::from(step.channel);
        let metrics = routes.entry(kind).or_default();
        metrics.steps = metrics.steps.saturating_add(1);
        metrics.candidates = metrics
            .candidates
            .saturating_add(usize_u64(step.candidate_count));
        metrics.selected = metrics
            .selected
            .saturating_add(usize_u64(step.selected_count));
        metrics.refreshes = metrics
            .refreshes
            .saturating_add(usize_u64(step.source_refresh_count));

        if !is_actual_retrieval_step(step) {
            continue;
        }
        actual_seen.insert(kind, true);
        let next_stale = match (
            stale_known.get(&kind).copied().flatten(),
            step.stale_rejected,
        ) {
            (Some(total), Some(value)) => Some(total.saturating_add(usize_u64(value))),
            (None, Some(value)) if !stale_known.contains_key(&kind) => Some(usize_u64(value)),
            (_, None) | (None, Some(_)) => None,
        };
        stale_known.insert(kind, next_stale);
    }

    for kind in RetrievalRouteKind::ALL {
        let metrics = routes.entry(kind).or_default();
        metrics.attempts = u64::from(actual_seen.get(&kind).copied().unwrap_or(false));
        metrics.stale_rejected = if metrics.attempts == 0 {
            None
        } else {
            stale_known.get(&kind).copied().flatten()
        };
        metrics.retrieval_hit_quality =
            MetricRatio::conditional(0, metrics.selected, verified_success);
    }
    if let Some(dependency) = routes.get_mut(&RetrievalRouteKind::Dependency) {
        dependency.expansions = usize_u64(trace.expansion_count);
    }
    routes
}

fn route_owners(
    trace: &RetrievalTrace,
    injected: &BTreeMap<&str, &EvidenceItem>,
) -> BTreeMap<String, RetrievalRouteKind> {
    let mut owners = BTreeMap::new();
    for link in &trace.evidence_channels {
        if owners.contains_key(&link.evidence_id) {
            continue;
        }
        let Some(item) = injected.get(link.evidence_id.as_str()) else {
            continue;
        };
        if item.source_digest != link.source_digest || item.content_digest != link.content_digest {
            continue;
        }
        owners.insert(
            link.evidence_id.clone(),
            RetrievalRouteKind::from(link.channel),
        );
    }
    owners
}

fn compression_bytes(
    outcome: &AttemptOutcomeFacts,
    injected: &BTreeMap<&str, &EvidenceItem>,
) -> (u64, u64) {
    let mut facts = outcome.tool_compression.iter().collect::<Vec<_>>();
    facts.sort_by(|left, right| {
        (
            &left.evidence_id,
            left.raw_output_bytes,
            left.synopsis_bytes,
        )
            .cmp(&(
                &right.evidence_id,
                right.raw_output_bytes,
                right.synopsis_bytes,
            ))
    });
    let mut seen = BTreeSet::new();
    facts
        .into_iter()
        .fold((0_u64, 0_u64), |(raw, synopsis), fact| {
            if !injected.contains_key(fact.evidence_id.as_str()) || !seen.insert(&fact.evidence_id)
            {
                return (raw, synopsis);
            }
            (
                raw.saturating_add(fact.raw_output_bytes),
                synopsis.saturating_add(fact.synopsis_bytes),
            )
        })
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
