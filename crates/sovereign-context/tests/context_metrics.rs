use sovereign_context::{
    AttemptOutcomeFacts, Channel, ContextBudget, ContextLevel, ContextMode, ContextPacket,
    ContextPacketInput, ContextPlanner, ContextTelemetry, EvidenceChannelLink, EvidenceItem,
    EvidenceKind, EvidenceUseFacts, MemoryTelemetryFacts, PacketSection, ProviderTokenUsage,
    RetrievalRouteKind, RetrievalTrace, RouteStep, StopCondition, TokenAccountingSource,
    ToolCompressionFact, TrustClass,
};
use std::collections::BTreeSet;

fn evidence(
    id: &str,
    section: PacketSection,
    level: ContextLevel,
    kind: EvidenceKind,
    text: &str,
) -> EvidenceItem {
    EvidenceItem::new(
        id,
        section,
        level,
        kind,
        format!("fixture://{id}"),
        format!("sha256:source:{id}"),
        "fixture",
        TrustClass::Derived,
        "fixture",
        text,
    )
}

fn packet_with_evidence() -> ContextPacket {
    let exact = evidence(
        "exact-1",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        "exact source alpha",
    )
    .with_reused(true);
    let lexical = evidence(
        "lexical-1",
        PacketSection::RoutedExpansion,
        ContextLevel::C2,
        EvidenceKind::SearchHit,
        "lexical beta",
    );
    let duplicate = evidence(
        "duplicate-1",
        PacketSection::RoutedExpansion,
        ContextLevel::C2,
        EvidenceKind::RoutedExpansion,
        "exact source alpha",
    );
    let tool = evidence(
        "tool-1",
        PacketSection::ToolEvidence,
        ContextLevel::C1,
        EvidenceKind::ToolSynopsis,
        "compressed tool synopsis",
    );
    let schema = evidence(
        "schema-1",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::ToolSchema,
        "tool schema body",
    );

    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "controller".to_owned(),
                task_contract: "task contract".to_owned(),
                current_state: "current state".to_owned(),
                candidates: vec![exact, lexical, duplicate, tool, schema],
                output_schema: "output schema".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("packet: {error}"))
}

fn step(channel: Channel, selected_id: &str, stale_rejected: Option<usize>) -> RouteStep {
    RouteStep {
        channel,
        reason: "fixture route".to_owned(),
        candidate_count: 1,
        selected_count: 1,
        candidate_ids: vec![selected_id.to_owned()],
        selected_ids: vec![selected_id.to_owned()],
        freshness_checked: true,
        stale_rejected,
        source_refresh_count: usize::from(channel == Channel::Lexical),
        source_snapshot: Some("snapshot:g1".to_owned()),
        source_fingerprint: Some("sha256:fingerprint".to_owned()),
        bound: None,
    }
}

fn trace_for(packet: &ContextPacket) -> RetrievalTrace {
    let exact = packet
        .items
        .iter()
        .find(|item| item.evidence_id == "exact-1")
        .unwrap_or_else(|| panic!("exact evidence missing"));
    let lexical = packet
        .items
        .iter()
        .find(|item| item.evidence_id == "lexical-1")
        .unwrap_or_else(|| panic!("lexical evidence missing"));
    RetrievalTrace {
        trace_id: "retrieval:fixture".to_owned(),
        route: vec![
            step(Channel::Exact, "exact-1", Some(0)),
            step(Channel::Lexical, "lexical-1", None),
            RouteStep {
                channel: Channel::Semantic,
                reason: "semantic unavailable in M2".to_owned(),
                candidate_count: 0,
                selected_count: 0,
                candidate_ids: Vec::new(),
                selected_ids: Vec::new(),
                freshness_checked: false,
                stale_rejected: None,
                source_refresh_count: 0,
                source_snapshot: None,
                source_fingerprint: None,
                bound: None,
            },
        ],
        candidate_count: 2,
        selected_count: 2,
        evidence_channels: vec![
            EvidenceChannelLink {
                evidence_id: exact.evidence_id.clone(),
                channel: Channel::Exact,
                source_digest: exact.source_digest.clone(),
                content_digest: exact.content_digest.clone(),
            },
            EvidenceChannelLink {
                evidence_id: exact.evidence_id.clone(),
                channel: Channel::Lexical,
                source_digest: exact.source_digest.clone(),
                content_digest: exact.content_digest.clone(),
            },
            EvidenceChannelLink {
                evidence_id: lexical.evidence_id.clone(),
                channel: Channel::Lexical,
                source_digest: lexical.source_digest.clone(),
                content_digest: lexical.content_digest.clone(),
            },
        ],
        freshness_checked: true,
        stale_rejected: None,
        source_refresh_count: 1,
        source_snapshot: Some("snapshot:g1".to_owned()),
        source_fingerprint: Some("sha256:fingerprint".to_owned()),
        expansion_count: 0,
        stop_reason: StopCondition::SemanticUnavailable,
        semantic_available: false,
        semantic_unavailable_reason: Some("semantic retrieval is unavailable in M2".to_owned()),
    }
}

fn success_outcome() -> AttemptOutcomeFacts {
    AttemptOutcomeFacts {
        verified_success: true,
        accepted_change_set: true,
        model_output_for_token_fallback: "fallback output".to_owned(),
        evidence_use: EvidenceUseFacts {
            cited_evidence_ids: BTreeSet::from(["exact-1".to_owned()]),
            authorized_action_evidence_ids: BTreeSet::from(["lexical-1".to_owned()]),
            expanded_evidence_ids: BTreeSet::from(["tool-1".to_owned()]),
            verification_evidence_ids: BTreeSet::from(["exact-1".to_owned()]),
            failure_evidence_ids: BTreeSet::new(),
            raw_drilldown_evidence_ids: BTreeSet::from(["tool-1".to_owned()]),
        },
        tool_compression: vec![ToolCompressionFact {
            evidence_id: "tool-1".to_owned(),
            raw_output_bytes: 1_000,
            synopsis_bytes: 100,
        }],
        memory: MemoryTelemetryFacts::default(),
    }
}

#[test]
fn context_metrics_provider_usage_wins_and_typed_use_is_unique_after_packet_dedupe() {
    let packet = packet_with_evidence();
    let trace = trace_for(&packet);
    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage {
            input_tokens: Some(777),
            output_tokens: None,
            tokenizer_id: Some("provider-tokenizer-v1".to_owned()),
        },
        &success_outcome(),
    );

    assert_eq!(metrics.input_tokens.tokens, 777);
    assert_eq!(
        metrics.input_tokens.source,
        TokenAccountingSource::ProviderAuthoritative
    );
    assert_eq!(
        metrics.output_tokens.source,
        TokenAccountingSource::PinnedFallback
    );
    assert_eq!(
        metrics.output_tokens.tokenizer_id.as_deref(),
        Some("utf8-ceil4-v1")
    );
    assert_eq!(metrics.injected_evidence_items, 3);
    assert_eq!(metrics.used_evidence_items, 3);
    assert_eq!(metrics.context_precision.parts_per_million, Some(1_000_000));
    assert_eq!(metrics.context_waste.parts_per_million, Some(0));
    assert!(metrics.duplicate_context_ratio.numerator > 0);
    assert_eq!(
        metrics.duplicate_context_ratio.denominator,
        u64::from(packet.metrics.candidate_tokens_before_dedupe)
    );
    assert!(metrics.context_reuse.numerator > 0);
    assert_eq!(metrics.cross_attempt_context_carry, metrics.context_reuse);
    assert_eq!(metrics.tool_compression_ratio.numerator, 1_000);
    assert_eq!(metrics.tool_compression_ratio.denominator, 100);
    assert_eq!(metrics.evidence_expansion_rate.numerator, 1);
    assert_eq!(metrics.raw_drilldown_rate.numerator, 1);

    let exact = &metrics.routes[&RetrievalRouteKind::Exact];
    let lexical = &metrics.routes[&RetrievalRouteKind::Lexical];
    assert_eq!(exact.injected_items, 1);
    assert_eq!(exact.useful_selected, 1);
    assert_eq!(lexical.injected_items, 1);
    assert_eq!(lexical.useful_selected, 1);
    assert_eq!(exact.stale_rejected, Some(0));
    assert_eq!(lexical.stale_rejected, None);
    assert_eq!(lexical.refreshes, 1);
    assert_eq!(
        exact
            .injected_tokens
            .saturating_add(lexical.injected_tokens),
        packet
            .items
            .iter()
            .filter(|item| item.evidence_id == "exact-1" || item.evidence_id == "lexical-1")
            .map(|item| u64::from(item.token_cost))
            .sum::<u64>()
    );
}

#[test]
fn context_metrics_semantic_unavailable_is_not_an_attempt_or_escalation() {
    let packet = packet_with_evidence();
    let trace = trace_for(&packet);
    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &success_outcome(),
    );

    let semantic = &metrics.routes[&RetrievalRouteKind::Semantic];
    assert_eq!(semantic.steps, 1);
    assert_eq!(semantic.attempts, 0);
    assert_eq!(semantic.selected, 0);
    assert_eq!(semantic.retrieval_hit_quality.denominator, 0);
    assert_eq!(semantic.retrieval_hit_quality.parts_per_million, None);
    assert_eq!(metrics.semantic_escalation_rate.numerator, 0);
    assert_eq!(metrics.semantic_escalation_rate.denominator, 1);
    assert_eq!(metrics.semantic_escalation_rate.parts_per_million, Some(0));
    assert_eq!(metrics.semantic_incremental_hit_rate.denominator, 0);
    assert_eq!(
        metrics.semantic_incremental_hit_rate.parts_per_million,
        None
    );
}

#[test]
fn context_metrics_history_unavailable_is_not_an_episodic_attempt() {
    let packet = packet_with_evidence();
    let trace = RetrievalTrace {
        trace_id: "retrieval:history-unavailable".to_owned(),
        route: vec![RouteStep {
            channel: Channel::History,
            reason: "history provider absent until M4".to_owned(),
            candidate_count: 0,
            selected_count: 0,
            candidate_ids: Vec::new(),
            selected_ids: Vec::new(),
            freshness_checked: false,
            stale_rejected: None,
            source_refresh_count: 0,
            source_snapshot: None,
            source_fingerprint: None,
            bound: None,
        }],
        candidate_count: 0,
        selected_count: 0,
        evidence_channels: Vec::new(),
        freshness_checked: false,
        stale_rejected: None,
        source_refresh_count: 0,
        source_snapshot: None,
        source_fingerprint: None,
        expansion_count: 0,
        stop_reason: StopCondition::HistoryUnavailable,
        semantic_available: false,
        semantic_unavailable_reason: Some("semantic retrieval is unavailable in M2".to_owned()),
    };
    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &success_outcome(),
    );

    let episodic = &metrics.routes[&RetrievalRouteKind::Episodic];
    assert_eq!(episodic.steps, 1);
    assert_eq!(episodic.attempts, 0);
    assert_eq!(episodic.selected, 0);
    assert_eq!(metrics.retrieval_attempts, 0);
    assert_eq!(metrics.semantic_escalation_rate.denominator, 0);
    assert_eq!(metrics.semantic_escalation_rate.parts_per_million, None);
}

#[test]
fn context_metrics_failed_semantic_evidence_is_not_verified_incremental_value() {
    let packet = packet_with_evidence();
    let mut trace = trace_for(&packet);
    trace.route[1].channel = Channel::Semantic;
    trace.evidence_channels[2].channel = Channel::Semantic;
    let outcome = AttemptOutcomeFacts {
        verified_success: false,
        model_output_for_token_fallback: "failed after semantic evidence".to_owned(),
        evidence_use: EvidenceUseFacts {
            failure_evidence_ids: BTreeSet::from(["lexical-1".to_owned()]),
            ..EvidenceUseFacts::default()
        },
        ..AttemptOutcomeFacts::default()
    };
    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &outcome,
    );

    assert_eq!(metrics.routes[&RetrievalRouteKind::Semantic].attempts, 1);
    assert_eq!(metrics.semantic_escalation_rate.numerator, 1);
    assert_eq!(metrics.semantic_escalation_rate.denominator, 1);
    assert_eq!(metrics.semantic_incremental_hit_rate.numerator, 0);
    assert_eq!(metrics.semantic_incremental_hit_rate.denominator, 1);
    assert_eq!(
        metrics.semantic_incremental_hit_rate.parts_per_million,
        None
    );
}

#[test]
fn context_metrics_medium_fixture_succeeds_without_semantic_and_records_route_tokens() {
    let packet = packet_with_evidence();
    let trace = trace_for(&packet);
    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage {
            input_tokens: Some(640),
            output_tokens: Some(96),
            tokenizer_id: Some("fixture-provider-v1".to_owned()),
        },
        &success_outcome(),
    );

    assert!(metrics.verified_success);
    assert_eq!(metrics.retrieval_attempts, 1);
    assert_eq!(metrics.routes[&RetrievalRouteKind::Semantic].attempts, 0);
    assert_eq!(metrics.semantic_escalation_rate.numerator, 0);
    assert_eq!(metrics.semantic_escalation_rate.denominator, 1);
    assert!(metrics.routes[&RetrievalRouteKind::Exact].injected_tokens > 0);
    assert!(metrics.routes[&RetrievalRouteKind::Lexical].injected_tokens > 0);
    assert!(metrics.injected_evidence_tokens > 0);
    assert_eq!(metrics.total_model_tokens, 736);
    assert!(metrics.packet_fill.denominator > 0);
}

#[test]
fn context_metrics_failed_attempt_keeps_hit_quality_not_applicable_and_zero_denominators_none() {
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "controller".to_owned(),
                task_contract: "task".to_owned(),
                current_state: "state".to_owned(),
                candidates: Vec::new(),
                output_schema: "schema".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("packet: {error}"));
    let trace = RetrievalTrace {
        trace_id: "retrieval:empty".to_owned(),
        route: Vec::new(),
        candidate_count: 0,
        selected_count: 0,
        evidence_channels: Vec::new(),
        freshness_checked: false,
        stale_rejected: None,
        source_refresh_count: 0,
        source_snapshot: None,
        source_fingerprint: None,
        expansion_count: 0,
        stop_reason: StopCondition::NoEvidence,
        semantic_available: false,
        semantic_unavailable_reason: Some("semantic retrieval is unavailable in M2".to_owned()),
    };
    let outcome = AttemptOutcomeFacts {
        verified_success: false,
        model_output_for_token_fallback: "failed".to_owned(),
        ..AttemptOutcomeFacts::default()
    };
    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &outcome,
    );

    assert_eq!(metrics.injected_evidence_tokens, 0);
    assert_eq!(metrics.context_precision.parts_per_million, None);
    assert_eq!(metrics.context_waste.parts_per_million, None);
    assert_eq!(metrics.context_reuse.parts_per_million, None);
    assert_eq!(metrics.tool_compression_ratio.parts_per_million, None);
    assert_eq!(metrics.memory_conflict_surface_rate.parts_per_million, None);
    assert_eq!(metrics.memory_revalidation_rate.parts_per_million, None);
    assert_eq!(metrics.retrieval_attempts, 0);
    assert_eq!(metrics.semantic_escalation_rate.parts_per_million, None);
}

#[test]
fn context_metrics_failed_attempt_with_injected_selection_keeps_hit_quality_none() {
    let packet = packet_with_evidence();
    let trace = trace_for(&packet);
    let outcome = AttemptOutcomeFacts {
        verified_success: false,
        model_output_for_token_fallback: "failed after using exact evidence".to_owned(),
        evidence_use: EvidenceUseFacts {
            failure_evidence_ids: BTreeSet::from(["exact-1".to_owned()]),
            ..EvidenceUseFacts::default()
        },
        ..AttemptOutcomeFacts::default()
    };
    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &outcome,
    );
    let exact = &metrics.routes[&RetrievalRouteKind::Exact];

    assert_eq!(metrics.used_evidence_items, 1);
    assert_eq!(exact.useful_selected, 0);
    assert_eq!(exact.retrieval_hit_quality.numerator, 0);
    assert_eq!(exact.retrieval_hit_quality.denominator, 1);
    assert_eq!(exact.retrieval_hit_quality.parts_per_million, None);
}

#[test]
fn context_metrics_retrieval_hit_quality_uses_route_selected_not_injected_denominator() {
    let packet = packet_with_evidence();
    let mut trace = trace_for(&packet);
    trace.route[0].candidate_count = 2;
    trace.route[0].selected_count = 2;
    trace.route[0]
        .candidate_ids
        .push("exact-dropped".to_owned());
    trace.route[0].selected_ids.push("exact-dropped".to_owned());
    trace.candidate_count = trace.candidate_count.saturating_add(1);
    trace.selected_count = trace.selected_count.saturating_add(1);

    let metrics = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &success_outcome(),
    );
    let exact = &metrics.routes[&RetrievalRouteKind::Exact];

    assert_eq!(exact.selected, 2);
    assert_eq!(exact.injected_items, 1);
    assert_eq!(exact.useful_selected, 1);
    assert_eq!(exact.retrieval_hit_quality.numerator, 1);
    assert_eq!(exact.retrieval_hit_quality.denominator, 2);
    assert_eq!(exact.retrieval_hit_quality.parts_per_million, Some(500_000));
}

#[test]
fn context_metrics_digest_join_rejects_same_id_with_changed_content_and_fallback_is_reproducible() {
    let packet = packet_with_evidence();
    let mut trace = trace_for(&packet);
    trace.evidence_channels[0].content_digest = "sha256:not-the-packet-content".to_owned();
    let outcome = AttemptOutcomeFacts {
        verified_success: true,
        model_output_for_token_fallback: "12345678".to_owned(),
        evidence_use: EvidenceUseFacts {
            cited_evidence_ids: BTreeSet::from(["exact-1".to_owned()]),
            ..EvidenceUseFacts::default()
        },
        ..AttemptOutcomeFacts::default()
    };
    let first = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &outcome,
    );
    let second = ContextTelemetry::default().measure(
        &packet,
        &trace,
        &ProviderTokenUsage::default(),
        &outcome,
    );

    assert_eq!(first, second);
    assert_eq!(
        first.input_tokens.tokens,
        u64::from(packet.metrics.final_serialized_input_tokens)
    );
    assert_eq!(first.output_tokens.tokens, 2);
    assert_eq!(first.routes[&RetrievalRouteKind::Exact].injected_items, 0);
    assert!(
        packet
            .metrics
            .tokens_by_section
            .contains_key("directevidence")
    );
    assert!(packet.metrics.evidence_candidate_tokens_before_dedupe > 0);
}
