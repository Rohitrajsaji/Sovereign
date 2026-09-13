use sovereign_context::{
    AccountedTokens, AttemptContextMetrics, ContextLevel, MetricRatio, RetrievalRouteKind,
    RouteContextMetrics, TokenAccountingSource,
};
use sovereign_eval::{EvaluationAttemptRecord, aggregate_context_metrics};
use std::collections::BTreeMap;

fn route_metrics(
    trace_counts: (u64, u64, u64, u64),
    injected: (u64, u64, u64),
    stale_rejected: Option<u64>,
) -> RouteContextMetrics {
    let (attempts, steps, candidates, selected) = trace_counts;
    let (injected_items, injected_tokens, useful_selected) = injected;
    RouteContextMetrics {
        attempts,
        steps,
        candidates,
        selected,
        injected_items,
        injected_tokens,
        useful_selected,
        stale_rejected,
        refreshes: u64::from(attempts != 0),
        expansions: 0,
        retrieval_hit_quality: MetricRatio::new(useful_selected, injected_items),
    }
}

fn attempt_metrics(
    trace_id: &str,
    total_model_tokens: u64,
    verified_success: bool,
    accepted_change_set: bool,
    level: ContextLevel,
    exact: RouteContextMetrics,
    lexical: RouteContextMetrics,
) -> AttemptContextMetrics {
    let mut routes = RetrievalRouteKind::ALL
        .into_iter()
        .map(|kind| (kind, RouteContextMetrics::default()))
        .collect::<BTreeMap<_, _>>();
    routes.insert(RetrievalRouteKind::Exact, exact);
    routes.insert(RetrievalRouteKind::Lexical, lexical);
    let semantic = routes
        .get_mut(&RetrievalRouteKind::Semantic)
        .unwrap_or_else(|| panic!("semantic route missing"));
    semantic.steps = 1;

    AttemptContextMetrics {
        schema: "sovereign-context-metrics-v1".to_owned(),
        trace_id: trace_id.to_owned(),
        verified_success,
        accepted_change_set,
        input_tokens: AccountedTokens {
            tokens: total_model_tokens.saturating_sub(10),
            source: TokenAccountingSource::ProviderAuthoritative,
            tokenizer_id: Some("provider".to_owned()),
        },
        output_tokens: AccountedTokens {
            tokens: 10,
            source: TokenAccountingSource::ProviderAuthoritative,
            tokenizer_id: Some("provider".to_owned()),
        },
        total_model_tokens,
        injected_evidence_items: 2,
        injected_evidence_tokens: 20,
        used_evidence_items: u64::from(verified_success),
        used_evidence_tokens: if verified_success { 10 } else { 0 },
        context_precision: MetricRatio::new(if verified_success { 10 } else { 0 }, 20),
        context_waste: MetricRatio::new(if verified_success { 10 } else { 20 }, 20),
        duplicate_context_ratio: MetricRatio::new(2, 40),
        context_reuse: MetricRatio::new(0, 20),
        cross_attempt_context_carry: MetricRatio::new(0, 20),
        packet_fill: MetricRatio::new(100, 8_000),
        tool_schema_ratio: MetricRatio::new(10, 100),
        evidence_expansion_rate: MetricRatio::new(0, 2),
        raw_drilldown_rate: MetricRatio::new(0, 2),
        tool_compression_ratio: MetricRatio::new(100, 20),
        memory_conflict_surface_rate: MetricRatio::new(0, 0),
        memory_revalidation_rate: MetricRatio::new(0, 0),
        retrieval_attempts: 1,
        semantic_escalation_rate: MetricRatio::new(0, 1),
        semantic_incremental_hit_rate: MetricRatio::conditional(0, 0, verified_success),
        max_context_level: level,
        routes,
    }
}

fn record(
    task_id: &str,
    depth: &str,
    role: &str,
    attempt_index: u32,
    metrics: AttemptContextMetrics,
) -> EvaluationAttemptRecord {
    EvaluationAttemptRecord {
        task_id: task_id.to_owned(),
        depth: depth.to_owned(),
        role: role.to_owned(),
        attempt_id: format!("{task_id}-attempt-{attempt_index}"),
        attempt_index,
        metrics,
    }
}

#[test]
fn metrics_report_is_versioned_btree_deterministic_and_aggregates_task_depth_role() {
    let failed = record(
        "task-a",
        "d1",
        "implementer",
        0,
        attempt_metrics(
            "trace-a0",
            100,
            false,
            false,
            ContextLevel::C2,
            route_metrics((1, 1, 2, 1), (1, 8, 0), Some(0)),
            RouteContextMetrics::default(),
        ),
    );
    let repaired = record(
        "task-a",
        "d1",
        "implementer",
        1,
        attempt_metrics(
            "trace-a1",
            200,
            true,
            true,
            ContextLevel::C3,
            route_metrics((1, 1, 3, 3), (2, 16, 1), Some(1)),
            RouteContextMetrics::default(),
        ),
    );
    let first_pass = record(
        "task-b",
        "d0",
        "reviewer",
        0,
        attempt_metrics(
            "trace-b0",
            80,
            true,
            false,
            ContextLevel::C1,
            RouteContextMetrics::default(),
            route_metrics((1, 1, 1, 1), (1, 5, 1), Some(0)),
        ),
    );

    let first = aggregate_context_metrics(&[first_pass.clone(), repaired.clone(), failed.clone()]);
    let second = aggregate_context_metrics(&[failed, first_pass, repaired]);
    assert_eq!(first, second);
    assert_eq!(first.schema, "sovereign-context-token-report-v1");
    assert_eq!(first.groups.len(), 2);
    assert_eq!(first.groups[0].key.task_id, "task-a");
    assert_eq!(first.groups[1].key.task_id, "task-b");

    let task_a = &first.groups[0];
    assert_eq!(task_a.attempts, 2);
    assert_eq!(task_a.total_model_tokens, 300);
    assert_eq!(task_a.succeeded_tasks, 1);
    assert_eq!(task_a.accepted_change_sets, 1);
    assert_eq!(task_a.tokens_per_verified_task.numerator, 300);
    assert_eq!(task_a.tokens_per_verified_task.denominator, 1);
    assert_eq!(task_a.retries, 1);
    assert_eq!(task_a.reasoning_retries_per_verified_task.numerator, 1);
    assert_eq!(
        task_a.first_pass_verification_rate.parts_per_million,
        Some(0)
    );
    assert_eq!(task_a.escalation_distribution.get("c2"), Some(&1));
    assert_eq!(task_a.escalation_distribution.get("c3"), Some(&1));

    let exact = &task_a.routes[&RetrievalRouteKind::Exact];
    assert_eq!(exact.attempts, 2);
    assert_eq!(exact.candidates, 5);
    assert_eq!(exact.selected, 4);
    assert_eq!(exact.injected_tokens, 24);
    assert_eq!(exact.stale_rejected, Some(1));
    assert_eq!(
        exact
            .stale_rejection_rate
            .as_ref()
            .map(|ratio| ratio.numerator),
        Some(1)
    );
    assert_eq!(exact.retrieval_hit_quality.numerator, 1);
    assert_eq!(exact.retrieval_hit_quality.denominator, 3);

    let encoded_first =
        serde_json::to_string(&first).unwrap_or_else(|error| panic!("json: {error}"));
    let encoded_second =
        serde_json::to_string(&second).unwrap_or_else(|error| panic!("json: {error}"));
    assert_eq!(encoded_first, encoded_second);
}

#[test]
fn metrics_zero_success_divisions_and_semantic_unavailable_remain_not_applicable() {
    let failed = record(
        "task-failed",
        "d1",
        "implementer",
        0,
        attempt_metrics(
            "trace-failed",
            120,
            false,
            false,
            ContextLevel::C2,
            route_metrics((1, 1, 1, 1), (1, 6, 0), Some(0)),
            RouteContextMetrics::default(),
        ),
    );
    let report = aggregate_context_metrics(&[failed]);
    let group = &report.groups[0];

    assert_eq!(group.succeeded_tasks, 0);
    assert_eq!(group.tokens_per_verified_task.denominator, 0);
    assert_eq!(group.tokens_per_verified_task.parts_per_million, None);
    assert_eq!(group.tokens_per_verified_change.denominator, 0);
    assert_eq!(group.tokens_per_verified_change.parts_per_million, None);
    assert_eq!(
        group.reasoning_retries_per_verified_task.parts_per_million,
        None
    );
    assert_eq!(group.first_pass_verification_rate.denominator, 0);
    assert_eq!(group.first_pass_verification_rate.parts_per_million, None);
    assert_eq!(group.semantic_escalation_rate.numerator, 0);
    assert_eq!(group.semantic_escalation_rate.denominator, 1);
    assert_eq!(group.semantic_incremental_hit_rate.denominator, 0);
    assert_eq!(group.semantic_incremental_hit_rate.parts_per_million, None);
    assert_eq!(group.routes[&RetrievalRouteKind::Semantic].attempts, 0);
    assert_eq!(group.routes[&RetrievalRouteKind::Semantic].steps, 1);
}

#[test]
fn metrics_route_stale_unknown_is_preserved_across_aggregation() {
    let known = record(
        "task-stale",
        "d2",
        "implementer",
        0,
        attempt_metrics(
            "trace-known",
            100,
            false,
            false,
            ContextLevel::C2,
            RouteContextMetrics::default(),
            route_metrics((1, 1, 3, 2), (2, 12, 0), Some(0)),
        ),
    );
    let unknown = record(
        "task-stale",
        "d2",
        "implementer",
        1,
        attempt_metrics(
            "trace-unknown",
            110,
            true,
            true,
            ContextLevel::C2,
            RouteContextMetrics::default(),
            route_metrics((1, 1, 4, 2), (2, 14, 1), None),
        ),
    );
    let report = aggregate_context_metrics(&[known, unknown]);
    let lexical = &report.groups[0].routes[&RetrievalRouteKind::Lexical];

    assert_eq!(lexical.attempts, 2);
    assert_eq!(lexical.candidates, 7);
    assert_eq!(lexical.stale_rejected, None);
    assert_eq!(lexical.stale_rejection_rate, None);
    assert_eq!(lexical.retrieval_hit_quality.numerator, 1);
    assert_eq!(lexical.retrieval_hit_quality.denominator, 2);
}
