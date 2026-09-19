//! Deterministic evaluation aggregation over immutable attempt telemetry.

mod local_smoke;
mod runner;
mod schema;

use serde::{Deserialize, Serialize};
use sovereign_context::{AttemptContextMetrics, MetricRatio, RetrievalRouteKind};
use std::collections::BTreeMap;

pub use local_smoke::{LocalModelSmokeConfig, run_local_model_smoke};
pub use runner::run_offline_profile;
pub use schema::{
    EVAL_REPORT_SCHEMA_VERSION, EVAL_SCENARIO_SCHEMA_VERSION, EvalAggregateV1, EvalReportV1,
    EvalResourceMetricsV1, EvalResourceSourceV1, EvalRestartExerciseV1, EvalRestartMetricsV1,
    EvalRetrievalMetricsV1, EvalScale, EvalScenarioResultV1, EvalScenarioV1, EvalTokenMetricsV1,
    LocalModelSmokeReportV1, M1_8GB_PROFILE_ID,
};

/// One attempt supplied to the deterministic M2 metric aggregator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationAttemptRecord {
    pub task_id: String,
    pub depth: String,
    pub role: String,
    pub attempt_id: String,
    pub attempt_index: u32,
    pub metrics: AttemptContextMetrics,
}

/// Stable aggregation key. `BTree` ordering is task, then depth, then role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvaluationMetricKey {
    pub task_id: String,
    pub depth: String,
    pub role: String,
}

/// Aggregated retrieval value for one route taxonomy member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationRouteMetrics {
    pub attempts: u64,
    pub steps: u64,
    pub candidates: u64,
    pub selected: u64,
    pub injected_tokens: u64,
    pub useful_selected: u64,
    pub stale_rejected: Option<u64>,
    pub refreshes: u64,
    pub expansions: u64,
    pub retrieval_hit_quality: MetricRatio,
    pub stale_rejection_rate: Option<MetricRatio>,
}

impl Default for EvaluationRouteMetrics {
    fn default() -> Self {
        Self {
            attempts: 0,
            steps: 0,
            candidates: 0,
            selected: 0,
            injected_tokens: 0,
            useful_selected: 0,
            stale_rejected: None,
            refreshes: 0,
            expansions: 0,
            retrieval_hit_quality: MetricRatio::conditional(0, 0, false),
            stale_rejection_rate: None,
        }
    }
}

/// One deterministic task/depth/role metric group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationMetricGroup {
    pub key: EvaluationMetricKey,
    pub attempts: u64,
    pub total_model_tokens: u64,
    pub succeeded_tasks: u64,
    pub accepted_change_sets: u64,
    pub tokens_per_verified_task: MetricRatio,
    pub tokens_per_verified_change: MetricRatio,
    pub retries: u64,
    pub reasoning_retries_per_verified_task: MetricRatio,
    pub escalation_distribution: BTreeMap<String, u64>,
    pub first_pass_verification_rate: MetricRatio,
    pub semantic_escalation_rate: MetricRatio,
    pub semantic_incremental_hit_rate: MetricRatio,
    pub routes: BTreeMap<RetrievalRouteKind, EvaluationRouteMetrics>,
}

/// Versioned deterministic M2 context/token report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationMetricReport {
    pub schema: String,
    pub groups: Vec<EvaluationMetricGroup>,
}

/// Aggregates attempt telemetry without reopening repositories, indexes, history, or tool output.
#[must_use]
pub fn aggregate_context_metrics(attempts: &[EvaluationAttemptRecord]) -> EvaluationMetricReport {
    let mut grouped = BTreeMap::<EvaluationMetricKey, Vec<&EvaluationAttemptRecord>>::new();
    for attempt in attempts {
        let key = EvaluationMetricKey {
            task_id: attempt.task_id.clone(),
            depth: attempt.depth.clone(),
            role: attempt.role.clone(),
        };
        grouped.entry(key).or_default().push(attempt);
    }

    let groups = grouped
        .into_iter()
        .map(|(key, mut records)| {
            records.sort_by(|left, right| {
                (left.attempt_index, &left.attempt_id, &left.metrics.trace_id).cmp(&(
                    right.attempt_index,
                    &right.attempt_id,
                    &right.metrics.trace_id,
                ))
            });
            aggregate_group(key, &records)
        })
        .collect();

    EvaluationMetricReport {
        schema: "sovereign-context-token-report-v1".to_owned(),
        groups,
    }
}

fn aggregate_group(
    key: EvaluationMetricKey,
    records: &[&EvaluationAttemptRecord],
) -> EvaluationMetricGroup {
    let attempts = usize_u64(records.len());
    let total_model_tokens = records.iter().fold(0_u64, |sum, record| {
        sum.saturating_add(record.metrics.total_model_tokens)
    });
    let succeeded = records.iter().any(|record| record.metrics.verified_success);
    let succeeded_tasks = u64::from(succeeded);
    let accepted_change_sets = records.iter().fold(0_u64, |sum, record| {
        sum.saturating_add(u64::from(record.metrics.accepted_change_set))
    });
    let retries = records.iter().fold(0_u64, |sum, record| {
        sum.saturating_add(u64::from(record.attempt_index != 0))
    });
    let first_pass = records
        .iter()
        .any(|record| record.attempt_index == 0 && record.metrics.verified_success);

    let mut escalation_distribution = BTreeMap::new();
    for record in records {
        let level = format!("{:?}", record.metrics.max_context_level).to_ascii_lowercase();
        let entry = escalation_distribution.entry(level).or_insert(0_u64);
        *entry = entry.saturating_add(1);
    }

    let routes = aggregate_routes(records);
    let semantic_escalation = records.iter().fold((0_u64, 0_u64), |(num, den), record| {
        (
            num.saturating_add(record.metrics.semantic_escalation_rate.numerator),
            den.saturating_add(record.metrics.semantic_escalation_rate.denominator),
        )
    });
    let semantic_incremental = records.iter().fold((0_u64, 0_u64), |(num, den), record| {
        (
            num.saturating_add(record.metrics.semantic_incremental_hit_rate.numerator),
            den.saturating_add(record.metrics.semantic_incremental_hit_rate.denominator),
        )
    });

    EvaluationMetricGroup {
        key,
        attempts,
        total_model_tokens,
        succeeded_tasks,
        accepted_change_sets,
        tokens_per_verified_task: MetricRatio::new(total_model_tokens, succeeded_tasks),
        tokens_per_verified_change: MetricRatio::new(total_model_tokens, accepted_change_sets),
        retries,
        reasoning_retries_per_verified_task: MetricRatio::new(retries, succeeded_tasks),
        escalation_distribution,
        first_pass_verification_rate: MetricRatio::new(u64::from(first_pass), succeeded_tasks),
        semantic_escalation_rate: MetricRatio::new(semantic_escalation.0, semantic_escalation.1),
        semantic_incremental_hit_rate: MetricRatio::new(
            semantic_incremental.0,
            semantic_incremental.1,
        ),
        routes,
    }
}

fn aggregate_routes(
    records: &[&EvaluationAttemptRecord],
) -> BTreeMap<RetrievalRouteKind, EvaluationRouteMetrics> {
    let mut routes = RetrievalRouteKind::ALL
        .into_iter()
        .map(|kind| (kind, EvaluationRouteMetrics::default()))
        .collect::<BTreeMap<_, _>>();
    let mut stale_observable = BTreeMap::<RetrievalRouteKind, bool>::new();
    let mut stale_totals = BTreeMap::<RetrievalRouteKind, u64>::new();
    let mut successful_quality = BTreeMap::<RetrievalRouteKind, (u64, u64)>::new();

    for record in records {
        for kind in RetrievalRouteKind::ALL {
            let Some(source) = record.metrics.routes.get(&kind) else {
                continue;
            };
            let target = routes.entry(kind).or_default();
            target.attempts = target.attempts.saturating_add(source.attempts);
            target.steps = target.steps.saturating_add(source.steps);
            target.candidates = target.candidates.saturating_add(source.candidates);
            target.selected = target.selected.saturating_add(source.selected);
            target.injected_tokens = target
                .injected_tokens
                .saturating_add(source.injected_tokens);
            target.useful_selected = target
                .useful_selected
                .saturating_add(source.useful_selected);
            target.refreshes = target.refreshes.saturating_add(source.refreshes);
            target.expansions = target.expansions.saturating_add(source.expansions);

            if source.attempts != 0 {
                match source.stale_rejected {
                    Some(value) if stale_observable.get(&kind).copied().unwrap_or(true) => {
                        stale_observable.entry(kind).or_insert(true);
                        let entry = stale_totals.entry(kind).or_insert(0);
                        *entry = entry.saturating_add(value);
                    }
                    Some(_) => {}
                    None => {
                        stale_observable.insert(kind, false);
                    }
                }
            }

            if record.metrics.verified_success {
                let entry = successful_quality.entry(kind).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(source.useful_selected);
                entry.1 = entry.1.saturating_add(source.selected);
            }
        }
    }

    for kind in RetrievalRouteKind::ALL {
        let target = routes.entry(kind).or_default();
        target.stale_rejected =
            if target.attempts == 0 || !stale_observable.get(&kind).copied().unwrap_or(false) {
                None
            } else {
                Some(stale_totals.get(&kind).copied().unwrap_or(0))
            };
        let (useful, selected) = successful_quality.get(&kind).copied().unwrap_or((0, 0));
        target.retrieval_hit_quality = MetricRatio::new(useful, selected);
        target.stale_rejection_rate = target
            .stale_rejected
            .map(|stale| MetricRatio::new(stale, target.candidates));
    }
    routes
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
