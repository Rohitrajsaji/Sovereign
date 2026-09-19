use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version for one deterministic evaluation scenario.
pub const EVAL_SCENARIO_SCHEMA_VERSION: u32 = 1;
/// Schema version for the aggregate evaluation report.
pub const EVAL_REPORT_SCHEMA_VERSION: u32 = 1;
/// Stable local resource profile selected by M9 evaluation.
pub const M1_8GB_PROFILE_ID: &str = "m1-8gb";

/// Fixed corpus scale used by release evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalScale {
    Tiny,
    Medium,
    Large,
}

/// Origin of one reported resource measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalResourceSourceV1 {
    DeterministicSimulation,
    PhysicalLocalModel,
}

/// Versioned immutable evaluation scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalScenarioV1 {
    pub schema_version: u32,
    pub scenario_id: String,
    pub scale: EvalScale,
    pub fixture_digest: String,
    pub goal: String,
    pub expected_verified_success: bool,
    pub model_claims_done: bool,
    pub restart_required: bool,
}

/// Deterministic token accounting for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalTokenMetricsV1 {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub source: String,
}

/// Deterministic retrieval-use metrics for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalRetrievalMetricsV1 {
    pub attempts: u64,
    pub selected: u64,
    pub useful_selected: u64,
    pub source: String,
}

/// Resource measurement carried separately from correctness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalResourceMetricsV1 {
    pub peak_rss_kib: u64,
    pub source: EvalResourceSourceV1,
}

/// Whether restart/reopen recovery was exercised for one scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalRestartExerciseV1 {
    NotExercised,
    Exercised,
}

/// Restart/reopen facts for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalRestartMetricsV1 {
    pub exercise: EvalRestartExerciseV1,
    pub durable_state_reopened: bool,
    pub recovered_value_matches: bool,
    pub unknown_actions: u64,
    pub mutation_blocked: bool,
}

/// Result of evaluating one scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalScenarioResultV1 {
    pub scenario: EvalScenarioV1,
    pub scenario_passed: bool,
    pub verified_success: bool,
    pub false_completion_accepted: bool,
    pub attempts: u32,
    pub retries: u32,
    pub tokens: EvalTokenMetricsV1,
    pub retrieval: EvalRetrievalMetricsV1,
    pub resources: EvalResourceMetricsV1,
    pub restart: EvalRestartMetricsV1,
}

/// Aggregate correctness/resource facts over the deterministic corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalAggregateV1 {
    pub scenario_count: u64,
    pub scenario_pass_count: u64,
    pub verified_success_count: u64,
    pub false_completion_attempts: u64,
    pub false_completion_accepted: u64,
    pub total_model_tokens: u64,
    pub total_retries: u64,
    pub max_peak_rss_kib: u64,
    pub restart_scenarios: u64,
    pub restart_recovered: u64,
}

/// Versioned deterministic M9 evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalReportV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub offline: bool,
    pub corpus_digest: String,
    pub scenarios: Vec<EvalScenarioResultV1>,
    pub aggregate: EvalAggregateV1,
}

impl EvalReportV1 {
    /// Validates stable report/schema invariants.
    ///
    /// # Errors
    /// Returns a descriptive error for unsupported versions or internally inconsistent aggregates.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != EVAL_REPORT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported evaluation report schema version {}",
                self.schema_version
            ));
        }
        if self.profile_id != M1_8GB_PROFILE_ID || !self.offline || self.corpus_digest.is_empty() {
            return Err("evaluation report profile/offline/corpus binding is invalid".to_owned());
        }
        for result in &self.scenarios {
            if result.scenario.schema_version != EVAL_SCENARIO_SCHEMA_VERSION
                || result.scenario.scenario_id.trim().is_empty()
                || result.scenario.fixture_digest.trim().is_empty()
                || result.scenario.goal.trim().is_empty()
                || result.tokens.source.trim().is_empty()
                || result.retrieval.source.trim().is_empty()
                || result.attempts == 0
                || result.retries != result.attempts.saturating_sub(1)
                || result.tokens.total_tokens
                    != result
                        .tokens
                        .input_tokens
                        .saturating_add(result.tokens.output_tokens)
            {
                return Err("evaluation scenario/result schema is invalid".to_owned());
            }
            if result.false_completion_accepted
                && (!result.scenario.model_claims_done || result.verified_success)
            {
                return Err(
                    "accepted false completion must be a model done-claim without verified success"
                        .to_owned(),
                );
            }
            let restart_ok = !result.scenario.restart_required
                || (result.restart.exercise == EvalRestartExerciseV1::Exercised
                    && result.restart.durable_state_reopened
                    && result.restart.recovered_value_matches
                    && result.restart.unknown_actions == 0
                    && !result.restart.mutation_blocked);
            let expected_passed = result.verified_success
                == result.scenario.expected_verified_success
                && !result.false_completion_accepted
                && restart_ok;
            if result.scenario_passed != expected_passed {
                return Err(
                    "evaluation scenario pass state is inconsistent with correctness/recovery facts"
                        .to_owned(),
                );
            }
        }
        if self.corpus_digest != corpus_digest(&self.scenarios)?
            || self.aggregate != aggregate_scenarios(&self.scenarios)
        {
            return Err("evaluation aggregate does not match scenario results".to_owned());
        }
        Ok(())
    }
}

pub(crate) fn corpus_digest(results: &[EvalScenarioResultV1]) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for result in results {
        let bytes = serde_json::to_vec(&result.scenario).map_err(|error| error.to_string())?;
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub(crate) fn aggregate_scenarios(results: &[EvalScenarioResultV1]) -> EvalAggregateV1 {
    EvalAggregateV1 {
        scenario_count: usize_u64(results.len()),
        scenario_pass_count: usize_u64(
            results
                .iter()
                .filter(|result| result.scenario_passed)
                .count(),
        ),
        verified_success_count: usize_u64(
            results
                .iter()
                .filter(|result| result.verified_success)
                .count(),
        ),
        false_completion_attempts: usize_u64(
            results
                .iter()
                .filter(|result| result.scenario.model_claims_done && !result.verified_success)
                .count(),
        ),
        false_completion_accepted: usize_u64(
            results
                .iter()
                .filter(|result| result.false_completion_accepted)
                .count(),
        ),
        total_model_tokens: results.iter().fold(0_u64, |sum, result| {
            sum.saturating_add(result.tokens.total_tokens)
        }),
        total_retries: results.iter().fold(0_u64, |sum, result| {
            sum.saturating_add(u64::from(result.retries))
        }),
        max_peak_rss_kib: results
            .iter()
            .map(|result| result.resources.peak_rss_kib)
            .max()
            .unwrap_or(0),
        restart_scenarios: usize_u64(
            results
                .iter()
                .filter(|result| result.restart.exercise == EvalRestartExerciseV1::Exercised)
                .count(),
        ),
        restart_recovered: usize_u64(
            results
                .iter()
                .filter(|result| {
                    result.restart.exercise == EvalRestartExerciseV1::Exercised
                        && result.restart.durable_state_reopened
                        && result.restart.recovered_value_matches
                        && result.restart.unknown_actions == 0
                        && !result.restart.mutation_blocked
                })
                .count(),
        ),
    }
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Physical one-model smoke report; kept separate from deterministic/simulated corpus RSS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalModelSmokeReportV1 {
    pub schema_version: u32,
    pub model_id: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub startup_peak_rss_kib: Option<u64>,
    pub post_load_rss_kib: Option<u64>,
    pub call_peak_rss_kib: Option<u64>,
    pub process_id: Option<u32>,
    pub process_absent_after_unload: bool,
    pub resource_source: EvalResourceSourceV1,
}
