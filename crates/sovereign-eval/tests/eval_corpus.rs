use sovereign_eval::{
    EVAL_REPORT_SCHEMA_VERSION, EvalRestartExerciseV1, EvalScale, M1_8GB_PROFILE_ID,
    run_offline_profile,
};
use std::collections::BTreeSet;

#[test]
fn fake_report_v1_is_byte_repeatable() {
    let first = run_offline_profile(M1_8GB_PROFILE_ID)
        .unwrap_or_else(|error| panic!("first deterministic report: {error}"));
    let second = run_offline_profile(M1_8GB_PROFILE_ID)
        .unwrap_or_else(|error| panic!("second deterministic report: {error}"));
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).unwrap_or_else(|error| panic!("encode first: {error}")),
        serde_json::to_vec(&second).unwrap_or_else(|error| panic!("encode second: {error}"))
    );
}

#[test]
fn tiny_medium_large_cover_required_metrics() {
    let report = run_offline_profile(M1_8GB_PROFILE_ID)
        .unwrap_or_else(|error| panic!("deterministic report: {error}"));
    assert_eq!(report.schema_version, EVAL_REPORT_SCHEMA_VERSION);
    let scales = report
        .scenarios
        .iter()
        .map(|result| result.scenario.scale)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        scales,
        BTreeSet::from([EvalScale::Tiny, EvalScale::Medium, EvalScale::Large])
    );
    assert_eq!(report.aggregate.scenario_count, 4);
    assert_eq!(report.aggregate.scenario_pass_count, 4);
    assert_eq!(report.aggregate.false_completion_attempts, 1);
    assert_eq!(report.aggregate.false_completion_accepted, 0);
    assert!(report.aggregate.total_model_tokens > 0);
    assert!(report.aggregate.total_retries > 0);
    assert!(report.aggregate.max_peak_rss_kib > 0);
    assert_eq!(report.aggregate.restart_scenarios, 1);
    assert_eq!(report.aggregate.restart_recovered, 1);
    for result in &report.scenarios {
        assert!(result.tokens.total_tokens > 0);
        assert!(result.retrieval.attempts > 0);
        assert!(result.resources.peak_rss_kib > 0);
    }
}

#[test]
fn correctness_is_independent_of_token_minimization_and_false_completion_fails_closed() {
    let report = run_offline_profile(M1_8GB_PROFILE_ID)
        .unwrap_or_else(|error| panic!("deterministic report: {error}"));
    let failed = report
        .scenarios
        .iter()
        .find(|result| result.scenario.scenario_id == "tiny-false-completion")
        .unwrap_or_else(|| panic!("false-completion scenario missing"));
    let successful = report
        .scenarios
        .iter()
        .find(|result| result.scenario.scenario_id == "tiny-success")
        .unwrap_or_else(|| panic!("tiny-success scenario missing"));
    assert!(failed.tokens.total_tokens < successful.tokens.total_tokens);
    assert!(!failed.verified_success);
    assert!(!failed.false_completion_accepted);
    assert!(failed.scenario_passed);
}

#[test]
fn restart_result_is_durable_and_schema_version_is_rejected_on_drift() {
    let report = run_offline_profile(M1_8GB_PROFILE_ID)
        .unwrap_or_else(|error| panic!("deterministic report: {error}"));
    let restart = report
        .scenarios
        .iter()
        .find(|result| result.scenario.scenario_id == "large-restart")
        .unwrap_or_else(|| panic!("large restart scenario missing"));
    assert_eq!(restart.restart.exercise, EvalRestartExerciseV1::Exercised);
    assert!(restart.restart.durable_state_reopened);
    assert!(restart.restart.recovered_value_matches);
    assert_eq!(restart.restart.unknown_actions, 0);
    assert!(!restart.restart.mutation_blocked);

    let mut unsupported = report;
    unsupported.schema_version = EVAL_REPORT_SCHEMA_VERSION.saturating_add(1);
    assert!(unsupported.validate().is_err());
}
