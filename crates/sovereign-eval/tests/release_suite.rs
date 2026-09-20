use sovereign_eval::{M1_8GB_PROFILE_ID, SOAK_REPORT_SCHEMA_VERSION, run_release_suite};
use std::collections::BTreeSet;

#[test]
fn release_suite_emits_and_strictly_validates_complete_measured_m1_report() {
    let report = run_release_suite(M1_8GB_PROFILE_ID)
        .unwrap_or_else(|error| panic!("run release suite: {error}"));
    report
        .validate()
        .unwrap_or_else(|error| panic!("validate release suite: {error}"));
    assert_eq!(report.schema_version, SOAK_REPORT_SCHEMA_VERSION);
    assert_eq!(report.suite, "release");
    assert!(report.offline);
    assert_eq!(report.profile_id, M1_8GB_PROFILE_ID);
    assert_eq!(report.git_head.len(), 40);
    assert!(report.source_tree_digest.starts_with("sha256:"));
    assert_eq!(report.measurement.scenario_loop_iterations, 8);
    assert!(report.measurement.process_peak_rss_kib > 0);
    assert!(!report.measurement.process_cpu_time.is_empty());
    assert!(report.measurement.durable_fixture_disk_bytes > 0);
    assert!(report.measurement.durable_fixture_write_bytes > 0);
    assert!(report.measurement.total_model_tokens > report.workload.aggregate.total_model_tokens);
    assert_eq!(report.measurement.failure_count, 0);
    assert!(report.measurement.replan_exercises > 0);
    assert_eq!(report.measurement.restart_scenarios, 8);
    assert_eq!(report.measurement.restart_recovered, 8);
    assert_eq!(report.workload.aggregate.false_completion_accepted, 0);

    let case_ids = report
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    let required_cases = [
        "bounded-equivalent-soak-loop",
        "tiny-medium-large-workloads",
        "forced-kill-recovery-matrix",
        "offline-no-provider-core",
        "optional-adapter-on-off-matrix",
        "heavy-lease-pair-admission-matrix",
        "swap-growth-pressure-semantics",
        "context-refinement-decomposition",
        "malicious-repository-isolation-matrix",
        "audit-cas-checkpoint-tamper-matrix",
        "rollback-unknown-no-duplicate-compensation",
        "outer-budget-runaway-containment",
        "external-intelligence-policy-matrix",
        "false-completion-remains-rejected",
        "disk-full-simulation",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(case_ids, required_cases);
    assert!(
        report
            .cases
            .iter()
            .filter(|case| case.case_id != "disk-full-simulation")
            .all(|case| case.applicable && case.passed)
    );
    let disk = report
        .cases
        .iter()
        .find(|case| case.case_id == "disk-full-simulation")
        .unwrap_or_else(|| panic!("disk-full release case missing"));
    assert!(!disk.applicable);
    assert!(!disk.passed);

    let probe_ids = report
        .probes
        .iter()
        .map(|probe| probe.probe_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(probe_ids.len(), 12);
    assert!(report.probes.iter().all(|probe| probe.passed));

    let mut failed = report.clone();
    failed.cases[0].passed = false;
    assert!(failed.validate().is_err());

    let mut hidden_required = report.clone();
    hidden_required.cases[0].applicable = false;
    assert!(hidden_required.validate().is_err());

    let mut missing = report.clone();
    missing.cases.pop();
    assert!(missing.validate().is_err());

    let mut duplicate = report.clone();
    duplicate.cases.push(duplicate.cases[0].clone());
    assert!(duplicate.validate().is_err());

    let mut failed_probe = report.clone();
    failed_probe.probes[0].passed = false;
    assert!(failed_probe.validate().is_err());

    let mut unsafe_disk_failure = report.clone();
    let disk = unsafe_disk_failure
        .cases
        .iter_mut()
        .find(|case| case.case_id == "disk-full-simulation")
        .unwrap_or_else(|| panic!("disk-full release case missing"));
    disk.applicable = true;
    assert!(unsafe_disk_failure.validate().is_err());

    let mut wrong_profile = report;
    wrong_profile.profile_id = "other".to_owned();
    assert!(wrong_profile.validate().is_err());
}
