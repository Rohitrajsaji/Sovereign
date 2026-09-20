use crate::{EvalReportV1, M1_8GB_PROFILE_ID, run_offline_profile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextLevel, ContextMode, ContextPacketInput, ContextPlanner, EvidenceItem,
    EvidenceKind, PacketSection, TrustClass,
};
use sovereign_policy::{
    HardwareProfileV1, OsMemoryPressure, PressureBand, ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_state::StateStore;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

/// Schema version for the final M1/8GB release soak report.
pub const SOAK_REPORT_SCHEMA_VERSION: u32 = 1;
const SOAK_ITERATIONS: u32 = 8;
const DISK_FULL_CASE_ID: &str = "disk-full-simulation";
const REQUIRED_CASE_IDS: [&str; 14] = [
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
];
const REQUIRED_PROBE_IDS: [&str; 12] = [
    "crash-resume",
    "controller-resilience",
    "security-resilience",
    "completion-governance",
    "prompt-injection",
    "external-intelligence",
    "resource-policy",
    "repository-security",
    "sandbox-kernel",
    "secret-isolation",
    "tool-runner-containment",
    "browser-policy",
];

static SOAK_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// One named release-gate fact emitted by the bounded release suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakCaseV1 {
    pub case_id: String,
    pub applicable: bool,
    pub passed: bool,
    pub detail: String,
}

/// One authoritative focused regression target executed by the release command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakProbeV1 {
    pub probe_id: String,
    pub command: String,
    pub passed: bool,
    pub summary: String,
}

/// Exact local hardware/runtime identity carried with release evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakHardwareV1 {
    pub profile_id: String,
    pub architecture: String,
    pub operating_system: String,
    pub operating_system_version: Option<String>,
    pub logical_cpus: usize,
    pub physical_memory_mib: u64,
    pub optional_browser_detected: bool,
}

/// Directly measured host/process/durable-state facts from the release command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakMeasurementV1 {
    pub scenario_loop_iterations: u32,
    pub process_peak_rss_kib: u64,
    pub process_cpu_time: String,
    pub durable_fixture_disk_bytes: u64,
    pub durable_fixture_write_bytes: u64,
    pub total_model_tokens: u64,
    pub total_retries: u64,
    pub failure_count: u64,
    pub replan_exercises: u64,
    pub restart_scenarios: u64,
    pub restart_recovered: u64,
}

/// Versioned final M1/8GB soak/crash/security release report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakReportV1 {
    pub schema_version: u32,
    pub suite: String,
    pub profile_id: String,
    pub offline: bool,
    pub sovereign_version: String,
    pub git_head: String,
    pub source_tree_dirty: bool,
    pub source_tree_digest: String,
    pub hardware: SoakHardwareV1,
    pub measurement: SoakMeasurementV1,
    pub workload: EvalReportV1,
    pub probes: Vec<SoakProbeV1>,
    pub cases: Vec<SoakCaseV1>,
}

impl SoakReportV1 {
    /// Validates that the report is a complete release-gating M1/8GB offline result.
    ///
    /// # Errors
    /// Returns a descriptive error for schema/profile/source drift, missing or failed mandatory
    /// cases/probes, or invalid workload/resource/restart accounting.
    pub fn validate(&self) -> Result<(), String> {
        self.validate_identity_and_measurement()?;
        self.validate_probes()?;
        self.validate_cases()?;
        Ok(())
    }

    fn validate_identity_and_measurement(&self) -> Result<(), String> {
        if self.schema_version != SOAK_REPORT_SCHEMA_VERSION
            || self.suite != "release"
            || self.profile_id != M1_8GB_PROFILE_ID
            || !self.offline
            || self.git_head.trim().is_empty()
            || !self.source_tree_digest.starts_with("sha256:")
        {
            return Err(
                "release soak report schema/suite/profile/source binding is invalid".to_owned(),
            );
        }
        self.workload.validate()?;
        if self.workload.profile_id != self.profile_id || !self.workload.offline {
            return Err(
                "release workload is not bound to the soak profile/offline mode".to_owned(),
            );
        }
        if self.hardware.profile_id != self.profile_id
            || self.hardware.logical_cpus == 0
            || self.hardware.physical_memory_mib == 0
            || self.measurement.scenario_loop_iterations != SOAK_ITERATIONS
            || self.measurement.process_peak_rss_kib == 0
            || self.measurement.process_cpu_time.trim().is_empty()
            || self.measurement.durable_fixture_disk_bytes == 0
            || self.measurement.durable_fixture_write_bytes == 0
            || self.measurement.failure_count != 0
            || self.measurement.replan_exercises == 0
        {
            return Err("release hardware/resource/failure measurement is incomplete".to_owned());
        }
        let iterations = u64::from(self.measurement.scenario_loop_iterations);
        if self.measurement.total_model_tokens
            != self
                .workload
                .aggregate
                .total_model_tokens
                .saturating_mul(iterations)
            || self.measurement.total_retries
                != self
                    .workload
                    .aggregate
                    .total_retries
                    .saturating_mul(iterations)
            || self.measurement.restart_scenarios
                != self
                    .workload
                    .aggregate
                    .restart_scenarios
                    .saturating_mul(iterations)
            || self.measurement.restart_recovered
                != self
                    .workload
                    .aggregate
                    .restart_recovered
                    .saturating_mul(iterations)
            || self.measurement.restart_scenarios == 0
            || self.measurement.restart_scenarios != self.measurement.restart_recovered
        {
            return Err(
                "release aggregate accounting does not match the bounded scenario loop".to_owned(),
            );
        }
        Ok(())
    }

    fn validate_probes(&self) -> Result<(), String> {
        let ids = self
            .probes
            .iter()
            .map(|probe| probe.probe_id.as_str())
            .collect::<BTreeSet<_>>();
        let required = REQUIRED_PROBE_IDS.into_iter().collect::<BTreeSet<_>>();
        if ids != required || self.probes.len() != required.len() {
            return Err(
                "release regression probe set is missing, duplicated, or unexpected".to_owned(),
            );
        }
        if self.probes.iter().any(|probe| {
            !probe.passed || probe.command.trim().is_empty() || probe.summary.trim().is_empty()
        }) {
            return Err(
                "release regression probe failed or lacks command/result binding".to_owned(),
            );
        }
        Ok(())
    }

    fn validate_cases(&self) -> Result<(), String> {
        let ids = self
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut required = REQUIRED_CASE_IDS.into_iter().collect::<BTreeSet<_>>();
        required.insert(DISK_FULL_CASE_ID);
        if ids != required || self.cases.len() != required.len() {
            return Err("release case set is missing, duplicated, or unexpected".to_owned());
        }
        for case in &self.cases {
            if case.detail.trim().is_empty() {
                return Err("release case detail is empty".to_owned());
            }
            if case.case_id == DISK_FULL_CASE_ID {
                if case.applicable && !case.passed {
                    return Err("feasible disk-full simulation failed".to_owned());
                }
            } else if !case.applicable || !case.passed {
                return Err(format!(
                    "required release case {} did not pass",
                    case.case_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct WorkloadLoop {
    representative: EvalReportV1,
    total_model_tokens: u64,
    total_retries: u64,
    restart_scenarios: u64,
    restart_recovered: u64,
    scenario_failures: u64,
}

struct CaseInputs<'a> {
    workload: &'a WorkloadLoop,
    durable_restart: CaseFact,
    context_refinement: CaseFact,
    pressure_growth: CaseFact,
    probes: &'a [SoakProbeV1],
    browser: BrowserAvailability,
}

#[derive(Clone, Copy)]
enum CaseFact {
    Passed,
    Failed,
}

impl CaseFact {
    const fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

impl From<bool> for CaseFact {
    fn from(value: bool) -> Self {
        if value { Self::Passed } else { Self::Failed }
    }
}

#[derive(Clone, Copy)]
enum BrowserAvailability {
    Detected,
    Absent,
}

/// Runs the bounded local release suite against existing Controller/security/resource/recovery
/// machinery. The command executes authoritative focused regression targets rather than creating a
/// second authority ledger, test-only recovery API, or external-provider dependency.
///
/// # Errors
/// Returns an error when the profile is unsupported or any mandatory release fact fails closed.
pub fn run_release_suite(profile_id: &str) -> Result<SoakReportV1, String> {
    if profile_id != M1_8GB_PROFILE_ID {
        return Err(format!("unsupported release profile {profile_id:?}"));
    }
    let workspace = workspace_root()?;
    let sampler = PeakRssSampler::start();
    let workload = run_bounded_workload(profile_id)?;
    let (durable_fixture_disk_bytes, durable_fixture_write_bytes, durable_restart_ok) =
        exercise_durable_soak_loop()?;
    let profile = HardwareProfileV1::m1_8gb();
    let context_ok = context_refinement_is_bounded(&profile)?;
    let pressure_ok = pressure_growth_semantics(&profile);
    let probes = run_regression_matrix(&workspace)?;
    let process_peak_rss_kib = sampler.finish()?;
    let process_cpu_time = process_cpu_time()?;
    let (git_head, source_tree_dirty, source_tree_digest) = source_identity(&workspace)?;
    let probe_failures = probes.iter().filter(|probe| !probe.passed).count() as u64;
    let hardware = hardware_facts(&profile)?;
    let cases = build_cases(&CaseInputs {
        workload: &workload,
        durable_restart: durable_restart_ok.into(),
        context_refinement: context_ok.into(),
        pressure_growth: pressure_ok.into(),
        probes: &probes,
        browser: if hardware.optional_browser_detected {
            BrowserAvailability::Detected
        } else {
            BrowserAvailability::Absent
        },
    });
    let report = SoakReportV1 {
        schema_version: SOAK_REPORT_SCHEMA_VERSION,
        suite: "release".to_owned(),
        profile_id: profile_id.to_owned(),
        offline: true,
        sovereign_version: env!("CARGO_PKG_VERSION").to_owned(),
        git_head,
        source_tree_dirty,
        source_tree_digest,
        hardware,
        measurement: SoakMeasurementV1 {
            scenario_loop_iterations: SOAK_ITERATIONS,
            process_peak_rss_kib,
            process_cpu_time,
            durable_fixture_disk_bytes,
            durable_fixture_write_bytes,
            total_model_tokens: workload.total_model_tokens,
            total_retries: workload.total_retries,
            failure_count: workload.scenario_failures.saturating_add(probe_failures),
            replan_exercises: u64::from(probe_pass(&probes, "controller-resilience")),
            restart_scenarios: workload.restart_scenarios,
            restart_recovered: workload.restart_recovered,
        },
        workload: workload.representative,
        probes,
        cases,
    };
    report.validate()?;
    Ok(report)
}

fn run_bounded_workload(profile_id: &str) -> Result<WorkloadLoop, String> {
    let mut representative = None;
    let mut total_model_tokens = 0_u64;
    let mut total_retries = 0_u64;
    let mut restart_scenarios = 0_u64;
    let mut restart_recovered = 0_u64;
    let mut scenario_failures = 0_u64;
    for _ in 0..SOAK_ITERATIONS {
        let report = run_offline_profile(profile_id)?;
        report.validate()?;
        if let Some(first) = &representative {
            if first != &report {
                return Err(
                    "deterministic release corpus drifted across soak iterations".to_owned(),
                );
            }
        } else {
            representative = Some(report.clone());
        }
        total_model_tokens = total_model_tokens.saturating_add(report.aggregate.total_model_tokens);
        total_retries = total_retries.saturating_add(report.aggregate.total_retries);
        restart_scenarios = restart_scenarios.saturating_add(report.aggregate.restart_scenarios);
        restart_recovered = restart_recovered.saturating_add(report.aggregate.restart_recovered);
        scenario_failures = scenario_failures.saturating_add(
            report
                .aggregate
                .scenario_count
                .saturating_sub(report.aggregate.scenario_pass_count),
        );
    }
    Ok(WorkloadLoop {
        representative: representative
            .ok_or_else(|| "release scenario loop produced no report".to_owned())?,
        total_model_tokens,
        total_retries,
        restart_scenarios,
        restart_recovered,
        scenario_failures,
    })
}

fn build_cases(inputs: &CaseInputs<'_>) -> Vec<SoakCaseV1> {
    let mut cases = workload_and_resource_cases(inputs);
    cases.extend(security_and_authority_cases(inputs));
    cases.push(release_case(
        DISK_FULL_CASE_ID,
        false,
        false,
        "host ENOSPC is not induced because destructive disk exhaustion is unsafe; low-free-disk admission remains covered by resource-policy regression",
    ));
    cases
}

fn workload_and_resource_cases(inputs: &CaseInputs<'_>) -> Vec<SoakCaseV1> {
    let all_scenarios_pass = inputs.workload.representative.aggregate.scenario_count == 4
        && inputs.workload.representative.aggregate.scenario_pass_count == 4;
    let malicious_repo_ok = [
        "prompt-injection",
        "repository-security",
        "sandbox-kernel",
        "secret-isolation",
        "tool-runner-containment",
    ]
    .into_iter()
    .all(|id| probe_pass(inputs.probes, id));
    vec![
        release_case(
            "bounded-equivalent-soak-loop",
            true,
            inputs.workload.scenario_failures == 0,
            format!("{SOAK_ITERATIONS} deterministic corpus iterations completed without drift"),
        ),
        release_case(
            "tiny-medium-large-workloads",
            true,
            all_scenarios_pass,
            "representative tiny/medium/large Controller corpus remains fully passing",
        ),
        release_case(
            "forced-kill-recovery-matrix",
            true,
            inputs.durable_restart.passed() && probe_pass(inputs.probes, "crash-resume"),
            "crash_resume forced-kill target passed and canonical SQLite reopen retained authoritative state",
        ),
        release_case(
            "offline-no-provider-core",
            true,
            inputs.workload.representative.offline
                && probe_pass(inputs.probes, "external-intelligence"),
            "offline deterministic corpus and no-provider external-intelligence path both passed",
        ),
        release_case(
            "optional-adapter-on-off-matrix",
            true,
            probe_pass(inputs.probes, "browser-policy"),
            match inputs.browser {
                BrowserAvailability::Detected => {
                    "local Chrome detected; browser_policy exercised installed browser paths plus demand-load/shutdown behavior"
                }
                BrowserAvailability::Absent => {
                    "no local Chrome detected; browser_policy passed core absence-valid and demand-load policy paths"
                }
            },
        ),
        release_case(
            "heavy-lease-pair-admission-matrix",
            true,
            probe_pass(inputs.probes, "resource-policy"),
            "authoritative resource-policy tests exercised pair rules, conditional admission, serialization, and pressure deferral",
        ),
        release_case(
            "swap-growth-pressure-semantics",
            true,
            inputs.pressure_growth.passed() && probe_pass(inputs.probes, "resource-policy"),
            "stable occupied swap remains diagnostic while active swap-out growth constrains admission",
        ),
        release_case(
            "context-refinement-decomposition",
            true,
            inputs.context_refinement.passed(),
            "oversize evidence was reduced to a bounded packet with an expansion handle under the 8k default and 16k hard ceiling",
        ),
        release_case(
            "malicious-repository-isolation-matrix",
            true,
            malicious_repo_ok,
            "prompt injection, repository scope, Git/PATH/package surfaces, sandbox, secrets, and forked-child containment targets passed",
        ),
    ]
}

fn security_and_authority_cases(inputs: &CaseInputs<'_>) -> Vec<SoakCaseV1> {
    let no_false_completion = inputs
        .workload
        .representative
        .aggregate
        .false_completion_accepted
        == 0;
    vec![
        release_case(
            "audit-cas-checkpoint-tamper-matrix",
            true,
            probe_pass(inputs.probes, "security-resilience"),
            "security_resilience audit-chain and CAS/checkpoint tamper target passed fail-closed recovery checks",
        ),
        release_case(
            "rollback-unknown-no-duplicate-compensation",
            true,
            probe_pass(inputs.probes, "controller-resilience"),
            "controller resilience target passed rollback Unknown fencing and no-blind-redispatch recovery",
        ),
        release_case(
            "outer-budget-runaway-containment",
            true,
            probe_pass(inputs.probes, "controller-resilience")
                && probe_pass(inputs.probes, "security-resilience"),
            "Controller replan/no-refill and nested model/tool/browser autonomy-budget regressions passed after reopen",
        ),
        release_case(
            "external-intelligence-policy-matrix",
            true,
            probe_pass(inputs.probes, "external-intelligence"),
            "fake-provider minimization, policy, deadline/byte budgets, untrusted output, zero authority, and no-provider paths passed",
        ),
        release_case(
            "false-completion-remains-rejected",
            true,
            no_false_completion && probe_pass(inputs.probes, "completion-governance"),
            "deterministic DONE-claim corpus and completion-governance target accepted zero false completions",
        ),
    ]
}

fn release_case(
    case_id: &str,
    applicable: bool,
    passed: bool,
    detail: impl Into<String>,
) -> SoakCaseV1 {
    SoakCaseV1 {
        case_id: case_id.to_owned(),
        applicable,
        passed,
        detail: detail.into(),
    }
}

fn run_regression_matrix(workspace: &Path) -> Result<Vec<SoakProbeV1>, String> {
    let specs = [
        ("crash-resume", "sovereign-eval", "crash_resume", None),
        (
            "controller-resilience",
            "sovereign-controller",
            "m6_t06_resilience",
            Some("recovery-test-hooks"),
        ),
        (
            "security-resilience",
            "sovereign-eval",
            "security_resilience",
            None,
        ),
        (
            "completion-governance",
            "sovereign-eval",
            "completion_governance",
            None,
        ),
        (
            "prompt-injection",
            "sovereign-eval",
            "prompt_injection",
            None,
        ),
        (
            "external-intelligence",
            "sovereign-eval",
            "external_intelligence_policy",
            None,
        ),
        ("resource-policy", "sovereign-policy", "resources", None),
        ("repository-security", "sovereign-policy", "security", None),
        ("sandbox-kernel", "sovereign-policy", "kernel", None),
        ("secret-isolation", "sovereign-policy", "secret", None),
        ("tool-runner-containment", "sovereign-tools", "runner", None),
        ("browser-policy", "sovereign-eval", "browser_policy", None),
    ];
    specs
        .into_iter()
        .map(|(probe_id, package, target, features)| {
            run_cargo_test_probe(workspace, probe_id, package, target, features)
        })
        .collect()
}

fn run_cargo_test_probe(
    workspace: &Path,
    probe_id: &str,
    package: &str,
    target: &str,
    features: Option<&str>,
) -> Result<SoakProbeV1, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let feature_args = features.map_or_else(String::new, |value| format!(" --features {value}"));
    let command = format!(
        "cargo test -p {package} --test {target}{feature_args} --offline -- --test-threads=1"
    );
    let mut args = vec!["test", "-p", package, "--test", target];
    if let Some(features) = features {
        args.extend(["--features", features]);
    }
    args.extend(["--offline", "--", "--test-threads=1"]);
    let output = Command::new(cargo)
        .args(args)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .current_dir(workspace)
        .output()
        .map_err(|error| format!("run release regression probe {probe_id}: {error}"))?;
    let passed = output.status.success();
    let summary = test_output_summary(&output.stdout, &output.stderr, passed);
    Ok(SoakProbeV1 {
        probe_id: probe_id.to_owned(),
        command,
        passed,
        summary,
    })
}

fn test_output_summary(stdout: &[u8], stderr: &[u8], passed: bool) -> String {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    combined
        .lines()
        .rev()
        .find(|line| line.contains("test result:") || !line.trim().is_empty())
        .map_or_else(
            || {
                if passed {
                    "passed".to_owned()
                } else {
                    "failed".to_owned()
                }
            },
            |line| line.trim().to_owned(),
        )
}

fn probe_pass(probes: &[SoakProbeV1], probe_id: &str) -> bool {
    probes
        .iter()
        .find(|probe| probe.probe_id == probe_id)
        .is_some_and(|probe| probe.passed)
}

fn context_refinement_is_bounded(profile: &HardwareProfileV1) -> Result<bool, String> {
    let oversized = EvidenceItem::new(
        "release.oversized-evidence",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        "repo://release/oversized-evidence",
        "sha256:release-oversized-source",
        "release_probe",
        TrustClass::Repository,
        "prove bounded refinement",
        "0123456789abcdef".repeat(6_000),
    );
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "bounded release probe; no authority".to_owned(),
                task_contract: "inspect oversize evidence without increasing context ceiling"
                    .to_owned(),
                current_state: "offline=true".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![oversized],
                output_schema: "bounded response".to_owned(),
            },
        )
        .map_err(|error| error.to_string())?;
    let refined = packet
        .items
        .iter()
        .find(|item| item.evidence_id == "release.oversized-evidence")
        .and_then(|item| item.expansion_handle.as_ref())
        .is_some_and(|handle| handle.total_length > handle.retained_length);
    Ok(profile.default_model_input_tokens == 8_192
        && profile.hard_model_input_tokens_without_profile_override == 16_384
        && packet.budget.max_input_tokens
            <= profile.hard_model_input_tokens_without_profile_override
        && packet.metrics.final_serialized_input_tokens <= packet.budget.max_input_tokens
        && refined)
}

fn exercise_durable_soak_loop() -> Result<(u64, u64, bool), String> {
    let sequence = SOAK_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "sovereign-m9-release-soak-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let db = root.join("state.sqlite3");
    let result = (|| {
        let mut state = StateStore::open(&db).map_err(|error| error.to_string())?;
        let mut write_bytes = 0_u64;
        for iteration in 0..64_u32 {
            let key = format!("iteration-{iteration:03}");
            let value = format!(r#"{{"iteration":{iteration},"offline":true}}"#);
            write_bytes = write_bytes.saturating_add((key.len() + value.len()) as u64);
            state
                .put_state("eval.release_soak", &key, &value)
                .map_err(|error| error.to_string())?;
            if iteration % 8 == 7 {
                state.checkpoint_wal().map_err(|error| error.to_string())?;
                drop(state);
                state = StateStore::open(&db).map_err(|error| error.to_string())?;
            }
        }
        state.checkpoint_wal().map_err(|error| error.to_string())?;
        drop(state);
        let reopened = StateStore::open(&db).map_err(|error| error.to_string())?;
        let recovered = reopened
            .get_state("eval.release_soak", "iteration-063")
            .map_err(|error| error.to_string())?
            .is_some_and(|value| value.contains("\"iteration\":63"));
        reopened
            .checkpoint_wal()
            .map_err(|error| error.to_string())?;
        let bytes = sqlite_family_bytes(&db)?;
        Ok((bytes, write_bytes, recovered))
    })();
    let _ = fs::remove_dir_all(&root);
    result
}

fn sqlite_family_bytes(db: &Path) -> Result<u64, String> {
    let mut total = fs::metadata(db).map_err(|error| error.to_string())?.len();
    for suffix in ["-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", db.display()));
        if let Ok(metadata) = fs::metadata(path) {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

struct PeakRssSampler {
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<u64>,
}

impl PeakRssSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let pid = std::process::id();
        let handle = thread::spawn(move || {
            let mut peak = 0_u64;
            while !thread_stop.load(Ordering::Relaxed) {
                peak = peak.max(sample_rss_kib(pid).unwrap_or(0));
                thread::sleep(Duration::from_millis(100));
            }
            peak.max(sample_rss_kib(pid).unwrap_or(0))
        });
        Self { stop, handle }
    }

    fn finish(self) -> Result<u64, String> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|_| "release peak-RSS sampler panicked".to_owned())
            .and_then(|peak| {
                (peak > 0)
                    .then_some(peak)
                    .ok_or_else(|| "release peak-RSS sampler returned zero".to_owned())
            })
    }
}

fn sample_rss_kib(pid: u32) -> Option<u64> {
    command_stdout("/bin/ps", &["-o", "rss=", "-p", &pid.to_string()])?
        .trim()
        .parse()
        .ok()
}

fn process_cpu_time() -> Result<String, String> {
    let pid = std::process::id().to_string();
    command_stdout("/bin/ps", &["-o", "time=", "-p", &pid])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "ps did not report process CPU time".to_owned())
}

fn hardware_facts(profile: &HardwareProfileV1) -> Result<SoakHardwareV1, String> {
    let physical_bytes = command_stdout("/usr/sbin/sysctl", &["-n", "hw.memsize"])
        .ok_or_else(|| "sysctl did not report physical memory".to_owned())?
        .parse::<u64>()
        .map_err(|error| format!("parse physical memory: {error}"))?;
    Ok(SoakHardwareV1 {
        profile_id: profile.profile_id.clone(),
        architecture: std::env::consts::ARCH.to_owned(),
        operating_system: std::env::consts::OS.to_owned(),
        operating_system_version: command_stdout("/usr/bin/sw_vers", &["-productVersion"]),
        logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        physical_memory_mib: physical_bytes / (1_024 * 1_024),
        optional_browser_detected: Path::new(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        )
        .is_file(),
    })
}

fn source_identity(workspace: &Path) -> Result<(String, bool, String), String> {
    let head = git_stdout(workspace, &["rev-parse", "HEAD"])?;
    let status = git_bytes(workspace, &["status", "--porcelain=v1", "-z"])?;
    let diff = git_bytes(workspace, &["diff", "--binary", "HEAD", "--"])?;
    let untracked = git_bytes(
        workspace,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"sovereign-release-source-tree-v1\0");
    hasher.update(&status);
    hasher.update(&diff);
    for relative in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        hasher.update((relative.len() as u64).to_le_bytes());
        hasher.update(relative);
        let path = workspace.join(String::from_utf8_lossy(relative).as_ref());
        let bytes = fs::read(&path)
            .map_err(|error| format!("read untracked source {}: {error}", path.display()))?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok((
        head,
        !status.is_empty(),
        format!("sha256:{:x}", hasher.finalize()),
    ))
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| format!("resolve Sovereign workspace root: {error}"))
}

fn git_stdout(workspace: &Path, args: &[&str]) -> Result<String, String> {
    let bytes = git_bytes(workspace, args)?;
    let value = String::from_utf8(bytes).map_err(|error| format!("decode git output: {error}"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("git {} returned empty output", args.join(" ")));
    }
    Ok(value)
}

fn git_bytes(workspace: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("/usr/bin/git")
        .args(args)
        .current_dir(workspace)
        .output()
        .map_err(|error| format!("run git {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn command_stdout(executable: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(executable).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn pressure_growth_semantics(profile: &HardwareProfileV1) -> bool {
    let stable = ResourcePressureSnapshotV1 {
        schema_version: 1,
        observed_at_ms: 1_000,
        controlled_working_set_mib: 512,
        host_headroom_mib: 4_096,
        swap_used_mib: Some(10_000),
        swap_out_growth_mib_per_min: 0,
        compressor_growth_mib_per_min: 0,
        os_memory_pressure: OsMemoryPressure::Normal,
        recent_pressure_event: false,
        thermal_pressure: ThermalPressure::Normal,
        allocation_failure: false,
        repeated_resource_kill: false,
        uncontrolled_child_growth: false,
        host_free_disk_mib: Some(40_000),
    };
    let growing = ResourcePressureSnapshotV1 {
        observed_at_ms: 2_000,
        swap_out_growth_mib_per_min: profile.constrained_growth_mib_per_min.saturating_add(1),
        ..stable
    };
    stable.classify(profile) == PressureBand::Green
        && growing.classify(profile) == PressureBand::Constrained
}
