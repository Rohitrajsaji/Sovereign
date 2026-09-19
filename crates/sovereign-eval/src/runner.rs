use crate::schema::{
    EVAL_REPORT_SCHEMA_VERSION, EVAL_SCENARIO_SCHEMA_VERSION, EvalReportV1, EvalResourceMetricsV1,
    EvalResourceSourceV1, EvalRestartExerciseV1, EvalRestartMetricsV1, EvalRetrievalMetricsV1,
    EvalScale, EvalScenarioResultV1, EvalScenarioV1, EvalTokenMetricsV1, M1_8GB_PROFILE_ID,
    aggregate_scenarios, corpus_digest,
};
use crate::{EvaluationAttemptRecord, aggregate_context_metrics};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    AttemptOutcomeFacts, Channel, ContextBudget, ContextMode, ContextPacket, ContextPacketInput,
    ContextPlanner, ContextTelemetry, EvidenceChannelLink, EvidenceItem, EvidenceUseFacts,
    ProviderTokenUsage, RetrievalRouteKind, RetrievalTrace, RouteStep, StopCondition,
};
use sovereign_controller::{
    Controller, ControllerError, ExecutionRuntime, ReadinessInputs, RecoveryManager,
    ResourcePressureProbe, RoleId, RoleRegistry, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelMessage, ModelMessageRole, ModelOutputContract,
    ModelRequest, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, IsolatedCommand,
    IsolationCapabilities, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    OsMemoryPressure, PinnedExecutable, PolicyError, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
    ReconciliationPolicy, ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::StateStore;
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const TINY_APP: &[u8] = include_bytes!("../fixtures/m9/tiny/app.txt");
const MEDIUM_SOURCE: &[u8] = include_bytes!("../fixtures/m9/medium/source.txt");
const MEDIUM_TEST: &[u8] = include_bytes!("../fixtures/m9/medium/test.txt");
const LARGE_API: &[u8] = include_bytes!("../fixtures/m9/large/api.txt");
const LARGE_STORE: &[u8] = include_bytes!("../fixtures/m9/large/store.txt");
const LARGE_UI: &[u8] = include_bytes!("../fixtures/m9/large/ui.txt");
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct ScenarioObservation {
    verified_success: bool,
    false_completion_accepted: bool,
    attempts: u32,
    tokens: EvalTokenMetricsV1,
    retrieval: EvalRetrievalMetricsV1,
    resources: EvalResourceMetricsV1,
    restart: EvalRestartMetricsV1,
}

struct FakeAttempt<'a> {
    content: &'a str,
    verified_success: bool,
}

struct FakeMetricObservation {
    attempts: u32,
    retries: u32,
    tokens: EvalTokenMetricsV1,
    retrieval: EvalRetrievalMetricsV1,
}

struct FakeAttemptTelemetryContext<'a> {
    scenario_id: &'a str,
    packet: &'a ContextPacket,
    trace: &'a RetrievalTrace,
    telemetry: &'a ContextTelemetry,
    evidence_ids: &'a BTreeSet<String>,
}

struct ActivatedFixture {
    controller: Controller,
    task_id: String,
    plan_digest: String,
    registry: ProjectRegistry,
}

struct FixtureRepository {
    root: PathBuf,
    state_path: PathBuf,
}

struct NoopIsolation {
    capabilities: MacSandboxExecBackend,
}

#[derive(Clone)]
struct FixedResourcePressureProbe(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedResourcePressureProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

impl ExecutionIsolationBackend for NoopIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        self.capabilities.capabilities()
    }

    fn isolate(
        &self,
        _spec: &CommandSpec,
        _request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        Ok(IsolatedCommand {
            executable: PathBuf::from("/usr/bin/true"),
            args: Vec::new(),
        })
    }
}

impl FixtureRepository {
    fn create(label: &str, files: &[(&str, &'static [u8])]) -> Result<Self, String> {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "sovereign-m9-{label}-{}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        for (path, bytes) in files {
            let destination = root.join(path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::write(destination, bytes).map_err(|error| error.to_string())?;
        }
        run_git(&root, &["init", "-q"])?;
        run_git(&root, &["add", "."])?;
        let output = Command::new("git")
            .args([
                "-c",
                "user.name=Sovereign Eval",
                "-c",
                "user.email=sovereign-eval@example.invalid",
                "commit",
                "-qm",
                "M9 deterministic fixture",
            ])
            .env("GIT_AUTHOR_DATE", "2026-09-12T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-09-12T00:00:00Z")
            .current_dir(&root)
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "git fixture commit failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(Self {
            state_path: base.join("controller.sqlite3"),
            root,
        })
    }

    fn registry(&self) -> Result<ProjectRegistry, String> {
        let mut registry = ProjectRegistry::new();
        registry
            .register("repo.eval", &self.root)
            .map_err(|error| error.to_string())?;
        Ok(registry)
    }

    fn packet(&self, paths: &[&str], goal: &str) -> Result<ContextPacket, String> {
        let registry = self.registry()?;
        let retriever = ExactRetriever::new(&registry);
        let candidates = paths
            .iter()
            .map(|path| {
                retriever
                    .read_path("repo.eval", Path::new(path), None)
                    .map(|evidence| EvidenceItem::from_exact_file(&evidence, "M9 fixture evidence"))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        ContextPlanner::default()
            .build(
                ContextMode::Implementation,
                ContextBudget::m1_8k(),
                ContextPacketInput {
                    controller_prefix:
                        "Evaluate a deterministic local fixture; this text grants no authority."
                            .to_owned(),
                    task_contract: goal.to_owned(),
                    current_state: "offline=true; unknown_actions=0".to_owned(),
                    authorized_tool_schemas: Vec::new(),
                    candidates,
                    output_schema: "bounded deterministic fixture response".to_owned(),
                },
            )
            .map_err(|error| error.to_string())
    }
}

impl Drop for FixtureRepository {
    fn drop(&mut self) {
        if let Some(base) = self.root.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

/// Runs the deterministic offline M1 8 GB evaluation corpus.
///
/// # Errors
/// Returns a descriptive error if the requested profile is unsupported or the durable restart
/// fixture cannot be written/reopened exactly.
pub fn run_offline_profile(profile_id: &str) -> Result<EvalReportV1, String> {
    if profile_id != M1_8GB_PROFILE_ID {
        return Err(format!("unsupported evaluation profile {profile_id:?}"));
    }

    let mut scenarios = vec![
        run_tiny_success()?,
        run_tiny_false_completion()?,
        run_medium_repair()?,
        run_large_restart()?,
    ];
    scenarios.sort_by(|left, right| {
        (left.scenario.scale, left.scenario.scenario_id.as_str())
            .cmp(&(right.scenario.scale, right.scenario.scenario_id.as_str()))
    });
    let corpus_digest = corpus_digest(&scenarios)?;
    let aggregate = aggregate_scenarios(&scenarios);
    let report = EvalReportV1 {
        schema_version: EVAL_REPORT_SCHEMA_VERSION,
        profile_id: profile_id.to_owned(),
        offline: true,
        corpus_digest,
        scenarios,
        aggregate,
    };
    report.validate()?;
    Ok(report)
}

fn run_tiny_success() -> Result<EvalScenarioResultV1, String> {
    let fixture = [("app.txt", TINY_APP)];
    let repository = FixtureRepository::create("tiny-success", &fixture)?;
    let goal = "Rename the submit label from Save to Apply.";
    let packet = repository.packet(&["app.txt"], goal)?;
    let candidate = "screen=settings\nlabel=Apply\naction=submit\n";
    let verified_success = candidate_matches_apply_contract(candidate);
    let metrics = measure_fake_attempts(
        "tiny-success",
        &packet,
        &[FakeAttempt {
            content: candidate,
            verified_success,
        }],
    )?;
    Ok(scenario_result(
        scenario(
            "tiny-success",
            EvalScale::Tiny,
            &fixture,
            goal,
            true,
            true,
            false,
        ),
        ScenarioObservation {
            verified_success,
            false_completion_accepted: false,
            attempts: metrics.attempts,
            tokens: metrics.tokens,
            retrieval: metrics.retrieval,
            resources: simulated_resources(TINY_APP.len(), 64),
            restart: no_restart(),
        },
    ))
}

fn run_tiny_false_completion() -> Result<EvalScenarioResultV1, String> {
    let fixture = [("app.txt", TINY_APP)];
    let repository = FixtureRepository::create("tiny-false-completion", &fixture)?;
    let goal = "Replace Save with Apply in app.txt; reject completion until verification passes.";
    let packet = repository.packet(&["app.txt"], goal)?;
    let metrics = measure_fake_attempts(
        "tiny-false-completion",
        &packet,
        &[FakeAttempt {
            content: "done",
            verified_success: false,
        }],
    )?;
    let verified_success = false;
    let model_claims_done = true;
    let controller_accepted = controller_accepts_false_completion(&repository, &packet, goal)?;
    let false_completion_accepted = model_claims_done && !verified_success && controller_accepted;
    Ok(scenario_result(
        scenario(
            "tiny-false-completion",
            EvalScale::Tiny,
            &fixture,
            goal,
            false,
            model_claims_done,
            false,
        ),
        ScenarioObservation {
            verified_success,
            false_completion_accepted,
            attempts: metrics.attempts,
            tokens: metrics.tokens,
            retrieval: metrics.retrieval,
            resources: simulated_resources(TINY_APP.len(), 48),
            restart: no_restart(),
        },
    ))
}

fn controller_accepts_false_completion(
    repository: &FixtureRepository,
    packet: &ContextPacket,
    goal: &str,
) -> Result<bool, String> {
    let mut activated = activate_fixture_task(repository, packet, goal, "app.txt")?;
    let source = ExactRetriever::new(&activated.registry)
        .read_path("repo.eval", Path::new("app.txt"), None)
        .map_err(|error| error.to_string())?;
    let execution = DeterministicFakeBackend::new(
        fake_model_capabilities(),
        vec![ModelResponse {
            schema_version: MODEL_SCHEMA_VERSION,
            request_id: "m9-false-completion-execution".to_owned(),
            content: json!({
                "schema_version": 1,
                "evidence_ids": ["file:repo.eval:app.txt"],
                "action": {
                    "kind": "replace_literal",
                    "repository_id": "repo.eval",
                    "path": "app.txt",
                    "expected_source_digest": source.digest,
                    "old_literal": "Save",
                    "new_literal": "Apply",
                    "expected_occurrences": 1
                }
            })
            .to_string(),
            structured: None,
            tool_calls: Vec::new(),
            finish_reason: ModelFinishReason::Stop,
            usage: ModelUsage {
                input_tokens: u64::from(packet.metrics.final_serialized_input_tokens),
                output_tokens: 64,
            },
            elapsed_ms: 1,
            peak_rss_kb_during_call: None,
        }],
    )
    .map_err(|error| error.to_string())?;
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .map_err(|error| error.to_string())?;
    let executable_root = python
        .path
        .parent()
        .ok_or_else(|| "pinned python executable has no parent".to_owned())?
        .to_path_buf();
    let command_policy =
        CommandPolicy::new([python], [executable_root]).map_err(|error| error.to_string())?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME must be set for deterministic Controller fixture".to_owned())?;
    let isolation_request = IsolationRequest {
        repository_root: repository.root.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };
    let isolation = NoopIsolation {
        capabilities: MacSandboxExecBackend::detect().map_err(|error| error.to_string())?,
    };
    let base = repository
        .root
        .parent()
        .ok_or_else(|| "evaluation repository has no fixture base".to_owned())?;
    let artifacts = ArtifactStore::open(base.join("cas")).map_err(|error| error.to_string())?;
    let tool_manifest = write_tool_manifest();
    let ready = activated
        .controller
        .derive_ready_lease(
            &activated.registry,
            &activated.task_id,
            ReadinessInputs::permissive_m1("sha256:m9-eval-resources"),
            &tool_manifest,
        )
        .map_err(|error| error.to_string())?;
    let runtime = ExecutionRuntime {
        registry: &activated.registry,
        backend: &execution,
        command_policy: &command_policy,
        isolation_backend: &isolation,
        isolation_request: &isolation_request,
        artifacts: &artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let result = activated
        .controller
        .execute_replace(ready, &runtime, packet, &mut budget);
    let rejected_by_verification = matches!(result, Err(ControllerError::VerificationFailed(_)));
    let state = activated.controller.task_state(&activated.task_id);
    if !rejected_by_verification || state != Some(TaskState::RepairPending) {
        return Err(format!(
            "Controller false-completion fixture did not fail closed at verification: result={result:?}, state={state:?}"
        ));
    }
    Ok(state == Some(TaskState::Succeeded))
}

fn write_tool_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.patch".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: WRITE_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]),
        declared_risk_floor: CommandRisk::RepositoryMutation,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

fn run_medium_repair() -> Result<EvalScenarioResultV1, String> {
    let fixture = [("source.txt", MEDIUM_SOURCE), ("test.txt", MEDIUM_TEST)];
    let repository = FixtureRepository::create("medium-repair", &fixture)?;
    let goal = "Apply the focused change after one bounded failed proposal.";
    let packet = repository.packet(&["source.txt", "test.txt"], goal)?;
    let first_candidate = "component=settings-form\nlabel=Submit\nsubmit=preserve\n";
    let first_pass = candidate_matches_apply_contract(first_candidate);
    let repaired_candidate = "component=settings-form\nlabel=Apply\nsubmit=preserve\n";
    let verified_success = !first_pass && candidate_matches_apply_contract(repaired_candidate);
    let metrics = measure_fake_attempts(
        "medium-repair",
        &packet,
        &[
            FakeAttempt {
                content: first_candidate,
                verified_success: first_pass,
            },
            FakeAttempt {
                content: repaired_candidate,
                verified_success,
            },
        ],
    )?;
    if metrics.retries != 1 {
        return Err(
            "medium repair fake-model telemetry did not record exactly one retry".to_owned(),
        );
    }
    Ok(scenario_result(
        scenario(
            "medium-repair",
            EvalScale::Medium,
            &fixture,
            goal,
            true,
            true,
            false,
        ),
        ScenarioObservation {
            verified_success,
            false_completion_accepted: false,
            attempts: metrics.attempts,
            tokens: metrics.tokens,
            retrieval: metrics.retrieval,
            resources: simulated_resources(
                MEDIUM_SOURCE.len().saturating_add(MEDIUM_TEST.len()),
                192,
            ),
            restart: no_restart(),
        },
    ))
}

fn run_large_restart() -> Result<EvalScenarioResultV1, String> {
    let fixture = [
        ("api.txt", LARGE_API),
        ("store.txt", LARGE_STORE),
        ("ui.txt", LARGE_UI),
    ];
    let repository = FixtureRepository::create("large-restart", &fixture)?;
    let goal = "Recover a durable multi-file evaluation checkpoint without losing canonical state.";
    let packet = repository.packet(&["api.txt", "store.txt", "ui.txt"], goal)?;
    let metrics = measure_fake_attempts(
        "large-restart",
        &packet,
        &[FakeAttempt {
            content: "{\"recovered\":true}",
            verified_success: true,
        }],
    )?;
    let restart = exercise_controller_restart(&repository, &packet, goal, "api.txt")?;
    let verified_success = restart.recovered_value_matches && !restart.mutation_blocked;
    Ok(scenario_result(
        scenario(
            "large-restart",
            EvalScale::Large,
            &fixture,
            goal,
            true,
            true,
            true,
        ),
        ScenarioObservation {
            verified_success,
            false_completion_accepted: false,
            attempts: metrics.attempts,
            tokens: metrics.tokens,
            retrieval: metrics.retrieval,
            resources: simulated_resources(
                LARGE_API
                    .len()
                    .saturating_add(LARGE_STORE.len())
                    .saturating_add(LARGE_UI.len()),
                384,
            ),
            restart,
        },
    ))
}

fn candidate_matches_apply_contract(candidate: &str) -> bool {
    candidate.contains("label=Apply") && !candidate.contains("label=Save")
}

fn scenario<const N: usize>(
    scenario_id: &str,
    scale: EvalScale,
    fixture: &[(&str, &'static [u8]); N],
    goal: &str,
    expected_verified_success: bool,
    model_claims_done: bool,
    restart_required: bool,
) -> EvalScenarioV1 {
    EvalScenarioV1 {
        schema_version: EVAL_SCENARIO_SCHEMA_VERSION,
        scenario_id: scenario_id.to_owned(),
        scale,
        fixture_digest: digest_fixture(fixture),
        goal: goal.to_owned(),
        expected_verified_success,
        model_claims_done,
        restart_required,
    }
}

fn scenario_result(
    scenario: EvalScenarioV1,
    observation: ScenarioObservation,
) -> EvalScenarioResultV1 {
    let restart_ok = !scenario.restart_required
        || (observation.restart.exercise == EvalRestartExerciseV1::Exercised
            && observation.restart.durable_state_reopened
            && observation.restart.recovered_value_matches
            && observation.restart.unknown_actions == 0
            && !observation.restart.mutation_blocked);
    let scenario_passed = observation.verified_success == scenario.expected_verified_success
        && !observation.false_completion_accepted
        && restart_ok;
    EvalScenarioResultV1 {
        scenario,
        scenario_passed,
        verified_success: observation.verified_success,
        false_completion_accepted: observation.false_completion_accepted,
        attempts: observation.attempts,
        retries: observation.attempts.saturating_sub(1),
        tokens: observation.tokens,
        retrieval: observation.retrieval,
        resources: observation.resources,
        restart: observation.restart,
    }
}

fn measure_fake_attempts(
    scenario_id: &str,
    packet: &ContextPacket,
    attempts: &[FakeAttempt<'_>],
) -> Result<FakeMetricObservation, String> {
    if attempts.is_empty() {
        return Err("evaluation fake-model scenario requires at least one attempt".to_owned());
    }
    let responses = attempts
        .iter()
        .enumerate()
        .map(|(index, attempt)| fake_attempt_response(scenario_id, packet, index, attempt))
        .collect::<Vec<_>>();
    let backend = DeterministicFakeBackend::new(fake_model_capabilities(), responses)
        .map_err(|error| error.to_string())?;
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 512,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .map_err(|error| error.to_string())?;
    let trace = exact_trace(packet, scenario_id)?;
    let evidence_ids = trace
        .evidence_channels
        .iter()
        .map(|link| link.evidence_id.clone())
        .collect::<BTreeSet<_>>();
    let telemetry = ContextTelemetry::default();
    let telemetry_context = FakeAttemptTelemetryContext {
        scenario_id,
        packet,
        trace: &trace,
        telemetry: &telemetry,
        evidence_ids: &evidence_ids,
    };
    let mut records = Vec::with_capacity(attempts.len());
    let mut input_tokens = 0_u64;
    let mut output_tokens = 0_u64;
    for (index, attempt) in attempts.iter().enumerate() {
        let request = fake_attempt_request(scenario_id, packet, index);
        let response = backend
            .complete(&request)
            .map_err(|error| error.to_string())?;
        input_tokens = input_tokens.saturating_add(response.usage.input_tokens);
        output_tokens = output_tokens.saturating_add(response.usage.output_tokens);
        records.push(fake_attempt_record(
            &telemetry_context,
            index,
            attempt,
            response,
        ));
    }
    backend.unload().map_err(|error| error.to_string())?;
    let report = aggregate_context_metrics(&records);
    let group = report
        .groups
        .first()
        .ok_or_else(|| "evaluation context metric group missing".to_owned())?;
    let exact = group
        .routes
        .get(&RetrievalRouteKind::Exact)
        .ok_or_else(|| "evaluation exact-route metrics missing".to_owned())?;
    Ok(FakeMetricObservation {
        attempts: u32::try_from(group.attempts).unwrap_or(u32::MAX),
        retries: u32::try_from(group.retries).unwrap_or(u32::MAX),
        tokens: EvalTokenMetricsV1 {
            input_tokens,
            output_tokens,
            total_tokens: input_tokens.saturating_add(output_tokens),
            source: "context_telemetry_provider_authoritative_v1".to_owned(),
        },
        retrieval: EvalRetrievalMetricsV1 {
            attempts: exact.attempts,
            selected: exact.selected,
            useful_selected: exact.useful_selected,
            source: "aggregate_context_metrics_v1".to_owned(),
        },
    })
}

fn fake_attempt_response(
    scenario_id: &str,
    packet: &ContextPacket,
    index: usize,
    attempt: &FakeAttempt<'_>,
) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: format!("{scenario_id}-template-{index}"),
        content: attempt.content.to_owned(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(packet.metrics.final_serialized_input_tokens),
            output_tokens: u64::try_from(attempt.content.len().div_ceil(4).max(1))
                .unwrap_or(u64::MAX),
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

fn fake_attempt_request(scenario_id: &str, packet: &ContextPacket, index: usize) -> ModelRequest {
    ModelRequest {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: format!("{scenario_id}-attempt-{index}"),
        messages: vec![ModelMessage {
            role: ModelMessageRole::User,
            content: packet.serialized_input.clone(),
            tool_call_id: None,
        }],
        tools: Vec::new(),
        output_contract: ModelOutputContract::Text,
        input_token_ceiling: 8_000,
        max_output_tokens: 128,
        deadline_ms: 1_000,
        temperature_milli: 0,
    }
}

fn fake_attempt_record(
    context: &FakeAttemptTelemetryContext<'_>,
    index: usize,
    attempt: &FakeAttempt<'_>,
    response: ModelResponse,
) -> EvaluationAttemptRecord {
    let evidence_use = if attempt.verified_success {
        EvidenceUseFacts {
            cited_evidence_ids: context.evidence_ids.clone(),
            verification_evidence_ids: context.evidence_ids.clone(),
            ..EvidenceUseFacts::default()
        }
    } else {
        EvidenceUseFacts::default()
    };
    let metrics = context.telemetry.measure(
        context.packet,
        context.trace,
        &ProviderTokenUsage {
            input_tokens: Some(response.usage.input_tokens),
            output_tokens: Some(response.usage.output_tokens),
            tokenizer_id: Some("deterministic-fake-provider-v1".to_owned()),
        },
        &AttemptOutcomeFacts {
            verified_success: attempt.verified_success,
            accepted_change_set: attempt.verified_success,
            model_output_for_token_fallback: response.content,
            evidence_use,
            ..AttemptOutcomeFacts::default()
        },
    );
    EvaluationAttemptRecord {
        task_id: context.scenario_id.to_owned(),
        depth: "d1".to_owned(),
        role: "role.eval".to_owned(),
        attempt_id: format!("{}-attempt-{index}", context.scenario_id),
        attempt_index: u32::try_from(index).unwrap_or(u32::MAX),
        metrics,
    }
}

fn exact_trace(packet: &ContextPacket, scenario_id: &str) -> Result<RetrievalTrace, String> {
    let evidence = packet
        .items
        .iter()
        .filter(|item| item.repository_id.as_deref() == Some("repo.eval"))
        .collect::<Vec<_>>();
    if evidence.is_empty() {
        return Err("evaluation packet contains no repository evidence".to_owned());
    }
    let selected_ids = evidence
        .iter()
        .map(|item| item.evidence_id.clone())
        .collect::<Vec<_>>();
    Ok(RetrievalTrace {
        trace_id: format!("retrieval:{scenario_id}"),
        route: vec![RouteStep {
            channel: Channel::Exact,
            reason: "deterministic M9 fixture paths".to_owned(),
            candidate_count: evidence.len(),
            selected_count: evidence.len(),
            candidate_ids: selected_ids.clone(),
            selected_ids,
            freshness_checked: true,
            stale_rejected: Some(0),
            source_refresh_count: 0,
            source_snapshot: None,
            source_fingerprint: None,
            bound: None,
        }],
        candidate_count: evidence.len(),
        selected_count: evidence.len(),
        evidence_channels: evidence
            .into_iter()
            .map(|item| EvidenceChannelLink {
                evidence_id: item.evidence_id.clone(),
                channel: Channel::Exact,
                source_digest: item.source_digest.clone(),
                content_digest: item.content_digest.clone(),
            })
            .collect(),
        freshness_checked: true,
        stale_rejected: Some(0),
        source_refresh_count: 0,
        source_snapshot: None,
        source_fingerprint: None,
        expansion_count: 0,
        stop_reason: StopCondition::Satisfied,
        semantic_available: false,
        semantic_unavailable_reason: Some("not required by deterministic exact fixture".to_owned()),
    })
}

fn fake_model_capabilities() -> ModelCapabilities {
    ModelCapabilities {
        schema_version: MODEL_SCHEMA_VERSION,
        model_id: "fake-m9-eval".to_owned(),
        parameter_class: "fixture".to_owned(),
        quantization: "fixture".to_owned(),
        max_context_tokens: 16_384,
        supports_tools: false,
        supports_json_schema: true,
        local: true,
    }
}

fn simulated_resources(fixture_bytes: usize, base_mib: u64) -> EvalResourceMetricsV1 {
    let kib = base_mib
        .saturating_mul(1_024)
        .saturating_add(u64::try_from(fixture_bytes).unwrap_or(u64::MAX));
    EvalResourceMetricsV1 {
        peak_rss_kib: kib,
        source: EvalResourceSourceV1::DeterministicSimulation,
    }
}

fn no_restart() -> EvalRestartMetricsV1 {
    EvalRestartMetricsV1 {
        exercise: EvalRestartExerciseV1::NotExercised,
        durable_state_reopened: false,
        recovered_value_matches: false,
        unknown_actions: 0,
        mutation_blocked: false,
    }
}

fn exercise_controller_restart(
    repository: &FixtureRepository,
    packet: &ContextPacket,
    goal: &str,
    path: &str,
) -> Result<EvalRestartMetricsV1, String> {
    let activated = activate_fixture_task(repository, packet, goal, path)?;
    let expected_task_digest = activated
        .controller
        .task_contract_digest(&activated.task_id)
        .ok_or_else(|| "activated evaluation task contract digest missing".to_owned())?
        .to_owned();
    let task_id = activated.task_id;
    let plan_digest = activated.plan_digest;
    let registry = activated.registry;
    drop(activated.controller);
    let state = StateStore::open(&repository.state_path).map_err(|error| error.to_string())?;
    let (recovered, summary) =
        RecoveryManager::recover(state, &registry).map_err(|error| error.to_string())?;
    let recovered_value_matches = summary.plan_digest == plan_digest
        && recovered.task_contract_digest(&task_id) == Some(expected_task_digest.as_str())
        && recovered.task_state(&task_id) == Some(TaskState::Planned);
    Ok(EvalRestartMetricsV1 {
        exercise: EvalRestartExerciseV1::Exercised,
        durable_state_reopened: true,
        recovered_value_matches,
        unknown_actions: u64::try_from(summary.unknown_action_ids.len()).unwrap_or(u64::MAX),
        mutation_blocked: summary.mutation_blocked,
    })
}

fn activate_fixture_task(
    repository: &FixtureRepository,
    packet: &ContextPacket,
    goal: &str,
    path: &str,
) -> Result<ActivatedFixture, String> {
    let registry = repository.registry()?;
    let snapshot = registry
        .snapshot("repo.eval")
        .map_err(|error| error.to_string())?;
    let backend = fixture_plan_backend(packet, goal, path)?;
    let input = fixture_plan_input(&snapshot, packet, goal)?;
    let validator =
        PlanValidator::new(ValidationEnvironment::default()).map_err(|error| error.to_string())?;
    let compiler = PlanCompiler::new(&backend, &validator, "m9-eval-compiler-v1")
        .map_err(|e| e.to_string())?;
    let mut budget = ModelCallBudget::new(1, 1_000);
    let compilation = compiler
        .compile(&input, &mut budget)
        .map_err(|error| error.to_string())?;
    backend.unload().map_err(|error| error.to_string())?;
    let state = StateStore::open(&repository.state_path).map_err(|error| error.to_string())?;
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        deterministic_green_pressure(),
    )));
    let activation = controller
        .activate(compilation, &registry)
        .map_err(|error| error.to_string())?;
    let task_id = activation
        .task_ids
        .first()
        .ok_or_else(|| "M9 evaluation activation produced no task".to_owned())?
        .clone();
    Ok(ActivatedFixture {
        controller,
        task_id,
        plan_digest: activation.plan_digest,
        registry,
    })
}

fn deterministic_green_pressure() -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
        observed_at_ms: 1_000,
        controlled_working_set_mib: 512,
        host_headroom_mib: 6_144,
        swap_used_mib: Some(0),
        swap_out_growth_mib_per_min: 0,
        compressor_growth_mib_per_min: 0,
        os_memory_pressure: OsMemoryPressure::Normal,
        recent_pressure_event: false,
        thermal_pressure: ThermalPressure::Normal,
        allocation_failure: false,
        repeated_resource_kill: false,
        uncontrolled_child_growth: false,
        host_free_disk_mib: Some(8_192),
    }
}

fn fixture_plan_backend(
    packet: &ContextPacket,
    goal: &str,
    path: &str,
) -> Result<DeterministicFakeBackend, String> {
    let proposal = json!({
        "tasks": [{
            "title": "M9 deterministic evaluation task",
            "objective": goal,
            "rationale": "Exact current fixture evidence defines one bounded task.",
            "files": [path],
            "symbols": [],
            "evidence_queries": [],
            "expected_change": "Satisfy the deterministic evaluation goal."
        }]
    });
    let response = ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "m9-plan-template".to_owned(),
        content: proposal.to_string(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(packet.metrics.final_serialized_input_tokens),
            output_tokens: 128,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    };
    let backend = DeterministicFakeBackend::new(fake_model_capabilities(), vec![response])
        .map_err(|error| error.to_string())?;
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 512,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .map_err(|error| error.to_string())?;
    Ok(backend)
}

fn fixture_plan_input(
    snapshot: &RepositorySnapshot,
    packet: &ContextPacket,
    goal: &str,
) -> Result<PlanCompilationInput, String> {
    let role = canonical_implementer_role()?;
    let skills = vec![capability(
        "skill.focused-edit",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )];
    let write_tool = capability(
        "tool.patch",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );
    let read_tool = capability(
        "tool.read",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let policy: Value = serde_json::from_str(include_str!("../fixtures/m9/policy.json"))
        .map_err(|e| e.to_string())?;
    Ok(PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.m9.eval".to_owned(),
        compiled_at: "2026-09-20T00:00:00Z".to_owned(),
        project_id: "project.m9.eval".to_owned(),
        project_name: "M9 deterministic evaluation fixture".to_owned(),
        workspace_roots: vec![snapshot.root.display().to_string()],
        goal_id: "goal.m9.eval".to_owned(),
        goal_statement: goal.to_owned(),
        goal_invariants: vec!["Remain offline and preserve fixture scope.".to_owned()],
        goal_non_goals: vec!["Do not broaden authority.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: snapshot.repository_id.clone(),
            root: snapshot.root.display().to_string(),
            head: snapshot.head.clone(),
            branch: snapshot.branch.clone(),
            dirty_digest: snapshot.dirty_digest.clone(),
            protected_changes_present: snapshot.protected_changes_present,
            languages: vec!["text".to_owned()],
        },
        policy,
        role,
        skills,
        tools: vec![write_tool, read_tool],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: packet.clone(),
        m3: None,
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    })
}

fn capability(id: &str, digest: &str) -> Value {
    json!({"id": id, "version": "1.0.0", "digest": digest})
}

fn canonical_implementer_role() -> Result<Value, String> {
    let pin = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .map_err(|error| error.to_string())?;
    Ok(json!({"id": pin.id, "version": pin.version, "digest": pin.digest}))
}

fn run_git(root: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn digest_fixture<const N: usize>(fixture: &[(&str, &'static [u8]); N]) -> String {
    let mut hasher = Sha256::new();
    for (path, bytes) in fixture {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        hasher.update([0xff]);
    }
    format!("sha256:{:x}", hasher.finalize())
}
