#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    Controller, ControllerError, ExecutionRuntime, ReadinessInputs, ResourcePressureProbe, RoleId,
    RoleRegistry, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanIr, PlanReplanInput, PlanValidator, ReplanScope,
    ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    OsMemoryPressure, PinnedExecutable, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
    ReconciliationPolicy, ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::{ActionTransition, NewActionRecord, StateStore};
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SETTINGS_FORM: &[u8] = include_bytes!("fixtures/scenario1/src/settings/SettingsForm.tsx");
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const READ_TOOL_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct FixedPressureProbe(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedPressureProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

fn green_snapshot(observed_at_ms: i64) -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
        observed_at_ms,
        controlled_working_set_mib: 512,
        host_headroom_mib: 6_144,
        swap_used_mib: Some(9_728),
        swap_out_growth_mib_per_min: 0,
        compressor_growth_mib_per_min: 0,
        os_memory_pressure: OsMemoryPressure::Normal,
        recent_pressure_event: false,
        thermal_pressure: ThermalPressure::Normal,
        allocation_failure: false,
        repeated_resource_kill: false,
        uncontrolled_child_growth: false,
        host_free_disk_mib: Some(64 * 1_024),
    }
}

struct FixtureRepo {
    base: PathBuf,
    root: PathBuf,
}

impl FixtureRepo {
    fn create(label: &str) -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for macOS Seatbelt tests"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-completion-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        let settings = root.join("src/settings");
        fs::create_dir_all(&settings)
            .unwrap_or_else(|error| panic!("create fixture directories: {error}"));
        fs::write(settings.join("SettingsForm.tsx"), SETTINGS_FORM)
            .unwrap_or_else(|error| panic!("write SettingsForm fixture: {error}"));
        fs::write(
            root.join("Verify.mk"),
            concat!(
                ".PHONY: pass fail widen\n",
                "pass:\n\t@true\n",
                "fail:\n\t@false\n",
                "widen:\n\t@printf 'out-of-scope\\n' > out-of-scope.txt\n",
            ),
        )
        .unwrap_or_else(|error| panic!("write verification makefile: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "sovereign-eval@example.invalid"],
        );
        git(&root, &["config", "user.name", "Sovereign Eval"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "completion governance baseline"]);
        Self { base, root }
    }

    fn state_path(&self) -> PathBuf {
        self.base.join("state.sqlite3")
    }
}

impl Drop for FixtureRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct PreparedContext {
    registry: ProjectRegistry,
    packet: ContextPacket,
    snapshot: RepositorySnapshot,
    form_digest: String,
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn global_policy(build_heavy: bool) -> Value {
    let mut policy: Value = serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse Scenario 1 policy fixture: {error}"));
    if build_heavy {
        policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY"]);
    }
    policy
}

fn capability(id: &str, digest: &str) -> Value {
    json!({"id": id, "version": "1.0.0", "digest": digest})
}

fn canonical_implementer_role() -> Value {
    let pin = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .unwrap_or_else(|error| panic!("canonical implementer pin: {error}"));
    json!({"id": pin.id, "version": pin.version, "digest": pin.digest})
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

fn prepare_context(fixture: &FixtureRepo) -> PreparedContext {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &fixture.root)
        .unwrap_or_else(|error| panic!("register repository: {error}"));
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot repository: {error}"));
    let form = ExactRetriever::new(&registry)
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read SettingsForm: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns completion authority.".to_owned(),
                task_contract: "Rename the Settings button from Save to Apply.".to_owned(),
                current_state: format!("dirty_digest={}", snapshot.dirty_digest),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![EvidenceItem::from_exact_file(
                    &form,
                    "exact current Settings form",
                )],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build context packet: {error}"));
    PreparedContext {
        registry,
        packet,
        snapshot,
        form_digest: form.digest,
    }
}

fn response(content: &Value, packet_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "completion-governance-model-done".to_owned(),
        content: content.to_string(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(packet_tokens),
            output_tokens: 128,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

fn backend(responses: Vec<ModelResponse>) -> DeterministicFakeBackend {
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-completion-governance-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        responses,
    )
    .unwrap_or_else(|error| panic!("create deterministic backend: {error}"))
}

fn m3_plan_proposal(local_id: &str, title: &str, command_target: Option<&str>) -> Value {
    let acceptance = command_target.map_or_else(
        || {
            json!([{
                "kind": "diff",
                "description": "The scoped Save-to-Apply diff is accepted.",
                "manual_gate_id": Value::Null
            }])
        },
        |target| {
            json!([{
                "kind": "command",
                "description": "The governed completion verification command must succeed.",
                "manual_gate_id": Value::Null,
                "command_spec": {
                    "tool_id": "tool.patch",
                    "mode": "exec",
                    "program": "make",
                    "args": ["-f", "Verify.mk", target],
                    "repository_id": "repo.app",
                    "working_dir_relative": ".",
                    "literal_env": {},
                    "secret_env": {},
                    "timeout_seconds": 10,
                    "output_limit_bytes": 16384
                },
                "expected_exit_codes": [0]
            }])
        },
    );
    json!({
        "tasks": [{
            "local_id": local_id,
            "repository_id": "repo.app",
            "title": title,
            "objective": "Change Save to Apply in SettingsForm.",
            "rationale": "Exact current source identifies one bounded edit.",
            "files": ["src/settings/SettingsForm.tsx"],
            "symbols": ["SettingsForm"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "SettingsForm renders Apply.",
            "acceptance": acceptance
        }]
    })
}

fn m3_plan_proposal_claiming_done(
    local_id: &str,
    title: &str,
    command_target: Option<&str>,
) -> Value {
    let mut proposal = m3_plan_proposal(local_id, title, command_target);
    proposal["tasks"][0]["rationale"] = json!(
        "DONE: the model claims the implementation is complete; deterministic verification remains authoritative."
    );
    proposal
}

fn depth_d3() -> sovereign_plan::DepthDecision {
    let mut decision = DepthClassifier.classify(&DepthFeatureInput {
        repository_count: 1,
        language_count: 1,
        expected_files: 1,
        expected_modules: 1,
        expected_symbols: 1,
        ..DepthFeatureInput::default()
    });
    decision.mode = ExecutionDepth::D3;
    "completion governance fixture".clone_into(&mut decision.reason);
    decision
}

fn compile_plan(
    prepared: &PreparedContext,
    label: &str,
    proposal: &Value,
    m3: Option<M3PlanningInput>,
    build_heavy: bool,
) -> PlanCompilationResult {
    let planner = backend(vec![response(
        proposal,
        prepared.packet.metrics.final_serialized_input_tokens,
    )]);
    planner
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load planning backend: {error}"));
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("construct validator: {error}"));
    let compiler = PlanCompiler::new(&planner, &validator, "completion-governance-compiler-v1")
        .unwrap_or_else(|error| panic!("construct compiler: {error}"));
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: format!("compile.completion.{label}"),
        compiled_at: "2026-09-20T00:00:00Z".to_owned(),
        project_id: "project.completion-governance".to_owned(),
        project_name: "M9-T02 completion governance".to_owned(),
        workspace_roots: vec![prepared.snapshot.root.display().to_string()],
        goal_id: "goal.completion-governance".to_owned(),
        goal_statement: "Change Save to Apply in SettingsForm.".to_owned(),
        goal_invariants: vec!["Preserve submit behavior.".to_owned()],
        goal_non_goals: vec!["Do not widen repository scope.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: prepared.snapshot.repository_id.clone(),
            root: prepared.snapshot.root.display().to_string(),
            head: prepared.snapshot.head.clone(),
            branch: prepared.snapshot.branch.clone(),
            dirty_digest: prepared.snapshot.dirty_digest.clone(),
            protected_changes_present: prepared.snapshot.protected_changes_present,
            languages: vec!["typescript".to_owned()],
        },
        policy: global_policy(build_heavy),
        role: canonical_implementer_role(),
        skills: vec![capability(
            "skill.focused-edit",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )],
        tools: vec![
            capability("tool.patch", WRITE_TOOL_DIGEST),
            capability("tool.read", READ_TOOL_DIGEST),
        ],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: prepared.packet.clone(),
        m3,
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile {label}: {error}"));
    planner
        .unload()
        .unwrap_or_else(|error| panic!("unload planning backend: {error}"));
    result
}

fn compile_initial(prepared: &PreparedContext, label: &str) -> PlanCompilationResult {
    compile_m3(
        prepared,
        label,
        &m3_plan_proposal("rename-label", "Rename Settings submit label", None),
        None,
        false,
    )
}

fn compile_m3(
    prepared: &PreparedContext,
    label: &str,
    proposal: &Value,
    replan: Option<PlanReplanInput>,
    build_heavy: bool,
) -> PlanCompilationResult {
    compile_plan(
        prepared,
        label,
        proposal,
        Some(M3PlanningInput {
            depth: depth_d3(),
            supplied_sources: Vec::new(),
            additional_repositories: Vec::new(),
            manual_gates: Vec::new(),
            absence_evaluator: None,
            replan,
        }),
        build_heavy,
    )
}

fn execution_proposal(prepared: &PreparedContext) -> Value {
    json!({
        "schema_version": 1,
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": prepared.form_digest,
            "old_literal": "Save",
            "new_literal": "Apply",
            "expected_occurrences": 1
        }
    })
}

fn activate(
    fixture: &FixtureRepo,
    prepared: &PreparedContext,
    compilation: PlanCompilationResult,
) -> (Controller, String) {
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open Controller state: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(20_000))));
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate plan: {error}"));
    let task_id = activation
        .task_ids
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("activation must expose one task"));
    (controller, task_id)
}

fn execute_task(
    fixture: &FixtureRepo,
    prepared: &PreparedContext,
    controller: &mut Controller,
    task_id: &str,
) -> Result<(), ControllerError> {
    let execution = backend(vec![response(
        &execution_proposal(prepared),
        prepared.packet.metrics.final_serialized_input_tokens,
    )]);
    let artifacts = ArtifactStore::open(fixture.base.join("cas"))
        .unwrap_or_else(|error| panic!("open artifact store: {error}"));
    let ready = controller.derive_ready_lease(
        &prepared.registry,
        task_id,
        ReadinessInputs::permissive_m1("sha256:completion-resource-admission"),
        &write_tool_manifest(),
    )?;
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")?;
    let make = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")?;
    let toolchain_roots = [python.path.clone(), make.path.clone()]
        .into_iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect::<BTreeSet<_>>();
    let command_policy = CommandPolicy::new([python, make], toolchain_roots)?;
    let isolation_backend = MacSandboxExecBackend::detect()?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| ControllerError::NotReady("HOME is not set".to_owned()))?;
    let isolation_request = IsolationRequest {
        repository_root: fixture.root.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };
    let runtime = ExecutionRuntime {
        registry: &prepared.registry,
        backend: &execution,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &isolation_request,
        artifacts: &artifacts,
        tool_manifest: &write_tool_manifest(),
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(4, 30_000);
    controller
        .execute_replace(ready, &runtime, &prepared.packet, &mut budget)
        .map(|_| ())
}

fn completed_controller(label: &str) -> (FixtureRepo, PreparedContext, Controller, String) {
    let fixture = FixtureRepo::create(label);
    let prepared = prepare_context(&fixture);
    let compilation = compile_initial(&prepared, label);
    let (mut controller, task_id) = activate(&fixture, &prepared, compilation);
    execute_task(&fixture, &prepared, &mut controller, &task_id)
        .unwrap_or_else(|error| panic!("execute successful task: {error}"));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    (fixture, prepared, controller, task_id)
}

fn assert_completion_blocked(
    controller: &mut Controller,
    registry: &ProjectRegistry,
    needle: &str,
) {
    let error = match controller.complete_goal(registry) {
        Err(error) => error,
        Ok(record) => panic!("completion unexpectedly succeeded: {record:?}"),
    };
    assert!(
        error.to_string().contains(needle),
        "completion error {error:?} did not contain {needle:?}"
    );
    assert_eq!(
        controller
            .completion_record()
            .unwrap_or_else(|error| panic!("read completion record: {error}")),
        None
    );
}

#[test]
fn model_done_claim_cannot_override_failed_controller_verification() {
    let fixture = FixtureRepo::create("failed-verification");
    let prepared = prepare_context(&fixture);
    let done_claim = m3_plan_proposal_claiming_done("rename-label", "Rename label", Some("fail"));
    assert!(
        done_claim["tasks"][0]["rationale"]
            .as_str()
            .is_some_and(|rationale| rationale.contains("DONE:"))
    );
    let compilation = compile_m3(&prepared, "failed-verification", &done_claim, None, true);
    let (mut controller, task_id) = activate(&fixture, &prepared, compilation);
    let Err(error) = execute_task(&fixture, &prepared, &mut controller, &task_id) else {
        panic!("governed command verification unexpectedly passed");
    };
    let verification = match error {
        ControllerError::VerificationFailed(verification) => verification,
        other => panic!("expected real Controller verification failure, got {other:?}"),
    };
    assert!(!verification.passed);
    assert_eq!(
        verification.failure_code.as_deref(),
        Some("command_unexpected_exit")
    );
    assert!(
        verification
            .command_results
            .iter()
            .any(|result| !result.passed)
    );
    assert_ne!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_completion_blocked(&mut controller, &prepared.registry, "is not succeeded");
}

#[test]
fn unmapped_must_requirement_blocks_completion_even_after_real_task_success() {
    let fixture = FixtureRepo::create("unmapped-must");
    let prepared = prepare_context(&fixture);
    let initial = compile_m3(
        &prepared,
        "unmapped-must-initial",
        &m3_plan_proposal("rename-label", "Initial rename label", None),
        None,
        false,
    );
    let mut previous = initial.plan().as_value().clone();
    let task_id = previous["tasks"][0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("initial task id missing"))
        .to_owned();
    let invariant_id =
        previous["tasks"][0]["implementation_contract"]["invariants"][0]["clause_id"]
            .as_str()
            .unwrap_or_else(|| panic!("stable invariant id missing"))
            .to_owned();
    previous["requirements"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("requirements array missing"))
        .push(json!({
            "requirement_id": "REQ.unmapped.must",
            "priority": "must",
            "kind": "functional",
            "text": "A second must requirement must be explicitly covered.",
            "source": {"kind": "user", "locator": "fixture:unmapped-must"},
            "evidence_expectations": ["diff_result"]
        }));
    let previous_digest = PlanIr::from_value(previous.clone())
        .canonical_digest()
        .unwrap_or_else(|error| panic!("digest previous plan: {error}"));
    let replan = PlanReplanInput {
        previous_plan: previous,
        previous_plan_digest: previous_digest,
        scope: ReplanScope::Plan,
        invalidated_contract_ids: vec![invariant_id],
        affected_task_ids: vec![task_id.clone()],
    };
    let compilation = compile_m3(
        &prepared,
        "unmapped-must-revision",
        &m3_plan_proposal(&task_id, "Replanned rename label", None),
        Some(replan),
        false,
    );
    assert_eq!(
        compilation.plan().as_value()["requirements"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    let (mut controller, active_task_id) = activate(&fixture, &prepared, compilation);
    execute_task(&fixture, &prepared, &mut controller, &active_task_id)
        .unwrap_or_else(|error| panic!("execute replanned task: {error}"));
    assert_eq!(
        controller.task_state(&active_task_id),
        Some(TaskState::Succeeded)
    );
    assert_completion_blocked(
        &mut controller,
        &prepared.registry,
        "REQ.unmapped.must has no succeeded task mapping",
    );
}

#[test]
fn real_unknown_action_lifecycle_blocks_completion() {
    let (fixture, prepared, mut controller, _task_id) = completed_controller("unknown-action");
    let epoch = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("read execution epoch: {error}"));
    let policy_digest = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("read action records: {error}"))
        .into_iter()
        .find(|record| record.state == "committed")
        .map_or_else(
            || panic!("successful task must leave a committed action"),
            |record| record.policy_digest,
        );
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen state for unknown action: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: "action.completion.unknown",
            state: "prepared",
            payload_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            policy_digest: &policy_digest,
            execution_epoch: epoch,
            event_id: "event.completion.unknown.prepared",
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert prepared action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: "action.completion.unknown",
            expected_state: "prepared",
            next_state: "authorized",
            expected_epoch: epoch,
            event_id: "event.completion.unknown.authorized",
            event_kind: "authorized",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("authorize fixture action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: "action.completion.unknown",
            expected_state: "authorized",
            next_state: "dispatched",
            expected_epoch: epoch,
            event_id: "event.completion.unknown.dispatched",
            event_kind: "dispatched",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("dispatch unknown fixture action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: "action.completion.unknown",
            expected_state: "dispatched",
            next_state: "unknown",
            expected_epoch: epoch,
            event_id: "event.completion.unknown.unknown",
            event_kind: "unknown",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("mark fixture action unknown: {error}"));
    drop(state);
    assert_completion_blocked(
        &mut controller,
        &prepared.registry,
        "unresolved action/process/rollback authority",
    );
}

#[test]
fn out_of_scope_diff_is_rejected_by_controller_verification_and_cannot_complete() {
    let fixture = FixtureRepo::create("out-of-scope");
    let prepared = prepare_context(&fixture);
    let compilation = compile_m3(
        &prepared,
        "out-of-scope",
        &m3_plan_proposal("rename-label", "Rename label", Some("widen")),
        None,
        true,
    );
    let (mut controller, task_id) = activate(&fixture, &prepared, compilation);
    let Err(error) = execute_task(&fixture, &prepared, &mut controller, &task_id) else {
        panic!("out-of-scope command diff unexpectedly passed verification");
    };
    let verification = match error {
        ControllerError::VerificationFailed(verification) => verification,
        other => panic!("expected scope verification failure, got {other:?}"),
    };
    assert!(!verification.passed);
    assert_eq!(
        verification.failure_code.as_deref(),
        Some("scope_audit_failed")
    );
    assert_ne!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_completion_blocked(&mut controller, &prepared.registry, "is not succeeded");
}

#[test]
#[allow(clippy::too_many_lines)]
fn valid_completion_is_bound_once_and_exact_repeat_adds_no_event_or_checkpoint() {
    let (_fixture, prepared, mut controller, task_id) = completed_controller("valid");
    let checkpoint_before = controller
        .state()
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("checkpoint before completion: {error}"))
        .unwrap_or_else(|| panic!("activation/execution must establish a checkpoint"));
    let record = controller
        .complete_goal(&prepared.registry)
        .unwrap_or_else(|error| panic!("complete valid goal: {error}"));
    assert!(record.action_recovery_clear);
    assert_eq!(
        record.task_resolution.get(&task_id),
        Some(&TaskState::Succeeded)
    );
    assert_eq!(record.must_requirement_coverage.len(), 1);
    assert!(
        record
            .must_requirement_coverage
            .values()
            .all(|tasks| tasks == &vec![task_id.clone()])
    );
    let proof = record
        .artifact_proofs
        .values()
        .next()
        .unwrap_or_else(|| panic!("completion artifact proof missing"));
    assert_eq!(proof.locator, "controller-change-set");
    assert!(!proof.output_binding_digest.is_empty());
    assert!(!proof.verification_id.is_empty());
    assert!(!proof.verification_artifact_digest.is_empty());
    assert!(!proof.concrete_digests.is_empty());
    assert_eq!(
        record.checkpoint.generation,
        checkpoint_before.generation + 1,
        "completion record must bind checkpoint A"
    );
    assert_eq!(
        controller
            .completion_record()
            .unwrap_or_else(|error| panic!("read durable completion record: {error}")),
        Some(record.clone())
    );

    let completion_events = controller
        .state()
        .journal_after(0)
        .unwrap_or_else(|error| panic!("read completion journal: {error}"))
        .into_iter()
        .filter(|event| event.event_kind == "project_completed")
        .collect::<Vec<_>>();
    assert_eq!(completion_events.len(), 1);
    assert_eq!(
        completion_events[0].sequence,
        record.checkpoint.action_sequence + 1,
        "the single completion publication must immediately follow checkpoint A"
    );
    let checkpoint_after = controller
        .state()
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("checkpoint after completion: {error}"))
        .unwrap_or_else(|| panic!("completion must seal a checkpoint"));
    assert_eq!(
        checkpoint_after.generation,
        record.checkpoint.generation + 1,
        "checkpoint B must seal the atomic completion publication"
    );
    assert_eq!(
        checkpoint_after.action_sequence,
        completion_events[0].sequence
    );
    let sequence_after = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal sequence after completion: {error}"));

    let repeated = controller
        .complete_goal(&prepared.registry)
        .unwrap_or_else(|error| panic!("repeat exact completion: {error}"));
    assert_eq!(repeated, record);
    assert_eq!(
        controller
            .state()
            .latest_checkpoint_integrity()
            .unwrap_or_else(|error| panic!("checkpoint after repeat: {error}"))
            .unwrap_or_else(|| panic!("repeat must retain completion checkpoint")),
        checkpoint_after
    );
    assert_eq!(
        controller
            .state()
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal sequence after repeat: {error}")),
        sequence_after
    );
    assert_eq!(
        controller
            .state()
            .journal_after(0)
            .unwrap_or_else(|error| panic!("journal after repeat: {error}"))
            .into_iter()
            .filter(|event| event.event_kind == "project_completed")
            .count(),
        1
    );
}
