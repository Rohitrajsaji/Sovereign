#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    Controller, ReadinessInputs, RecoveryManager, ResourcePressureProbe, ResourceResidencyStateV1,
    RoleId, RoleRegistry, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    AdmissionStatus, CommandMode, CommandPolicy, CommandRisk, CommandSpec,
    ConditionalLeaseContextV1, HardwareProfileV1, HeavyLeaseClass, IsolationRequest,
    M6ResourceGovernor, M6ResourceGovernorSnapshotV1, MacSandboxExecBackend, ModelCallBudget,
    OsMemoryPressure, PinnedExecutable, PlanHeavyLeaseClass, PressureBand,
    RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION, ReconciliationPolicy, ResourceLeaseOwnerV1,
    ResourceLeaseRequestV1, ResourcePolicyEventV1, ResourcePressureEventV1,
    ResourcePressureSnapshotV1, TaskResourceBudgetV1, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::StateStore;
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SOURCE: &str =
    "export function SettingsForm() {\n  return <button type=\"submit\">Save</button>;\n}\n";
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct FixedPressureProbe(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedPressureProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

struct Fixture {
    base: PathBuf,
    root: PathBuf,
    state_path: PathBuf,
}

impl Fixture {
    fn create(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for resource simulation"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-m6-resource-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        fs::create_dir_all(root.join("src/settings"))
            .unwrap_or_else(|error| panic!("create resource fixture: {error}"));
        fs::write(root.join("src/settings/SettingsForm.tsx"), SOURCE)
            .unwrap_or_else(|error| panic!("write resource fixture: {error}"));
        fs::write(
            root.join("Makefile"),
            "all:\n\t@printf 'sovereign-heavy-ok MAKEFLAGS=%s\\n' \"$(MAKEFLAGS)\"\n",
        )
        .unwrap_or_else(|error| panic!("write resource Makefile: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "sovereign-resource@example.invalid"],
        );
        git(&root, &["config", "user.name", "Sovereign Resource"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "resource baseline"]);
        let state_path = base.join("state.sqlite3");
        Self {
            base,
            root,
            state_path,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct Prepared {
    registry: ProjectRegistry,
    packet: ContextPacket,
    snapshot: sovereign_repo::RepositorySnapshot,
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

fn constrained_snapshot(observed_at_ms: i64) -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        controlled_working_set_mib: 6_000,
        host_headroom_mib: 512,
        swap_out_growth_mib_per_min: 512,
        compressor_growth_mib_per_min: 512,
        os_memory_pressure: OsMemoryPressure::Warning,
        recent_pressure_event: true,
        ..green_snapshot(observed_at_ms)
    }
}

fn owner(task_id: &str) -> ResourceLeaseOwnerV1 {
    ResourceLeaseOwnerV1 {
        plan_id: "plan.m6-resource".to_owned(),
        plan_revision: 1,
        task_id: task_id.to_owned(),
    }
}

fn budget(classes: impl IntoIterator<Item = PlanHeavyLeaseClass>) -> TaskResourceBudgetV1 {
    TaskResourceBudgetV1::new(5_500, 8, classes)
}

fn request(
    lease_id: &str,
    class: HeavyLeaseClass,
    calibrated: bool,
    p95_mib: u64,
) -> ResourceLeaseRequestV1 {
    ResourceLeaseRequestV1 {
        lease_id: lease_id.to_owned(),
        owner: owner(lease_id),
        class,
        calibrated,
        calibrated_p95_rss_mib: p95_mib,
        evictable_idle_rss_mib: 0,
        task_budget: budget([class.plan_ir_class()]),
        conditional: ConditionalLeaseContextV1::default(),
        automatic_reload: false,
        disk_expanding: false,
    }
}

fn observe_green(governor: &mut M6ResourceGovernor, at_ms: i64) -> ResourcePressureEventV1 {
    governor.observe_pressure(green_snapshot(at_ms))
}

fn prepare(fixture: &Fixture) -> Prepared {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &fixture.root)
        .unwrap_or_else(|error| panic!("register resource repo: {error}"));
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot resource repo: {error}"));
    let exact = ExactRetriever::new(&registry)
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read resource fixture: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns resource admission and mutation authority."
                    .to_owned(),
                task_contract: "Rename the Settings label without changing behavior.".to_owned(),
                current_state: format!(
                    "repository=repo.app; head={:?}; dirty_digest={}",
                    snapshot.head, snapshot.dirty_digest
                ),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![EvidenceItem::from_exact_file(
                    &exact,
                    "exact Settings source for resource simulation",
                )],
                output_schema: "minimal-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build resource context: {error}"));
    Prepared {
        registry,
        packet,
        snapshot,
    }
}

fn response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "m6.resource.compiler".to_owned(),
        content,
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(input_tokens),
            output_tokens: 64,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

fn compiler_backend(packet: &ContextPacket) -> DeterministicFakeBackend {
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-m6-resource-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![response(
            json!({
                "tasks": [{
                    "title": "Rename Settings submit label",
                    "objective": "Change Save to Apply in the exact SettingsForm source.",
                    "rationale": "The bounded source identifies one exact edit.",
                    "files": ["src/settings/SettingsForm.tsx"],
                    "symbols": ["SettingsForm"],
                    "evidence_queries": [],
                    "expected_change": "SettingsForm renders Apply instead of Save."
                }]
            })
            .to_string(),
            packet.metrics.final_serialized_input_tokens,
        )],
    )
    .unwrap_or_else(|error| panic!("construct resource fake backend: {error}"))
}

fn canonical_role() -> Value {
    let pin = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .unwrap_or_else(|error| panic!("canonical implementer pin: {error}"));
    json!({"id": pin.id, "version": pin.version, "digest": pin.digest})
}

fn capability(id: &str, digest: &str) -> Value {
    json!({"id": id, "version": "1.0.0", "digest": digest})
}

fn policy_with_heavy_leases(classes: &[&str]) -> Value {
    let mut policy: Value = serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse scenario policy: {error}"));
    policy["resources"]["heavy_leases"] = json!(classes);
    policy
}

fn tool_manifest() -> ToolManifest {
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

fn compile_and_activate(
    fixture: &Fixture,
    prepared: &Prepared,
    policy: Value,
) -> (Controller, String, DeterministicFakeBackend, ToolManifest) {
    let backend = compiler_backend(&prepared.packet);
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load compiler-only resource backend: {error}"));
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.m6-resource-sim".to_owned(),
        compiled_at: "2026-09-14T04:00:00Z".to_owned(),
        project_id: "project.m6-resource".to_owned(),
        project_name: "M6 resource simulation".to_owned(),
        workspace_roots: vec![prepared.snapshot.root.display().to_string()],
        goal_id: "goal.m6-resource".to_owned(),
        goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
        goal_invariants: vec!["Do not alter submit behavior.".to_owned()],
        goal_non_goals: vec!["Do not redesign the form.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: prepared.snapshot.repository_id.clone(),
            root: prepared.snapshot.root.display().to_string(),
            head: prepared.snapshot.head.clone(),
            branch: prepared.snapshot.branch.clone(),
            dirty_digest: prepared.snapshot.dirty_digest.clone(),
            protected_changes_present: prepared.snapshot.protected_changes_present,
            languages: vec!["typescript".to_owned()],
        },
        policy,
        role: canonical_role(),
        skills: vec![capability(
            "skill.focused-edit",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )],
        tools: vec![
            capability("tool.patch", WRITE_TOOL_DIGEST),
            capability(
                "tool.read",
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            ),
        ],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: prepared.packet.clone(),
        m3: None,
        max_model_calls: 2,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("resource validator: {error}"));
    let compiler = PlanCompiler::new(&backend, &validator, "m6-resource-sim-v1")
        .unwrap_or_else(|error| panic!("resource compiler: {error}"));
    let mut compiler_budget = ModelCallBudget::new(1, 1_000);
    let compilation = compiler
        .compile(&input, &mut compiler_budget)
        .unwrap_or_else(|error| panic!("compile resource simulation: {error}"));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload compiler-only resource backend: {error}"));

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open resource simulation state: {error}"));
    let mut controller = Controller::new(state);
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate resource simulation: {error}"));
    assert_eq!(activation.task_ids.len(), 1);
    (
        controller,
        activation.task_ids[0].clone(),
        backend,
        tool_manifest(),
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn m1_8gb_policy_simulation_enforces_pressure_caps_pairs_cooldown_and_restart_state() {
    let profile = HardwareProfileV1::m1_8gb();
    let high_stable_swap = green_snapshot(0);
    assert_eq!(high_stable_swap.classify(&profile), PressureBand::Green);
    assert_eq!(
        ResourcePressureSnapshotV1 {
            swap_out_growth_mib_per_min: 64,
            ..high_stable_swap
        }
        .classify(&profile),
        PressureBand::Guarded
    );
    assert_eq!(
        ResourcePressureSnapshotV1 {
            compressor_growth_mib_per_min: 257,
            ..high_stable_swap
        }
        .classify(&profile),
        PressureBand::Constrained
    );

    let mut governor = M6ResourceGovernor::default();
    let pressure = observe_green(&mut governor, 0);
    let mut over_budget = request("over-budget", HeavyLeaseClass::Model, true, 4_000);
    over_budget.task_budget.max_peak_rss_mib = 3_900;
    assert_eq!(
        governor.admit(&over_budget, &pressure).status,
        AdmissionStatus::Denied
    );

    let model = request("model-a", HeavyLeaseClass::Model, true, 1_000);
    assert_eq!(
        governor.admit(&model, &pressure).status,
        AdmissionStatus::Admitted
    );
    assert_eq!(
        governor
            .admit(
                &request("model-b", HeavyLeaseClass::Model, true, 1_000),
                &pressure
            )
            .status,
        AdmissionStatus::Denied
    );
    assert_eq!(
        governor
            .admit(
                &request("build-while-model", HeavyLeaseClass::BuildHeavy, true, 512),
                &pressure,
            )
            .status,
        AdmissionStatus::Serialize
    );
    let _ = governor.release("model-a");

    let mut unknown = request("unknown-build", HeavyLeaseClass::Unknown, false, 256);
    unknown.task_budget = budget([PlanHeavyLeaseClass::BuildHeavy]);
    let unknown_admission = governor.admit(&unknown, &pressure);
    assert_eq!(unknown_admission.status, AdmissionStatus::Admitted);
    assert!(
        unknown_admission
            .parallel_job_cap
            .is_some_and(|cap| cap <= 2)
    );
    assert!(unknown_admission.subprocess_cap <= 2);
    let _ = governor.release("unknown-build");

    let mut build = request("build-heavy", HeavyLeaseClass::BuildHeavy, false, 256);
    build.task_budget = budget([PlanHeavyLeaseClass::BuildHeavy]);
    let build_admission = governor.admit(&build, &pressure);
    assert_eq!(build_admission.status, AdmissionStatus::Admitted);
    assert!(build_admission.parallel_job_cap.is_some_and(|cap| cap <= 2));
    assert!(build_admission.subprocess_cap <= 2);
    let _ = governor.release("build-heavy");

    let mut hysteresis = M6ResourceGovernor::default();
    let guarded = hysteresis.observe_pressure(ResourcePressureSnapshotV1 {
        swap_out_growth_mib_per_min: 64,
        ..green_snapshot(0)
    });
    assert_eq!(guarded.effective_band, PressureBand::Guarded);
    assert_eq!(
        observe_green(&mut hysteresis, 1_000).effective_band,
        PressureBand::Guarded
    );
    assert_eq!(
        observe_green(&mut hysteresis, 120_999).effective_band,
        PressureBand::Guarded
    );
    assert_eq!(
        observe_green(&mut hysteresis, 121_000).effective_band,
        PressureBand::Green
    );

    let mut cooldown = M6ResourceGovernor::default();
    let initial = observe_green(&mut cooldown, 0);
    assert_eq!(
        cooldown
            .admit(
                &request("model-0", HeavyLeaseClass::Model, true, 1_000),
                &initial
            )
            .status,
        AdmissionStatus::Admitted
    );
    let _ = cooldown.record_eviction("model-0", 0);
    let at_29 = observe_green(&mut cooldown, 29_000);
    let mut reload = request("model-1", HeavyLeaseClass::Model, true, 1_000);
    reload.automatic_reload = true;
    assert_eq!(
        cooldown.admit(&reload, &at_29).status,
        AdmissionStatus::Cooldown
    );
    let at_30 = observe_green(&mut cooldown, 30_000);
    assert_eq!(
        cooldown.admit(&reload, &at_30).status,
        AdmissionStatus::Admitted
    );
    assert!(matches!(
        cooldown.record_eviction("model-1", 40_000),
        Some(ResourcePolicyEventV1::Evict { .. })
    ));
    let at_70 = observe_green(&mut cooldown, 70_000);
    reload.lease_id = "model-2".to_owned();
    assert_eq!(
        cooldown.admit(&reload, &at_70).status,
        AdmissionStatus::Admitted
    );

    let snapshot = cooldown.snapshot();
    let mut restored = M6ResourceGovernor::restore(HardwareProfileV1::m1_8gb(), &snapshot)
        .unwrap_or_else(|error| panic!("restore governor snapshot: {error}"));
    assert_eq!(restored.snapshot(), snapshot);
    assert!(matches!(
        restored.record_eviction("model-2", 80_000),
        Some(ResourcePolicyEventV1::Defer { .. })
    ));
}

#[test]
fn controller_deferred_resource_consumes_no_attempt_or_model_budget() {
    let fixture = Fixture::create("controller-defer");
    let prepared = prepare(&fixture);
    let (mut controller, task_id, _backend, manifest) = compile_and_activate(
        &fixture,
        &prepared,
        policy_with_heavy_leases(&["MODEL", "BUILD_HEAVY"]),
    );
    controller
        .set_resource_pressure_probe(Box::new(FixedPressureProbe(constrained_snapshot(2_000))));
    let execution_budget = ModelCallBudget::new(2, 30_000);
    let denied = controller.derive_ready_lease(
        &prepared.registry,
        &task_id,
        ReadinessInputs::permissive_m1("sha256:m6-resource-defer"),
        &manifest,
    );
    let Err(error) = denied else {
        panic!("constrained MODEL admission must defer");
    };
    assert!(error.to_string().contains("resource denied"));
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::DeferredResource)
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(0));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(0));
    assert_eq!(controller.task_resource_deferrals_used(&task_id), Some(1));
    assert_eq!(execution_budget.remaining_calls(), 2);
    let snapshot = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("resource snapshot after deferral: {error}"));
    assert!(snapshot.governor.active_leases.is_empty());
    assert!(snapshot.model_residency.is_none());
}

#[test]
fn controller_build_heavy_release_requires_controller_owned_execution_proof() {
    let fixture = Fixture::create("controller-build-release-before-execute");
    let prepared = prepare(&fixture);
    let (mut controller, task_id, backend, manifest) = compile_and_activate(
        &fixture,
        &prepared,
        policy_with_heavy_leases(&["MODEL", "BUILD_HEAVY"]),
    );
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(10_000))));
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:m6-model-ready"),
            &manifest,
        )
        .unwrap_or_else(|error| panic!("derive MODEL lease: {error}"));
    let before = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("snapshot MODEL reservation: {error}"));
    assert_eq!(before.governor.active_leases.len(), 1);
    assert_eq!(
        before.governor.active_leases[0].class,
        HeavyLeaseClass::Model
    );
    assert_eq!(
        before
            .model_residency
            .as_ref()
            .map(|residency| residency.state),
        Some(ResourceResidencyStateV1::Reserved)
    );

    let build = controller
        .acquire_build_heavy(ready, &prepared.registry, &manifest, &backend)
        .unwrap_or_else(|error| panic!("MODEL -> BUILD_HEAVY handoff: {error}"));
    assert_eq!(build.class(), HeavyLeaseClass::BuildHeavy);
    assert!(build.parallel_job_cap().is_some_and(|cap| cap <= 2));
    assert!(build.subprocess_cap() <= 2);
    let during = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("snapshot BUILD_HEAVY phase: {error}"));
    assert_eq!(during.governor.active_leases.len(), 1);
    assert_eq!(
        during.governor.active_leases[0].class,
        HeavyLeaseClass::BuildHeavy
    );
    assert!(during.model_residency.is_none());

    let Err(error) = controller.release_build_heavy(&build) else {
        panic!("BUILD_HEAVY release before execution must fail closed")
    };
    assert!(
        error
            .to_string()
            .contains("cannot be released before Controller-owned execution/reap proof"),
        "unexpected pre-execution release error: {error}"
    );
    let after_failed_release = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("snapshot after rejected BUILD_HEAVY release: {error}"));
    assert_eq!(after_failed_release.governor.active_leases.len(), 1);
    assert_eq!(
        after_failed_release.governor.active_leases[0].class,
        HeavyLeaseClass::BuildHeavy
    );
    assert!(after_failed_release.model_residency.is_none());
}

#[test]
#[allow(clippy::too_many_lines)]
fn controller_build_heavy_executes_through_process_runner_and_releases_after_reap() {
    let fixture = Fixture::create("controller-build-execute-release");
    let prepared = prepare(&fixture);
    let (mut controller, task_id, backend, manifest) = compile_and_activate(
        &fixture,
        &prepared,
        policy_with_heavy_leases(&["MODEL", "BUILD_HEAVY"]),
    );
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(11_000))));
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:m6-build-process-runner"),
            &manifest,
        )
        .unwrap_or_else(|error| panic!("derive MODEL lease for BUILD_HEAVY execution: {error}"));
    let mut build = controller
        .acquire_build_heavy(ready, &prepared.registry, &manifest, &backend)
        .unwrap_or_else(|error| panic!("acquire BUILD_HEAVY execution lease: {error}"));

    let returned_subprocess_cap = build.subprocess_cap();
    let returned_job_cap = build.parallel_job_cap();
    let bounded_process_cap = returned_job_cap.map_or(returned_subprocess_cap, |jobs| {
        jobs.min(returned_subprocess_cap)
    });
    assert!(bounded_process_cap > 0);
    assert!(bounded_process_cap <= returned_subprocess_cap);
    assert!(returned_job_cap.is_none_or(|jobs| bounded_process_cap <= jobs));

    let executable = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
        .unwrap_or_else(|error| panic!("pin deterministic BUILD_HEAVY executable: {error}"));
    let toolchain_root = executable
        .path
        .parent()
        .unwrap_or_else(|| panic!("BUILD_HEAVY executable parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([executable.clone()], [toolchain_root])
        .unwrap_or_else(|error| panic!("BUILD_HEAVY command policy: {error}"));
    let home = std::env::var_os("HOME").map_or_else(
        || panic!("HOME must be set for BUILD_HEAVY isolation"),
        PathBuf::from,
    );
    let isolation_request = IsolationRequest {
        repository_root: fixture.root.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let isolation = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect BUILD_HEAVY sandbox: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join("cas"))
        .unwrap_or_else(|error| panic!("open BUILD_HEAVY artifact store: {error}"));
    let command = CommandSpec {
        executable: executable.path.clone(),
        args: Vec::new(),
        working_directory: fixture.root.clone(),
        environment: BTreeMap::default(),
        mode: CommandMode::Direct,
        // The active fixture intentionally reuses its existing tool.patch manifest, whose
        // deterministic risk floor is RepositoryMutation even though this command itself is a
        // no-op. Matching that frozen manifest floor keeps this regression scoped to M6 resource
        // execution rather than changing the compiled tool contract.
        declared_risk: CommandRisk::RepositoryMutation,
        timeout_ms: 5_000,
        output_limit_bytes: 16 * 1_024,
        disk_write_limit_bytes: 16 * 1_024,
        subprocess_limit: bounded_process_cap,
    };
    let action_ids_before = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("BUILD_HEAVY actions before execute: {error}"))
        .into_iter()
        .map(|record| record.action_id)
        .collect::<BTreeSet<_>>();
    let process_keys_before = controller
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("BUILD_HEAVY process rows before execute: {error}"))
        .into_iter()
        .map(|record| record.key)
        .collect::<BTreeSet<_>>();

    let result = controller
        .execute_build_heavy(
            &mut build,
            command,
            &command_policy,
            &isolation,
            &isolation_request,
            &artifacts,
            &manifest,
        )
        .unwrap_or_else(|error| panic!("execute BUILD_HEAVY through ProcessRunner: {error}"));
    assert_eq!(result.exit_code, Some(0));
    assert!(result.process_group_reaped);
    assert!(result.terminated_for_limit.is_none());
    let stdout = String::from_utf8(result.stdout.clone())
        .unwrap_or_else(|error| panic!("BUILD_HEAVY make stdout must be UTF-8: {error}"));
    assert!(stdout.contains("sovereign-heavy-ok"));
    assert!(
        stdout.contains("-j"),
        "Controller-injected make job cap must reach the executed build: {stdout:?}"
    );

    let actions = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("BUILD_HEAVY actions after execute: {error}"));
    assert_eq!(actions.len(), action_ids_before.len() + 1);
    let action = actions
        .iter()
        .find(|record| !action_ids_before.contains(&record.action_id))
        .unwrap_or_else(|| panic!("BUILD_HEAVY committed action record missing"));
    assert_eq!(action.state, "committed");
    assert!(action.result_digest.is_some());

    let process_rows = controller
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("BUILD_HEAVY process rows after execute: {error}"));
    assert_eq!(process_rows.len(), process_keys_before.len() + 1);
    let process_row = process_rows
        .iter()
        .find(|record| !process_keys_before.contains(&record.key))
        .unwrap_or_else(|| panic!("new BUILD_HEAVY process lease missing"));
    let process: Value = serde_json::from_str(&process_row.value_json)
        .unwrap_or_else(|error| panic!("decode BUILD_HEAVY process lease: {error}"));
    assert_eq!(
        process["action_id"].as_str(),
        Some(action.action_id.as_str())
    );
    assert_eq!(process["task_id"].as_str(), Some(task_id.as_str()));
    assert_eq!(process["state"].as_str(), Some("reaped"));
    assert!(process["process_group_id"].as_u64().is_some());
    assert!(process["leader_identity"].as_str().is_some());
    let completed_but_held = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("snapshot after BUILD_HEAVY execution: {error}"));
    assert_eq!(completed_but_held.governor.active_leases.len(), 1);
    assert_eq!(
        completed_but_held.governor.active_leases[0].class,
        HeavyLeaseClass::BuildHeavy
    );

    controller
        .release_build_heavy(&build)
        .unwrap_or_else(|error| panic!("release completed BUILD_HEAVY lease: {error}"));
    let after = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("snapshot after completed BUILD_HEAVY release: {error}"));
    assert!(after.governor.active_leases.is_empty());
    assert!(after.model_residency.is_none());
}

#[test]
#[allow(clippy::too_many_lines)]
fn controller_build_heavy_predispatch_rejection_cancels_logical_lease_without_dispatch() {
    let fixture = Fixture::create("controller-build-predispatch-cancel");
    let prepared = prepare(&fixture);
    let (mut controller, task_id, backend, manifest) = compile_and_activate(
        &fixture,
        &prepared,
        policy_with_heavy_leases(&["MODEL", "BUILD_HEAVY"]),
    );
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(12_000))));
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:m6-build-predispatch-cancel"),
            &manifest,
        )
        .unwrap_or_else(|error| panic!("derive MODEL lease for pre-dispatch rejection: {error}"));
    let mut build = controller
        .acquire_build_heavy(ready, &prepared.registry, &manifest, &backend)
        .unwrap_or_else(|error| panic!("acquire BUILD_HEAVY for pre-dispatch rejection: {error}"));

    let executable = PinnedExecutable::from_path("/usr/bin/true", "macos-system-true")
        .unwrap_or_else(|error| panic!("pin pre-dispatch executable: {error}"));
    let toolchain_root = executable
        .path
        .parent()
        .unwrap_or_else(|| panic!("pre-dispatch executable parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([executable.clone()], [toolchain_root])
        .unwrap_or_else(|error| panic!("pre-dispatch command policy: {error}"));
    let home = std::env::var_os("HOME").map_or_else(
        || panic!("HOME must be set for pre-dispatch isolation"),
        PathBuf::from,
    );
    let isolation_request = IsolationRequest {
        repository_root: fixture.root.clone(),
        user_home_root: home,
        extra_protected_read_roots: Vec::new(),
        network_offline: true,
        allow_repository_write: false,
        require_full_filesystem_read_jail: false,
    };
    let isolation = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect pre-dispatch sandbox: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join("cas-predispatch"))
        .unwrap_or_else(|error| panic!("open pre-dispatch artifact store: {error}"));
    let bounded_process_cap = build
        .parallel_job_cap()
        .map_or(build.subprocess_cap(), |jobs| {
            jobs.min(build.subprocess_cap())
        });
    assert!(bounded_process_cap > 0);
    let command = CommandSpec {
        executable: executable.path.clone(),
        args: Vec::new(),
        // Existing subdirectory, but deliberately not the exact task execution root. This must be
        // rejected before durable action authorization or ProcessRunner dispatch.
        working_directory: fixture.root.join("src"),
        environment: BTreeMap::default(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::RepositoryMutation,
        timeout_ms: 5_000,
        output_limit_bytes: 16 * 1_024,
        disk_write_limit_bytes: 16 * 1_024,
        subprocess_limit: bounded_process_cap,
    };
    let action_ids_before = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("actions before pre-dispatch rejection: {error}"))
        .into_iter()
        .map(|record| record.action_id)
        .collect::<BTreeSet<_>>();
    let process_keys_before = controller
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("process rows before pre-dispatch rejection: {error}"))
        .into_iter()
        .map(|record| record.key)
        .collect::<BTreeSet<_>>();

    let Err(error) = controller.execute_build_heavy(
        &mut build,
        command,
        &command_policy,
        &isolation,
        &isolation_request,
        &artifacts,
        &manifest,
    ) else {
        panic!("wrong exact BUILD_HEAVY root must fail before ProcessRunner dispatch");
    };
    assert!(
        error
            .to_string()
            .contains("working directory must equal the exact task execution root"),
        "unexpected pre-dispatch rejection: {error}"
    );

    let action_ids_after = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("actions after pre-dispatch rejection: {error}"))
        .into_iter()
        .map(|record| record.action_id)
        .collect::<BTreeSet<_>>();
    let process_keys_after = controller
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("process rows after pre-dispatch rejection: {error}"))
        .into_iter()
        .map(|record| record.key)
        .collect::<BTreeSet<_>>();
    assert_eq!(action_ids_after, action_ids_before);
    assert_eq!(process_keys_after, process_keys_before);

    let after = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("snapshot after pre-dispatch BUILD_HEAVY cancel: {error}"));
    assert!(after.governor.active_leases.is_empty());
    assert!(after.model_residency.is_none());
}

#[test]
fn controller_recovery_blocks_ambiguous_reserved_model_before_advancing_epoch() {
    let fixture = Fixture::create("controller-restart");
    let prepared = prepare(&fixture);
    let (mut controller, task_id, _backend, manifest) = compile_and_activate(
        &fixture,
        &prepared,
        policy_with_heavy_leases(&["MODEL", "BUILD_HEAVY"]),
    );
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(20_000))));
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:m6-restart-ready"),
            &manifest,
        )
        .unwrap_or_else(|error| panic!("derive restart MODEL lease: {error}"));
    let before = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("resource snapshot before restart: {error}"));
    assert_eq!(ready.execution_epoch(), before.execution_epoch);
    assert_eq!(before.governor.active_leases.len(), 1);
    let epoch_before = before.execution_epoch;
    drop(controller);

    let state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen resource state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &prepared.registry) else {
        panic!("Reserved MODEL must not survive restart as fresh authority");
    };
    assert!(
        error
            .to_string()
            .contains("cannot prove pre-crash MODEL absence"),
        "unexpected recovery error: {error}"
    );

    let recovered_state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("reopen blocked resource state: {error}"));
    assert_eq!(
        recovered_state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("read blocked recovery epoch: {error}")),
        epoch_before,
        "ambiguous pre-crash MODEL must block before execution-epoch advance"
    );
    let residency_raw = recovered_state
        .get_state("controller.resource_residency", "model")
        .unwrap_or_else(|error| panic!("read blocked MODEL residency: {error}"))
        .unwrap_or_else(|| panic!("blocked MODEL residency must remain durable"));
    let residency: sovereign_controller::ResourceResidencyV1 = serde_json::from_str(&residency_raw)
        .unwrap_or_else(|error| panic!("decode blocked MODEL residency: {error}"));
    assert_eq!(residency.state, ResourceResidencyStateV1::Unknown);

    let governor_raw = recovered_state
        .get_state("controller.resource_governor", "active")
        .unwrap_or_else(|error| panic!("read blocked governor snapshot: {error}"))
        .unwrap_or_else(|| panic!("blocked governor snapshot must remain durable"));
    let governor: M6ResourceGovernorSnapshotV1 = serde_json::from_str(&governor_raw)
        .unwrap_or_else(|error| panic!("decode blocked governor snapshot: {error}"));
    assert_eq!(governor.active_leases.len(), 1);
    assert_eq!(governor.active_leases[0].class, HeavyLeaseClass::Model);
}
