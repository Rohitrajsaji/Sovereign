#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
#[cfg(feature = "recovery-test-hooks")]
use sovereign_controller::RollbackRecordV1;
use sovereign_controller::{
    CheckpointManifest, Controller, ControllerError, ExecutionRuntime, FailureClassification,
    ReadinessInputs, RecoveryManager, ResourcePressureProbe, RoleId, RoleRegistry,
    RollbackStatusV1, StableContractInvalidation, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    BackendHealth, DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelError, ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResidencyProof,
    ModelResponse, ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanReplanInput, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandSpec, ExecutionIsolationBackend, IsolatedCommand, IsolationCapabilities,
    IsolationRequest, MacSandboxExecBackend, ModelCallBudget, OsMemoryPressure, PinnedExecutable,
    PolicyError, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION, ReconciliationPolicy,
    ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::{NewCheckpointIntegrityRecord, StateStore};
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(feature = "recovery-test-hooks")]
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOURCE: &str =
    "export function SettingsForm() {\n  return <button type=\"submit\">Save</button>;\n}\n";
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REPLAN_EVIDENCE_ID: &str = "ev.settings_form";
const ASSUMPTION_EVIDENCE_ID: &str = "ev.assumed_settings";
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "recovery-test-hooks")]
const ROLLBACK_CRASH_STATE: &str = "SOVEREIGN_M6_T06_ROLLBACK_STATE";
#[cfg(feature = "recovery-test-hooks")]
const ROLLBACK_CRASH_ROOT: &str = "SOVEREIGN_M6_T06_ROLLBACK_ROOT";
#[cfg(feature = "recovery-test-hooks")]
const ROLLBACK_CRASH_BASE: &str = "SOVEREIGN_M6_T06_ROLLBACK_BASE";
#[cfg(feature = "recovery-test-hooks")]
const ROLLBACK_CRASH_ORIGINAL_ACTION: &str = "SOVEREIGN_M6_T06_ROLLBACK_ORIGINAL_ACTION";

struct TestRepo {
    base: PathBuf,
    root: PathBuf,
    state_path: PathBuf,
}

impl TestRepo {
    fn create(label: &str) -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home =
            std::env::var_os("HOME").map_or_else(|| panic!("HOME must be set"), PathBuf::from);
        let base = home.join(format!(
            ".sovereign-m6-t06-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        fs::create_dir_all(root.join("src/settings"))
            .unwrap_or_else(|error| panic!("create repo: {error}"));
        fs::write(root.join("src/settings/SettingsForm.tsx"), SOURCE)
            .unwrap_or_else(|error| panic!("write source: {error}"));
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.email", "m6-t06@example.invalid"]);
        git(&root, &["config", "user.name", "Sovereign M6 T06"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "baseline"]);
        let state_path = base.join("state.sqlite3");
        Self {
            base,
            root,
            state_path,
        }
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

struct Fixture {
    repo: TestRepo,
    registry: ProjectRegistry,
    packet: ContextPacket,
    form_digest: String,
    compilation: Option<PlanCompilationResult>,
}

#[derive(Clone)]
struct FixedPressure(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedPressure {
    fn sample(&mut self) -> std::io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
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

fn capabilities() -> ModelCapabilities {
    ModelCapabilities {
        schema_version: MODEL_SCHEMA_VERSION,
        model_id: "m6-t06-fixture".to_owned(),
        parameter_class: "fixture".to_owned(),
        quantization: "fixture".to_owned(),
        max_context_tokens: 16_384,
        supports_tools: false,
        supports_json_schema: true,
        local: true,
    }
}

fn response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "fixture".to_owned(),
        content,
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(input_tokens),
            output_tokens: 128,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

fn fake_backend(responses: Vec<ModelResponse>) -> DeterministicFakeBackend {
    DeterministicFakeBackend::new(capabilities(), responses)
        .unwrap_or_else(|error| panic!("fake backend: {error}"))
}

fn policy() -> Value {
    serde_json::from_str(include_str!(
        "../../sovereign-eval/tests/fixtures/scenario1/policy.json"
    ))
    .unwrap_or_else(|error| panic!("policy fixture: {error}"))
}

fn capability(id: &str, digest: &str) -> Value {
    json!({"id": id, "version": "1.0.0", "digest": digest})
}

fn implementer_role() -> Value {
    let pin = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .unwrap_or_else(|error| panic!("canonical implementer role: {error}"));
    json!({"id": pin.id, "version": pin.version, "digest": pin.digest})
}

#[allow(clippy::too_many_lines)]
fn fixture(label: &str) -> Fixture {
    let repo = TestRepo::create(label);
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &repo.root)
        .unwrap_or_else(|error| panic!("register repository: {error}"));
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    let form = ExactRetriever::new(&registry)
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read form: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns state and authority.".to_owned(),
                task_contract: "Rename Save to Apply only.".to_owned(),
                current_state: format!("dirty_digest={}", snapshot.dirty_digest),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![EvidenceItem::from_exact_file(&form, "exact source")],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context packet: {error}"));
    let planning = json!({
        "tasks": [{
            "title": "Rename label",
            "objective": "Change Save to Apply in SettingsForm.",
            "rationale": "Exact source identifies the bounded edit.",
            "files": ["src/settings/SettingsForm.tsx"],
            "symbols": ["SettingsForm"],
            "evidence_queries": [],
            "expected_change": "SettingsForm renders Apply."
        }]
    });
    let planner = fake_backend(vec![response(
        planning.to_string(),
        packet.metrics.final_serialized_input_tokens,
    )]);
    planner
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load planner: {error}"));
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let compiler = PlanCompiler::new(&planner, &validator, "m6-t06-test-compiler")
        .unwrap_or_else(|error| panic!("compiler: {error}"));
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: format!("compile.{label}"),
        compiled_at: "2026-09-15T16:00:00Z".to_owned(),
        project_id: "project.m6-t06".to_owned(),
        project_name: "M6-T06 resilience".to_owned(),
        workspace_roots: vec![snapshot.root.display().to_string()],
        goal_id: format!("goal.{label}"),
        goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
        goal_invariants: vec!["Preserve submit behavior.".to_owned()],
        goal_non_goals: vec!["No redesign.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: snapshot.repository_id.clone(),
            root: snapshot.root.display().to_string(),
            head: snapshot.head.clone(),
            branch: snapshot.branch.clone(),
            dirty_digest: snapshot.dirty_digest.clone(),
            protected_changes_present: snapshot.protected_changes_present,
            languages: vec!["typescript".to_owned()],
        },
        policy: policy(),
        role: implementer_role(),
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
        context_packet: packet.clone(),
        m3: None,
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let mut compile_budget = ModelCallBudget::new(1, 30_000);
    let compilation = compiler
        .compile(&input, &mut compile_budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    planner
        .unload()
        .unwrap_or_else(|error| panic!("unload planner: {error}"));
    Fixture {
        repo,
        registry,
        packet,
        form_digest: form.digest,
        compilation: Some(compilation),
    }
}

fn replan_policy() -> Value {
    let mut value = policy();
    value["retry"]["max_replans_per_scope"] = json!(1);
    value["resources"]["max_model_calls"] = json!(2);
    value
}

fn m3_replan_proposal(local_id: &str, revision_label: &str) -> String {
    json!({
        "tasks": [{
            "local_id": local_id,
            "repository_id": "repo.app",
            "title": format!("Rename label {revision_label}"),
            "objective": "Change Save to Apply in SettingsForm.",
            "rationale": "The exact current source and stable assumption define the bounded task.",
            "files": ["src/settings/SettingsForm.tsx"],
            "symbols": ["SettingsForm"],
            "dependencies": [],
            "evidence_needs": [],
            "assumptions": [{
                "text": "The SettingsForm source fingerprint remains the assumed fixture value.",
                "invalidation_scope": "dependency_branch",
                "evidence_ids": [ASSUMPTION_EVIDENCE_ID],
                "fingerprints": [
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                ]
            }],
            "expected_change": "SettingsForm renders Apply.",
            "acceptance": [{
                "kind": "diff",
                "description": "The scoped Save-to-Apply diff is accepted.",
                "manual_gate_id": Value::Null
            }]
        }]
    })
    .to_string()
}

#[allow(clippy::too_many_lines)]
fn compile_m3_candidate(
    fixture: &Fixture,
    compilation_id: &str,
    policy_value: Value,
    replan: Option<PlanReplanInput>,
    local_id: &str,
    revision_label: &str,
) -> Result<PlanCompilationResult, String> {
    let snapshot = fixture
        .registry
        .snapshot("repo.app")
        .map_err(|error| format!("snapshot for M3 compile: {error}"))?;
    let source_plan = replan
        .as_ref()
        .map(|input| &input.previous_plan)
        .or_else(|| {
            fixture
                .compilation
                .as_ref()
                .map(|compilation| compilation.plan().as_value())
        })
        .ok_or_else(|| "M3 compile requires a source plan".to_owned())?;
    let goal_id = source_plan
        .pointer("/goal/goal_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "source plan goal id missing".to_owned())?
        .to_owned();
    let goal_statement = source_plan
        .pointer("/goal/statement")
        .and_then(Value::as_str)
        .ok_or_else(|| "source plan goal statement missing".to_owned())?
        .to_owned();
    let goal_invariants = source_plan
        .pointer("/goal/invariants")
        .and_then(Value::as_array)
        .ok_or_else(|| "source plan invariants missing".to_owned())?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let goal_non_goals = source_plan
        .pointer("/goal/non_goals")
        .and_then(Value::as_array)
        .ok_or_else(|| "source plan non-goals missing".to_owned())?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let mut decision = DepthClassifier.classify(&DepthFeatureInput {
        repository_count: 1,
        language_count: 1,
        expected_files: 1,
        expected_modules: 1,
        expected_symbols: 1,
        ..DepthFeatureInput::default()
    });
    decision.mode = ExecutionDepth::D2;
    "M6-T06 replan resilience fixture".clone_into(&mut decision.reason);
    let m3 = M3PlanningInput {
        depth: decision,
        supplied_sources: Vec::new(),
        additional_repositories: Vec::new(),
        manual_gates: Vec::new(),
        absence_evaluator: None,
        replan,
    };
    let planning = m3_replan_proposal(local_id, revision_label);
    let planner = fake_backend(vec![response(
        planning,
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    planner
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .map_err(|error| format!("load M3 planner: {error}"))?;
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .map_err(|error| format!("M3 validator: {error}"))?;
    let compiler = PlanCompiler::new(&planner, &validator, "m6-t06-replan-compiler")
        .map_err(|error| format!("M3 compiler: {error}"))?;
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: compilation_id.to_owned(),
        compiled_at: "2026-09-15T17:00:00Z".to_owned(),
        project_id: "project.m6-t06-replan".to_owned(),
        project_name: "M6-T06 replan resilience".to_owned(),
        workspace_roots: vec![snapshot.root.display().to_string()],
        goal_id,
        goal_statement,
        goal_invariants,
        goal_non_goals,
        repository: PlanCompilationRepository {
            repository_id: snapshot.repository_id.clone(),
            root: snapshot.root.display().to_string(),
            head: snapshot.head.clone(),
            branch: snapshot.branch.clone(),
            dirty_digest: snapshot.dirty_digest.clone(),
            protected_changes_present: snapshot.protected_changes_present,
            languages: vec!["typescript".to_owned()],
        },
        policy: policy_value,
        role: implementer_role(),
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
        context_packet: fixture.packet.clone(),
        m3: Some(m3),
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let result = compiler
        .compile(&input, &mut budget)
        .map_err(|error| format!("{error:?}"));
    planner
        .unload()
        .map_err(|error| format!("unload M3 planner: {error}"))?;
    result
}

fn replan_fixture(label: &str) -> Fixture {
    let mut value = fixture(label);
    let snapshot = value
        .registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot replan fixture: {error}"));
    let mut exact = value
        .packet
        .items
        .iter()
        .find(|item| item.source_uri.contains("src/settings/SettingsForm.tsx"))
        .cloned()
        .unwrap_or_else(|| panic!("exact SettingsForm evidence missing"));
    REPLAN_EVIDENCE_ID.clone_into(&mut exact.evidence_id);
    let mut assumed = EvidenceItem::new(
        ASSUMPTION_EVIDENCE_ID,
        exact.section,
        exact.level,
        exact.kind,
        exact.source_uri.clone(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        exact.provenance.clone(),
        exact.trust_class,
        "historical assumption basis fixture",
        format!("{}\n// historical assumption basis", exact.text),
    )
    .with_trust_label(exact.trust_label);
    if let Some(repository_id) = exact.repository_id.clone() {
        assumed = assumed.with_repository(repository_id);
    }
    if let Some(locator) = exact.locator.clone() {
        assumed = assumed.with_locator(locator);
    }
    value.packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns state and authority.".to_owned(),
                task_contract: "Rename Save to Apply only.".to_owned(),
                current_state: format!("dirty_digest={}", snapshot.dirty_digest),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![exact, assumed],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("rebuild replan context packet: {error}"));
    let compilation = compile_m3_candidate(
        &value,
        &format!("compile.{label}.m3-r1"),
        replan_policy(),
        None,
        "root",
        "r1",
    )
    .unwrap_or_else(|error| panic!("compile M3 replan fixture: {error}"));
    value.compilation = Some(compilation);
    value
}

fn controller_for(fixture: &mut Fixture) -> (Controller, String) {
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open state: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedPressure(ResourcePressureSnapshotV1 {
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
    })));
    let activation = controller
        .activate(
            fixture
                .compilation
                .take()
                .unwrap_or_else(|| panic!("fixture already activated")),
            &fixture.registry,
        )
        .unwrap_or_else(|error| panic!("activate: {error}"));
    (controller, activation.task_ids[0].clone())
}

fn manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.patch".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: WRITE_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]),
        declared_risk_floor: sovereign_policy::CommandRisk::RepositoryMutation,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

struct RuntimeParts {
    command_policy: CommandPolicy,
    isolation_request: IsolationRequest,
    artifacts: ArtifactStore,
}

fn runtime_parts(fixture: &Fixture) -> RuntimeParts {
    runtime_parts_for(&fixture.repo.root, &fixture.repo.base)
}

fn runtime_parts_for(repository_root: &Path, base: &Path) -> RuntimeParts {
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin python: {error}"));
    let root = python
        .path
        .parent()
        .unwrap_or_else(|| panic!("python parent"))
        .to_path_buf();
    RuntimeParts {
        command_policy: CommandPolicy::new([python], [root])
            .unwrap_or_else(|error| panic!("command policy: {error}")),
        isolation_request: IsolationRequest {
            repository_root: repository_root.to_path_buf(),
            user_home_root: std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from),
            extra_protected_read_roots: Vec::new(),
            rust_toolchain: None,
            build_scratch_root: None,
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        },
        artifacts: ArtifactStore::open(base.join("cas"))
            .unwrap_or_else(|error| panic!("artifact store: {error}")),
    }
}

struct PanicIsolation {
    inner: MacSandboxExecBackend,
}

impl ExecutionIsolationBackend for PanicIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        self.inner.capabilities()
    }

    fn isolate(
        &self,
        _spec: &CommandSpec,
        _request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        panic!("M6-T06 fixture crash after model-call accounting and before process dispatch")
    }
}

fn proposal(source_digest: &str) -> String {
    proposal_with_evidence(source_digest, "file:repo.app:src/settings/SettingsForm.tsx")
}

fn proposal_with_evidence(source_digest: &str, evidence_id: &str) -> String {
    json!({
        "schema_version": 1,
        "evidence_ids": [evidence_id],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": source_digest,
            "old_literal": "Save",
            "new_literal": "Apply",
            "expected_occurrences": 1
        }
    })
    .to_string()
}

fn readiness() -> ReadinessInputs<'static> {
    ReadinessInputs::permissive_m1("sha256:resources")
}

fn latest_checkpoint_manifest(state: &StateStore) -> CheckpointManifest {
    let latest = state
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest checkpoint: {error}"))
        .unwrap_or_else(|| panic!("checkpoint missing"));
    let state_parent = state
        .path()
        .parent()
        .unwrap_or_else(|| panic!("state parent missing"));
    let store = ArtifactStore::open(state_parent.join("checkpoint-cas"))
        .unwrap_or_else(|error| panic!("checkpoint store: {error}"));
    let mut file = store
        .open_artifact(state, &latest.payload_digest)
        .unwrap_or_else(|error| panic!("open checkpoint manifest: {error}"));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("read checkpoint manifest: {error}"));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("decode checkpoint manifest: {error}"))
}

fn append_modified_checkpoint(
    state: &mut StateStore,
    mutate: impl FnOnce(&mut CheckpointManifest),
) {
    let mut manifest = latest_checkpoint_manifest(state);
    mutate(&mut manifest);
    let bytes = serde_json::to_vec(&manifest)
        .unwrap_or_else(|error| panic!("encode modified checkpoint manifest: {error}"));
    let state_parent = state
        .path()
        .parent()
        .unwrap_or_else(|| panic!("state parent missing"));
    let store = ArtifactStore::open(state_parent.join("checkpoint-cas"))
        .unwrap_or_else(|error| panic!("checkpoint store: {error}"));
    let artifact = store
        .put(state, &bytes)
        .unwrap_or_else(|error| panic!("store modified checkpoint manifest: {error}"));
    let checkpoint = state
        .append_checkpoint_integrity(NewCheckpointIntegrityRecord {
            payload_digest: &artifact.digest,
            action_sequence: manifest.action_journal_sequence,
        })
        .unwrap_or_else(|error| panic!("append modified checkpoint: {error}"));
    state
        .add_artifact_reference(
            &format!("checkpoint.manifest.{}", checkpoint.generation),
            &artifact.digest,
        )
        .unwrap_or_else(|error| panic!("bind modified checkpoint artifact: {error}"));
}

fn attempt_ids(state: &StateStore) -> BTreeSet<String> {
    state
        .state_records("controller.attempt")
        .unwrap_or_else(|error| panic!("read attempts: {error}"))
        .into_iter()
        .filter_map(|record| {
            serde_json::from_str::<Value>(&record.value_json)
                .ok()
                .and_then(|value| value.get("attempt_id")?.as_str().map(str::to_owned))
        })
        .collect()
}

fn induce_executing_attempt_after_model_charge(
    controller: &mut Controller,
    fixture: &Fixture,
    task_id: &str,
) -> String {
    let ready = controller
        .derive_ready_lease(&fixture.registry, task_id, readiness(), &manifest())
        .unwrap_or_else(|error| panic!("derive replan fixture ready lease: {error}"));
    let execution_backend = fake_backend(vec![response(
        proposal_with_evidence(&fixture.form_digest, REPLAN_EVIDENCE_ID),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(fixture);
    let isolation = PanicIsolation {
        inner: MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("seatbelt for replan fixture: {error}")),
    };
    let tool_manifest = manifest();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution_backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let attempts_before = attempt_ids(controller.state());
    let mut caller_budget = ModelCallBudget::new(1, 30_000);
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        controller.execute_replace(ready, &runtime, &fixture.packet, &mut caller_budget)
    }));
    if let Ok(result) = unwind {
        panic!(
            "fixture isolation must crash after durable model accounting and attempt start; execute_replace returned {result:?}"
        );
    }
    assert_eq!(caller_budget.remaining_calls(), 0);
    assert_eq!(controller.task_state(task_id), Some(TaskState::Running));
    let attempts_after = attempt_ids(controller.state());
    let added = attempts_after
        .difference(&attempts_before)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        added.len(),
        1,
        "exactly one executing attempt must be added"
    );
    added[0].clone()
}

fn record_assumption_plan_failure(
    controller: &mut Controller,
    fixture: &Fixture,
    task_id: &str,
    attempt_id: &str,
) -> FailureClassification {
    let plan = latest_checkpoint_manifest(controller.state()).plan_document;
    let task = plan["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("active plan tasks missing"))
        .iter()
        .find(|task| task["task_id"] == task_id)
        .unwrap_or_else(|| panic!("active replan task missing"));
    let contract_id = task["implementation_contract"]["assumptions"][0]["assumption_id"]
        .as_str()
        .unwrap_or_else(|| panic!("compiled assumption id missing"))
        .to_owned();
    controller
        .record_plan_failure(
            &fixture.registry,
            task_id,
            attempt_id,
            &fixture.packet,
            &[StableContractInvalidation {
                contract_id,
                evidence_refs: vec![REPLAN_EVIDENCE_ID.to_owned()],
                observed_fingerprints: vec![fixture.form_digest.clone()],
            }],
        )
        .unwrap_or_else(|error| panic!("record verified assumption invalidation: {error}"))
}

fn sole_replan_counter(state: &StateStore) -> Value {
    let records = state
        .state_records("controller.replan_scope_counter")
        .unwrap_or_else(|error| panic!("read replan counters: {error}"));
    assert_eq!(
        records.len(),
        1,
        "one stable scope lineage counter expected"
    );
    serde_json::from_str(&records[0].value_json)
        .unwrap_or_else(|error| panic!("decode replan counter: {error}"))
}

#[cfg(feature = "recovery-test-hooks")]
fn action_event_count(state: &StateStore, action_id: &str, event_kind: &str) -> usize {
    state
        .journal()
        .unwrap_or_else(|error| panic!("read action journal: {error}"))
        .into_iter()
        .filter(|event| event.entity_id == action_id && event.event_kind == event_kind)
        .count()
}

#[cfg(feature = "recovery-test-hooks")]
fn rollback_record_for_action(state: &StateStore, action_id: &str) -> RollbackRecordV1 {
    state
        .state_records("controller.rollback")
        .unwrap_or_else(|error| panic!("read rollback records: {error}"))
        .into_iter()
        .filter_map(|record| serde_json::from_str::<RollbackRecordV1>(&record.value_json).ok())
        .find(|record| record.rollback_action_id == action_id)
        .unwrap_or_else(|| panic!("rollback record for action {action_id} missing"))
}

#[cfg(feature = "recovery-test-hooks")]
fn spawn_rollback_crash_worker(fixture: &Fixture, original_action_id: &str) -> (Child, PathBuf) {
    let marker = fixture.repo.base.join("rollback-crash.marker");
    let current =
        std::env::current_exe().unwrap_or_else(|error| panic!("current test exe: {error}"));
    let child = Command::new(current)
        .args(["--exact", "rollback_crash_worker_entry", "--nocapture"])
        .env(ROLLBACK_CRASH_STATE, &fixture.repo.state_path)
        .env(ROLLBACK_CRASH_ROOT, &fixture.repo.root)
        .env(ROLLBACK_CRASH_BASE, &fixture.repo.base)
        .env(ROLLBACK_CRASH_ORIGINAL_ACTION, original_action_id)
        .env(
            "SOVEREIGN_RECOVERY_TEST_PAUSE_AT",
            "after_process_spawn_before_identity_lease",
        )
        .env("SOVEREIGN_RECOVERY_TEST_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn rollback crash worker: {error}"));
    (child, marker)
}

#[cfg(feature = "recovery-test-hooks")]
fn wait_for_marker(marker: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if marker.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for crash marker {}", marker.display());
}

#[cfg(feature = "recovery-test-hooks")]
fn wait_for_dispatched_rollback_action(state_path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let state = StateStore::open(state_path).unwrap_or_else(|error| {
            panic!("open state while waiting for rollback dispatch: {error}")
        });
        let dispatched = state
            .action_records()
            .unwrap_or_else(|error| panic!("read actions while waiting for rollback: {error}"))
            .into_iter()
            .find(|record| {
                record.action_id.starts_with("rollback-action.") && record.state == "dispatched"
            });
        if let Some(record) = dispatched {
            return record.action_id;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for dispatched rollback action");
}

#[derive(Clone)]
struct BlockingBackend {
    loaded: Arc<AtomicBool>,
    complete_started: Arc<AtomicBool>,
    unload_calls: Arc<AtomicU64>,
}

impl BlockingBackend {
    fn new() -> Self {
        Self {
            loaded: Arc::new(AtomicBool::new(false)),
            complete_started: Arc::new(AtomicBool::new(false)),
            unload_calls: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl ModelBackend for BlockingBackend {
    fn capabilities(&self) -> ModelCapabilities {
        capabilities()
    }

    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.loaded.store(true, Ordering::Release);
        Ok(ModelLease {
            lease_id: "lease.m6-t06-blocking".to_owned(),
            model_id: "m6-t06-fixture".to_owned(),
            context_tokens: profile.context_tokens,
            server_context_tokens: profile
                .context_tokens
                .saturating_add(profile.output_reserve_tokens),
            process_id: None,
            startup_peak_rss_kb: Some(64 * 1_024),
            post_load_rss_kb: Some(64 * 1_024),
        })
    }

    fn complete(&self, _request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        self.complete_started.store(true, Ordering::Release);
        let started = Instant::now();
        while self.loaded.load(Ordering::Acquire) {
            if started.elapsed() > Duration::from_secs(2) {
                return Err(ModelError::DeadlineExceeded("fixture cancellation"));
            }
            thread::sleep(Duration::from_millis(2));
        }
        Err(ModelError::NotLoaded)
    }

    fn count_tokens(&self, _content: &str) -> Result<u32, ModelError> {
        Ok(1)
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        let loaded = self.loaded.load(Ordering::Acquire);
        Ok(BackendHealth {
            reachable: true,
            loaded,
            detail: "fixture".to_owned(),
        })
    }

    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        Ok(if self.loaded.load(Ordering::Acquire) {
            ModelResidencyProof::Resident { process_id: None }
        } else {
            ModelResidencyProof::Absent
        })
    }

    fn unload(&self) -> Result<(), ModelError> {
        self.unload_calls.fetch_add(1, Ordering::AcqRel);
        self.loaded.store(false, Ordering::Release);
        Ok(())
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn controller_inflight_model_cancellation_interrupts_backend_and_keeps_call_consumed() {
    let mut fixture = fixture("model-cancel");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest())
        .unwrap_or_else(|error| panic!("derive ready lease: {error}"));
    let cancellation = controller
        .task_cancellation_handle(&task_id)
        .unwrap_or_else(|error| panic!("task cancellation handle: {error}"));
    let backend = BlockingBackend::new();
    let cancel_backend = backend.clone();
    let cancel_handle = cancellation.clone();
    let canceller = thread::spawn(move || {
        let started = Instant::now();
        while !cancel_backend.complete_started.load(Ordering::Acquire) {
            assert!(
                // Model admission, checkpoints, and Seatbelt setup run before `complete`.
                // One second is not enough when the rest of the suite is loaded.
                started.elapsed() < Duration::from_secs(15),
                "Controller never entered model completion"
            );
            thread::sleep(Duration::from_millis(2));
        }
        cancel_handle
            .cancel()
            .unwrap_or_else(|error| panic!("cancel task: {error}"));
    });
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let tool_manifest = manifest();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut caller_budget = ModelCallBudget::new(1, 30_000);
    let error = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut caller_budget)
        .err()
        .unwrap_or_else(|| panic!("cancelled model request unexpectedly succeeded"));
    canceller
        .join()
        .unwrap_or_else(|_| panic!("cancellation thread panicked"));

    assert!(
        error
            .to_string()
            .contains("cancelled during model dispatch"),
        "unexpected cancellation error: {error}"
    );
    assert!(backend.unload_calls.load(Ordering::Acquire) >= 1);
    assert!(!backend.loaded.load(Ordering::Acquire));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(caller_budget.remaining_calls(), 0);
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::FailedTerminal)
    );
    assert!(
        controller
            .state()
            .state_records("controller.cancellation_request")
            .unwrap_or_else(|error| panic!("cancellation records: {error}"))
            .iter()
            .any(|record| record.value_json.contains(&task_id))
    );

    let checkpoint = latest_checkpoint_manifest(controller.state());
    let goal_budget = checkpoint
        .goal_autonomy_budget
        .as_ref()
        .unwrap_or_else(|| panic!("checkpoint goal autonomy budget missing"));
    assert_eq!(goal_budget.used_model_calls, 1);

    drop(controller);
    let reopened_state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state for recovery: {error}"));
    let (recovered, _) = RecoveryManager::recover(reopened_state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover consumed goal/model budget: {error}"));
    assert_eq!(recovered.task_model_calls_used(&task_id), Some(1));
    assert_eq!(
        latest_checkpoint_manifest(recovered.state())
            .goal_autonomy_budget
            .as_ref()
            .map(|budget| budget.used_model_calls),
        Some(1),
        "RecoveryManager must not refill the outer goal model-call counter"
    );

    drop(recovered);
    let mut tampered_state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state for budget tamper: {error}"));
    append_modified_checkpoint(&mut tampered_state, |manifest| {
        manifest
            .goal_autonomy_budget
            .as_mut()
            .unwrap_or_else(|| panic!("checkpoint goal autonomy budget missing"))
            .used_model_calls = 0;
    });
    drop(tampered_state);
    let tampered_state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen tampered state: {error}"));
    let (recovered_after_tamper, summary) =
        RecoveryManager::recover(tampered_state, &fixture.registry)
            .unwrap_or_else(|error| panic!("recover through trusted checkpoint fallback: {error}"));
    assert!(
        summary.fallback_checkpoint_used,
        "a digest-mismatched checkpoint must never become recovery authority"
    );
    assert_eq!(
        latest_checkpoint_manifest(recovered_after_tamper.state())
            .goal_autonomy_budget
            .as_ref()
            .map(|budget| budget.used_model_calls),
        Some(1),
        "fallback/re-anchor must retain the consumed goal counter rather than accepting refill"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn replan_scope_and_goal_budget_survive_supersession_reopen_without_refill() {
    let mut fixture = replan_fixture("replan-budget-recovery");
    let (mut controller, task_id) = controller_for(&mut fixture);

    let first_attempt =
        induce_executing_attempt_after_model_charge(&mut controller, &fixture, &task_id);
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    let first_budget = latest_checkpoint_manifest(controller.state())
        .goal_autonomy_budget
        .unwrap_or_else(|| panic!("first goal budget missing"));
    assert_eq!(first_budget.used_model_calls, 1);
    assert_eq!(first_budget.max_model_calls, 2);

    let first_classification =
        record_assumption_plan_failure(&mut controller, &fixture, &task_id, &first_attempt);
    let first_replan = controller
        .replan_input(&first_classification)
        .unwrap_or_else(|error| panic!("derive first replan input: {error}"));
    let revision_two = compile_m3_candidate(
        &fixture,
        "compile.m6-t06.replan-r2",
        replan_policy(),
        Some(first_replan),
        &task_id,
        "r2",
    )
    .unwrap_or_else(|error| panic!("compile revision two: {error}"));
    let (activation, diff) = controller
        .activate_superseding_revision(revision_two, &first_classification, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate revision two: {error}"));
    assert_eq!(activation.revision, 2);
    assert_eq!(diff.from_revision, 1);
    assert_eq!(diff.to_revision, 2);
    assert_eq!(activation.task_ids.len(), 1);
    let revision_two_task = activation.task_ids[0].clone();
    let counter = sole_replan_counter(controller.state());
    assert_eq!(counter["count"], json!(1));
    let after_supersession = latest_checkpoint_manifest(controller.state())
        .goal_autonomy_budget
        .unwrap_or_else(|| panic!("goal budget after supersession missing"));
    assert_eq!(after_supersession.used_model_calls, 1);
    assert_eq!(after_supersession.max_model_calls, 2);

    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen superseded state: {error}"));
    let (mut recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover revision two: {error}"));
    recovered.set_resource_pressure_probe(Box::new(FixedPressure(ResourcePressureSnapshotV1 {
        schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
        observed_at_ms: 2_000,
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
    })));
    assert!(!summary.mutation_blocked);
    let recovered_manifest = latest_checkpoint_manifest(recovered.state());
    assert_eq!(recovered_manifest.plan_revision, 2);
    let recovered_budget = recovered_manifest
        .goal_autonomy_budget
        .as_ref()
        .unwrap_or_else(|| panic!("recovered goal budget missing"));
    assert_eq!(recovered_budget.used_model_calls, 1);
    assert_eq!(recovered_budget.max_model_calls, 2);
    assert_eq!(sole_replan_counter(recovered.state())["count"], json!(1));

    let second_attempt =
        induce_executing_attempt_after_model_charge(&mut recovered, &fixture, &revision_two_task);
    let second_classification = record_assumption_plan_failure(
        &mut recovered,
        &fixture,
        &revision_two_task,
        &second_attempt,
    );
    let second_replan = recovered
        .replan_input(&second_classification)
        .unwrap_or_else(|error| panic!("derive second replan input: {error}"));
    let after_second_failure = latest_checkpoint_manifest(recovered.state())
        .goal_autonomy_budget
        .unwrap_or_else(|| panic!("goal budget after second failure missing"));
    assert_eq!(after_second_failure.used_model_calls, 2);
    assert_eq!(after_second_failure.max_model_calls, 2);

    let mut widened_policy = replan_policy();
    widened_policy["resources"]["max_model_calls"] = json!(3);
    let widen_error = compile_m3_candidate(
        &fixture,
        "compile.m6-t06.replan-widen",
        widened_policy,
        Some(second_replan.clone()),
        &revision_two_task,
        "widen",
    )
    .err()
    .unwrap_or_else(|| panic!("replan compiler unexpectedly widened governed goal budget"));
    assert!(
        widen_error.contains("replan cannot change root goal or authoritative policy"),
        "unexpected widened-policy error: {widen_error}"
    );

    let revision_three = compile_m3_candidate(
        &fixture,
        "compile.m6-t06.replan-r3",
        replan_policy(),
        Some(second_replan),
        &revision_two_task,
        "r3",
    )
    .unwrap_or_else(|error| panic!("compile revision three candidate: {error}"));
    let error = recovered
        .activate_superseding_revision(revision_three, &second_classification, &fixture.registry)
        .err()
        .unwrap_or_else(|| panic!("second same-lineage supersession unexpectedly succeeded"));
    assert!(
        error
            .to_string()
            .contains("replan scope budget exhausted: used=1, limit=1"),
        "unexpected replan ceiling error: {error}"
    );
    assert_eq!(sole_replan_counter(recovered.state())["count"], json!(1));
    assert_eq!(
        latest_checkpoint_manifest(recovered.state()).plan_revision,
        2
    );
    assert!(
        recovered
            .state()
            .state_records("controller.plan_revision")
            .unwrap_or_else(|read_error| panic!("read plan revision rows: {read_error}"))
            .into_iter()
            .filter_map(|record| serde_json::from_str::<Value>(&record.value_json).ok())
            .all(|record| record["revision"] != json!(3)),
        "N+2 revision state must not be persisted after scope-budget exhaustion"
    );
}

#[test]
fn rollback_patch_reverse_uses_fresh_authority_and_typed_verification() {
    let mut fixture = fixture("rollback-verified");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest())
        .unwrap_or_else(|error| panic!("derive ready lease: {error}"));
    let execution_backend = fake_backend(vec![response(
        proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let tool_manifest = manifest();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution_backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut model_budget = ModelCallBudget::new(1, 30_000);
    let success = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut model_budget)
        .unwrap_or_else(|error| panic!("execute original mutation: {error}"));
    assert!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read postimage: {error}"))
            .contains("Apply")
    );

    let rollback = controller
        .rollback_patch_reverse(&success.action_id, &runtime)
        .unwrap_or_else(|error| panic!("rollback committed mutation: {error}"));
    assert_eq!(rollback.status, RollbackStatusV1::Verified);
    assert_eq!(
        rollback.verification_evaluator,
        "builtin.diff.controller_patch_absent.v1"
    );
    assert!(rollback.verification_evidence_id.is_some());
    assert!(rollback.verification_artifact_digest.is_some());
    assert_eq!(rollback.original_action_id, success.action_id);
    assert_eq!(
        controller
            .state()
            .action_record(&rollback.rollback_action_id)
            .unwrap_or_else(|error| panic!("rollback action record: {error}"))
            .map(|record| record.state),
        Some("committed".to_owned())
    );
    let restored = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read restored source: {error}"));
    assert_eq!(restored, SOURCE);
    let rollback_events = controller
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("rollback journal: {error}"))
        .into_iter()
        .filter(|event| event.entity_id == rollback.rollback_action_id)
        .map(|event| event.event_kind)
        .collect::<Vec<_>>();
    assert!(rollback_events.iter().any(|kind| kind == "authorized"));
    assert!(rollback_events.iter().any(|kind| kind == "committed"));
}

#[test]
fn rollback_patch_reverse_rejects_drifted_postimage_before_inverse_dispatch() {
    let mut fixture = fixture("rollback-precondition");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest())
        .unwrap_or_else(|error| panic!("derive ready lease: {error}"));
    let execution_backend = fake_backend(vec![response(
        proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let tool_manifest = manifest();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution_backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut model_budget = ModelCallBudget::new(1, 30_000);
    let success = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut model_budget)
        .unwrap_or_else(|error| panic!("execute original mutation: {error}"));
    let before_actions = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("actions before rollback: {error}"))
        .len();
    fs::write(
        fixture.repo.root.join("src/settings/SettingsForm.tsx"),
        SOURCE.replace("Save", "Drifted"),
    )
    .unwrap_or_else(|error| panic!("drift postimage: {error}"));

    let error = controller
        .rollback_patch_reverse(&success.action_id, &runtime)
        .err()
        .unwrap_or_else(|| panic!("drifted rollback unexpectedly dispatched"));
    assert!(
        error.to_string().contains("digest")
            || error.to_string().contains("precondition")
            || error.to_string().contains("stale file hash"),
        "unexpected rollback precondition error: {error}"
    );
    assert_eq!(
        controller
            .state()
            .action_records()
            .unwrap_or_else(|read_error| panic!("actions after rollback: {read_error}"))
            .len(),
        before_actions,
        "rollback drift must fail before fresh inverse action authorization"
    );
    assert!(!matches!(error, ControllerError::UnknownAction(_)));
}

#[cfg(feature = "recovery-test-hooks")]
#[test]
fn rollback_crash_worker_entry() {
    let Some(state_path) = std::env::var_os(ROLLBACK_CRASH_STATE).map(PathBuf::from) else {
        return;
    };
    let root = PathBuf::from(
        std::env::var_os(ROLLBACK_CRASH_ROOT)
            .unwrap_or_else(|| panic!("rollback crash root env missing")),
    );
    let base = PathBuf::from(
        std::env::var_os(ROLLBACK_CRASH_BASE)
            .unwrap_or_else(|| panic!("rollback crash base env missing")),
    );
    let original_action_id = std::env::var(ROLLBACK_CRASH_ORIGINAL_ACTION)
        .unwrap_or_else(|error| panic!("rollback original action env: {error}"));
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &root)
        .unwrap_or_else(|error| panic!("register crash-worker repository: {error}"));
    let state = StateStore::open(state_path)
        .unwrap_or_else(|error| panic!("open crash-worker state: {error}"));
    let (mut controller, _) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover before crash-worker rollback: {error}"));
    let backend = fake_backend(Vec::new());
    let parts = runtime_parts_for(&root, &base);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let tool_manifest = manifest();
    let runtime = ExecutionRuntime {
        registry: &registry,
        backend: &backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let result = controller.rollback_patch_reverse(&original_action_id, &runtime);
    panic!("rollback crash worker unexpectedly returned: {result:?}");
}

#[cfg(feature = "recovery-test-hooks")]
#[test]
#[allow(clippy::too_many_lines)]
fn rollback_post_dispatch_crash_recovers_unknown_and_never_blindly_redispatches() {
    let mut fixture = fixture("rollback-dispatch-crash");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest())
        .unwrap_or_else(|error| panic!("derive original ready lease: {error}"));
    let execution_backend = fake_backend(vec![response(
        proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let tool_manifest = manifest();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution_backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let original = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
        .unwrap_or_else(|error| panic!("execute original mutation: {error}"));
    drop(controller);

    let (mut child, marker) = spawn_rollback_crash_worker(&fixture, &original.action_id);
    wait_for_marker(&marker);
    let rollback_action_id = wait_for_dispatched_rollback_action(&fixture.repo.state_path);
    let precrash_state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open precrash state: {error}"));
    assert_eq!(
        rollback_record_for_action(&precrash_state, &rollback_action_id).status,
        RollbackStatusV1::Prepared
    );
    assert_eq!(
        action_event_count(&precrash_state, &rollback_action_id, "dispatched"),
        1
    );
    drop(precrash_state);
    child
        .kill()
        .unwrap_or_else(|error| panic!("kill rollback crash worker: {error}"));
    child
        .wait()
        .unwrap_or_else(|error| panic!("wait rollback crash worker: {error}"));

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen crashed rollback state: {error}"));
    let (mut recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover crashed rollback: {error}"));
    assert!(summary.mutation_blocked);
    assert!(summary.unknown_action_ids.contains(&rollback_action_id));
    assert!(!summary.unresolved_process_lease_ids.is_empty());
    assert_eq!(
        recovered
            .state()
            .action_record(&rollback_action_id)
            .unwrap_or_else(|error| panic!("read recovered rollback action: {error}"))
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
    assert_eq!(
        rollback_record_for_action(recovered.state(), &rollback_action_id).status,
        RollbackStatusV1::Unknown
    );
    assert_eq!(
        action_event_count(recovered.state(), &rollback_action_id, "dispatched"),
        1
    );

    let retry_backend = fake_backend(Vec::new());
    let retry_parts = runtime_parts(&fixture);
    let retry_isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let retry_manifest = manifest();
    let retry_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &retry_backend,
        command_policy: &retry_parts.command_policy,
        isolation_backend: &retry_isolation,
        isolation_request: &retry_parts.isolation_request,
        artifacts: &retry_parts.artifacts,
        tool_manifest: &retry_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let retry_error = recovered
        .rollback_patch_reverse(&original.action_id, &retry_runtime)
        .err()
        .unwrap_or_else(|| panic!("unknown rollback unexpectedly redispatched"));
    assert!(
        retry_error.to_string().contains("unknown")
            || retry_error.to_string().contains("blocked")
            || retry_error.to_string().contains("stale file hash")
            || retry_error.to_string().contains("precondition"),
        "unexpected rollback retry fence error: {retry_error}"
    );
    assert_eq!(
        action_event_count(recovered.state(), &rollback_action_id, "dispatched"),
        1,
        "rollback recovery must never blindly redispatch an ambiguous inverse action"
    );
    assert_eq!(
        recovered
            .state()
            .action_record(&rollback_action_id)
            .unwrap_or_else(|error| panic!("read rollback action after retry: {error}"))
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
}
