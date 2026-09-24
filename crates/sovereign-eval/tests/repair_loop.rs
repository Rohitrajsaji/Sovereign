#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextLevel, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner,
    EvidenceItem, EvidenceKind, PacketSection, TrustClass,
};
use sovereign_controller::{
    Controller, ExecutionRuntime, ReadinessInputs, RecoveryManager, ResourcePressureProbe, RoleId,
    RoleRegistry, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    BackendHealth, DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelError, ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResidencyProof,
    ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CapabilitySet, CommandPolicy, CommandRisk, IsolationRequest, MacSandboxExecBackend,
    ModelCallBudget, OsMemoryPressure, PinnedExecutable, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
    ReconciliationPolicy, ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::StateStore;
use sovereign_tools::{PermissionClass, ToolManifest, ToolSchemaV1};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SETTINGS_FORM: &[u8] = include_bytes!("fixtures/scenario1/src/settings/SettingsForm.tsx");
const SETTINGS_FORM_TEST: &[u8] =
    include_bytes!("fixtures/scenario1/src/settings/SettingsForm.test.tsx");
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct FixedResourcePressureProbe(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedResourcePressureProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

fn pressure_snapshot(observed_at_ms: i64, constrained: bool) -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
        observed_at_ms,
        controlled_working_set_mib: if constrained { 6_000 } else { 512 },
        host_headroom_mib: if constrained { 512 } else { 6_144 },
        swap_used_mib: Some(4_096),
        swap_out_growth_mib_per_min: if constrained { 512 } else { 0 },
        compressor_growth_mib_per_min: if constrained { 512 } else { 0 },
        os_memory_pressure: if constrained {
            OsMemoryPressure::Warning
        } else {
            OsMemoryPressure::Normal
        },
        recent_pressure_event: constrained,
        thermal_pressure: ThermalPressure::Normal,
        allocation_failure: false,
        repeated_resource_kill: false,
        uncontrolled_child_growth: false,
        host_free_disk_mib: Some(8_192),
    }
}

struct Fixture {
    base: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn create(label: &str) -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for repair fixture"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-t09-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        let settings = root.join("src/settings");
        fs::create_dir_all(&settings)
            .unwrap_or_else(|error| panic!("create repair fixture: {error}"));
        fs::write(settings.join("SettingsForm.tsx"), SETTINGS_FORM)
            .unwrap_or_else(|error| panic!("write SettingsForm: {error}"));
        fs::write(settings.join("SettingsForm.test.tsx"), SETTINGS_FORM_TEST)
            .unwrap_or_else(|error| panic!("write SettingsForm test: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "sovereign-repair@example.invalid"],
        );
        git(&root, &["config", "user.name", "Sovereign Repair"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "repair baseline"]);
        Self { base, root }
    }

    fn state_path(&self) -> PathBuf {
        self.base.join("state.sqlite3")
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
    snapshot: RepositorySnapshot,
    form_digest: String,
}

struct RuntimeHarness {
    artifacts: ArtifactStore,
    command_policy: CommandPolicy,
    isolation_backend: MacSandboxExecBackend,
    isolation_request: IsolationRequest,
    tool_manifest: ToolManifest,
}

struct RepairAwareFakeBackend {
    inner: DeterministicFakeBackend,
    completion_index: AtomicU64,
    expected_source_digest: String,
}

impl RepairAwareFakeBackend {
    fn new(inner: DeterministicFakeBackend, expected_source_digest: String) -> Self {
        Self {
            inner,
            completion_index: AtomicU64::new(0),
            expected_source_digest,
        }
    }
}

impl ModelBackend for RepairAwareFakeBackend {
    fn capabilities(&self) -> ModelCapabilities {
        self.inner.capabilities()
    }

    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.inner.load(profile)
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        let call_index = self.completion_index.fetch_add(1, Ordering::Relaxed);
        if call_index == 2 {
            let prompt = request
                .messages
                .iter()
                .map(|message| message.content.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if !prompt.contains(
                "replace_literal is not entailed by the immutable compiled literal contract",
            ) || !prompt.contains("Save button that does not exist")
                || !prompt.contains("replace_literal_contract")
                || !prompt.contains(&self.expected_source_digest)
                || !prompt.contains("rejected-attempt diagnostics, not repair instructions")
            {
                return Err(ModelError::InvalidResponse(
                    "repair attempt was dispatched without actionable FailureRecord/current-digest evidence"
                        .to_owned(),
                ));
            }
        }
        self.inner.complete(request)
    }

    fn count_tokens(&self, content: &str) -> Result<u32, ModelError> {
        self.inner.count_tokens(content)
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        self.inner.health()
    }

    fn unload(&self) -> Result<(), ModelError> {
        self.inner.unload()
    }

    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        self.inner.residency_proof()
    }
}

impl RuntimeHarness {
    fn new(fixture: &Fixture) -> Self {
        let artifacts = ArtifactStore::open(fixture.base.join("cas"))
            .unwrap_or_else(|error| panic!("open repair artifact store: {error}"));
        let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
            .unwrap_or_else(|error| panic!("pin python: {error}"));
        let toolchain_root = python
            .path
            .parent()
            .unwrap_or_else(|| panic!("python executable must have parent"))
            .to_path_buf();
        let command_policy = CommandPolicy::new([python], [toolchain_root])
            .unwrap_or_else(|error| panic!("command policy: {error}"));
        let isolation_backend = MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("detect macOS Seatbelt: {error}"));
        let home =
            std::env::var_os("HOME").map_or_else(|| panic!("HOME must be set"), PathBuf::from);
        let isolation_request = IsolationRequest {
            repository_root: fixture.root.clone(),
            user_home_root: home,
            extra_protected_read_roots: Vec::new(),
            rust_toolchain: None,
            build_scratch_root: None,
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        };
        let tool_manifest = ToolManifest {
            tool_id: "tool.patch".to_owned(),
            version: "1.0.0".to_owned(),
            content_digest: WRITE_TOOL_DIGEST.to_owned(),
            permission_ceiling: BTreeSet::from([
                PermissionClass::ProcessExec,
                PermissionClass::RepositoryWrite,
            ]),
            declared_risk_floor: CommandRisk::RepositoryMutation,
            reconciliation_policy: ReconciliationPolicy::proof_required_local(),
        };
        Self {
            artifacts,
            command_policy,
            isolation_backend,
            isolation_request,
            tool_manifest,
        }
    }

    fn runtime<'a>(
        &'a self,
        prepared: &'a Prepared,
        backend: &'a dyn ModelBackend,
    ) -> ExecutionRuntime<'a, MacSandboxExecBackend> {
        ExecutionRuntime {
            registry: &prepared.registry,
            backend,
            command_policy: &self.command_policy,
            isolation_backend: &self.isolation_backend,
            isolation_request: &self.isolation_request,
            artifacts: &self.artifacts,
            tool_manifest: &self.tool_manifest,
            python_executable: Path::new("/usr/bin/python3"),
        }
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

fn global_policy() -> Value {
    serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("policy fixture: {error}"))
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

fn prepare(fixture: &Fixture) -> Prepared {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &fixture.root)
        .unwrap_or_else(|error| panic!("register repository: {error}"));
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot repository: {error}"));
    let retriever = ExactRetriever::new(&registry);
    let form = retriever
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read SettingsForm: {error}"));
    let focused_test = retriever
        .read_path(
            "repo.app",
            Path::new("src/settings/SettingsForm.test.tsx"),
            None,
        )
        .unwrap_or_else(|error| panic!("read SettingsForm test: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix:
                    "Controller owns repair state, retry counters, and mutation authority."
                        .to_owned(),
                task_contract:
                    "Rename the Settings button from Save to Apply without changing submit behavior."
                        .to_owned(),
                current_state: format!(
                    "repository=repo.app; head={:?}; dirty_digest={}; active_attempt=none",
                    snapshot.head, snapshot.dirty_digest
                ),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![
                    EvidenceItem::from_exact_file(&form, "exact current Settings form"),
                    EvidenceItem::from_exact_file(&focused_test, "focused current Settings test"),
                ],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build context packet: {error}"));

    Prepared {
        registry,
        packet,
        snapshot,
        form_digest: form.digest,
    }
}

fn repair_base_context(base: &ContextPacket) -> ContextPacket {
    let mut packet = base.clone();
    // Adversarial non-authoritative baggage: repair projection must exclude these even when a
    // caller supplies them after normal PlanCompiler context construction.
    packet.items.push(EvidenceItem::new(
        "adversarial.prior-transcript",
        PacketSection::ToolEvidence,
        ContextLevel::C1,
        EvidenceKind::PriorAttemptTranscript,
        "controller://attempt/transcript",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "test_only_untrusted_transcript",
        TrustClass::Untrusted,
        "must be excluded from repair",
        "RAW_PRIOR_ATTEMPT_TRANSCRIPT_MUST_NOT_APPEAR",
    ));
    packet.items.push(EvidenceItem::new(
        "adversarial.raw-tool-log",
        PacketSection::ToolEvidence,
        ContextLevel::C1,
        EvidenceKind::RawToolLog,
        "tool://raw/log",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "test_only_untrusted_raw_log",
        TrustClass::Untrusted,
        "must be excluded from repair",
        "RAW_TOOL_LOG_MUST_NOT_APPEAR",
    ));
    packet.items.push(EvidenceItem::new(
        "adversarial.tool-schema",
        PacketSection::ToolEvidence,
        ContextLevel::C1,
        EvidenceKind::ToolSchema,
        "tool://tool.patch@1.0.0/schema",
        WRITE_TOOL_DIGEST,
        "caller_supplied_generic_tool_schema",
        TrustClass::Untrusted,
        "must not self-authorize into repair",
        "FORGED_TOOL_SCHEMA_MUST_NOT_APPEAR",
    ));
    packet
}

fn response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "repair.fixture".to_owned(),
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

fn plan_proposal() -> Value {
    json!({
        "tasks": [{
            "title": "Rename Settings submit label",
            "objective": "Change the rendered Settings submit label from Save to Apply without altering submit behavior.",
            "rationale": "Exact current source identifies one bounded edit.",
            "files": ["src/settings/SettingsForm.tsx", "src/settings/SettingsForm.test.tsx"],
            "symbols": ["SettingsForm"],
            "evidence_queries": [],
            "expected_change": "SettingsForm renders Apply instead of Save."
        }]
    })
}

fn execution_proposal(prepared: &Prepared, old_literal: &str) -> Value {
    json!({
        "schema_version": 1,
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": prepared.form_digest,
            "old_literal": old_literal,
            "new_literal": "Apply",
            "expected_occurrences": 1
        }
    })
}

fn fake_backend(prepared: &Prepared, second_attempt_succeeds: bool) -> RepairAwareFakeBackend {
    let bad = execution_proposal(prepared, "Save button that does not exist");
    let second = if second_attempt_succeeds {
        execution_proposal(prepared, "Save")
    } else {
        bad.clone()
    };
    let inner = DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-m1-repair-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![
            response(
                plan_proposal().to_string(),
                prepared.packet.metrics.final_serialized_input_tokens,
            ),
            response(
                bad.to_string(),
                prepared.packet.metrics.final_serialized_input_tokens,
            ),
            response(
                second.to_string(),
                prepared.packet.metrics.final_serialized_input_tokens,
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("create fake repair backend: {error}"));
    RepairAwareFakeBackend::new(inner, prepared.form_digest.clone())
}

fn compile_and_activate(
    fixture: &Fixture,
    prepared: &Prepared,
    backend: &dyn ModelBackend,
) -> (Controller, String, String) {
    let role = canonical_implementer_role();
    let skills = vec![capability(
        "skill.focused-edit",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )];
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.scenario1.t09".to_owned(),
        compiled_at: "2026-09-13T03:00:00Z".to_owned(),
        project_id: "project.scenario1".to_owned(),
        project_name: "Scenario 1 repair fixture".to_owned(),
        workspace_roots: vec![prepared.snapshot.root.display().to_string()],
        goal_id: "goal.scenario1".to_owned(),
        goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
        goal_invariants: vec!["Do not alter submit behavior.".to_owned()],
        goal_non_goals: vec!["Do not redesign the Settings form.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: prepared.snapshot.repository_id.clone(),
            root: prepared.snapshot.root.display().to_string(),
            head: prepared.snapshot.head.clone(),
            branch: prepared.snapshot.branch.clone(),
            dirty_digest: prepared.snapshot.dirty_digest.clone(),
            protected_changes_present: prepared.snapshot.protected_changes_present,
            languages: vec!["typescript".to_owned()],
        },
        policy: global_policy(),
        role,
        skills,
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
        .unwrap_or_else(|error| panic!("construct validator: {error}"));
    let compiler = PlanCompiler::new(backend, &validator, "m1-eval-repair-compiler-v1")
        .unwrap_or_else(|error| panic!("construct compiler: {error}"));
    let mut compiler_budget = ModelCallBudget::new(2, 1_000);
    let compilation = compiler
        .compile(&input, &mut compiler_budget)
        .unwrap_or_else(|error| panic!("compile repair goal: {error}"));
    assert!(validator.validate(compilation.plan()).is_empty());
    assert_eq!(compiler_budget.remaining_calls(), 1);
    backend
        .unload()
        .unwrap_or_else(|error| panic!("release compiler-only model residency: {error}"));

    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open repair state: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        pressure_snapshot(1_000, false),
    )));
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate compiler result: {error}"));
    assert_eq!(activation.task_ids.len(), 1);
    let task_id = activation.task_ids[0].clone();
    let plan_digest = activation.plan_digest;
    (controller, task_id, plan_digest)
}

fn task_contract_and_acceptance(controller: &Controller, task_id: &str) -> (String, Value) {
    let digest = controller
        .task_contract_digest(task_id)
        .unwrap_or_else(|| panic!("task contract digest missing"))
        .to_owned();
    let raw = controller
        .state()
        .get_state("controller.task", task_id)
        .unwrap_or_else(|error| panic!("read task runtime: {error}"))
        .unwrap_or_else(|| panic!("task runtime missing"));
    let runtime: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("task runtime json: {error}"));
    let acceptance = runtime
        .pointer("/task/acceptance_criteria")
        .cloned()
        .unwrap_or_else(|| panic!("acceptance criteria missing"));
    (digest, acceptance)
}

#[test]
#[allow(clippy::too_many_lines)]
fn failed_attempt_recovers_resource_defers_then_targeted_repair_succeeds() {
    let fixture = Fixture::create("repair-success");
    let prepared = prepare(&fixture);
    let backend = fake_backend(&prepared, true);
    let _model_lease = backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load fake backend: {error}"));
    let runtime_harness = RuntimeHarness::new(&fixture);
    let (mut controller, task_id, plan_digest) =
        compile_and_activate(&fixture, &prepared, &backend);
    let (task_contract_before, acceptance_before) =
        task_contract_and_acceptance(&controller, &task_id);
    let plan_before = controller
        .state()
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read plan document: {error}"))
        .unwrap_or_else(|| panic!("plan document missing"));

    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:repair-initial-admission"),
            &runtime_harness.tool_manifest,
        )
        .unwrap_or_else(|error| panic!("derive initial ready lease: {error}"));
    let runtime = runtime_harness.runtime(&prepared, &backend);
    let repair_context = repair_base_context(&prepared.packet);
    let repair_schema = ToolSchemaV1 {
        tool_id: runtime_harness.tool_manifest.tool_id.clone(),
        version: runtime_harness.tool_manifest.version.clone(),
        content_digest: runtime_harness.tool_manifest.content_digest.clone(),
        name: "patch".to_owned(),
        description: "Apply one exact Controller-authorized replacement".to_owned(),
        input_schema: json!({"type": "object", "required": ["path"]}),
        required_capabilities: CapabilitySet::new([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]),
    };
    let mut execution_budget = ModelCallBudget::new(2, 30_000);
    let first =
        controller.execute_replace(ready, &runtime, &prepared.packet, &mut execution_budget);
    assert!(first.is_err(), "attempt 1 must fail before mutation");
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(1));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    let failure = controller
        .latest_failure_record(&task_id)
        .unwrap_or_else(|error| panic!("read durable FailureRecord: {error}"))
        .unwrap_or_else(|| panic!("attempt 1 must persist FailureRecord"));
    assert_eq!(failure.category, "proposal_validation_failure");
    assert_eq!(failure.failure_code, "replace_literal_contract");
    assert_eq!(failure.decision, "repair");
    assert_eq!(failure.task_contract_digest, task_contract_before);
    assert_eq!(failure.plan_digest, plan_digest);
    assert!(failure.action_id.is_none());
    assert!(
        failure
            .synopsis
            .contains("replace_literal is not entailed by the immutable compiled literal contract")
    );
    assert_eq!(
        failure
            .failed_action_facts
            .get("old_literal")
            .map(String::as_str),
        Some("Save button that does not exist")
    );
    assert!(failure.affected_contract_ids.is_empty());

    // Recovery must reconstruct Controller-owned attempt/model/failure counters without chat replay.
    drop(controller);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen state for repair recovery: {error}"));
    let (mut controller, recovery) = RecoveryManager::recover(state, &prepared.registry)
        .unwrap_or_else(|error| panic!("recover failed repair state: {error}"));
    assert_eq!(recovery.plan_digest, plan_digest);
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(1));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(
        controller
            .latest_failure_record(&task_id)
            .unwrap_or_else(|error| panic!("failure after recovery: {error}")),
        Some(failure.clone())
    );

    // One constrained-host denial occurs before a repair attempt starts. It consumes the
    // resource retry allowance, but it must not fabricate attempt/model-call counters.
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        pressure_snapshot(2_000, true),
    )));
    let denied = controller.repair_replace(
        &task_id,
        &runtime,
        &repair_context,
        std::slice::from_ref(&repair_schema),
        ReadinessInputs::permissive_m1("sha256:repair-resource-constrained"),
        &mut execution_budget,
    );
    let Err(denied_error) = denied else {
        panic!("constrained repair admission must defer");
    };
    assert!(
        denied_error.to_string().contains("resource denied"),
        "repair failed before resource admission: {denied_error}"
    );
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::DeferredResource)
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(1));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(controller.task_resource_deferrals_used(&task_id), Some(1));
    assert_eq!(execution_budget.remaining_calls(), 1);

    // resource_retry_limit=1 permits re-entry; attempt 2 gets the remaining model call.
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        pressure_snapshot(130_000, false),
    )));
    let (success, repair_packet) = controller
        .repair_replace(
            &task_id,
            &runtime,
            &repair_context,
            std::slice::from_ref(&repair_schema),
            ReadinessInputs::permissive_m1("sha256:repair-resource-recovered"),
            &mut execution_budget,
        )
        .unwrap_or_else(|error| panic!("targeted repair attempt 2: {error}"));
    assert!(success.verification.passed);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_attempts_started(&task_id), Some(2));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(2));
    assert_eq!(execution_budget.remaining_calls(), 0);

    assert_eq!(repair_packet.plan_digest, plan_digest);
    assert_eq!(repair_packet.task_contract_digest, task_contract_before);
    assert_eq!(
        repair_packet.acceptance_contract_digest,
        success.verification.acceptance_contract_digest
    );
    assert_eq!(repair_packet.prior_attempt_id, failure.attempt_id);
    assert_eq!(repair_packet.failure_signature, failure.signature);
    assert!(!repair_packet.failure_record_digest.is_empty());
    assert!(
        repair_packet
            .context
            .items
            .iter()
            .any(|item| item.kind == EvidenceKind::Diff)
    );
    let failure_item = repair_packet
        .context
        .items
        .iter()
        .find(|item| item.kind == EvidenceKind::FailureSynopsis)
        .unwrap_or_else(|| panic!("repair packet must contain FailureRecord synopsis"));
    assert!(failure_item.text.contains(&failure.attempt_id));
    assert!(failure_item.text.contains(&failure.signature));
    assert!(failure_item.text.contains("replace_literal_contract"));
    assert!(
        failure_item
            .text
            .contains("replace_literal is not entailed by the immutable compiled literal contract")
    );
    assert!(
        failure_item
            .text
            .contains("Save button that does not exist")
    );
    assert!(repair_packet.context.items.iter().all(|item| !matches!(
        item.kind,
        EvidenceKind::PriorAttemptTranscript
            | EvidenceKind::RawToolLog
            | EvidenceKind::HiddenReasoning
    )));
    assert!(
        !repair_packet
            .context
            .serialized_input
            .contains("RAW_PRIOR_ATTEMPT_TRANSCRIPT_MUST_NOT_APPEAR")
    );
    assert!(
        !repair_packet
            .context
            .serialized_input
            .contains("RAW_TOOL_LOG_MUST_NOT_APPEAR")
    );
    let repair_tool_schema = repair_packet
        .context
        .items
        .iter()
        .find(|item| item.kind == EvidenceKind::ToolSchema)
        .unwrap_or_else(|| panic!("repair must preserve exact Controller-authorized tool schema"));
    assert_eq!(
        repair_tool_schema.provenance,
        "controller_authorized_tool_schema_v1"
    );
    assert_eq!(repair_tool_schema.trust_class, TrustClass::Tool);
    assert!(
        repair_tool_schema
            .text
            .contains("\"tool_id\":\"tool.patch\"")
    );
    assert!(
        !repair_packet
            .context
            .serialized_input
            .contains("FORGED_TOOL_SCHEMA_MUST_NOT_APPEAR")
    );

    let (task_contract_after, acceptance_after) =
        task_contract_and_acceptance(&controller, &task_id);
    assert_eq!(task_contract_after, task_contract_before);
    assert_eq!(acceptance_after, acceptance_before);
    let plan_after = controller
        .state()
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read plan document after repair: {error}"))
        .unwrap_or_else(|| panic!("plan document missing after repair"));
    assert_eq!(plan_after, plan_before);

    let source = fs::read_to_string(fixture.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read repaired source: {error}"));
    assert!(source.contains("Apply"));
    assert!(!source.contains(">Save<"));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload fake backend: {error}"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn identical_second_failure_blocks_third_repair() {
    let fixture = Fixture::create("identical-failure-limit");
    let prepared = prepare(&fixture);
    let backend = fake_backend(&prepared, false);
    let _model_lease = backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load fake backend: {error}"));
    let runtime_harness = RuntimeHarness::new(&fixture);
    let (mut controller, task_id, _plan_digest) =
        compile_and_activate(&fixture, &prepared, &backend);
    let runtime = runtime_harness.runtime(&prepared, &backend);
    let mut execution_budget = ModelCallBudget::new(3, 30_000);

    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:identical-initial"),
            &runtime_harness.tool_manifest,
        )
        .unwrap_or_else(|error| panic!("derive identical-failure initial lease: {error}"));
    assert!(
        controller
            .execute_replace(ready, &runtime, &prepared.packet, &mut execution_budget)
            .is_err()
    );
    let first_failure = controller
        .latest_failure_record(&task_id)
        .unwrap_or_else(|error| panic!("first failure record: {error}"))
        .unwrap_or_else(|| panic!("first FailureRecord missing"));
    assert_eq!(first_failure.decision, "repair");
    assert_eq!(controller.task_attempts_started(&task_id), Some(1));

    let second = controller.repair_replace(
        &task_id,
        &runtime,
        &prepared.packet,
        &[],
        ReadinessInputs::permissive_m1("sha256:identical-second"),
        &mut execution_budget,
    );
    let Err(second_error) = second else {
        panic!("identical repair attempt 2 must fail");
    };
    assert!(
        !second_error.to_string().contains("repair context rejected"),
        "attempt 2 never reached model/validation: {second_error}"
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(2));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(2));
    let second_failure = controller
        .latest_failure_record(&task_id)
        .unwrap_or_else(|error| panic!("second failure record: {error}"))
        .unwrap_or_else(|| panic!("second FailureRecord missing"));
    assert_eq!(second_failure.signature, first_failure.signature);
    assert_eq!(second_failure.decision, "block");
    assert_ne!(second_failure.attempt_id, first_failure.attempt_id);

    let budget_before_third = execution_budget.remaining_calls();
    let third = controller.repair_replace(
        &task_id,
        &runtime,
        &prepared.packet,
        &[],
        ReadinessInputs::permissive_m1("sha256:identical-third"),
        &mut execution_budget,
    );
    let Err(error) = third else {
        panic!("third repair must be blocked after identical second failure");
    };
    assert!(
        error
            .to_string()
            .contains("not eligible for targeted repair")
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(2));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(2));
    assert_eq!(execution_budget.remaining_calls(), budget_before_third);

    let journal = controller
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("read repair journal: {error}"));
    assert_eq!(
        journal
            .iter()
            .filter(|event| {
                event.entity_type == "controller" && event.event_kind == "attempt_started"
            })
            .count(),
        2
    );
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload fake backend: {error}"));
}
