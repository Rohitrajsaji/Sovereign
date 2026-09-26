#![cfg_attr(not(target_os = "macos"), allow(unused_imports, dead_code))]

use serde_json::{Value, json};
use sovereign_context::{
    AttemptOutcomeFacts, ContextBudget, ContextMode, ContextPacket, ContextPacketInput,
    ContextPlanner, ContextTelemetry, EvidenceItem, EvidenceUseFacts, ProviderTokenUsage,
    RepositoryRetrievalBackend, RetrievalIntent, RetrievalRouteKind, RetrievalRouter,
    RetrievalTrace,
};
use sovereign_controller::{
    Controller, ExecutionRuntime, ReadinessInputs, ResourcePressureProbe, RoleId, RoleRegistry,
    TaskState,
};
use sovereign_eval::{EvaluationAttemptRecord, aggregate_context_metrics};
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
    CommandPolicy, CommandRisk, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    OsMemoryPressure, PinnedExecutable, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
    ReconciliationPolicy, ResourcePressureSnapshotV1, ThermalPressure,
};
use sovereign_repo::{
    ExactRetriever, IndexConfig, LexicalRetriever, ProjectRegistry, RepositoryIntelligence,
    RepositorySnapshot, StructuralConfig, StructuralIndex,
};
use sovereign_state::StateStore;
use sovereign_tools::{PermissionClass, ToolManifest};
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

struct FixtureRepo {
    base: PathBuf,
    root: PathBuf,
}

impl FixtureRepo {
    fn create() -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let home = std::env::var_os("HOME").map_or_else(
            || panic!("HOME must be set for the macOS Seatbelt fixture"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-t07-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        let settings = root.join("src/settings");
        fs::create_dir_all(&settings)
            .unwrap_or_else(|error| panic!("create fixture directories: {error}"));
        fs::write(settings.join("SettingsForm.tsx"), SETTINGS_FORM)
            .unwrap_or_else(|error| panic!("write SettingsForm fixture: {error}"));
        fs::write(settings.join("SettingsForm.test.tsx"), SETTINGS_FORM_TEST)
            .unwrap_or_else(|error| panic!("write SettingsForm test fixture: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "sovereign-eval@example.invalid"],
        );
        git(&root, &["config", "user.name", "Sovereign Eval"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "scenario1 baseline"]);
        Self { base, root }
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

fn global_policy() -> Value {
    serde_json::from_str(include_str!("fixtures/scenario1/policy.json"))
        .unwrap_or_else(|error| panic!("parse Scenario 1 policy fixture: {error}"))
}

fn capability(id: &str, version: &str, digest: &str) -> Value {
    json!({"id": id, "version": version, "digest": digest})
}

fn canonical_implementer_role() -> Value {
    let pin = RoleRegistry::canonical()
        .canonical_pin(RoleId::Implementer)
        .unwrap_or_else(|error| panic!("canonical implementer pin: {error}"));
    json!({"id": pin.id, "version": pin.version, "digest": pin.digest})
}

fn prepare_context(fixture: &FixtureRepo) -> PreparedContext {
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
    let instructions = registry
        .instructions_for_path("repo.app", Path::new("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("resolve instructions: {error}"));
    let mut candidates = vec![
        EvidenceItem::from_exact_file(&form, "exact current Settings form"),
        EvidenceItem::from_exact_file(&focused_test, "focused current Settings test"),
    ];
    candidates.extend(instructions.iter().map(|instruction| {
        EvidenceItem::from_instruction("repo.app", instruction, "scoped repository instruction")
    }));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix:
                    "Use bounded evidence only. The Controller owns all state and authority."
                        .to_owned(),
                task_contract:
                    "Rename the Settings button from Save to Apply without changing submit behavior."
                        .to_owned(),
                current_state: format!(
                    "repository=repo.app; head={:?}; dirty_digest={}; active_attempt=none",
                    snapshot.head, snapshot.dirty_digest
                ),
                authorized_tool_schemas: Vec::new(),
                candidates,
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

fn response(content: String, packet_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "template".to_owned(),
        content,
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

fn fake_backend(prepared: &PreparedContext) -> DeterministicFakeBackend {
    let plan_proposal = json!({
        "tasks": [{
            "title": "Rename Settings submit label",
            "objective": "Change the rendered Settings submit label from Save to Apply without altering submit behavior.",
            "rationale": "Exact current source and focused-test evidence identify one bounded SettingsForm edit.",
            "files": ["src/settings/SettingsForm.tsx"],
            "symbols": ["SettingsForm"],
            "evidence_queries": [],
            "expected_change": "The scoped SettingsForm renders Apply instead of Save."
        }]
    });
    let execution_proposal = json!({
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
    });
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-m1-controller-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![
            response(
                plan_proposal.to_string(),
                prepared.packet.metrics.final_serialized_input_tokens,
            ),
            response(
                execution_proposal.to_string(),
                prepared.packet.metrics.final_serialized_input_tokens,
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("create fake backend: {error}"))
}

struct RoutedAttemptContext {
    packet: ContextPacket,
    trace: RetrievalTrace,
    evidence_id: String,
    source_digest: String,
}

fn routed_attempt_context(
    fixture: &FixtureRepo,
    prepared: &PreparedContext,
    path: &str,
    task_contract: &str,
    label: &str,
) -> RoutedAttemptContext {
    let mut lexical = LexicalRetriever::open(
        &prepared.registry,
        "repo.app",
        fixture.base.join(format!("{label}-lexical.sqlite3")),
        IndexConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open lexical index for {label}: {error}"));
    let mut structural = StructuralIndex::open(
        &prepared.registry,
        "repo.app",
        fixture.base.join(format!("{label}-structural.sqlite3")),
        StructuralConfig::default(),
    )
    .unwrap_or_else(|error| panic!("open structural index for {label}: {error}"));
    let outcome = {
        let mut backend = RepositoryRetrievalBackend::new(
            "repo.app",
            &prepared.registry,
            &mut lexical,
            &mut structural,
        )
        .unwrap_or_else(|error| panic!("construct repository retrieval backend: {error}"));
        RetrievalRouter
            .route(
                &mut backend,
                &RetrievalIntent::KnownPath {
                    repository_id: "repo.app".to_owned(),
                    path: PathBuf::from(path),
                },
            )
            .unwrap_or_else(|error| panic!("route {label}: {error}"))
    };
    assert_eq!(outcome.trace.route.len(), 1);
    assert_eq!(outcome.trace.route[0].selected_count, 1);
    assert!(
        outcome
            .trace
            .route
            .iter()
            .all(|step| step.channel != sovereign_context::Channel::Semantic)
    );
    let item = outcome
        .evidence
        .first()
        .unwrap_or_else(|| panic!("{label} route must return exact evidence"));
    let evidence_id = item.evidence_id.clone();
    let source_digest = item.source_digest.clone();
    let snapshot = prepared
        .registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot routed packet for {label}: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix:
                    "Use bounded routed evidence only. The Controller owns all state and authority."
                        .to_owned(),
                task_contract: task_contract.to_owned(),
                current_state: format!(
                    "repository=repo.app; head={:?}; dirty_digest={}; active_attempt=none",
                    snapshot.head, snapshot.dirty_digest
                ),
                authorized_tool_schemas: Vec::new(),
                candidates: outcome.evidence,
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build routed packet for {label}: {error}"));
    assert!(packet.metrics.final_serialized_input_tokens <= 8_000);
    RoutedAttemptContext {
        packet,
        trace: outcome.trace,
        evidence_id,
        source_digest,
    }
}

fn medium_plan_backend(prepared: &PreparedContext) -> DeterministicFakeBackend {
    let plan_proposal = json!({
        "tasks": [
            {
                "title": "Update Settings submit label",
                "objective": "Change the Settings button label from Save to Apply.",
                "rationale": "Exact current source identifies the component mutation and must be verified before the dependent focused-test update.",
                "files": ["src/settings/SettingsForm.tsx"],
                "symbols": ["SettingsForm"],
                "evidence_queries": ["exact:path=src/settings/SettingsForm.tsx;contains=Save"],
                "expected_change": "SettingsForm renders Apply instead of Save."
            },
            {
                "title": "Update focused Settings test",
                "objective": "Update the focused Settings test expectation from Save to Apply after the source edit succeeds.",
                "rationale": "The dependent test change keeps the source and focused verification fixture consistent.",
                "files": ["src/settings/SettingsForm.test.tsx"],
                "symbols": ["SettingsForm"],
                "evidence_queries": [],
                "expected_change": "The focused test expects the Apply button label."
            }
        ]
    });
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-m2-medium-plan-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![response(
            plan_proposal.to_string(),
            prepared.packet.metrics.final_serialized_input_tokens,
        )],
    )
    .unwrap_or_else(|error| panic!("create medium-plan backend: {error}"))
}

fn execution_backend(content: String, packet_tokens: u32) -> DeterministicFakeBackend {
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-m2-medium-execution-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![response(content, packet_tokens)],
    )
    .unwrap_or_else(|error| panic!("create medium execution backend: {error}"))
}

fn replace_proposal(
    evidence_id: &str,
    path: &str,
    source_digest: &str,
    old_literal: &str,
    new_literal: &str,
) -> String {
    json!({
        "schema_version": 1,
        "evidence_ids": [evidence_id],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": path,
            "expected_source_digest": source_digest,
            "old_literal": old_literal,
            "new_literal": new_literal,
            "expected_occurrences": 1
        }
    })
    .to_string()
}

fn telemetry_outcome(
    proposal: String,
    evidence_id: &str,
    verification_ids: &[String],
) -> AttemptOutcomeFacts {
    let mut evidence_use = EvidenceUseFacts::default();
    evidence_use
        .authorized_action_evidence_ids
        .insert(evidence_id.to_owned());
    evidence_use
        .verification_evidence_ids
        .extend(verification_ids.iter().cloned());
    AttemptOutcomeFacts {
        verified_success: true,
        accepted_change_set: true,
        model_output_for_token_fallback: proposal,
        evidence_use,
        ..AttemptOutcomeFacts::default()
    }
}

#[cfg(target_os = "macos")]
#[test]
#[allow(clippy::too_many_lines)]
fn natural_language_goal_compiles_then_controller_edits_and_deterministically_verifies() {
    let fixture = FixtureRepo::create();
    let prepared = prepare_context(&fixture);
    assert!(prepared.packet.metrics.final_serialized_input_tokens <= 8_000);
    let backend = fake_backend(&prepared);
    let _model_lease = backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load fake backend: {error}"));

    let role = canonical_implementer_role();
    let skills = vec![capability(
        "skill.focused-edit",
        "1.0.0",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )];
    let write_tool = capability("tool.patch", "1.0.0", WRITE_TOOL_DIGEST);
    let read_tool = capability(
        "tool.read",
        "1.0.0",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.scenario1.t07".to_owned(),
        compiled_at: "2026-09-12T18:20:00Z".to_owned(),
        project_id: "project.scenario1".to_owned(),
        project_name: "Scenario 1 runtime fixture".to_owned(),
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
        tools: vec![write_tool, read_tool],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: prepared.packet.clone(),
        m3: None,
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("construct validator: {error}"));
    let compiler = PlanCompiler::new(&backend, &validator, "m1-eval-compiler-v1")
        .unwrap_or_else(|error| panic!("construct compiler: {error}"));
    let mut compiler_budget = ModelCallBudget::new(1, 1_000);
    let compilation = compiler
        .compile(&input, &mut compiler_budget)
        .unwrap_or_else(|error| panic!("compile natural-language goal: {error:?}"));
    assert!(validator.validate(compilation.plan()).is_empty());
    assert_eq!(compiler_budget.remaining_calls(), 0);

    let state = StateStore::open(fixture.base.join("state.sqlite3"))
        .unwrap_or_else(|error| panic!("open controller state: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join("cas"))
        .unwrap_or_else(|error| panic!("open artifact store: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(10_000))));
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate compiler result: {error}"));
    assert_eq!(activation.task_ids.len(), 1);
    let task_id = activation.task_ids[0].clone();
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:resource-admission-current"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive ready lease: {error}"));

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
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME must be set"), PathBuf::from);
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
    let tool_manifest = write_tool_manifest();
    let runtime = ExecutionRuntime {
        registry: &prepared.registry,
        backend: &backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &isolation_request,
        artifacts: &artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut execution_budget = ModelCallBudget::new(4, 30_000);
    let success = controller
        .execute_replace(ready, &runtime, &prepared.packet, &mut execution_budget)
        .unwrap_or_else(|error| panic!("execute T07 vertical slice: {error}"));

    assert_eq!(execution_budget.remaining_calls(), 3);
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert!(success.verification.passed);
    assert_eq!(success.action_result_digest.len(), 64);
    assert!(
        success
            .action_result_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert!(
        success
            .verification_evidence_id
            .starts_with("evidence.verification.")
    );
    let journal = controller
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("read end-to-end journal: {error}"));
    for required_event in [
        "plan_activated",
        "task_model_call_consumed",
        "attempt_started",
        "verification_recorded",
        "attempt_succeeded",
        "task_succeeded",
    ] {
        assert!(
            journal.iter().any(|event| {
                event.entity_type == "controller" && event.event_kind == required_event
            }),
            "missing Controller journal event {required_event}"
        );
    }
    for required_action_event in ["authorized", "dispatched", "observed", "committed"] {
        assert!(
            journal.iter().any(|event| {
                event.entity_type == "action" && event.event_kind == required_action_event
            }),
            "missing action journal event {required_action_event}"
        );
    }
    let final_source = fs::read_to_string(fixture.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read final source: {error}"));
    assert!(final_source.contains("Apply"));
    assert!(!final_source.contains("Save"));
    let diff = ExactRetriever::new(&prepared.registry)
        .current_diff("repo.app")
        .unwrap_or_else(|error| panic!("read final diff: {error}"));
    assert!(diff.content.contains("SettingsForm.tsx"));
    assert!(
        diff.content
            .contains("-      <button type=\"submit\">Save</button>")
    );
    assert!(
        diff.content
            .contains("+      <button type=\"submit\">Apply</button>")
    );
    assert!(!diff.content.contains("SettingsForm.test.tsx"));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload fake backend: {error}"));
}

#[cfg(target_os = "macos")]
#[test]
#[allow(clippy::too_many_lines)]
fn m2_medium_d2_goal_succeeds_with_real_routing_and_context_token_metrics_without_semantic() {
    let fixture = FixtureRepo::create();
    let prepared = prepare_context(&fixture);
    let planner_backend = medium_plan_backend(&prepared);
    let _planner_lease = planner_backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load medium planner backend: {error}"));

    let role = canonical_implementer_role();
    let skills = vec![capability(
        "skill.focused-edit",
        "1.0.0",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )];
    let write_tool = capability("tool.patch", "1.0.0", WRITE_TOOL_DIGEST);
    let read_tool = capability(
        "tool.read",
        "1.0.0",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.m2.medium.d2".to_owned(),
        compiled_at: "2026-09-13T08:20:00Z".to_owned(),
        project_id: "project.m2.medium".to_owned(),
        project_name: "M2 medium routed telemetry fixture".to_owned(),
        workspace_roots: vec![prepared.snapshot.root.display().to_string()],
        goal_id: "goal.m2.medium".to_owned(),
        goal_statement:
            "Rename the Settings button from Save to Apply and update the focused test expectation."
                .to_owned(),
        goal_invariants: vec![
            "Preserve submit behavior and keep the focused test aligned.".to_owned(),
        ],
        goal_non_goals: vec!["Do not redesign the Settings form or broaden scope.".to_owned()],
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
        tools: vec![write_tool, read_tool],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scope_and_literal.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: prepared.packet.clone(),
        m3: None,
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("construct medium validator: {error}"));
    let compiler = PlanCompiler::new(&planner_backend, &validator, "m2-medium-eval-compiler-v1")
        .unwrap_or_else(|error| panic!("construct medium compiler: {error}"));
    let mut compiler_budget = ModelCallBudget::new(1, 1_000);
    let compilation = compiler
        .compile(&input, &mut compiler_budget)
        .unwrap_or_else(|error| panic!("compile medium D2 goal: {error}"));
    assert!(validator.validate(compilation.plan()).is_empty());
    assert_eq!(compilation.plan().as_value()["depth"]["mode"], json!("D2"));
    let tasks = compilation.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("compiled medium tasks missing"));
    assert_eq!(tasks.len(), 2);
    let upstream = tasks[0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("upstream task id missing"))
        .to_owned();
    let downstream = tasks[1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("downstream task id missing"))
        .to_owned();
    let evidence_requirement = tasks[0]["evidence_requirements"][0]["requirement_id"]
        .as_str()
        .unwrap_or_else(|| panic!("medium upstream evidence requirement missing"))
        .to_owned();
    assert_eq!(tasks[1]["dependencies"][0], json!(upstream));
    planner_backend
        .unload()
        .unwrap_or_else(|error| panic!("unload medium planner backend: {error}"));

    let state = StateStore::open(fixture.base.join("medium-state.sqlite3"))
        .unwrap_or_else(|error| panic!("open medium Controller state: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join("medium-cas"))
        .unwrap_or_else(|error| panic!("open medium artifact store: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedPressureProbe(green_snapshot(20_000))));
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate medium plan: {error}"));
    assert_eq!(
        activation.task_ids,
        vec![upstream.clone(), downstream.clone()]
    );

    let source_context = routed_attempt_context(
        &fixture,
        &prepared,
        "src/settings/SettingsForm.tsx",
        "Change the Settings button label from Save to Apply after exact evidence is satisfied.",
        "medium-source",
    );
    controller
        .record_exact_evidence_satisfaction(
            &prepared.registry,
            &upstream,
            &evidence_requirement,
            &source_context.packet,
            std::slice::from_ref(&source_context.evidence_id),
        )
        .unwrap_or_else(|error| panic!("satisfy medium upstream exact evidence: {error}"));
    let upstream_ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &upstream,
            ReadinessInputs::permissive_m1("sha256:m2-medium-resource-admission"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive medium upstream readiness: {error}"));

    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin medium python: {error}"));
    let toolchain_root = python
        .path
        .parent()
        .unwrap_or_else(|| panic!("medium python executable must have parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([python], [toolchain_root])
        .unwrap_or_else(|error| panic!("medium command policy: {error}"));
    let isolation_backend = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect medium macOS Seatbelt: {error}"));
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME must be set"), PathBuf::from);
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
    let tool_manifest = write_tool_manifest();

    let upstream_proposal = replace_proposal(
        &source_context.evidence_id,
        "src/settings/SettingsForm.tsx",
        &source_context.source_digest,
        "Save",
        "Apply",
    );
    let upstream_backend = execution_backend(
        upstream_proposal.clone(),
        source_context.packet.metrics.final_serialized_input_tokens,
    );
    let _upstream_model_lease = upstream_backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load upstream execution backend: {error}"));
    let upstream_runtime = ExecutionRuntime {
        registry: &prepared.registry,
        backend: &upstream_backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &isolation_request,
        artifacts: &artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut upstream_budget = ModelCallBudget::new(2, 30_000);
    let upstream_success = controller
        .execute_replace(
            upstream_ready,
            &upstream_runtime,
            &source_context.packet,
            &mut upstream_budget,
        )
        .unwrap_or_else(|error| panic!("execute medium upstream edit: {error}"));
    upstream_backend
        .unload()
        .unwrap_or_else(|error| panic!("unload upstream execution backend: {error}"));
    assert_eq!(controller.task_state(&upstream), Some(TaskState::Succeeded));
    assert!(upstream_success.verification.passed);

    let test_context = routed_attempt_context(
        &fixture,
        &prepared,
        "src/settings/SettingsForm.test.tsx",
        "Update the focused Settings test expectation from Save to Apply after the verified source edit.",
        "medium-test",
    );
    let downstream_ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &downstream,
            ReadinessInputs::permissive_m1("sha256:m2-medium-resource-admission"),
            &tool_manifest,
        )
        .unwrap_or_else(|error| panic!("derive medium downstream readiness: {error}"));
    let downstream_proposal = replace_proposal(
        &test_context.evidence_id,
        "src/settings/SettingsForm.test.tsx",
        &test_context.source_digest,
        "Save",
        "Apply",
    );
    let downstream_backend = execution_backend(
        downstream_proposal.clone(),
        test_context.packet.metrics.final_serialized_input_tokens,
    );
    let _downstream_model_lease = downstream_backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load downstream execution backend: {error}"));
    let downstream_runtime = ExecutionRuntime {
        registry: &prepared.registry,
        backend: &downstream_backend,
        command_policy: &command_policy,
        isolation_backend: &isolation_backend,
        isolation_request: &isolation_request,
        artifacts: &artifacts,
        tool_manifest: &tool_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut downstream_budget = ModelCallBudget::new(2, 30_000);
    let downstream_success = controller
        .execute_replace(
            downstream_ready,
            &downstream_runtime,
            &test_context.packet,
            &mut downstream_budget,
        )
        .unwrap_or_else(|error| panic!("execute medium downstream edit: {error}"));
    downstream_backend
        .unload()
        .unwrap_or_else(|error| panic!("unload downstream execution backend: {error}"));
    assert_eq!(
        controller.task_state(&downstream),
        Some(TaskState::Succeeded)
    );
    assert!(downstream_success.verification.passed);

    let final_source = fs::read_to_string(fixture.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read medium final source: {error}"));
    let final_test = fs::read_to_string(fixture.root.join("src/settings/SettingsForm.test.tsx"))
        .unwrap_or_else(|error| panic!("read medium final test: {error}"));
    assert!(final_source.contains(">Apply</button>"));
    assert!(final_test.contains("name: \"Apply\""));
    let diff = ExactRetriever::new(&prepared.registry)
        .current_diff("repo.app")
        .unwrap_or_else(|error| panic!("read medium final diff: {error}"));
    assert!(diff.content.contains("SettingsForm.tsx"));
    assert!(diff.content.contains("SettingsForm.test.tsx"));

    let telemetry = ContextTelemetry::default();
    let upstream_metrics = telemetry.measure(
        &source_context.packet,
        &source_context.trace,
        &ProviderTokenUsage {
            input_tokens: Some(u64::from(
                source_context.packet.metrics.final_serialized_input_tokens,
            )),
            output_tokens: Some(128),
            tokenizer_id: Some("deterministic-fake-provider-v1".to_owned()),
        },
        &telemetry_outcome(
            upstream_proposal,
            &source_context.evidence_id,
            &upstream_success.verification.evidence_ids,
        ),
    );
    let downstream_metrics = telemetry.measure(
        &test_context.packet,
        &test_context.trace,
        &ProviderTokenUsage {
            input_tokens: Some(u64::from(
                test_context.packet.metrics.final_serialized_input_tokens,
            )),
            output_tokens: Some(128),
            tokenizer_id: Some("deterministic-fake-provider-v1".to_owned()),
        },
        &telemetry_outcome(
            downstream_proposal,
            &test_context.evidence_id,
            &downstream_success.verification.evidence_ids,
        ),
    );

    for metrics in [&upstream_metrics, &downstream_metrics] {
        assert!(metrics.verified_success);
        assert!(metrics.total_model_tokens > 0);
        assert!(metrics.injected_evidence_tokens > 0);
        assert_eq!(metrics.retrieval_attempts, 1);
        let exact = metrics
            .routes
            .get(&RetrievalRouteKind::Exact)
            .unwrap_or_else(|| panic!("exact route metrics missing"));
        assert_eq!(exact.attempts, 1);
        assert_eq!(exact.selected, 1);
        assert!(exact.injected_tokens > 0);
        assert_eq!(exact.useful_selected, 1);
        assert_eq!(metrics.semantic_escalation_rate.numerator, 0);
        assert_eq!(metrics.semantic_escalation_rate.denominator, 1);
        assert_eq!(metrics.semantic_incremental_hit_rate.denominator, 0);
        assert_eq!(
            metrics
                .routes
                .get(&RetrievalRouteKind::Semantic)
                .map(|route| route.attempts),
            Some(0)
        );
    }

    let report = aggregate_context_metrics(&[
        EvaluationAttemptRecord {
            task_id: upstream,
            depth: "D2".to_owned(),
            role: "role.implementer".to_owned(),
            attempt_id: upstream_success.attempt_id,
            attempt_index: 0,
            metrics: upstream_metrics,
        },
        EvaluationAttemptRecord {
            task_id: downstream,
            depth: "D2".to_owned(),
            role: "role.implementer".to_owned(),
            attempt_id: downstream_success.attempt_id,
            attempt_index: 0,
            metrics: downstream_metrics,
        },
    ]);
    assert_eq!(report.schema, "sovereign-context-token-report-v1");
    assert_eq!(report.groups.len(), 2);
    for group in &report.groups {
        assert_eq!(group.key.depth, "D2");
        assert_eq!(group.succeeded_tasks, 1);
        assert_eq!(group.accepted_change_sets, 1);
        assert!(group.total_model_tokens > 0);
        assert_eq!(group.first_pass_verification_rate.numerator, 1);
        assert_eq!(group.semantic_escalation_rate.numerator, 0);
        assert_eq!(group.semantic_escalation_rate.denominator, 1);
        assert_eq!(group.semantic_incremental_hit_rate.denominator, 0);
        let exact = group
            .routes
            .get(&RetrievalRouteKind::Exact)
            .unwrap_or_else(|| panic!("aggregated exact route metrics missing"));
        assert_eq!(exact.attempts, 1);
        assert!(exact.injected_tokens > 0);
        assert_eq!(exact.useful_selected, 1);
    }
}
