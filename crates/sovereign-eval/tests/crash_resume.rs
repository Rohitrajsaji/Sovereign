#![cfg(target_os = "macos")]

use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    Controller, ExecutionRuntime, ReadinessInputs, RecoveryManager, ResourcePressureProbe, RoleId,
    RoleRegistry, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository, PlanCompiler,
    PlanIr, PlanRevisionDiff, PlanValidator, ReplanScope, ValidationEnvironment,
};
use sovereign_policy::{
    CommandMode, CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend,
    IsolatedCommand, IsolationCapabilities, IsolationRequest, M6ResourceGovernor,
    MacSandboxExecBackend, ModelCallBudget, OsMemoryPressure, PinnedExecutable, PolicyError,
    RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION, ReconciliationPolicy, ResourcePressureSnapshotV1,
    ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::{
    ActionTransition, NewActionRecord, NewJournalEvent, StateRecordUpdate, StateStore,
};
use sovereign_tools::{PermissionClass, ToolManifest, process_group_leader_identity};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SETTINGS_FORM: &[u8] = include_bytes!("fixtures/scenario1/src/settings/SettingsForm.tsx");
const SETTINGS_FORM_TEST: &[u8] =
    include_bytes!("fixtures/scenario1/src/settings/SettingsForm.test.tsx");
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const CHILD_CASE: &str = "SOVEREIGN_CRASH_CHILD_CASE";
const CHILD_BASE: &str = "SOVEREIGN_CRASH_CHILD_BASE";
const CHILD_ROOT: &str = "SOVEREIGN_CRASH_CHILD_ROOT";
const CHILD_MARKER: &str = "SOVEREIGN_CRASH_CHILD_MARKER";
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct FixedResourcePressureProbe(ResourcePressureSnapshotV1);

impl ResourcePressureProbe for FixedResourcePressureProbe {
    fn sample(&mut self) -> io::Result<ResourcePressureSnapshotV1> {
        Ok(self.0)
    }
}

fn green_pressure_snapshot(observed_at_ms: i64) -> ResourcePressureSnapshotV1 {
    ResourcePressureSnapshotV1 {
        schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
        observed_at_ms,
        controlled_working_set_mib: 512,
        host_headroom_mib: 6_144,
        swap_used_mib: Some(4_096),
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
            || panic!("HOME must be set for macOS recovery tests"),
            PathBuf::from,
        );
        let base = home.join(format!(
            ".sovereign-eval-t08-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        let settings = root.join("src/settings");
        fs::create_dir_all(&settings)
            .unwrap_or_else(|error| panic!("create crash fixture: {error}"));
        fs::write(settings.join("SettingsForm.tsx"), SETTINGS_FORM)
            .unwrap_or_else(|error| panic!("write SettingsForm: {error}"));
        fs::write(settings.join("SettingsForm.test.tsx"), SETTINGS_FORM_TEST)
            .unwrap_or_else(|error| panic!("write SettingsForm test: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &["config", "user.email", "sovereign-recovery@example.invalid"],
        );
        git(&root, &["config", "user.name", "Sovereign Recovery"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "recovery baseline"]);
        Self { base, root }
    }

    fn state_path(&self) -> PathBuf {
        self.base.join("state.sqlite3")
    }

    fn marker(&self) -> PathBuf {
        self.base.join("crash.marker")
    }

    fn stdout_log(&self) -> PathBuf {
        self.base.join("crash-child.stdout.log")
    }

    fn stderr_log(&self) -> PathBuf {
        self.base.join("crash-child.stderr.log")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn sole_persisted_repository_baseline(value: &Value) -> &Value {
    let repositories = value["repositories"]
        .as_object()
        .unwrap_or_else(|| panic!("repository baseline set missing repositories"));
    assert_eq!(
        repositories.len(),
        1,
        "crash-resume fixture expects exactly one repository baseline"
    );
    repositories
        .values()
        .next()
        .unwrap_or_else(|| panic!("repository baseline set unexpectedly empty"))
}

fn sole_persisted_repository_baseline_mut(value: &mut Value) -> &mut Value {
    let repositories = value["repositories"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("repository baseline set missing repositories"));
    assert_eq!(
        repositories.len(),
        1,
        "crash-resume fixture expects exactly one repository baseline"
    );
    repositories
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("repository baseline set unexpectedly empty"))
}

struct Prepared {
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

fn registry_for(root: &Path) -> ProjectRegistry {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", root)
        .unwrap_or_else(|error| panic!("register repository: {error}"));
    registry
}

fn prepare(root: &Path) -> Prepared {
    let registry = registry_for(root);
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    let retriever = ExactRetriever::new(&registry);
    let form = retriever
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read form: {error}"));
    let focused_test = retriever
        .read_path(
            "repo.app",
            Path::new("src/settings/SettingsForm.test.tsx"),
            None,
        )
        .unwrap_or_else(|error| panic!("read focused test: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns durable recovery authority.".to_owned(),
                task_contract: "Rename Save to Apply only.".to_owned(),
                current_state: format!("dirty_digest={}", snapshot.dirty_digest),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![
                    EvidenceItem::from_exact_file(&form, "exact form"),
                    EvidenceItem::from_exact_file(&focused_test, "focused test"),
                ],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context packet: {error}"));
    Prepared {
        registry,
        packet,
        snapshot,
        form_digest: form.digest,
    }
}

fn response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "recovery.fixture".to_owned(),
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

fn fake_backend(prepared: &Prepared, with_execution: bool) -> DeterministicFakeBackend {
    let plan = json!({
        "tasks": [{
            "title": "Rename Settings submit label",
            "objective": "Change the rendered Settings submit label from Save to Apply without altering submit behavior.",
            "rationale": "Exact current source identifies one bounded edit.",
            "files": ["src/settings/SettingsForm.tsx"],
            "symbols": ["SettingsForm"],
            "evidence_queries": [],
            "expected_change": "SettingsForm renders Apply instead of Save."
        }]
    });
    let execution = json!({
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
    let mut responses = vec![response(
        plan.to_string(),
        prepared.packet.metrics.final_serialized_input_tokens,
    )];
    if with_execution {
        responses.push(response(
            execution.to_string(),
            prepared.packet.metrics.final_serialized_input_tokens,
        ));
    }
    let backend = DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-recovery-model".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        responses,
    )
    .unwrap_or_else(|error| panic!("fake backend: {error}"));
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load fake backend: {error}"));
    backend
}

fn compile_and_activate(
    base: &Path,
    prepared: &Prepared,
    backend: &DeterministicFakeBackend,
) -> (Controller, String) {
    compile_and_activate_with_policy(base, prepared, backend, global_policy())
}

fn compile_and_activate_with_policy(
    base: &Path,
    prepared: &Prepared,
    backend: &DeterministicFakeBackend,
    policy: Value,
) -> (Controller, String) {
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.t08.crash".to_owned(),
        compiled_at: "2026-09-12T20:00:00Z".to_owned(),
        project_id: "project.t08".to_owned(),
        project_name: "T08 crash fixture".to_owned(),
        workspace_roots: vec![prepared.snapshot.root.display().to_string()],
        goal_id: "goal.t08".to_owned(),
        goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
        goal_invariants: vec!["Preserve submit behavior.".to_owned()],
        goal_non_goals: vec!["No redesign.".to_owned()],
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
        role: canonical_implementer_role(),
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
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let compiler = PlanCompiler::new(backend, &validator, "m1-t08-crash-compiler")
        .unwrap_or_else(|error| panic!("compiler: {error}"));
    let mut budget = ModelCallBudget::new(1, 1_000);
    let compilation = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile T08 goal: {error:?} ({error})"));
    let state = StateStore::open(base.join("state.sqlite3"))
        .unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let activation = controller
        .activate(compilation, &prepared.registry)
        .unwrap_or_else(|error| panic!("activate: {error}"));
    (controller, activation.task_ids[0].clone())
}

fn canonical_value_digest(value: &Value) -> String {
    PlanIr::from_value(value.clone())
        .canonical_digest()
        .unwrap_or_else(|error| panic!("canonical digest: {error}"))
}

fn raw_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn active_plan_scope(state: &StateStore) -> (String, u32) {
    let raw = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read active plan scope: {error}"))
        .unwrap_or_else(|| panic!("active plan scope missing"));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("active plan scope json: {error}"));
    let plan_id = value["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("active plan id missing"))
        .to_owned();
    let revision = value["revision"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| panic!("active plan revision missing"));
    (plan_id, revision)
}

fn resource_binding_key(namespace: &str, key: &str) -> String {
    format!("{namespace}:{key}")
}

fn scoped_resource_key(plan_id: &str, revision: u32, logical_key: &str) -> String {
    if revision == 1 {
        logical_key.to_owned()
    } else {
        format!("{plan_id}@r{revision}:{logical_key}")
    }
}

fn publish_resource_row_with_event(
    state: &mut StateStore,
    namespace: &str,
    key: &str,
    value_json: &str,
    event_kind: &str,
    entity_id: &str,
    payload: &Value,
) {
    let payload_json = payload.to_string();
    let sequence = state
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("resource event sequence: {error}"));
    let event_id = format!(
        "fixture.resource.{}",
        &raw_sha256(format!("{event_kind}\0{entity_id}\0{sequence}\0{payload_json}").as_bytes())
            [7..27]
    );
    state
        .put_state_records_with_events(
            &[StateRecordUpdate {
                namespace,
                key,
                value_json,
            }],
            &[NewJournalEvent {
                event_id: &event_id,
                entity_type: "controller",
                entity_id,
                event_kind,
                payload_json: &payload_json,
            }],
        )
        .unwrap_or_else(|error| panic!("publish resource row/event: {error}"));
}

fn exact_resource_event_payload(
    plan_id: &str,
    revision: u32,
    binding_key: &str,
    value_json: &str,
) -> Value {
    json!({
        "plan_id": plan_id,
        "plan_revision": revision,
        "post_image_digests": BTreeMap::from([(
            binding_key.to_owned(),
            raw_sha256(value_json.as_bytes()),
        )]),
    })
}

fn reserved_model_fixture(label: &str) -> (Fixture, String, i64) {
    let fixture = Fixture::create(label);
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (mut controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    let _lease = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-resource-recovery"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive resource recovery lease: {error}"));
    let epoch = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("resource recovery snapshot: {error}"))
        .execution_epoch;
    drop(controller);
    (fixture, task_id, epoch)
}

fn sole_resource_record(state: &StateStore, namespace: &str) -> (String, String) {
    let records = state
        .state_records(namespace)
        .unwrap_or_else(|error| panic!("read resource records {namespace}: {error}"));
    assert_eq!(records.len(), 1, "expected one resource row in {namespace}");
    let record = records
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("resource row disappeared from {namespace}"));
    (record.key, record.value_json)
}

fn build_heavy_resource_record(state: &StateStore) -> (String, Value) {
    state
        .state_records("controller.resource_lease")
        .unwrap_or_else(|error| panic!("read BUILD_HEAVY resource leases: {error}"))
        .into_iter()
        .find_map(|record| {
            let value: Value = serde_json::from_str(&record.value_json)
                .unwrap_or_else(|error| panic!("BUILD_HEAVY resource lease json: {error}"));
            (value["class"] == "BUILD_HEAVY").then_some((record.key, value))
        })
        .unwrap_or_else(|| panic!("BUILD_HEAVY resource lease row missing"))
}

fn latest_checkpoint_goal_budget(state: &StateStore) -> (Value, String) {
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
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .unwrap_or_else(|error| panic!("read checkpoint manifest: {error}"));
    let manifest: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("decode checkpoint manifest: {error}"));
    let budget = manifest["goal_autonomy_budget"].clone();
    assert!(!budget.is_null(), "checkpoint goal autonomy budget missing");
    let digest = manifest["goal_autonomy_budget_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("checkpoint goal autonomy budget digest missing"))
        .to_owned();
    (budget, digest)
}

#[allow(clippy::too_many_lines)]
fn install_uncheckpointed_supersession(
    state: &mut StateStore,
    task_id: &str,
    tamper_task_runtime_digest: bool,
) -> String {
    let active_raw = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read active plan: {error}"))
        .unwrap_or_else(|| panic!("active plan record missing"));
    let active: Value =
        serde_json::from_str(&active_raw).unwrap_or_else(|error| panic!("active json: {error}"));
    let plan_id = active["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("active plan id"))
        .to_owned();
    let goal_id = active["goal_id"]
        .as_str()
        .unwrap_or_else(|| panic!("active goal id"))
        .to_owned();
    let previous_digest = active["plan_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("active plan digest"))
        .to_owned();
    let previous_document_raw = state
        .get_state("controller.plan_document", "active")
        .unwrap_or_else(|error| panic!("read active plan document: {error}"))
        .unwrap_or_else(|| panic!("active plan document missing"));
    let previous_document: Value = serde_json::from_str(&previous_document_raw)
        .unwrap_or_else(|error| panic!("previous plan json: {error}"));
    let mut next_document = previous_document.clone();
    next_document["revision"] = json!(2);
    next_document["supersedes_revision"] = json!(1);
    next_document["tasks"][0]["title"] = json!("Replanned Settings submit label");
    let next_digest = canonical_value_digest(&next_document);
    let diff = PlanRevisionDiff::between(
        &previous_document,
        &next_document,
        ReplanScope::Task,
        &["ASSUME.fixture-invalidated".to_owned()],
        &[task_id.to_owned()],
    )
    .unwrap_or_else(|error| panic!("revision diff: {error}"));
    let diff_json =
        serde_json::to_string(&diff).unwrap_or_else(|error| panic!("diff json: {error}"));
    let diff_digest = raw_sha256(diff_json.as_bytes());

    let task = next_document["tasks"][0].clone();
    let task_contract_digest = canonical_value_digest(&task);
    let previous_task_runtime_raw = state
        .get_state("controller.task", task_id)
        .unwrap_or_else(|error| panic!("read revision N task runtime: {error}"))
        .unwrap_or_else(|| panic!("revision N task runtime missing"));
    let previous_task_runtime: Value = serde_json::from_str(&previous_task_runtime_raw)
        .unwrap_or_else(|error| panic!("revision N task runtime json: {error}"));
    let autonomy_budget = previous_task_runtime["autonomy_budget"].clone();
    assert!(
        !autonomy_budget.is_null(),
        "revision N task autonomy budget missing"
    );
    let task_runtime = json!({
        "state": "planned",
        "attempts_started": 0,
        "model_calls_used": 0,
        "failure_counts": {},
        "retry_exhausted": false,
        "resource_deferrals_used": 0,
        "resource_retry_exhausted": false,
        "resource_deferred_from": Value::Null,
        "task_contract_digest": task_contract_digest,
        "autonomy_budget": autonomy_budget,
        "task": task
    });
    let task_runtime_values = BTreeMap::from([(task_id.to_owned(), task_runtime.clone())]);
    let task_runtime_map_digest = if tamper_task_runtime_digest {
        format!("sha256:{}", "f".repeat(64))
    } else {
        canonical_value_digest(
            &serde_json::to_value(&task_runtime_values)
                .unwrap_or_else(|error| panic!("task runtime map: {error}")),
        )
    };
    let attempt_runtime_map_digest = canonical_value_digest(&json!({}));
    let prior_grant_raw = state
        .get_state("controller.task_capability_grant", task_id)
        .unwrap_or_else(|error| panic!("read revision N task capability grant: {error}"))
        .unwrap_or_else(|| panic!("revision N task capability grant missing"));
    let mut next_grant: Value = serde_json::from_str(&prior_grant_raw)
        .unwrap_or_else(|error| panic!("revision N task capability grant json: {error}"));
    next_grant["plan_revision"] = json!(2);
    next_grant["task_contract_digest"] = Value::String(task_contract_digest.clone());
    let task_capability_grant_values = BTreeMap::from([(task_id.to_owned(), next_grant.clone())]);
    let task_capability_grant_map_digest = canonical_value_digest(
        &serde_json::to_value(&task_capability_grant_values)
            .unwrap_or_else(|error| panic!("task capability grant map: {error}")),
    );
    let carry_record_digests = BTreeMap::<String, String>::new();
    let carry_proof_digest = canonical_value_digest(
        &serde_json::to_value(&carry_record_digests)
            .unwrap_or_else(|error| panic!("carry digest map: {error}")),
    );
    let compilation_evidence = json!({
        "schema": "fixture-post-checkpoint-supersession",
        "plan_digest": next_digest,
        "validator_passed": true
    });
    let compilation_evidence_digest = canonical_value_digest(&compilation_evidence);
    let (goal_autonomy_budget, goal_autonomy_budget_digest) = latest_checkpoint_goal_budget(state);
    let baseline_raw = state
        .get_state("controller.repository_baseline", "active")
        .unwrap_or_else(|error| panic!("read baseline: {error}"))
        .unwrap_or_else(|| panic!("baseline missing"));
    let baseline_set: Value = serde_json::from_str(&baseline_raw)
        .unwrap_or_else(|error| panic!("baseline json: {error}"));
    let baseline = sole_persisted_repository_baseline(&baseline_set);
    let baseline_snapshot: RepositorySnapshot =
        serde_json::from_value(baseline["snapshot"].clone())
            .unwrap_or_else(|error| panic!("baseline snapshot json: {error}"));
    let repository_snapshot_digest = raw_sha256(
        baseline_snapshot
            .manifest_json()
            .unwrap_or_else(|error| panic!("baseline snapshot manifest: {error}"))
            .as_bytes(),
    );
    let baseline_diff_digest = baseline["diff_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("baseline diff digest"))
        .to_owned();
    let epoch = state
        .advance_execution_epoch()
        .unwrap_or_else(|error| panic!("advance epoch: {error}"));
    let revision_key = format!("{plan_id}@r2");
    let active_plan_json = json!({
        "plan_id": plan_id,
        "goal_id": goal_id,
        "revision": 2,
        "plan_digest": next_digest,
        "compilation_evidence_digest": compilation_evidence_digest,
        "validity": "current"
    })
    .to_string();
    let revision_record_json = json!({
        "plan_id": plan_id,
        "revision": 2,
        "plan_digest": next_digest,
        "compilation_evidence_digest": compilation_evidence_digest,
        "previous_plan_digest": previous_digest,
        "plan_document": next_document
    })
    .to_string();
    let prior_lifecycle = json!({
        "plan_id": plan_id,
        "revision": 1,
        "plan_digest": previous_digest,
        "status": "superseded",
        "superseded_by_revision": 2,
        "superseded_by_digest": next_digest
    })
    .to_string();
    let next_lifecycle = json!({
        "plan_id": plan_id,
        "revision": 2,
        "plan_digest": next_digest,
        "status": "active",
        "superseded_by_revision": Value::Null,
        "superseded_by_digest": Value::Null
    })
    .to_string();
    let task_key = format!("{plan_id}@r2:{task_id}");
    let task_grant_key = format!("{plan_id}@r2:{task_id}");
    let prior_revision_key = format!("{plan_id}@r1");
    let task_runtime_json = task_runtime.to_string();
    let task_grant_json = next_grant.to_string();
    let next_document_json = next_document.to_string();
    let compilation_json = compilation_evidence.to_string();
    let activation_payload = json!({
        "from_revision": 1,
        "to_revision": 2,
        "from_plan_digest": previous_digest,
        "to_plan_digest": next_digest,
        "plan_revision_diff_digest": diff_digest,
        "carry_proof_digest": carry_proof_digest,
        "task_runtime_map_digest": task_runtime_map_digest,
        "attempt_runtime_map_digest": attempt_runtime_map_digest,
        "task_capability_grant_map_digest": task_capability_grant_map_digest,
        "execution_epoch": epoch,
        "repository_snapshot_digest": repository_snapshot_digest,
        "baseline_diff_digest": baseline_diff_digest,
        "goal_autonomy_budget": goal_autonomy_budget,
        "goal_autonomy_budget_digest": goal_autonomy_budget_digest,
        "plan_validity": "current"
    });
    let activation_json = activation_payload.to_string();
    let event_id = format!(
        "fixture.supersession.{}",
        &raw_sha256(activation_json.as_bytes())[7..27]
    );
    let records = vec![
        ("controller.plan", "active", active_plan_json.as_str()),
        (
            "controller.plan_document",
            "active",
            next_document_json.as_str(),
        ),
        (
            "controller.plan_revision",
            revision_key.as_str(),
            revision_record_json.as_str(),
        ),
        (
            "controller.plan_revision_diff",
            revision_key.as_str(),
            diff_json.as_str(),
        ),
        (
            "controller.compilation_evidence",
            revision_key.as_str(),
            compilation_json.as_str(),
        ),
        (
            "controller.plan_revision_lifecycle",
            prior_revision_key.as_str(),
            prior_lifecycle.as_str(),
        ),
        (
            "controller.plan_revision_lifecycle",
            revision_key.as_str(),
            next_lifecycle.as_str(),
        ),
        (
            "controller.task",
            task_key.as_str(),
            task_runtime_json.as_str(),
        ),
        (
            "controller.task_capability_grant",
            task_grant_key.as_str(),
            task_grant_json.as_str(),
        ),
    ];
    let owned_records = records
        .iter()
        .map(|(namespace, key, value_json)| {
            (
                (*namespace).to_owned(),
                (*key).to_owned(),
                (*value_json).to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let updates = owned_records
        .iter()
        .map(|(namespace, key, value_json)| StateRecordUpdate {
            namespace,
            key,
            value_json,
        })
        .collect::<Vec<_>>();
    state
        .put_state_records_with_events(
            &updates,
            &[NewJournalEvent {
                event_id: &event_id,
                entity_type: "controller",
                entity_id: &plan_id,
                event_kind: "plan_revision_activated",
                payload_json: &activation_json,
            }],
        )
        .unwrap_or_else(|error| panic!("publish supersession: {error}"));
    next_digest
}

struct RuntimeParts {
    command_policy: CommandPolicy,
    isolation_request: IsolationRequest,
    artifacts: ArtifactStore,
    manifest: ToolManifest,
}

fn runtime_parts(base: &Path, root: &Path) -> RuntimeParts {
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin python: {error}"));
    let make = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
        .unwrap_or_else(|error| panic!("pin make: {error}"));
    let toolchain = python
        .path
        .parent()
        .unwrap_or_else(|| panic!("python parent"))
        .to_path_buf();
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME missing"), PathBuf::from);
    RuntimeParts {
        command_policy: CommandPolicy::new([python, make], [toolchain])
            .unwrap_or_else(|error| panic!("command policy: {error}")),
        isolation_request: IsolationRequest {
            repository_root: root.to_path_buf(),
            user_home_root: home,
            extra_protected_read_roots: Vec::new(),
            rust_toolchain: None,
            build_scratch_root: None,
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        },
        artifacts: ArtifactStore::open(base.join("cas"))
            .unwrap_or_else(|error| panic!("artifact store: {error}")),
        manifest: write_tool_manifest(),
    }
}

enum CrashIsolation {
    Normal(MacSandboxExecBackend),
    BlockBefore {
        inner: MacSandboxExecBackend,
        marker: PathBuf,
    },
    Ambiguous(MacSandboxExecBackend),
    Orphan(MacSandboxExecBackend),
    PendingSpawn(MacSandboxExecBackend),
}

impl ExecutionIsolationBackend for CrashIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        match self {
            Self::Normal(inner)
            | Self::BlockBefore { inner, .. }
            | Self::Ambiguous(inner)
            | Self::Orphan(inner)
            | Self::PendingSpawn(inner) => inner.capabilities(),
        }
    }

    fn isolate(
        &self,
        spec: &CommandSpec,
        request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        match self {
            Self::Normal(inner) => inner.isolate(spec, request),
            Self::BlockBefore { marker, .. } => {
                fs::write(marker, b"before_mutation")?;
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
            Self::Ambiguous(_) => Ok(IsolatedCommand {
                executable: PathBuf::from("/usr/bin/python3"),
                args: vec![
                    "-I".to_owned(),
                    "-c".to_owned(),
                    "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('ambiguous crash residue\\n'); time.sleep(60)".to_owned(),
                    request
                        .repository_root
                        .join("src/settings/SettingsForm.tsx")
                        .display()
                        .to_string(),
                ],
            }),
            Self::Orphan(_) => Ok(IsolatedCommand {
                executable: PathBuf::from("/bin/sleep"),
                args: vec!["60".to_owned()],
            }),
            Self::PendingSpawn(_) => Ok(IsolatedCommand {
                executable: PathBuf::from("/bin/sleep"),
                args: vec!["2".to_owned()],
            }),
        }
    }
}

fn run_child(case: &str, base: &Path, root: &Path, marker: &Path) {
    let prepared = prepare(root);
    if matches!(case, "build_pending_spawn" | "build_orphan_sleep") {
        run_build_heavy_child(case, base, root, &prepared);
        return;
    }
    let backend = fake_backend(&prepared, true);
    let (mut controller, task_id) = compile_and_activate(base, &prepared, &backend);
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-resource"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("child ready: {error}"));
    let parts = runtime_parts(base, root);
    let detected =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("detect Seatbelt: {error}"));
    let isolation = match case {
        "before_mutation" => CrashIsolation::BlockBefore {
            inner: detected,
            marker: marker.to_path_buf(),
        },
        "dispatch_ambiguous" => CrashIsolation::Ambiguous(detected),
        "orphan_sleep" => CrashIsolation::Orphan(detected),
        "pending_spawn" => CrashIsolation::PendingSpawn(detected),
        _ => CrashIsolation::Normal(detected),
    };
    let runtime = ExecutionRuntime {
        registry: &prepared.registry,
        backend: &backend,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(4, 30_000);
    let _ = controller.execute_replace(ready, &runtime, &prepared.packet, &mut budget);
}

fn run_build_heavy_child(case: &str, base: &Path, root: &Path, prepared: &Prepared) {
    let backend = fake_backend(prepared, false);
    let mut policy = global_policy();
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY"]);
    let (mut controller, task_id) =
        compile_and_activate_with_policy(base, prepared, &backend, policy);
    let model_lease = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-build-heavy-child"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive child MODEL lease: {error}"));
    let mut build_lease = controller
        .acquire_build_heavy(
            model_lease,
            &prepared.registry,
            &write_tool_manifest(),
            &backend,
        )
        .unwrap_or_else(|error| panic!("acquire child BUILD_HEAVY lease: {error}"));
    let parts = runtime_parts(base, root);
    let detected =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("detect Seatbelt: {error}"));
    let isolation = match case {
        "build_pending_spawn" => CrashIsolation::PendingSpawn(detected),
        "build_orphan_sleep" => CrashIsolation::Orphan(detected),
        _ => panic!("unsupported BUILD_HEAVY crash child case {case}"),
    };
    let command = CommandSpec {
        // BUILD_HEAVY commands must have a deterministic parallel-job adapter. CrashIsolation
        // replaces this command before spawn for the two crash windows below, but Controller
        // authorization still correctly binds/injects the make job cap before dispatch.
        executable: PathBuf::from("/usr/bin/make"),
        args: Vec::new(),
        working_directory: root.to_path_buf(),
        environment: BTreeMap::default(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::RepositoryMutation,
        // Stay within the governed 30-second single-tool-action ceiling. The crash fixtures kill
        // the child at a deterministic pre-timeout point, so a longer timeout is neither needed
        // nor legitimate authority.
        timeout_ms: 30_000,
        output_limit_bytes: 16 * 1_024,
        disk_write_limit_bytes: 16 * 1_024,
        subprocess_limit: build_lease.subprocess_cap(),
    };
    let _ = controller.execute_build_heavy(
        &mut build_lease,
        command,
        &parts.command_policy,
        &isolation,
        &parts.isolation_request,
        &parts.artifacts,
        &parts.manifest,
    );
}

#[test]
fn crash_worker_entry() {
    let Ok(case) = std::env::var(CHILD_CASE) else {
        return;
    };
    let base = PathBuf::from(
        std::env::var(CHILD_BASE).unwrap_or_else(|error| panic!("child base env: {error}")),
    );
    let root = PathBuf::from(
        std::env::var(CHILD_ROOT).unwrap_or_else(|error| panic!("child root env: {error}")),
    );
    let marker = PathBuf::from(
        std::env::var(CHILD_MARKER).unwrap_or_else(|error| panic!("child marker env: {error}")),
    );
    run_child(&case, &base, &root, &marker);
}

fn spawn_child(fixture: &Fixture, case: &str, pause_at: Option<&str>) -> Child {
    let current =
        std::env::current_exe().unwrap_or_else(|error| panic!("current test exe: {error}"));
    let mut command = Command::new(current);
    command
        .args(["--exact", "crash_worker_entry", "--nocapture"])
        .env(CHILD_CASE, case)
        .env(CHILD_BASE, &fixture.base)
        .env(CHILD_ROOT, &fixture.root)
        .env(CHILD_MARKER, fixture.marker())
        .env("RUST_BACKTRACE", "1")
        .stdout(Stdio::from(
            fs::File::create(fixture.stdout_log())
                .unwrap_or_else(|error| panic!("create crash child stdout log: {error}")),
        ))
        .stderr(Stdio::from(
            fs::File::create(fixture.stderr_log())
                .unwrap_or_else(|error| panic!("create crash child stderr log: {error}")),
        ));
    if let Some(point) = pause_at {
        command
            .env("SOVEREIGN_RECOVERY_TEST_PAUSE_AT", point)
            .env("SOVEREIGN_RECOVERY_TEST_MARKER", fixture.marker());
    }
    command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn crash child: {error}"))
}

fn kill_child(child: &mut Child) {
    child
        .kill()
        .unwrap_or_else(|error| panic!("SIGKILL child: {error}"));
    child
        .wait()
        .unwrap_or_else(|error| panic!("wait killed child: {error}"));
}

fn child_diagnostics(fixture: &Fixture, child: &mut Child) -> String {
    const MAX_LOG_BYTES: usize = 16 * 1024;
    let status = child
        .try_wait()
        .unwrap_or_else(|error| panic!("inspect crash child status: {error}"))
        .map_or_else(|| "still running".to_owned(), |status| status.to_string());
    let read_tail = |path: PathBuf| {
        let Ok(bytes) = fs::read(path) else {
            return "<log unavailable>".to_owned();
        };
        let start = bytes.len().saturating_sub(MAX_LOG_BYTES);
        String::from_utf8_lossy(&bytes[start..]).into_owned()
    };
    format!(
        "child status: {status}\nchild stdout (last {MAX_LOG_BYTES} bytes):\n{}\nchild stderr (last {MAX_LOG_BYTES} bytes):\n{}",
        read_tail(fixture.stdout_log()),
        read_tail(fixture.stderr_log())
    )
}

fn wait_for_marker(path: &Path, fixture: &Fixture, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect crash child before marker: {error}"))
        {
            panic!(
                "crash child exited before marker {}: {status}\n{}",
                path.display(),
                child_diagnostics(fixture, child)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for crash marker {}\n{}",
        path.display(),
        child_diagnostics(fixture, child)
    );
}

fn wait_for_source_contains(root: &Path, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if fs::read_to_string(root.join("src/settings/SettingsForm.tsx"))
            .is_ok_and(|content| content.contains(needle))
        {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for source to contain {needle:?}");
}

fn wait_for_action_state(
    path: &Path,
    expected: &str,
    fixture: &Fixture,
    child: &mut Child,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(state) = StateStore::open(path)
            && let Ok(records) = state.action_records()
            && let Some(record) = records.iter().find(|record| record.state == expected)
        {
            return record.action_id.clone();
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect crash child before action state: {error}"))
        {
            panic!(
                "crash child exited before action state {expected}: {status}\n{}",
                child_diagnostics(fixture, child)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for action state {expected}\n{}",
        child_diagnostics(fixture, child)
    );
}

fn wait_for_active_process_lease(path: &Path) -> (u32, String) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(state) = StateStore::open(path)
            && let Ok(records) = state.state_records("controller.process_lease")
        {
            for record in records {
                let value: Value = serde_json::from_str(&record.value_json)
                    .unwrap_or_else(|error| panic!("process lease json: {error}"));
                if value["state"] == "active"
                    && let (Some(pgid), Some(identity)) = (
                        value["process_group_id"].as_u64(),
                        value["leader_identity"].as_str(),
                    )
                {
                    return (
                        u32::try_from(pgid).unwrap_or_else(|_| panic!("pgid overflow")),
                        identity.to_owned(),
                    );
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for active process lease");
}

fn wait_for_pending_process_lease(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(state) = StateStore::open(path)
            && let Ok(records) = state.state_records("controller.process_lease")
        {
            for record in records {
                let value: Value = serde_json::from_str(&record.value_json)
                    .unwrap_or_else(|error| panic!("process lease json: {error}"));
                if value["state"] == "pending_spawn"
                    && value["process_group_id"].is_null()
                    && value["leader_identity"].is_null()
                {
                    return value["lease_id"]
                        .as_str()
                        .unwrap_or_else(|| panic!("pending lease id missing"))
                        .to_owned();
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for pending process lease");
}

fn first_task_id(state: &StateStore) -> String {
    state
        .state_records("controller.task")
        .unwrap_or_else(|error| panic!("task records: {error}"))
        .first()
        .map_or_else(
            || panic!("task record missing"),
            |record| {
                let value: Value = serde_json::from_str(&record.value_json)
                    .unwrap_or_else(|error| panic!("task runtime json: {error}"));
                value
                    .pointer("/task/task_id")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("task runtime lacks logical task id"))
                    .to_owned()
            },
        )
}

fn source(root: &Path) -> String {
    fs::read_to_string(root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"))
}

fn action_event_count(state: &StateStore, kind: &str) -> usize {
    state
        .journal()
        .unwrap_or_else(|error| panic!("journal: {error}"))
        .iter()
        .filter(|event| event.entity_type == "action" && event.event_kind == kind)
        .count()
}

fn recover(
    fixture: &Fixture,
) -> (
    Controller,
    sovereign_controller::RecoverySummary,
    ProjectRegistry,
) {
    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open state for recovery: {error}"));
    let (mut controller, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover controller: {error}"));
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(2_000),
    )));
    (controller, summary, registry)
}

fn normal_runtime<'a>(
    registry: &'a ProjectRegistry,
    backend: &'a DeterministicFakeBackend,
    parts: &'a RuntimeParts,
    isolation: &'a MacSandboxExecBackend,
) -> ExecutionRuntime<'a, MacSandboxExecBackend> {
    ExecutionRuntime {
        registry,
        backend,
        command_policy: &parts.command_policy,
        isolation_backend: isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    }
}

#[test]
fn kill_before_mutation_resumes_persisted_intent_without_model_replay() {
    let fixture = Fixture::create("before-mutation");
    let mut child = spawn_child(&fixture, "before_mutation", None);
    wait_for_marker(&fixture.marker(), &fixture, &mut child);
    let _old_action =
        wait_for_action_state(&fixture.state_path(), "authorized", &fixture, &mut child);
    kill_child(&mut child);
    assert!(source(&fixture.root).contains("Save"));

    let (mut controller, summary, registry) = recover(&fixture);
    assert!(!summary.mutation_blocked);
    assert_eq!(summary.pending_recovery_action_ids.len(), 1);
    let task_id = first_task_id(controller.state());
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let parts = runtime_parts(&fixture.base, &fixture.root);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("Seatbelt: {error}"));
    let runtime = normal_runtime(&registry, &backend, &parts, &isolation);
    controller
        .resume_recovered_replace(
            &summary.pending_recovery_action_ids[0],
            &runtime,
            ReadinessInputs::permissive_m1("sha256:t08-recovery-resource"),
        )
        .unwrap_or_else(|error| panic!("resume persisted action: {error}"));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn kill_after_atomic_initial_activation_commit_bootstraps_first_checkpoint() {
    let fixture = Fixture::create("initial-activation-bootstrap");
    let mut child = spawn_child(
        &fixture,
        "initial_activation_bootstrap",
        Some("after_initial_plan_activation_commit"),
    );
    wait_for_marker(&fixture.marker(), &fixture, &mut child);

    let pre_crash = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open initial activation state: {error}"));
    assert!(
        pre_crash
            .get_state("controller.plan", "active")
            .unwrap_or_else(|error| panic!("read initial active plan: {error}"))
            .is_some(),
        "atomic initial activation publication must be durable before the crash hook"
    );
    assert!(
        pre_crash
            .latest_checkpoint_integrity()
            .unwrap_or_else(|error| panic!("read pre-crash checkpoint: {error}"))
            .is_none(),
        "crash hook must fire before the first activation checkpoint"
    );
    assert!(
        pre_crash
            .action_records()
            .unwrap_or_else(|error| panic!("read pre-crash actions: {error}"))
            .is_empty(),
        "pristine initial activation must not publish action authority"
    );
    drop(pre_crash);
    kill_child(&mut child);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(!summary.mutation_blocked);
    assert!(summary.unknown_action_ids.is_empty());
    assert!(summary.pending_recovery_action_ids.is_empty());
    let task_id = first_task_id(controller.state());
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(0));
    let first_checkpoint = controller
        .state()
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("read bootstrapped checkpoint: {error}"))
        .unwrap_or_else(|| panic!("initial activation recovery did not seal a checkpoint"));
    let recovered_plan_digest = summary.plan_digest.clone();
    drop(controller);

    let (controller, second_summary, _registry) = recover(&fixture);
    assert_eq!(second_summary.plan_digest, recovered_plan_digest);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(0));
    let second_checkpoint = controller
        .state()
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("read second recovery checkpoint: {error}"))
        .unwrap_or_else(|| panic!("second recovery lost initial activation checkpoint"));
    assert!(second_checkpoint.generation >= first_checkpoint.generation);
}

#[test]
fn initial_activation_bootstrap_rejects_precheckpoint_side_effect_authority() {
    let fixture = Fixture::create("initial-activation-side-effect");
    let mut child = spawn_child(
        &fixture,
        "initial_activation_side_effect",
        Some("after_initial_plan_activation_commit"),
    );
    wait_for_marker(&fixture.marker(), &fixture, &mut child);
    kill_child(&mut child);

    let mut tampered = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open initial activation for tamper: {error}"));
    let task_key = tampered
        .state_records("controller.task")
        .unwrap_or_else(|error| panic!("read initial task record: {error}"))
        .first()
        .unwrap_or_else(|| panic!("initial task record missing"))
        .key
        .clone();
    tampered
        .put_state(
            "controller.failure_record",
            &task_key,
            &json!({"tampered": true}).to_string(),
        )
        .unwrap_or_else(|error| panic!("inject precheckpoint side-effect authority: {error}"));
    assert!(
        tampered
            .latest_checkpoint_integrity()
            .unwrap_or_else(|error| panic!("read checkpoint before failed bootstrap: {error}"))
            .is_none()
    );
    drop(tampered);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen tampered initial activation: {error}"));
    let error = RecoveryManager::recover(state, &registry)
        .err()
        .unwrap_or_else(|| panic!("bootstrap accepted precheckpoint side-effect authority"));
    assert!(
        error
            .to_string()
            .contains("side-effect authority before first checkpoint"),
        "unexpected bootstrap rejection: {error}"
    );
    let after = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen failed-bootstrap state: {error}"));
    assert!(
        after
            .latest_checkpoint_integrity()
            .unwrap_or_else(|error| panic!("read checkpoint after failed bootstrap: {error}"))
            .is_none(),
        "failed bootstrap must not publish a checkpoint"
    );
}

#[test]
fn tampered_persisted_intent_is_rejected_before_recovered_mutation() {
    let fixture = Fixture::create("tampered-intent");
    let mut child = spawn_child(&fixture, "before_mutation", None);
    wait_for_marker(&fixture.marker(), &fixture, &mut child);
    let action_id =
        wait_for_action_state(&fixture.state_path(), "authorized", &fixture, &mut child);
    kill_child(&mut child);

    let (mut controller, summary, registry) = recover(&fixture);
    assert_eq!(summary.pending_recovery_action_ids, vec![action_id.clone()]);
    let dispatched_before = action_event_count(controller.state(), "dispatched");
    let task_id = first_task_id(controller.state());

    let mut external_state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open state for intent tamper: {error}"));
    let raw = external_state
        .get_state("controller.action_intent", &action_id)
        .unwrap_or_else(|error| panic!("read action intent: {error}"))
        .unwrap_or_else(|| panic!("action intent missing"));
    let mut value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("intent json: {error}"));
    let mode = value["expected_target_mode"]
        .as_u64()
        .unwrap_or_else(|| panic!("expected target mode missing"));
    value["expected_target_mode"] = json!(mode + 1);
    external_state
        .put_state("controller.action_intent", &action_id, &value.to_string())
        .unwrap_or_else(|error| panic!("tamper action intent: {error}"));
    drop(external_state);

    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let parts = runtime_parts(&fixture.base, &fixture.root);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("Seatbelt: {error}"));
    let runtime = normal_runtime(&registry, &backend, &parts, &isolation);
    let Err(error) = controller.resume_recovered_replace(
        &action_id,
        &runtime,
        ReadinessInputs::permissive_m1("sha256:t08-recovery-resource"),
    ) else {
        panic!("tampered recovery intent must not execute");
    };
    assert!(
        error
            .to_string()
            .contains("differs from its trusted recovery checkpoint binding")
    );
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert!(source(&fixture.root).contains("Save"));
}

fn assert_verification_only_recovery(pause_at: &str, label: &str) {
    let fixture = Fixture::create(label);
    let mut child = spawn_child(&fixture, "normal", Some(pause_at));
    wait_for_marker(&fixture.marker(), &fixture, &mut child);
    let action_id =
        wait_for_action_state(&fixture.state_path(), "committed", &fixture, &mut child);
    kill_child(&mut child);
    assert!(source(&fixture.root).contains("Apply"));
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before recovery: {error}"));
    let dispatched_before = action_event_count(&before, "dispatched");
    let committed_before = action_event_count(&before, "committed");
    drop(before);

    let (controller, summary, _registry) = recover(&fixture);
    let task_id = first_task_id(controller.state());
    assert!(!summary.mutation_blocked);
    assert!(summary.pending_recovery_action_ids.is_empty());
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert_eq!(
        action_event_count(controller.state(), "committed"),
        committed_before
    );
    let action = controller
        .state()
        .action_record(&action_id)
        .unwrap_or_else(|error| panic!("action after recovery: {error}"))
        .unwrap_or_else(|| panic!("committed action disappeared"));
    assert_eq!(action.state, "committed");
    assert!(action.result_digest.is_some());
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn kill_after_local_edit_recovers_by_deterministic_verification_only() {
    assert_verification_only_recovery("after_mutation_checkpoint", "after-edit");
}

#[test]
fn kill_during_verification_recovers_by_deterministic_verification_only() {
    assert_verification_only_recovery("verification_started", "during-verification");
}

#[test]
fn kill_after_dispatch_before_observed_blocks_ambiguous_effect_without_replay() {
    let fixture = Fixture::create("dispatch-unknown");
    let mut child = spawn_child(&fixture, "dispatch_ambiguous", None);
    let action_id =
        wait_for_action_state(&fixture.state_path(), "dispatched", &fixture, &mut child);
    let _lease = wait_for_active_process_lease(&fixture.state_path());
    wait_for_source_contains(&fixture.root, "ambiguous crash residue");
    kill_child(&mut child);
    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.mutation_blocked);
    assert_eq!(summary.unknown_action_ids, vec![action_id.clone()]);
    let task_id = first_task_id(controller.state());
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::ReconcilingUnknown)
    );
    assert_eq!(action_event_count(controller.state(), "dispatched"), 1);
    assert_eq!(action_event_count(controller.state(), "committed"), 0);
    assert!(source(&fixture.root).contains("ambiguous crash residue"));
}

#[test]
fn orphan_process_group_is_reaped_before_recovery_continues() {
    let fixture = Fixture::create("orphan-reap");
    let mut child = spawn_child(&fixture, "orphan_sleep", None);
    let _action_id =
        wait_for_action_state(&fixture.state_path(), "dispatched", &fixture, &mut child);
    let (pgid, identity) = wait_for_active_process_lease(&fixture.state_path());
    assert_eq!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe child identity: {error}"))
            .as_deref(),
        Some(identity.as_str())
    );
    kill_child(&mut child);
    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.unresolved_process_lease_ids.is_empty());
    assert!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe reaped group: {error}"))
            .is_none()
    );
    let leases = controller
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("process leases: {error}"));
    assert!(
        leases
            .iter()
            .any(|record| record.value_json.contains("reaped_recovery"))
    );
}

#[test]
fn kill_after_spawn_before_identity_lease_stays_recovery_blocked() {
    let fixture = Fixture::create("pending-spawn");
    let mut child = spawn_child(
        &fixture,
        "pending_spawn",
        Some("after_process_spawn_before_identity_lease"),
    );
    wait_for_marker(&fixture.marker(), &fixture, &mut child);
    let action_id =
        wait_for_action_state(&fixture.state_path(), "dispatched", &fixture, &mut child);
    let pending_lease_id = wait_for_pending_process_lease(&fixture.state_path());
    kill_child(&mut child);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.mutation_blocked);
    assert!(
        summary
            .unresolved_process_lease_ids
            .contains(&pending_lease_id)
    );
    assert_eq!(summary.unknown_action_ids, vec![action_id]);
    let task_id = first_task_id(controller.state());
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::ReconcilingUnknown)
    );
    assert_eq!(action_event_count(controller.state(), "dispatched"), 1);
    assert_eq!(action_event_count(controller.state(), "committed"), 0);
    thread::sleep(Duration::from_millis(2_100));
}

fn run_to_success(fixture: &Fixture) -> String {
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, true);
    let (mut controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    let ready = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-resource"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let parts = runtime_parts(&fixture.base, &fixture.root);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("Seatbelt: {error}"));
    let runtime = normal_runtime(&prepared.registry, &backend, &parts, &isolation);
    let mut budget = ModelCallBudget::new(4, 30_000);
    controller
        .execute_replace(ready, &runtime, &prepared.packet, &mut budget)
        .unwrap_or_else(|error| panic!("normal success: {error}"));
    task_id
}

#[test]
fn corrupt_latest_checkpoint_falls_back_and_committed_edit_is_never_replayed() {
    let fixture = Fixture::create("checkpoint-fallback");
    let task_id = run_to_success(&fixture);
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before corruption: {error}"));
    let dispatched_before = action_event_count(&before, "dispatched");
    let committed_before = action_event_count(&before, "committed");
    let corrupt_generation = before
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest checkpoint: {error}"))
        .unwrap_or_else(|| panic!("checkpoint missing"))
        .generation;
    drop(before);
    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=(SELECT MAX(generation) FROM checkpoint_integrity);\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("simulate immutable checkpoint disk corruption: {error}"));
    drop(connection);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.fallback_checkpoint_used);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert_eq!(
        action_event_count(controller.state(), "committed"),
        committed_before
    );
    assert!(source(&fixture.root).contains("Apply"));
    let newest = controller
        .state()
        .latest_valid_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest valid recovery checkpoint: {error}"))
        .unwrap_or_else(|| panic!("recovery checkpoint missing"));
    assert!(newest.generation > corrupt_generation);
    assert_eq!(
        newest.action_sequence,
        controller
            .state()
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal tail: {error}"))
    );
}

#[test]
fn missing_latest_manifest_cas_reanchors_to_older_trusted_checkpoint() {
    let fixture = Fixture::create("checkpoint-cas-missing");
    let task_id = run_to_success(&fixture);
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before CAS loss: {error}"));
    let dispatched_before = action_event_count(&before, "dispatched");
    let committed_before = action_event_count(&before, "committed");
    let latest = before
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest checkpoint: {error}"))
        .unwrap_or_else(|| panic!("checkpoint missing"));
    drop(before);
    let cas_path = fixture
        .state_path()
        .parent()
        .unwrap_or_else(|| panic!("state database parent missing"))
        .join("checkpoint-cas")
        .join("sha256")
        .join(&latest.payload_digest[..2])
        .join(&latest.payload_digest);
    fs::remove_file(&cas_path)
        .unwrap_or_else(|error| panic!("remove latest checkpoint manifest CAS: {error}"));

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.fallback_checkpoint_used);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
    assert_eq!(
        action_event_count(controller.state(), "committed"),
        committed_before
    );
    let reanchored = controller
        .state()
        .latest_valid_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest valid re-anchor: {error}"))
        .unwrap_or_else(|| panic!("re-anchor checkpoint missing"));
    assert!(reanchored.generation > latest.generation);
    drop(controller);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(!summary.fallback_checkpoint_used);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(
        action_event_count(controller.state(), "dispatched"),
        dispatched_before
    );
}

#[test]
fn corrupt_tail_then_missing_reanchor_manifest_falls_back_only_on_trusted_ancestry() {
    let fixture = Fixture::create("checkpoint-ancestry");
    let task_id = run_to_success(&fixture);
    let before = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before combined corruption: {error}"));
    let corrupt = before
        .latest_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest checkpoint: {error}"))
        .unwrap_or_else(|| panic!("checkpoint missing"));
    drop(before);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for checkpoint corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=(SELECT MAX(generation) FROM checkpoint_integrity);\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("simulate corrupt immutable checkpoint tail: {error}"));
    drop(connection);

    let (controller, first_summary, _registry) = recover(&fixture);
    assert!(first_summary.fallback_checkpoint_used);
    assert!(first_summary.checkpoint_generation < corrupt.generation);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    let reanchor = controller
        .state()
        .latest_valid_checkpoint_integrity()
        .unwrap_or_else(|error| panic!("latest recovery re-anchor: {error}"))
        .unwrap_or_else(|| panic!("re-anchor missing"));
    assert!(reanchor.generation > corrupt.generation);
    drop(controller);

    let reanchor_cas = fixture
        .state_path()
        .parent()
        .unwrap_or_else(|| panic!("state database parent missing"))
        .join("checkpoint-cas")
        .join("sha256")
        .join(&reanchor.payload_digest[..2])
        .join(&reanchor.payload_digest);
    fs::remove_file(&reanchor_cas)
        .unwrap_or_else(|error| panic!("remove re-anchor manifest CAS: {error}"));

    let (controller, second_summary, _registry) = recover(&fixture);
    assert!(second_summary.fallback_checkpoint_used);
    assert!(second_summary.checkpoint_generation < corrupt.generation);
    assert_ne!(second_summary.checkpoint_generation, corrupt.generation);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn unjournaled_task_state_drift_is_rejected_during_recovery() {
    let fixture = Fixture::create("unjournaled-task-drift");
    let task_id = run_to_success(&fixture);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for task drift: {error}"));
    let raw = state
        .get_state("controller.task", &task_id)
        .unwrap_or_else(|error| panic!("read task state: {error}"))
        .unwrap_or_else(|| panic!("task state missing"));
    let mut value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("task json: {error}"));
    let calls = value["model_calls_used"]
        .as_u64()
        .unwrap_or_else(|| panic!("model call counter missing"));
    value["model_calls_used"] = json!(calls + 1);
    state
        .put_state("controller.task", &task_id, &value.to_string())
        .unwrap_or_else(|error| panic!("write unjournaled task drift: {error}"));
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen drifted state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("unjournaled current-state drift must not recover");
    };
    assert!(
        error
            .to_string()
            .contains("does not equal ordered post-checkpoint journal replay")
    );
}

#[test]
fn recovery_normalized_attempt_state_survives_second_restart() {
    let fixture = Fixture::create("recovery-second-restart");
    let mut child = spawn_child(&fixture, "before_mutation", None);
    wait_for_marker(&fixture.marker(), &fixture, &mut child);
    let action_id =
        wait_for_action_state(&fixture.state_path(), "authorized", &fixture, &mut child);
    kill_child(&mut child);

    let (controller, first, _registry) = recover(&fixture);
    assert!(!first.mutation_blocked);
    assert_eq!(first.pending_recovery_action_ids, vec![action_id.clone()]);
    drop(controller);

    let (controller, second, _registry) = recover(&fixture);
    assert!(!second.mutation_blocked);
    assert_eq!(second.pending_recovery_action_ids, vec![action_id.clone()]);
    assert_eq!(
        controller
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("action after second recovery: {error}"))
            .unwrap_or_else(|| panic!("recovery action missing"))
            .state,
        "authorized"
    );
}

#[test]
fn older_checkpoint_fallback_replays_model_and_attempt_transitions_exactly() {
    let fixture = Fixture::create("ordered-runtime-replay");
    let task_id = run_to_success(&fixture);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before replay fallback: {error}"));
    let generation_two = state
        .checkpoint_integrity_by_generation(2)
        .unwrap_or_else(|error| panic!("checkpoint generation 2: {error}"))
        .unwrap_or_else(|| panic!("checkpoint generation 2 missing"));
    assert_eq!(generation_two.generation, 2);
    drop(state);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for ordered replay corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=2;\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("simulate early checkpoint corruption: {error}"));
    drop(connection);

    let (controller, summary, _registry) = recover(&fixture);
    assert!(summary.fallback_checkpoint_used);
    assert_eq!(summary.checkpoint_generation, 1);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert!(source(&fixture.root).contains("Apply"));
}

#[test]
fn unjournaled_repository_baseline_and_validity_drift_is_rejected_during_recovery() {
    let fixture = Fixture::create("unjournaled-baseline-drift");
    let _task_id = run_to_success(&fixture);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for baseline drift: {error}"));

    let raw_baseline = state
        .get_state("controller.repository_baseline", "active")
        .unwrap_or_else(|error| panic!("read repository baseline: {error}"))
        .unwrap_or_else(|| panic!("repository baseline missing"));
    let mut baseline_set: Value = serde_json::from_str(&raw_baseline)
        .unwrap_or_else(|error| panic!("baseline json: {error}"));
    let baseline = sole_persisted_repository_baseline_mut(&mut baseline_set);
    baseline["diff_digest"] = Value::String(format!("sha256:{}", "b".repeat(64)));
    state
        .put_state(
            "controller.repository_baseline",
            "active",
            &baseline_set.to_string(),
        )
        .unwrap_or_else(|error| panic!("write unjournaled baseline drift: {error}"));

    let raw_plan = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read active plan: {error}"))
        .unwrap_or_else(|| panic!("active plan missing"));
    let mut plan: Value =
        serde_json::from_str(&raw_plan).unwrap_or_else(|error| panic!("plan json: {error}"));
    plan["validity"] = Value::String("stale_evidence".to_owned());
    state
        .put_state("controller.plan", "active", &plan.to_string())
        .unwrap_or_else(|error| panic!("write unjournaled validity drift: {error}"));
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen baseline-drifted state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("unjournaled baseline/validity drift must not recover");
    };
    assert!(error.to_string().contains("durable repository baseline"));
    assert!(error.to_string().contains("corrupt or misbound"));
}

#[test]
fn fallback_rejects_baseline_diff_content_tamper_before_reconstruction() {
    let fixture = Fixture::create("fallback-baseline-content-tamper");
    let _task_id = run_to_success(&fixture);

    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for baseline-content tamper: {error}"));
    let raw_baseline = state
        .get_state("controller.repository_baseline", "active")
        .unwrap_or_else(|error| panic!("read repository baseline: {error}"))
        .unwrap_or_else(|| panic!("repository baseline missing"));
    let mut baseline_set: Value = serde_json::from_str(&raw_baseline)
        .unwrap_or_else(|error| panic!("baseline json: {error}"));
    let baseline = sole_persisted_repository_baseline_mut(&mut baseline_set);
    let content = baseline["diff_content"]
        .as_str()
        .unwrap_or_else(|| panic!("baseline diff content missing"));
    baseline["diff_content"] =
        Value::String(format!("{content}\n# tampered without digest update\n"));
    state
        .put_state(
            "controller.repository_baseline",
            "active",
            &baseline_set.to_string(),
        )
        .unwrap_or_else(|error| panic!("write baseline-content tamper: {error}"));
    drop(state);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for fallback corruption: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=2;\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("force older checkpoint fallback: {error}"));
    drop(connection);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen tampered fallback state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("fallback must reject baseline diff content tamper");
    };
    assert!(error.to_string().contains("durable repository baseline"));
    assert!(error.to_string().contains("corrupt or misbound"));
}

#[test]
fn recovery_rejects_execution_epoch_rollback_below_trusted_manifest() {
    let fixture = Fixture::create("epoch-rollback-manifest");
    let _task_id = run_to_success(&fixture);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before epoch rollback: {error}"));
    let current_epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("current epoch: {error}"));
    assert!(current_epoch > 0);
    drop(state);

    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for epoch rollback: {error}"));
    connection
        .execute(
            "UPDATE controller_runtime SET execution_epoch=?1 WHERE singleton=1",
            [current_epoch - 1],
        )
        .unwrap_or_else(|error| panic!("rollback execution epoch: {error}"));
    drop(connection);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen epoch-rolled state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("execution epoch rollback below trusted manifest must fail closed");
    };
    assert!(error.to_string().contains("below trusted recovery floor"));
}

#[test]
fn fallback_rejects_epoch_below_later_authoritative_journal_epoch() {
    let fixture = Fixture::create("epoch-rollback-fallback");
    let _task_id = run_to_success(&fixture);
    let connection = Connection::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("open sqlite for fallback epoch rollback: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER checkpoint_integrity_no_update;\
             UPDATE checkpoint_integrity SET checkpoint_hash='sha256:0000000000000000000000000000000000000000000000000000000000000000' \
             WHERE generation=2;\
             UPDATE controller_runtime SET execution_epoch=1 WHERE singleton=1;\
             CREATE TRIGGER checkpoint_integrity_no_update \
             BEFORE UPDATE ON checkpoint_integrity \
             BEGIN \
                 SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable'); \
             END;",
        )
        .unwrap_or_else(|error| panic!("force fallback and epoch rollback: {error}"));
    drop(connection);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen fallback epoch state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("fallback must honor later authoritative execution epoch");
    };
    assert!(error.to_string().contains("below trusted recovery floor"));
}

#[test]
fn unjournaled_resource_row_mutation_is_rejected_during_recovery() {
    let fixture = Fixture::create("resource-unjournaled-row");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (controller, _task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    drop(controller);

    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for unjournaled resource row: {error}"));
    let (plan_id, revision) = active_plan_scope(&state);
    let mut governor = M6ResourceGovernor::default();
    let pressure = governor.observe_pressure(green_pressure_snapshot(1_500));
    let key = scoped_resource_key(&plan_id, revision, &pressure.event_id);
    let value_json = serde_json::to_string(&pressure)
        .unwrap_or_else(|error| panic!("serialize resource pressure: {error}"));
    state
        .put_state("controller.resource_pressure", &key, &value_json)
        .unwrap_or_else(|error| panic!("write unjournaled resource row: {error}"));
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen unjournaled resource state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("unjournaled resource row must fail closed");
    };
    assert!(error.to_string().contains(
        "current resource state does not equal checkpoint plus ordered resource-journal replay"
    ));
}

#[test]
fn post_checkpoint_resource_event_tamper_is_rejected() {
    for tamper_revision in [false, true] {
        let label = if tamper_revision {
            "resource-event-revision-tamper"
        } else {
            "resource-event-digest-tamper"
        };
        let fixture = Fixture::create(label);
        let prepared = prepare(&fixture.root);
        let backend = fake_backend(&prepared, false);
        let (controller, _task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
        drop(controller);

        let mut state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("state for resource event tamper: {error}"));
        let (plan_id, revision) = active_plan_scope(&state);
        let mut governor = M6ResourceGovernor::default();
        let pressure = governor.observe_pressure(green_pressure_snapshot(1_500));
        let key = scoped_resource_key(&plan_id, revision, &pressure.event_id);
        let value_json = serde_json::to_string(&pressure)
            .unwrap_or_else(|error| panic!("serialize tampered resource pressure: {error}"));
        let binding_key = resource_binding_key("controller.resource_pressure", &key);
        let mut payload =
            exact_resource_event_payload(&plan_id, revision, &binding_key, &value_json);
        if tamper_revision {
            payload["plan_revision"] = json!(revision + 1);
        } else {
            payload["post_image_digests"][&binding_key] =
                Value::String(format!("sha256:{}", "0".repeat(64)));
        }
        publish_resource_row_with_event(
            &mut state,
            "controller.resource_pressure",
            &key,
            &value_json,
            "resource_fixture_pressure",
            &pressure.event_id,
            &payload,
        );
        drop(state);

        let registry = registry_for(&fixture.root);
        let state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("reopen tampered resource state: {error}"));
        let Err(error) = RecoveryManager::recover(state, &registry) else {
            panic!("tampered resource event must fail closed");
        };
        let message = error.to_string();
        if tamper_revision {
            assert!(
                message
                    .contains("post-checkpoint resource event targets a different plan revision")
            );
        } else {
            assert!(message.contains(
                "current resource state does not equal checkpoint plus ordered resource-journal replay"
            ));
        }
    }
}

#[test]
fn valid_post_checkpoint_resource_mutation_replays_during_recovery() {
    let fixture = Fixture::create("resource-valid-replay");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (controller, _task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    drop(controller);

    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for valid resource replay: {error}"));
    let epoch_before = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("resource replay epoch: {error}"));
    let (plan_id, revision) = active_plan_scope(&state);
    let mut governor = M6ResourceGovernor::default();
    let pressure = governor.observe_pressure(green_pressure_snapshot(1_500));
    let key = scoped_resource_key(&plan_id, revision, &pressure.event_id);
    let value_json = serde_json::to_string(&pressure)
        .unwrap_or_else(|error| panic!("serialize replay resource pressure: {error}"));
    let binding_key = resource_binding_key("controller.resource_pressure", &key);
    let payload = exact_resource_event_payload(&plan_id, revision, &binding_key, &value_json);
    publish_resource_row_with_event(
        &mut state,
        "controller.resource_pressure",
        &key,
        &value_json,
        "resource_fixture_pressure",
        &pressure.event_id,
        &payload,
    );
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen valid resource replay state: {error}"));
    let (controller, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("valid resource replay must recover: {error}"));
    assert!(summary.replayed_events >= 1);
    assert_eq!(summary.execution_epoch_before, epoch_before);
    assert!(summary.execution_epoch_after > epoch_before);
    drop(controller);
}

#[test]
fn stale_model_residency_states_block_before_recovery_epoch_advance() {
    for (label, state_name) in [
        ("resource-stale-model-resident", "resident"),
        ("resource-stale-model-unloading", "unloading"),
        ("resource-stale-model-unknown", "unknown"),
    ] {
        let (fixture, task_id, epoch_before) = reserved_model_fixture(label);
        let mut state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("state for stale MODEL residency: {error}"));
        let (plan_id, revision) = active_plan_scope(&state);
        let (key, raw) = sole_resource_record(&state, "controller.resource_residency");
        let mut residency: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("stale MODEL residency json: {error}"));
        residency["state"] = Value::String(state_name.to_owned());
        residency["updated_at_ms"] = json!(1_750);
        let value_json = residency.to_string();
        let binding_key = resource_binding_key("controller.resource_residency", &key);
        let payload = exact_resource_event_payload(&plan_id, revision, &binding_key, &value_json);
        publish_resource_row_with_event(
            &mut state,
            "controller.resource_residency",
            &key,
            &value_json,
            "resource_fixture_model_state",
            &task_id,
            &payload,
        );
        drop(state);

        let registry = registry_for(&fixture.root);
        let state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("reopen stale MODEL residency: {error}"));
        let Err(error) = RecoveryManager::recover(state, &registry) else {
            panic!("stale MODEL state {state_name} must block recovery");
        };
        assert!(
            error
                .to_string()
                .contains("recovery cannot prove pre-crash MODEL absence")
        );
        let state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("inspect stale MODEL recovery epoch: {error}"));
        assert_eq!(
            state
                .current_execution_epoch()
                .unwrap_or_else(|error| panic!("stale MODEL recovery epoch: {error}")),
            epoch_before,
            "MODEL state {state_name} advanced the recovery epoch despite unresolved physical residency"
        );
    }
}

#[test]
fn admitted_build_heavy_without_process_row_is_released_before_recovery_epoch_advance() {
    let fixture = Fixture::create("resource-stale-build-heavy");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let mut policy = global_policy();
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY"]);
    let (mut controller, task_id) =
        compile_and_activate_with_policy(&fixture.base, &prepared, &backend, policy);
    let model_lease = controller
        .derive_ready_lease(
            &prepared.registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-build-heavy-recovery"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive MODEL lease before BUILD_HEAVY: {error}"));
    let _build_lease = controller
        .acquire_build_heavy(
            model_lease,
            &prepared.registry,
            &write_tool_manifest(),
            &backend,
        )
        .unwrap_or_else(|error| panic!("acquire BUILD_HEAVY recovery fixture lease: {error}"));
    let epoch_before = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("BUILD_HEAVY recovery snapshot: {error}"))
        .execution_epoch;
    let (build_row_key, build_row_before) = build_heavy_resource_record(controller.state());
    assert_eq!(build_row_before["state"], "ACTIVE");
    assert!(
        controller
            .state()
            .state_records("controller.process_lease")
            .unwrap_or_else(|error| panic!("BUILD_HEAVY process rows before crash: {error}"))
            .is_empty(),
        "admission without execution must not fabricate a process row"
    );
    drop(controller);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen stale BUILD_HEAVY state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover never-spawned BUILD_HEAVY lease: {error}"));
    assert_eq!(summary.execution_epoch_before, epoch_before);
    assert!(summary.execution_epoch_after > epoch_before);
    assert!(summary.unresolved_process_lease_ids.is_empty());
    let snapshot = recovered
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("resource snapshot after BUILD_HEAVY recovery: {error}"));
    assert_eq!(snapshot.execution_epoch, summary.execution_epoch_after);
    assert!(snapshot.governor.active_leases.is_empty());
    let released = recovered
        .state()
        .get_state("controller.resource_lease", &build_row_key)
        .unwrap_or_else(|error| panic!("read released BUILD_HEAVY row: {error}"))
        .unwrap_or_else(|| panic!("released BUILD_HEAVY row disappeared"));
    let released: Value = serde_json::from_str(&released)
        .unwrap_or_else(|error| panic!("released BUILD_HEAVY row json: {error}"));
    assert_eq!(released["class"], "BUILD_HEAVY");
    assert_eq!(released["state"], "RELEASED");
}

#[test]
fn pending_spawn_build_heavy_blocks_before_recovery_epoch_advance() {
    let fixture = Fixture::create("resource-build-heavy-pending-spawn");
    let mut child = spawn_child(
        &fixture,
        "build_pending_spawn",
        Some("after_process_spawn_before_identity_lease"),
    );
    wait_for_marker(&fixture.marker(), &fixture, &mut child);
    let _action_id =
        wait_for_action_state(&fixture.state_path(), "dispatched", &fixture, &mut child);
    let pending_lease_id = wait_for_pending_process_lease(&fixture.state_path());
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before pending BUILD_HEAVY crash: {error}"));
    let epoch_before = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("pending BUILD_HEAVY epoch: {error}"));
    drop(state);
    kill_child(&mut child);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen pending BUILD_HEAVY state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("pending-spawn BUILD_HEAVY must block recovery before epoch advance");
    };
    assert!(
        error
            .to_string()
            .contains("recovery cannot prove physical cleanup for stale active BUILD_HEAVY lease"),
        "unexpected pending BUILD_HEAVY recovery error: {error}"
    );
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("inspect pending BUILD_HEAVY recovery: {error}"));
    assert_eq!(
        state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("pending BUILD_HEAVY recovery epoch: {error}")),
        epoch_before
    );
    let pending = state
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("pending BUILD_HEAVY process rows: {error}"));
    assert!(pending.iter().any(|record| {
        let value: Value = serde_json::from_str(&record.value_json)
            .unwrap_or_else(|error| panic!("pending BUILD_HEAVY process json: {error}"));
        value["lease_id"] == pending_lease_id && value["state"] == "pending_spawn"
    }));
    thread::sleep(Duration::from_millis(2_100));
}

#[test]
fn active_build_heavy_process_is_reaped_then_resource_lease_released_before_epoch_advance() {
    let fixture = Fixture::create("resource-build-heavy-active-reap");
    let mut child = spawn_child(&fixture, "build_orphan_sleep", None);
    let _action_id =
        wait_for_action_state(&fixture.state_path(), "dispatched", &fixture, &mut child);
    let (pgid, identity) = wait_for_active_process_lease(&fixture.state_path());
    assert_eq!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe BUILD_HEAVY child identity: {error}"))
            .as_deref(),
        Some(identity.as_str())
    );
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state before active BUILD_HEAVY crash: {error}"));
    let epoch_before = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("active BUILD_HEAVY epoch: {error}"));
    let (build_row_key, build_before) = build_heavy_resource_record(&state);
    assert_eq!(build_before["state"], "ACTIVE");
    drop(state);
    kill_child(&mut child);

    let (recovered, summary, _registry) = recover(&fixture);
    assert!(summary.unresolved_process_lease_ids.is_empty());
    assert!(summary.execution_epoch_after > epoch_before);
    assert!(
        process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe reaped BUILD_HEAVY group: {error}"))
            .is_none()
    );
    let process_rows = recovered
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("BUILD_HEAVY process rows after recovery: {error}"));
    assert!(
        process_rows
            .iter()
            .any(|record| record.value_json.contains("reaped_recovery"))
    );
    let snapshot = recovered
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("BUILD_HEAVY resource snapshot after reap: {error}"));
    assert!(snapshot.governor.active_leases.is_empty());
    let released = recovered
        .state()
        .get_state("controller.resource_lease", &build_row_key)
        .unwrap_or_else(|error| panic!("read reaped BUILD_HEAVY resource row: {error}"))
        .unwrap_or_else(|| panic!("reaped BUILD_HEAVY resource row disappeared"));
    let released: Value = serde_json::from_str(&released)
        .unwrap_or_else(|error| panic!("reaped BUILD_HEAVY resource row json: {error}"));
    assert_eq!(released["state"], "RELEASED");
}

#[test]
#[allow(clippy::too_many_lines)]
fn resource_recovery_rejects_future_epoch_task_contract_and_governor_mismatch() {
    {
        let (fixture, task_id, epoch_before) = reserved_model_fixture("resource-future-epoch");
        let mut state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("state for future resource epoch: {error}"));
        let (plan_id, revision) = active_plan_scope(&state);
        let (key, raw) = sole_resource_record(&state, "controller.resource_residency");
        let mut residency: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("future resource epoch json: {error}"));
        residency["execution_epoch"] = json!(epoch_before + 1);
        let value_json = residency.to_string();
        let binding_key = resource_binding_key("controller.resource_residency", &key);
        let payload = exact_resource_event_payload(&plan_id, revision, &binding_key, &value_json);
        publish_resource_row_with_event(
            &mut state,
            "controller.resource_residency",
            &key,
            &value_json,
            "resource_fixture_future_epoch",
            &task_id,
            &payload,
        );
        drop(state);

        let registry = registry_for(&fixture.root);
        let state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("reopen future resource epoch state: {error}"));
        let Err(error) = RecoveryManager::recover(state, &registry) else {
            panic!("future resource epoch must fail closed");
        };
        assert!(
            error
                .to_string()
                .contains("is ahead of current execution epoch")
        );
    }

    {
        let (fixture, task_id, _epoch_before) =
            reserved_model_fixture("resource-task-contract-mismatch");
        let mut state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("state for resource task-contract mismatch: {error}"));
        let (plan_id, revision) = active_plan_scope(&state);
        let (key, raw) = sole_resource_record(&state, "controller.resource_residency");
        let mut residency: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("resource task-contract json: {error}"));
        residency["task_contract_digest"] = Value::String(format!("sha256:{}", "f".repeat(64)));
        let value_json = residency.to_string();
        let binding_key = resource_binding_key("controller.resource_residency", &key);
        let payload = exact_resource_event_payload(&plan_id, revision, &binding_key, &value_json);
        publish_resource_row_with_event(
            &mut state,
            "controller.resource_residency",
            &key,
            &value_json,
            "resource_fixture_task_contract",
            &task_id,
            &payload,
        );
        drop(state);

        let registry = registry_for(&fixture.root);
        let state = StateStore::open(fixture.state_path()).unwrap_or_else(|error| {
            panic!("reopen task-contract-mismatched resource state: {error}")
        });
        let Err(error) = RecoveryManager::recover(state, &registry) else {
            panic!("stale resource task-contract binding must fail closed");
        };
        assert!(
            error
                .to_string()
                .contains("MODEL residency task-contract digest is stale")
        );
    }

    {
        let (fixture, task_id, _epoch_before) =
            reserved_model_fixture("resource-governor-row-mismatch");
        let mut state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("state for resource governor mismatch: {error}"));
        let (plan_id, revision) = active_plan_scope(&state);
        let (key, raw) = sole_resource_record(&state, "controller.resource_governor");
        let mut governor: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("resource governor json: {error}"));
        governor["active_leases"] = json!([]);
        let value_json = governor.to_string();
        let binding_key = resource_binding_key("controller.resource_governor", &key);
        let payload = exact_resource_event_payload(&plan_id, revision, &binding_key, &value_json);
        publish_resource_row_with_event(
            &mut state,
            "controller.resource_governor",
            &key,
            &value_json,
            "resource_fixture_governor_mismatch",
            &task_id,
            &payload,
        );
        drop(state);

        let registry = registry_for(&fixture.root);
        let state = StateStore::open(fixture.state_path())
            .unwrap_or_else(|error| panic!("reopen governor-mismatched resource state: {error}"));
        let Err(error) = RecoveryManager::recover(state, &registry) else {
            panic!("resource governor/current-row mismatch must fail closed");
        };
        assert!(error.to_string().contains(
            "resource-governor active leases do not exactly match durable nonterminal lease rows"
        ));
    }
}

#[test]
fn superseded_plan_checkpoint_is_blocked_without_explicit_carry_forward() {
    let fixture = Fixture::create("superseded");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (_controller, _task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for supersede: {error}"));
    let raw = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read active plan: {error}"))
        .unwrap_or_else(|| panic!("active plan missing"));
    let mut value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("plan json: {error}"));
    value["plan_id"] = Value::String("plan.superseding-n-plus-one".to_owned());
    value["revision"] = json!(2);
    value["plan_digest"] = Value::String(format!("sha256:{}", "f".repeat(64)));
    state
        .put_state("controller.plan", "active", &value.to_string())
        .unwrap_or_else(|error| panic!("write superseding plan state: {error}"));
    drop(state);
    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen state: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("superseded checkpoint must not resume");
    };
    assert!(error.to_string().contains("superseded plan"));
    assert!(source(&fixture.root).contains("Save"));
}

#[test]
fn post_activation_pre_checkpoint_recovery_switches_to_n_plus_one_without_deleting_n_rows() {
    let fixture = Fixture::create("supersession-switch");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    drop(controller);

    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for supersession: {error}"));
    assert!(
        state
            .get_state("controller.task", &task_id)
            .unwrap_or_else(|error| panic!("read N task: {error}"))
            .is_some(),
        "revision N runtime must exist before supersession"
    );
    let next_digest = install_uncheckpointed_supersession(&mut state, &task_id, false);
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen supersession state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover N+1 activation: {error}"));
    assert_eq!(summary.plan_digest, next_digest);
    assert_eq!(recovered.task_state(&task_id), Some(TaskState::Planned));
    drop(recovered);

    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("inspect recovered supersession: {error}"));
    assert!(
        state
            .get_state("controller.task", &task_id)
            .unwrap_or_else(|error| panic!("read historical N task: {error}"))
            .is_some(),
        "historical N task runtime must remain auditable"
    );
    let active_raw = state
        .get_state("controller.plan", "active")
        .unwrap_or_else(|error| panic!("read recovered active plan: {error}"))
        .unwrap_or_else(|| panic!("recovered active plan missing"));
    let active: Value = serde_json::from_str(&active_raw)
        .unwrap_or_else(|error| panic!("recovered active plan json: {error}"));
    let plan_id = active["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("recovered plan id"));
    assert_eq!(active["revision"], json!(2));
    assert!(
        state
            .get_state("controller.task", &format!("{plan_id}@r2:{task_id}"))
            .unwrap_or_else(|error| panic!("read active N+1 task: {error}"))
            .is_some(),
        "N+1 runtime must use its revision-scoped namespace"
    );
}

#[test]
fn post_activation_pre_checkpoint_recovery_rejects_tampered_n_plus_one_runtime_digest() {
    let fixture = Fixture::create("supersession-tamper");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    drop(controller);
    let mut state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("state for supersession tamper: {error}"));
    let _ = install_uncheckpointed_supersession(&mut state, &task_id, true);
    drop(state);

    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("reopen tampered supersession: {error}"));
    let Err(error) = RecoveryManager::recover(state, &registry) else {
        panic!("tampered N+1 runtime digest must block recovery");
    };
    assert!(error.to_string().contains("task runtime map differs"));
}

#[test]
fn historical_unknown_that_is_now_failed_does_not_block_recovered_readiness() {
    let fixture = Fixture::create("historical-unknown");
    let prepared = prepare(&fixture.root);
    let backend = fake_backend(&prepared, false);
    let (_controller, task_id) = compile_and_activate(&fixture.base, &prepared, &backend);
    let mut state =
        StateStore::open(fixture.state_path()).unwrap_or_else(|error| panic!("state: {error}"));
    let epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: "action.synthetic-history",
            state: "prepared",
            payload_digest: "sha256:synthetic-payload",
            policy_digest: "sha256:synthetic-policy",
            execution_epoch: epoch,
            event_id: "event.synthetic.prepared",
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert synthetic action: {error}"));
    for (expected, next, id) in [
        ("prepared", "authorized", "event.synthetic.authorized"),
        ("authorized", "dispatched", "event.synthetic.dispatched"),
        ("dispatched", "unknown", "event.synthetic.unknown"),
        ("unknown", "reconciled", "event.synthetic.reconciled"),
        ("reconciled", "failed", "event.synthetic.failed"),
    ] {
        state
            .transition_action_with_event(ActionTransition {
                action_id: "action.synthetic-history",
                expected_state: expected,
                next_state: next,
                expected_epoch: epoch,
                event_id: id,
                event_kind: next,
                payload_json: "{}",
                result_digest: None,
            })
            .unwrap_or_else(|error| panic!("synthetic transition {expected}->{next}: {error}"));
    }
    drop(state);
    let registry = registry_for(&fixture.root);
    let state = StateStore::open(fixture.state_path())
        .unwrap_or_else(|error| panic!("recovery state: {error}"));
    let (mut controller, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover historical unknown: {error}"));
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(2_000),
    )));
    assert!(summary.unknown_action_ids.is_empty());
    let lease = controller
        .derive_ready_lease(
            &registry,
            &task_id,
            ReadinessInputs::permissive_m1("sha256:t08-history-resource"),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("historical unknown should not block: {error}"));
    controller
        .cancel_ready_lease(lease)
        .unwrap_or_else(|error| panic!("cancel lease: {error}"));
}
