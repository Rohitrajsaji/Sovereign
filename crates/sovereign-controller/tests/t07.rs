#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
    EvidenceKind, RepairPacket,
};
use sovereign_controller::{
    CheckpointActionRecord, CheckpointManifest, Controller, ControllerError, ExecutionRuntime,
    ExecutionSuccess, FailureClassification, FailureClassificationKind, ModelProposalV1,
    PermissionContext, PlanValidity, ReadinessInputs, RecoveryManager, ResourcePressureProbe,
    RoleId, RoleRegistry, SchedulerView, SecretProcessRuntime, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_memory::{MemoryKind, MemoryTrust, ProcedurePattern};
use sovereign_model::{
    BackendHealth, DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelError, ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResidencyProof,
    ModelResponse, ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, DiagnosticCode, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanIr, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CapabilitySet, CommandMode, CommandPolicy, CommandRisk, CommandSpec, ControllerSecretLocator,
    ExecutionIsolationBackend, FakeSecretProvider, IsolatedCommand, IsolationCapabilities,
    IsolationRequest, MacSandboxExecBackend, ModelCallBudget, OsMemoryPressure, PinnedExecutable,
    PolicyError, RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION, ReconciliationPolicy,
    ResourcePressureSnapshotV1, SecretBroker, SecretInjection, SecretProviderBackend,
    SecretProviderKind, SecretRef, SecretValue, ThermalPressure,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::{
    ActionTransition, NewActionRecord, NewCheckpointIntegrityRecord, NewJournalEvent,
    StateRecordUpdate, StateStore,
};
use sovereign_tools::{EPHEMERAL_SECRET_FILE_ENV, PermissionClass, ToolManifest, ToolSchemaV1};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

const SOURCE: &str =
    "export function SettingsForm() {\n  return <button type=\"submit\">Save</button>;\n}\n";
const OTHER_SOURCE: &str = "baseline other file\n";
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
        // Absolute swap is diagnostic context only. Keeping this deliberately high also makes
        // the legacy Controller regressions exercise the M6 rule that swap-used alone is not an
        // admission blocker.
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
            ".sovereign-controller-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        let root = base.join("repo");
        fs::create_dir_all(root.join("src/settings"))
            .unwrap_or_else(|error| panic!("create repo: {error}"));
        fs::write(root.join("src/settings/SettingsForm.tsx"), SOURCE)
            .unwrap_or_else(|error| panic!("write source: {error}"));
        fs::write(
            root.join("src/settings/SettingsImport.tsx"),
            "import { SettingsForm } from './SettingsForm';\nexport const imported = SettingsForm;\n",
        )
        .unwrap_or_else(|error| panic!("write import-only source: {error}"));
        fs::write(root.join("src/other.txt"), OTHER_SOURCE)
            .unwrap_or_else(|error| panic!("write other source: {error}"));
        git(&root, &["init", "-q"]);
        git(
            &root,
            &[
                "config",
                "user.email",
                "sovereign-controller@example.invalid",
            ],
        );
        git(&root, &["config", "user.name", "Sovereign Controller"]);
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

struct CompiledFixture {
    repo: TestRepo,
    registry: ProjectRegistry,
    packet: ContextPacket,
    form_digest: String,
    compilation: Option<PlanCompilationResult>,
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

fn git_text(root: &Path, args: &[&str]) -> String {
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
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("git output utf8: {error}"))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn runtime_secret_sentinel(label: &str) -> Vec<u8> {
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let seed = format!("{label}\0{}\0{nanos}\0{sequence}", std::process::id());
    let mut sentinel = b"M6-RUNTIME-SECRET-".to_vec();
    sentinel.extend_from_slice(&Sha256::digest(seed.as_bytes()));
    sentinel.extend_from_slice(&[0xff, 0x00, 0xfe]);
    sentinel
}

fn sha256_needles(bytes: &[u8]) -> Vec<Vec<u8>> {
    let digest = Sha256::digest(bytes);
    let hex = format!("{digest:x}");
    vec![
        digest.to_vec(),
        hex.as_bytes().to_vec(),
        format!("sha256:{hex}").into_bytes(),
    ]
}

fn assert_file_excludes_needles(path: &Path, needles: &[(&str, &[u8])]) {
    if !path.is_file() {
        return;
    }
    let bytes = fs::read(path)
        .unwrap_or_else(|error| panic!("read runtime persistence {}: {error}", path.display()));
    for (label, needle) in needles {
        assert!(
            !needle.is_empty() && !bytes.windows(needle.len()).any(|window| window == *needle),
            "runtime persistence {} contains forbidden {label}",
            path.display()
        );
    }
}

fn assert_tree_excludes_needles(root: &Path, needles: &[(&str, &[u8])]) {
    if !root.exists() {
        return;
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).unwrap_or_else(|error| {
            panic!("runtime persistence metadata {}: {error}", path.display())
        });
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            assert_file_excludes_needles(&path, needles);
            continue;
        }
        if metadata.is_dir() {
            let entries = fs::read_dir(&path).unwrap_or_else(|error| {
                panic!("read runtime persistence dir {}: {error}", path.display())
            });
            for entry in entries {
                pending.push(
                    entry
                        .unwrap_or_else(|error| {
                            panic!("read runtime persistence entry {}: {error}", path.display())
                        })
                        .path(),
                );
            }
        }
    }
}

fn assert_runtime_persistence_excludes_secret(
    repo: &TestRepo,
    artifacts: &ArtifactStore,
    sentinel: &[u8],
    raw_stdout: &[u8],
    raw_stderr: &[u8],
) {
    let stdout_needles = sha256_needles(raw_stdout);
    let stderr_needles = sha256_needles(raw_stderr);
    let needles = vec![
        ("resolved secret bytes", sentinel),
        ("raw stdout sha256 bytes", stdout_needles[0].as_slice()),
        ("raw stdout sha256 hex", stdout_needles[1].as_slice()),
        ("raw stdout sha256 tag", stdout_needles[2].as_slice()),
        ("raw stderr sha256 bytes", stderr_needles[0].as_slice()),
        ("raw stderr sha256 hex", stderr_needles[1].as_slice()),
        ("raw stderr sha256 tag", stderr_needles[2].as_slice()),
    ];

    assert_file_excludes_needles(&repo.state_path, &needles);
    for suffix in ["-wal", "-shm"] {
        let mut path = repo.state_path.as_os_str().to_os_string();
        path.push(suffix);
        assert_file_excludes_needles(&PathBuf::from(path), &needles);
    }
    assert_tree_excludes_needles(artifacts.root(), &needles);
    assert_tree_excludes_needles(&repo.base.join("checkpoint-cas"), &needles);
}

fn append_modified_checkpoint(
    state: &mut StateStore,
    mutate: impl FnOnce(&mut CheckpointManifest),
) {
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
    let mut manifest: CheckpointManifest = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("decode checkpoint manifest: {error}"));
    mutate(&mut manifest);
    let bytes = serde_json::to_vec(&manifest)
        .unwrap_or_else(|error| panic!("encode modified checkpoint manifest: {error}"));
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

fn replace_persisted_task_runtime(
    state: &mut StateStore,
    task_id: &str,
    mutate: impl FnOnce(&mut Value),
) {
    let record = state
        .state_records("controller.task")
        .unwrap_or_else(|error| panic!("task records: {error}"))
        .into_iter()
        .find(|record| {
            serde_json::from_str::<Value>(&record.value_json)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/task/task_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .as_deref()
                == Some(task_id)
        })
        .unwrap_or_else(|| panic!("persisted task {task_id} missing"));
    let mut value: Value = serde_json::from_str(&record.value_json)
        .unwrap_or_else(|error| panic!("decode persisted task: {error}"));
    mutate(&mut value);
    state
        .put_state(
            "controller.task",
            &record.key,
            &serde_json::to_string(&value)
                .unwrap_or_else(|error| panic!("encode persisted task: {error}")),
        )
        .unwrap_or_else(|error| panic!("replace persisted task: {error}"));
    append_modified_checkpoint(state, |manifest| {
        manifest.task_records.insert(task_id.to_owned(), value);
    });
}

fn first_evidence_requirement_id(fixture: &CompiledFixture) -> String {
    fixture
        .compilation
        .as_ref()
        .and_then(|compilation| {
            compilation
                .plan()
                .as_value()
                .pointer("/tasks/0/evidence_requirements/0/requirement_id")
        })
        .and_then(Value::as_str)
        .map_or_else(
            || panic!("compiled evidence requirement missing"),
            str::to_owned,
        )
}

struct TwoTaskContract {
    requirement: String,
    upstream: String,
    downstream: String,
    artifact: String,
}

fn worktree_graph_task(
    local_id: &str,
    file: &str,
    dependencies: &[&str],
    old_literal: &str,
    new_literal: &str,
) -> Value {
    let local_id = format!("task-{local_id}");
    let dependencies = dependencies
        .iter()
        .map(|dependency| format!("task-{dependency}"))
        .collect::<Vec<_>>();
    json!({
        "local_id": local_id,
        "repository_id": "repo.app",
        "title": format!("Implement {local_id}"),
        "objective": format!("Change {old_literal} to {new_literal} in {file}."),
        "rationale": "The dependency-closed repository view requires this exact bounded mutation.",
        "files": [file],
        "symbols": [local_id],
        "dependencies": dependencies,
        "evidence_needs": [],
        "expected_change": format!("Change {old_literal} to {new_literal} in {file}."),
        "acceptance": [{
            "kind": "diff",
            "description": format!("The exact {old_literal}-to-{new_literal} delta is accepted."),
            "manual_gate_id": Value::Null
        }]
    })
}

fn task_id_for_objective(fixture: &CompiledFixture, relation: &str) -> String {
    fixture
        .compilation
        .as_ref()
        .unwrap_or_else(|| panic!("compiled graph fixture missing"))
        .plan()
        .as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("compiled graph tasks missing"))
        .iter()
        .find(|task| {
            task["objective"]
                .as_str()
                .is_some_and(|objective| objective.contains(relation))
        })
        .and_then(|task| task["task_id"].as_str())
        .map_or_else(
            || panic!("compiled task for relation {relation:?} missing"),
            str::to_owned,
        )
}

fn two_task_contract(fixture: &CompiledFixture) -> TwoTaskContract {
    let plan = fixture
        .compilation
        .as_ref()
        .unwrap_or_else(|| panic!("compiled two-task fixture missing"))
        .plan()
        .as_value();
    let tasks = plan["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("compiled tasks missing"));
    assert_eq!(tasks.len(), 2);
    TwoTaskContract {
        requirement: first_evidence_requirement_id(fixture),
        upstream: tasks[0]["task_id"]
            .as_str()
            .unwrap_or_else(|| panic!("upstream task id missing"))
            .to_owned(),
        downstream: tasks[1]["task_id"]
            .as_str()
            .unwrap_or_else(|| panic!("downstream task id missing"))
            .to_owned(),
        artifact: tasks[0]["expected_artifacts"][0]["artifact_id"]
            .as_str()
            .unwrap_or_else(|| panic!("upstream artifact id missing"))
            .to_owned(),
    }
}

fn global_policy() -> Value {
    serde_json::from_str(include_str!(
        "../../sovereign-eval/tests/fixtures/scenario1/policy.json"
    ))
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

fn model_response(content: String, input_tokens: u32) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "template".to_owned(),
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

fn backend(responses: Vec<ModelResponse>) -> DeterministicFakeBackend {
    let backend = DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-controller".to_owned(),
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

#[allow(clippy::too_many_lines)]
fn compiled_fixture(label: &str, evidence_query: bool) -> CompiledFixture {
    compiled_fixture_inner(
        label,
        evidence_query,
        false,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
    )
}

fn test_secret_ref() -> SecretRef {
    SecretRef {
        secret_ref_id: "secret.t07.sentinel".to_owned(),
        provider: SecretProviderKind::ExternalBroker,
        purpose: "T07 exact secret sentinel".to_owned(),
        injection: SecretInjection::TemporaryFile,
        target: EPHEMERAL_SECRET_FILE_ENV.to_owned(),
    }
}

fn compiled_secret_fixture(label: &str) -> (CompiledFixture, SecretRef) {
    let mut policy = global_policy();
    policy["capability_ceiling"] = json!(["read", "repo_write", "process_exec", "secret_use"]);
    policy["secrets"]["allowed_providers"] = json!(["external_broker"]);
    let mut fixture = compiled_fixture_inner(
        label,
        false,
        false,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        Some(policy),
    );
    let secret_ref = test_secret_ref();
    let target_task_id = fixture
        .compilation
        .as_ref()
        .and_then(|compilation| compilation.plan().as_value()["tasks"].as_array())
        .and_then(|tasks| tasks.first())
        .and_then(|task| task["task_id"].as_str())
        .unwrap_or_else(|| panic!("compiled secret fixture target task"))
        .to_owned();
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("secret binding validator: {error}"));
    let source = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled secret fixture source"));
    fixture.compilation = Some(
        source
            .bind_controller_secret_ref(&validator, &target_task_id, &secret_ref)
            .unwrap_or_else(|error| panic!("bind Controller SecretRef: {error}")),
    );
    (fixture, secret_ref)
}

#[allow(clippy::too_many_lines)]
fn compiled_fixture_with_dirty_target(label: &str) -> CompiledFixture {
    compiled_fixture_inner(
        label, false, true, None, None, false, false, None, None, None, None,
    )
}

#[allow(clippy::too_many_lines)]
fn compiled_fixture_with_task_model_call_cap(label: &str, cap: u64) -> CompiledFixture {
    compiled_fixture_inner(
        label,
        false,
        false,
        Some(cap),
        None,
        false,
        false,
        None,
        None,
        None,
        None,
    )
}

#[derive(Clone, Copy)]
enum ResourceFixtureOverride {
    NoBuildHeavyAuthority,
}

fn compiled_fixture_with_resource_override(
    label: &str,
    resource_override: ResourceFixtureOverride,
) -> CompiledFixture {
    compiled_fixture_inner(
        label,
        false,
        false,
        None,
        None,
        false,
        false,
        None,
        None,
        Some(resource_override),
        None,
    )
}

fn compiled_fixture_with_target_mode(label: &str, mode: u32) -> CompiledFixture {
    compiled_fixture_inner(
        label,
        false,
        false,
        None,
        Some(mode),
        false,
        false,
        None,
        None,
        None,
        None,
    )
}

fn compiled_two_task_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(
        label, false, false, None, None, true, false, None, None, None, None,
    )
}

fn compiled_learning_two_path_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(
        label,
        false,
        false,
        None,
        None,
        false,
        false,
        Some(json!({
            "tasks": [
                {
                    "title": "Apply verified label change",
                    "objective": "Change Save to Apply in SettingsForm.",
                    "rationale": "Exact current label evidence gates the mutation.",
                    "files": ["src/settings/SettingsForm.tsx"],
                    "symbols": ["SettingsForm"],
                    "evidence_queries": ["exact:path=src/settings/SettingsForm.tsx;contains=Save"],
                    "expected_change": "SettingsForm renders Apply."
                },
                {
                    "title": "Update independent baseline text",
                    "objective": "Change baseline other file to updated other file in src/other.txt.",
                    "rationale": "A second bounded path provides distinct verified workflow support without overlapping the first Controller-owned hunk.",
                    "files": ["src/other.txt"],
                    "symbols": ["other"],
                    "evidence_queries": [],
                    "expected_change": "src/other.txt contains updated other file."
                }
            ]
        })),
        Some(
            "Change Save to Apply in SettingsForm and change baseline other file to updated other file in src/other.txt."
                .to_owned(),
        ),
        None,
        None,
    )
}

fn compiled_worktree_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(
        label, false, false, None, None, false, true, None, None, None, None,
    )
}

fn compiled_worktree_graph_fixture(label: &str, tasks: &[Value]) -> CompiledFixture {
    compiled_fixture_inner(
        label,
        false,
        false,
        None,
        None,
        false,
        true,
        Some(json!({"tasks": tasks})),
        Some(
            "Change Save to Apply, Apply to Applied, Apply to Approved, baseline to branchthree, imported to finalized."
                .to_owned(),
        ),
        None,
        None,
    )
}

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn compiled_fixture_inner(
    label: &str,
    evidence_query: bool,
    dirty_target: bool,
    task_model_call_cap: Option<u64>,
    target_mode: Option<u32>,
    two_task: bool,
    worktree_depth: bool,
    planning_override: Option<Value>,
    goal_statement_override: Option<String>,
    resource_override: Option<ResourceFixtureOverride>,
    policy_override: Option<Value>,
) -> CompiledFixture {
    let repo = TestRepo::create(label);
    if let Some(mode) = target_mode {
        fs::set_permissions(
            repo.root.join("src/settings/SettingsForm.tsx"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap_or_else(|error| panic!("set target mode: {error}"));
        git(&repo.root, &["add", "src/settings/SettingsForm.tsx"]);
        git(&repo.root, &["commit", "-qm", "fixture target mode"]);
    }
    if dirty_target {
        fs::write(
            repo.root.join("src/settings/SettingsForm.tsx"),
            SOURCE.replace("  return", "  // user-owned pre-existing note\n  return"),
        )
        .unwrap_or_else(|error| panic!("write pre-existing user hunk: {error}"));
        fs::write(repo.root.join("user-owned-untracked.txt"), "keep exactly\n")
            .unwrap_or_else(|error| panic!("write unrelated user file: {error}"));
        fs::write(repo.root.join("src/other.txt"), "user staged version\n")
            .unwrap_or_else(|error| panic!("write staged user file: {error}"));
        git(&repo.root, &["add", "src/other.txt"]);
        fs::write(
            repo.root.join("src/other.txt"),
            "user staged version\nuser unstaged tail\n",
        )
        .unwrap_or_else(|error| panic!("write unstaged user file: {error}"));
    }
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &repo.root)
        .unwrap_or_else(|error| panic!("register: {error}"));
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    let retriever = ExactRetriever::new(&registry);
    let form = retriever
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read source: {error}"));
    let other = retriever
        .read_path("repo.app", Path::new("src/other.txt"), None)
        .unwrap_or_else(|error| panic!("read other source: {error}"));
    let import_only = retriever
        .read_path(
            "repo.app",
            Path::new("src/settings/SettingsImport.tsx"),
            None,
        )
        .unwrap_or_else(|error| panic!("read import-only source: {error}"));
    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns all state and authority.".to_owned(),
                task_contract: "Rename Save to Apply only.".to_owned(),
                current_state: format!("dirty_digest={}", snapshot.dirty_digest),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![
                    EvidenceItem::from_exact_file(&form, "exact source"),
                    EvidenceItem::from_exact_file(&other, "unrelated exact source"),
                    EvidenceItem::from_exact_file(&import_only, "mentions symbol but not label"),
                ],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context: {error}"));
    let planning = if let Some(planning) = planning_override {
        planning
    } else if worktree_depth {
        json!({
            "tasks": [{
                "local_id": "settings-label",
                "repository_id": "repo.app",
                "title": "Rename label",
                "objective": "Change Save to Apply in SettingsForm.",
                "rationale": "Exact source identifies the bounded edit.",
                "files": ["src/settings/SettingsForm.tsx"],
                "symbols": ["SettingsForm"],
                "dependencies": [],
                "evidence_needs": [],
                "expected_change": "SettingsForm renders Apply.",
                "acceptance": [{
                    "kind": "diff",
                    "description": "The scoped Save-to-Apply diff is accepted.",
                    "manual_gate_id": Value::Null
                }]
            }]
        })
    } else if two_task {
        json!({
            "tasks": [
                {
                    "title": "Apply verified label change",
                    "objective": "Change Save to Apply in SettingsForm.",
                    "rationale": "Exact current label evidence gates the mutation.",
                    "files": ["src/settings/SettingsForm.tsx"],
                    "symbols": ["SettingsForm"],
                    "evidence_queries": ["exact:path=src/settings/SettingsForm.tsx;contains=Save"],
                    "expected_change": "SettingsForm renders Apply."
                },
                {
                    "title": "Dependent follow-up",
                    "objective": "Change Apply to Applied in SettingsForm after the upstream verified output.",
                    "rationale": "The second step consumes the verified first-step artifact and criterion.",
                    "files": ["src/settings/SettingsForm.tsx"],
                    "symbols": ["SettingsForm"],
                    "evidence_queries": [],
                    "expected_change": "SettingsForm renders Applied."
                }
            ]
        })
    } else {
        json!({
            "tasks": [{
                "title": "Rename label",
                "objective": "Change Save to Apply in SettingsForm.",
                "rationale": "Exact source identifies the edit.",
                "files": ["src/settings/SettingsForm.tsx"],
                "symbols": ["SettingsForm"],
                "evidence_queries": if evidence_query { vec!["exact:path=src/settings/SettingsForm.tsx;contains=Save"] } else { Vec::<&str>::new() },
                "expected_change": "SettingsForm renders Apply."
            }]
        })
    };
    let planner = backend(vec![model_response(
        planning.to_string(),
        packet.metrics.final_serialized_input_tokens,
    )]);
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let compiler = PlanCompiler::new(&planner, &validator, "t07-test-compiler")
        .unwrap_or_else(|error| panic!("compiler: {error}"));
    let mut policy = policy_override.unwrap_or_else(global_policy);
    if let Some(cap) = task_model_call_cap {
        let resource_cap = policy
            .pointer_mut("/resources/max_model_calls")
            .unwrap_or_else(|| panic!("policy max_model_calls missing"));
        *resource_cap = json!(cap);
    }
    if let Some(resource_override) = resource_override {
        match resource_override {
            ResourceFixtureOverride::NoBuildHeavyAuthority => {
                policy["resources"]["heavy_leases"] = json!(["MODEL"]);
            }
        }
    }
    let m3 = worktree_depth.then(|| {
        let mut decision = DepthClassifier.classify(&DepthFeatureInput {
            repository_count: 1,
            language_count: 1,
            expected_files: 1,
            expected_modules: 2,
            architecture_uncertainty_percent: 60,
            ..DepthFeatureInput::default()
        });
        decision.mode = ExecutionDepth::D3;
        "controller worktree fixture".clone_into(&mut decision.reason);
        M3PlanningInput {
            depth: decision,
            supplied_sources: Vec::new(),
            additional_repositories: Vec::new(),
            manual_gates: Vec::new(),
            absence_evaluator: None,
            replan: None,
        }
    });
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: format!("compile.{label}"),
        compiled_at: "2026-09-12T18:20:00Z".to_owned(),
        project_id: "project.t07".to_owned(),
        project_name: "T07 fixture".to_owned(),
        workspace_roots: vec![snapshot.root.display().to_string()],
        goal_id: format!("goal.{label}"),
        goal_statement: goal_statement_override
            .unwrap_or_else(|| "Rename the Settings button from Save to Apply.".to_owned()),
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
        context_packet: packet.clone(),
        m3,
        max_model_calls: task_model_call_cap
            .and_then(|cap| u8::try_from(cap).ok())
            .filter(|cap| *cap > 0)
            .unwrap_or(1),
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let compilation = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    planner
        .unload()
        .unwrap_or_else(|error| panic!("unload planner: {error}"));
    CompiledFixture {
        repo,
        registry,
        packet,
        form_digest: form.digest,
        compilation: Some(compilation),
    }
}

fn valid_execution_proposal(form_digest: &str) -> String {
    execution_proposal(
        "src/settings/SettingsForm.tsx",
        form_digest,
        "Save",
        "Apply",
    )
}

fn execution_proposal(
    path: &str,
    source_digest: &str,
    old_literal: &str,
    new_literal: &str,
) -> String {
    json!({
        "schema_version": 1,
        "evidence_ids": [format!("file:repo.app:{path}")],
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

fn controller_for(fixture: &mut CompiledFixture) -> (Controller, String) {
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate: {error}"));
    (controller, activation.task_ids[0].clone())
}

fn readiness() -> ReadinessInputs<'static> {
    ReadinessInputs::permissive_m1("sha256:resources")
}

fn learning_procedure() -> ProcedurePattern {
    ProcedurePattern {
        subject: "workflow.settings-repair".to_owned(),
        summary: "Use exact evidence, apply one bounded replacement, then verify".to_owned(),
        steps: vec![
            "inspect exact failure and source evidence".to_owned(),
            "apply the bounded replacement and rerun deterministic verification".to_owned(),
        ],
    }
}

struct RuntimeParts {
    command_policy: CommandPolicy,
    isolation_request: IsolationRequest,
    artifacts: ArtifactStore,
    manifest: ToolManifest,
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

fn secret_tool_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.patch".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: WRITE_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
            PermissionClass::SecretUse,
        ]),
        declared_risk_floor: CommandRisk::ReadOnly,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    }
}

fn runtime_parts(fixture: &CompiledFixture) -> RuntimeParts {
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin python: {error}"));
    let root = python
        .path
        .parent()
        .unwrap_or_else(|| panic!("python parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([python], [root])
        .unwrap_or_else(|error| panic!("command policy: {error}"));
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
    RuntimeParts {
        command_policy,
        isolation_request: IsolationRequest {
            repository_root: fixture.repo.root.clone(),
            user_home_root: home,
            extra_protected_read_roots: Vec::new(),
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        },
        artifacts: ArtifactStore::open(fixture.repo.base.join("cas"))
            .unwrap_or_else(|error| panic!("artifacts: {error}")),
        manifest: write_tool_manifest(),
    }
}

fn execute_verified_replace(
    controller: &mut Controller,
    fixture: &CompiledFixture,
    task_id: &str,
    path: &str,
    source_digest: &str,
    old_literal: &str,
    new_literal: &str,
) -> ExecutionSuccess {
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive {task_id} ready lease: {error}"));
    let execution = backend(vec![model_response(
        execution_proposal(path, source_digest, old_literal, new_literal),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
        .unwrap_or_else(|error| {
            panic!("execute {task_id} {old_literal}->{new_literal} verified edit: {error}")
        })
}

fn assert_verification_journal_binding(controller: &Controller, success: &ExecutionSuccess) {
    let event = controller
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("verification journal: {error}"))
        .into_iter()
        .find(|event| {
            event.event_kind == "verification_recorded"
                && event.entity_id == success.verification.verification_id
        })
        .unwrap_or_else(|| panic!("real verification journal event missing"));
    let payload: Value = serde_json::from_str(&event.payload_json)
        .unwrap_or_else(|error| panic!("verification journal payload: {error}"));
    assert_eq!(
        payload.get("task_id").and_then(Value::as_str),
        Some(success.verification.task_id.as_str())
    );
    assert_eq!(
        payload.get("task_contract_digest").and_then(Value::as_str),
        Some(success.verification.task_contract_digest.as_str())
    );
    assert_eq!(
        payload.get("attempt_id").and_then(Value::as_str),
        Some(success.verification.attempt_id.as_str())
    );
}

fn assert_task_succeeded(controller: &Controller, task_id: &str) {
    assert_eq!(controller.task_state(task_id), Some(TaskState::Succeeded));
}

fn assert_repair_learning_origin(
    controller: &Controller,
    episode_assertion: &str,
    prior_attempt_id: &str,
    failure_record_digest: &str,
    task_id: &str,
) {
    let assertion: Value = serde_json::from_str(episode_assertion)
        .unwrap_or_else(|error| panic!("decode repaired learning assertion: {error}"));
    let repair_origin = assertion
        .pointer("/outcome_proof/repair_origin")
        .unwrap_or_else(|| panic!("repaired episode origin missing"));
    assert_eq!(
        repair_origin["prior_attempt_id"].as_str(),
        Some(prior_attempt_id)
    );
    assert_eq!(
        repair_origin["failure_record_digest"].as_str(),
        Some(failure_record_digest)
    );
    assert!(
        repair_origin["repair_packet_digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );
    let repair_event = controller
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("repair journal: {error}"))
        .into_iter()
        .find(|event| {
            event.entity_type == "controller" && event.event_kind == "repair_packet_built"
        })
        .unwrap_or_else(|| panic!("repair-packet journal event missing"));
    let payload: Value = serde_json::from_str(&repair_event.payload_json)
        .unwrap_or_else(|error| panic!("repair event payload: {error}"));
    assert_eq!(payload["task_id"].as_str(), Some(task_id));
}

fn execute_worktree_replace(
    controller: &mut Controller,
    fixture: &CompiledFixture,
    task_id: &str,
    path: &str,
    old_literal: &str,
    new_literal: &str,
) {
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive {task_id} ready lease: {error}"));
    let lease = controller
        .task_worktree_lease(task_id)
        .cloned()
        .unwrap_or_else(|| panic!("{task_id} worktree lease missing"));
    let source = fixture
        .registry
        .read_worktree_path(&lease, Path::new(path), None)
        .unwrap_or_else(|error| panic!("read {task_id} composed source {path}: {error}"));
    let execution = backend(vec![model_response(
        execution_proposal(path, &source.digest, old_literal, new_literal),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let success = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
        .unwrap_or_else(|error| panic!("execute {task_id} {old_literal}->{new_literal}: {error}"));
    assert!(success.verification.passed);
    assert_eq!(controller.task_state(task_id), Some(TaskState::Succeeded));
}

struct SwapIsolation {
    inner: MacSandboxExecBackend,
    executable: PathBuf,
    advance_epoch_db: Option<PathBuf>,
}

impl ExecutionIsolationBackend for SwapIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        self.inner.capabilities()
    }

    fn isolate(
        &self,
        _spec: &CommandSpec,
        _request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        if let Some(path) = &self.advance_epoch_db {
            let mut state = StateStore::open(path)
                .map_err(|error| PolicyError::Denied(format!("test epoch open failed: {error}")))?;
            state.advance_execution_epoch().map_err(|error| {
                PolicyError::Denied(format!("test epoch advance failed: {error}"))
            })?;
        }
        Ok(IsolatedCommand {
            executable: self.executable.clone(),
            args: Vec::new(),
        })
    }
}

struct PassthroughIsolation {
    capabilities: MacSandboxExecBackend,
}

impl ExecutionIsolationBackend for PassthroughIsolation {
    fn capabilities(&self) -> IsolationCapabilities {
        self.capabilities.capabilities()
    }

    fn isolate(
        &self,
        spec: &CommandSpec,
        _request: &IsolationRequest,
    ) -> Result<IsolatedCommand, PolicyError> {
        Ok(IsolatedCommand {
            executable: spec.executable.clone(),
            args: spec.args.clone(),
        })
    }
}

struct SentinelFailingSecretProvider {
    sentinel: String,
}

impl SecretProviderBackend for SentinelFailingSecretProvider {
    fn kind(&self) -> SecretProviderKind {
        SecretProviderKind::ExternalBroker
    }

    fn resolve(&self, _locator: &ControllerSecretLocator) -> Result<SecretValue, PolicyError> {
        Err(PolicyError::Denied(format!(
            "provider runtime failure leaked {}",
            self.sentinel
        )))
    }
}

struct CapturingBackend {
    inner: DeterministicFakeBackend,
    captured: Mutex<Vec<ModelRequest>>,
}

impl CapturingBackend {
    fn new() -> Self {
        let inner = DeterministicFakeBackend::new(
            ModelCapabilities {
                schema_version: MODEL_SCHEMA_VERSION,
                model_id: "fake-controller-capture".to_owned(),
                parameter_class: "fixture".to_owned(),
                quantization: "fixture".to_owned(),
                max_context_tokens: 16_384,
                supports_tools: false,
                supports_json_schema: true,
                local: true,
            },
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("capturing fake backend: {error}"));
        Self {
            inner,
            captured: Mutex::new(Vec::new()),
        }
    }

    fn captured(&self) -> Vec<ModelRequest> {
        self.captured
            .lock()
            .unwrap_or_else(|error| panic!("captured model requests lock: {error}"))
            .clone()
    }
}

impl ModelBackend for CapturingBackend {
    fn capabilities(&self) -> ModelCapabilities {
        self.inner.capabilities()
    }

    fn load(&self, profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.inner.load(profile)
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        self.captured
            .lock()
            .map_err(|_| ModelError::LockPoisoned("captured model requests"))?
            .push(request.clone());
        Err(ModelError::InvalidResponse("capture-stop".to_owned()))
    }

    fn count_tokens(&self, content: &str) -> Result<u32, ModelError> {
        self.inner.count_tokens(content)
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        self.inner.health()
    }

    fn residency_proof(&self) -> Result<ModelResidencyProof, ModelError> {
        self.inner.residency_proof()
    }

    fn unload(&self) -> Result<(), ModelError> {
        self.inner.unload()
    }
}

#[test]
fn strict_model_proposal_rejects_injected_state_success_and_permissions() {
    let injected = json!({
        "schema_version": 1,
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
        "task_state": "succeeded",
        "permissions": ["destructive"],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": format!("sha256:{}", "a".repeat(64)),
            "old_literal": "Save",
            "new_literal": "Apply",
            "expected_occurrences": 1,
            "success": true
        }
    });
    assert!(serde_json::from_value::<ModelProposalV1>(injected).is_err());
}

#[test]
fn readiness_requires_all_guard_classes_and_never_persists_ready_bit() {
    let mut fixture = compiled_fixture("readiness", true);
    let requirement_id = first_evidence_requirement_id(&fixture);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let Err(error) = controller.derive_ready_lease(
        &fixture.registry,
        &task_id,
        readiness(),
        &write_tool_manifest(),
    ) else {
        panic!("execution-gating evidence unexpectedly produced readiness")
    };
    assert!(error.to_string().contains("unsatisfied"));

    controller
        .record_exact_evidence_satisfaction(
            &fixture.registry,
            &task_id,
            &requirement_id,
            &fixture.packet,
            &["file:repo.app:src/settings/SettingsForm.tsx".to_owned()],
        )
        .unwrap_or_else(|error| panic!("record evidence satisfaction: {error}"));
    let lease = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready after evidence satisfaction: {error}"));
    controller
        .cancel_ready_lease(lease)
        .unwrap_or_else(|error| panic!("cancel readiness lease: {error}"));

    let persisted = controller
        .state()
        .get_state("controller.task", &task_id)
        .unwrap_or_else(|error| panic!("read task state: {error}"))
        .unwrap_or_else(|| panic!("missing task state"));
    assert!(!persisted.contains("\"ready\""));

    assert_eq!(
        controller.scheduler_view(&task_id),
        Some(SchedulerView::Blocked)
    );
}

#[test]
fn pause_is_durable_across_recovery_and_gates_readiness_until_resume() {
    let mut fixture = compiled_fixture("pause-recovery", true);
    let (mut controller, task_id) = controller_for(&mut fixture);
    controller
        .pause(Some("operator requested"))
        .unwrap_or_else(|error| panic!("pause: {error}"));
    assert!(
        controller
            .execution_control()
            .unwrap_or_else(|error| panic!("control: {error}"))
            .paused
    );
    let Err(error) = controller.derive_ready_lease(
        &fixture.registry,
        &task_id,
        readiness(),
        &write_tool_manifest(),
    ) else {
        panic!("paused controller unexpectedly derived readiness")
    };
    assert!(error.to_string().contains("paused"));
    drop(controller);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state: {error}"));
    let (mut recovered, _) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover paused controller: {error}"));
    assert!(
        recovered
            .execution_control()
            .unwrap_or_else(|error| panic!("recovered control: {error}"))
            .paused
    );
    let Err(error) = recovered.derive_ready_lease(
        &fixture.registry,
        &task_id,
        readiness(),
        &write_tool_manifest(),
    ) else {
        panic!("recovered paused controller unexpectedly derived readiness")
    };
    assert!(error.to_string().contains("paused"));

    recovered
        .resume()
        .unwrap_or_else(|error| panic!("resume: {error}"));
    assert!(
        !recovered
            .execution_control()
            .unwrap_or_else(|error| panic!("resumed control: {error}"))
            .paused
    );
}

#[test]
fn durable_status_exposes_controller_state_and_evidence_without_mutation_authority() {
    let mut fixture = compiled_fixture("status-view", true);
    let requirement_id = first_evidence_requirement_id(&fixture);
    let (mut controller, task_id) = controller_for(&mut fixture);
    controller
        .record_exact_evidence_satisfaction(
            &fixture.registry,
            &task_id,
            &requirement_id,
            &fixture.packet,
            &["file:repo.app:src/settings/SettingsForm.tsx".to_owned()],
        )
        .unwrap_or_else(|error| panic!("record evidence: {error}"));
    let before_sequence = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal before status: {error}"));
    drop(controller);
    let controller = Controller::new(
        StateStore::open(&fixture.repo.state_path)
            .unwrap_or_else(|error| panic!("reopen state for status: {error}")),
    );
    let view = controller
        .durable_status()
        .unwrap_or_else(|error| panic!("durable status: {error}"));
    let after_sequence = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal after status: {error}"));
    assert_eq!(before_sequence, after_sequence, "status read mutated state");
    assert!(view.active_plan.is_some());
    assert!(!view.tasks.is_empty());
    assert!(view.actions.is_empty());
    assert!(!view.evidence.is_empty());
    assert!(view.approval_requests.is_empty());
}

#[test]
fn durable_status_is_read_only_and_empty_before_plan_activation() {
    let fixture = TestRepo::create("status-before-plan");
    let mut controller = Controller::new(
        StateStore::open(&fixture.state_path)
            .unwrap_or_else(|error| panic!("open pre-plan state: {error}")),
    );
    let intent = controller
        .submit_goal_intent("Build inventory")
        .unwrap_or_else(|error| panic!("submit goal: {error}"));
    let before_sequence = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal before status: {error}"));

    let view = controller
        .durable_status()
        .unwrap_or_else(|error| panic!("pre-plan status: {error}"));
    let after_sequence = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal after status: {error}"));

    assert_eq!(before_sequence, after_sequence, "status read mutated state");
    assert!(view.active_plan.is_none());
    assert!(view.tasks.is_empty());
    assert!(view.attempts.is_empty());
    assert!(view.evidence.is_empty());
    assert!(view.approval_requests.is_empty());
    assert_eq!(view.goal_intents.len(), 1);
    assert_eq!(view.goal_intents[0].goal_id, intent.goal_id);
}

#[test]
fn durable_status_uses_only_durable_active_revision_rows_after_reopen() {
    let fixture = TestRepo::create("status-revision-scope");
    let mut state = StateStore::open(&fixture.state_path)
        .unwrap_or_else(|error| panic!("open revision-scoped status state: {error}"));
    let plan_id = "plan.status-scope";
    let current_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    state
        .put_state(
            "controller.plan",
            "active",
            &json!({
                "plan_id": plan_id,
                "goal_id": "goal.status-scope",
                "revision": 2,
                "plan_digest": current_digest,
                "compilation_evidence_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                "validity": "current"
            })
            .to_string(),
        )
        .unwrap_or_else(|error| panic!("write active status pointer: {error}"));
    state
        .put_state("controller.task", "task.rev1", r#"{"marker":"rev1-task"}"#)
        .unwrap_or_else(|error| panic!("write historical task: {error}"));
    state
        .put_state(
            "controller.task",
            &format!("{plan_id}@r2:task.rev2"),
            r#"{"marker":"rev2-task"}"#,
        )
        .unwrap_or_else(|error| panic!("write current task: {error}"));
    state
        .put_state(
            "controller.attempt",
            "attempt.rev1",
            r#"{"marker":"rev1-attempt"}"#,
        )
        .unwrap_or_else(|error| panic!("write historical attempt: {error}"));
    state
        .put_state(
            "controller.attempt",
            &format!("{plan_id}@r2:attempt.rev2"),
            r#"{"marker":"rev2-attempt"}"#,
        )
        .unwrap_or_else(|error| panic!("write current attempt: {error}"));
    state
        .put_state(
            "controller.verification",
            "verification.rev1",
            &json!({
                "plan_id": plan_id,
                "plan_revision": 1,
                "plan_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "marker": "rev1-verification"
            })
            .to_string(),
        )
        .unwrap_or_else(|error| panic!("write historical verification: {error}"));
    state
        .put_state(
            "controller.verification",
            &format!("{plan_id}@r2:verification.rev2"),
            &json!({
                "plan_id": plan_id,
                "plan_revision": 2,
                "plan_digest": current_digest,
                "marker": "rev2-verification"
            })
            .to_string(),
        )
        .unwrap_or_else(|error| panic!("write current verification: {error}"));
    state
        .put_state(
            "controller.evidence_item",
            "evidence.rev1",
            r#"{"marker":"rev1-evidence"}"#,
        )
        .unwrap_or_else(|error| panic!("write historical evidence: {error}"));
    state
        .put_state(
            "controller.evidence_item",
            &format!("{plan_id}@r2:evidence.rev2"),
            r#"{"marker":"rev2-evidence"}"#,
        )
        .unwrap_or_else(|error| panic!("write current evidence: {error}"));

    let view = Controller::new(state)
        .durable_status()
        .unwrap_or_else(|error| panic!("revision-scoped status: {error}"));

    assert_eq!(view.tasks, vec![json!({"marker": "rev2-task"})]);
    assert_eq!(view.attempts, vec![json!({"marker": "rev2-attempt"})]);
    assert_eq!(view.evidence.len(), 2);
    assert!(
        view.evidence
            .iter()
            .all(|value| !value.to_string().contains("rev1"))
    );
}

#[test]
fn exact_evidence_satisfaction_rejects_unrelated_retained_evidence() {
    let mut fixture = compiled_fixture("evidence-provenance", true);
    let requirement_id = first_evidence_requirement_id(&fixture);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let Err(error) = controller.record_exact_evidence_satisfaction(
        &fixture.registry,
        &task_id,
        &requirement_id,
        &fixture.packet,
        &["file:repo.app:src/settings/SettingsImport.tsx".to_owned()],
    ) else {
        panic!("unrelated retained evidence must not satisfy requirement")
    };
    assert!(error.to_string().contains("required exact path"));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
}

#[test]
fn stale_evidence_record_invalidates_ready_lease_before_model_dispatch() {
    let mut fixture = compiled_fixture("stale-evidence", true);
    let requirement_id = first_evidence_requirement_id(&fixture);
    let (mut controller, task_id) = controller_for(&mut fixture);
    controller
        .record_exact_evidence_satisfaction(
            &fixture.registry,
            &task_id,
            &requirement_id,
            &fixture.packet,
            &["file:repo.app:src/settings/SettingsForm.tsx".to_owned()],
        )
        .unwrap_or_else(|error| panic!("record evidence satisfaction: {error}"));
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive ready lease: {error}"));

    let mut second = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("second state: {error}"));
    let key = format!("{task_id}:{requirement_id}");
    let raw = second
        .get_state("controller.evidence_satisfaction", &key)
        .unwrap_or_else(|error| panic!("read evidence satisfaction: {error}"))
        .unwrap_or_else(|| panic!("evidence satisfaction missing"));
    let mut value: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse satisfaction: {error}"));
    value["plan_digest"] = Value::String(format!("sha256:{}", "f".repeat(64)));
    second
        .put_state("controller.evidence_satisfaction", &key, &value.to_string())
        .unwrap_or_else(|error| panic!("corrupt satisfaction binding: {error}"));

    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(4, 30_000);
    assert!(matches!(
        controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget),
        Err(ControllerError::NotReady(_))
    ));
    assert_eq!(budget.remaining_calls(), 4);
    assert_eq!(controller.task_model_calls_used(&task_id), Some(0));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn verified_upstream_bindings_make_dependent_task_ready_and_misbound_record_blocks_it() {
    let mut fixture = compiled_two_task_fixture("dependency-bindings");
    let contract = two_task_contract(&fixture);

    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate two-task plan: {error}"));
    assert_eq!(
        activation.task_ids,
        vec![contract.upstream.clone(), contract.downstream.clone()]
    );
    assert!(
        controller
            .derive_ready_lease(
                &fixture.registry,
                &contract.downstream,
                readiness(),
                &write_tool_manifest()
            )
            .is_err(),
        "dependent task must stay blocked before upstream verified success"
    );

    controller
        .record_exact_evidence_satisfaction(
            &fixture.registry,
            &contract.upstream,
            &contract.requirement,
            &fixture.packet,
            &["file:repo.app:src/settings/SettingsForm.tsx".to_owned()],
        )
        .unwrap_or_else(|error| panic!("satisfy upstream exact evidence: {error}"));
    let upstream_ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &contract.upstream,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("upstream ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(2, 30_000);
    controller
        .execute_replace(upstream_ready, &runtime, &fixture.packet, &mut budget)
        .unwrap_or_else(|error| panic!("execute upstream verified edit: {error}"));
    assert_eq!(
        controller.task_state(&contract.upstream),
        Some(TaskState::Succeeded)
    );
    let downstream_ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &contract.downstream,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("fresh verified dependency should be ready: {error}"));
    controller
        .cancel_ready_lease(downstream_ready)
        .unwrap_or_else(|error| panic!("cancel downstream readiness: {error}"));

    let binding_key = format!("{}:{}", contract.upstream, contract.artifact);
    let mut second = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("second state: {error}"));
    let raw = second
        .get_state("controller.artifact_binding", &binding_key)
        .unwrap_or_else(|error| panic!("read artifact binding: {error}"))
        .unwrap_or_else(|| panic!("artifact binding missing"));
    let mut value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("parse artifact binding: {error}"));
    value["plan_digest"] = Value::String(format!("sha256:{}", "e".repeat(64)));
    second
        .put_state(
            "controller.artifact_binding",
            &binding_key,
            &value.to_string(),
        )
        .unwrap_or_else(|error| panic!("tamper artifact binding: {error}"));
    assert!(
        controller
            .derive_ready_lease(
                &fixture.registry,
                &contract.downstream,
                readiness(),
                &write_tool_manifest()
            )
            .is_err(),
        "misbound dependency artifact must block readiness"
    );
}

#[test]
fn controller_learning_uses_real_verified_attempts_and_checkpoints_memory_journal() {
    let mut fixture = compiled_learning_two_path_fixture("controller-learning-success");
    let contract = two_task_contract(&fixture);
    let (mut controller, _) = controller_for(&mut fixture);
    controller
        .record_exact_evidence_satisfaction(
            &fixture.registry,
            &contract.upstream,
            &contract.requirement,
            &fixture.packet,
            &["file:repo.app:src/settings/SettingsForm.tsx".to_owned()],
        )
        .unwrap_or_else(|error| panic!("satisfy upstream evidence: {error}"));
    let first = execute_verified_replace(
        &mut controller,
        &fixture,
        &contract.upstream,
        "src/settings/SettingsForm.tsx",
        &fixture.form_digest,
        "Save",
        "Apply",
    );
    assert_verification_journal_binding(&controller, &first);
    let sequence_before_learning = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal before learning: {error}"));
    let first_episode = controller
        .record_attempt_episode(
            &first.attempt_id,
            Some(learning_procedure()),
            1_800_000_000_000,
        )
        .unwrap_or_else(|error| panic!("record first verified episode: {error}"));
    assert_eq!(first_episode.episode.kind, MemoryKind::Episodic);
    assert_eq!(first_episode.episode.trust, MemoryTrust::Observed);
    assert!(first_episode.candidate.is_none());
    assert_task_succeeded(&controller, &contract.upstream);

    let learned_sequence = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal after learning: {error}"));
    assert!(learned_sequence > sequence_before_learning);
    let floor = controller
        .state()
        .validate_checkpoint_integrity_floor(learned_sequence)
        .unwrap_or_else(|error| panic!("learning checkpoint floor: {error}"))
        .unwrap_or_else(|| panic!("learning checkpoint missing"));
    assert_eq!(floor.action_sequence, learned_sequence);
    assert_eq!(
        latest_checkpoint_manifest(controller.state()).action_journal_sequence,
        learned_sequence
    );

    let replay = controller
        .record_attempt_episode(
            &first.attempt_id,
            Some(learning_procedure()),
            1_800_000_000_001,
        )
        .unwrap_or_else(|error| panic!("replay first verified episode: {error}"));
    assert_eq!(replay.episode.id, first_episode.episode.id);
    assert!(replay.candidate.is_none());
    assert_eq!(
        controller
            .state()
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal after replay: {error}")),
        learned_sequence,
        "duplicate replay must not append support or checkpoint facts"
    );

    let current = ExactRetriever::new(&fixture.registry)
        .read_path("repo.app", Path::new("src/other.txt"), None)
        .unwrap_or_else(|error| panic!("read downstream source: {error}"));
    let second = execute_verified_replace(
        &mut controller,
        &fixture,
        &contract.downstream,
        "src/other.txt",
        &current.digest,
        "baseline other file",
        "updated other file",
    );
    let second_episode = controller
        .record_attempt_episode(
            &second.attempt_id,
            Some(learning_procedure()),
            1_800_000_000_002,
        )
        .unwrap_or_else(|error| panic!("record second verified episode: {error}"));
    let candidate = second_episode
        .candidate
        .unwrap_or_else(|| panic!("two distinct verified attempts must create a candidate"));
    assert_eq!(candidate.supporting_verified_episodes, 2);
    assert_eq!(candidate.record.kind, MemoryKind::ProceduralCandidate);
    assert_eq!(candidate.record.trust, MemoryTrust::Observed);
    assert_task_succeeded(&controller, &contract.downstream);
}

#[test]
fn controller_learning_rejects_tampered_real_verification_bytes() {
    let mut fixture = compiled_fixture("controller-learning-tamper", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let success = execute_verified_replace(
        &mut controller,
        &fixture,
        &task_id,
        "src/settings/SettingsForm.tsx",
        &fixture.form_digest,
        "Save",
        "Apply",
    );
    let mut second = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open verifier tamper state: {error}"));
    let record = second
        .state_records("controller.verification")
        .unwrap_or_else(|error| panic!("verification records: {error}"))
        .into_iter()
        .find(|record| record.value_json.contains(&success.attempt_id))
        .unwrap_or_else(|| panic!("verification row for learned attempt missing"));
    let mut value: Value = serde_json::from_str(&record.value_json)
        .unwrap_or_else(|error| panic!("decode verification row: {error}"));
    value["evidence_ids"] = json!(["tampered-after-controller-verification"]);
    second
        .put_state("controller.verification", &record.key, &value.to_string())
        .unwrap_or_else(|error| panic!("tamper verification row: {error}"));
    let Err(error) = controller.record_attempt_episode(
        &success.attempt_id,
        Some(learning_procedure()),
        1_800_000_100_000,
    ) else {
        panic!("tampered verification bytes must fail closed")
    };
    assert!(
        error
            .to_string()
            .contains("append-only passed journal evidence")
    );
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
}

#[test]
fn permission_context_is_controller_owned_and_can_deny_repo_write() {
    let mut fixture = compiled_fixture("permission-denied", false);
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller = Controller::with_permission_context(state, PermissionContext::read_only());
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate: {error}"));
    let Err(error) = controller.derive_ready_lease(
        &fixture.registry,
        &activation.task_ids[0],
        readiness(),
        &write_tool_manifest(),
    ) else {
        panic!("read-only permission context unexpectedly produced readiness")
    };
    assert!(error.to_string().contains("permission intersection"));
}

#[test]
fn m6_secret_use_requires_explicit_local_profile() {
    let mut fixture = compiled_fixture("m6-secret-profile-denied", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let Err(error) = controller.set_task_capability_grant(
        &task_id,
        CapabilitySet::new([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
            PermissionClass::SecretUse,
        ]),
    ) else {
        panic!("default local profile unexpectedly granted secret_use")
    };
    assert!(
        error
            .to_string()
            .contains("cannot exceed configured user authority")
    );
}

#[test]
fn m6_secret_profile_does_not_manufacture_missing_plan_secret_binding() {
    let mut fixture = compiled_fixture("m6-secret-plan-binding-denied", false);
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m6_local_secret_execution());
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate: {error}"));
    let task_id = &activation.task_ids[0];
    controller
        .set_task_capability_grant(
            task_id,
            CapabilitySet::new([
                PermissionClass::ProcessExec,
                PermissionClass::RepositoryWrite,
                PermissionClass::SecretUse,
            ]),
        )
        .unwrap_or_else(|error| panic!("explicit secret profile grant ceiling: {error}"));

    let Err(error) = controller.task_secret_ref(task_id, "secret.test") else {
        panic!("Controller profile/grant unexpectedly manufactured a Plan IR SecretRef")
    };
    assert!(
        error
            .to_string()
            .contains("does not bind SecretRef secret.test")
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn m6_secret_provider_failure_never_persists_or_returns_provider_free_text() {
    let (mut fixture, secret_ref) = compiled_secret_fixture("m6-secret-provider-error-redaction");
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m6_local_secret_execution());
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled secret fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate secret fixture: {error}"));
    let task_id = &activation.task_ids[0];
    let manifest = secret_tool_manifest();
    let ready = controller
        .derive_ready_lease(&fixture.registry, task_id, readiness(), &manifest)
        .unwrap_or_else(|error| panic!("secret readiness: {error}"));

    let sentinel = "T07-PROVIDER-RUNTIME-SECRET-SENTINEL".to_owned();
    let mut broker = SecretBroker::new();
    broker
        .register_provider(Arc::new(SentinelFailingSecretProvider {
            sentinel: sentinel.clone(),
        }))
        .unwrap_or_else(|error| panic!("register failing secret provider: {error}"));
    broker
        .register_secret(
            secret_ref.clone(),
            ControllerSecretLocator::FakeKey {
                provider: SecretProviderKind::ExternalBroker,
                key: "provider-error-sentinel".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("register exact failing secret handle: {error}"));

    let parts = runtime_parts(&fixture);
    let mut isolation_request = parts.isolation_request.clone();
    isolation_request.allow_repository_write = false;
    let isolation = PassthroughIsolation {
        capabilities: MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("seatbelt capability source: {error}")),
    };
    let private_root = fixture.repo.base.join("controller-private-secrets");
    let runtime = SecretProcessRuntime {
        registry: &fixture.registry,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &manifest,
        secret_broker: &broker,
        controller_private_root: &private_root,
    };
    let command = CommandSpec {
        executable: PathBuf::from("/usr/bin/python3"),
        args: vec!["-I".to_owned(), "-c".to_owned(), "pass".to_owned()],
        working_directory: fixture.repo.root.clone(),
        environment: BTreeMap::new(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::ReadOnly,
        timeout_ms: 5_000,
        output_limit_bytes: 64 * 1024,
        disk_write_limit_bytes: 64 * 1024,
        subprocess_limit: 1,
    };
    let error = controller
        .execute_secret_process(ready, &runtime, &secret_ref.secret_ref_id, command)
        .err()
        .unwrap_or_else(|| panic!("failing provider unexpectedly executed"));
    let public_error = error.to_string();
    assert!(!public_error.contains(&sentinel));
    assert!(public_error.contains("provider details withheld"));

    let failure_rows = controller
        .state()
        .state_records("controller.failure_record")
        .unwrap_or_else(|error| panic!("failure rows: {error}"));
    assert!(
        !failure_rows.is_empty(),
        "provider failure must route a durable FailureRecord"
    );
    for row in &failure_rows {
        assert!(!row.value_json.contains(&sentinel));
        let value: Value = serde_json::from_str(&row.value_json)
            .unwrap_or_else(|error| panic!("decode provider failure row: {error}"));
        assert!(
            value["synopsis"].as_str().is_some_and(|synopsis| synopsis
                .contains("Controller secret resolution denied; provider details withheld")),
            "durable provider failure synopsis must contain only the safe diagnostic"
        );
    }
    for row in controller
        .state()
        .state_records("controller.repair_packet")
        .unwrap_or_else(|error| panic!("repair rows: {error}"))
    {
        assert!(!row.value_json.contains(&sentinel));
    }
    for event in controller
        .state()
        .journal_after(0)
        .unwrap_or_else(|error| panic!("provider failure journal: {error}"))
    {
        assert!(!event.payload_json.contains(&sentinel));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn m6_unresolved_historical_secret_lifecycle_fences_live_authority() {
    let (mut fixture, secret_ref) = compiled_secret_fixture("m6-live-secret-lifecycle-fence");
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m6_local_secret_execution());
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled secret fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate secret fixture: {error}"));
    let task_id = activation.task_ids[0].clone();
    let task_contract_digest = controller
        .task_contract_digest(&task_id)
        .unwrap_or_else(|| panic!("secret task contract digest"))
        .to_owned();
    let write_manifest = write_tool_manifest();
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &write_manifest)
        .unwrap_or_else(|error| panic!("pre-marker readiness: {error}"));
    let before = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read target before fenced mutation: {error}"));
    let manifest = latest_checkpoint_manifest(controller.state());
    let execution_epoch = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("live fence epoch: {error}"));

    let action_id = "action.m6-historical-unresolved".to_owned();
    let marker_revision = manifest.plan_revision.saturating_sub(1);
    let marker = json!({
        "schema_version": 1,
        "plan_id": manifest.plan_id,
        "plan_revision": marker_revision,
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "action_id": action_id,
        "permission_decision_digest": sha256_prefixed(b"historical-unresolved-permission"),
        "execution_epoch": execution_epoch,
        "secret_ref_binding_digest": secret_ref
            .binding_digest()
            .unwrap_or_else(|error| panic!("secret ref binding digest: {error}")),
        "provider": "external_broker",
        "injection": "temporary_file",
        "target": EPHEMERAL_SECRET_FILE_ENV,
        "expires_at_ms": 1_900_000_000_000_i64,
        "action_payload_digest": sha256_prefixed(b"historical-unresolved-action"),
        "state": "cleanup_proven",
        "result_digest": Value::Null,
    });
    let marker_json = serde_json::to_string(&marker)
        .unwrap_or_else(|error| panic!("encode historical marker: {error}"));
    let marker_digest = sha256_prefixed(marker_json.as_bytes());
    let marker_event_payload = json!({
        "plan_id": manifest.plan_id,
        "plan_revision": marker_revision,
        "plan_digest": manifest.plan_digest,
        "secret_action_lifecycle": marker,
        "record_digest": marker_digest,
    })
    .to_string();
    let mut external_state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open external marker writer: {error}"));
    external_state
        .put_state_records_with_events(
            &[StateRecordUpdate {
                namespace: "controller.secret_action_lifecycle",
                key: &action_id,
                value_json: &marker_json,
            }],
            &[NewJournalEvent {
                event_id: "event.m6-historical-unresolved.cleanup-proven",
                entity_type: "controller",
                entity_id: &action_id,
                event_kind: "secret_action_cleanup_proven",
                payload_json: &marker_event_payload,
            }],
        )
        .unwrap_or_else(|error| panic!("persist historical unresolved marker: {error}"));
    drop(external_state);

    let readiness_error = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &write_manifest)
        .err()
        .unwrap_or_else(|| panic!("unresolved historical marker unexpectedly allowed readiness"));
    assert!(
        readiness_error
            .to_string()
            .contains("secret action lifecycle blocked")
    );

    let grant_error = controller
        .set_task_capability_grant(
            &task_id,
            CapabilitySet::new([
                PermissionClass::ProcessExec,
                PermissionClass::RepositoryWrite,
                PermissionClass::SecretUse,
            ]),
        )
        .err()
        .unwrap_or_else(|| {
            panic!("unresolved historical marker unexpectedly allowed grant mutation")
        });
    assert!(
        grant_error
            .to_string()
            .contains("secret action lifecycle blocked")
    );

    let classification = FailureClassification {
        kind: FailureClassificationKind::PlanFailure,
        scope: None,
        affected_task_ids: vec![task_id.clone()],
        affected_contract_ids: Vec::new(),
        evidence_refs: Vec::new(),
    };
    let replan_error = controller
        .replan_input(&classification)
        .err()
        .unwrap_or_else(|| {
            panic!("unresolved historical marker unexpectedly allowed replan input")
        });
    assert!(
        replan_error
            .to_string()
            .contains("secret action lifecycle blocked")
    );

    let mut unrelated = compiled_fixture("m6-live-fence-supersession-candidate", false);
    let unrelated_compilation = unrelated
        .compilation
        .take()
        .unwrap_or_else(|| panic!("supersession candidate compilation"));
    let supersession_error = controller
        .activate_superseding_revision(unrelated_compilation, &classification, &fixture.registry)
        .err()
        .unwrap_or_else(|| {
            panic!("unresolved historical marker unexpectedly allowed supersession")
        });
    assert!(
        supersession_error
            .to_string()
            .contains("secret action lifecycle blocked")
    );

    let execution = backend(vec![model_response(
        execution_proposal(
            "src/settings/SettingsForm.tsx",
            &fixture.form_digest,
            "Save",
            "Apply",
        ),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let mutation_error = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
        .err()
        .unwrap_or_else(|| panic!("pre-existing ready lease bypassed unresolved marker fence"));
    assert!(
        mutation_error
            .to_string()
            .contains("secret action lifecycle blocked")
    );
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read target after fenced mutation: {error}")),
        before,
        "unresolved secret lifecycle must block mutation before repository change"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn m6_secret_process_redacts_binary_sentinel_closes_lease_and_stops_at_verifying() {
    let (mut fixture, secret_ref) = compiled_secret_fixture("m6-secret-sentinel");
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m6_local_secret_execution());
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled secret fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate secret fixture: {error}"));
    let task_id = &activation.task_ids[0];
    let manifest = secret_tool_manifest();
    let ready = controller
        .derive_ready_lease(&fixture.registry, task_id, readiness(), &manifest)
        .unwrap_or_else(|error| panic!("secret readiness: {error}"));

    let sentinel = b"T07-SECRET-\xff-\x00-SENTINEL".to_vec();
    let mut broker = SecretBroker::new();
    broker
        .register_provider(Arc::new(FakeSecretProvider::new(
            SecretProviderKind::ExternalBroker,
            [("sentinel-key".to_owned(), sentinel.clone())],
        )))
        .unwrap_or_else(|error| panic!("register fake secret provider: {error}"));
    broker
        .register_secret(
            secret_ref.clone(),
            ControllerSecretLocator::FakeKey {
                provider: SecretProviderKind::ExternalBroker,
                key: "sentinel-key".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("register exact secret handle: {error}"));

    let parts = runtime_parts(&fixture);
    let mut isolation_request = parts.isolation_request.clone();
    isolation_request.allow_repository_write = false;
    let isolation = PassthroughIsolation {
        capabilities: MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("seatbelt capability source: {error}")),
    };
    let private_root = fixture.repo.base.join("controller-private-secrets");
    let runtime = SecretProcessRuntime {
        registry: &fixture.registry,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &manifest,
        secret_broker: &broker,
        controller_private_root: &private_root,
    };
    let command = CommandSpec {
        executable: PathBuf::from("/usr/bin/python3"),
        args: vec![
            "-I".to_owned(),
            "-c".to_owned(),
            "import os,sys; p=os.environ['SOVEREIGN_SECRET_FILE']; b=open(p,'rb').read(); sys.stdout.buffer.write(b); sys.stderr.buffer.write(b)".to_owned(),
        ],
        working_directory: fixture.repo.root.clone(),
        environment: BTreeMap::new(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::ReadOnly,
        timeout_ms: 5_000,
        output_limit_bytes: 64 * 1024,
        disk_write_limit_bytes: 64 * 1024,
        subprocess_limit: 1,
    };
    let raw = controller
        .execute_secret_process(ready, &runtime, &secret_ref.secret_ref_id, command)
        .unwrap_or_else(|error| panic!("execute secret sentinel: {error}"));
    assert_eq!(raw.exit_code, Some(0));
    assert!(raw.process_group_reaped);
    assert!(
        !raw.stdout
            .windows(sentinel.len())
            .any(|window| window == sentinel)
    );
    assert!(
        !raw.stderr
            .windows(sentinel.len())
            .any(|window| window == sentinel)
    );
    assert_eq!(raw.stdout, b"[REDACTED]");
    assert_eq!(raw.stderr, b"[REDACTED]");
    assert_eq!(controller.task_state(task_id), Some(TaskState::Verifying));

    let action = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("secret action records: {error}"))
        .into_iter()
        .find(|record| record.state == "committed" && record.result_digest.is_some())
        .unwrap_or_else(|| panic!("committed secret action record"));
    let action_id = action.action_id.clone();
    let receipt_digest = action
        .result_digest
        .clone()
        .unwrap_or_else(|| panic!("secret action result digest"));
    let lifecycle_raw = controller
        .state()
        .get_state("controller.secret_action_lifecycle", &action_id)
        .unwrap_or_else(|error| panic!("secret lifecycle marker: {error}"))
        .unwrap_or_else(|| panic!("secret lifecycle marker missing"));
    let lifecycle: Value = serde_json::from_str(&lifecycle_raw)
        .unwrap_or_else(|error| panic!("decode secret lifecycle marker: {error}"));
    assert_eq!(lifecycle["state"], json!("complete"));
    assert_eq!(lifecycle["action_id"], json!(action_id));
    assert_eq!(lifecycle["result_digest"], json!(receipt_digest));
    assert_eq!(lifecycle["provider"], json!("external_broker"));
    assert_eq!(lifecycle["injection"], json!("temporary_file"));
    assert_eq!(lifecycle["target"], json!(EPHEMERAL_SECRET_FILE_ENV));
    assert!(!lifecycle_raw.contains("sentinel-key"));
    let receipt_path = parts
        .artifacts
        .root()
        .join("sha256")
        .join(&receipt_digest[..2])
        .join(&receipt_digest);
    let receipt = fs::read(receipt_path).unwrap_or_else(|error| panic!("secret receipt: {error}"));
    assert!(
        !receipt
            .windows(sentinel.len())
            .any(|window| window == sentinel)
    );
    assert!(
        fs::read_dir(&private_root)
            .unwrap_or_else(|error| panic!("private secret root: {error}"))
            .next()
            .is_none(),
        "secret task/action injection directories must be absent after committed execution"
    );
    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen complete secret lifecycle: {error}"));
    let (_, recovery) = RecoveryManager::recover_with_permission_context(
        state,
        &fixture.registry,
        PermissionContext::m6_local_secret_execution(),
    )
    .unwrap_or_else(|error| panic!("complete secret lifecycle must recover: {error}"));
    assert!(
        !recovery.mutation_blocked,
        "complete secret lifecycle must not become a recovery blocker"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn m6_runtime_secret_failure_never_reaches_persistence_context_or_local_model_request() {
    let (mut fixture, secret_ref) = compiled_secret_fixture("m6-secret-runtime-persistence");
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m6_local_secret_execution());
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled secret fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate secret fixture: {error}"));
    let task_id = activation.task_ids[0].clone();
    let secret_manifest = secret_tool_manifest();
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &secret_manifest)
        .unwrap_or_else(|error| panic!("secret readiness: {error}"));

    let sentinel = runtime_secret_sentinel("m6-secret-runtime-persistence");
    let mut raw_stdout = b"stdout:".to_vec();
    raw_stdout.extend_from_slice(&sentinel);
    let mut raw_stderr = b"stderr:".to_vec();
    raw_stderr.extend_from_slice(&sentinel);
    let mut broker = SecretBroker::new();
    broker
        .register_provider(Arc::new(FakeSecretProvider::new(
            SecretProviderKind::ExternalBroker,
            [("runtime-sentinel-key".to_owned(), sentinel.clone())],
        )))
        .unwrap_or_else(|error| panic!("register runtime fake secret provider: {error}"));
    broker
        .register_secret(
            secret_ref.clone(),
            ControllerSecretLocator::FakeKey {
                provider: SecretProviderKind::ExternalBroker,
                key: "runtime-sentinel-key".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("register runtime secret handle: {error}"));

    let parts = runtime_parts(&fixture);
    let mut secret_isolation_request = parts.isolation_request.clone();
    secret_isolation_request.allow_repository_write = false;
    let isolation = PassthroughIsolation {
        capabilities: MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("seatbelt capability source: {error}")),
    };
    let private_root = fixture.repo.base.join("controller-private-secrets");
    let secret_runtime = SecretProcessRuntime {
        registry: &fixture.registry,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &secret_isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &secret_manifest,
        secret_broker: &broker,
        controller_private_root: &private_root,
    };
    let command = CommandSpec {
        executable: PathBuf::from("/usr/bin/python3"),
        args: vec![
            "-I".to_owned(),
            "-c".to_owned(),
            "import os,sys; p=os.environ['SOVEREIGN_SECRET_FILE']; b=open(p,'rb').read(); sys.stdout.buffer.write(b'stdout:'+b); sys.stderr.buffer.write(b'stderr:'+b); sys.exit(7)".to_owned(),
        ],
        working_directory: fixture.repo.root.clone(),
        environment: BTreeMap::new(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::ReadOnly,
        timeout_ms: 5_000,
        output_limit_bytes: 64 * 1024,
        disk_write_limit_bytes: 64 * 1024,
        subprocess_limit: 1,
    };
    let error = controller
        .execute_secret_process(ready, &secret_runtime, &secret_ref.secret_ref_id, command)
        .err()
        .unwrap_or_else(|| panic!("nonzero secret child unexpectedly succeeded"));
    let ControllerError::ExecutionFailed(failure) = error else {
        panic!("nonzero secret child must route as ExecutionFailed, got {error}")
    };
    assert_eq!(failure.exit_code, Some(7));
    assert_eq!(failure.decision, "repair");
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    let failure_json = serde_json::to_vec(failure.as_ref())
        .unwrap_or_else(|error| panic!("serialize secret failure record: {error}"));
    assert!(
        !failure_json
            .windows(sentinel.len())
            .any(|window| window == sentinel)
    );
    assert!(failure.synopsis.contains("[REDACTED]"));

    for event in controller
        .state()
        .journal_after(0)
        .unwrap_or_else(|error| panic!("secret failure journal: {error}"))
    {
        assert!(
            !event
                .payload_json
                .as_bytes()
                .windows(sentinel.len())
                .any(|window| window == sentinel),
            "journal event {} leaked runtime secret bytes",
            event.event_id
        );
    }
    for record in controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("secret action records: {error}"))
    {
        let encoded = serde_json::to_vec(&json!({
            "action_id": record.action_id,
            "state": record.state,
            "payload_digest": record.payload_digest,
            "policy_digest": record.policy_digest,
            "execution_epoch": record.execution_epoch,
            "result_digest": record.result_digest,
            "last_event_sequence": record.last_event_sequence,
            "updated_at_ms": record.updated_at_ms,
        }))
        .unwrap_or_else(|error| panic!("encode action record: {error}"));
        assert!(
            !encoded
                .windows(sentinel.len())
                .any(|window| window == sentinel)
        );
    }
    assert!(
        fs::read_dir(&private_root)
            .unwrap_or_else(|error| panic!("runtime private secret root: {error}"))
            .next()
            .is_none(),
        "failed secret process must remove its task/action private injection directories"
    );

    let capture = CapturingBackend::new();
    let repair_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &capture,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &secret_manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut repair_budget = ModelCallBudget::new(1, 30_000);
    let repair_error = controller
        .repair_replace(
            &task_id,
            &repair_runtime,
            &fixture.packet,
            &[],
            readiness(),
            &mut repair_budget,
        )
        .err()
        .unwrap_or_else(|| panic!("capturing repair backend unexpectedly returned a proposal"));
    assert!(repair_error.to_string().contains("capture-stop"));

    let repair_row = controller
        .state()
        .state_records("controller.repair_packet")
        .unwrap_or_else(|error| panic!("repair packet rows: {error}"))
        .into_iter()
        .find(|record| record.value_json.contains(&task_id))
        .unwrap_or_else(|| panic!("production repair packet missing"));
    let repair_packet: RepairPacket = serde_json::from_str(&repair_row.value_json)
        .unwrap_or_else(|error| panic!("decode production repair packet: {error}"));
    let repair_context_bytes = serde_json::to_vec(&repair_packet.context)
        .unwrap_or_else(|error| panic!("serialize repair ContextPacket: {error}"));
    assert!(
        !repair_context_bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel),
        "Controller-built repair ContextPacket leaked runtime secret bytes"
    );

    let captured = capture.captured();
    assert_eq!(
        captured.len(),
        1,
        "repair must reach exactly one local ModelRequest boundary"
    );
    let request = &captured[0];
    assert!(request.tools.is_empty());
    assert_eq!(request.messages.len(), 2);
    assert_eq!(
        request.messages[1].content, repair_packet.context.serialized_input,
        "captured user message must be the exact production repair ContextPacket input"
    );
    let request_bytes = serde_json::to_vec(request)
        .unwrap_or_else(|error| panic!("serialize captured ModelRequest: {error}"));
    assert!(
        !request_bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel),
        "local ModelRequest leaked runtime secret bytes"
    );

    let checkpoint = latest_checkpoint_manifest(controller.state());
    let checkpoint_bytes = serde_json::to_vec(&checkpoint)
        .unwrap_or_else(|error| panic!("serialize checkpoint manifest: {error}"));
    assert!(
        !checkpoint_bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel),
        "checkpoint manifest leaked runtime secret bytes"
    );
    assert_runtime_persistence_excludes_secret(
        &fixture.repo,
        &parts.artifacts,
        &sentinel,
        &raw_stdout,
        &raw_stderr,
    );
}

#[allow(clippy::too_many_lines)]
fn assert_incomplete_secret_lifecycle_recovery_blocked(
    label: &str,
    lifecycle_state: &str,
    lifecycle_event_kind: &str,
    commit_action: bool,
    marker_revision_override: Option<u32>,
    expected_state_debug: &str,
) {
    let (mut fixture, secret_ref) = compiled_secret_fixture(label);
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m6_local_secret_execution());
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled secret fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate secret fixture: {error}"));
    let task_id = activation.task_ids[0].clone();
    let task_contract_digest = controller
        .task_contract_digest(&task_id)
        .unwrap_or_else(|| panic!("secret task contract digest"))
        .to_owned();
    let manifest = latest_checkpoint_manifest(controller.state());
    let execution_epoch = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("secret recovery epoch: {error}"));
    drop(controller);

    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen crash state: {error}"));
    let result_store = ArtifactStore::open(fixture.repo.base.join("cas"))
        .unwrap_or_else(|error| panic!("secret crash result store: {error}"));
    let result = result_store
        .put(&mut state, format!("sanitized-{label}-result").as_bytes())
        .unwrap_or_else(|error| panic!("secret crash result artifact: {error}"));
    let action_id = format!("action.{label}");
    let payload_digest = sha256_prefixed(format!("payload-{label}").as_bytes());
    let prepared_event_id = format!("event.{label}.prepared");
    state
        .insert_action_record(NewActionRecord {
            action_id: &action_id,
            state: "prepared",
            payload_digest: &payload_digest,
            policy_digest: &manifest.policy_digest,
            execution_epoch,
            event_id: &prepared_event_id,
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert secret crash action: {error}"));
    let observed_event_id = format!("event.{label}.observed");
    state
        .transition_action_with_event(ActionTransition {
            action_id: &action_id,
            expected_state: "prepared",
            next_state: "observed",
            expected_epoch: execution_epoch,
            event_id: &observed_event_id,
            event_kind: "observed",
            payload_json: "{}",
            result_digest: Some(&result.digest),
        })
        .unwrap_or_else(|error| panic!("observe secret crash action: {error}"));

    let marker_revision = marker_revision_override.unwrap_or(manifest.plan_revision);
    let marker = json!({
        "schema_version": 1,
        "plan_id": manifest.plan_id,
        "plan_revision": marker_revision,
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "action_id": action_id,
        "permission_decision_digest": sha256_prefixed(format!("permission-{label}").as_bytes()),
        "execution_epoch": execution_epoch,
        "secret_ref_binding_digest": secret_ref
            .binding_digest()
            .unwrap_or_else(|error| panic!("secret ref binding digest: {error}")),
        "provider": "external_broker",
        "injection": "temporary_file",
        "target": EPHEMERAL_SECRET_FILE_ENV,
        "expires_at_ms": 1_900_000_000_000_i64,
        "action_payload_digest": payload_digest,
        "state": lifecycle_state,
        "result_digest": Value::Null,
    });
    let marker_json = serde_json::to_string(&marker)
        .unwrap_or_else(|error| panic!("encode secret crash marker: {error}"));
    let marker_digest = sha256_prefixed(marker_json.as_bytes());
    let marker_event_payload = json!({
        "plan_id": manifest.plan_id,
        "plan_revision": marker_revision,
        "plan_digest": manifest.plan_digest,
        "secret_action_lifecycle": marker,
        "record_digest": marker_digest,
    })
    .to_string();
    let marker_event_id = format!("event.{label}.{lifecycle_state}");
    state
        .put_state_records_with_events(
            &[StateRecordUpdate {
                namespace: "controller.secret_action_lifecycle",
                key: &action_id,
                value_json: &marker_json,
            }],
            &[NewJournalEvent {
                event_id: &marker_event_id,
                entity_type: "controller",
                entity_id: &action_id,
                event_kind: lifecycle_event_kind,
                payload_json: &marker_event_payload,
            }],
        )
        .unwrap_or_else(|error| panic!("persist secret crash marker: {error}"));

    if commit_action {
        let committed_event_id = format!("event.{label}.committed");
        state
            .transition_action_with_event(ActionTransition {
                action_id: &action_id,
                expected_state: "observed",
                next_state: "committed",
                expected_epoch: execution_epoch,
                event_id: &committed_event_id,
                event_kind: "committed",
                payload_json: "{}",
                result_digest: Some(&result.digest),
            })
            .unwrap_or_else(|error| panic!("commit secret crash action: {error}"));
    }

    let epoch_before_recovery = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch before blocked recovery: {error}"));
    let sequence_before_recovery = state
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("sequence before blocked recovery: {error}"));
    drop(state);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open blocked secret recovery state: {error}"));
    let error = RecoveryManager::recover_with_permission_context(
        state,
        &fixture.registry,
        PermissionContext::m6_local_secret_execution(),
    )
    .err()
    .unwrap_or_else(|| panic!("incomplete secret lifecycle {lifecycle_state} must block recovery"));
    assert!(
        error.to_string().contains("secret action recovery blocked")
            && error.to_string().contains(expected_state_debug),
        "unexpected secret recovery blocker for {lifecycle_state}: {error}"
    );

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state after blocked recovery: {error}"));
    assert_eq!(
        state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("epoch after blocked recovery: {error}")),
        epoch_before_recovery,
        "blocked recovery must not advance execution authority"
    );
    assert_eq!(
        state
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("sequence after blocked recovery: {error}")),
        sequence_before_recovery,
        "blocked recovery must not replay, commit, or append recovery state"
    );
    assert_eq!(
        state
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("secret crash action after recovery: {error}"))
            .map(|record| record.state),
        Some(
            if commit_action {
                "committed"
            } else {
                "observed"
            }
            .to_owned()
        ),
        "recovery must not reinterpret or replay the crashed action"
    );
}

#[test]
fn m6_recovery_blocks_all_incomplete_secret_lifecycle_crash_windows() {
    assert_incomplete_secret_lifecycle_recovery_blocked(
        "m6-cleanup-proven-before-close",
        "cleanup_proven",
        "secret_action_cleanup_proven",
        false,
        None,
        "CleanupProven",
    );
    assert_incomplete_secret_lifecycle_recovery_blocked(
        "m6-lease-closed-before-commit",
        "lease_closed",
        "secret_action_lease_closed",
        false,
        None,
        "LeaseClosed",
    );
    assert_incomplete_secret_lifecycle_recovery_blocked(
        "m6-commit-before-complete",
        "lease_closed",
        "secret_action_lease_closed",
        true,
        None,
        "LeaseClosed",
    );
    assert_incomplete_secret_lifecycle_recovery_blocked(
        "m6-old-revision-unresolved",
        "cleanup_proven",
        "secret_action_cleanup_proven",
        false,
        Some(0),
        "CleanupProven",
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn m6_recovery_blocks_observed_secret_action_without_durable_cleanup_or_lease_close() {
    let (mut fixture, secret_ref) = compiled_secret_fixture("m6-secret-recovery-block");
    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m6_local_secret_execution());
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("compiled secret fixture already activated"));
    let activation = controller
        .activate(compilation, &fixture.registry)
        .unwrap_or_else(|error| panic!("activate secret fixture: {error}"));
    let task_id = activation.task_ids[0].clone();
    let task_contract_digest = controller
        .task_contract_digest(&task_id)
        .unwrap_or_else(|| panic!("secret task contract digest"))
        .to_owned();
    let manifest = latest_checkpoint_manifest(controller.state());
    let execution_epoch = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("secret recovery epoch: {error}"));
    drop(controller);

    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen crash state: {error}"));
    let result_store = ArtifactStore::open(fixture.repo.base.join("cas"))
        .unwrap_or_else(|error| panic!("secret crash result store: {error}"));
    let result = result_store
        .put(&mut state, b"sanitized observed secret result")
        .unwrap_or_else(|error| panic!("secret crash result artifact: {error}"));
    let action_id = "action.secret-observed-before-cleanup".to_owned();
    let payload_digest = sha256_prefixed(b"secret-observed-before-cleanup-payload");
    state
        .insert_action_record(NewActionRecord {
            action_id: &action_id,
            state: "prepared",
            payload_digest: &payload_digest,
            policy_digest: &manifest.policy_digest,
            execution_epoch,
            event_id: "event.secret-crash-prepared",
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert secret crash action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: &action_id,
            expected_state: "prepared",
            next_state: "observed",
            expected_epoch: execution_epoch,
            event_id: "event.secret-crash-observed",
            event_kind: "observed",
            payload_json: "{}",
            result_digest: Some(&result.digest),
        })
        .unwrap_or_else(|error| panic!("observe secret crash action: {error}"));

    let marker = json!({
        "schema_version": 1,
        "plan_id": manifest.plan_id,
        "plan_revision": manifest.plan_revision,
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "action_id": action_id,
        "permission_decision_digest": sha256_prefixed(b"secret-crash-permission-decision"),
        "execution_epoch": execution_epoch,
        "secret_ref_binding_digest": secret_ref
            .binding_digest()
            .unwrap_or_else(|error| panic!("secret ref binding digest: {error}")),
        "provider": "external_broker",
        "injection": "temporary_file",
        "target": EPHEMERAL_SECRET_FILE_ENV,
        "expires_at_ms": 1_900_000_000_000_i64,
        "action_payload_digest": payload_digest,
        "state": "pending_cleanup",
        "result_digest": Value::Null,
    });
    let marker_json = serde_json::to_string(&marker)
        .unwrap_or_else(|error| panic!("encode secret crash marker: {error}"));
    let marker_digest = sha256_prefixed(marker_json.as_bytes());
    let marker_event_payload = json!({
        "plan_id": manifest.plan_id,
        "plan_revision": manifest.plan_revision,
        "plan_digest": manifest.plan_digest,
        "secret_action_lifecycle": marker,
        "record_digest": marker_digest,
    })
    .to_string();
    state
        .put_state_records_with_events(
            &[StateRecordUpdate {
                namespace: "controller.secret_action_lifecycle",
                key: &action_id,
                value_json: &marker_json,
            }],
            &[NewJournalEvent {
                event_id: "event.secret-crash-pending-cleanup",
                entity_type: "controller",
                entity_id: &action_id,
                event_kind: "secret_action_pending_cleanup",
                payload_json: &marker_event_payload,
            }],
        )
        .unwrap_or_else(|error| panic!("persist secret crash marker: {error}"));
    let epoch_before_recovery = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch before blocked recovery: {error}"));
    let sequence_before_recovery = state
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("sequence before blocked recovery: {error}"));
    drop(state);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open blocked secret recovery state: {error}"));
    let error = RecoveryManager::recover_with_permission_context(
        state,
        &fixture.registry,
        PermissionContext::m6_local_secret_execution(),
    )
    .err()
    .unwrap_or_else(|| panic!("observed secret action without cleanup proof must block recovery"));
    assert!(
        error.to_string().contains("secret action recovery blocked")
            && error.to_string().contains("PendingCleanup"),
        "unexpected secret recovery blocker: {error}"
    );

    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state after blocked recovery: {error}"));
    assert_eq!(
        state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("epoch after blocked recovery: {error}")),
        epoch_before_recovery,
        "blocked recovery must not advance execution authority"
    );
    assert_eq!(
        state
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("sequence after blocked recovery: {error}")),
        sequence_before_recovery,
        "blocked recovery must not replay, commit, or append recovery state"
    );
    assert_eq!(
        state
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("secret crash action after recovery: {error}"))
            .map(|record| record.state),
        Some("observed".to_owned()),
        "Observed alone must never imply temp cleanup or SecretLease closure"
    );
    let durable_marker = state
        .get_state("controller.secret_action_lifecycle", &action_id)
        .unwrap_or_else(|error| panic!("durable secret crash marker: {error}"))
        .unwrap_or_else(|| panic!("durable secret crash marker missing"));
    let durable_marker: Value = serde_json::from_str(&durable_marker)
        .unwrap_or_else(|error| panic!("decode durable secret crash marker: {error}"));
    assert_eq!(durable_marker["state"], json!("pending_cleanup"));

    let mut tampered = durable_marker;
    tampered["target"] = json!("SOVEREIGN_SECRET_FILE_TAMPERED");
    state
        .put_state(
            "controller.secret_action_lifecycle",
            &action_id,
            &tampered.to_string(),
        )
        .unwrap_or_else(|error| panic!("tamper secret crash marker: {error}"));
    drop(state);
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen tampered secret marker state: {error}"));
    let tamper_error = RecoveryManager::recover_with_permission_context(
        state,
        &fixture.registry,
        PermissionContext::m6_local_secret_execution(),
    )
    .err()
    .unwrap_or_else(|| panic!("tampered secret lifecycle marker must fail recovery"));
    assert!(
        tamper_error
            .to_string()
            .contains("trusted checkpoint plus ordered journal replay"),
        "unexpected secret marker tamper error: {tamper_error}"
    );
}

#[test]
fn reconciliation_repo_write_approval_required_policy_is_schema_rejected() {
    let fixture = compiled_fixture("m6-reconciliation-invalid-repo-write-approval", false);
    let mut document = fixture
        .compilation
        .as_ref()
        .unwrap_or_else(|| panic!("compiled fixture missing"))
        .plan()
        .as_value()
        .clone();
    document["policy"]["approval"]["required_permissions"] = json!(["repo_write"]);
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let diagnostics = validator.validate(&PlanIr::from_value(document));
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::Schema),
        "repo_write must remain invalid in approval.required_permissions: {diagnostics:#?}"
    );
}

#[derive(Clone, Copy)]
enum RecoveryEffectFixture {
    Preimage,
    Postimage,
    Ambiguous,
}

#[allow(clippy::too_many_lines)]
fn seeded_reconciliation_recovery(
    label: &str,
    policy: ReconciliationPolicy,
    observed: RecoveryEffectFixture,
) -> (CompiledFixture, String, String) {
    let mut fixture = compiled_fixture(label, false);
    let (controller, task_id) = controller_for(&mut fixture);
    let task_contract_digest = controller
        .task_contract_digest(&task_id)
        .unwrap_or_else(|| panic!("reconciliation task contract digest"))
        .to_owned();
    drop(controller);

    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen reconciliation state: {error}"));
    let manifest = latest_checkpoint_manifest(&state);
    let execution_epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("reconciliation execution epoch: {error}"));
    let target = fixture.repo.root.join("src/settings/SettingsForm.tsx");
    let expected_target_mode = fs::metadata(&target)
        .unwrap_or_else(|error| panic!("reconciliation target metadata: {error}"))
        .permissions()
        .mode()
        & 0o7777;
    let postimage = SOURCE.replacen("Save", "Apply", 1);
    let observed_content = match observed {
        RecoveryEffectFixture::Preimage => SOURCE.to_owned(),
        RecoveryEffectFixture::Postimage => postimage.clone(),
        RecoveryEffectFixture::Ambiguous => SOURCE.replacen("Save", "Review", 1),
    };
    fs::write(&target, &observed_content)
        .unwrap_or_else(|error| panic!("materialize reconciliation observed file: {error}"));

    let action_id = format!("action.{label}");
    let payload_digest = sha256_prefixed(format!("payload-{label}").as_bytes());
    let intent = json!({
        "schema_version": 3,
        "action_id": action_id,
        "plan_id": manifest.plan_id,
        "plan_revision": manifest.plan_revision,
        "plan_digest": manifest.plan_digest,
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "attempt_id": format!("attempt.{label}"),
        "execution_epoch": execution_epoch,
        "payload_digest": payload_digest,
        "action_nonce": format!("nonce.{label}"),
        "policy_digest": manifest.policy_digest,
        "repository_id": manifest.repository_id,
        "worktree_lease_id": Value::Null,
        "execution_root": fixture.repo.root,
        "path": "src/settings/SettingsForm.tsx",
        "expected_source_digest": fixture.form_digest,
        "old_literal": "Save",
        "new_literal": "Apply",
        "expected_post_digest": sha256_prefixed(postimage.as_bytes()),
        "expected_target_mode": expected_target_mode,
        "artifact_store_root": fixture.repo.base.join("cas")
    });
    let intent_raw = serde_json::to_string(&intent)
        .unwrap_or_else(|error| panic!("encode reconciliation action intent: {error}"));
    state
        .put_state("controller.action_intent", &action_id, &intent_raw)
        .unwrap_or_else(|error| panic!("persist reconciliation action intent: {error}"));

    let reconciliation = json!({
        "schema_version": 1,
        "action_id": action_id,
        "plan_id": manifest.plan_id,
        "plan_revision": manifest.plan_revision,
        "task_id": task_id,
        "payload_digest": payload_digest,
        "policy_digest": manifest.policy_digest,
        "execution_epoch": execution_epoch,
        "policy": policy,
    });
    let reconciliation_raw = serde_json::to_string(&reconciliation)
        .unwrap_or_else(|error| panic!("encode reconciliation binding: {error}"));
    state
        .put_state(
            "controller.action_reconciliation",
            &action_id,
            &reconciliation_raw,
        )
        .unwrap_or_else(|error| panic!("persist reconciliation binding: {error}"));

    state
        .insert_action_record(NewActionRecord {
            action_id: &action_id,
            state: "prepared",
            payload_digest: &payload_digest,
            policy_digest: &manifest.policy_digest,
            execution_epoch,
            event_id: &format!("event.{label}.prepared"),
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert reconciliation action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: &action_id,
            expected_state: "prepared",
            next_state: "authorized",
            expected_epoch: execution_epoch,
            event_id: &format!("event.{label}.authorized"),
            event_kind: "authorized",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("authorize reconciliation action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: &action_id,
            expected_state: "authorized",
            next_state: "dispatched",
            expected_epoch: execution_epoch,
            event_id: &format!("event.{label}.dispatched"),
            event_kind: "dispatched",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("dispatch reconciliation action: {error}"));

    let action_sequence = state
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("reconciliation action sequence: {error}"));
    let action_records = state
        .action_records()
        .unwrap_or_else(|error| panic!("reconciliation checkpoint actions: {error}"))
        .into_iter()
        .map(|record| CheckpointActionRecord {
            action_id: record.action_id,
            state: record.state,
            payload_digest: record.payload_digest,
            policy_digest: record.policy_digest,
            execution_epoch: record.execution_epoch,
            result_digest: record.result_digest,
            last_event_sequence: record.last_event_sequence,
        })
        .collect::<Vec<_>>();
    let intent_digest = sha256_prefixed(intent_raw.as_bytes());
    let reconciliation_digest = sha256_prefixed(reconciliation_raw.as_bytes());
    append_modified_checkpoint(&mut state, |checkpoint| {
        checkpoint.action_records = action_records;
        checkpoint.action_journal_sequence = action_sequence;
        checkpoint.evidence_binding_digests.insert(
            format!("controller.action_intent:{action_id}"),
            intent_digest,
        );
        checkpoint.evidence_binding_digests.insert(
            format!("controller.action_reconciliation:{action_id}"),
            reconciliation_digest,
        );
    });
    drop(state);
    (fixture, task_id, action_id)
}

#[test]
fn reconciliation_consequential_external_recovery_never_infers_local_postimage_or_replays() {
    let (fixture, task_id, action_id) = seeded_reconciliation_recovery(
        "m6-reconciliation-external-unknown",
        ReconciliationPolicy::consequential_external(),
        RecoveryEffectFixture::Postimage,
    );
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open external recovery state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover consequential external action: {error}"));

    assert!(summary.mutation_blocked);
    assert_eq!(summary.unknown_action_ids, vec![action_id.clone()]);
    assert_eq!(
        recovered.task_state(&task_id),
        Some(TaskState::ReconcilingUnknown)
    );
    assert_eq!(
        recovered
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("external recovered action: {error}"))
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read external observed postimage: {error}")),
        SOURCE.replacen("Save", "Apply", 1),
        "recovery must not blind replay or rewrite a consequential external unknown"
    );
}

#[test]
fn reconciliation_proof_required_local_postimage_commits_historical_unknown() {
    let (fixture, _task_id, action_id) = seeded_reconciliation_recovery(
        "m6-reconciliation-local-postimage",
        ReconciliationPolicy::proof_required_local(),
        RecoveryEffectFixture::Postimage,
    );
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open local postimage recovery state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover local postimage action: {error}"));

    assert!(!summary.mutation_blocked);
    assert!(summary.unknown_action_ids.is_empty());
    let action = recovered
        .state()
        .action_record(&action_id)
        .unwrap_or_else(|error| panic!("local postimage recovered action: {error}"))
        .unwrap_or_else(|| panic!("local postimage action missing"));
    assert_eq!(action.state, "committed");
    assert!(action.result_digest.is_some());
}

#[test]
fn reconciliation_proof_required_local_preimage_fails_historical_unknown() {
    let (fixture, _task_id, action_id) = seeded_reconciliation_recovery(
        "m6-reconciliation-local-preimage",
        ReconciliationPolicy::proof_required_local(),
        RecoveryEffectFixture::Preimage,
    );
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open local preimage recovery state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover local preimage action: {error}"));

    assert!(!summary.mutation_blocked);
    assert!(summary.unknown_action_ids.is_empty());
    assert_eq!(
        recovered
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("local preimage recovered action: {error}"))
            .map(|record| record.state),
        Some("failed".to_owned())
    );
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read local preimage after recovery: {error}")),
        SOURCE,
        "effect-absent reconciliation must not dispatch the action"
    );
}

#[test]
fn reconciliation_proof_required_local_ambiguous_digest_remains_unknown() {
    let (fixture, task_id, action_id) = seeded_reconciliation_recovery(
        "m6-reconciliation-local-ambiguous",
        ReconciliationPolicy::proof_required_local(),
        RecoveryEffectFixture::Ambiguous,
    );
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open local ambiguous recovery state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover local ambiguous action: {error}"));

    assert!(summary.mutation_blocked);
    assert_eq!(summary.unknown_action_ids, vec![action_id.clone()]);
    assert_eq!(
        recovered.task_state(&task_id),
        Some(TaskState::ReconcilingUnknown)
    );
    assert_eq!(
        recovered
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("local ambiguous recovered action: {error}"))
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
}

#[test]
fn m5_t03_task_grant_change_is_exact_and_invalidates_stale_ready_authority() {
    let mut fixture = compiled_fixture("m5-grant-scope", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let manifest = write_tool_manifest();
    let stale = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest)
        .unwrap_or_else(|error| panic!("initial exact grant readiness: {error}"));
    let epoch_before = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch before grant change: {error}"));
    let epoch_after = controller
        .set_task_capability_grant(
            &task_id,
            CapabilitySet::new([PermissionClass::RepositoryWrite]),
        )
        .unwrap_or_else(|error| panic!("narrow exact task grant: {error}"));
    assert!(epoch_after > epoch_before);

    let Err(error) =
        controller.derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest)
    else {
        panic!("grant without process_exec unexpectedly produced readiness")
    };
    assert!(error.to_string().contains("permission intersection"));

    controller
        .cancel_ready_lease(stale)
        .unwrap_or_else(|error| panic!("release stale resource lease: {error}"));
    controller
        .set_task_capability_grant(
            &task_id,
            CapabilitySet::new([
                PermissionClass::ProcessExec,
                PermissionClass::RepositoryWrite,
            ]),
        )
        .unwrap_or_else(|error| panic!("restore exact task grant: {error}"));
    let current = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest)
        .unwrap_or_else(|error| panic!("restored exact grant readiness: {error}"));
    controller
        .cancel_ready_lease(current)
        .unwrap_or_else(|error| panic!("release restored lease: {error}"));
}

#[test]
fn m5_t03_only_exact_pinned_authorized_tool_schema_enters_context_packet() {
    let mut fixture = compiled_fixture("m5-schema-filter", false);
    let (controller, task_id) = controller_for(&mut fixture);
    let patch_manifest = write_tool_manifest();
    let irrelevant_digest =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let irrelevant_manifest = ToolManifest {
        tool_id: "tool.unpinned".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: irrelevant_digest.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]),
        declared_risk_floor: CommandRisk::RepositoryMutation,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    };
    let patch_schema = ToolSchemaV1 {
        tool_id: patch_manifest.tool_id.clone(),
        version: patch_manifest.version.clone(),
        content_digest: patch_manifest.content_digest.clone(),
        name: "patch".to_owned(),
        description: "Apply one exact Controller-authorized replacement".to_owned(),
        input_schema: json!({"type": "object", "required": ["path"]}),
        required_capabilities: CapabilitySet::new([
            PermissionClass::ProcessExec,
            PermissionClass::RepositoryWrite,
        ]),
    };
    let irrelevant_schema = ToolSchemaV1 {
        tool_id: irrelevant_manifest.tool_id.clone(),
        version: irrelevant_manifest.version.clone(),
        content_digest: irrelevant_manifest.content_digest.clone(),
        name: "unpinned".to_owned(),
        description: "must never enter this task packet".to_owned(),
        input_schema: json!({"type": "object"}),
        required_capabilities: CapabilitySet::new([PermissionClass::ProcessExec]),
    };
    let authorized = controller
        .authorized_tool_schema_evidence(
            &task_id,
            &[patch_schema, irrelevant_schema],
            &[patch_manifest, irrelevant_manifest],
        )
        .unwrap_or_else(|error| panic!("derive authorized tool schemas: {error}"));
    assert_eq!(authorized.len(), 1);
    assert_eq!(authorized[0].kind, EvidenceKind::ToolSchema);
    assert!(authorized[0].text.contains("tool.patch"));
    assert!(!authorized[0].text.contains("tool.unpinned"));

    let packet = ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns authority.".to_owned(),
                task_contract: "Use only the exact pinned patch tool.".to_owned(),
                current_state: "ready for bounded schema projection".to_owned(),
                authorized_tool_schemas: authorized,
                candidates: Vec::new(),
                output_schema: "typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build authorized schema packet: {error}"));
    assert_eq!(
        packet
            .items
            .iter()
            .filter(|item| item.kind == EvidenceKind::ToolSchema)
            .count(),
        1
    );
    assert!(packet.serialized_input.contains("tool.patch"));
    assert!(!packet.serialized_input.contains("tool.unpinned"));
    assert!(packet.metrics.tool_schema_tokens > 0);
    assert!(packet.metrics.tool_schema_tokens <= packet.budget.tool_schema_tokens);
}

#[test]
fn constrained_pressure_defers_before_ready_lease_is_issued() {
    let mut fixture = compiled_fixture("pressure", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        ResourcePressureSnapshotV1 {
            schema_version: RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION,
            observed_at_ms: 1_000,
            controlled_working_set_mib: 6_000,
            host_headroom_mib: 512,
            swap_used_mib: Some(4_096),
            swap_out_growth_mib_per_min: 300,
            compressor_growth_mib_per_min: 300,
            os_memory_pressure: OsMemoryPressure::Warning,
            recent_pressure_event: true,
            thermal_pressure: ThermalPressure::Normal,
            allocation_failure: false,
            repeated_resource_kill: false,
            uncontrolled_child_growth: false,
            host_free_disk_mib: Some(8_192),
        },
    )));
    assert!(
        controller
            .derive_ready_lease(
                &fixture.registry,
                &task_id,
                readiness(),
                &write_tool_manifest(),
            )
            .is_err()
    );
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::DeferredResource)
    );
}

#[test]
fn checkpoint_sequence_gap_blocks_readiness() {
    let mut fixture = compiled_fixture("checkpoint-gap", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let mut second = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("second state: {error}"));
    second
        .append_event(NewJournalEvent {
            event_id: "test.checkpoint-gap",
            entity_type: "test",
            entity_id: "gap",
            event_kind: "gap",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("append gap: {error}"));
    assert!(
        controller
            .derive_ready_lease(
                &fixture.registry,
                &task_id,
                readiness(),
                &write_tool_manifest()
            )
            .is_err()
    );
}

#[test]
fn baseline_drift_invalidates_ready_lease_and_advances_epoch() {
    let mut fixture = compiled_fixture("baseline-drift", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let old_epoch = ready.execution_epoch();
    fs::write(
        fixture.repo.root.join("src/settings/SettingsForm.tsx"),
        SOURCE.replace("Save", "UserChanged"),
    )
    .unwrap_or_else(|error| panic!("drift source: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    assert!(matches!(
        controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget),
        Err(ControllerError::NotReady(_))
    ));
    assert_eq!(
        controller.plan_validity(),
        Some(PlanValidity::StaleEvidence)
    );
    assert!(
        controller
            .state()
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("epoch: {error}"))
            > old_epoch
    );
}

#[test]
fn pause_after_ready_lease_blocks_mutation_before_model_or_tool_dispatch() {
    let mut fixture = compiled_fixture("pause-after-ready", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    controller
        .pause(Some("operator requested"))
        .unwrap_or_else(|error| panic!("pause: {error}"));

    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let Err(error) = controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget)
    else {
        panic!("paused controller unexpectedly executed a repository mutation")
    };
    assert!(matches!(error, ControllerError::NotReady(_)));
    assert_eq!(budget.remaining_calls(), 1);
    assert_eq!(controller.task_model_calls_used(&task_id), Some(0));
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
}

#[test]
fn malformed_model_output_cannot_set_success_or_authority() {
    let mut fixture = compiled_fixture("malformed", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let malformed = json!({
        "schema_version": 1,
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
        "task_state": "succeeded",
        "permissions": ["destructive"],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": fixture.form_digest,
            "old_literal": "Save",
            "new_literal": "Apply",
            "expected_occurrences": 1
        }
    });
    let execution = backend(vec![model_response(
        malformed.to_string(),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    assert!(
        controller
            .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
            .is_err()
    );
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert_eq!(
        controller.scheduler_view(&task_id),
        Some(SchedulerView::Blocked)
    );
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
    assert!(
        controller
            .state()
            .journal()
            .unwrap_or_else(|error| panic!("journal: {error}"))
            .iter()
            .all(|event| event.entity_type != "action")
    );
}

#[test]
fn wrong_literal_relation_cannot_satisfy_compiled_acceptance_contract() {
    let mut fixture = compiled_fixture("wrong-literal-relation", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let wrong = json!({
        "schema_version": 1,
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": fixture.form_digest,
            "old_literal": "Settings",
            "new_literal": "Apply",
            "expected_occurrences": 1
        }
    });
    let execution = backend(vec![model_response(
        wrong.to_string(),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let Err(error) = controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget)
    else {
        panic!("semantically wrong literal relation unexpectedly executed")
    };
    assert!(error.to_string().contains("compiled literal contract"));
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read unchanged source: {error}")),
        SOURCE
    );
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert!(
        controller
            .state()
            .journal()
            .unwrap_or_else(|error| panic!("journal: {error}"))
            .iter()
            .all(|event| event.entity_type != "action")
    );
}

#[test]
fn verifier_failure_cannot_transition_task_to_succeeded() {
    let mut fixture = compiled_fixture("verify-fail", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation = SwapIsolation {
        inner: MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}")),
        executable: PathBuf::from("/usr/bin/true"),
        advance_epoch_db: None,
    };
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    assert!(matches!(
        controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget),
        Err(ControllerError::VerificationFailed(_))
    ));
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert_ne!(controller.task_state(&task_id), Some(TaskState::Succeeded));
}

#[test]
fn preexisting_dirty_target_hunk_is_preserved_by_verified_controller_edit() {
    let mut fixture = compiled_fixture_with_dirty_target("dirty-target");
    let staged_before = git_text(
        &fixture.repo.root,
        &["diff", "--cached", "--", "src/other.txt"],
    );
    let unstaged_before = git_text(&fixture.repo.root, &["diff", "--", "src/other.txt"]);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(4, 30_000);
    let success = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
        .unwrap_or_else(|error| panic!("execute dirty-target edit: {error}"));
    assert!(success.verification.passed);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(budget.remaining_calls(), 3);
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("user-owned pre-existing note"));
    assert!(source.contains(">Apply</button>"));
    assert!(!source.contains(">Save</button>"));
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("user-owned-untracked.txt"))
            .unwrap_or_else(|error| panic!("read unrelated user file: {error}")),
        "keep exactly\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/other.txt"))
            .unwrap_or_else(|error| panic!("read dirty unrelated file: {error}")),
        "user staged version\nuser unstaged tail\n"
    );
    assert_eq!(
        git_text(
            &fixture.repo.root,
            &["diff", "--cached", "--", "src/other.txt"]
        ),
        staged_before
    );
    assert_eq!(
        git_text(&fixture.repo.root, &["diff", "--", "src/other.txt"]),
        unstaged_before
    );
}

#[test]
fn verified_atomic_replace_preserves_target_file_mode() {
    let mut fixture = compiled_fixture_with_target_mode("target-mode", 0o755);
    let target = fixture.repo.root.join("src/settings/SettingsForm.tsx");
    let before_mode = fs::metadata(&target)
        .unwrap_or_else(|error| panic!("target metadata before edit: {error}"))
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(before_mode, 0o755);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let success = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
        .unwrap_or_else(|error| panic!("execute mode-preserving edit: {error}"));
    let after_mode = fs::metadata(&target)
        .unwrap_or_else(|error| panic!("target metadata after edit: {error}"))
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(after_mode, before_mode);
    assert_eq!(success.verification.expected_target_mode, before_mode);
    assert_eq!(success.verification.observed_target_mode, before_mode);
    assert!(!git_text(&fixture.repo.root, &["diff", "--summary"]).contains("mode change"));
}

#[test]
fn committed_nonzero_process_result_is_execution_failure_not_unknown() {
    let mut fixture = compiled_fixture("nonzero", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation = SwapIsolation {
        inner: MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}")),
        executable: PathBuf::from("/usr/bin/false"),
        advance_epoch_db: None,
    };
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    let failure = match controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget) {
        Err(ControllerError::ExecutionFailed(failure)) => failure,
        other => panic!("expected committed execution failure, got {other:?}"),
    };
    assert_eq!(failure.exit_code, Some(1));
    assert!(failure.result_digest.is_some());
    let action_id = failure
        .action_id
        .as_deref()
        .unwrap_or_else(|| panic!("failure must bind action"));
    let action = controller
        .state()
        .action_record(action_id)
        .unwrap_or_else(|error| panic!("action record: {error}"))
        .unwrap_or_else(|| panic!("missing action record"));
    assert_eq!(action.state, "committed");
    assert_ne!(action.state, "unknown");
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
}

#[test]
fn controller_learning_records_real_failure_and_accepts_exact_repair_origin() {
    let mut fixture = compiled_fixture_with_task_model_call_cap("controller-learning-repair", 2);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("initial repair fixture readiness: {error}"));
    let execution = backend(vec![
        model_response(
            valid_execution_proposal(&fixture.form_digest),
            fixture.packet.metrics.final_serialized_input_tokens,
        ),
        model_response(
            valid_execution_proposal(&fixture.form_digest),
            fixture.packet.metrics.final_serialized_input_tokens,
        ),
    ]);
    let parts = runtime_parts(&fixture);
    let failing_isolation = SwapIsolation {
        inner: MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}")),
        executable: PathBuf::from("/usr/bin/false"),
        advance_epoch_db: None,
    };
    let failing_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &failing_isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(2, 30_000);
    let failure =
        match controller.execute_replace(ready, &failing_runtime, &fixture.packet, &mut budget) {
            Err(ControllerError::ExecutionFailed(failure)) => failure,
            other => panic!("expected real committed failure before repair, got {other:?}"),
        };
    let failed_episode = controller
        .record_attempt_episode(
            &failure.attempt_id,
            Some(learning_procedure()),
            1_800_000_200_000,
        )
        .unwrap_or_else(|error| panic!("record real failed episode: {error}"));
    assert_eq!(failed_episode.episode.kind, MemoryKind::Episodic);
    assert!(failed_episode.candidate.is_none());
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );

    let repair_isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("repair seatbelt: {error}"));
    let repair_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &repair_isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let (success, repair_packet) = controller
        .repair_replace(
            &task_id,
            &repair_runtime,
            &fixture.packet,
            &[],
            readiness(),
            &mut budget,
        )
        .unwrap_or_else(|error| panic!("real targeted repair: {error}"));
    let repaired_episode = controller
        .record_attempt_episode(
            &success.attempt_id,
            Some(learning_procedure()),
            1_800_000_200_001,
        )
        .unwrap_or_else(|error| panic!("record repaired verified episode: {error}"));
    assert!(repaired_episode.candidate.is_none());
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_repair_learning_origin(
        &controller,
        &repaired_episode.episode.assertion,
        &failure.attempt_id,
        &repair_packet.failure_record_digest,
        &task_id,
    );
}

#[test]
fn epoch_change_after_authorization_blocks_dispatch_before_mutation() {
    let mut fixture = compiled_fixture("epoch", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation = SwapIsolation {
        inner: MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}")),
        executable: PathBuf::from("/usr/bin/true"),
        advance_epoch_db: Some(fixture.repo.state_path.clone()),
    };
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(1, 30_000);
    assert!(
        controller
            .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
            .is_err()
    );
    let journal = controller
        .state()
        .journal()
        .unwrap_or_else(|error| panic!("journal: {error}"));
    let action_id = journal
        .iter()
        .find(|event| event.entity_type == "action" && event.event_kind == "authorized")
        .map_or_else(
            || panic!("authorized action event missing"),
            |event| event.entity_id.clone(),
        );
    let action = controller
        .state()
        .action_record(&action_id)
        .unwrap_or_else(|error| panic!("action record: {error}"))
        .unwrap_or_else(|| panic!("action missing"));
    assert_eq!(action.state, "authorized");
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
}

#[test]
fn exhausted_outer_model_budget_is_not_a_resource_pressure_deferral() {
    let mut fixture = compiled_fixture("budget", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(0, 30_000);
    assert!(matches!(
        controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget),
        Err(ControllerError::Policy(_))
    ));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    assert_eq!(controller.task_resource_deferrals_used(&task_id), Some(0));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(0));
    assert_eq!(budget.remaining_calls(), 0);
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
}

#[test]
fn compiled_task_model_call_ceiling_is_permanent_and_not_a_resource_pressure_deferral() {
    let mut fixture = compiled_fixture_with_task_model_call_cap("task-budget", 0);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("ready: {error}"));
    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut caller_budget = ModelCallBudget::new(4, 30_000);
    let Err(error) =
        controller.execute_replace(ready, &runtime, &fixture.packet, &mut caller_budget)
    else {
        panic!("compiled zero-call ceiling must block before backend dispatch")
    };
    assert!(
        error
            .to_string()
            .contains("task model-call budget exhausted")
    );
    assert_eq!(caller_budget.remaining_calls(), 4);
    assert_eq!(controller.task_model_calls_used(&task_id), Some(0));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    assert_eq!(controller.task_resource_deferrals_used(&task_id), Some(0));
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
}

#[test]
fn permanent_build_heavy_authority_denial_does_not_evict_model_reservation() {
    let mut fixture = compiled_fixture_with_resource_override(
        "build-heavy-no-authority",
        ResourceFixtureOverride::NoBuildHeavyAuthority,
    );
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("MODEL ready lease: {error}"));
    let execution = backend(Vec::new());
    execution
        .unload()
        .unwrap_or_else(|error| panic!("execution backend must start absent: {error}"));
    assert_eq!(
        execution
            .residency_proof()
            .unwrap_or_else(|error| panic!("backend residency before BUILD_HEAVY: {error}")),
        ModelResidencyProof::Absent
    );
    let before = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("resource snapshot before BUILD_HEAVY denial: {error}"));

    let Err(error) = controller.acquire_build_heavy(
        ready,
        &fixture.registry,
        &write_tool_manifest(),
        &execution,
    ) else {
        panic!("BUILD_HEAVY without task authority must be denied")
    };
    assert!(error.to_string().contains("does not authorize BUILD_HEAVY"));
    let after = controller
        .resource_snapshot()
        .unwrap_or_else(|error| panic!("resource snapshot after BUILD_HEAVY denial: {error}"));
    assert_eq!(
        after, before,
        "permanent preflight denial must be side-effect free"
    );
    assert_eq!(controller.task_resource_deferrals_used(&task_id), Some(0));
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    assert_eq!(
        execution
            .residency_proof()
            .unwrap_or_else(|error| panic!("backend residency after BUILD_HEAVY denial: {error}")),
        ModelResidencyProof::Absent
    );
}

#[test]
fn worktree_d3_execution_persists_change_set_and_never_mutates_primary() {
    let mut fixture = compiled_worktree_fixture("worktree-d3-execution");
    let primary_before = fixture
        .registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("primary before: {error}"));
    let primary_source_before =
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("primary source before: {error}"));
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("D3 ready: {error}"));
    let lease = controller
        .task_worktree_lease(&task_id)
        .cloned()
        .unwrap_or_else(|| panic!("D3 task worktree lease missing"));
    assert!(lease.worktree_path.exists());
    assert_eq!(
        lease.worktree_path.parent(),
        Some(
            fixture
                .repo
                .state_path
                .parent()
                .unwrap_or_else(|| panic!("state parent"))
                .join("worktrees")
                .canonicalize()
                .unwrap_or_else(|error| panic!("canonical worktrees: {error}"))
                .as_path()
        )
    );

    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation =
        MacSandboxExecBackend::detect().unwrap_or_else(|error| panic!("seatbelt: {error}"));
    let runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mut budget = ModelCallBudget::new(4, 30_000);
    let success = controller
        .execute_replace(ready, &runtime, &fixture.packet, &mut budget)
        .unwrap_or_else(|error| panic!("execute D3 worktree edit: {error}"));
    assert!(success.verification.passed);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    let change_set = controller
        .task_change_set(&task_id)
        .unwrap_or_else(|| panic!("D3 ChangeSet missing"));
    assert_eq!(change_set.lease_id, lease.lease_id);
    assert!(change_set.diff_content.contains("Apply"));
    assert!(change_set.diff_content.contains("Save"));
    assert!(!lease.worktree_path.exists());
    assert_eq!(
        fixture
            .registry
            .snapshot("repo.app")
            .unwrap_or_else(|error| panic!("primary after: {error}")),
        primary_before
    );
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("primary source after: {error}")),
        primary_source_before
    );
}

#[test]
fn worktree_recovery_revalidates_exact_head_and_common_git_directory() {
    let mut fixture = compiled_worktree_fixture("worktree-recovery");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("D3 ready: {error}"));
    let lease = controller
        .task_worktree_lease(&task_id)
        .cloned()
        .unwrap_or_else(|| panic!("worktree lease missing"));
    controller
        .cancel_ready_lease(ready)
        .unwrap_or_else(|error| panic!("cancel ready: {error}"));
    drop(controller);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover exact worktree: {error}"));
    assert!(!summary.mutation_blocked);
    assert_eq!(recovered.task_worktree_lease(&task_id), Some(&lease));
    drop(recovered);

    git(
        &lease.worktree_path,
        &["commit", "--allow-empty", "-qm", "drift"],
    );
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen drifted state: {error}"));
    let error = RecoveryManager::recover(state, &fixture.registry)
        .err()
        .unwrap_or_else(|| panic!("drifted worktree recovery must fail closed"));
    assert!(
        error.to_string().contains("worktree HEAD differs")
            || error.to_string().contains("worktree lease")
    );
}

#[test]
fn recovery_manager_rejects_persisted_worktree_root_and_path_tamper() {
    for (label, field) in [
        ("worktree-recovery-root-tamper", "controller_root"),
        ("worktree-recovery-path-tamper", "worktree_path"),
    ] {
        let mut fixture = compiled_worktree_fixture(label);
        let (mut controller, task_id) = controller_for(&mut fixture);
        let ready = controller
            .derive_ready_lease(
                &fixture.registry,
                &task_id,
                readiness(),
                &write_tool_manifest(),
            )
            .unwrap_or_else(|error| panic!("D3 ready before {field} tamper: {error}"));
        let lease = controller
            .task_worktree_lease(&task_id)
            .cloned()
            .unwrap_or_else(|| panic!("worktree lease missing before {field} tamper"));
        controller
            .cancel_ready_lease(ready)
            .unwrap_or_else(|error| panic!("cancel ready before {field} tamper: {error}"));
        drop(controller);

        let mut state = StateStore::open(&fixture.repo.state_path)
            .unwrap_or_else(|error| panic!("reopen state for {field} tamper: {error}"));
        let foreign = if field == "controller_root" {
            fixture.repo.base.join("foreign-controller-root")
        } else {
            lease.controller_root.join("foreign-lease-path")
        };
        replace_persisted_task_runtime(&mut state, &task_id, |runtime| {
            runtime["worktree_lease"][field] = json!(foreign);
        });
        drop(state);

        let state = StateStore::open(&fixture.repo.state_path)
            .unwrap_or_else(|error| panic!("reopen tampered state: {error}"));
        let error = RecoveryManager::recover(state, &fixture.registry)
            .err()
            .unwrap_or_else(|| panic!("RecoveryManager must reject persisted {field} tamper"));
        assert!(
            error.to_string().contains("path/root-tampered"),
            "unexpected {field} tamper recovery error: {error}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn committed_v2_action_intent_recovers_as_primary_only_and_cannot_gain_worktree_authority() {
    let mut fixture = compiled_worktree_fixture("committed-v2-action-intent");
    let (controller, task_id) = controller_for(&mut fixture);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    assert!(controller.task_worktree_lease(&task_id).is_none());
    drop(controller);

    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state for v2 intent: {error}"));
    let manifest = latest_checkpoint_manifest(&state);
    let mut task_runtime = manifest
        .task_records
        .get(&task_id)
        .cloned()
        .unwrap_or_else(|| panic!("checkpoint task runtime missing"));
    task_runtime["state"] = json!("verifying");
    task_runtime["attempts_started"] = json!(1);
    task_runtime["worktree_lease"] = Value::Null;
    task_runtime["worktree_state"] = Value::Null;
    task_runtime["change_set"] = Value::Null;
    task_runtime["change_set_artifact_digest"] = Value::Null;
    task_runtime["change_set_carry"] = Value::Null;
    task_runtime["worktree_baseline"] = Value::Null;
    task_runtime["worktree_composition"] = json!([]);
    task_runtime["worktree_conflict"] = Value::Null;
    let task_contract_digest = task_runtime
        .get("task_contract_digest")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("task contract digest missing"))
        .to_owned();
    let task_record = state
        .state_records("controller.task")
        .unwrap_or_else(|error| panic!("task records: {error}"))
        .into_iter()
        .find(|record| {
            serde_json::from_str::<Value>(&record.value_json)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/task/task_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .as_deref()
                == Some(task_id.as_str())
        })
        .unwrap_or_else(|| panic!("persisted task runtime missing"));
    state
        .put_state(
            "controller.task",
            &task_record.key,
            &serde_json::to_string(&task_runtime)
                .unwrap_or_else(|error| panic!("encode task runtime: {error}")),
        )
        .unwrap_or_else(|error| panic!("persist task runtime: {error}"));

    let attempt_id = "attempt.legacy-v2-primary.1".to_owned();
    let attempt_runtime = json!({
        "task_id": task_id,
        "attempt_id": attempt_id,
        "state": "verifying",
        "task_contract_digest": task_contract_digest,
        "repair_origin": null,
        "baseline_digest": manifest.repository_snapshot_digest,
        "pre_snapshot_digest": manifest.repository_snapshot_digest,
        "pre_diff_digest": manifest.baseline_diff_digest,
        "pre_changed_fingerprints": {}
    });
    state
        .put_state(
            "controller.attempt",
            &attempt_id,
            &serde_json::to_string(&attempt_runtime)
                .unwrap_or_else(|error| panic!("encode attempt runtime: {error}")),
        )
        .unwrap_or_else(|error| panic!("persist attempt runtime: {error}"));

    let target = fixture.repo.root.join("src/settings/SettingsForm.tsx");
    let expected_target_mode = fs::metadata(&target)
        .unwrap_or_else(|error| panic!("target metadata: {error}"))
        .permissions()
        .mode()
        & 0o7777;
    let postimage = SOURCE.replacen("Save", "Apply", 1);
    let expected_post_digest = sha256_prefixed(postimage.as_bytes());
    fs::write(&target, &postimage)
        .unwrap_or_else(|error| panic!("materialize historical primary effect: {error}"));

    let action_id = "action.legacy-v2-primary".to_owned();
    let payload_digest = sha256_prefixed(b"legacy-v2-primary-payload");
    let result_store = ArtifactStore::open(fixture.repo.base.join("cas"))
        .unwrap_or_else(|error| panic!("legacy result store: {error}"));
    let result = result_store
        .put(&mut state, b"legacy-v2-primary-committed-result")
        .unwrap_or_else(|error| panic!("legacy result artifact: {error}"));
    let epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("execution epoch: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: &action_id,
            state: "prepared",
            payload_digest: &payload_digest,
            policy_digest: &manifest.policy_digest,
            execution_epoch: epoch,
            event_id: "event.legacy-v2-primary-prepared",
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert legacy action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: &action_id,
            expected_state: "prepared",
            next_state: "committed",
            expected_epoch: epoch,
            event_id: "event.legacy-v2-primary-committed",
            event_kind: "committed",
            payload_json: "{}",
            result_digest: Some(&result.digest),
        })
        .unwrap_or_else(|error| panic!("commit legacy action: {error}"));

    let legacy = json!({
        "schema_version": 2,
        "action_id": action_id,
        "plan_id": manifest.plan_id,
        "plan_revision": manifest.plan_revision,
        "plan_digest": manifest.plan_digest,
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "attempt_id": attempt_id,
        "execution_epoch": epoch,
        "payload_digest": payload_digest,
        "action_nonce": "nonce.legacy-v2-primary",
        "policy_digest": manifest.policy_digest,
        "repository_id": manifest.repository_id,
        "path": "src/settings/SettingsForm.tsx",
        "expected_source_digest": fixture.form_digest,
        "old_literal": "Save",
        "new_literal": "Apply",
        "expected_post_digest": expected_post_digest,
        "expected_target_mode": expected_target_mode,
        "artifact_store_root": fixture.repo.base.join("cas")
    });
    assert!(legacy.get("worktree_lease_id").is_none());
    assert!(legacy.get("execution_root").is_none());
    let legacy_raw = serde_json::to_string(&legacy)
        .unwrap_or_else(|error| panic!("encode genuine v2 intent: {error}"));
    state
        .put_state("controller.action_intent", &action_id, &legacy_raw)
        .unwrap_or_else(|error| panic!("persist genuine v2 intent: {error}"));
    let legacy_digest = sha256_prefixed(legacy_raw.as_bytes());
    let action_sequence = state
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("latest action sequence: {error}"));
    let checkpoint_actions = state
        .action_records()
        .unwrap_or_else(|error| panic!("checkpoint actions: {error}"))
        .into_iter()
        .map(|record| CheckpointActionRecord {
            action_id: record.action_id,
            state: record.state,
            payload_digest: record.payload_digest,
            policy_digest: record.policy_digest,
            execution_epoch: record.execution_epoch,
            result_digest: record.result_digest,
            last_event_sequence: record.last_event_sequence,
        })
        .collect::<Vec<_>>();
    append_modified_checkpoint(&mut state, |manifest| {
        manifest.task_records.insert(task_id.clone(), task_runtime);
        manifest
            .attempt_records
            .insert(attempt_id.clone(), attempt_runtime);
        manifest.action_records = checkpoint_actions;
        manifest.action_journal_sequence = action_sequence;
        manifest.evidence_binding_digests.insert(
            format!("controller.action_intent:{action_id}"),
            legacy_digest,
        );
    });
    drop(state);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen checkpoint-bound v2 state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover genuine committed v2 intent: {error}"));
    assert!(!summary.mutation_blocked);
    assert_eq!(recovered.task_state(&task_id), Some(TaskState::Succeeded));
    assert!(recovered.task_worktree_lease(&task_id).is_none());
    assert!(recovered.task_change_set(&task_id).is_none());
    assert_eq!(
        recovered
            .state()
            .state_records("controller.task_carry_fingerprint")
            .unwrap_or_else(|error| panic!("legacy carry records: {error}"))
            .len(),
        0,
        "legacy primary recovery must not become modern D3/D4 carry authority"
    );
    assert_eq!(
        recovered
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("recovered action record: {error}"))
            .map(|record| record.state),
        Some("committed".to_owned())
    );
    assert_eq!(
        fs::read_to_string(&target)
            .unwrap_or_else(|error| panic!("read recovered primary effect: {error}")),
        postimage
    );
    drop(recovered);

    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen state for forged v2 authority: {error}"));
    let mut forged = legacy;
    forged["worktree_lease_id"] = json!("worktree.forged-v2");
    forged["execution_root"] = json!(fixture.repo.base.join("forged-worktree"));
    let forged_raw = serde_json::to_string(&forged)
        .unwrap_or_else(|error| panic!("encode forged v2 authority: {error}"));
    state
        .put_state("controller.action_intent", &action_id, &forged_raw)
        .unwrap_or_else(|error| panic!("persist forged v2 authority: {error}"));
    let forged_digest = sha256_prefixed(forged_raw.as_bytes());
    append_modified_checkpoint(&mut state, |manifest| {
        manifest.evidence_binding_digests.insert(
            format!("controller.action_intent:{action_id}"),
            forged_digest,
        );
    });
    drop(state);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen forged v2 state: {error}"));
    let error = RecoveryManager::recover(state, &fixture.registry)
        .err()
        .unwrap_or_else(|| panic!("v2 intent with worktree fields must fail recovery"));
    assert!(
        error
            .to_string()
            .contains("legacy v2 action intent contains fields that did not exist in v2"),
        "unexpected forged-v2 recovery error: {error}"
    );
}

#[test]
fn worktree_mutating_t1_to_t2_composes_verified_upstream_and_readiness_uses_composed_view() {
    let mut fixture = compiled_worktree_graph_fixture(
        "worktree-mutating-chain",
        &[
            worktree_graph_task("T1", "src/settings/SettingsForm.tsx", &[], "Save", "Apply"),
            worktree_graph_task(
                "T2",
                "src/settings/SettingsForm.tsx",
                &["T1"],
                "Apply",
                "Applied",
            ),
        ],
    );
    let t1 = task_id_for_objective(&fixture, "Save to Apply");
    let t2 = task_id_for_objective(&fixture, "Apply to Applied");
    let primary_before = fixture
        .registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("primary before chain: {error}"));
    let (mut controller, _) = controller_for(&mut fixture);

    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t1,
        "src/settings/SettingsForm.tsx",
        "Save",
        "Apply",
    );
    let t1_change_set = controller
        .task_change_set(&t1)
        .cloned()
        .unwrap_or_else(|| panic!("T1 ChangeSet missing"));
    assert!(t1_change_set.diff_content.contains("Apply"));

    let ready = controller
        .derive_ready_lease(&fixture.registry, &t2, readiness(), &write_tool_manifest())
        .unwrap_or_else(|error| {
            panic!("T2 must become ready from composed T1 output, not primary: {error}")
        });
    let t2_lease = controller
        .task_worktree_lease(&t2)
        .cloned()
        .unwrap_or_else(|| panic!("T2 worktree missing"));
    let composed = fs::read_to_string(t2_lease.worktree_path.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read T2 composed form: {error}"));
    assert!(composed.contains(">Apply</button>"));
    assert!(!composed.contains(">Save</button>"));
    assert!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read primary during T2: {error}"))
            .contains(">Save</button>")
    );
    controller
        .cancel_ready_lease(ready)
        .unwrap_or_else(|error| panic!("cancel T2 preflight ready: {error}"));

    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t2,
        "src/settings/SettingsForm.tsx",
        "Apply",
        "Applied",
    );
    let t2_change_set = controller
        .task_change_set(&t2)
        .unwrap_or_else(|| panic!("T2 ChangeSet missing"));
    assert!(t2_change_set.diff_content.contains("Applied"));
    assert!(t2_change_set.diff_content.contains("Apply"));
    assert!(!t2_change_set.diff_content.contains(">Save</button>"));
    assert_eq!(
        fixture
            .registry
            .snapshot("repo.app")
            .unwrap_or_else(|error| panic!("primary after chain: {error}")),
        primary_before
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn worktree_join_composes_shared_ancestor_once_and_branch_local_deltas_deterministically() {
    let mut fixture = compiled_worktree_graph_fixture(
        "worktree-join",
        &[
            worktree_graph_task("T1", "src/settings/SettingsForm.tsx", &[], "Save", "Apply"),
            worktree_graph_task(
                "T2",
                "src/settings/SettingsForm.tsx",
                &["T1"],
                "Apply",
                "Applied",
            ),
            worktree_graph_task("T3", "src/other.txt", &["T1"], "baseline", "branchthree"),
            worktree_graph_task(
                "T4",
                "src/settings/SettingsImport.tsx",
                &["T2", "T3"],
                "imported",
                "finalized",
            ),
        ],
    );
    let t1 = task_id_for_objective(&fixture, "Save to Apply");
    let t2 = task_id_for_objective(&fixture, "Apply to Applied");
    let t3 = task_id_for_objective(&fixture, "baseline to branchthree");
    let t4 = task_id_for_objective(&fixture, "imported to finalized");
    let primary_before = fixture
        .registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("join primary before: {error}"));
    let (mut controller, _) = controller_for(&mut fixture);

    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t1,
        "src/settings/SettingsForm.tsx",
        "Save",
        "Apply",
    );
    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t2,
        "src/settings/SettingsForm.tsx",
        "Apply",
        "Applied",
    );
    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t3,
        "src/other.txt",
        "baseline",
        "branchthree",
    );

    let ready = controller
        .derive_ready_lease(&fixture.registry, &t4, readiness(), &write_tool_manifest())
        .unwrap_or_else(|error| panic!("join T4 ready: {error}"));
    let t4_lease = controller
        .task_worktree_lease(&t4)
        .cloned()
        .unwrap_or_else(|| panic!("join T4 lease missing"));
    let form = fs::read_to_string(t4_lease.worktree_path.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read joined form: {error}"));
    assert!(form.contains(">Applied</button>"));
    assert_eq!(form.matches("Applied").count(), 1);
    assert_eq!(
        fs::read_to_string(t4_lease.worktree_path.join("src/other.txt"))
            .unwrap_or_else(|error| panic!("read joined other: {error}")),
        "branchthree other file\n"
    );
    controller
        .cancel_ready_lease(ready)
        .unwrap_or_else(|error| panic!("cancel T4 preflight ready: {error}"));

    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t4,
        "src/settings/SettingsImport.tsx",
        "imported",
        "finalized",
    );
    let t4_change_set = controller
        .task_change_set(&t4)
        .unwrap_or_else(|| panic!("T4 ChangeSet missing"));
    assert_eq!(
        t4_change_set.changed_paths,
        vec![PathBuf::from("src/settings/SettingsImport.tsx")]
    );
    assert!(!t4_change_set.diff_content.contains("SettingsForm.tsx"));
    assert!(!t4_change_set.diff_content.contains("src/other.txt"));
    assert_eq!(
        fixture
            .registry
            .snapshot("repo.app")
            .unwrap_or_else(|error| panic!("join primary after: {error}")),
        primary_before
    );
}

#[test]
fn worktree_join_conflict_is_durable_and_blocks_before_mutation() {
    let mut fixture = compiled_worktree_graph_fixture(
        "worktree-join-conflict",
        &[
            worktree_graph_task("T1", "src/settings/SettingsForm.tsx", &[], "Save", "Apply"),
            worktree_graph_task(
                "T2",
                "src/settings/SettingsForm.tsx",
                &["T1"],
                "Apply",
                "Applied",
            ),
            worktree_graph_task(
                "T3",
                "src/settings/SettingsForm.tsx",
                &["T1"],
                "Apply",
                "Approved",
            ),
            worktree_graph_task(
                "T4",
                "src/settings/SettingsImport.tsx",
                &["T2", "T3"],
                "imported",
                "finalized",
            ),
        ],
    );
    let t1 = task_id_for_objective(&fixture, "Save to Apply");
    let t2 = task_id_for_objective(&fixture, "Apply to Applied");
    let t3 = task_id_for_objective(&fixture, "Apply to Approved");
    let t4 = task_id_for_objective(&fixture, "imported to finalized");
    let (mut controller, _) = controller_for(&mut fixture);
    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t1,
        "src/settings/SettingsForm.tsx",
        "Save",
        "Apply",
    );
    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t2,
        "src/settings/SettingsForm.tsx",
        "Apply",
        "Applied",
    );
    execute_worktree_replace(
        &mut controller,
        &fixture,
        &t3,
        "src/settings/SettingsForm.tsx",
        "Apply",
        "Approved",
    );

    let error = controller
        .derive_ready_lease(&fixture.registry, &t4, readiness(), &write_tool_manifest())
        .err()
        .unwrap_or_else(|| panic!("conflicting join must not become ready"));
    assert!(error.to_string().contains("composition conflict"));
    let conflict = controller
        .task_worktree_conflict(&t4)
        .cloned()
        .unwrap_or_else(|| panic!("durable T4 conflict evidence missing"));
    assert!(
        conflict
            .conflict_paths
            .contains(&PathBuf::from("src/settings/SettingsForm.tsx"))
    );
    let durable_conflicts = controller
        .state()
        .state_records("controller.worktree_conflict")
        .unwrap_or_else(|error| panic!("read durable conflict records: {error}"));
    assert_eq!(durable_conflicts.len(), 1);
    assert!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read conflict primary: {error}"))
            .contains(">Save</button>")
    );
}
