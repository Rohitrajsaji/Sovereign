#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
    EvidenceKind, RepairPacket,
};
use sovereign_controller::{
    CheckpointActionRecord, CheckpointManifest, CheckpointRepositoryBaselineV1, Controller,
    ControllerError, ExecutionRuntime, ExecutionSuccess, FailureClassification,
    FailureClassificationKind, LocalControl, ModelProposalV1, PermissionContext, PlanValidity,
    ProductionAdvanceOutcome, ProductionAdvanceResources, ProductionBlockReason,
    ProductionBrowserResources, ProductionCompilationResources, ProductionExecutionCatalog,
    ProductionExecutionResources, ReadinessInputs, RecoveryManager,
    ResourcePressureProbe, RoleId, RoleRegistry, SchedulerView, SecretProcessRuntime, TaskState,
    VERIFICATION_RESULT_SCHEMA_VERSION, VerificationResultV1,
};
#[cfg(feature = "recovery-test-hooks")]
use sovereign_controller::{
    REPOSITORY_PROPOSAL_SCHEMA_VERSION, RepositoryActionV1, RepositoryProposalV1,
};
use sovereign_evidence::ArtifactStore;
use sovereign_memory::{MemoryKind, MemoryTrust, ProcedurePattern};
use sovereign_model::{
    BackendHealth, DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelError, ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResidencyProof,
    ModelResponse, ModelUsage,
};
use sovereign_plan::{
    BrowserAcceptanceActionV1, BrowserAcceptanceExpectationV1, BrowserAcceptanceSemanticV1,
    BrowserAcceptanceStepV1, BrowserAcceptanceTemplateV1, BrowserManagedAppLaunchV1,
    BrowserManagedArgBindingV1, BrowserManagedPersistenceBindingV1, BrowserManagedReadinessV1,
    DepthClassifier, DepthFeatureInput, DiagnosticCode, ExecutionDepth,
    M3PlanningInput, PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput,
    PlanCompilationRepository, PlanCompilationResult, PlanCompiler, PlanIr, PlanValidator,
    ValidationEnvironment,
};
use sovereign_policy::{
    CapabilityLayers, CapabilitySet, CommandMode, CommandPolicy, CommandRisk, CommandSpec,
    ControllerSecretLocator, ExecutionIsolationBackend, FakeSecretProvider, IsolatedCommand,
    IsolationCapabilities, IsolationRequest, MacSandboxExecBackend, ModelCallBudget,
    OsMemoryPressure, PermissionDecision, PinnedExecutable, PolicyError,
    RESOURCE_PRESSURE_EVENT_SCHEMA_VERSION, ReconciliationPolicy, ResourcePressureSnapshotV1,
    SecretBroker, SecretInjection, SecretProviderBackend, SecretProviderKind, SecretRef,
    SecretValue, ThermalPressure,
};
use sovereign_repo::{
    ExactRetriever, OfflineDependencyLimits, ProjectRegistry, RepositoryIntelligence,
};
use sovereign_state::{
    ActionTransition, NewActionRecord, NewCheckpointIntegrityRecord, NewJournalEvent,
    StateRecordUpdate, StateStore,
};
use sovereign_tools::browser::BrowserAdapterConfig;
use sovereign_tools::{
    ActionJournal, AuthorizedAction, EPHEMERAL_SECRET_FILE_ENV, PermissionClass, ProcessRunner,
    ReconciliationMode, ToolError, ToolManifest, ToolSchemaV1, process_group_leader_identity,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOURCE: &str =
    "export function SettingsForm() {\n  return <button type=\"submit\">Save</button>;\n}\n";
const OTHER_SOURCE: &str = "baseline other file\n";
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BROWSER_TOOL_DIGEST: &str =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const MANAGED_LOOPBACK_NETWORK_BYTES: u64 = 1024 * 1024;
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "recovery-test-hooks")]
const PD_T05_V4_CRASH_STATE: &str = "SOVEREIGN_PD_T05_V4_CRASH_STATE";
#[cfg(feature = "recovery-test-hooks")]
const PD_T05_V4_CRASH_ROOT: &str = "SOVEREIGN_PD_T05_V4_CRASH_ROOT";
#[cfg(feature = "recovery-test-hooks")]
const PD_T05_V4_CRASH_BASE: &str = "SOVEREIGN_PD_T05_V4_CRASH_BASE";
#[cfg(feature = "recovery-test-hooks")]
const PD_T05_V4_CRASH_TASK: &str = "SOVEREIGN_PD_T05_V4_CRASH_TASK";
#[cfg(feature = "recovery-test-hooks")]
const PD_T05_V4_CRASH_KIND: &str = "SOVEREIGN_PD_T05_V4_CRASH_KIND";

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
    compilation_input: PlanCompilationInput,
    planning_response: ModelResponse,
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

fn singleton_checkpoint_repository(
    manifest: &CheckpointManifest,
) -> (String, CheckpointRepositoryBaselineV1) {
    assert_eq!(
        manifest.repository_baselines.len(),
        1,
        "single-repository fixture must carry exactly one canonical checkpoint baseline"
    );
    let (repository_id, baseline) = manifest
        .repository_baselines
        .iter()
        .next()
        .unwrap_or_else(|| panic!("single-repository checkpoint baseline missing"));
    assert_eq!(
        baseline.repository_snapshot.repository_id, *repository_id,
        "checkpoint repository baseline is misbound"
    );
    (repository_id.clone(), baseline.clone())
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

fn managed_loopback_policy(port: u16) -> Value {
    let mut policy = global_policy();
    policy["capability_ceiling"] = json!([
        "read",
        "process_exec",
        "browser_interactive",
        "network_read",
        "network_write"
    ]);
    policy["network"] = json!({
        "default": "task_scoped",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_schemes": ["http"],
        "allowed_ports": [port],
        "allowed_methods": ["GET", "POST"],
        "follow_redirects": true,
        "max_redirects": 1,
        "allow_private_ranges": false,
        "dns_revalidation": true,
        "connected_peer_validation": true,
        "ambient_proxy": "deny",
        "allow_task_loopback": true
    });
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY", "BROWSER"]);
    policy["resources"]["max_network_bytes"] = json!(MANAGED_LOOPBACK_NETWORK_BYTES);
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
        None,
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
        label, false, true, None, None, false, false, None, None, None, None, None,
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
        None,
    )
}

fn compiled_two_task_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(
        label, false, false, None, None, true, false, None, None, None, None, None,
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
        None,
    )
}

fn compiled_worktree_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(
        label, false, false, None, None, false, true, None, None, None, None, None,
    )
}

fn compiled_worktree_graph_fixture(label: &str, tasks: &[Value]) -> CompiledFixture {
    let mut policy = global_policy();
    policy["resources"]["max_model_calls"] = json!(tasks.len().max(2));
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
        Some(policy),
        None,
    )
}

fn compiled_command_verification_fixture(
    label: &str,
    expected_exit_codes: &[i32],
) -> CompiledFixture {
    let mut policy = global_policy();
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY"]);
    let planning = json!({
        "tasks": [{
            "local_id": "settings-command-verification",
            "repository_id": "repo.app",
            "title": "Rename label and run governed verification",
            "objective": "Change Save to Apply in SettingsForm and run the exact governed verification command.",
            "rationale": "The repository edit and its command evidence are both frozen in the task contract.",
            "files": ["src/settings/SettingsForm.tsx"],
            "symbols": ["SettingsForm"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "SettingsForm renders Apply.",
            "acceptance": [
                {
                    "kind": "diff",
                    "description": "The scoped Save-to-Apply diff is accepted.",
                    "manual_gate_id": Value::Null
                },
                {
                    "kind": "command",
                    "description": "Run the immutable nonzero verification command through the governed process path.",
                    "manual_gate_id": Value::Null,
                    "command_spec": {
                        "tool_id": "tool.patch",
                        "mode": "exec",
                        "program": "make",
                        "args": ["-f", "/dev/null", "sovereign-nonexistent-target"],
                        "repository_id": "repo.app",
                        "working_dir_relative": ".",
                        "literal_env": {},
                        "secret_env": {},
                        "timeout_seconds": 15,
                        "output_limit_bytes": 65_536
                    },
                    "expected_exit_codes": expected_exit_codes
                }
            ]
        }]
    });
    compiled_fixture_inner(
        label,
        false,
        false,
        None,
        None,
        false,
        false,
        Some(planning),
        Some("Rename Save to Apply and verify with the exact governed command.".to_owned()),
        None,
        Some(policy),
        Some(ExecutionDepth::D2),
    )
}

fn compiled_managed_loopback_fixture(label: &str, port: u16) -> CompiledFixture {
    compiled_managed_loopback_fixture_with_launch(label, port, BrowserManagedAppLaunchV1::PythonManagedServerV1 {
        server_relative_path: "src/other.txt".to_owned(),
        database_filename: "managed.sqlite3".to_owned(),
        required_generations: 2,
    })
}

fn compiled_managed_loopback_fixture_with_launch(label: &str, port: u16, launch: BrowserManagedAppLaunchV1) -> CompiledFixture {
    let acceptance = if label == "managed-node-production-driver" {
        json!([{
            "kind":"command", "description":"Run a bounded no-recipe Makefile gate",
            "manual_gate_id":null,
            "command_spec": {
                "tool_id":"tool.patch", "mode":"exec", "program":"make",
                "args":["-f", "Makefile", "all"], "repository_id":"repo.app",
                "working_dir_relative":".", "literal_env":{}, "secret_env":{},
                "timeout_seconds":15, "output_limit_bytes":65536
            },
            "expected_exit_codes":[0]
        }])
    } else {
        json!([{
            "kind": "command",
            "description": "Run the bounded local verification command.",
            "manual_gate_id": null,
            "command_spec": {
                "tool_id": "tool.patch", "mode": "exec", "program": "python3",
                "args": ["-B", "-c", "pass"], "repository_id": "repo.app",
                "working_dir_relative": ".", "literal_env": {}, "secret_env": {},
                "timeout_seconds": 15, "output_limit_bytes": 65536
            },
            "expected_exit_codes": [0]
        }])
    };
    let planning = json!({
        "tasks": [{
            "local_id": "managed-loopback-browser",
            "repository_id": "repo.app",
            "title": "Verify managed loopback authority",
            "objective": "Verify the local application through one governed loopback browser session.",
            "rationale": "The focused Controller regression needs exact process and browser authority without repository mutation.",
            "files": [],
            "create_files": [],
            "symbols": ["managed-loopback"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "No repository mutation; local browser verification succeeds.",
            "acceptance": acceptance
        }]
    });
    let mut fixture = compiled_fixture_inner(
        label,
        false,
        false,
        None,
        None,
        false,
        false,
        Some(planning),
        Some("Verify exact managed loopback application authority.".to_owned()),
        None,
        Some(managed_loopback_policy(port)),
        Some(ExecutionDepth::D2),
    );
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("managed loopback validator: {error}"));
    let compilation = fixture
        .compilation
        .take()
        .unwrap_or_else(|| panic!("managed loopback compilation missing"));
    let task_id = compilation.plan().as_value()["tasks"]
        .as_array()
        .and_then(|tasks| tasks.first())
        .and_then(|task| task["task_id"].as_str())
        .map_or_else(|| panic!("managed loopback task id missing"), str::to_owned);
    fixture.compilation = Some(
        compilation
            .bind_controller_loopback_browser_acceptance(
                &validator,
                &task_id,
                &capability("tool.browser", BROWSER_TOOL_DIGEST),
                port,
                MANAGED_LOOPBACK_NETWORK_BYTES,
                &BrowserAcceptanceTemplateV1 {
                    launch,
                    steps: vec![
                        BrowserAcceptanceStepV1 {
                            step_id: "browser.initial".to_owned(),
                            generation: 1,
                            action: BrowserAcceptanceActionV1::Navigate {
                                path: "/health".to_owned(),
                            },
                            expectation: BrowserAcceptanceExpectationV1 {
                                semantic: BrowserAcceptanceSemanticV1::Read,
                                required_contains: Vec::new(),
                                forbidden_contains: Vec::new(),
                            },
                        },
                        BrowserAcceptanceStepV1 {
                            step_id: "browser.restart.navigate".to_owned(),
                            generation: 2,
                            action: BrowserAcceptanceActionV1::Navigate { path: "/".to_owned() },
                            expectation: BrowserAcceptanceExpectationV1 {
                                semantic: BrowserAcceptanceSemanticV1::Read,
                                required_contains: Vec::new(),
                                forbidden_contains: Vec::new(),
                            },
                        },
                        BrowserAcceptanceStepV1 {
                            step_id: "browser.restart".to_owned(),
                            generation: 2,
                            action: BrowserAcceptanceActionV1::CaptureSynopsis,
                            expectation: BrowserAcceptanceExpectationV1 {
                                semantic: BrowserAcceptanceSemanticV1::RestartPersistence,
                                required_contains: vec!["persisted".to_owned()],
                                forbidden_contains: Vec::new(),
                            },
                        },
                    ],
                },
            )
            .unwrap_or_else(|error| panic!("bind managed loopback browser authority: {error:?}")),
    );
    fixture
}

#[test]
fn managed_loopback_compilation_binds_typed_browser_acceptance_without_symbol_heuristics() {
    let fixture = compiled_managed_loopback_fixture("typed-browser-acceptance", 41_739);
    let compilation = fixture
        .compilation
        .as_ref()
        .unwrap_or_else(|| panic!("typed browser compilation missing"));
    let task = &compilation.plan().as_value()["tasks"][0];
    let acceptance = &task["browser_acceptance"];

    assert_eq!(acceptance["schema_version"], json!(1));
    assert_eq!(acceptance["loopback"]["scheme"], json!("http"));
    assert_eq!(acceptance["loopback"]["host"], json!("127.0.0.1"));
    assert_eq!(acceptance["loopback"]["port"], json!(41_739));
    assert_eq!(
        acceptance["launch"]["runtime"],
        json!("python_managed_server_v1")
    );
    assert_eq!(acceptance["launch"]["required_generations"], json!(2));
    assert_eq!(
        acceptance["evidence_binding"]["receipt_digest"],
        json!(true)
    );
    assert_eq!(
        acceptance["evidence_binding"]["action_commit_sequence"],
        json!(true)
    );
    assert_eq!(
        acceptance["evidence_binding"]["managed_generation"],
        json!(true)
    );
    assert!(
        acceptance["steps"]
            .as_array()
            .is_some_and(|steps| steps.iter().any(|step| {
                step["generation"] == json!(2)
                    && step["expectation"]["semantic"] == json!("restart_persistence")
            }))
    );
    assert!(task["scope"]["symbols"].as_array().is_some_and(|symbols| {
        symbols
            .iter()
            .all(|symbol| symbol != "inventory-browser-proof")
    }));
}

#[cfg(feature = "recovery-test-hooks")]
fn compiled_repository_create_fixture(label: &str) -> CompiledFixture {
    let planning = json!({
        "tasks": [{
            "local_id": "create-generated-file",
            "repository_id": "repo.app",
            "title": "Create generated repository file",
            "objective": "Create src/generated.txt with the exact governed content.",
            "rationale": "The product proof requires a typed exact-scope create action.",
            "files": [],
            "create_files": ["src/generated.txt"],
            "symbols": ["generated"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "src/generated.txt exists with the exact governed content.",
            "acceptance": [{
                "kind": "diff",
                "description": "The exact create-file diff is accepted.",
                "manual_gate_id": Value::Null
            }]
        }]
    });
    compiled_fixture_inner(
        label,
        false,
        false,
        None,
        None,
        false,
        false,
        Some(planning),
        Some("Create the exact governed generated repository file.".to_owned()),
        None,
        None,
        Some(ExecutionDepth::D2),
    )
}

#[cfg(feature = "recovery-test-hooks")]
fn compiled_repository_update_fixture(label: &str) -> CompiledFixture {
    compiled_repository_update_fixture_inner(label, None)
}

#[cfg(feature = "recovery-test-hooks")]
fn compiled_repository_update_repair_fixture(label: &str) -> CompiledFixture {
    compiled_repository_update_fixture_inner(label, Some(2))
}

#[cfg(feature = "recovery-test-hooks")]
fn compiled_repository_update_fixture_inner(
    label: &str,
    task_model_call_cap: Option<u64>,
) -> CompiledFixture {
    let planning = json!({
        "tasks": [{
            "local_id": "update-settings-file",
            "repository_id": "repo.app",
            "title": "Update governed repository file",
            "objective": "Update SettingsForm.tsx with the exact governed content.",
            "rationale": "The product proof requires a typed exact-scope structured update action.",
            "files": ["src/settings/SettingsForm.tsx"],
            "create_files": [],
            "symbols": ["SettingsForm"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "SettingsForm.tsx contains the exact governed postimage.",
            "acceptance": [{
                "kind": "diff",
                "description": "The exact update-file diff is accepted.",
                "manual_gate_id": Value::Null
            }]
        }]
    });
    compiled_fixture_inner(
        label,
        false,
        false,
        task_model_call_cap,
        None,
        false,
        false,
        Some(planning),
        Some("Update the exact governed SettingsForm repository file.".to_owned()),
        None,
        None,
        Some(ExecutionDepth::D2),
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
    m3_depth_override: Option<ExecutionDepth>,
) -> CompiledFixture {
    let repo = TestRepo::create(label);
    if label == "managed-node-production-driver" {
        fs::write(repo.root.join("Makefile"), "all:\n")
            .unwrap_or_else(|error| panic!("write no-recipe fixture: {error}"));
        git(&repo.root, &["add", "Makefile"]);
        git(&repo.root, &["commit", "-qm", "bounded no-recipe gate"]);
    }
    if label.starts_with("managed-node-") || label.starts_with("managed-postgres-") {
        fs::create_dir_all(repo.root.join("apps/inventory"))
            .unwrap_or_else(|error| panic!("create Node fixture directory: {error}"));
        let server_source = if label.starts_with("managed-postgres-") { r#"
const http = require('node:http');
const net = require('node:net');
const args = process.argv.slice(2);
const value = (name) => args[args.indexOf(name) + 1];
const port = Number(value('--port'));
const database = new URL(value('--database-url'));
if (!Number.isInteger(port) || port <= 0 || database.pathname !== '/sovereign_app' || database.username !== 'sovereign_app_runtime') process.exit(2);
const connection = net.connect(Number(database.port), database.hostname);
let buffer = Buffer.alloc(0);
let queried = false;
let row = false;
let ready = false;
connection.on('connect', () => {
  const body = Buffer.concat([Buffer.from([0, 3, 0, 0]), Buffer.from('user\0sovereign_app_runtime\0database\0sovereign_app\0\0')]);
  const packet = Buffer.alloc(4); packet.writeUInt32BE(body.length + 4);
  connection.write(Buffer.concat([packet, body]));
});
connection.on('data', (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  while (buffer.length >= 5) {
    const length = buffer.readUInt32BE(1);
    if (length < 4 || length > 65536) process.exit(3);
    if (buffer.length < length + 1) break;
    const kind = String.fromCharCode(buffer[0]);
    const body = buffer.subarray(5, length + 1);
    buffer = buffer.subarray(length + 1);
    if (kind === 'E') process.exit(4);
    if (kind === 'D') row = body.includes(Buffer.from('sovereign_app_runtime')) && body.includes(Buffer.from('sovereign_app'));
    if (kind === 'Z' && !queried) {
      queried = true;
      const query = Buffer.from('SELECT current_user,current_database()\0');
      const packet = Buffer.alloc(5); packet[0] = 81; packet.writeUInt32BE(query.length + 4, 1);
      connection.write(Buffer.concat([packet, query]));
    } else if (kind === 'Z' && queried && row && !ready) {
      ready = true;
      const direct = net.connect(5432, '127.0.0.1');
      direct.setTimeout(500);
      direct.on('connect', () => process.exit(7));
      let served = false;
      const serve = () => { if (served) return; served = true; http.createServer((req, res) => {
        res.writeHead(200, {'content-type': 'text/plain'});
        res.end(req.url === '/health' ? 'ok' : 'sovereign_app');
      }).listen(port, '127.0.0.1'); };
      direct.on('error', serve);
      direct.on('timeout', () => { direct.destroy(); serve(); });
    }
  }
});
connection.on('error', () => process.exit(5));
connection.on('close', () => { if (!ready) process.exit(6); });
"# } else { r#"
const http = require('node:http');
const fs = require('node:fs');
const args = process.argv.slice(2);
const value = (name) => args[args.indexOf(name) + 1];
const port = Number(value('--port'));
const db = value('--db');
if (!Number.isInteger(port) || port <= 0 || !db) process.exit(2);
fs.writeFileSync(db, fs.existsSync(db) ? fs.readFileSync(db) : 'persisted');
http.createServer((req, res) => {
  res.writeHead(200, {'content-type': 'text/plain'});
  res.end(req.url === '/health' ? 'ok' : fs.readFileSync(db));
}).listen(port, '127.0.0.1');
"# };
        fs::write(repo.root.join("apps/inventory/server.js"), server_source)
            .unwrap_or_else(|error| panic!("write Node fixture: {error}"));
        git(&repo.root, &["add", "apps/inventory/server.js"]);
        git(&repo.root, &["commit", "-qm", "Node managed fixture"]);
    }
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
    let uses_general_repository_action = planning["tasks"]
        .as_array()
        .is_some_and(|tasks| tasks.iter().any(|task| task.get("create_files").is_some()));
    let planning_response = model_response(
        planning.to_string(),
        packet.metrics.final_serialized_input_tokens,
    );
    let planner = backend(vec![planning_response.clone()]);
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
    let requested_m3_depth =
        m3_depth_override.or_else(|| worktree_depth.then_some(ExecutionDepth::D3));
    let m3 = requested_m3_depth.map(|depth| {
        let mut decision = DepthClassifier.classify(&DepthFeatureInput {
            repository_count: 1,
            language_count: 1,
            expected_files: 1,
            expected_modules: 2,
            architecture_uncertainty_percent: 60,
            ..DepthFeatureInput::default()
        });
        decision.mode = depth;
        if worktree_depth {
            "controller worktree fixture".clone_into(&mut decision.reason);
        } else {
            "controller rich-plan fixture".clone_into(&mut decision.reason);
        }
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
        diff_evaluator: if uses_general_repository_action {
            "builtin.diff.scoped_change.v1".to_owned()
        } else {
            "builtin.diff.scope_and_literal.v1".to_owned()
        },
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
        compilation_input: input,
        planning_response,
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

#[test]
fn production_driver_compiles_executes_verifies_and_finalizes_queued_goal() {
    let fixture = compiled_worktree_fixture("production-driver-complete");
    let state = StateStore::open(&fixture.repo.state_path).expect("open production state");
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let intent = controller
        .submit_goal_intent(&fixture.compilation_input.goal_statement)
        .expect("submit queued production goal");
    let mut input = fixture.compilation_input.clone();
    input.goal_id = intent.goal_id.clone();
    let planner = backend(vec![fixture.planning_response.clone()]);
    let validator = PlanValidator::new(ValidationEnvironment::default()).expect("validator");
    let mut compile_budget = ModelCallBudget::new(1, 30_000);
    let compilation = ProductionCompilationResources {
        input: &input,
        backend: &planner,
        validator: &validator,
        compiler_version: "t07-test-compiler",
        model_budget: &mut compile_budget,
    };
    let compiled = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources::<MacSandboxExecBackend> {
                compilation: Some(compilation),
                execution: None,
            },
        )
        .expect("compile and activate queued goal");
    assert!(matches!(
        compiled,
        ProductionAdvanceOutcome::PlanActivated { .. }
    ));
    planner.unload().expect("unload planning model");
    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path).expect("reopen activated plan state");
    let mut controller = Controller::reopen_local(state).expect("recover activated queued goal");
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));

    let execution = backend(vec![model_response(
        valid_execution_proposal(&fixture.form_digest),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let parts = runtime_parts(&fixture);
    let isolation = MacSandboxExecBackend::detect().expect("seatbelt isolation");
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
    let mut execution_budget = ModelCallBudget::new(1, 30_000);
    let verified = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources {
                compilation: None,
                execution: Some(ProductionExecutionResources {
                    runtime: &runtime,
                    context: &fixture.packet,
                    tool_schemas: &[],
                    readiness: readiness(),
                    model_budget: &mut execution_budget,
                }),
            },
        )
        .expect("execute and verify compiled task");
    assert!(matches!(
        verified,
        ProductionAdvanceOutcome::TaskVerified { .. }
    ));
    assert!(matches!(
        controller
            .advance_production_goal(
                &fixture.registry,
                ProductionAdvanceResources::<MacSandboxExecBackend>::default(),
            )
            .expect("complete verified goal"),
        ProductionAdvanceOutcome::GoalCompleted { .. }
    ));
    assert!(matches!(
        controller
            .advance_production_goal(
                &fixture.registry,
                ProductionAdvanceResources::<MacSandboxExecBackend>::default(),
            )
            .expect("finalize completed goal"),
        ProductionAdvanceOutcome::Complete { .. }
    ));
    assert!(
        controller
            .durable_status()
            .expect("status")
            .active_plan
            .is_none()
    );
}

#[test]
fn production_compilation_failure_does_not_refill_model_calls_after_restart() {
    let fixture = compiled_fixture("production-compile-restart", false);
    let state = StateStore::open(&fixture.repo.state_path).expect("open production state");
    let mut controller = Controller::new(state);
    let intent = controller
        .submit_goal_intent(&fixture.compilation_input.goal_statement)
        .expect("submit queued goal");
    let mut input = fixture.compilation_input.clone();
    input.goal_id = intent.goal_id.clone();
    let bad_backend = backend(vec![model_response(
        "not a JSON planning proposal".to_owned(),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let validator = PlanValidator::new(ValidationEnvironment::default()).expect("validator");
    let mut budget = ModelCallBudget::new(1, 30_000);
    let failed = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources::<MacSandboxExecBackend> {
                compilation: Some(ProductionCompilationResources {
                    input: &input,
                    backend: &bad_backend,
                    validator: &validator,
                    compiler_version: "t07-test-compiler",
                    model_budget: &mut budget,
                }),
                execution: None,
            },
        )
        .expect("bounded compile rejection");
    assert!(matches!(
        failed,
        ProductionAdvanceOutcome::Blocked {
            reason: ProductionBlockReason::CompilationFailed(_),
            ..
        }
    ));
    assert_eq!(
        controller
            .next_queued_goal_intent()
            .expect("queue")
            .unwrap()
            .goal_id,
        intent.goal_id
    );
    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path).expect("reopen state");
    let mut controller = Controller::reopen_local(state).expect("recover queued state");
    let valid_backend = backend(vec![fixture.planning_response.clone()]);
    let mut fresh_budget = ModelCallBudget::new(1, 30_000);
    let exhausted = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources::<MacSandboxExecBackend> {
                compilation: Some(ProductionCompilationResources {
                    input: &input,
                    backend: &valid_backend,
                    validator: &validator,
                    compiler_version: "t07-test-compiler",
                    model_budget: &mut fresh_budget,
                }),
                execution: None,
            },
        )
        .expect("durable compile budget denial");
    assert!(matches!(
        exhausted,
        ProductionAdvanceOutcome::Blocked {
            reason: ProductionBlockReason::CompilationBudgetExhausted,
            ..
        }
    ));
    assert_eq!(
        controller
            .next_queued_goal_intent()
            .expect("queue")
            .unwrap()
            .goal_id,
        intent.goal_id
    );
}

#[test]
fn production_compilation_budget_rejects_tampered_reservation_history() {
    let fixture = compiled_fixture("production-compile-tamper", false);
    let state = StateStore::open(&fixture.repo.state_path).expect("open state");
    let mut controller = Controller::new(state);
    let intent = controller
        .submit_goal_intent(&fixture.compilation_input.goal_statement)
        .expect("submit goal");
    let mut input = fixture.compilation_input.clone();
    input.goal_id = intent.goal_id.clone();
    let bad_backend = backend(vec![model_response(
        "invalid planning proposal".to_owned(),
        fixture.packet.metrics.final_serialized_input_tokens,
    )]);
    let validator = PlanValidator::new(ValidationEnvironment::default()).expect("validator");
    let mut budget = ModelCallBudget::new(1, 30_000);
    let _ = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources::<MacSandboxExecBackend> {
                compilation: Some(ProductionCompilationResources {
                    input: &input,
                    backend: &bad_backend,
                    validator: &validator,
                    compiler_version: "t07-test-compiler",
                    model_budget: &mut budget,
                }),
                execution: None,
            },
        )
        .expect("consume reserved call");
    drop(controller);

    let mut state = StateStore::open(&fixture.repo.state_path).expect("open tamper state");
    let raw = state
        .get_state("controller.goal_compilation_budget", &intent.goal_id)
        .expect("read budget")
        .expect("budget row");
    let mut forged: Value = serde_json::from_str(&raw).expect("decode budget");
    forged["calls_used"] = json!(0);
    state
        .put_state(
            "controller.goal_compilation_budget",
            &intent.goal_id,
            &forged.to_string(),
        )
        .expect("forge budget row");
    let mut controller = Controller::reopen_local(state).expect("reopen queued goal");
    let valid_backend = backend(vec![fixture.planning_response.clone()]);
    let mut fresh_budget = ModelCallBudget::new(1, 30_000);
    let error = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources::<MacSandboxExecBackend> {
                compilation: Some(ProductionCompilationResources {
                    input: &input,
                    backend: &valid_backend,
                    validator: &validator,
                    compiler_version: "t07-test-compiler",
                    model_budget: &mut fresh_budget,
                }),
                execution: None,
            },
        )
        .expect_err("tampered budget cannot refill a model call");
    assert!(error.to_string().contains("compilation budget version"));
}

#[test]
fn production_driver_requests_browser_execution_inputs_instead_of_external_handoff() {
    let mut fixture = compiled_managed_loopback_fixture("production-browser-handoff", 41_740);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let outcome = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources::<MacSandboxExecBackend>::default(),
        )
        .expect("browser resource request");
    assert_eq!(
        outcome,
        ProductionAdvanceOutcome::Blocked {
            task_id: Some(task_id),
            reason: ProductionBlockReason::ExecutionInputsRequired,
        }
    );
}

#[test]
fn production_driver_executes_typed_browser_task_without_external_handoff() {
    let node_path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("node"))
        .find(|path| path.is_file())
        .expect("installed Node fixture executable");
    let node = PinnedExecutable::from_path(&node_path, "fixture-node").expect("pin Node");
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .expect("pin Python");
    let make = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
        .expect("pin Make");
    let policy = CommandPolicy::new(
        [python.clone(), node.clone(), make.clone()],
        [python.path.parent().unwrap().to_path_buf(), node.path.parent().unwrap().to_path_buf(), make.path.parent().unwrap().to_path_buf()],
    ).expect("command policy");
    let listener = TcpListener::bind("127.0.0.1:0").expect("dynamic app port");
    let port = listener.local_addr().expect("loopback address").port();
    drop(listener);
    let launch = BrowserManagedAppLaunchV1::NodeManagedServerV1 {
        working_directory_relative_path: "apps/inventory".to_owned(),
        entrypoint_relative_path: "server.js".to_owned(),
        argv: Vec::new(),
        dynamic_port: BrowserManagedArgBindingV1::ArgvFlag { flag: "--port".to_owned() },
        readiness: BrowserManagedReadinessV1 { path: "/health".to_owned(), status: 200, body: "ok".to_owned(), timeout_ms: 5_000 },
        persistence: BrowserManagedPersistenceBindingV1::ArgvFlag { flag: "--db".to_owned(), filename: "inventory.sqlite3".to_owned() },
        required_generations: 2,
    };
    let mut fixture = compiled_managed_loopback_fixture_with_launch("managed-node-production-driver", port, launch);
    let state = StateStore::open(&fixture.repo.state_path).expect("open state");
    let mut controller = Controller::with_permission_context(state, PermissionContext::m7_local_browser_execution());
    let mut pressure = green_pressure_snapshot(1_000);
    pressure.host_free_disk_mib = Some(32_768);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(pressure)));
    let activation = controller.activate(fixture.compilation.take().expect("plan"), &fixture.registry)
        .expect("activate browser task");
    controller.configure_managed_node_executable(&policy, &node.path).expect("pin Controller Node");
    let parts = runtime_parts(&fixture);
    let backend = backend(Vec::new());
    backend.unload().expect("browser fixture has no Controller-owned MODEL residency");
    let isolation = MacSandboxExecBackend::detect().expect("Seatbelt");
    let runtime = ExecutionRuntime {
        registry: &fixture.registry, backend: &backend, command_policy: &policy,
        isolation_backend: &isolation, isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts, tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let browser_manifest = browser_tool_manifest();
    let read_manifest = sovereign_tools::canonical_read_tool_manifest();
    let catalog = ProductionExecutionCatalog {
        read_tool_manifest: &read_manifest,
        process_tool_manifest: &sovereign_tools::canonical_process_tool_manifest(),
        browser: Some(ProductionBrowserResources {
            tool_manifest: &browser_manifest,
            chrome_path: Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            adapter_config: BrowserAdapterConfig { request_timeout_ms: 5_000, ..BrowserAdapterConfig::default() },
        }),
    };
    let mut budget = ModelCallBudget::new(0, 30_000);
    let context = controller
        .production_task_context(&fixture.registry, &activation.task_ids[0])
        .expect("Controller-created browser context");
    let outcome = controller.advance_production_goal_with_catalog(
        &fixture.registry,
        ProductionAdvanceResources {
            compilation: None,
            execution: Some(ProductionExecutionResources {
                runtime: &runtime, context: &context, tool_schemas: &[],
                readiness: readiness(), model_budget: &mut budget,
            }),
        },
        Some(&catalog),
    ).expect("Controller-owned browser execution");
    assert_eq!(outcome, ProductionAdvanceOutcome::TaskVerified { task_id: activation.task_ids[0].clone() });
    assert_eq!(controller.task_state(&activation.task_ids[0]), Some(TaskState::Succeeded));
}

#[test]
fn production_driver_respects_durable_pause_before_task_dispatch() {
    let mut fixture = compiled_worktree_fixture("production-driver-pause");
    let (mut controller, task_id) = controller_for(&mut fixture);
    controller
        .pause(Some("operator pause"))
        .expect("pause Controller");
    let before = controller.task_state(&task_id);
    let outcome = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources::<MacSandboxExecBackend>::default(),
        )
        .expect("paused production step");
    assert_eq!(outcome, ProductionAdvanceOutcome::Paused);
    assert_eq!(controller.task_state(&task_id), before);
}

#[test]
fn production_driver_preserves_non_write_permission_denial() {
    let planning = json!({
        "tasks": [{
            "local_id": "non-write-command",
            "repository_id": "repo.app",
            "title": "Verify repository without mutation",
            "objective": "Read the repository and run the bounded verification command.",
            "rationale": "The command and no-write scope are frozen in the task contract.",
            "files": [],
            "create_files": [],
            "symbols": [],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "No repository mutation; verification passes.",
            "acceptance": [{
                "kind": "command",
                "description": "The exact read-only command exits successfully.",
                "manual_gate_id": Value::Null,
                "command_spec": {
                    "tool_id": "tool.patch",
                    "mode": "exec",
                    "program": "python3",
                    "args": ["-B", "-c", "pass"],
                    "repository_id": "repo.app",
                    "working_dir_relative": ".",
                    "literal_env": {},
                    "secret_env": {},
                    "timeout_seconds": 15,
                    "output_limit_bytes": 65536
                },
                "expected_exit_codes": [0]
            }]
        }]
    });
    let mut policy = global_policy();
    policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY"]);
    let mut fixture = compiled_fixture_inner(
        "production-read-process",
        false,
        false,
        None,
        None,
        false,
        false,
        Some(planning),
        Some("Verify a repository without changing it.".to_owned()),
        None,
        Some(policy),
        Some(ExecutionDepth::D2),
    );
    let (mut controller, task_id) = controller_for(&mut fixture);
    controller
        .set_task_capability_grant(&task_id, CapabilitySet::new([PermissionClass::ProcessExec]))
        .expect("narrow task grant to omit read");
    let execution = backend(Vec::new());
    let mut parts = runtime_parts(&fixture);
    parts
        .manifest
        .permission_ceiling
        .insert(PermissionClass::Read);
    parts
        .manifest
        .permission_ceiling
        .remove(&PermissionClass::RepositoryWrite);
    parts.isolation_request.allow_repository_write = false;
    let isolation = MacSandboxExecBackend::detect().expect("seatbelt isolation");
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
    let outcome = controller
        .advance_production_goal(
            &fixture.registry,
            ProductionAdvanceResources {
                compilation: None,
                execution: Some(ProductionExecutionResources {
                    runtime: &runtime,
                    context: &fixture.packet,
                    tool_schemas: &[],
                    readiness: readiness(),
                    model_budget: &mut budget,
                }),
            },
        )
        .expect("governed non-write execution");
    assert!(matches!(
        outcome,
        ProductionAdvanceOutcome::Blocked {
            task_id: Some(blocked_task_id),
            reason: ProductionBlockReason::Readiness(reason),
        } if blocked_task_id == task_id && reason.contains("effective permission intersection")
    ));
}

#[test]
fn production_driver_completes_genuine_read_only_task() {
    let planning = json!({
        "tasks": [{
            "local_id": "inspect-repository",
            "repository_id": "repo.app",
            "title": "Inspect repository evidence",
            "objective": "Read the bounded repository snapshot and record the requested evidence.",
            "rationale": "The task is read-only and requires no process or repository mutation authority.",
            "files": [],
            "create_files": [],
            "symbols": [],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "A Controller evidence artifact is recorded without repository changes.",
            "acceptance": [{
                "kind": "artifact",
                "description": "The Controller records the repository evidence artifact.",
                "manual_gate_id": Value::Null
            }]
        }]
    });
    let fixture = compiled_fixture_inner(
        "production-driver-read-only",
        false,
        false,
        None,
        None,
        false,
        false,
        Some(planning),
        Some("Inspect the repository without modifying it.".to_owned()),
        None,
        None,
        Some(ExecutionDepth::D2),
    );
    let state = StateStore::open(&fixture.repo.state_path).expect("open read-only state");
    let mut controller = Controller::new(state);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let compilation = fixture
        .compilation
        .as_ref()
        .expect("compiled fixture plan");
    let activation = controller
        .activate(compilation.clone(), &fixture.registry)
        .expect("activate read-only plan");
    let task_id = activation.task_ids[0].clone();
    let compiled_task = &compilation.plan().as_value()["tasks"][0];
    assert_eq!(compiled_task["permissions"], json!(["read"]));
    assert!(
        compiled_task["scope"]["files"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert!(
        compiled_task["scope"]["allow_create"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );

    let mut parts = runtime_parts(&fixture);
    parts.isolation_request.allow_repository_write = false;
    let read_manifest = ToolManifest {
        tool_id: "tool.read".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        permission_ceiling: BTreeSet::from([PermissionClass::Read]),
        declared_risk_floor: CommandRisk::ReadOnly,
        reconciliation_policy: ReconciliationPolicy::proof_required_local(),
    };
    let execution = backend(Vec::new());
    let isolation = MacSandboxExecBackend::detect().expect("seatbelt isolation");
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
    let context = controller
        .production_task_context(&fixture.registry, &task_id)
        .expect("Controller-created read-only context");
    let outcome = controller
        .advance_production_goal_with_catalog(
            &fixture.registry,
            ProductionAdvanceResources {
                compilation: None,
                execution: Some(ProductionExecutionResources {
                    runtime: &runtime,
                    context: &context,
                    tool_schemas: &[],
                    readiness: readiness(),
                    model_budget: &mut budget,
                }),
            },
            Some(&ProductionExecutionCatalog {
                read_tool_manifest: &read_manifest,
                process_tool_manifest: &sovereign_tools::canonical_process_tool_manifest(),
                browser: None,
            }),
        )
        .expect("advance read-only task");
    assert_eq!(
        outcome,
        ProductionAdvanceOutcome::TaskVerified {
            task_id: task_id.clone()
        }
    );
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
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

fn browser_tool_manifest() -> ToolManifest {
    ToolManifest {
        tool_id: "tool.browser".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: BROWSER_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([
            PermissionClass::BrowserInteractive,
            PermissionClass::NetworkRead,
            PermissionClass::NetworkWrite,
        ]),
        declared_risk_floor: CommandRisk::ReadOnly,
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
    runtime_parts_for_paths(&fixture.repo.root, &fixture.repo.base)
}

fn runtime_parts_for_paths(root: &Path, base: &Path) -> RuntimeParts {
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin python: {error}"));
    let executable_root = python
        .path
        .parent()
        .unwrap_or_else(|| panic!("python parent"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([python], [executable_root])
        .unwrap_or_else(|error| panic!("command policy: {error}"));
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
    RuntimeParts {
        command_policy,
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
            .unwrap_or_else(|error| panic!("artifacts: {error}")),
        manifest: write_tool_manifest(),
    }
}

fn runtime_parts_with_make(fixture: &CompiledFixture) -> RuntimeParts {
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin python: {error}"));
    let make = PinnedExecutable::from_path("/usr/bin/make", "macos-system-make")
        .unwrap_or_else(|error| panic!("pin make: {error}"));
    let roots = [
        python
            .path
            .parent()
            .unwrap_or_else(|| panic!("python parent"))
            .to_path_buf(),
        make.path
            .parent()
            .unwrap_or_else(|| panic!("make parent"))
            .to_path_buf(),
    ];
    let command_policy = CommandPolicy::new([python, make], roots)
        .unwrap_or_else(|error| panic!("command policy with make: {error}"));
    let home = std::env::var_os("HOME").map_or_else(|| panic!("HOME"), PathBuf::from);
    RuntimeParts {
        command_policy,
        isolation_request: IsolationRequest {
            repository_root: fixture.repo.root.clone(),
            user_home_root: home,
            extra_protected_read_roots: Vec::new(),
            rust_toolchain: None,
            build_scratch_root: None,
            network_offline: true,
            allow_repository_write: true,
            require_full_filesystem_read_jail: false,
        },
        artifacts: ArtifactStore::open(fixture.repo.base.join("cas"))
            .unwrap_or_else(|error| panic!("artifacts: {error}")),
        manifest: write_tool_manifest(),
    }
}

#[cfg(feature = "recovery-test-hooks")]
fn repository_context_packet(registry: &ProjectRegistry, task_contract: &str) -> ContextPacket {
    let snapshot = registry
        .snapshot("repo.app")
        .unwrap_or_else(|error| panic!("snapshot crash-worker repository: {error}"));
    let retriever = ExactRetriever::new(registry);
    let form = retriever
        .read_path("repo.app", Path::new("src/settings/SettingsForm.tsx"), None)
        .unwrap_or_else(|error| panic!("read crash-worker source: {error}"));
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns all state and authority.".to_owned(),
                task_contract: task_contract.to_owned(),
                current_state: format!("dirty_digest={}", snapshot.dirty_digest),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![EvidenceItem::from_exact_file(&form, "exact source")],
                output_schema: "phase-specific typed proposal".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build crash-worker context: {error}"))
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

#[cfg(feature = "recovery-test-hooks")]
#[test]
#[allow(clippy::too_many_lines)]
fn repository_model_stale_update_repairs_from_repair_pending_to_success() {
    let mut fixture = compiled_repository_update_repair_fixture("repository-model-stale-repair");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive repository ready lease: {error}"));
    let context = repository_context_packet(
        &fixture.registry,
        "Update the exact governed SettingsForm repository file.",
    );
    let exact_source = context
        .items
        .iter()
        .find(|item| item.evidence_id == "file:repo.app:src/settings/SettingsForm.tsx")
        .unwrap_or_else(|| panic!("repository update exact evidence missing"));
    let updated_content = SOURCE.replacen("Save", "Apply", 1);
    let stale = json!({
        "schema_version": REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        "evidence_ids": [exact_source.evidence_id.clone()],
        "action": {
            "kind": "update_file",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": format!("sha256:{}", "a".repeat(64)),
            "content": updated_content.clone()
        }
    });
    let repaired = json!({
        "schema_version": REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        "evidence_ids": [exact_source.evidence_id.clone()],
        "action": {
            "kind": "update_file",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": exact_source.source_digest.clone(),
            "content": updated_content.clone()
        }
    });
    let execution = backend(vec![
        model_response(
            stale.to_string(),
            context.metrics.final_serialized_input_tokens,
        ),
        model_response(
            repaired.to_string(),
            context.metrics.final_serialized_input_tokens,
        ),
    ]);
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
    let error = controller
        .execute_repository_with_model(ready, &runtime, &context, &mut budget)
        .err()
        .unwrap_or_else(|| panic!("stale repository proposal unexpectedly succeeded"));
    assert!(matches!(error, ControllerError::ProposalRejected(_)));
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    assert_eq!(controller.task_attempts_started(&task_id), Some(1));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(1));
    assert_eq!(budget.remaining_calls(), 1);
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read unchanged repository source: {error}")),
        SOURCE
    );
    let failure = controller
        .latest_failure_record(&task_id)
        .unwrap_or_else(|error| panic!("read stale repository failure: {error}"))
        .unwrap_or_else(|| panic!("stale repository failure missing"));
    assert_eq!(failure.category, "proposal_validation_failure");

    let (success, repair_packet) = controller
        .repair_repository_with_model(&task_id, &runtime, &context, &[], readiness(), &mut budget)
        .unwrap_or_else(|error| panic!("repair stale repository proposal: {error}"));
    assert!(success.verification.passed);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_attempts_started(&task_id), Some(2));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(2));
    assert_eq!(budget.remaining_calls(), 0);
    assert_eq!(repair_packet.prior_attempt_id, failure.attempt_id);
    assert_eq!(repair_packet.failure_signature, failure.signature);
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read repaired repository source: {error}")),
        updated_content
    );
    let attempt_raw = controller
        .state()
        .get_state("controller.attempt", &success.attempt_id)
        .unwrap_or_else(|error| panic!("read repository repair attempt: {error}"))
        .unwrap_or_else(|| panic!("repository repair attempt missing"));
    let attempt: Value = serde_json::from_str(&attempt_raw)
        .unwrap_or_else(|error| panic!("decode repository repair attempt: {error}"));
    assert_eq!(
        attempt
            .pointer("/repair_origin/prior_attempt_id")
            .and_then(Value::as_str),
        Some(failure.attempt_id.as_str())
    );
    assert_eq!(
        attempt
            .pointer("/repair_origin/failure_record_digest")
            .and_then(Value::as_str),
        Some(repair_packet.failure_record_digest.as_str())
    );
}

#[cfg(feature = "recovery-test-hooks")]
#[test]
#[allow(clippy::too_many_lines)]
fn repository_model_malformed_schema_repairs_from_repair_pending_to_success() {
    let mut fixture = compiled_repository_update_repair_fixture("repository-model-schema-repair");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .unwrap_or_else(|error| panic!("derive repository ready lease: {error}"));
    let context = repository_context_packet(
        &fixture.registry,
        "Update the exact governed SettingsForm repository file.",
    );
    let exact_source = context
        .items
        .iter()
        .find(|item| item.evidence_id == "file:repo.app:src/settings/SettingsForm.tsx")
        .unwrap_or_else(|| panic!("repository update exact evidence missing"));
    let updated_content = SOURCE.replacen("Save", "Apply", 1);
    let malformed = json!({
        "schema_version": REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        "evidence_ids": [exact_source.evidence_id.clone()],
        "task_state": "succeeded",
        "action": {
            "kind": "update_file",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": exact_source.source_digest.clone(),
            "content": updated_content.clone()
        }
    });
    let repaired = json!({
        "schema_version": REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        "evidence_ids": [exact_source.evidence_id.clone()],
        "action": {
            "kind": "update_file",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": exact_source.source_digest.clone(),
            "content": updated_content.clone()
        }
    });
    let execution = backend(vec![
        model_response(
            malformed.to_string(),
            context.metrics.final_serialized_input_tokens,
        ),
        model_response(
            repaired.to_string(),
            context.metrics.final_serialized_input_tokens,
        ),
    ]);
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
    assert!(
        controller
            .execute_repository_with_model(ready, &runtime, &context, &mut budget)
            .is_err()
    );
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::RepairPending)
    );
    let failure = controller
        .latest_failure_record(&task_id)
        .unwrap_or_else(|error| panic!("read malformed repository failure: {error}"))
        .unwrap_or_else(|| panic!("malformed repository failure missing"));
    assert_eq!(failure.category, "model_proposal_failure");

    let (success, repair_packet) = controller
        .repair_repository_with_model(&task_id, &runtime, &context, &[], readiness(), &mut budget)
        .unwrap_or_else(|error| panic!("repair malformed repository proposal: {error}"));
    assert!(success.verification.passed);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Succeeded));
    assert_eq!(controller.task_attempts_started(&task_id), Some(2));
    assert_eq!(controller.task_model_calls_used(&task_id), Some(2));
    assert_eq!(budget.remaining_calls(), 0);
    assert_eq!(repair_packet.prior_attempt_id, failure.attempt_id);
    assert_eq!(
        fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
            .unwrap_or_else(|error| panic!("read schema-repaired source: {error}")),
        updated_content
    );
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
fn local_control_reopen_uses_controller_recovery_and_delegates_mutations() {
    let mut fixture = compiled_fixture("local-control-reopen", true);
    let (mut controller, _) = controller_for(&mut fixture);
    controller
        .pause(Some("local control restart fixture"))
        .unwrap_or_else(|error| panic!("pause before reopen: {error}"));
    let epoch_before = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch before reopen: {error}"));
    drop(controller);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen local control state: {error}"));
    let mut control = LocalControl::reopen(state)
        .unwrap_or_else(|error| panic!("local control recover: {error}"));
    let recovered = control
        .read_model()
        .unwrap_or_else(|error| panic!("local control status: {error}"));
    assert!(recovered.status.active_plan.is_some());
    assert!(!recovered.status.tasks.is_empty());
    assert!(recovered.status.execution_control.paused);
    assert!(recovered.recovery.execution_epoch > epoch_before);
    assert!(recovered.recovery.checkpoint.is_some());
    assert!(!recovered.recovery.mutation_blocked);

    control
        .resume()
        .unwrap_or_else(|error| panic!("local control resume: {error}"));
    let goal = control
        .submit_goal("Build inventory from the local control facade")
        .unwrap_or_else(|error| panic!("local control goal: {error}"));
    let after = control
        .read_model()
        .unwrap_or_else(|error| panic!("local control reread: {error}"));
    assert!(!after.status.execution_control.paused);
    assert!(
        after
            .status
            .goal_intents
            .iter()
            .any(|intent| intent.goal_id == goal.goal_id)
    );
    let Err(error) = control.respond_to_approval(
        "approval.missing",
        sovereign_controller::ApprovalDecisionV1::Deny,
        "test:operator",
    ) else {
        panic!("missing approval request unexpectedly accepted")
    };
    assert!(error.to_string().contains("unknown approval request"));
}

#[test]
fn local_control_read_only_active_status_does_not_run_recovery_until_mutation() {
    let mut fixture = compiled_fixture("local-control-read-only", true);
    let (mut controller, _) = controller_for(&mut fixture);
    controller
        .pause(Some("read-only restart fixture"))
        .unwrap_or_else(|error| panic!("pause before read-only reopen: {error}"));
    let epoch_before = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch before read-only reopen: {error}"));
    let journal_before = controller
        .state()
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal before read-only reopen: {error}"));
    drop(controller);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("read-only local control state: {error}"));
    let mut control = LocalControl::read_only(state);
    let view = control
        .read_model()
        .unwrap_or_else(|error| panic!("read-only local control status: {error}"));
    assert!(view.status.active_plan.is_some());
    assert!(!view.status.tasks.is_empty());
    assert!(!view.plan_revisions.is_empty());
    assert!(view.status.execution_control.paused);
    assert_eq!(view.recovery.execution_epoch, epoch_before);

    let observer = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("observer after read-only status: {error}"));
    assert_eq!(
        observer
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal after read-only status: {error}")),
        journal_before,
        "read-only local status unexpectedly ran recovery or mutated canonical state"
    );
    assert_eq!(
        observer
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("epoch after read-only status: {error}")),
        epoch_before,
        "read-only local status unexpectedly advanced the execution epoch"
    );
    drop(observer);

    control
        .resume()
        .unwrap_or_else(|error| panic!("mutation after read-only open: {error}"));
    let after = control
        .read_model()
        .unwrap_or_else(|error| panic!("status after recovered mutation: {error}"));
    assert!(!after.status.execution_control.paused);
    assert!(after.recovery.execution_epoch > epoch_before);
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
fn durable_status_fails_closed_on_malformed_verification_rows() {
    let mut fixture = compiled_fixture("status-malformed-verification", true);
    let (controller, _) = controller_for(&mut fixture);
    let mut second = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open second state: {error}"));
    second
        .put_state(
            "controller.verification",
            "malformed.fixture",
            r#"{"plan_id":"unterminated""#,
        )
        .unwrap_or_else(|error| panic!("write malformed verification: {error}"));

    let Err(error) = controller.durable_status() else {
        panic!("malformed verification row was silently omitted from durable status")
    };
    assert!(
        error.to_string().contains("EOF")
            || error.to_string().contains("expected")
            || error.to_string().contains("JSON"),
        "unexpected fail-closed error: {error}"
    );
}

#[test]
fn durable_status_fails_closed_on_structurally_invalid_verification_rows() {
    let mut fixture = compiled_fixture("status-invalid-verification-schema", true);
    let (controller, _) = controller_for(&mut fixture);
    let active = controller
        .durable_status()
        .unwrap_or_else(|error| panic!("read active status before corruption: {error}"))
        .active_plan
        .unwrap_or_else(|| panic!("compiled fixture must have an active plan"));
    let plan_id = active["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("active plan id missing"));
    let revision = active["revision"]
        .as_u64()
        .unwrap_or_else(|| panic!("active revision missing"));
    let plan_digest = active["plan_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("active plan digest missing"));
    let mut second = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open second state: {error}"));
    second
        .put_state(
            "controller.verification",
            &format!("{plan_id}@r{revision}:verification.structurally-invalid"),
            &json!({
                "schema_version": VERIFICATION_RESULT_SCHEMA_VERSION,
                "verification_id": "verification.structurally-invalid",
                "plan_id": plan_id,
                "plan_revision": revision,
                "plan_digest": plan_digest
            })
            .to_string(),
        )
        .unwrap_or_else(|error| panic!("write structurally invalid verification: {error}"));

    let Err(error) = controller.durable_status() else {
        panic!("structurally invalid verification row was silently accepted")
    };
    assert!(
        error.to_string().contains("missing field"),
        "unexpected fail-closed error: {error}"
    );
}

#[test]
fn verification_rows_are_validated_without_an_active_plan() {
    let repo = TestRepo::create("status-invalid-verification-no-active-plan");
    let mut state = StateStore::open(&repo.state_path)
        .unwrap_or_else(|error| panic!("open no-active state: {error}"));
    state
        .put_state(
            "controller.verification",
            "verification.invalid-no-active",
            &json!({"schema_version": VERIFICATION_RESULT_SCHEMA_VERSION}).to_string(),
        )
        .unwrap_or_else(|error| panic!("write invalid no-active verification: {error}"));
    drop(state);

    let controller = Controller::new(
        StateStore::open(&repo.state_path)
            .unwrap_or_else(|error| panic!("reopen no-active controller: {error}")),
    );
    let Err(error) = controller.durable_status() else {
        panic!("invalid verification row was skipped because no active plan exists")
    };
    assert!(
        error.to_string().contains("missing field"),
        "unexpected fail-closed status error: {error}"
    );

    let control = LocalControl::read_only(
        StateStore::open(&repo.state_path)
            .unwrap_or_else(|error| panic!("reopen no-active local control: {error}")),
    );
    let Err(error) = control.read_model() else {
        panic!("local read model skipped invalid verification row without an active plan")
    };
    assert!(
        error.to_string().contains("missing field"),
        "unexpected fail-closed local-control error: {error}"
    );
}

#[test]
fn local_control_read_model_rejects_invalid_durable_action_lifecycle_state() {
    let mut fixture = compiled_fixture("local-control-invalid-action-state", true);
    let (controller, _) = controller_for(&mut fixture);
    let epoch = controller
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("execution epoch: {error}"));
    drop(controller);

    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open state for invalid action: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: "action.invalid-lifecycle",
            state: "not-a-canonical-action-state",
            payload_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            policy_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            execution_epoch: epoch,
            event_id: "event.invalid-lifecycle",
            event_kind: "fixture_corruption",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("persist invalid action lifecycle fixture: {error}"));
    drop(state);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen invalid action lifecycle fixture: {error}"));
    let control = LocalControl::read_only(state);
    let Err(error) = control.read_model() else {
        panic!("invalid durable action lifecycle state was projected as safe")
    };
    assert!(
        error
            .to_string()
            .contains("invalid durable action lifecycle state"),
        "unexpected fail-closed error: {error}"
    );

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen invalid action for recovery manager: {error}"));
    let Err(error) = RecoveryManager::recover(state, &fixture.registry) else {
        panic!("RecoveryManager accepted invalid durable action lifecycle state")
    };
    assert!(
        error
            .to_string()
            .contains("invalid durable action lifecycle state"),
        "unexpected fail-closed RecoveryManager error: {error}"
    );

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen invalid action for recovery: {error}"));
    let Err(error) = LocalControl::reopen(state) else {
        panic!("active-plan recovery accepted invalid durable action lifecycle state")
    };
    assert!(
        error
            .to_string()
            .contains("invalid durable action lifecycle state"),
        "unexpected fail-closed recovery error: {error}"
    );
}

#[test]
fn local_control_mutation_rejects_invalid_action_state_without_active_plan() {
    let repo = TestRepo::create("local-control-invalid-action-state-no-active-plan");
    let mut state = StateStore::open(&repo.state_path)
        .unwrap_or_else(|error| panic!("open no-active state: {error}"));
    let epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("execution epoch: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: "action.invalid-no-active",
            state: "not-a-canonical-action-state",
            payload_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            policy_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            execution_epoch: epoch,
            event_id: "event.invalid-no-active",
            event_kind: "fixture_corruption",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("persist invalid no-active action: {error}"));
    let before_sequence = state
        .latest_journal_sequence()
        .unwrap_or_else(|error| panic!("journal before rejected mutation: {error}"));
    drop(state);

    let mut control = LocalControl::read_only(
        StateStore::open(&repo.state_path)
            .unwrap_or_else(|error| panic!("reopen invalid no-active action: {error}")),
    );
    let Err(error) = control.submit_goal("must not persist") else {
        panic!("mutation proceeded despite invalid durable action lifecycle state")
    };
    assert!(
        error
            .to_string()
            .contains("invalid durable action lifecycle state"),
        "unexpected fail-closed mutation error: {error}"
    );

    let observer = StateStore::open(&repo.state_path)
        .unwrap_or_else(|error| panic!("observe rejected mutation: {error}"));
    assert_eq!(
        observer
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal after rejected mutation: {error}")),
        before_sequence,
        "rejected local-control mutation changed the journal"
    );
    assert!(
        observer
            .state_records("controller.goal_intent")
            .unwrap_or_else(|error| panic!("goal intents after rejected mutation: {error}"))
            .is_empty(),
        "rejected local-control mutation persisted a goal intent"
    );
    drop(observer);

    let mut controller = Controller::new(
        StateStore::open(&repo.state_path)
            .unwrap_or_else(|error| panic!("reopen controller for direct mutation: {error}")),
    );
    let Err(error) = controller.submit_goal_intent("must also fail directly") else {
        panic!("Controller mutation bypassed invalid durable action lifecycle validation")
    };
    assert!(
        error
            .to_string()
            .contains("invalid durable action lifecycle state"),
        "unexpected fail-closed Controller mutation error: {error}"
    );
}

fn status_verification_fixture(
    plan_id: &str,
    plan_revision: u32,
    plan_digest: &str,
    label: &str,
) -> VerificationResultV1 {
    VerificationResultV1 {
        schema_version: VERIFICATION_RESULT_SCHEMA_VERSION,
        verification_id: format!("verification.{label}"),
        plan_id: plan_id.to_owned(),
        plan_revision,
        plan_digest: plan_digest.to_owned(),
        task_id: format!("task.{label}"),
        task_contract_digest: format!("contract.{label}"),
        attempt_id: format!("attempt.{label}"),
        execution_epoch: i64::from(plan_revision),
        evaluator: "fixture".to_owned(),
        acceptance_contract_digest: format!("acceptance.{label}"),
        diff_digest: format!("diff.{label}"),
        post_snapshot_digest: format!("snapshot.{label}"),
        expected_target_mode: 0o644,
        observed_target_mode: 0o644,
        evidence_ids: vec![format!("evidence.{label}-verification")],
        command_results: Vec::new(),
        passed: true,
        failure_code: None,
    }
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
            &serde_json::to_string(&status_verification_fixture(
                plan_id,
                1,
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "rev1",
            ))
            .unwrap_or_else(|error| panic!("encode historical verification: {error}")),
        )
        .unwrap_or_else(|error| panic!("write historical verification: {error}"));
    state
        .put_state(
            "controller.verification",
            &format!("{plan_id}@r2:verification.rev2"),
            &serde_json::to_string(&status_verification_fixture(
                plan_id,
                2,
                current_digest,
                "rev2",
            ))
            .unwrap_or_else(|error| panic!("encode current verification: {error}")),
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
    assert!(view.evidence.iter().all(|value| {
        value.get("plan_revision") != Some(&json!(1))
            && value.get("marker") != Some(&json!("rev1-evidence"))
    }));
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
fn m6_inflight_secret_cancellation_reaps_closes_and_recovers_as_unknown_without_leakage() {
    let (mut fixture, secret_ref) = compiled_secret_fixture("m6-secret-cancel-inflight");
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
    let manifest = secret_tool_manifest();
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness(), &manifest)
        .unwrap_or_else(|error| panic!("secret readiness: {error}"));
    let cancellation = controller
        .task_cancellation_handle(&task_id)
        .unwrap_or_else(|error| panic!("task cancellation handle: {error}"));

    let sentinel = b"T07-CANCELLED-SECRET-\xff-\x00-SENTINEL".to_vec();
    let mut broker = SecretBroker::new();
    broker
        .register_provider(Arc::new(FakeSecretProvider::new(
            SecretProviderKind::ExternalBroker,
            [("cancel-key".to_owned(), sentinel.clone())],
        )))
        .unwrap_or_else(|error| panic!("register fake secret provider: {error}"));
    broker
        .register_secret(
            secret_ref.clone(),
            ControllerSecretLocator::FakeKey {
                provider: SecretProviderKind::ExternalBroker,
                key: "cancel-key".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("register exact secret handle: {error}"));

    let parts = runtime_parts(&fixture);
    let isolation = PassthroughIsolation {
        capabilities: MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("seatbelt capability source: {error}")),
    };
    let private_root = fixture.repo.base.join("controller-private-secrets");
    let runtime = SecretProcessRuntime {
        registry: &fixture.registry,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &manifest,
        secret_broker: &broker,
        controller_private_root: &private_root,
    };
    let marker = fixture.repo.root.join("secret-cancel.started");
    let command = CommandSpec {
        executable: PathBuf::from("/usr/bin/python3"),
        args: vec![
            "-I".to_owned(),
            "-c".to_owned(),
            "import os,sys,time; p=os.environ['SOVEREIGN_SECRET_FILE']; b=open(p,'rb').read(); open('secret-cancel.started','wb').write(b'1'); sys.stdout.buffer.write(b); sys.stdout.flush(); sys.stderr.buffer.write(b); sys.stderr.flush(); time.sleep(30)".to_owned(),
        ],
        working_directory: fixture.repo.root.clone(),
        environment: BTreeMap::new(),
        mode: CommandMode::Direct,
        declared_risk: CommandRisk::RepositoryMutation,
        timeout_ms: 30_000,
        output_limit_bytes: 64 * 1024,
        disk_write_limit_bytes: 64 * 1024,
        subprocess_limit: 1,
    };
    let cancel_handle = cancellation.clone();
    let marker_for_thread = marker.clone();
    let canceller = thread::spawn(move || {
        let started = Instant::now();
        while !marker_for_thread.exists() {
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "secret process never reached the in-flight marker"
            );
            thread::sleep(Duration::from_millis(5));
        }
        cancel_handle
            .cancel()
            .unwrap_or_else(|error| panic!("cancel in-flight secret task: {error}"));
    });

    let error = controller
        .execute_secret_process(ready, &runtime, &secret_ref.secret_ref_id, command)
        .err()
        .unwrap_or_else(|| panic!("cancelled secret process unexpectedly succeeded"));
    canceller
        .join()
        .unwrap_or_else(|_| panic!("secret cancellation thread panicked"));
    let action_id = match error {
        ControllerError::UnknownAction(action_id) => action_id,
        other => panic!("cancelled dispatched secret action must be Unknown, got {other}"),
    };
    assert_eq!(
        controller
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|read_error| panic!("cancelled action record: {read_error}"))
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
    let lifecycle_raw = controller
        .state()
        .get_state("controller.secret_action_lifecycle", &action_id)
        .unwrap_or_else(|read_error| panic!("cancelled secret lifecycle: {read_error}"))
        .unwrap_or_else(|| panic!("cancelled secret lifecycle missing"));
    let lifecycle: Value = serde_json::from_str(&lifecycle_raw)
        .unwrap_or_else(|decode_error| panic!("decode cancelled lifecycle: {decode_error}"));
    assert_eq!(lifecycle["state"], json!("cancelled_post_dispatch_unknown"));
    assert_eq!(lifecycle["result_digest"], Value::Null);
    let process_raw = controller
        .state()
        .get_state("controller.process_lease", &action_id)
        .unwrap_or_else(|read_error| panic!("cancelled process lease: {read_error}"))
        .unwrap_or_else(|| panic!("cancelled process lease missing"));
    let process: Value = serde_json::from_str(&process_raw)
        .unwrap_or_else(|decode_error| panic!("decode process lease: {decode_error}"));
    assert_eq!(process["state"], json!("reaped"));
    let pgid = process["process_group_id"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| panic!("cancelled process PGID missing"));
    assert!(process["leader_identity"].as_str().is_some());
    assert_eq!(
        process_group_leader_identity(pgid).unwrap_or_else(|observe_error| panic!(
            "observe cancelled secret group: {observe_error}"
        )),
        None
    );
    assert!(
        !private_root.exists()
            || fs::read_dir(&private_root)
                .unwrap_or_else(|read_error| panic!("private secret root: {read_error}"))
                .next()
                .is_none(),
        "cancelled secret temporary injection must be removed before terminal lifecycle"
    );
    assert_runtime_persistence_excludes_secret(
        &fixture.repo,
        &parts.artifacts,
        &sentinel,
        &sentinel,
        &sentinel,
    );

    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|open_error| panic!("reopen cancelled secret state: {open_error}"));
    let (recovered, recovery) = RecoveryManager::recover_with_permission_context(
        state,
        &fixture.registry,
        PermissionContext::m6_local_secret_execution(),
    )
    .unwrap_or_else(|recovery_error| panic!("recover cancelled secret action: {recovery_error}"));
    assert!(recovery.mutation_blocked);
    assert!(recovery.unknown_action_ids.contains(&action_id));
    assert_eq!(
        recovered
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|read_error| panic!("recovered cancelled action: {read_error}"))
            .map(|record| record.state),
        Some("unknown".to_owned())
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn m6_cancelled_predispatch_secret_lifecycle_replays_from_post_checkpoint_journal() {
    let (mut fixture, secret_ref) =
        compiled_secret_fixture("m6-secret-cancel-predispatch-correlation");
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
        .unwrap_or_else(|error| panic!("secret cancellation epoch: {error}"));
    drop(controller);

    let action_id = "action.m6-secret-cancelled-predispatch".to_owned();
    let payload_digest = sha256_prefixed(b"m6-secret-cancelled-predispatch-payload");
    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen cancellation state: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: &action_id,
            state: "prepared",
            payload_digest: &payload_digest,
            policy_digest: &manifest.policy_digest,
            execution_epoch,
            event_id: "event.m6-secret-cancelled-predispatch.prepared",
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert cancelled secret action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: &action_id,
            expected_state: "prepared",
            next_state: "authorized",
            expected_epoch: execution_epoch,
            event_id: "event.m6-secret-cancelled-predispatch.authorized",
            event_kind: "authorized",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("authorize cancelled secret action: {error}"));
    let marker = json!({
        "schema_version": 1,
        "plan_id": manifest.plan_id,
        "plan_revision": manifest.plan_revision,
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "action_id": action_id,
        "permission_decision_digest": sha256_prefixed(b"m6-secret-cancelled-predispatch-permission"),
        "execution_epoch": execution_epoch,
        "secret_ref_binding_digest": secret_ref
            .binding_digest()
            .unwrap_or_else(|error| panic!("secret ref binding digest: {error}")),
        "provider": "external_broker",
        "injection": "temporary_file",
        "target": EPHEMERAL_SECRET_FILE_ENV,
        "expires_at_ms": 1_900_000_000_000_i64,
        "action_payload_digest": payload_digest,
        "state": "cancelled_pre_dispatch",
        "result_digest": Value::Null,
    });
    let marker_json = serde_json::to_string(&marker)
        .unwrap_or_else(|error| panic!("encode cancelled lifecycle: {error}"));
    let marker_digest = sha256_prefixed(marker_json.as_bytes());
    let payload = json!({
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
                event_id: "event.m6-secret-cancelled-predispatch.lifecycle",
                entity_type: "controller",
                entity_id: &action_id,
                event_kind: "secret_action_cancelled_predispatch",
                payload_json: &payload,
            }],
        )
        .unwrap_or_else(|error| panic!("persist cancelled lifecycle: {error}"));
    drop(state);

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen cancelled lifecycle state: {error}"));
    let (recovered, recovery) = RecoveryManager::recover_with_permission_context(
        state,
        &fixture.registry,
        PermissionContext::m6_local_secret_execution(),
    )
    .unwrap_or_else(|error| panic!("cancelled predispatch correlation must recover: {error}"));
    assert!(!recovery.mutation_blocked);
    assert_eq!(
        recovered
            .state()
            .action_record(&action_id)
            .unwrap_or_else(|error| panic!("recovered cancelled action: {error}"))
            .map(|record| record.state),
        Some("authorized".to_owned())
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
fn m6_pending_cleanup_recovery_reaps_exact_active_process_before_lifecycle_fence() {
    let (mut fixture, secret_ref) = compiled_secret_fixture("m6-secret-pending-cleanup-reap-first");
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
        .unwrap_or_else(|error| panic!("pending cleanup epoch: {error}"));
    drop(controller);

    let action_id = "action.m6-secret-pending-cleanup-active-process".to_owned();
    let payload_digest = sha256_prefixed(b"m6-secret-pending-cleanup-active-process-payload");
    let mut state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen pending cleanup state: {error}"));
    let result_store = ArtifactStore::open(fixture.repo.base.join("cas"))
        .unwrap_or_else(|error| panic!("pending cleanup result store: {error}"));
    let result = result_store
        .put(&mut state, b"sanitized pending cleanup result")
        .unwrap_or_else(|error| panic!("pending cleanup result artifact: {error}"));
    state
        .insert_action_record(NewActionRecord {
            action_id: &action_id,
            state: "prepared",
            payload_digest: &payload_digest,
            policy_digest: &manifest.policy_digest,
            execution_epoch,
            event_id: "event.m6-secret-pending-cleanup.prepared",
            event_kind: "prepared",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("insert pending cleanup action: {error}"));
    state
        .transition_action_with_event(ActionTransition {
            action_id: &action_id,
            expected_state: "prepared",
            next_state: "observed",
            expected_epoch: execution_epoch,
            event_id: "event.m6-secret-pending-cleanup.observed",
            event_kind: "observed",
            payload_json: "{}",
            result_digest: Some(&result.digest),
        })
        .unwrap_or_else(|error| panic!("observe pending cleanup action: {error}"));
    let marker = json!({
        "schema_version": 1,
        "plan_id": manifest.plan_id,
        "plan_revision": manifest.plan_revision,
        "task_id": task_id,
        "task_contract_digest": task_contract_digest,
        "action_id": action_id,
        "permission_decision_digest": sha256_prefixed(b"m6-secret-pending-cleanup-permission"),
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
        .unwrap_or_else(|error| panic!("encode pending lifecycle: {error}"));
    let marker_digest = sha256_prefixed(marker_json.as_bytes());
    let lifecycle_payload = json!({
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
                event_id: "event.m6-secret-pending-cleanup.lifecycle",
                entity_type: "controller",
                entity_id: &action_id,
                event_kind: "secret_action_pending_cleanup",
                payload_json: &lifecycle_payload,
            }],
        )
        .unwrap_or_else(|error| panic!("persist pending lifecycle: {error}"));

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("while :; do sleep 1; done")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap_or_else(|error| panic!("spawn pending cleanup child: {error}"));
    let pgid = child.id();
    let identity_started = Instant::now();
    let leader_identity = loop {
        if let Some(identity) = process_group_leader_identity(pgid)
            .unwrap_or_else(|error| panic!("observe pending cleanup leader: {error}"))
        {
            break identity;
        }
        assert!(
            identity_started.elapsed() < Duration::from_secs(1),
            "pending cleanup child never exposed a stable leader identity"
        );
        thread::sleep(Duration::from_millis(5));
    };
    state
        .put_state(
            "controller.process_lease",
            &action_id,
            &json!({
                "schema_version": 1,
                "lease_id": format!("process.{action_id}"),
                "task_id": task_id,
                "attempt_id": "attempt.m6-secret-pending-cleanup",
                "action_id": action_id,
                "process_group_id": pgid,
                "leader_identity": leader_identity,
                "state": "active",
            })
            .to_string(),
        )
        .unwrap_or_else(|error| panic!("persist active process lease: {error}"));
    drop(state);
    let waiter = thread::spawn(move || child.wait());

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen recovery state: {error}"));
    let error = RecoveryManager::recover_with_permission_context(
        state,
        &fixture.registry,
        PermissionContext::m6_local_secret_execution(),
    )
    .err()
    .unwrap_or_else(|| panic!("PendingCleanup lifecycle unexpectedly recovered"));
    assert!(
        error.to_string().contains("secret action recovery blocked")
            && error.to_string().contains("PendingCleanup"),
        "unexpected pending cleanup recovery error: {error}"
    );
    waiter
        .join()
        .unwrap_or_else(|_| panic!("pending cleanup child waiter panicked"))
        .unwrap_or_else(|wait_error| panic!("wait pending cleanup child: {wait_error}"));
    assert_eq!(
        process_group_leader_identity(pgid).unwrap_or_else(|observe_error| panic!(
            "observe reaped recovery group: {observe_error}"
        )),
        None
    );
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|open_error| panic!("reopen reaped process state: {open_error}"));
    let process_raw = state
        .get_state("controller.process_lease", &action_id)
        .unwrap_or_else(|read_error| panic!("read recovery process lease: {read_error}"))
        .unwrap_or_else(|| panic!("recovery process lease missing"));
    let process: Value = serde_json::from_str(&process_raw)
        .unwrap_or_else(|decode_error| panic!("decode recovery process lease: {decode_error}"));
    assert_eq!(process["state"], json!("reaped_recovery"));
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
    let (repository_id, _) = singleton_checkpoint_repository(&manifest);
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
        "repository_id": repository_id,
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
#[allow(clippy::too_many_lines)]
fn governed_command_verification_treats_real_nonzero_exit_as_evidence_only() {
    for (label, expected_exit_codes, command_should_pass) in [
        ("command-expected-nonzero", vec![0, 2], true),
        ("command-unexpected-nonzero", vec![0], false),
    ] {
        let mut fixture = compiled_command_verification_fixture(label, &expected_exit_codes);
        let (mut controller, task_id) = controller_for(&mut fixture);
        let ready = controller
            .derive_ready_lease(
                &fixture.registry,
                &task_id,
                readiness(),
                &write_tool_manifest(),
            )
            .unwrap_or_else(|error| panic!("derive governed command ready lease: {error}"));
        let execution = backend(vec![model_response(
            valid_execution_proposal(&fixture.form_digest),
            fixture.packet.metrics.final_serialized_input_tokens,
        )]);
        let parts = runtime_parts_with_make(&fixture);
        let isolation = PassthroughIsolation {
            capabilities: MacSandboxExecBackend::detect()
                .unwrap_or_else(|error| panic!("detect command isolation capabilities: {error}")),
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
        let verification =
            match controller.execute_replace(ready, &runtime, &fixture.packet, &mut budget) {
                Ok(success) => {
                    assert!(
                        command_should_pass,
                        "unexpected nonzero command exit must not complete the task"
                    );
                    success.verification
                }
                Err(ControllerError::VerificationFailed(verification)) => {
                    assert!(
                        !command_should_pass,
                        "expected nonzero command exit must be accepted as verification evidence"
                    );
                    *verification
                }
                other => {
                    panic!("governed command verification returned unexpected result: {other:?}")
                }
            };

        assert_eq!(verification.command_results.len(), 1);
        let command = &verification.command_results[0];
        assert_eq!(command.expected_exit_codes, expected_exit_codes);
        assert_eq!(command.exit_code, Some(2));
        assert!(command.process_group_reaped);
        assert_eq!(command.passed, command_should_pass);
        assert_eq!(
            command.failure_code.as_deref(),
            (!command_should_pass).then_some("command_unexpected_exit")
        );
        assert_eq!(verification.passed, command_should_pass);
        assert_eq!(
            verification.failure_code.as_deref(),
            (!command_should_pass).then_some("command_unexpected_exit")
        );
        assert_eq!(
            controller.task_state(&task_id) == Some(TaskState::Succeeded),
            command_should_pass,
            "command evidence must not become a second completion authority"
        );

        let action = controller
            .state()
            .action_record(&command.action_id)
            .unwrap_or_else(|error| panic!("read governed command action: {error}"))
            .unwrap_or_else(|| panic!("governed command action missing"));
        assert_eq!(action.state, "committed");
        assert_eq!(
            action.result_digest.as_deref(),
            command.result_digest.as_deref()
        );
        let process_raw = controller
            .state()
            .get_state("controller.process_lease", &command.action_id)
            .unwrap_or_else(|error| panic!("read governed command process lease: {error}"))
            .unwrap_or_else(|| panic!("governed command process lease missing"));
        let process: Value = serde_json::from_str(&process_raw)
            .unwrap_or_else(|error| panic!("decode governed command process lease: {error}"));
        assert_eq!(process["state"], json!("reaped"));
        assert_eq!(
            controller
                .state()
                .state_records("controller.verification")
                .unwrap_or_else(|error| panic!("read aggregate verification rows: {error}"))
                .len(),
            1,
            "command verification must remain part of one aggregate verification row"
        );
    }
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
fn controller_materializes_existing_ignored_dependencies_under_task_lease() {
    let mut fixture = controller_offline_fixture("controller-offline-dependencies");
    let source = fixture.repo.root.join("node_modules/pkg/index.js");
    let original = fs::read(&source).expect("read source");
    let primary_before = fixture
        .registry
        .snapshot("repo.app")
        .expect("primary before copy");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .expect("derive ready worktree");
    let lease = controller
        .task_worktree_lease(&task_id)
        .expect("task lease")
        .clone();
    assert!(!lease.worktree_path.join("node_modules").exists());
    let receipt = controller
        .materialize_task_existing_node_modules(
            &fixture.registry,
            &task_id,
            Path::new(""),
            offline_limits(),
        )
        .expect("materialize under controller lease");
    assert_eq!(receipt.worktree_lease_id, lease.lease_id);
    assert_eq!(receipt.source_manifest, receipt.destination_manifest);
    assert_eq!(fs::read(&source).expect("source after"), original);
    assert_eq!(
        fixture
            .registry
            .snapshot("repo.app")
            .expect("primary after copy"),
        primary_before
    );
    assert_eq!(
        fs::read(lease.worktree_path.join("node_modules/pkg/index.js")).expect("copied package"),
        original
    );
    let state = StateStore::open(&fixture.repo.state_path).expect("read state");
    let records = state
        .state_records("controller.offline_node_modules")
        .expect("receipt records");
    assert_eq!(records.len(), 1);
    let bound: Value = serde_json::from_str(&records[0].value_json).expect("receipt JSON");
    assert_eq!(bound["state"], "committed");
    assert_eq!(
        bound["provenance"]["destination_manifest"]["digest"],
        receipt.destination_manifest.digest
    );
    drop(state);
    controller.cancel_ready_lease(ready).expect("cancel ready");
    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path).expect("reopen state");
    let (mut recovered, summary) =
        RecoveryManager::recover(state, &fixture.registry).expect("recover verified dependencies");
    assert!(!summary.mutation_blocked);
    assert_eq!(
        recovered
            .materialize_task_existing_node_modules(
                &fixture.registry,
                &task_id,
                Path::new(""),
                offline_limits()
            )
            .expect("idempotent verified receipt"),
        receipt
    );
}

fn offline_limits() -> OfflineDependencyLimits {
    OfflineDependencyLimits {
        max_entries: 16,
        max_bytes: 1024,
    }
}

fn controller_offline_fixture(label: &str) -> CompiledFixture {
    let fixture = compiled_worktree_fixture(label);
    fs::write(
        fixture.repo.root.join(".git/info/exclude"),
        "node_modules/\n",
    )
    .expect("ignore fixture dependencies");
    let source = fixture.repo.root.join("node_modules/pkg/index.js");
    fs::create_dir_all(source.parent().expect("package parent")).expect("create package");
    fs::write(&source, "module.exports = 42;\n").expect("write package");
    fixture
}

#[test]
fn controller_offline_dependencies_deny_stale_lease_before_copy() {
    let mut fixture = controller_offline_fixture("controller-offline-stale-lease");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .expect("derive ready worktree");
    let lease = controller
        .task_worktree_lease(&task_id)
        .expect("task lease")
        .clone();
    git(
        &lease.worktree_path,
        &["commit", "--allow-empty", "-qm", "drift"],
    );
    let error = controller
        .materialize_task_existing_node_modules(
            &fixture.registry,
            &task_id,
            Path::new(""),
            offline_limits(),
        )
        .expect_err("stale HEAD must deny offline copy");
    assert!(error.to_string().contains("worktree HEAD differs"));
    assert!(!lease.worktree_path.join("node_modules").exists());
    let state = StateStore::open(&fixture.repo.state_path).expect("read state");
    assert!(state
        .state_records("controller.offline_node_modules")
        .expect("receipts")
        .is_empty());
    controller.cancel_ready_lease(ready).expect("cancel ready");
}

#[test]
fn controller_offline_dependencies_detect_destination_and_source_drift_on_restart() {
    let mut fixture = controller_offline_fixture("controller-offline-drift");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .expect("ready");
    let lease = controller
        .task_worktree_lease(&task_id)
        .expect("lease")
        .clone();
    controller
        .materialize_task_existing_node_modules(
            &fixture.registry,
            &task_id,
            Path::new(""),
            offline_limits(),
        )
        .expect("copy");
    controller.cancel_ready_lease(ready).expect("cancel ready");
    drop(controller);
    let destination = lease.worktree_path.join("node_modules/pkg/index.js");
    fs::write(&destination, "changed destination\n").expect("drift destination");
    let state = StateStore::open(&fixture.repo.state_path).expect("reopen after destination drift");
    assert!(RecoveryManager::recover(state, &fixture.registry).is_err());
    fs::write(&destination, "module.exports = 42;\n").expect("restore destination");
    fs::write(
        fixture.repo.root.join("node_modules/pkg/index.js"),
        "changed source\n",
    )
    .expect("drift source");
    let state = StateStore::open(&fixture.repo.state_path).expect("reopen after source drift");
    assert!(RecoveryManager::recover(state, &fixture.registry).is_err());
}

#[test]
fn controller_offline_dependencies_reject_checkpoint_receipt_tamper() {
    let mut fixture = controller_offline_fixture("controller-offline-receipt-tamper");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .expect("ready");
    controller
        .materialize_task_existing_node_modules(
            &fixture.registry,
            &task_id,
            Path::new(""),
            offline_limits(),
        )
        .expect("copy");
    controller.cancel_ready_lease(ready).expect("cancel ready");
    drop(controller);
    let mut state =
        StateStore::open(&fixture.repo.state_path).expect("open state for tamper fixture");
    let record = state
        .state_records("controller.offline_node_modules")
        .expect("receipt records")
        .pop()
        .expect("receipt");
    let mut value: Value = serde_json::from_str(&record.value_json).expect("receipt JSON");
    value["provenance"]["destination_manifest"]["digest"] = json!("sha256:tampered");
    state
        .put_state(
            "controller.offline_node_modules",
            &record.key,
            &value.to_string(),
        )
        .expect("tamper fixture receipt");
    drop(state);
    let state = StateStore::open(&fixture.repo.state_path).expect("reopen tampered state");
    let error = RecoveryManager::recover(state, &fixture.registry)
        .err()
        .expect("tamper must fail closed");
    assert!(
        error.to_string().contains("immutable record") || error.to_string().contains("receipt"),
        "{error}"
    );
}

#[test]
fn controller_offline_dependencies_deny_unsafe_tree_and_never_replay_unresolved_copy() {
    let mut fixture = controller_offline_fixture("controller-offline-unsafe");
    let source = fixture.repo.root.join("node_modules/pkg/index.js");
    fs::remove_file(&source).expect("remove fixture module");
    std::os::unix::fs::symlink("../../../outside.js", &source).expect("unsafe external link");
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &write_tool_manifest(),
        )
        .expect("ready");
    let lease = controller
        .task_worktree_lease(&task_id)
        .expect("lease")
        .clone();
    let error = controller
        .materialize_task_existing_node_modules(
            &fixture.registry,
            &task_id,
            Path::new(""),
            offline_limits(),
        )
        .expect_err("unsafe tree denied");
    assert!(error.to_string().contains("offline dependency"));
    assert!(!lease.worktree_path.join("node_modules").exists());
    let state = StateStore::open(&fixture.repo.state_path).expect("read prepared receipt");
    let records = state
        .state_records("controller.offline_node_modules")
        .expect("receipts");
    assert_eq!(records.len(), 1);
    let pending: Value =
        serde_json::from_str(&records[0].value_json).expect("prepared receipt JSON");
    assert_eq!(pending["state"], "prepared");
    drop(state);
    controller.cancel_ready_lease(ready).expect("cancel ready");
    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path).expect("reopen interrupted copy");
    let error = RecoveryManager::recover(state, &fixture.registry)
        .err()
        .expect("unresolved copy must deny recovery");
    assert!(error.to_string().contains("interrupted"));
    assert!(!lease.worktree_path.join("node_modules").exists());
}

#[cfg(feature = "recovery-test-hooks")]
#[test]
fn controller_offline_dependencies_crash_after_prepared_intent_is_not_replayed() {
    const CHILD: &str = "SOVEREIGN_OFFLINE_DEPENDENCY_CRASH_CHILD";
    const META: &str = "SOVEREIGN_OFFLINE_DEPENDENCY_CRASH_META";
    if std::env::var(CHILD).ok().as_deref() == Some("1") {
        let mut fixture = controller_offline_fixture("controller-offline-crash-child");
        let (mut controller, task_id) = controller_for(&mut fixture);
        let ready = controller
            .derive_ready_lease(
                &fixture.registry,
                &task_id,
                readiness(),
                &write_tool_manifest(),
            )
            .expect("child ready");
        let lease = controller
            .task_worktree_lease(&task_id)
            .expect("child lease")
            .clone();
        controller
            .cancel_ready_lease(ready)
            .expect("release MODEL before crash test");
        fs::write(
            std::env::var(META).expect("metadata path"),
            json!({
                "base": fixture.repo.base,
                "root": fixture.repo.root,
                "state": fixture.repo.state_path,
                "task_id": task_id,
                "worktree": lease.worktree_path,
            })
            .to_string(),
        )
        .expect("child metadata");
        let _ = controller.materialize_task_existing_node_modules(
            &fixture.registry,
            &task_id,
            Path::new(""),
            offline_limits(),
        );
        panic!("child must pause after durable intent");
    }
    let token = format!(
        "{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let harness = std::env::temp_dir().join(format!("sovereign-offline-crash-{token}"));
    fs::create_dir_all(&harness).expect("harness dir");
    let marker = harness.join("paused");
    let metadata = harness.join("metadata.json");
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "controller_offline_dependencies_crash_after_prepared_intent_is_not_replayed",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env(META, &metadata)
        .env(
            "SOVEREIGN_RECOVERY_TEST_PAUSE_AT",
            "after_offline_node_modules_prepare",
        )
        .env("SOVEREIGN_RECOVERY_TEST_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn crash child");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() && Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll child") {
            panic!("crash child exited before durable marker: {status}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    if !marker.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child did not reach prepared checkpoint");
    }
    child.kill().expect("kill paused child");
    child.wait().expect("reap child");
    let info: Value = serde_json::from_slice(&fs::read(&metadata).expect("child metadata"))
        .expect("metadata JSON");
    let root = PathBuf::from(info["root"].as_str().expect("root"));
    let state_path = PathBuf::from(info["state"].as_str().expect("state"));
    let worktree = PathBuf::from(info["worktree"].as_str().expect("worktree"));
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &root)
        .expect("register recovered repo");
    assert!(!worktree.join("node_modules").exists());
    let state = StateStore::open(&state_path).expect("open crashed state");
    let error = RecoveryManager::recover(state, &registry)
        .err()
        .expect("prepared copy blocks recovery");
    assert!(error.to_string().contains("interrupted"), "{error}");
    assert!(
        !worktree.join("node_modules").exists(),
        "recovery must not copy"
    );
    fs::create_dir_all(worktree.join("node_modules/pkg"))
        .expect("simulate completed but unreceipted copy");
    fs::write(
        worktree.join("node_modules/pkg/index.js"),
        "module.exports = 42;\n",
    )
    .expect("simulate uncertain installed tree");
    let state = StateStore::open(&state_path).expect("reopen uncertain copy");
    let error = RecoveryManager::recover(state, &registry)
        .err()
        .expect("unreceipted tree blocks recovery");
    assert!(error.to_string().contains("interrupted"), "{error}");
    fs::remove_dir_all(info["base"].as_str().expect("base")).expect("remove crash fixture");
    fs::remove_dir_all(harness).expect("remove crash harness");
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
    let (repository_id, repository_baseline) = singleton_checkpoint_repository(&manifest);
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
        "baseline_digest": repository_baseline.repository_snapshot_digest,
        "pre_snapshot_digest": repository_baseline.repository_snapshot_digest,
        "pre_diff_digest": repository_baseline.baseline_diff_digest,
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
        "repository_id": repository_id,
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

#[cfg(feature = "recovery-test-hooks")]
#[test]
fn repository_v4_recovery_crash_worker_entry() {
    let Some(state_path) = std::env::var_os(PD_T05_V4_CRASH_STATE).map(PathBuf::from) else {
        return;
    };
    let root = PathBuf::from(
        std::env::var_os(PD_T05_V4_CRASH_ROOT)
            .unwrap_or_else(|| panic!("PD-T05 v4 crash root env missing")),
    );
    let base = PathBuf::from(
        std::env::var_os(PD_T05_V4_CRASH_BASE)
            .unwrap_or_else(|| panic!("PD-T05 v4 crash base env missing")),
    );
    let task_id = std::env::var(PD_T05_V4_CRASH_TASK)
        .unwrap_or_else(|error| panic!("PD-T05 v4 crash task env: {error}"));
    let mutation_kind = std::env::var(PD_T05_V4_CRASH_KIND).unwrap_or_else(|_| "create".to_owned());
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.app", &root)
        .unwrap_or_else(|error| panic!("register PD-T05 crash-worker repository: {error}"));
    let state = StateStore::open(&state_path)
        .unwrap_or_else(|error| panic!("open PD-T05 crash-worker state: {error}"));
    let (mut controller, summary) = RecoveryManager::recover(state, &registry)
        .unwrap_or_else(|error| panic!("recover before PD-T05 crash-worker create: {error}"));
    assert!(!summary.mutation_blocked);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(
        green_pressure_snapshot(1_000),
    )));
    let manifest = write_tool_manifest();
    let ready = controller
        .derive_ready_lease(&registry, &task_id, readiness(), &manifest)
        .unwrap_or_else(|error| panic!("derive PD-T05 create ready lease: {error}"));
    let task_contract = match mutation_kind.as_str() {
        "create" => "Create the exact governed generated repository file.",
        "update" => "Update the exact governed SettingsForm repository file.",
        other => panic!("unsupported PD-T05 v4 crash mutation kind: {other}"),
    };
    let context = repository_context_packet(&registry, task_contract);
    let exact_source = context
        .items
        .iter()
        .find(|item| item.evidence_id == "file:repo.app:src/settings/SettingsForm.tsx")
        .unwrap_or_else(|| panic!("PD-T05 exact repository source evidence missing"));
    let evidence_id = exact_source.evidence_id.clone();
    let action = match mutation_kind.as_str() {
        "create" => RepositoryActionV1::CreateFile {
            repository_id: "repo.app".to_owned(),
            path: "src/generated.txt".to_owned(),
            content: "generated by governed v4 recovery\n".to_owned(),
        },
        "update" => {
            let path = "src/settings/SettingsForm.tsx";
            let source = fs::read(root.join(path))
                .unwrap_or_else(|error| panic!("read PD-T05 update preimage: {error}"));
            assert_eq!(sha256_prefixed(&source), exact_source.source_digest);
            let updated_content = String::from_utf8(source.clone())
                .unwrap_or_else(|error| panic!("decode PD-T05 update preimage: {error}"))
                .replacen("Save", "Apply", 1);
            RepositoryActionV1::UpdateFile {
                repository_id: "repo.app".to_owned(),
                path: path.to_owned(),
                expected_source_digest: exact_source.source_digest.clone(),
                content: updated_content,
            }
        }
        other => panic!("unsupported PD-T05 v4 crash mutation kind: {other}"),
    };
    let proposal = RepositoryProposalV1 {
        schema_version: REPOSITORY_PROPOSAL_SCHEMA_VERSION,
        evidence_ids: vec![evidence_id],
        action,
    };
    let execution = backend(Vec::new());
    let parts = runtime_parts_for_paths(&root, &base);
    let isolation = PassthroughIsolation {
        capabilities: MacSandboxExecBackend::detect()
            .unwrap_or_else(|error| panic!("detect PD-T05 crash-worker isolation: {error}")),
    };
    let runtime = ExecutionRuntime {
        registry: &registry,
        backend: &execution,
        command_policy: &parts.command_policy,
        isolation_backend: &isolation,
        isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts,
        tool_manifest: &manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let result = controller.execute_repository_proposal(ready, &runtime, &context, proposal);
    panic!("PD-T05 v4 recovery crash worker unexpectedly returned: {result:?}");
}

#[cfg(feature = "recovery-test-hooks")]
#[test]
#[allow(clippy::too_many_lines)]
fn committed_v4_repository_create_recovers_through_recovery_manager_to_success() {
    let mut fixture = compiled_repository_create_fixture("repository-v4-create-recovery");
    let compiled_task = &fixture
        .compilation
        .as_ref()
        .unwrap_or_else(|| panic!("compiled repository create fixture missing plan"))
        .plan()
        .as_value()["tasks"][0];
    assert_eq!(
        compiled_task["verification"]["steps"][0]["evaluator"],
        json!("builtin.diff.scoped_change.v1")
    );
    let (controller, task_id) = controller_for(&mut fixture);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    drop(controller);

    let marker = fixture.repo.base.join("repository-v4-recovery.marker");
    let current =
        std::env::current_exe().unwrap_or_else(|error| panic!("current test executable: {error}"));
    let mut child = Command::new(current)
        .args([
            "--exact",
            "repository_v4_recovery_crash_worker_entry",
            "--nocapture",
        ])
        .env(PD_T05_V4_CRASH_STATE, &fixture.repo.state_path)
        .env(PD_T05_V4_CRASH_ROOT, &fixture.repo.root)
        .env(PD_T05_V4_CRASH_BASE, &fixture.repo.base)
        .env(PD_T05_V4_CRASH_TASK, &task_id)
        .env(PD_T05_V4_CRASH_KIND, "create")
        .env("SOVEREIGN_RECOVERY_TEST_PAUSE_AT", "verification_started")
        .env("SOVEREIGN_RECOVERY_TEST_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn PD-T05 v4 crash worker: {error}"));
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && !marker.exists() {
        if child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll PD-T05 v4 crash worker: {error}"))
            .is_some()
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !marker.exists() {
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!("PD-T05 v4 crash worker never reached verification_started: {stderr}");
    }

    let precrash_state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open PD-T05 precrash state: {error}"));
    let intent_records = precrash_state
        .state_records("controller.action_intent")
        .unwrap_or_else(|error| panic!("read PD-T05 action intents: {error}"));
    let (intent_key, intent) = intent_records
        .iter()
        .find_map(|record| {
            let value = serde_json::from_str::<Value>(&record.value_json).ok()?;
            (value["schema_version"] == json!(4)).then_some((record.key.clone(), value))
        })
        .unwrap_or_else(|| panic!("committed repository-v4 action intent missing"));
    assert_eq!(intent["mutation"]["kind"], json!("create_file"));
    assert_eq!(intent["mutation"]["path"], json!("src/generated.txt"));
    assert_eq!(intent["expected_target_mode"], json!(0o644));
    let expected_post_digest = intent["expected_post_digest"]
        .as_str()
        .unwrap_or_else(|| panic!("v4 expected post digest missing"))
        .to_owned();
    let expected_post_artifact_digest = expected_post_digest
        .strip_prefix("sha256:")
        .unwrap_or_else(|| panic!("v4 expected post digest is not canonical sha256"));
    assert_eq!(
        intent["postimage_artifact_digest"].as_str(),
        Some(expected_post_artifact_digest)
    );
    let origin_epoch = intent["execution_epoch"]
        .as_i64()
        .unwrap_or_else(|| panic!("v4 origin execution epoch missing"));
    let attempt_id = intent["attempt_id"]
        .as_str()
        .unwrap_or_else(|| panic!("v4 attempt id missing"))
        .to_owned();
    let action = precrash_state
        .action_record(&intent_key)
        .unwrap_or_else(|error| panic!("read committed v4 action: {error}"))
        .unwrap_or_else(|| panic!("committed v4 action record missing"));
    assert_eq!(action.state, "committed");
    let committed_result_digest = action
        .result_digest
        .clone()
        .unwrap_or_else(|| panic!("committed v4 action result digest missing"));

    let target = fixture.repo.root.join("src/generated.txt");
    let target_bytes = fs::read(&target)
        .unwrap_or_else(|error| panic!("read committed v4 create target: {error}"));
    assert_eq!(target_bytes, b"generated by governed v4 recovery\n");
    assert_eq!(sha256_prefixed(&target_bytes), expected_post_digest);
    let target_metadata = fs::symlink_metadata(&target)
        .unwrap_or_else(|error| panic!("v4 create target metadata: {error}"));
    assert!(target_metadata.is_file() && !target_metadata.file_type().is_symlink());
    assert_eq!(target_metadata.permissions().mode() & 0o7777, 0o644);

    let task_runtime = precrash_state
        .state_records("controller.task")
        .unwrap_or_else(|error| panic!("read precrash task runtime: {error}"))
        .into_iter()
        .filter_map(|record| serde_json::from_str::<Value>(&record.value_json).ok())
        .find(|value| value.pointer("/task/task_id").and_then(Value::as_str) == Some(&task_id))
        .unwrap_or_else(|| panic!("precrash v4 task runtime missing"));
    assert_eq!(task_runtime["state"], json!("verifying"));
    let attempt_runtime = precrash_state
        .get_state("controller.attempt", &attempt_id)
        .unwrap_or_else(|error| panic!("read precrash v4 attempt: {error}"))
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or_else(|| panic!("precrash v4 attempt runtime missing"));
    assert_eq!(attempt_runtime["state"], json!("verifying"));
    assert!(
        precrash_state
            .state_records("controller.verification")
            .unwrap_or_else(|error| panic!("read precrash verification rows: {error}"))
            .is_empty(),
        "crash must occur before deterministic verification is persisted"
    );
    drop(precrash_state);

    child
        .kill()
        .unwrap_or_else(|error| panic!("kill PD-T05 v4 crash worker: {error}"));
    child
        .wait()
        .unwrap_or_else(|error| panic!("wait PD-T05 v4 crash worker: {error}"));

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen PD-T05 crashed state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover committed repository-v4 action: {error}"));
    assert!(!summary.mutation_blocked);
    assert!(summary.unknown_action_ids.is_empty());
    assert!(summary.pending_recovery_action_ids.is_empty());
    assert!(summary.unresolved_process_lease_ids.is_empty());
    assert_eq!(recovered.task_state(&task_id), Some(TaskState::Succeeded));
    let recovered_action = recovered
        .state()
        .action_record(&intent_key)
        .unwrap_or_else(|error| panic!("read recovered v4 action: {error}"))
        .unwrap_or_else(|| panic!("recovered v4 action missing"));
    assert_eq!(recovered_action.state, "committed");
    assert_eq!(
        recovered_action.result_digest.as_deref(),
        Some(committed_result_digest.as_str())
    );

    let verification_records = recovered
        .state()
        .state_records("controller.verification")
        .unwrap_or_else(|error| panic!("read recovered aggregate verification: {error}"));
    assert_eq!(verification_records.len(), 1);
    let verification: VerificationResultV1 =
        serde_json::from_str(&verification_records[0].value_json)
            .unwrap_or_else(|error| panic!("decode recovered aggregate verification: {error}"));
    assert!(verification.passed);
    assert!(verification.command_results.is_empty());
    assert_eq!(verification.task_id, task_id);
    assert_eq!(verification.attempt_id, attempt_id);
    let current_epoch = recovered
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("read recovered execution epoch: {error}"));
    assert!(verification.execution_epoch > origin_epoch);
    assert!(current_epoch > verification.execution_epoch);
    assert_eq!(
        recovered
            .state()
            .action_records()
            .unwrap_or_else(|error| panic!("read recovered action records: {error}"))
            .into_iter()
            .filter(|record| record.state == "unknown")
            .count(),
        0
    );
    let recovered_bytes =
        fs::read(&target).unwrap_or_else(|error| panic!("read recovered v4 target: {error}"));
    assert_eq!(sha256_prefixed(&recovered_bytes), expected_post_digest);
    assert_eq!(
        fs::symlink_metadata(&target)
            .unwrap_or_else(|error| panic!("recovered target metadata: {error}"))
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
}

#[cfg(feature = "recovery-test-hooks")]
#[test]
#[allow(clippy::too_many_lines)]
fn committed_v4_repository_update_recovers_through_recovery_manager_to_success() {
    let mut fixture = compiled_repository_update_fixture("repository-v4-update-recovery");
    let compiled_task = &fixture
        .compilation
        .as_ref()
        .unwrap_or_else(|| panic!("compiled repository update fixture missing plan"))
        .plan()
        .as_value()["tasks"][0];
    assert_eq!(
        compiled_task["verification"]["steps"][0]["evaluator"],
        json!("builtin.diff.scoped_change.v1")
    );
    let expected_source_digest = fixture.form_digest.clone();
    let expected_postimage = SOURCE.replacen("Save", "Apply", 1);
    let expected_post_digest = sha256_prefixed(expected_postimage.as_bytes());
    let (controller, task_id) = controller_for(&mut fixture);
    assert_eq!(controller.task_state(&task_id), Some(TaskState::Planned));
    drop(controller);

    let marker = fixture
        .repo
        .base
        .join("repository-v4-update-recovery.marker");
    let current =
        std::env::current_exe().unwrap_or_else(|error| panic!("current test executable: {error}"));
    let mut child = Command::new(current)
        .args([
            "--exact",
            "repository_v4_recovery_crash_worker_entry",
            "--nocapture",
        ])
        .env(PD_T05_V4_CRASH_STATE, &fixture.repo.state_path)
        .env(PD_T05_V4_CRASH_ROOT, &fixture.repo.root)
        .env(PD_T05_V4_CRASH_BASE, &fixture.repo.base)
        .env(PD_T05_V4_CRASH_TASK, &task_id)
        .env(PD_T05_V4_CRASH_KIND, "update")
        .env("SOVEREIGN_RECOVERY_TEST_PAUSE_AT", "verification_started")
        .env("SOVEREIGN_RECOVERY_TEST_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn PD-T05 update crash worker: {error}"));
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && !marker.exists() {
        if child
            .try_wait()
            .unwrap_or_else(|error| panic!("poll PD-T05 update crash worker: {error}"))
            .is_some()
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !marker.exists() {
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        panic!("PD-T05 update crash worker never reached verification_started: {stderr}");
    }

    let precrash_state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open PD-T05 update precrash state: {error}"));
    let intent_records = precrash_state
        .state_records("controller.action_intent")
        .unwrap_or_else(|error| panic!("read PD-T05 update action intents: {error}"));
    let (intent_key, intent) = intent_records
        .iter()
        .find_map(|record| {
            let value = serde_json::from_str::<Value>(&record.value_json).ok()?;
            (value["schema_version"] == json!(4)).then_some((record.key.clone(), value))
        })
        .unwrap_or_else(|| panic!("committed repository-v4 update action intent missing"));
    assert_eq!(intent["mutation"]["kind"], json!("update_file"));
    assert_eq!(
        intent["mutation"]["path"],
        json!("src/settings/SettingsForm.tsx")
    );
    assert_eq!(
        intent["mutation"]["expected_source_digest"],
        json!(expected_source_digest)
    );
    let expected_source_mode = u32::try_from(
        intent["mutation"]["expected_source_mode"]
            .as_u64()
            .unwrap_or_else(|| panic!("v4 update expected source mode missing")),
    )
    .unwrap_or_else(|error| panic!("v4 update expected source mode out of range: {error}"));
    assert_eq!(
        intent["expected_target_mode"].as_u64(),
        Some(u64::from(expected_source_mode))
    );
    assert_eq!(
        intent["expected_post_digest"].as_str(),
        Some(expected_post_digest.as_str())
    );
    let expected_post_artifact_digest = expected_post_digest
        .strip_prefix("sha256:")
        .unwrap_or_else(|| panic!("v4 update expected post digest is not canonical sha256"));
    assert_eq!(
        intent["postimage_artifact_digest"].as_str(),
        Some(expected_post_artifact_digest)
    );
    let origin_epoch = intent["execution_epoch"]
        .as_i64()
        .unwrap_or_else(|| panic!("v4 update origin execution epoch missing"));
    let attempt_id = intent["attempt_id"]
        .as_str()
        .unwrap_or_else(|| panic!("v4 update attempt id missing"))
        .to_owned();
    let action = precrash_state
        .action_record(&intent_key)
        .unwrap_or_else(|error| panic!("read committed v4 update action: {error}"))
        .unwrap_or_else(|| panic!("committed v4 update action record missing"));
    assert_eq!(action.state, "committed");
    let committed_result_digest = action
        .result_digest
        .clone()
        .unwrap_or_else(|| panic!("committed v4 update action result digest missing"));

    let target = fixture.repo.root.join("src/settings/SettingsForm.tsx");
    let target_bytes = fs::read(&target)
        .unwrap_or_else(|error| panic!("read committed v4 update target: {error}"));
    assert_eq!(target_bytes, expected_postimage.as_bytes());
    assert_eq!(sha256_prefixed(&target_bytes), expected_post_digest);
    let target_metadata = fs::symlink_metadata(&target)
        .unwrap_or_else(|error| panic!("v4 update target metadata: {error}"));
    assert!(target_metadata.is_file() && !target_metadata.file_type().is_symlink());
    assert_eq!(
        target_metadata.permissions().mode() & 0o7777,
        expected_source_mode
    );

    let task_runtime = precrash_state
        .state_records("controller.task")
        .unwrap_or_else(|error| panic!("read precrash update task runtime: {error}"))
        .into_iter()
        .filter_map(|record| serde_json::from_str::<Value>(&record.value_json).ok())
        .find(|value| value.pointer("/task/task_id").and_then(Value::as_str) == Some(&task_id))
        .unwrap_or_else(|| panic!("precrash v4 update task runtime missing"));
    assert_eq!(task_runtime["state"], json!("verifying"));
    let attempt_runtime = precrash_state
        .get_state("controller.attempt", &attempt_id)
        .unwrap_or_else(|error| panic!("read precrash v4 update attempt: {error}"))
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or_else(|| panic!("precrash v4 update attempt runtime missing"));
    assert_eq!(attempt_runtime["state"], json!("verifying"));
    assert!(
        precrash_state
            .state_records("controller.verification")
            .unwrap_or_else(|error| panic!("read precrash update verification rows: {error}"))
            .is_empty(),
        "update crash must occur before deterministic verification is persisted"
    );
    drop(precrash_state);

    child
        .kill()
        .unwrap_or_else(|error| panic!("kill PD-T05 update crash worker: {error}"));
    child
        .wait()
        .unwrap_or_else(|error| panic!("wait PD-T05 update crash worker: {error}"));

    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("reopen PD-T05 update crashed state: {error}"));
    let (recovered, summary) = RecoveryManager::recover(state, &fixture.registry)
        .unwrap_or_else(|error| panic!("recover committed repository-v4 update action: {error}"));
    assert!(!summary.mutation_blocked);
    assert!(summary.unknown_action_ids.is_empty());
    assert!(summary.pending_recovery_action_ids.is_empty());
    assert!(summary.unresolved_process_lease_ids.is_empty());
    assert_eq!(recovered.task_state(&task_id), Some(TaskState::Succeeded));
    let recovered_action = recovered
        .state()
        .action_record(&intent_key)
        .unwrap_or_else(|error| panic!("read recovered v4 update action: {error}"))
        .unwrap_or_else(|| panic!("recovered v4 update action missing"));
    assert_eq!(recovered_action.state, "committed");
    assert_eq!(
        recovered_action.result_digest.as_deref(),
        Some(committed_result_digest.as_str())
    );

    let verification_records = recovered
        .state()
        .state_records("controller.verification")
        .unwrap_or_else(|error| panic!("read recovered update aggregate verification: {error}"));
    assert_eq!(verification_records.len(), 1);
    let verification: VerificationResultV1 =
        serde_json::from_str(&verification_records[0].value_json)
            .unwrap_or_else(|error| panic!("decode recovered update verification: {error}"));
    assert!(verification.passed);
    assert!(verification.command_results.is_empty());
    assert_eq!(verification.task_id, task_id);
    assert_eq!(verification.attempt_id, attempt_id);
    let current_epoch = recovered
        .state()
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("read recovered update execution epoch: {error}"));
    assert!(verification.execution_epoch > origin_epoch);
    assert!(current_epoch > verification.execution_epoch);
    assert_eq!(
        recovered
            .state()
            .action_records()
            .unwrap_or_else(|error| panic!("read recovered update action records: {error}"))
            .into_iter()
            .filter(|record| record.state == "unknown")
            .count(),
        0
    );
    let recovered_bytes = fs::read(&target)
        .unwrap_or_else(|error| panic!("read recovered v4 update target: {error}"));
    assert_eq!(sha256_prefixed(&recovered_bytes), expected_post_digest);
    assert_eq!(recovered_bytes, expected_postimage.as_bytes());
    assert_eq!(
        fs::symlink_metadata(&target)
            .unwrap_or_else(|error| panic!("recovered update target metadata: {error}"))
            .permissions()
            .mode()
            & 0o7777,
        expected_source_mode
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn managed_loopback_start_rejects_scope_escape_symlink_and_stale_baseline_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("reserve managed loopback port: {error}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("read managed loopback port: {error}"))
        .port();
    drop(listener);

    let mut fixture = compiled_managed_loopback_fixture("managed-loopback-authority", port);
    let state = StateStore::open(&fixture.repo.state_path)
        .unwrap_or_else(|error| panic!("open managed loopback state: {error}"));
    let mut controller =
        Controller::with_permission_context(state, PermissionContext::m7_local_browser_execution());
    let mut browser_pressure = green_pressure_snapshot(1_000);
    browser_pressure.host_free_disk_mib = Some(32_768);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(browser_pressure)));
    let activation = controller
        .activate(
            fixture
                .compilation
                .take()
                .unwrap_or_else(|| panic!("managed loopback compilation already activated")),
            &fixture.registry,
        )
        .unwrap_or_else(|error| panic!("activate managed loopback plan: {error}"));
    let task_id = activation
        .task_ids
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("managed loopback activation task missing"));
    let browser_manifest = browser_tool_manifest();
    let browser_config = BrowserAdapterConfig {
        request_timeout_ms: 5_000,
        ..BrowserAdapterConfig::default()
    };
    let ready = controller
        .derive_browser_ready_lease(
            &fixture.registry,
            &task_id,
            readiness(),
            &browser_manifest,
            browser_config.clone(),
        )
        .unwrap_or_else(|error| panic!("derive managed loopback browser lease: {error}"));
    let browser_backend = backend(Vec::new());
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    assert!(
        chrome.is_file(),
        "managed loopback regression requires local Google Chrome"
    );
    let session = controller
        .acquire_browser_session_from_ready_lease(
            ready,
            &fixture.registry,
            &browser_manifest,
            &browser_backend,
            chrome,
            browser_config,
        )
        .unwrap_or_else(|error| panic!("acquire managed loopback browser session: {error}"));
    let parts = runtime_parts(&fixture);
    let action_ids_before = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("read pre-test action records: {error}"))
        .into_iter()
        .map(|record| record.action_id)
        .collect::<BTreeSet<_>>();
    let process_leases_before = controller
        .state()
        .state_records("controller.process_lease")
        .unwrap_or_else(|error| panic!("read pre-test process leases: {error}"))
        .len();

    let sibling_root = fixture.repo.base.join("sibling-runtime-repo");
    fs::create_dir(&sibling_root)
        .unwrap_or_else(|error| panic!("create mismatched runtime repository: {error}"));
    let mut mismatched_isolation = parts.isolation_request.clone();
    mismatched_isolation.repository_root = sibling_root;
    let mismatch_backend = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect mismatch Seatbelt: {error}"));
    let mismatch_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &browser_backend,
        command_policy: &parts.command_policy,
        isolation_backend: &mismatch_backend,
        isolation_request: &mismatched_isolation,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let mismatch = controller
        .start_managed_loopback_app(
            &session,
            &mismatch_runtime,
            1,
            Path::new("src/other.txt"),
            "managed.sqlite3",
        )
        .err()
        .unwrap_or_else(|| panic!("mismatched runtime repository unexpectedly dispatched"));
    assert!(
        mismatch
            .to_string()
            .contains("runtime repository authority does not match")
    );
    assert_eq!(
        controller
            .state()
            .action_records()
            .unwrap_or_else(|error| panic!("read mismatch action records: {error}"))
            .into_iter()
            .map(|record| record.action_id)
            .collect::<BTreeSet<_>>(),
        action_ids_before
    );
    assert_eq!(
        controller
            .state()
            .state_records("controller.process_lease")
            .unwrap_or_else(|error| panic!("read mismatch process leases: {error}"))
            .len(),
        process_leases_before
    );

    let outside_server = fixture.repo.base.join("outside-server.py");
    fs::write(&outside_server, "print('outside')\n")
        .unwrap_or_else(|error| panic!("write outside managed server: {error}"));
    let server_path = fixture.repo.root.join("src/other.txt");
    fs::remove_file(&server_path).unwrap_or_else(|error| panic!("remove server target: {error}"));
    std::os::unix::fs::symlink(&outside_server, &server_path)
        .unwrap_or_else(|error| panic!("symlink escaping managed server: {error}"));
    let normal_isolation = parts.isolation_request.clone();
    let normal_backend = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect normal Seatbelt: {error}"));
    let normal_runtime = ExecutionRuntime {
        registry: &fixture.registry,
        backend: &browser_backend,
        command_policy: &parts.command_policy,
        isolation_backend: &normal_backend,
        isolation_request: &normal_isolation,
        artifacts: &parts.artifacts,
        tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let symlink_escape = controller
        .start_managed_loopback_app(
            &session,
            &normal_runtime,
            2,
            Path::new("src/other.txt"),
            "managed.sqlite3",
        )
        .err()
        .unwrap_or_else(|| panic!("escaping server symlink unexpectedly dispatched"));
    assert!(
        symlink_escape
            .to_string()
            .contains("server path escaped the canonical repository")
    );
    assert_eq!(
        controller
            .state()
            .action_records()
            .unwrap_or_else(|error| panic!("read symlink action records: {error}"))
            .into_iter()
            .map(|record| record.action_id)
            .collect::<BTreeSet<_>>(),
        action_ids_before
    );
    assert_eq!(
        controller
            .state()
            .state_records("controller.process_lease")
            .unwrap_or_else(|error| panic!("read symlink process leases: {error}"))
            .len(),
        process_leases_before
    );

    fs::remove_file(&server_path).unwrap_or_else(|error| panic!("remove server symlink: {error}"));
    fs::write(&server_path, OTHER_SOURCE)
        .unwrap_or_else(|error| panic!("restore server fixture: {error}"));
    fs::write(
        fixture.repo.root.join("src/settings/SettingsForm.tsx"),
        SOURCE.replace("Save", "Drifted"),
    )
    .unwrap_or_else(|error| panic!("write managed loopback baseline drift: {error}"));
    let baseline_error = controller
        .start_managed_loopback_app(
            &session,
            &normal_runtime,
            3,
            Path::new("src/other.txt"),
            "managed.sqlite3",
        )
        .err()
        .unwrap_or_else(|| panic!("stale managed loopback baseline unexpectedly dispatched"));
    assert!(
        baseline_error
            .to_string()
            .contains("repository baseline drifted"),
        "unexpected stale managed-loopback error: {baseline_error}"
    );
    let new_actions = controller
        .state()
        .action_records()
        .unwrap_or_else(|error| panic!("read stale-baseline action records: {error}"))
        .into_iter()
        .filter(|record| !action_ids_before.contains(&record.action_id))
        .collect::<Vec<_>>();
    assert_eq!(new_actions.len(), 1);
    assert_eq!(new_actions[0].state, "authorized");
    assert_eq!(
        controller
            .state()
            .state_records("controller.process_lease")
            .unwrap_or_else(|error| panic!("read stale-baseline process leases: {error}"))
            .len(),
        process_leases_before
    );
    controller
        .shutdown_browser_session(session)
        .unwrap_or_else(|error| panic!("shutdown managed loopback browser session: {error}"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn managed_node_launch_uses_controller_pin_dynamic_port_persistence_and_reaps_group() {
    let node_path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("node"))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("Node fixture requires an installed node executable"));
    let node = PinnedExecutable::from_path(&node_path, "fixture-node")
        .unwrap_or_else(|error| panic!("pin fixture Node: {error}"));
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin fixture Python: {error}"));
    let node_root = node.path.parent().unwrap().to_path_buf();
    let python_root = python.path.parent().unwrap().to_path_buf();
    let command_policy = CommandPolicy::new([python, node.clone()], [python_root, node_root])
        .unwrap_or_else(|error| panic!("Node fixture command policy: {error}"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let launch = BrowserManagedAppLaunchV1::NodeManagedServerV1 {
        working_directory_relative_path: "apps/inventory".to_owned(),
        entrypoint_relative_path: "server.js".to_owned(),
        argv: Vec::new(),
        dynamic_port: BrowserManagedArgBindingV1::ArgvFlag { flag: "--port".to_owned() },
        readiness: BrowserManagedReadinessV1 { path: "/health".to_owned(), status: 200, body: "ok".to_owned(), timeout_ms: 5_000 },
        persistence: BrowserManagedPersistenceBindingV1::ArgvFlag { flag: "--db".to_owned(), filename: "inventory.sqlite3".to_owned() },
        required_generations: 2,
    };
    let mut fixture = compiled_managed_loopback_fixture_with_launch("managed-node-runtime", port, launch);
    let state = StateStore::open(&fixture.repo.state_path).unwrap();
    let mut controller = Controller::with_permission_context(state, PermissionContext::m7_local_browser_execution());
    let mut pressure = green_pressure_snapshot(1_000);
    pressure.host_free_disk_mib = Some(32_768);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(pressure)));
    let activation = controller.activate(fixture.compilation.take().unwrap(), &fixture.registry).unwrap();
    let task_id = &activation.task_ids[0];
    let browser_manifest = browser_tool_manifest();
    let browser_config = BrowserAdapterConfig { request_timeout_ms: 5_000, ..BrowserAdapterConfig::default() };
    let ready = controller.derive_browser_ready_lease(&fixture.registry, task_id, readiness(), &browser_manifest, browser_config.clone()).unwrap();
    let backend = backend(Vec::new());
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    let session = controller.acquire_browser_session_from_ready_lease(ready, &fixture.registry, &browser_manifest, &backend, chrome, browser_config).unwrap();
    let parts = runtime_parts(&fixture);
    let isolation = MacSandboxExecBackend::detect().unwrap();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry, backend: &backend, command_policy: &command_policy,
        isolation_backend: &isolation, isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts, tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    let unconfigured = controller.start_plan_managed_loopback_app(&session, &runtime, 1).err().unwrap();
    assert!(unconfigured.to_string().contains("Node executable is not configured"));
    controller.configure_managed_node_executable(&command_policy, &node.path).unwrap();
    let mut first = controller.start_plan_managed_loopback_app(&session, &runtime, 1)
        .unwrap_or_else(|error| panic!("start Node generation one: {error}"));
    let first_group = first.process_group_id();
    let db = first.database_path().to_path_buf();
    assert_eq!(fs::read_to_string(&db).unwrap(), "persisted");
    controller.stop_managed_loopback_app(&session, &runtime, &mut first).unwrap();
    assert!(sovereign_tools::process_group_leader_identity(first_group).unwrap().is_none());
    assert_process_group_absent(first_group);
    let mut second = controller.start_plan_managed_loopback_app(&session, &runtime, 2)
        .unwrap_or_else(|error| panic!("start Node generation two: {error}"));
    assert_eq!(second.database_path(), db);
    assert_eq!(fs::read_to_string(&db).unwrap(), "persisted");
    let second_group = second.process_group_id();
    controller.stop_managed_loopback_app(&session, &runtime, &mut second).unwrap();
    assert!(sovereign_tools::process_group_leader_identity(second_group).unwrap().is_none());
    assert_process_group_absent(second_group);
    controller.shutdown_browser_session(session).unwrap();
}

#[test]
fn managed_node_postgres_broker_launches_two_generations_and_closes_each_endpoint() {
    let Ok(database_oid) = std::env::var("SOVEREIGN_TEST_LIVE_POSTGRES_OID") else { return; };
    let database_oid: u32 = database_oid.parse().unwrap();
    assert!(std::net::TcpStream::connect(("127.0.0.1", 5432)).is_ok(),
        "live PostgreSQL TCP must be reachable outside the managed-app sandbox for this denial proof");
    let node_path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("node"))
        .find(|path| path.is_file()).unwrap();
    let node = PinnedExecutable::from_path(&node_path, "fixture-node").unwrap();
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python").unwrap();
    let node_root = node.path.parent().unwrap().to_path_buf();
    let python_root = python.path.parent().unwrap().to_path_buf();
    let command_policy = CommandPolicy::new([python, node.clone()], [python_root, node_root]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let launch = BrowserManagedAppLaunchV1::NodeManagedServerV1 {
        working_directory_relative_path: "apps/inventory".to_owned(),
        entrypoint_relative_path: "server.js".to_owned(),
        argv: Vec::new(),
        dynamic_port: BrowserManagedArgBindingV1::ArgvFlag { flag: "--port".to_owned() },
        readiness: BrowserManagedReadinessV1 { path: "/health".to_owned(), status: 200, body: "ok".to_owned(), timeout_ms: 5_000 },
        persistence: BrowserManagedPersistenceBindingV1::PostgresBrokerV1 { flag: "--database-url".to_owned() },
        required_generations: 2,
    };
    let mut fixture = compiled_managed_loopback_fixture_with_launch("managed-postgres-runtime", port, launch);
    let state = StateStore::open(&fixture.repo.state_path).unwrap();
    let mut controller = Controller::with_permission_context(state, PermissionContext::m7_local_browser_execution());
    let mut pressure = green_pressure_snapshot(1_000);
    pressure.host_free_disk_mib = Some(32_768);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(pressure)));
    let activation = controller.activate(fixture.compilation.take().unwrap(), &fixture.registry).unwrap();
    let task_id = &activation.task_ids[0];
    let browser_manifest = browser_tool_manifest();
    let browser_config = BrowserAdapterConfig { request_timeout_ms: 5_000, ..BrowserAdapterConfig::default() };
    let ready = controller.derive_browser_ready_lease(&fixture.registry, task_id, readiness(), &browser_manifest, browser_config.clone()).unwrap();
    let backend = backend(Vec::new());
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    let session = controller.acquire_browser_session_from_ready_lease(ready, &fixture.registry, &browser_manifest, &backend, chrome, browser_config).unwrap();
    let parts = runtime_parts(&fixture);
    let isolation = MacSandboxExecBackend::detect().unwrap();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry, backend: &backend, command_policy: &command_policy,
        isolation_backend: &isolation, isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts, tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    controller.configure_managed_node_executable(&command_policy, &node.path).unwrap();
    controller.configure_managed_postgres_backend(Path::new("/tmp/.s.PGSQL.5432"), database_oid).unwrap();
    let mut groups = BTreeSet::new();
    let mut broker_ports = Vec::new();
    for generation in 1..=2 {
        let request_id = match controller.start_plan_managed_loopback_app(&session, &runtime, generation) {
            Err(sovereign_controller::ControllerError::AwaitingApproval { request_id, .. }) => request_id,
            Ok(_) => panic!("PostgreSQL generation {generation} started without network-write approval"),
            Err(error) => panic!("request PostgreSQL generation {generation} approval: {error}"),
        };
        let approved = controller.respond_to_approval(
            &request_id,
            sovereign_controller::ApprovalDecisionV1::Approve,
            "test:postgres-operator",
        ).unwrap_or_else(|error| panic!("approve PostgreSQL generation {generation}: {error}"));
        assert_eq!(approved.permission_class, "network_write");
        let mut app = controller.start_plan_managed_loopback_app(&session, &runtime, generation)
            .unwrap_or_else(|error| panic!("start approved PostgreSQL generation {generation}: {error}"));
        let broker_port = app.postgres_broker_port().unwrap();
        broker_ports.push(broker_port);
        assert_eq!(app.database_path(), Path::new("postgresql:sovereign_app"));
        let group = app.process_group_id();
        assert!(groups.insert(group), "managed PostgreSQL restart reused a process group");
        controller.stop_managed_loopback_app(&session, &runtime, &mut app).unwrap();
        assert_process_group_absent(group);
        assert!(std::net::TcpStream::connect(("127.0.0.1", broker_port)).is_err());
    }
    controller.shutdown_browser_session(session).unwrap();
    let grants = controller.state().action_records().unwrap().into_iter()
        .filter(|record| record.action_id.starts_with("managed-postgres-broker."))
        .map(|record| {
            assert_eq!(record.state, "committed");
            assert!(record.result_digest.is_some());
            (record.action_id, record.payload_digest, record.result_digest)
        }).collect::<Vec<_>>();
    assert_eq!(grants.len(), 2, "each generation needs one distinct durable network grant");
    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path).unwrap();
    let (recovered, recovery) = RecoveryManager::recover_with_permission_context(
        state, &fixture.registry, PermissionContext::m7_local_browser_execution(),
    ).unwrap_or_else(|error| panic!("recover stopped PostgreSQL generations: {error}"));
    assert!(recovery.unknown_action_ids.is_empty());
    for (action_id, payload_digest, result_digest) in grants {
        let record = recovered.state().action_record(&action_id).unwrap().unwrap();
        assert_eq!(record.state, "committed");
        assert_eq!(record.payload_digest, payload_digest);
        assert_eq!(record.result_digest, result_digest);
        assert_eq!(recovered.state().journal().unwrap().iter().filter(|event|
            event.entity_id == action_id && event.event_kind == "dispatched").count(), 1,
            "recovery replayed the generation-bound broker action");
    }
    for port in broker_ports {
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    }
    for group in groups {
        assert_process_group_absent(group);
    }
}

#[test]
fn managed_postgres_abrupt_handle_loss_recovery_reaps_generation_without_replay() {
    let Ok(database_oid) = std::env::var("SOVEREIGN_TEST_LIVE_POSTGRES_OID") else { return; };
    let database_oid: u32 = database_oid.parse().unwrap();
    let node_path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join("node"))
        .find(|path| path.is_file()).unwrap();
    let node = PinnedExecutable::from_path(&node_path, "fixture-node").unwrap();
    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python").unwrap();
    let command_policy = CommandPolicy::new(
        [python.clone(), node.clone()],
        [python.path.parent().unwrap().to_path_buf(), node.path.parent().unwrap().to_path_buf()],
    ).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let launch = BrowserManagedAppLaunchV1::NodeManagedServerV1 {
        working_directory_relative_path: "apps/inventory".to_owned(),
        entrypoint_relative_path: "server.js".to_owned(),
        argv: Vec::new(),
        dynamic_port: BrowserManagedArgBindingV1::ArgvFlag { flag: "--port".to_owned() },
        readiness: BrowserManagedReadinessV1 { path: "/health".to_owned(), status: 200, body: "ok".to_owned(), timeout_ms: 5_000 },
        persistence: BrowserManagedPersistenceBindingV1::PostgresBrokerV1 { flag: "--database-url".to_owned() },
        required_generations: 2,
    };
    let mut fixture = compiled_managed_loopback_fixture_with_launch("managed-postgres-recovery", port, launch);
    let state = StateStore::open(&fixture.repo.state_path).unwrap();
    let mut controller = Controller::with_permission_context(state, PermissionContext::m7_local_browser_execution());
    let mut pressure = green_pressure_snapshot(1_000);
    pressure.host_free_disk_mib = Some(32_768);
    controller.set_resource_pressure_probe(Box::new(FixedResourcePressureProbe(pressure)));
    let activation = controller.activate(fixture.compilation.take().unwrap(), &fixture.registry).unwrap();
    let browser_manifest = browser_tool_manifest();
    let browser_config = BrowserAdapterConfig { request_timeout_ms: 5_000, ..BrowserAdapterConfig::default() };
    let ready = controller.derive_browser_ready_lease(&fixture.registry, &activation.task_ids[0], readiness(), &browser_manifest, browser_config.clone()).unwrap();
    let backend = backend(Vec::new());
    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    let session = controller.acquire_browser_session_from_ready_lease(ready, &fixture.registry, &browser_manifest, &backend, chrome, browser_config).unwrap();
    let parts = runtime_parts(&fixture);
    let isolation = MacSandboxExecBackend::detect().unwrap();
    let runtime = ExecutionRuntime {
        registry: &fixture.registry, backend: &backend, command_policy: &command_policy,
        isolation_backend: &isolation, isolation_request: &parts.isolation_request,
        artifacts: &parts.artifacts, tool_manifest: &parts.manifest,
        python_executable: Path::new("/usr/bin/python3"),
    };
    controller.configure_managed_node_executable(&command_policy, &node.path).unwrap();
    controller.configure_managed_postgres_backend(Path::new("/tmp/.s.PGSQL.5432"), database_oid).unwrap();
    let request_id = match controller.start_plan_managed_loopback_app(&session, &runtime, 1) {
        Err(sovereign_controller::ControllerError::AwaitingApproval { request_id, .. }) => request_id,
        Ok(_) => panic!("managed PostgreSQL broker started without approval"),
        Err(error) => panic!("request managed PostgreSQL approval: {error}"),
    };
    controller.respond_to_approval(&request_id, sovereign_controller::ApprovalDecisionV1::Approve, "test:postgres-operator").unwrap();
    let app = controller.start_plan_managed_loopback_app(&session, &runtime, 1).unwrap();
    let broker_port = app.postgres_broker_port().unwrap();
    let group = app.process_group_id();
    let broker_grant = controller.state().action_records().unwrap().into_iter()
        .find(|record| record.action_id.starts_with("managed-postgres-broker."))
        .unwrap();
    assert_eq!(broker_grant.state, "committed");
    let start_action = controller.state().action_records().unwrap().into_iter()
        .find(|record| record.action_id.starts_with("managed-loopback-start."))
        .unwrap();
    assert_eq!(start_action.state, "committed");
    drop(app); // Simulates losing the ephemeral owner before a durable stopped transition.
    assert_process_group_absent(group);
    assert!(std::net::TcpStream::connect(("127.0.0.1", broker_port)).is_err());
    drop(session);
    drop(controller);
    let state = StateStore::open(&fixture.repo.state_path).unwrap();
    let (recovered, summary) = RecoveryManager::recover_with_permission_context(
        state, &fixture.registry, PermissionContext::m7_local_browser_execution(),
    ).unwrap_or_else(|error| panic!("recover lost managed PostgreSQL owner: {error}"));
    let recovered_grant = recovered.state().action_record(&broker_grant.action_id).unwrap().unwrap();
    assert!(summary.execution_epoch_after > broker_grant.execution_epoch);
    assert_eq!(recovered_grant.state, "committed");
    assert_eq!(recovered_grant.payload_digest, broker_grant.payload_digest);
    assert_eq!(recovered_grant.result_digest, broker_grant.result_digest);
    assert_eq!(recovered.state().journal().unwrap().iter().filter(|event|
        event.entity_id == broker_grant.action_id && event.event_kind == "dispatched").count(), 1,
        "recovery replayed the approved PostgreSQL grant");
    let recovered_start = recovered.state().action_record(&start_action.action_id).unwrap().unwrap();
    assert_eq!(recovered_start.state, "committed");
    assert_eq!(recovered_start.payload_digest, start_action.payload_digest);
    assert_eq!(recovered_start.result_digest, start_action.result_digest);
    assert_eq!(recovered.state().journal().unwrap().iter().filter(|event|
        event.entity_id == start_action.action_id && event.event_kind == "dispatched").count(), 1,
        "recovery replayed the managed process start");
    assert!(summary.unresolved_process_lease_ids.is_empty());
    assert_process_group_absent(group);
    assert!(std::net::TcpStream::connect(("127.0.0.1", broker_port)).is_err());
}

fn assert_process_group_absent(group: u32) {
    let output = Command::new("/bin/ps").args(["-A", "-o", "pgid="]).output()
        .unwrap_or_else(|error| panic!("inspect process groups: {error}"));
    assert!(output.status.success(), "inspect process groups failed");
    let listing = String::from_utf8(output.stdout).unwrap();
    assert!(!listing.lines().any(|line| line.trim() == group.to_string()),
        "managed process group {group} retained a process or child");
}

#[test]
#[allow(clippy::too_many_lines)]
fn managed_limit_cleanup_reaps_existing_lease_without_durable_stopped_acceptance() {
    let repo = TestRepo::create("managed-limit-durable-stop");
    let mut state = StateStore::open(&repo.state_path)
        .unwrap_or_else(|error| panic!("open managed-limit state: {error}"));
    let artifacts = ArtifactStore::open(repo.base.join("managed-limit-cas"))
        .unwrap_or_else(|error| panic!("open managed-limit artifacts: {error}"));
    let data_root = repo.base.join("managed-limit-data");
    fs::create_dir_all(&data_root)
        .unwrap_or_else(|error| panic!("create managed-limit data root: {error}"));

    let python = PinnedExecutable::from_path("/usr/bin/python3", "macos-system-python")
        .unwrap_or_else(|error| panic!("pin managed-limit python: {error}"));
    let executable = python.path.clone();
    let executable_digest = python.sha256.clone();
    let toolchain_root = executable
        .parent()
        .unwrap_or_else(|| panic!("managed-limit python parent missing"))
        .to_path_buf();
    let command_policy = CommandPolicy::new([python], [toolchain_root])
        .unwrap_or_else(|error| panic!("managed-limit command policy: {error}"));
    let manifest = write_tool_manifest();
    let policy_digest = format!("sha256:{:064x}", 71);
    let isolation_policy_digest = format!("sha256:{:064x}", 72);
    let execution_epoch = state
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("managed-limit execution epoch: {error}"));
    let expires_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("managed-limit clock: {error}"))
        .as_millis();
    let expires_at_ms = i64::try_from(expires_at_ms)
        .unwrap_or(i64::MAX)
        .saturating_add(60_000);
    let mut action = AuthorizedAction {
        action_id: "managed-loopback-start.limit-durable-stop".to_owned(),
        plan_id: "plan.managed-limit".to_owned(),
        plan_revision: 1,
        task_id: "task.managed-limit".to_owned(),
        attempt_id: "attempt.managed-limit".to_owned(),
        tool_id: manifest.tool_id.clone(),
        tool_version: manifest.version.clone(),
        tool_digest: manifest.content_digest.clone(),
        executable_digest,
        repository_id: "repo.managed-limit".to_owned(),
        destination_digest: Some(format!("sha256:{:064x}", 73)),
        permission_class: PermissionClass::ProcessExec,
        execution_epoch,
        policy_digest: policy_digest.clone(),
        permission_decision_digest: String::new(),
        isolation_policy_digest: isolation_policy_digest.clone(),
        nonce: "nonce.managed-limit".to_owned(),
        expires_at_ms,
        command: CommandSpec {
            executable: executable.clone(),
            args: vec!["-c".to_owned(), "import time; time.sleep(30)".to_owned()],
            working_directory: repo.root.clone(),
            environment: BTreeMap::new(),
            mode: CommandMode::Direct,
            declared_risk: CommandRisk::RepositoryMutation,
            timeout_ms: 5_000,
            output_limit_bytes: 64 * 1024,
            disk_write_limit_bytes: 64 * 1024,
            subprocess_limit: 0,
        },
        individually_authorized_environment: BTreeSet::new(),
        approval_required: false,
        reconciliation_mode: ReconciliationMode::UnsafeSideEffect,
    };
    let layers = CapabilityLayers {
        global: CapabilitySet::all(),
        project: CapabilitySet::all(),
        task: CapabilitySet::all(),
        role: CapabilitySet::all(),
        tool: CapabilitySet::all(),
        user: CapabilitySet::all(),
    };
    let permission_decision = PermissionDecision::new(
        action.plan_id.clone(),
        action.plan_revision,
        action.task_id.clone(),
        format!("sha256:{:064x}", 74),
        policy_digest,
        action.tool_id.clone(),
        action.tool_version.clone(),
        action.tool_digest.clone(),
        layers,
    )
    .unwrap_or_else(|error| panic!("managed-limit permission decision: {error}"));
    action.permission_decision_digest = permission_decision.digest();
    let isolated = IsolatedCommand {
        executable,
        args: action.command.args.clone(),
    };
    let isolation = MacSandboxExecBackend::detect()
        .unwrap_or_else(|error| panic!("detect managed-limit isolation: {error}"));
    let runner = ProcessRunner::new(&command_policy, &isolation);

    let mut process = {
        let mut journal = ActionJournal::new(&mut state);
        journal
            .authorize(&action, &manifest, &permission_decision)
            .unwrap_or_else(|error| panic!("authorize managed-limit action: {error}"));
        runner
            .start_managed_preisolated_with_write_root_until(
                &mut journal,
                &action,
                &isolated,
                &isolation_policy_digest,
                &data_root,
                Instant::now() + Duration::from_millis(750),
            )
            .unwrap_or_else(|error| panic!("start managed-limit process: {error}"))
    };
    let process_group_id = process.process_group_id();
    let leader_identity = process.leader_identity().to_owned();
    let start_result_digest = {
        let mut journal = ActionJournal::new(&mut state);
        runner
            .commit_managed_started(&mut journal, &action, &artifacts, &mut process)
            .unwrap_or_else(|error| panic!("commit managed-limit start: {error}"))
    };

    let app_id = "managed-loopback.limit-durable-stop";
    let binding = json!({
        "schema_version": 1,
        "app_id": app_id,
        "generation": 1,
        "plan_id": action.plan_id,
        "plan_revision": action.plan_revision,
        "task_id": action.task_id,
        "task_contract_digest": format!("sha256:{:064x}", 75),
        "attempt_id": action.attempt_id,
        "execution_epoch": execution_epoch,
        "browser_resource_lease_id": "browser:managed-limit",
        "loopback_grant_digest": format!("sha256:{:064x}", 76),
        "port": 49_997,
        "repository_root": repo.root,
        "data_root": data_root,
        "database_path": repo.base.join("managed-limit-data/managed.sqlite3"),
        "start_action_id": action.action_id,
        "start_result_digest": start_result_digest,
        "process_group_id": process_group_id,
        "leader_identity": leader_identity,
        "state": "ready"
    });
    let binding_json = binding.to_string();
    state
        .put_state_records_with_events(
            &[StateRecordUpdate {
                namespace: "controller.managed_loopback_app",
                key: &action.action_id,
                value_json: &binding_json,
            }],
            &[NewJournalEvent {
                event_id: "event.managed-limit.ready",
                entity_type: "managed_loopback_app",
                entity_id: app_id,
                event_kind: "managed_loopback_ready",
                payload_json: "{}",
            }],
        )
        .unwrap_or_else(|error| panic!("persist managed-limit ready binding: {error}"));

    thread::sleep(Duration::from_millis(1_000));
    let stop_error = {
        let mut journal = ActionJournal::new(&mut state);
        runner
            .stop_managed(&mut journal, &mut process)
            .err()
            .unwrap_or_else(|| panic!("limited managed generation reported a clean manual stop"))
    };
    assert!(
        matches!(&stop_error, ToolError::ResourceLimit(message) if message.contains("timeout"))
    );

    let lease_raw = state
        .get_state("controller.process_lease", &action.action_id)
        .unwrap_or_else(|error| panic!("read managed-limit process lease: {error}"))
        .unwrap_or_else(|| panic!("managed-limit process lease missing"));
    let lease: Value = serde_json::from_str(&lease_raw)
        .unwrap_or_else(|error| panic!("decode managed-limit process lease: {error}"));
    assert_eq!(lease["state"], json!("reaped"));
    assert_eq!(lease["process_group_id"], json!(process_group_id));
    assert_eq!(lease["leader_identity"], json!(leader_identity));
    let durable_binding_raw = state
        .get_state("controller.managed_loopback_app", &action.action_id)
        .unwrap_or_else(|error| panic!("read managed-limit app binding: {error}"))
        .unwrap_or_else(|| panic!("managed-limit app binding missing"));
    let durable_binding: Value = serde_json::from_str(&durable_binding_raw)
        .unwrap_or_else(|error| panic!("decode managed-limit app binding: {error}"));
    assert_eq!(durable_binding["state"], json!("ready"));
    let journal = state
        .journal()
        .unwrap_or_else(|error| panic!("read managed-limit journal: {error}"));
    assert_eq!(
        journal
            .iter()
            .filter(
                |event| event.entity_id == app_id && event.event_kind == "managed_loopback_ready"
            )
            .count(),
        1
    );
    assert_eq!(
        journal
            .iter()
            .filter(|event| {
                event.entity_id == app_id && event.event_kind == "managed_loopback_stopped"
            })
            .count(),
        0
    );
    assert_eq!(
        state
            .action_record(&action.action_id)
            .unwrap_or_else(|error| panic!("read managed-limit start action: {error}"))
            .unwrap_or_else(|| panic!("managed-limit start action missing"))
            .state,
        "committed"
    );
}
