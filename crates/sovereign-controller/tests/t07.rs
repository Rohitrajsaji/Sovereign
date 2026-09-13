#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    CheckpointActionRecord, CheckpointManifest, Controller, ControllerError, ExecutionRuntime,
    ModelProposalV1, PermissionContext, PlanValidity, ReadinessInputs, RecoveryManager,
    SchedulerView, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, HostPressureSnapshot,
    IsolatedCommand, IsolationCapabilities, IsolationRequest, MacSandboxExecBackend,
    ModelCallBudget, PinnedExecutable, PolicyError,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::{
    ActionTransition, NewActionRecord, NewCheckpointIntegrityRecord, NewJournalEvent, StateStore,
};
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SOURCE: &str =
    "export function SettingsForm() {\n  return <button type=\"submit\">Save</button>;\n}\n";
const OTHER_SOURCE: &str = "baseline other file\n";
const WRITE_TOOL_DIGEST: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
    )
}

#[allow(clippy::too_many_lines)]
fn compiled_fixture_with_dirty_target(label: &str) -> CompiledFixture {
    compiled_fixture_inner(label, false, true, None, None, false, false, None, None)
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
    )
}

fn compiled_two_task_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(label, false, false, None, None, true, false, None, None)
}

fn compiled_worktree_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(label, false, false, None, None, false, true, None, None)
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
    let mut policy = global_policy();
    if let Some(cap) = task_model_call_cap {
        let resource_cap = policy
            .pointer_mut("/resources/max_model_calls")
            .unwrap_or_else(|| panic!("policy max_model_calls missing"));
        *resource_cap = json!(cap);
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
        role: capability(
            "role.implementer",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
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
        max_model_calls: 1,
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
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
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

struct RuntimeParts {
    command_policy: CommandPolicy,
    isolation_request: IsolationRequest,
    artifacts: ArtifactStore,
    manifest: ToolManifest,
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
        manifest: ToolManifest {
            tool_id: "tool.patch".to_owned(),
            version: "1.0.0".to_owned(),
            content_digest: WRITE_TOOL_DIGEST.to_owned(),
            permission_ceiling: BTreeSet::from([PermissionClass::RepositoryWrite]),
            declared_risk_floor: CommandRisk::RepositoryMutation,
        },
    }
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
        .derive_ready_lease(&fixture.registry, task_id, readiness())
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
    let Err(error) = controller.derive_ready_lease(&fixture.registry, &task_id, readiness()) else {
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
    let Err(error) = controller.derive_ready_lease(&fixture.registry, &task_id, readiness()) else {
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
    let Err(error) = recovered.derive_ready_lease(&fixture.registry, &task_id, readiness()) else {
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
fn verified_upstream_bindings_make_dependent_task_ready_and_misbound_record_blocks_it() {
    let mut fixture = compiled_two_task_fixture("dependency-bindings");
    let contract = two_task_contract(&fixture);

    let state =
        StateStore::open(&fixture.repo.state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller = Controller::new(state);
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
            .derive_ready_lease(&fixture.registry, &contract.downstream, readiness())
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
        .derive_ready_lease(&fixture.registry, &contract.upstream, readiness())
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
        .derive_ready_lease(&fixture.registry, &contract.downstream, readiness())
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
            .derive_ready_lease(&fixture.registry, &contract.downstream, readiness())
            .is_err(),
        "misbound dependency artifact must block readiness"
    );
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
    let Err(error) =
        controller.derive_ready_lease(&fixture.registry, &activation.task_ids[0], readiness())
    else {
        panic!("read-only permission context unexpectedly produced readiness")
    };
    assert!(error.to_string().contains("permission intersection"));
}

#[test]
fn constrained_pressure_defers_before_ready_lease_is_issued() {
    let mut fixture = compiled_fixture("pressure", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let mut inputs = readiness();
    inputs.host_pressure = HostPressureSnapshot {
        controlled_working_set_mib: 6_000,
        host_headroom_mib: 512,
        swap_out_growth_mib_per_min: 300,
        compressor_growth_mib_per_min: 300,
        os_pressure_warning: true,
        recent_pressure_event: true,
        thermal_serious: false,
    };
    assert!(
        controller
            .derive_ready_lease(&fixture.registry, &task_id, inputs)
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
            .derive_ready_lease(&fixture.registry, &task_id, readiness())
            .is_err()
    );
}

#[test]
fn baseline_drift_invalidates_ready_lease_and_advances_epoch() {
    let mut fixture = compiled_fixture("baseline-drift", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
fn epoch_change_after_authorization_blocks_dispatch_before_mutation() {
    let mut fixture = compiled_fixture("epoch", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
fn exhausted_model_budget_defers_cleanly_before_backend_dispatch() {
    let mut fixture = compiled_fixture("budget", false);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::DeferredResource)
    );
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
}

#[test]
fn compiled_task_model_call_ceiling_cannot_be_refilled_by_caller_budget() {
    let mut fixture = compiled_fixture_with_task_model_call_cap("task-budget", 0);
    let (mut controller, task_id) = controller_for(&mut fixture);
    let ready = controller
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
    assert_eq!(
        controller.task_state(&task_id),
        Some(TaskState::DeferredResource)
    );
    let source = fs::read_to_string(fixture.repo.root.join("src/settings/SettingsForm.tsx"))
        .unwrap_or_else(|error| panic!("read source: {error}"));
    assert!(source.contains("Save"));
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
            .derive_ready_lease(&fixture.registry, &task_id, readiness())
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
        .derive_ready_lease(&fixture.registry, &t2, readiness())
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
        .derive_ready_lease(&fixture.registry, &t4, readiness())
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
        .derive_ready_lease(&fixture.registry, &t4, readiness())
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
