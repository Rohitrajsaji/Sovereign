#![cfg(target_os = "macos")]

use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{
    Controller, ControllerError, ExecutionRuntime, ModelProposalV1, PermissionContext,
    PlanValidity, ReadinessInputs, SchedulerView, TaskState,
};
use sovereign_evidence::ArtifactStore;
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{
    CommandPolicy, CommandRisk, CommandSpec, ExecutionIsolationBackend, HostPressureSnapshot,
    IsolatedCommand, IsolationCapabilities, IsolationRequest, MacSandboxExecBackend,
    ModelCallBudget, PinnedExecutable, PolicyError,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence};
use sovereign_state::{NewJournalEvent, StateStore};
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
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
    compiled_fixture_inner(label, evidence_query, false, None, None, false)
}

#[allow(clippy::too_many_lines)]
fn compiled_fixture_with_dirty_target(label: &str) -> CompiledFixture {
    compiled_fixture_inner(label, false, true, None, None, false)
}

#[allow(clippy::too_many_lines)]
fn compiled_fixture_with_task_model_call_cap(label: &str, cap: u64) -> CompiledFixture {
    compiled_fixture_inner(label, false, false, Some(cap), None, false)
}

fn compiled_fixture_with_target_mode(label: &str, mode: u32) -> CompiledFixture {
    compiled_fixture_inner(label, false, false, None, Some(mode), false)
}

fn compiled_two_task_fixture(label: &str) -> CompiledFixture {
    compiled_fixture_inner(label, false, false, None, None, true)
}

#[allow(clippy::too_many_lines)]
fn compiled_fixture_inner(
    label: &str,
    evidence_query: bool,
    dirty_target: bool,
    task_model_call_cap: Option<u64>,
    target_mode: Option<u32>,
    two_task: bool,
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
    let planning = if two_task {
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
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: format!("compile.{label}"),
        compiled_at: "2026-09-12T18:20:00Z".to_owned(),
        project_id: "project.t07".to_owned(),
        project_name: "T07 fixture".to_owned(),
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
    json!({
        "schema_version": 1,
        "evidence_ids": ["file:repo.app:src/settings/SettingsForm.tsx"],
        "action": {
            "kind": "replace_literal",
            "repository_id": "repo.app",
            "path": "src/settings/SettingsForm.tsx",
            "expected_source_digest": form_digest,
            "old_literal": "Save",
            "new_literal": "Apply",
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
