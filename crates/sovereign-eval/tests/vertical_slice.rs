use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_controller::{Controller, ExecutionRuntime, ReadinessInputs, TaskState};
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
    PinnedExecutable,
};
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use sovereign_state::StateStore;
use sovereign_tools::{PermissionClass, ToolManifest};
use std::collections::BTreeSet;
use std::fs;
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
            "files": [
                "src/settings/SettingsForm.tsx",
                "src/settings/SettingsForm.test.tsx"
            ],
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

    let role = capability(
        "role.implementer",
        "1.0.0",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
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
        .unwrap_or_else(|error| panic!("compile natural-language goal: {error}"));
    assert!(validator.validate(compilation.plan()).is_empty());
    assert_eq!(compiler_budget.remaining_calls(), 0);

    let state = StateStore::open(fixture.base.join("state.sqlite3"))
        .unwrap_or_else(|error| panic!("open controller state: {error}"));
    let artifacts = ArtifactStore::open(fixture.base.join("cas"))
        .unwrap_or_else(|error| panic!("open artifact store: {error}"));
    let mut controller = Controller::new(state);
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
        network_offline: true,
        allow_repository_write: true,
        require_full_filesystem_read_jail: false,
    };
    let tool_manifest = ToolManifest {
        tool_id: "tool.patch".to_owned(),
        version: "1.0.0".to_owned(),
        content_digest: WRITE_TOOL_DIGEST.to_owned(),
        permission_ceiling: BTreeSet::from([PermissionClass::RepositoryWrite]),
        declared_risk_floor: CommandRisk::RepositoryMutation,
    };
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
