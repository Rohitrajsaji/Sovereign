use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner, EvidenceItem,
};
use sovereign_model::{
    DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelFinishReason, ModelLoadProfile, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::ModelCallBudget;
use sovereign_repo::{ExactRetriever, ProjectRegistry, RepositoryIntelligence, RepositorySnapshot};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SETTINGS_FORM: &[u8] = include_bytes!("fixtures/scenario1/src/settings/SettingsForm.tsx");
const SETTINGS_FORM_TEST: &[u8] =
    include_bytes!("fixtures/scenario1/src/settings/SettingsForm.test.tsx");
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct FixtureRepo {
    root: PathBuf,
}

impl FixtureRepo {
    fn create() -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "sovereign-eval-compiler-{}-{nanos}-{sequence}",
            std::process::id()
        ));
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
        Self { root }
    }
}

impl Drop for FixtureRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
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

struct PreparedContext {
    packet: ContextPacket,
    snapshot: RepositorySnapshot,
    form_digest: String,
    test_digest: String,
}

struct ExpectedPins<'a> {
    role: &'a Value,
    skills: &'a [Value],
    write_tool: &'a Value,
    diff_evaluator: &'a str,
    rollback_evaluator: &'a str,
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
                    "Compile only a candidate plan. Do not activate plans or authorize tools."
                        .to_owned(),
                task_contract:
                    "Goal source is the user; preserve submit behavior and existing user work."
                        .to_owned(),
                current_state: format!(
                    "repository=repo.app; head={:?}; dirty_digest={}; plan_activation=none; authorized_actions=0",
                    snapshot.head, snapshot.dirty_digest
                ),
                candidates,
                output_schema: "bounded minimal planning proposal v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("build context packet: {error}"));
    PreparedContext {
        packet,
        snapshot,
        form_digest: form.digest,
        test_digest: focused_test.digest,
    }
}

fn fake_backend(packet_tokens: u32) -> DeterministicFakeBackend {
    let proposal = json!({
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
    let response = ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "template".to_owned(),
        content: proposal.to_string(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: u64::from(packet_tokens),
            output_tokens: 128,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    };
    DeterministicFakeBackend::new(
        ModelCapabilities {
            schema_version: MODEL_SCHEMA_VERSION,
            model_id: "fake-m1-planner".to_owned(),
            parameter_class: "fixture".to_owned(),
            quantization: "fixture".to_owned(),
            max_context_tokens: 16_384,
            supports_tools: false,
            supports_json_schema: true,
            local: true,
        },
        vec![response],
    )
    .unwrap_or_else(|error| panic!("create fake backend: {error}"))
}

fn assert_compilation(
    result: &PlanCompilationResult,
    validator: &PlanValidator,
    prepared: &PreparedContext,
    expected: &ExpectedPins<'_>,
) {
    assert!(result.plan_digest().starts_with("sha256:"));
    assert_eq!(result.plan_digest().len(), 71);
    assert!(result.compilation_evidence_digest().starts_with("sha256:"));
    assert_eq!(result.compilation_evidence_digest().len(), 71);
    assert!(result.compilation_evidence().validator_passed());
    assert_eq!(
        result.compilation_evidence().plan_digest(),
        result.plan_digest()
    );
    let exact = result.compilation_evidence().exact_evidence();
    assert!(exact.iter().any(|handle| {
        handle.source_uri == "repo://repo.app/src/settings/SettingsForm.tsx"
            && handle.source_digest == prepared.form_digest
    }));
    assert!(exact.iter().any(|handle| {
        handle.source_uri == "repo://repo.app/src/settings/SettingsForm.test.tsx"
            && handle.source_digest == prepared.test_digest
    }));
    let plan = result.plan().as_value();
    assert_eq!(
        plan["goal"]["statement"],
        "Rename the Settings button from Save to Apply."
    );
    assert_eq!(plan["revision"], 1);
    assert_eq!(plan["tasks"].as_array().map(Vec::len), Some(1));
    let task = &plan["tasks"][0];
    assert_eq!(&task["role"], expected.role);
    assert_eq!(task["skills"], Value::Array(expected.skills.to_vec()));
    assert_eq!(task["tools"], json!([expected.write_tool]));
    assert_eq!(
        task["verification"]["steps"][0]["evaluator"],
        expected.diff_evaluator
    );
    assert_eq!(
        task["rollback"]["verification_steps"][0]["evaluator"],
        expected.rollback_evaluator
    );
    assert!(plan.get("activation").is_none());
    assert!(plan.get("active").is_none());
    assert!(task.get("authorization").is_none());
    assert!(task.get("authorized_actions").is_none());
    assert!(task.get("action_id").is_none());
    assert_eq!(
        result
            .plan()
            .canonical_digest()
            .unwrap_or_else(|error| panic!("digest compiled plan: {error}")),
        result.plan_digest()
    );
    assert!(validator.validate(result.plan()).is_empty());
}

#[test]
fn compiler_vertical_slice_starts_from_natural_language_and_exact_repository_evidence() {
    let fixture = FixtureRepo::create();
    let prepared = prepare_context(&fixture);
    assert_eq!(prepared.packet.budget.max_input_tokens, 8_000);
    assert!(prepared.packet.metrics.final_serialized_input_tokens <= 8_000);
    let backend = fake_backend(prepared.packet.metrics.final_serialized_input_tokens);
    let _lease = backend
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
    let write_tool = capability(
        "tool.patch",
        "1.0.0",
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );
    let read_tool = capability(
        "tool.read",
        "1.0.0",
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let diff_evaluator = "builtin.diff.scope_and_literal.v1";
    let rollback_evaluator = "builtin.diff.controller_patch_absent.v1";
    let input = PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.scenario1".to_owned(),
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
        role: role.clone(),
        skills: skills.clone(),
        tools: vec![write_tool.clone(), read_tool],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: diff_evaluator.to_owned(),
        rollback_diff_evaluator: rollback_evaluator.to_owned(),
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
    let mut model_budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut model_budget)
        .unwrap_or_else(|error| panic!("compile natural-language goal: {error}"));

    assert_eq!(model_budget.remaining_calls(), 0);
    assert_compilation(
        &result,
        &validator,
        &prepared,
        &ExpectedPins {
            role: &role,
            skills: &skills,
            write_tool: &write_tool,
            diff_evaluator,
            rollback_evaluator,
        },
    );
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload fake backend: {error}"));
}
