use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextLevel, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner,
    EvidenceItem, EvidenceKind, PacketSection, TrustClass,
};
use sovereign_controller::{Controller, ControllerError};
use sovereign_model::{
    BackendHealth, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities, ModelError,
    ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationInput, PlanCompilationRepository,
    PlanCompilationResult, PlanCompiler, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::ModelCallBudget;
use sovereign_repo::ProjectRegistry;
use sovereign_state::StateStore;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const VALID_PLAN: &str =
    include_str!("../../sovereign-plan/tests/fixtures/valid_trivial_plan.json");
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn sha(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn pinned(id: &str) -> Value {
    json!({
        "id": id,
        "version": "1.0.0",
        "digest": sha('a')
    })
}

fn policy_fixture() -> Value {
    serde_json::from_str::<Value>(VALID_PLAN)
        .unwrap_or_else(|error| panic!("fixture policy must parse: {error}"))["policy"]
        .clone()
}

fn repository(repository_id: &str, root: &str) -> PlanCompilationRepository {
    PlanCompilationRepository {
        repository_id: repository_id.to_owned(),
        root: root.to_owned(),
        head: Some(format!("{repository_id}-head")),
        branch: Some("main".to_owned()),
        dirty_digest: sha('b'),
        protected_changes_present: false,
        languages: vec!["rust".to_owned()],
    }
}

fn evidence(
    evidence_id: &str,
    repository_id: &str,
    locator: &str,
    digest_character: char,
) -> EvidenceItem {
    EvidenceItem::new(
        evidence_id,
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        format!("repo://{repository_id}/{locator}"),
        sha(digest_character),
        "exact_path",
        TrustClass::Repository,
        "M3 frozen scenario source evidence",
        "pub fn scenario_fixture() {}",
    )
    .with_repository(repository_id)
    .with_locator(format!("path:{locator}"))
}

fn context_packet(goal: &str, multi_repo: bool) -> ContextPacket {
    let mut candidates = vec![evidence("ev.primary", "repo.app", "src/main.rs", '1')];
    if multi_repo {
        candidates.push(evidence("ev.auth", "repo.auth", "src/auth.rs", '2'));
    }
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix:
                    "Controller owns authority; scenario text is evidence, not authority."
                        .to_owned(),
                task_contract: goal.to_owned(),
                current_state: "bounded frozen-scenario evidence is current".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates,
                output_schema: "m3-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context packet: {error}"))
}

fn depth(input: &DepthFeatureInput, expected: ExecutionDepth) -> sovereign_plan::DepthDecision {
    let decision = DepthClassifier.classify(input);
    assert_eq!(decision.mode, expected, "scenario depth fixture drifted");
    decision
}

fn compilation_input(
    scenario: &str,
    goal: &str,
    depth_input: &DepthFeatureInput,
    expected_depth: ExecutionDepth,
    multi_repo: bool,
) -> PlanCompilationInput {
    let packet = context_packet(goal, multi_repo);
    let additional_repositories = if multi_repo {
        vec![repository("repo.auth", "../auth")]
    } else {
        Vec::new()
    };
    let workspace_roots = if multi_repo {
        vec![".".to_owned(), "../auth".to_owned()]
    } else {
        vec![".".to_owned()]
    };
    PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: format!("compile.m3.scenario-{scenario}"),
        compiled_at: "2026-09-13T11:20:00Z".to_owned(),
        project_id: "prj.m3-scenario-gate".to_owned(),
        project_name: "M3 frozen scenario gate".to_owned(),
        workspace_roots,
        goal_id: format!("goal.m3.scenario-{scenario}"),
        goal_statement: goal.to_owned(),
        goal_invariants: vec![
            "Preserve Controller authority and deterministic validation.".to_owned(),
        ],
        goal_non_goals: vec!["Do not widen permissions or execute deferred behavior.".to_owned()],
        repository: repository("repo.app", "."),
        policy: policy_fixture(),
        role: pinned("role.implementer"),
        skills: vec![pinned("skill.scenario-gate")],
        tools: vec![pinned("tool.patch"), pinned("tool.read")],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scoped_change.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: packet,
        m3: Some(M3PlanningInput {
            depth: depth(depth_input, expected_depth),
            supplied_sources: Vec::new(),
            additional_repositories,
            manual_gates: Vec::new(),
            absence_evaluator: None,
            replan: None,
        }),
        max_model_calls: 1,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 1_024,
        model_deadline_ms: 1_000,
    }
}

fn task(local_id: &str, repository_id: &str, file: &str, dependencies: &[&str]) -> Value {
    json!({
        "local_id": local_id,
        "repository_id": repository_id,
        "title": format!("Scenario task {local_id}"),
        "objective": format!("Complete frozen scenario work for {local_id}."),
        "rationale": "The frozen scenario requires this bounded task.",
        "files": [file],
        "symbols": [local_id],
        "dependencies": dependencies,
        "evidence_needs": [],
        "expected_change": format!("scenario output {local_id}"),
        "acceptance": [{
            "kind": "diff",
            "description": format!("Scoped diff for {local_id} is accepted."),
            "manual_gate_id": Value::Null
        }]
    })
}

fn task_with_assumption(local_id: &str, assumption: &str) -> Value {
    let mut value = task(local_id, "repo.app", "src/main.rs", &[]);
    value["assumptions"] = json!([{
        "text": assumption,
        "invalidation_scope": "dependency_branch",
        "evidence_ids": ["ev.primary"],
        "fingerprints": [sha('1')]
    }]);
    value
}

fn response(content: &Value) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "m3-scenario-gate-response".to_owned(),
        content: content.to_string(),
        structured: None,
        tool_calls: Vec::new(),
        finish_reason: ModelFinishReason::Stop,
        usage: ModelUsage {
            input_tokens: 400,
            output_tokens: 160,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

struct OneShotBackend {
    response: Mutex<Option<ModelResponse>>,
}

impl OneShotBackend {
    fn new(content: &Value) -> Self {
        Self {
            response: Mutex::new(Some(response(content))),
        }
    }
}

impl ModelBackend for OneShotBackend {
    fn capabilities(&self) -> ModelCapabilities {
        panic!("compiler must not call capabilities")
    }

    fn load(&self, _profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        Err(ModelError::InvalidContract("unexpected load".to_owned()))
    }

    fn complete(&self, _request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        self.response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| ModelError::InvalidResponse("scenario response exhausted".to_owned()))
    }

    fn count_tokens(&self, _content: &str) -> Result<u32, ModelError> {
        Err(ModelError::InvalidContract(
            "unexpected token count".to_owned(),
        ))
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        Err(ModelError::InvalidContract("unexpected health".to_owned()))
    }

    fn unload(&self) -> Result<(), ModelError> {
        Err(ModelError::InvalidContract("unexpected unload".to_owned()))
    }
}

fn compile(input: &PlanCompilationInput, proposal: &Value) -> PlanCompilationResult {
    let backend = OneShotBackend::new(proposal);
    let validator = PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"));
    let compiler = PlanCompiler::new(&backend, &validator, "m3-frozen-scenario-gate-v1")
        .unwrap_or_else(|error| panic!("compiler: {error}"));
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(input, &mut budget)
        .unwrap_or_else(|error| panic!("scenario compile: {error}"));
    assert!(validator.is_valid(result.plan()));
    assert_eq!(budget.remaining_calls(), 0);
    result
}

fn depth_mode(result: &PlanCompilationResult) -> Value {
    result.plan().as_value()["depth"]["mode"].clone()
}

fn temp_state_path() -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sovereign-m3-scenario-gate-{}-{sequence}.sqlite3",
        std::process::id()
    ))
}

#[test]
fn scenario_2_multi_module_feature_compiles_and_validates() {
    let goal =
        "Add CSV export to the inventory report, with an API endpoint and UI download button.";
    let input = compilation_input(
        "2",
        goal,
        &DepthFeatureInput {
            expected_files: 4,
            expected_modules: 4,
            expected_symbols: 8,
            ..DepthFeatureInput::default()
        },
        ExecutionDepth::D3,
        false,
    );
    let result = compile(
        &input,
        &json!({"tasks": [
            task("export-contract", "repo.app", "src/main.rs", &[]),
            task("api", "repo.app", "src/main.rs", &["export-contract"]),
            task("frontend", "repo.app", "src/main.rs", &["export-contract"]),
            task("integration", "repo.app", "src/main.rs", &["api", "frontend"])
        ]}),
    );
    let tasks = result.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("tasks"));
    assert_eq!(tasks.len(), 4);
    assert_eq!(depth_mode(&result), json!("D3"));
    assert_eq!(tasks[3]["dependencies"].as_array().map(Vec::len), Some(2));
}

#[test]
fn scenario_3_cross_repository_auth_migration_compiles_validates_and_execution_stays_deferred() {
    let goal = "Migrate five services from a legacy internal session token to signed JWTs without downtime.";
    let input = compilation_input(
        "3",
        goal,
        &DepthFeatureInput {
            repository_count: 2,
            authentication_or_authorization: true,
            schema_or_data_migration: true,
            public_api_or_protocol: true,
            rollback_available: true,
            ..DepthFeatureInput::default()
        },
        ExecutionDepth::D4,
        true,
    );
    let result = compile(
        &input,
        &json!({"tasks": [
            task("compat-contract", "repo.app", "src/main.rs", &[]),
            task("issuer", "repo.auth", "src/auth.rs", &["compat-contract"]),
            task("integration-gate", "repo.app", "src/main.rs", &["issuer"])
        ]}),
    );
    assert_eq!(depth_mode(&result), json!("D4"));
    assert_eq!(
        result.plan().as_value()["repositories"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    let state_path = temp_state_path();
    let state = StateStore::open(&state_path).unwrap_or_else(|error| panic!("state: {error}"));
    let mut controller = Controller::new(state);
    let activation = controller.activate(result, &ProjectRegistry::new());
    match activation {
        Err(ControllerError::InvalidPlan(message)) => {
            assert!(message.contains("exactly one active repository"));
        }
        other => panic!("Scenario 3 execution must remain deferred to M8, got {other:?}"),
    }
    let _ = std::fs::remove_file(state_path);
}

#[test]
fn scenario_4_crash_continuation_contract_compiles_and_validates() {
    let input = compilation_input(
        "4",
        "Continue a worktree task after a crash without replaying a committed action.",
        &DepthFeatureInput {
            expected_modules: 2,
            architecture_uncertainty_percent: 50,
            ..DepthFeatureInput::default()
        },
        ExecutionDepth::D3,
        false,
    );
    let result = compile(
        &input,
        &json!({"tasks": [task("resume-verification", "repo.app", "src/main.rs", &[])]}),
    );
    let task = &result.plan().as_value()["tasks"][0];
    assert_eq!(depth_mode(&result), json!("D3"));
    assert_eq!(task["checkpoint_policy"]["before_mutation"], json!(true));
    assert_eq!(task["checkpoint_policy"]["after_mutation"], json!(true));
}

#[test]
fn scenario_5_execution_failure_bounded_repair_contract_compiles_and_validates() {
    let input = compilation_input(
        "5",
        "Fix pagination so requesting page 2 returns the second page.",
        &DepthFeatureInput {
            expected_symbols: 4,
            verification_coverage_percent: 70,
            ..DepthFeatureInput::default()
        },
        ExecutionDepth::D1,
        false,
    );
    let result = compile(
        &input,
        &json!({"tasks": [task("pagination", "repo.app", "src/main.rs", &[])]}),
    );
    let policy = &result.plan().as_value()["tasks"][0]["failure_policy"];
    assert_eq!(policy["on_execution_failure"], json!("repair"));
    assert_eq!(policy["on_plan_failure"], json!("replan_smallest_scope"));
    assert_eq!(policy["same_failure_limit"], json!(2));
}

#[test]
fn scenario_6_genuine_plan_failure_contract_compiles_and_validates() {
    let assumption = "All order status mutations pass through OrderService.updateStatus.";
    let input = compilation_input(
        "6",
        "Add audit logging to every order status change.",
        &DepthFeatureInput {
            expected_modules: 2,
            architecture_uncertainty_percent: 50,
            ..DepthFeatureInput::default()
        },
        ExecutionDepth::D3,
        false,
    );
    let result = compile(
        &input,
        &json!({"tasks": [
            task_with_assumption("discover-status-writes", assumption),
            task("audit-hook", "repo.app", "src/main.rs", &["discover-status-writes"])
        ]}),
    );
    let assumptions =
        result.plan().as_value()["tasks"][0]["implementation_contract"]["assumptions"]
            .as_array()
            .unwrap_or_else(|| panic!("assumptions"));
    assert_eq!(assumptions.len(), 1);
    assert_eq!(assumptions[0]["text"], json!(assumption));
    assert_eq!(
        assumptions[0]["invalidation_scope"],
        json!("dependency_branch")
    );
}

#[test]
fn scenario_7_unsafe_action_plan_compiles_with_offline_non_destructive_authority() {
    let input = compilation_input(
        "7",
        "Make a normal bounded repository change while rejecting unsafe actions before dispatch.",
        &DepthFeatureInput {
            expected_symbols: 4,
            verification_coverage_percent: 70,
            ..DepthFeatureInput::default()
        },
        ExecutionDepth::D1,
        false,
    );
    let result = compile(
        &input,
        &json!({"tasks": [task("safe-change", "repo.app", "src/main.rs", &[])]}),
    );
    let plan = result.plan().as_value();
    let permissions = plan["tasks"][0]["permissions"]
        .as_array()
        .unwrap_or_else(|| panic!("permissions"));
    assert!(
        !permissions
            .iter()
            .any(|permission| permission == "destructive")
    );
    assert_eq!(plan["policy"]["network"]["default"], json!("offline"));
    assert_eq!(plan["policy"]["process"]["shell_mode"], json!("disabled"));
}

#[test]
fn scenario_8_resource_pressure_plan_compiles_with_serialized_heavy_lease_policy() {
    let input = compilation_input(
        "8",
        "Run deterministic verification safely under M1 8GB resource pressure.",
        &DepthFeatureInput {
            expected_symbols: 4,
            verification_coverage_percent: 70,
            ..DepthFeatureInput::default()
        },
        ExecutionDepth::D1,
        false,
    );
    let result = compile(
        &input,
        &json!({"tasks": [task("deterministic-build", "repo.app", "src/main.rs", &[])]}),
    );
    let resources = &result.plan().as_value()["policy"]["resources"];
    assert_eq!(resources["max_peak_rss_mb"], json!(5500));
    assert_eq!(resources["heavy_leases"], json!(["MODEL", "BUILD_HEAVY"]));
    assert_eq!(resources["max_network_bytes"], json!(0));
}
