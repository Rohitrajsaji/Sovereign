use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextLevel, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner,
    EvidenceItem, EvidenceKind, PacketSection, TrustClass,
};
use sovereign_model::{
    BackendHealth, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities, ModelError,
    ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResponse, ModelUsage,
};
use sovereign_plan::{
    DepthClassifier, DepthFeatureInput, ExecutionDepth, GovernedEvaluatorRef, M3PlanningInput,
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationError, PlanCompilationInput,
    PlanCompilationRepository, PlanCompiler, PlanReplanInput, PlanValidator,
    PreauthorizedManualGate, ReplanScope, SuppliedPlanningSourceKind, SuppliedPlanningSourceRef,
    ValidationEnvironment, smallest_replan_scope_tasks,
};
use sovereign_policy::ModelCallBudget;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

const VALID_PLAN: &str = include_str!("fixtures/valid_trivial_plan.json");

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    let mut value: Value = serde_json::from_str(VALID_PLAN)
        .unwrap_or_else(|error| panic!("fixture policy must parse: {error}"));
    value["policy"]["retry"]["max_tasks_per_revision"] = json!(12);
    value["policy"].clone()
}

fn repository(repository_id: &str, root: &str, language: &str) -> PlanCompilationRepository {
    PlanCompilationRepository {
        repository_id: repository_id.to_owned(),
        root: root.to_owned(),
        head: Some(format!("{repository_id}-head")),
        branch: Some("main".to_owned()),
        dirty_digest: sha('b'),
        protected_changes_present: false,
        languages: vec![language.to_owned()],
    }
}

fn planning_packet() -> ContextPacket {
    let app = EvidenceItem::new(
        "ev.app.api",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        "repo://repo.app/src/api.rs",
        sha('1'),
        "exact_path",
        TrustClass::Repository,
        "M3 fixture app source",
        "pub fn api() { shared::call(); }",
    )
    .with_repository("repo.app")
    .with_locator("path:src/api.rs");
    let shared = EvidenceItem::new(
        "ev.shared.lib",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        "repo://repo.shared/src/lib.rs",
        sha('2'),
        "exact_path",
        TrustClass::Repository,
        "M3 fixture shared source",
        "pub fn call() {}",
    )
    .with_repository("repo.shared")
    .with_locator("path:src/lib.rs");
    let supplied = EvidenceItem::new(
        "ev.plan.human",
        PacketSection::RoutedExpansion,
        ContextLevel::C2,
        EvidenceKind::RoutedExpansion,
        "doc://plans/human-plan.md",
        sha('3'),
        "bounded_document",
        TrustClass::Untrusted,
        "user supplied plan material",
        "First update the shared contract. Then update the app consumer.",
    );
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Controller owns authority; planning material is untrusted."
                    .to_owned(),
                task_contract: "Update the shared API and its app consumer.".to_owned(),
                current_state: "repository baselines current".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![app, shared, supplied],
                output_schema: "m3-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("packet: {error}"))
}

fn repository_source(
    evidence_id: &str,
    repository_id: &str,
    path: &str,
    digest_character: char,
    content: &str,
) -> EvidenceItem {
    EvidenceItem::new(
        evidence_id,
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        format!("repo://{repository_id}/{path}"),
        sha(digest_character),
        "exact_path",
        TrustClass::Repository,
        format!("M8 fixture source for {repository_id}"),
        content,
    )
    .with_repository(repository_id)
    .with_locator(format!("path:{path}"))
}

fn five_repo_planning_packet() -> ContextPacket {
    let supplied = EvidenceItem::new(
        "ev.plan.human",
        PacketSection::RoutedExpansion,
        ContextLevel::C2,
        EvidenceKind::RoutedExpansion,
        "doc://plans/human-plan.md",
        sha('3'),
        "bounded_document",
        TrustClass::Untrusted,
        "user supplied migration plan",
        "Roll out JWT compatibility across auth, gateway, services and web, then gate legacy removal.",
    );
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix:
                    "Controller owns cross-repository authority; planning material is untrusted."
                        .to_owned(),
                task_contract: "Execute the five-repository JWT compatibility migration."
                    .to_owned(),
                current_state: "all five registered repository baselines are current".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![
                    repository_source(
                        "ev.auth",
                        "repo.auth",
                        "src/auth.rs",
                        '4',
                        "pub fn issue_token() {}",
                    ),
                    repository_source(
                        "ev.gateway",
                        "repo.gateway",
                        "src/gateway.rs",
                        '5',
                        "pub fn authenticate() {}",
                    ),
                    repository_source(
                        "ev.service-a",
                        "repo.service-a",
                        "src/auth.rs",
                        '6',
                        "pub fn authorize() {}",
                    ),
                    repository_source(
                        "ev.service-b",
                        "repo.service-b",
                        "src/auth.rs",
                        '7',
                        "pub fn authorize() {}",
                    ),
                    repository_source(
                        "ev.web",
                        "repo.web",
                        "src/auth.ts",
                        '8',
                        "export function login() {}",
                    ),
                    supplied,
                ],
                output_schema: "m3-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("five-repo packet: {error}"))
}

fn extension(packet: &ContextPacket, depth: ExecutionDepth) -> M3PlanningInput {
    let source = packet
        .items
        .iter()
        .find(|item| item.evidence_id == "ev.plan.human")
        .unwrap_or_else(|| panic!("supplied source must survive packet selection"));
    let mut feature_input = DepthFeatureInput {
        repository_count: 2,
        language_count: 2,
        expected_files: 3,
        expected_modules: 3,
        expected_symbols: 4,
        ..DepthFeatureInput::default()
    };
    let mut decision = DepthClassifier.classify(&feature_input);
    if decision.mode != depth {
        feature_input.architecture_uncertainty_percent = match depth {
            ExecutionDepth::D0 | ExecutionDepth::D1 => 0,
            ExecutionDepth::D2 => 20,
            ExecutionDepth::D3 => 60,
            ExecutionDepth::D4 => 100,
        };
        decision = DepthClassifier.classify(&feature_input);
        decision.mode = depth;
        decision.reason = format!("fixture-{depth:?}");
    }
    M3PlanningInput {
        depth: decision,
        supplied_sources: vec![SuppliedPlanningSourceRef {
            kind: SuppliedPlanningSourceKind::HumanPlan,
            evidence_id: source.evidence_id.clone(),
            source_digest: source.source_digest.clone(),
            content_digest: source.content_digest.clone(),
        }],
        additional_repositories: vec![repository("repo.shared", "../shared", "rust")],
        manual_gates: vec![PreauthorizedManualGate {
            gate_id: "gate.api-review".to_owned(),
            description: "Human API owner approves the compatibility change.".to_owned(),
        }],
        absence_evaluator: Some(GovernedEvaluatorRef {
            evaluator_id: "absence.zero-hit".to_owned(),
            version: "1.0.0".to_owned(),
            digest: sha('c'),
        }),
        replan: None,
    }
}

fn compilation_input() -> PlanCompilationInput {
    let packet = planning_packet();
    let m3 = extension(&packet, ExecutionDepth::D3);
    PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.m3.fixture".to_owned(),
        compiled_at: "2026-09-13T08:50:00Z".to_owned(),
        project_id: "prj.m3-fixture".to_owned(),
        project_name: "M3 fixture".to_owned(),
        workspace_roots: vec![".".to_owned(), "../shared".to_owned()],
        goal_id: "goal.m3-fixture".to_owned(),
        goal_statement: "Update the shared API and the app consumer safely.".to_owned(),
        goal_invariants: vec![
            "Preserve existing API behavior until consumer migration.".to_owned(),
        ],
        goal_non_goals: vec!["Do not widen network or secret access.".to_owned()],
        repository: repository("repo.app", ".", "rust"),
        policy: policy_fixture(),
        role: pinned("role.implementer"),
        skills: vec![pinned("skill.multi-module")],
        tools: vec![pinned("tool.patch"), pinned("tool.read")],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scoped_change.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: packet,
        m3: Some(m3),
        max_model_calls: 2,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 1_024,
        model_deadline_ms: 1_000,
    }
}

fn five_repo_compilation_input() -> PlanCompilationInput {
    let packet = five_repo_planning_packet();
    let mut m3 = extension(&packet, ExecutionDepth::D4);
    m3.additional_repositories = vec![
        repository("repo.gateway", "../gateway", "rust"),
        repository("repo.service-a", "../service-a", "rust"),
        repository("repo.service-b", "../service-b", "rust"),
        repository("repo.web", "../web", "typescript"),
    ];
    let mut input = compilation_input();
    "compile.m8.cross-repo".clone_into(&mut input.compilation_id);
    "prj.m8-cross-repo".clone_into(&mut input.project_id);
    "M8 cross-repository fixture".clone_into(&mut input.project_name);
    input.workspace_roots = vec![
        ".".to_owned(),
        "../gateway".to_owned(),
        "../service-a".to_owned(),
        "../service-b".to_owned(),
        "../web".to_owned(),
    ];
    "goal.m8-cross-repo".clone_into(&mut input.goal_id);
    "Migrate five repositories from legacy authentication to JWT with a compatibility gate."
        .clone_into(&mut input.goal_statement);
    input.repository = repository("repo.auth", ".", "rust");
    input.context_packet = packet;
    input.m3 = Some(m3);
    input
}

fn task(local_id: &str, repository_id: &str, file: &str, dependencies: &[&str]) -> Value {
    json!({
        "local_id": local_id,
        "repository_id": repository_id,
        "title": format!("Implement {local_id}"),
        "objective": format!("Complete bounded work for {local_id}."),
        "rationale": "The bounded evidence and dependency contract require this cohesive task.",
        "files": [file],
        "symbols": [local_id],
        "dependencies": dependencies,
        "evidence_needs": [],
        "expected_change": format!("Required output for {local_id}"),
        "acceptance": [{
            "kind": "diff",
            "description": format!("Scoped diff for {local_id} is accepted."),
            "manual_gate_id": Value::Null
        }]
    })
}

fn multi_module_proposal() -> String {
    json!({
        "tasks": [
            task("consumer", "repo.app", "src/api.rs", &["shared", "api"]),
            task("shared", "repo.shared", "src/lib.rs", &[]),
            task("api", "repo.app", "src/api.rs", &[])
        ]
    })
    .to_string()
}

fn five_repo_migration_proposal() -> String {
    let mut a2 = task("node.A2", "repo.auth", "src/auth.rs", &["node.A1"]);
    a2["title"] = json!("A2 auth dual issuance");
    let mut a3 = task("node.A3", "repo.gateway", "src/gateway.rs", &["node.A2"]);
    a3["title"] = json!("A3 gateway dual acceptance");
    let mut a4 = task("node.A4", "repo.service-a", "src/auth.rs", &["node.A3"]);
    a4["title"] = json!("A4 service-a dual acceptance");
    let mut a5 = task("node.A5", "repo.service-b", "src/auth.rs", &["node.A3"]);
    a5["title"] = json!("A5 service-b dual acceptance");
    let mut a6 = task("node.A6", "repo.web", "src/auth.ts", &["node.A3"]);
    a6["title"] = json!("A6 web JWT-compatible flow");
    let mut a8 = task("node.A8", "repo.auth", "src/auth.rs", &["node.A7"]);
    a8["title"] = json!("A8 disable legacy issuance");
    let mut a9 = task("node.A9", "repo.auth", "src/auth.rs", &["node.A8"]);
    a9["title"] = json!("A9 remove legacy acceptance");
    json!({
        "tasks": [
            {
                "local_id": "node.A1",
                "repository_id": "repo.auth",
                "title": "A1 JWT compatibility contract",
                "objective": "Pin claims, key rotation, compatibility and rollback invariants.",
                "rationale": "All rollout mutations consume this immutable contract.",
                "files": [],
                "symbols": [],
                "dependencies": [],
                "evidence_needs": [],
                "expected_change": "Signed JWT compatibility contract",
                "acceptance": [{
                    "kind": "artifact",
                    "description": "The compatibility contract artifact is present.",
                    "manual_gate_id": Value::Null
                }]
            },
            a2,
            a3,
            a4,
            a5,
            a6,
            {
                "local_id": "node.A7",
                "repository_id": "repo.auth",
                "integration_repository_ids": [
                    "repo.auth", "repo.gateway", "repo.service-a", "repo.service-b", "repo.web"
                ],
                "title": "A7 cross-repo integration security gate",
                "objective": "Verify mixed-version compatibility across all five repositories.",
                "rationale": "Legacy removal is blocked until every compatible branch is current.",
                "files": [],
                "symbols": [],
                "dependencies": ["node.A4", "node.A5", "node.A6"],
                "evidence_needs": [],
                "expected_change": "Fresh cross-repository integration and security evidence",
                "acceptance": [{
                    "kind": "command",
                    "description": "The bounded integration/security command passes.",
                    "manual_gate_id": Value::Null,
                    "command_spec": {
                        "tool_id": "tool.read",
                        "mode": "exec",
                        "program": "true",
                        "args": [],
                        "repository_id": "repo.auth",
                        "working_dir_relative": ".",
                        "literal_env": {},
                        "secret_env": {},
                        "timeout_seconds": 30,
                        "output_limit_bytes": 4096
                    },
                    "expected_exit_codes": [0]
                }]
            },
            a8,
            a9
        ]
    })
    .to_string()
}

fn response(content: impl Into<String>) -> ModelResponse {
    ModelResponse {
        schema_version: MODEL_SCHEMA_VERSION,
        request_id: "fixture.response".to_owned(),
        content: content.into(),
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

struct RecordingBackend {
    responses: Mutex<VecDeque<ModelResponse>>,
    requests: Mutex<Vec<ModelRequest>>,
    calls: AtomicUsize,
}

impl RecordingBackend {
    fn new(responses: Vec<ModelResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        }
    }
}

impl ModelBackend for RecordingBackend {
    fn capabilities(&self) -> ModelCapabilities {
        panic!("compiler must not call capabilities")
    }

    fn load(&self, _profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        Err(ModelError::InvalidContract("unexpected load".to_owned()))
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        lock(&self.requests).push(request.clone());
        lock(&self.responses).pop_front().ok_or_else(|| {
            ModelError::InvalidResponse("recording backend response queue exhausted".to_owned())
        })
    }

    fn count_tokens(&self, _content: &str) -> Result<u32, ModelError> {
        Err(ModelError::InvalidContract(
            "compiler must not count tokens".to_owned(),
        ))
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        Err(ModelError::InvalidContract(
            "compiler must not call health".to_owned(),
        ))
    }

    fn unload(&self) -> Result<(), ModelError> {
        Err(ModelError::InvalidContract(
            "compiler must not unload".to_owned(),
        ))
    }
}

fn validator() -> PlanValidator {
    PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator: {error}"))
}

fn compiler<'a>(backend: &'a dyn ModelBackend, validator: &'a PlanValidator) -> PlanCompiler<'a> {
    PlanCompiler::new(backend, validator, "m3-canonical-compiler-v1")
        .unwrap_or_else(|error| panic!("compiler: {error}"))
}

#[test]
fn compiler_m3_multimodule_dag_is_topological_and_bindings_are_one_for_one() {
    let backend = RecordingBackend::new(vec![response(multi_module_proposal())]);
    let validator = validator();
    let input = compilation_input();
    let compiler = compiler(&backend, &validator);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let plan = result.plan().as_value();
    let tasks = plan["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("tasks array"));

    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0]["scope"]["repositories"], json!(["repo.app"]));
    assert_eq!(tasks[1]["scope"]["repositories"], json!(["repo.shared"]));
    assert_eq!(tasks[2]["dependencies"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        tasks[2]["dependency_bindings"].as_array().map(Vec::len),
        Some(2)
    );
    for binding in tasks[2]["dependency_bindings"]
        .as_array()
        .into_iter()
        .flatten()
    {
        assert_eq!(
            binding["required_artifact_ids"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            binding["required_acceptance_criterion_ids"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }
    assert_eq!(plan["edges"].as_array().map(Vec::len), Some(2));
    assert!(validator.is_valid(result.plan()));
}

#[test]
fn compiler_m8_five_repo_migration_emits_read_only_integration_scope_and_stable_contracts() {
    let backend = RecordingBackend::new(vec![response(five_repo_migration_proposal())]);
    let validator = validator();
    let input = five_repo_compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile five-repo migration: {error}"));
    let tasks = result.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("five-repo tasks"));

    assert_eq!(tasks.len(), 9);
    assert_eq!(
        tasks
            .iter()
            .map(|task| task["title"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec![
            "A1 JWT compatibility contract",
            "A2 auth dual issuance",
            "A3 gateway dual acceptance",
            "A4 service-a dual acceptance",
            "A5 service-b dual acceptance",
            "A6 web JWT-compatible flow",
            "A7 cross-repo integration security gate",
            "A8 disable legacy issuance",
            "A9 remove legacy acceptance",
        ]
    );
    for task in tasks
        .iter()
        .filter(|task| task["title"] != json!("A7 cross-repo integration security gate"))
    {
        assert_eq!(
            task["scope"]["repositories"].as_array().map(Vec::len),
            Some(1),
            "ordinary task unexpectedly spans repositories: {task:#?}"
        );
    }
    let gate = &tasks[6];
    assert_eq!(
        gate["scope"]["repositories"].as_array().map(Vec::len),
        Some(5)
    );
    assert_eq!(gate["permissions"], json!(["read", "process_exec"]));
    assert_eq!(gate["action_policy"]["write_roots"], json!([]));
    assert_eq!(
        gate["dependency_bindings"].as_array().map(Vec::len),
        Some(3)
    );
    assert!(validator.is_valid(result.plan()));

    let contracts = result
        .cross_repo_contracts()
        .unwrap_or_else(|error| panic!("derive cross-repo contracts: {error}"));
    assert_eq!(contracts.len(), 8, "{contracts:#?}");
    for contract in &contracts {
        contract
            .validate()
            .unwrap_or_else(|error| panic!("validate cross-repo contract: {error}"));
    }
    assert!(
        contracts
            .iter()
            .all(|contract| contract.contract_id.starts_with("binding:"))
    );
    let mut tampered = contracts[0].clone();
    tampered.freshness.push_str("-tampered");
    assert!(tampered.validate().is_err());
    let mut next_revision = result.plan().as_value().clone();
    next_revision["revision"] = json!(2);
    next_revision["supersedes_revision"] = json!(1);
    let next_revision = sovereign_plan::PlanIr::from_value(next_revision);
    let carried = validator
        .cross_repo_contracts(&next_revision)
        .unwrap_or_else(|error| panic!("derive carried contracts: {error}"));
    assert_eq!(contracts, carried);

    let producer_id = tasks[2]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("A3 task id"));
    let before = contracts
        .iter()
        .find(|contract| contract.producer_task_id == producer_id)
        .unwrap_or_else(|| panic!("A3 cross-repo contract"))
        .contract_digest
        .clone();
    let mut changed = result.plan().as_value().clone();
    changed["tasks"][2]["implementation_contract"]["outputs"][0] =
        json!("Changed gateway interface contract");
    let changed = sovereign_plan::PlanIr::from_value(changed);
    let changed_contracts = validator
        .cross_repo_contracts(&changed)
        .unwrap_or_else(|error| panic!("derive changed contracts: {error}"));
    let after = changed_contracts
        .iter()
        .find(|contract| contract.producer_task_id == producer_id)
        .unwrap_or_else(|| panic!("changed A3 cross-repo contract"))
        .contract_digest
        .clone();
    assert_ne!(before, after);
}

#[test]
fn compiler_m3_emits_guarded_cross_revision_freshness_for_machine_acceptance_and_dependencies() {
    let proposal = json!({
        "tasks": [
            task("root", "repo.app", "src/api.rs", &[]),
            task("consumer", "repo.app", "src/api.rs", &["root"])
        ]
    })
    .to_string();
    let backend = RecordingBackend::new(vec![response(proposal)]);
    let validator = validator();
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let tasks = result.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("tasks"));
    for compiled_task in tasks {
        assert!(
            compiled_task["acceptance_criteria"]
                .as_array()
                .unwrap_or_else(|| panic!("acceptance"))
                .iter()
                .all(|criterion| criterion["evidence_freshness"]
                    == json!("carry_forward_if_inputs_unchanged"))
        );
    }
    let consumer = tasks
        .iter()
        .find(|compiled_task| compiled_task["title"] == json!("Implement consumer"))
        .unwrap_or_else(|| panic!("consumer"));
    assert!(
        consumer["dependency_bindings"]
            .as_array()
            .unwrap_or_else(|| panic!("bindings"))
            .iter()
            .all(|binding| binding["freshness"] == json!("carry_forward_if_inputs_unchanged"))
    );
}

#[test]
fn compiler_m3_rejects_multi_file_mutation_and_repairs_to_one_mutable_path_per_task() {
    let mut invalid = json!({
        "tasks": [task("multi", "repo.app", "src/api.rs", &[])]
    });
    invalid["tasks"][0]["create_files"] = json!(["src/generated.rs"]);
    let corrected = json!({
        "tasks": [task("single", "repo.app", "src/api.rs", &[])]
    });
    let backend = RecordingBackend::new(vec![
        response(invalid.to_string()),
        response(corrected.to_string()),
    ]);
    let validator = validator();
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(2, 2_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile after multi-file repair: {error}"));

    assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
    let requests = lock(&backend.requests);
    assert!(
        requests[1].messages.iter().any(|message| {
            message
                .content
                .contains("split multi-file changes into explicit dependent tasks")
        }),
        "repair request did not preserve the deterministic one-mutation-per-task rejection"
    );
    let tasks = result.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("compiled tasks"));
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0]["scope"]["files"], json!(["src/api.rs"]));
    assert_eq!(tasks[0]["scope"]["allow_create"], json!([]));
}

#[test]
fn compiler_m3_preserves_multi_file_read_only_scope_without_repo_write_authority() {
    let mut proposed = task("inspect", "repo.app", "src/api.rs", &[]);
    proposed["files"] = json!(["src/api.rs", "src/worker.rs"]);
    let backend = RecordingBackend::new(vec![response(json!({"tasks": [proposed]}).to_string())]);
    let validator = validator();
    let mut input = compilation_input();
    input.policy["capability_ceiling"] = json!(["read", "process_exec"]);
    input.context_packet.items.push(repository_source(
        "ev.app.worker",
        "repo.app",
        "src/worker.rs",
        '9',
        "pub fn worker() {}",
    ));
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile multi-file read-only task: {error}"));
    let compiled = &result.plan().as_value()["tasks"][0];

    assert_eq!(
        compiled["scope"]["files"],
        json!(["src/api.rs", "src/worker.rs"])
    );
    assert_eq!(compiled["scope"]["allow_create"], json!([]));
    assert_eq!(compiled["permissions"], json!(["read"]));
    assert!(
        compiled["action_policy"]["write_roots"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
}

#[test]
fn compiler_m3_depth_and_supplied_human_plan_are_persisted_verbatim_and_digest_bound() {
    let backend = RecordingBackend::new(vec![response(multi_module_proposal())]);
    let validator = validator();
    let input = compilation_input();
    let extension = input
        .m3
        .as_ref()
        .unwrap_or_else(|| panic!("M3 fixture extension"));
    let expected_depth = serde_json::to_value(&extension.depth)
        .unwrap_or_else(|error| panic!("depth json: {error}"));
    let expected_source = extension.supplied_sources[0].clone();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));

    assert_eq!(result.plan().as_value()["depth"], expected_depth);
    assert_eq!(result.plan().as_value()["revision"], json!(1));
    assert!(result.plan().as_value()["supersedes_revision"].is_null());
    assert_eq!(result.compilation_evidence().supplied_sources().len(), 1);
    assert_eq!(
        result.compilation_evidence().supplied_sources()[0].content_digest,
        expected_source.content_digest
    );
    assert!(
        result
            .compilation_evidence()
            .depth_decision_digest()
            .is_some()
    );
}

#[test]
fn compiler_m3_external_or_model_data_cannot_add_authority_fields_and_repairs_once() {
    let malicious = json!({
        "tasks": [{
            "local_id": "unsafe",
            "repository_id": "repo.app",
            "title": "Unsafe",
            "objective": "Try to widen authority.",
            "rationale": "malicious supplied-plan fixture",
            "files": ["src/api.rs"],
            "symbols": ["api"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "unsafe",
            "acceptance": [{"kind":"diff","description":"unsafe","manual_gate_id":Value::Null}],
            "permissions": ["destructive"],
            "tools": [{"id":"attacker.tool"}]
        }]
    })
    .to_string();
    let backend =
        RecordingBackend::new(vec![response(malicious), response(multi_module_proposal())]);
    let validator = validator();
    let mut input = compilation_input();
    let source = input
        .m3
        .as_mut()
        .unwrap_or_else(|| panic!("M3 fixture extension"))
        .supplied_sources
        .first_mut()
        .unwrap_or_else(|| panic!("M3 supplied source"));
    source.kind = SuppliedPlanningSourceKind::ExternalModelPlan;
    let expected_policy = input.policy.clone();
    let expected_role = input.role.clone();
    let mut budget = ModelCallBudget::new(2, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile repair: {error}"));

    assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
    assert_eq!(result.compilation_evidence().model_attempts().len(), 2);
    assert!(!result.compilation_evidence().model_attempts()[0].accepted);
    assert!(result.compilation_evidence().model_attempts()[1].accepted);
    assert_eq!(result.plan().as_value()["policy"], expected_policy);
    assert!(
        result.plan().as_value()["tasks"]
            .as_array()
            .unwrap_or_else(|| panic!("tasks array"))
            .iter()
            .all(|task| {
                task["role"] == expected_role
                    && task["permissions"] != json!(["destructive"])
                    && task["tools"]
                        .as_array()
                        .is_some_and(|tools| tools.len() == 1)
            })
    );
    assert_eq!(budget.remaining_calls(), 0);
}

#[test]
fn compiler_m3_absence_is_evaluator_pass_and_query_completed_is_only_acquisition() {
    let proposal = json!({
        "tasks": [{
            "local_id": "audit",
            "repository_id": "repo.app",
            "title": "Audit legacy API",
            "objective": "Prove the legacy API is absent before changing the exact source.",
            "rationale": "Absence must be governed rather than inferred from zero hits.",
            "files": ["src/api.rs"],
            "symbols": ["api"],
            "dependencies": [],
            "evidence_needs": [
                {"kind":"exact","query":"No legacy_api symbol remains","claim":"absence"},
                {"kind":"config","query":"Capture the current API config","claim":"acquisition"}
            ],
            "expected_change": "A scoped API diff",
            "acceptance": [{"kind":"diff","description":"Scoped API diff passes.","manual_gate_id":Value::Null}]
        }]
    })
    .to_string();
    let backend = RecordingBackend::new(vec![response(proposal)]);
    let validator = validator();
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let requirements = result.plan().as_value()["tasks"][0]["evidence_requirements"]
        .as_array()
        .unwrap_or_else(|| panic!("requirements"));
    let absence = requirements
        .iter()
        .find(|requirement| requirement["query"] == json!("No legacy_api symbol remains"))
        .unwrap_or_else(|| panic!("absence requirement"));
    let acquisition = requirements
        .iter()
        .find(|requirement| requirement["query"] == json!("Capture the current API config"))
        .unwrap_or_else(|| panic!("acquisition requirement"));

    assert_eq!(absence["satisfaction"], json!("evaluator_pass"));
    assert!(
        absence["evaluator"]
            .as_str()
            .is_some_and(|value| value.starts_with("governed:"))
    );
    assert_eq!(acquisition["satisfaction"], json!("query_completed"));
    assert!(acquisition.get("evaluator").is_none());
}

#[test]
fn compiler_m3_unknown_path_is_evidence_not_executable_scope() {
    let proposal = json!({
        "tasks": [{
            "local_id": "unknown",
            "repository_id": "repo.app",
            "title": "Resolve unknown path",
            "objective": "Resolve a proposed module before mutation.",
            "rationale": "The supplied plan named a path not in bounded evidence.",
            "files": ["src/unknown.rs"],
            "symbols": ["unknown"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "Exact path evidence",
            "acceptance": [{"kind":"artifact","description":"Evidence artifact retained.","manual_gate_id":Value::Null}]
        }]
    })
    .to_string();
    let backend = RecordingBackend::new(vec![response(proposal)]);
    let validator = validator();
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let task = &result.plan().as_value()["tasks"][0];

    assert!(task["scope"]["files"].as_array().is_some_and(Vec::is_empty));
    assert!(
        task["scope"]["allow_create"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(
        task["scope"]["scope_resolution"],
        json!("bounded_discovery")
    );
    assert_eq!(task["permissions"], json!(["read"]));
    assert!(
        task["evidence_requirements"]
            .as_array()
            .is_some_and(|requirements| {
                requirements.iter().any(|requirement| {
                    requirement["query"]
                        .as_str()
                        .is_some_and(|query| query.contains("src/unknown.rs"))
                        && requirement["satisfaction"] == json!("exactly_one")
                })
            })
    );
}

#[test]
fn compiler_m3_explicit_create_is_bounded_scope_with_parent_write_root() {
    let mut proposed = task("create", "repo.app", "src/api.rs", &[]);
    proposed["files"] = json!([]);
    proposed["create_files"] = json!(["src/new_module.rs"]);
    let backend = RecordingBackend::new(vec![response(json!({"tasks": [proposed]}).to_string())]);
    let validator = validator();
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile explicit create: {error}"));
    let compiled = &result.plan().as_value()["tasks"][0];

    assert_eq!(compiled["scope"]["files"], json!([]));
    assert_eq!(
        compiled["scope"]["allow_create"],
        json!(["src/new_module.rs"])
    );
    assert_eq!(compiled["scope"]["scope_resolution"], json!("exact"));
    assert_eq!(
        compiled["permissions"],
        json!(["read", "repo_write", "process_exec"])
    );
    assert!(
        compiled["action_policy"]["write_roots"]
            .as_array()
            .is_some_and(|roots| roots.iter().any(|root| {
                root["repository_id"] == json!("repo.app") && root["path"] == json!("src")
            }))
    );
}

#[test]
fn compiler_m3_create_cannot_overlap_update_or_claim_known_path() {
    let validator = validator();

    let mut overlap = task("overlap", "repo.app", "src/api.rs", &[]);
    overlap["create_files"] = json!(["src/api.rs"]);
    let backend = RecordingBackend::new(vec![response(json!({"tasks": [overlap]}).to_string())]);
    let mut input = compilation_input();
    input.max_model_calls = 1;
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&backend, &validator).compile(&input, &mut budget),
        Err(PlanCompilationError::ProposalRejected { .. })
    ));

    let mut known_create = task("known-create", "repo.app", "src/api.rs", &[]);
    known_create["files"] = json!([]);
    known_create["create_files"] = json!(["src/api.rs"]);
    let backend =
        RecordingBackend::new(vec![response(json!({"tasks": [known_create]}).to_string())]);
    let mut input = compilation_input();
    input.max_model_calls = 1;
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&backend, &validator).compile(&input, &mut budget),
        Err(PlanCompilationError::InvalidInput(message))
            if message.contains("create authority for a path already present")
    ));
}

#[test]
fn compiler_m3_invalid_create_path_fails_closed() {
    let mut proposed = task("escape", "repo.app", "src/api.rs", &[]);
    proposed["files"] = json!([]);
    proposed["create_files"] = json!(["../escape.rs"]);
    let backend = RecordingBackend::new(vec![response(json!({"tasks": [proposed]}).to_string())]);
    let validator = validator();
    let mut input = compilation_input();
    input.max_model_calls = 1;
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&backend, &validator).compile(&input, &mut budget),
        Err(PlanCompilationError::ProposalRejected { .. })
    ));
}

#[test]
fn compiler_m3_command_only_task_gets_process_exec_without_repo_write() {
    let mut proposed = task("command-only", "repo.app", "src/api.rs", &[]);
    proposed["files"] = json!([]);
    proposed["acceptance"] = json!([{
        "kind": "command",
        "description": "Run the bounded Rust test suite.",
        "manual_gate_id": Value::Null,
        "command_spec": {
            "tool_id": "tool.process",
            "mode": "exec",
            "program": "cargo",
            "args": ["test", "-p", "fixture"],
            "repository_id": "repo.app",
            "working_dir_relative": ".",
            "literal_env": {},
            "secret_env": {},
            "timeout_seconds": 180,
            "output_limit_bytes": 1_048_576
        },
        "expected_exit_codes": [0]
    }]);
    let backend = RecordingBackend::new(vec![response(json!({"tasks": [proposed]}).to_string())]);
    let validator = validator();
    let mut input = compilation_input();
    input.tools.push(pinned("tool.process"));
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile command-only acceptance: {error}"));
    let compiled = &result.plan().as_value()["tasks"][0];

    assert_eq!(compiled["scope"]["files"], json!([]));
    assert_eq!(compiled["scope"]["allow_create"], json!([]));
    assert_eq!(compiled["permissions"], json!(["read", "process_exec"]));
    assert!(
        compiled["resource_budget"]["heavy_leases"]
            .as_array()
            .is_some_and(|leases| leases.iter().any(|lease| lease == "BUILD_HEAVY"))
    );
    assert!(
        compiled["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["id"] == json!("tool.process")))
    );
}

#[test]
fn compiler_m3_command_acceptance_requires_global_build_heavy_authority() {
    let mut proposed = task("command-heavy", "repo.app", "src/api.rs", &[]);
    proposed["files"] = json!([]);
    proposed["acceptance"] = json!([{
        "kind": "command",
        "description": "Run the bounded Rust test suite.",
        "manual_gate_id": Value::Null,
        "command_spec": {
            "tool_id": "tool.process",
            "mode": "exec",
            "program": "cargo",
            "args": ["test", "-p", "fixture"],
            "repository_id": "repo.app",
            "working_dir_relative": ".",
            "literal_env": {},
            "secret_env": {},
            "timeout_seconds": 180,
            "output_limit_bytes": 1_048_576
        },
        "expected_exit_codes": [0]
    }]);
    let backend = RecordingBackend::new(vec![response(json!({"tasks": [proposed]}).to_string())]);
    let validator = validator();
    let mut input = compilation_input();
    input.tools.push(pinned("tool.process"));
    input.policy["resources"]["heavy_leases"] = json!(["MODEL"]);
    let mut budget = ModelCallBudget::new(1, 1_000);

    assert!(matches!(
        compiler(&backend, &validator).compile(&input, &mut budget),
        Err(PlanCompilationError::InvalidInput(message))
            if message.contains("without global BUILD_HEAVY resource authority")
    ));
}

#[test]
fn compiler_m3_command_acceptance_emits_frozen_command_spec_and_task_tool() {
    let mut proposed = task("command", "repo.app", "src/api.rs", &[]);
    proposed["acceptance"] = json!([{
        "kind": "command",
        "description": "Run the bounded Rust test suite.",
        "manual_gate_id": Value::Null,
        "command_spec": {
            "tool_id": "tool.process",
            "mode": "exec",
            "program": "cargo",
            "args": ["test", "-p", "fixture"],
            "repository_id": "repo.app",
            "working_dir_relative": ".",
            "literal_env": {},
            "secret_env": {},
            "timeout_seconds": 180,
            "output_limit_bytes": 1_048_576
        },
        "expected_exit_codes": [0]
    }]);
    let backend = RecordingBackend::new(vec![response(json!({"tasks": [proposed]}).to_string())]);
    let validator = validator();
    let mut input = compilation_input();
    input.tools.push(pinned("tool.process"));
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile command acceptance: {error}"));
    let compiled = &result.plan().as_value()["tasks"][0];
    let step = &compiled["verification"]["steps"][0];

    assert_eq!(step["kind"], json!("command"));
    assert_eq!(step["command_spec"]["tool_id"], json!("tool.process"));
    assert_eq!(step["command_spec"]["program"], json!("cargo"));
    assert_eq!(step["command_spec"]["working_dir_relative"], json!("."));
    assert_eq!(step["expected_exit_codes"], json!([0]));
    assert!(
        compiled["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["id"] == json!("tool.process")))
    );
}

#[test]
fn compiler_m3_depth_and_policy_caps_fail_closed_without_hidden_calls() {
    let two_tasks = json!({
        "tasks": [
            task("one", "repo.app", "src/api.rs", &[]),
            task("two", "repo.app", "src/api.rs", &["one"])
        ]
    })
    .to_string();
    let backend = RecordingBackend::new(vec![response(two_tasks)]);
    let validator = validator();
    let mut input = compilation_input();
    let d1 = DepthClassifier.classify(&DepthFeatureInput {
        repository_count: 2,
        ..DepthFeatureInput::default()
    });
    assert_eq!(d1.mode, ExecutionDepth::D1);
    input
        .m3
        .as_mut()
        .unwrap_or_else(|| panic!("M3 fixture extension"))
        .depth = d1;
    input.max_model_calls = 1;
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&backend, &validator).compile(&input, &mut budget),
        Err(PlanCompilationError::ProposalRejected { attempts: 1, .. })
    ));
    assert_eq!(backend.calls.load(Ordering::Relaxed), 1);

    let mut policy_input = compilation_input();
    policy_input.policy["retry"]["max_tasks_per_revision"] = json!(2);
    policy_input.max_model_calls = 1;
    let backend = RecordingBackend::new(vec![response(multi_module_proposal())]);
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&backend, &validator).compile(&policy_input, &mut budget),
        Err(PlanCompilationError::ProposalRejected { attempts: 1, .. })
    ));
}

#[test]
fn compiler_m3_validator_invalid_candidate_gets_only_one_bounded_repair() {
    let diff = json!({
        "tasks": [task("api", "repo.app", "src/api.rs", &[])]
    })
    .to_string();
    let artifact = json!({
        "tasks": [{
            "local_id": "api",
            "repository_id": "repo.app",
            "title": "Implement api",
            "objective": "Complete bounded API work.",
            "rationale": "Use a machine-checkable required artifact after validator feedback.",
            "files": ["src/api.rs"],
            "symbols": ["api"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "Required API output",
            "acceptance": [{
                "kind": "artifact",
                "description": "Required artifact is retained.",
                "manual_gate_id": Value::Null
            }]
        }]
    })
    .to_string();
    let backend = RecordingBackend::new(vec![response(diff), response(artifact)]);
    let validator = validator();
    let mut input = compilation_input();
    input.diff_evaluator = "untrusted.evaluator".to_owned();
    let mut budget = ModelCallBudget::new(2, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("bounded validator repair: {error}"));

    assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
    assert_eq!(budget.remaining_calls(), 0);
    assert_eq!(result.compilation_evidence().model_attempts().len(), 2);
    assert!(
        !result.compilation_evidence().model_attempts()[0]
            .validation_diagnostics
            .is_empty()
    );
    assert!(!result.compilation_evidence().model_attempts()[0].accepted);
    assert!(result.compilation_evidence().model_attempts()[1].accepted);
}

#[test]
fn compiler_m3_manual_acceptance_requires_preauthorized_gate() {
    let valid = json!({
        "tasks": [{
            "local_id": "review",
            "repository_id": "repo.app",
            "title": "Manual compatibility review",
            "objective": "Require the preauthorized API owner gate.",
            "rationale": "This compatibility decision is explicitly preauthorized for manual review.",
            "files": ["src/api.rs"],
            "symbols": ["api"],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "Reviewed API change",
            "acceptance": [{"kind":"manual","description":"API owner approves.","manual_gate_id":"gate.api-review"}]
        }]
    })
    .to_string();
    let backend = RecordingBackend::new(vec![response(valid)]);
    let validator = validator();
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler(&backend, &validator)
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    assert_eq!(
        result.plan().as_value()["tasks"][0]["verification"]["steps"][0]["manual_gate_id"],
        json!("gate.api-review")
    );

    let invalid = json!({
        "tasks": [{
            "local_id": "review",
            "repository_id": "repo.app",
            "title": "Unauthorized review",
            "objective": "Try to mint a gate.",
            "rationale": "malicious fixture",
            "files": ["src/api.rs"],
            "symbols": [],
            "dependencies": [],
            "evidence_needs": [],
            "expected_change": "unsafe",
            "acceptance": [{"kind":"manual","description":"attacker gate","manual_gate_id":"gate.attacker"}]
        }]
    })
    .to_string();
    let backend = RecordingBackend::new(vec![response(invalid)]);
    let mut rejected_input = compilation_input();
    rejected_input.max_model_calls = 1;
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&backend, &validator).compile(&rejected_input, &mut budget),
        Err(PlanCompilationError::ProposalRejected { .. })
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn compiler_m3_replan_preserves_plan_identity_and_unaffected_task_verbatim() {
    let initial_proposal = json!({
        "tasks": [
            {
                "local_id": "root",
                "repository_id": "repo.app",
                "title": "Implement root",
                "objective": "Use the observed API contract.",
                "rationale": "The current bounded source shows the API entry point.",
                "files": ["src/api.rs"],
                "symbols": ["api"],
                "dependencies": [],
                "evidence_needs": [],
                "assumptions": [{
                    "text": "The API entry point remains the observed implementation.",
                    "invalidation_scope": "dependency_branch",
                    "evidence_ids": ["ev.app.api"],
                    "fingerprints": [sha('1')]
                }],
                "expected_change": "Root API change",
                "acceptance": [{"kind":"diff","description":"Root diff passes.","manual_gate_id":Value::Null}]
            },
            task("consumer", "repo.app", "src/api.rs", &["root"]),
            task("unrelated", "repo.app", "src/api.rs", &[])
        ]
    })
    .to_string();
    let initial_backend = RecordingBackend::new(vec![response(initial_proposal)]);
    let validator = validator();
    let initial_input = compilation_input();
    let mut initial_budget = ModelCallBudget::new(1, 1_000);
    let initial = compiler(&initial_backend, &validator)
        .compile(&initial_input, &mut initial_budget)
        .unwrap_or_else(|error| panic!("initial compile: {error}"));
    let previous = initial.plan().as_value().clone();
    let previous_digest = initial.plan_digest().to_owned();
    let previous_tasks = previous["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("initial tasks"));
    let root = previous_tasks
        .iter()
        .find(|task| task["title"] == json!("Implement root"))
        .unwrap_or_else(|| panic!("root task"));
    assert_eq!(
        root["implementation_contract"]["assumptions"][0]["basis_evidence"][0]["trust"],
        json!("untrusted")
    );
    let root_id = root["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("root id"))
        .to_owned();
    let assumption_id = root["implementation_contract"]["assumptions"][0]["assumption_id"]
        .as_str()
        .unwrap_or_else(|| panic!("assumption id"))
        .to_owned();
    let affected = smallest_replan_scope_tasks(&previous, &root_id, ReplanScope::DependencyBranch)
        .unwrap_or_else(|error| panic!("affected: {error}"));
    let consumer_id = affected
        .iter()
        .find(|task_id| *task_id != &root_id)
        .unwrap_or_else(|| panic!("consumer id"))
        .clone();
    let unrelated_before = previous_tasks
        .iter()
        .find(|task| task["title"] == json!("Implement unrelated"))
        .unwrap_or_else(|| panic!("unrelated task"))
        .clone();

    let replan_proposal = json!({
        "tasks": [
            {
                "local_id": root_id,
                "repository_id": "repo.app",
                "title": "Implement corrected root",
                "objective": "Use the corrected API topology.",
                "rationale": "Fresh exact evidence falsified the prior API assumption.",
                "files": ["src/api.rs"],
                "symbols": ["api"],
                "dependencies": [],
                "evidence_needs": [],
                "expected_change": "Corrected root API change",
                "acceptance": [{"kind":"diff","description":"Corrected root diff passes.","manual_gate_id":Value::Null}]
            },
            {
                "local_id": consumer_id,
                "repository_id": "repo.app",
                "title": "Implement corrected consumer",
                "objective": "Consume the corrected root contract.",
                "rationale": "The producer contract changed.",
                "files": ["src/api.rs"],
                "symbols": ["consumer"],
                "dependencies": [root_id],
                "evidence_needs": [],
                "expected_change": "Corrected consumer change",
                "acceptance": [{"kind":"diff","description":"Corrected consumer diff passes.","manual_gate_id":Value::Null}]
            }
        ]
    })
    .to_string();
    let replan_backend = RecordingBackend::new(vec![response(replan_proposal)]);
    let mut replan_input = compilation_input();
    replan_input.compilation_id = "compile.m3.replan".to_owned();
    replan_input
        .m3
        .as_mut()
        .unwrap_or_else(|| panic!("M3 extension"))
        .replan = Some(PlanReplanInput {
        previous_plan: previous.clone(),
        previous_plan_digest: previous_digest,
        scope: ReplanScope::DependencyBranch,
        invalidated_contract_ids: vec![assumption_id],
        affected_task_ids: affected,
    });

    let mut swapped_root = replan_input.clone();
    swapped_root
        .m3
        .as_mut()
        .unwrap_or_else(|| panic!("M3 extension"))
        .additional_repositories[0]
        .root = "../shared-swapped".to_owned();
    let mut invalid_budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&replan_backend, &validator).compile(&swapped_root, &mut invalid_budget),
        Err(PlanCompilationError::InvalidInput(message))
            if message.contains("repository identity/root set")
    ));

    let mut unknown_repository = replan_input.clone();
    unknown_repository
        .m3
        .as_mut()
        .unwrap_or_else(|| panic!("M3 extension"))
        .additional_repositories[0]
        .repository_id = "repo.unknown".to_owned();
    let mut invalid_budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler(&replan_backend, &validator)
            .compile(&unknown_repository, &mut invalid_budget),
        Err(PlanCompilationError::InvalidInput(message))
            if message.contains("repository identity/root set")
    ));

    let mut replan_budget = ModelCallBudget::new(1, 1_000);
    let revised = compiler(&replan_backend, &validator)
        .compile(&replan_input, &mut replan_budget)
        .unwrap_or_else(|error| panic!("replan compile: {error}"));
    let revised_plan = revised.plan().as_value();

    assert_eq!(revised_plan["plan_id"], previous["plan_id"]);
    assert_eq!(revised_plan["revision"], json!(2));
    assert_eq!(revised_plan["supersedes_revision"], json!(1));
    let unrelated_after = revised_plan["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("revised tasks"))
        .iter()
        .find(|task| task["task_id"] == unrelated_before["task_id"])
        .unwrap_or_else(|| panic!("carried unrelated task"));
    assert_eq!(unrelated_after, &unrelated_before);
}
