use serde_json::{Value, json};
use sovereign_context::{
    ContextBudget, ContextLevel, ContextMode, ContextPacket, ContextPacketInput, ContextPlanner,
    EvidenceItem, EvidenceKind, PacketSection, TrustClass,
};
use sovereign_model::{
    BackendHealth, DeterministicFakeBackend, MODEL_SCHEMA_VERSION, ModelBackend, ModelCapabilities,
    ModelError, ModelFinishReason, ModelLease, ModelLoadProfile, ModelRequest, ModelResponse,
    ModelUsage,
};
use sovereign_plan::{
    PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationError, PlanCompilationInput,
    PlanCompilationRepository, PlanCompiler, PlanValidator, ValidationEnvironment,
};
use sovereign_policy::{ModelCallBudget, SecretInjection, SecretProviderKind, SecretRef};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

const VALID_PLAN: &str = include_str!("fixtures/valid_trivial_plan.json");

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn policy_fixture() -> Value {
    let value: Value = serde_json::from_str(VALID_PLAN)
        .unwrap_or_else(|error| panic!("fixture policy must parse: {error}"));
    value["policy"].clone()
}

fn focused_packet() -> ContextPacket {
    let source = EvidenceItem::new(
        "ev.settings.form",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        "repo://repo.app/src/settings/SettingsForm.tsx",
        "sha256:settings-form-current",
        "exact_path",
        TrustClass::Repository,
        "goal names SettingsForm",
        "export function SettingsForm() { return <button>Save</button>; }",
    )
    .with_repository("repo.app")
    .with_locator("path:src/settings/SettingsForm.tsx");
    let test = EvidenceItem::new(
        "ev.settings.test",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::SourceSlice,
        "repo://repo.app/src/settings/SettingsForm.test.tsx",
        "sha256:settings-test-current",
        "exact_path",
        TrustClass::Repository,
        "focused test",
        "test('renders Save', () => { /* focused assertion */ });",
    )
    .with_repository("repo.app")
    .with_locator("path:src/settings/SettingsForm.test.tsx");
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Propose only; Controller owns authority.".to_owned(),
                task_contract: "Rename SettingsForm button Save to Apply without behavior changes."
                    .to_owned(),
                current_state: "attempt=0; repository baseline is current".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![source, test],
                output_schema: "minimal-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("context packet must build: {error}"))
}

fn pinned(id: &str) -> Value {
    json!({
        "id": id,
        "version": "1.0.0",
        "digest": format!("sha256:{:0<48}", id.replace('.', "-"))
    })
}

fn compilation_input() -> PlanCompilationInput {
    PlanCompilationInput {
        schema_version: PLAN_COMPILATION_SCHEMA_VERSION,
        compilation_id: "compile.settings-label".to_owned(),
        compiled_at: "2026-09-12T18:30:00Z".to_owned(),
        project_id: "prj.fixture".to_owned(),
        project_name: "Fixture project".to_owned(),
        workspace_roots: vec![".".to_owned()],
        goal_id: "goal.settings-label".to_owned(),
        goal_statement: "Rename the Settings button from Save to Apply.".to_owned(),
        goal_invariants: vec!["Do not alter submit behavior.".to_owned()],
        goal_non_goals: vec!["Do not redesign Settings UI.".to_owned()],
        repository: PlanCompilationRepository {
            repository_id: "repo.app".to_owned(),
            root: ".".to_owned(),
            head: Some("fixture-head".to_owned()),
            branch: Some("main".to_owned()),
            dirty_digest: "sha256:fixture-dirty".to_owned(),
            protected_changes_present: false,
            languages: vec!["typescript".to_owned()],
        },
        policy: policy_fixture(),
        role: pinned("role.implementer"),
        skills: vec![pinned("skill.focused-edit")],
        tools: vec![pinned("tool.patch"), pinned("tool.read")],
        write_tool_id: "tool.patch".to_owned(),
        read_tool_id: "tool.read".to_owned(),
        diff_evaluator: "builtin.diff.scoped_change.v1".to_owned(),
        rollback_diff_evaluator: "builtin.diff.controller_patch_absent.v1".to_owned(),
        context_packet: focused_packet(),
        m3: None,
        max_model_calls: 2,
        model_input_token_ceiling: 8_000,
        max_output_tokens: 512,
        model_deadline_ms: 1_000,
    }
}

fn secret_ref() -> SecretRef {
    SecretRef {
        secret_ref_id: "secret.settings-api".to_owned(),
        provider: SecretProviderKind::MacosKeychain,
        purpose: "Authenticate the exact settings API verification command.".to_owned(),
        injection: SecretInjection::TemporaryFile,
        target: "settings-api-token".to_owned(),
    }
}

fn enable_secret_use(input: &mut PlanCompilationInput) {
    input.policy["capability_ceiling"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("capability ceiling must be an array"))
        .push(json!("secret_use"));
}

fn one_task_proposal() -> String {
    json!({
        "tasks": [{
            "title": "Rename Settings submit label",
            "objective": "Change Save to Apply in the exact SettingsForm source.",
            "rationale": "The bounded source and focused test identify the requested component.",
            "files": ["src/settings/SettingsForm.tsx", "src/settings/SettingsForm.test.tsx"],
            "symbols": ["SettingsForm"],
            "evidence_queries": [],
            "expected_change": "A Controller-owned patch changes only the label."
        }]
    })
    .to_string()
}

fn two_task_proposal(with_evidence: bool) -> String {
    json!({
        "tasks": [
            {
                "title": "Confirm exact label scope",
                "objective": "Confirm the bounded SettingsForm label evidence before the edit.",
                "rationale": "A focused evidence check is required before the dependent edit.",
                "files": ["src/settings/SettingsForm.tsx"],
                "symbols": ["SettingsForm"],
                "evidence_queries": if with_evidence { vec!["Confirm the current Save label in SettingsForm"] } else { Vec::<&str>::new() },
                "expected_change": "Retained exact scope evidence."
            },
            {
                "title": "Apply the scoped label edit",
                "objective": "Change Save to Apply after the evidence dependency is satisfied.",
                "rationale": "Keep the implementation linear and bounded.",
                "files": ["src/settings/SettingsForm.tsx"],
                "symbols": ["SettingsForm"],
                "evidence_queries": [],
                "expected_change": "A Controller-owned patch changes only the label."
            }
        ]
    })
    .to_string()
}

fn unknown_path_proposal() -> String {
    json!({
        "tasks": [{
            "title": "Resolve unknown settings module",
            "objective": "Locate the proposed settings module before any mutation.",
            "rationale": "The proposed path is not present in bounded current evidence.",
            "files": ["src/settings/UnknownSettings.tsx"],
            "symbols": ["UnknownSettings"],
            "evidence_queries": [],
            "expected_change": "Exact evidence proving the current path and scope."
        }]
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
            input_tokens: 321,
            output_tokens: 64,
        },
        elapsed_ms: 1,
        peak_rss_kb_during_call: None,
    }
}

struct RecordingBackend {
    responses: Mutex<VecDeque<ModelResponse>>,
    requests: Mutex<Vec<ModelRequest>>,
    complete_calls: AtomicUsize,
    forbidden_calls: AtomicUsize,
}

impl RecordingBackend {
    fn new(responses: Vec<ModelResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            complete_calls: AtomicUsize::new(0),
            forbidden_calls: AtomicUsize::new(0),
        }
    }

    fn complete_calls(&self) -> usize {
        self.complete_calls.load(Ordering::Relaxed)
    }
}

impl ModelBackend for RecordingBackend {
    fn capabilities(&self) -> ModelCapabilities {
        self.forbidden_calls.fetch_add(1, Ordering::Relaxed);
        fake_capabilities()
    }

    fn load(&self, _profile: ModelLoadProfile) -> Result<ModelLease, ModelError> {
        self.forbidden_calls.fetch_add(1, Ordering::Relaxed);
        Err(ModelError::InvalidContract("unexpected load".to_owned()))
    }

    fn complete(&self, request: &ModelRequest) -> Result<ModelResponse, ModelError> {
        self.complete_calls.fetch_add(1, Ordering::Relaxed);
        lock(&self.requests).push(request.clone());
        lock(&self.responses).pop_front().ok_or_else(|| {
            ModelError::InvalidResponse("recording backend response queue exhausted".to_owned())
        })
    }

    fn count_tokens(&self, _content: &str) -> Result<u32, ModelError> {
        self.forbidden_calls.fetch_add(1, Ordering::Relaxed);
        Err(ModelError::InvalidContract(
            "unexpected count_tokens".to_owned(),
        ))
    }

    fn health(&self) -> Result<BackendHealth, ModelError> {
        self.forbidden_calls.fetch_add(1, Ordering::Relaxed);
        Err(ModelError::InvalidContract("unexpected health".to_owned()))
    }

    fn unload(&self) -> Result<(), ModelError> {
        self.forbidden_calls.fetch_add(1, Ordering::Relaxed);
        Err(ModelError::InvalidContract("unexpected unload".to_owned()))
    }
}

fn fake_capabilities() -> ModelCapabilities {
    ModelCapabilities {
        schema_version: MODEL_SCHEMA_VERSION,
        model_id: "fake-plan-model".to_owned(),
        parameter_class: "4b".to_owned(),
        quantization: "q4".to_owned(),
        max_context_tokens: 16_384,
        supports_tools: true,
        supports_json_schema: true,
        local: true,
    }
}

fn validator() -> PlanValidator {
    PlanValidator::new(ValidationEnvironment::default())
        .unwrap_or_else(|error| panic!("validator must build: {error}"))
}

fn compiler<'a>(backend: &'a dyn ModelBackend, validator: &'a PlanValidator) -> PlanCompiler<'a> {
    PlanCompiler::new(backend, validator, "m1-minimal-compiler-v1")
        .unwrap_or_else(|error| panic!("compiler must build: {error}"))
}

#[test]
fn minimal_compiler_simple_edit_is_one_valid_bounded_task_and_calls_only_complete() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));

    assert_eq!(
        result.plan().as_value()["tasks"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        result.plan().as_value()["tasks"][0]["objective"],
        json!(input.goal_statement)
    );
    assert!(
        result.plan().as_value()["tasks"][0]["implementation_contract"]["outputs"]
            .as_array()
            .is_some_and(|outputs| outputs
                .iter()
                .any(|value| value == &json!(input.goal_statement)))
    );
    assert_eq!(
        result.plan().as_value()["tasks"][0]["resource_budget"]["heavy_leases"],
        input.policy["resources"]["heavy_leases"],
        "compiler task budgets must preserve the caller-authorized heavy-lease set rather than silently stripping later deterministic phases"
    );
    assert!(validator.is_valid(result.plan()));
    assert_eq!(backend.complete_calls(), 1);
    assert_eq!(backend.forbidden_calls.load(Ordering::Relaxed), 0);
    assert_eq!(budget.remaining_calls(), 0);
    assert!(result.compilation_evidence().validator_passed());
    assert_eq!(
        result.compilation_evidence().plan_digest(),
        result.plan_digest()
    );
}

#[test]
fn controller_secret_binding_targets_one_task_and_recomputes_provenance() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_secret_use(&mut input);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let target_task_id = source.plan().as_value()["tasks"][0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("compiled task id"))
        .to_owned();
    let source_plan_digest = source.plan_digest().to_owned();
    let source_evidence_digest = source.compilation_evidence_digest().to_owned();
    let secret_ref = secret_ref();

    let bound = source
        .bind_controller_secret_ref(&validator, &target_task_id, &secret_ref)
        .unwrap_or_else(|error| panic!("bind Controller secret: {error}"));
    let task = &bound.plan().as_value()["tasks"][0];

    assert_eq!(bound.plan().as_value()["ir_version"], json!("1.2"));
    assert!(
        task["permissions"]
            .as_array()
            .is_some_and(|permissions| permissions.contains(&json!("secret_use")))
    );
    assert_eq!(
        task["action_policy"]["secret_refs"],
        json!([{
            "secret_ref_id": "secret.settings-api",
            "provider": "macos_keychain",
            "purpose": "Authenticate the exact settings API verification command.",
            "injection": "temporary_file",
            "target": "settings-api-token"
        }])
    );
    assert!(validator.is_valid(bound.plan()));
    assert_ne!(bound.plan_digest(), source_plan_digest);
    assert_ne!(bound.compilation_evidence_digest(), source_evidence_digest);
    assert_eq!(
        bound.compilation_evidence().plan_digest(),
        bound.plan_digest()
    );
    let bindings = bound.compilation_evidence().controller_bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].source_plan_digest(), source_plan_digest);
    assert_eq!(bindings[0].target_task_id(), target_task_id);
    assert!(bindings[0].secret_ref_digest().starts_with("sha256:"));
}

#[test]
fn controller_secret_binding_requires_global_secret_use_ceiling() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let target_task_id = source.plan().as_value()["tasks"][0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("compiled task id"));

    assert!(matches!(
        source.bind_controller_secret_ref(&validator, target_task_id, &secret_ref()),
        Err(PlanCompilationError::ControllerBindingRejected(message))
            if message.contains("global policy capability ceiling")
    ));
}

#[test]
fn controller_secret_binding_rejects_unknown_task() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_secret_use(&mut input);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));

    assert!(matches!(
        source.bind_controller_secret_ref(&validator, "task.missing", &secret_ref()),
        Err(PlanCompilationError::ControllerBindingRejected(message))
            if message.contains("must exist exactly once")
    ));
}

#[test]
fn controller_secret_binding_rejects_preexisting_secret_authority() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_secret_use(&mut input);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let target_task_id = source.plan().as_value()["tasks"][0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("compiled task id"))
        .to_owned();
    let bound = source
        .bind_controller_secret_ref(&validator, &target_task_id, &secret_ref())
        .unwrap_or_else(|error| panic!("first binding: {error}"));

    assert!(matches!(
        bound.bind_controller_secret_ref(&validator, &target_task_id, &secret_ref()),
        Err(PlanCompilationError::ControllerBindingRejected(message))
            if message.contains("already contains a Controller authority binding")
    ));
}

#[test]
fn controller_secret_binding_leaves_sibling_task_unchanged() {
    let backend = RecordingBackend::new(vec![response(two_task_proposal(true))]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_secret_use(&mut input);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let tasks = source.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("tasks array"));
    let sibling_before = tasks[0].clone();
    let target_task_id = tasks[1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("target task id"))
        .to_owned();

    let bound = source
        .bind_controller_secret_ref(&validator, &target_task_id, &secret_ref())
        .unwrap_or_else(|error| panic!("bind Controller secret: {error}"));
    let bound_tasks = bound.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("bound tasks array"));

    assert_eq!(bound_tasks[0], sibling_before);
    assert_eq!(
        serde_json::to_vec(&bound_tasks[0]).unwrap_or_default(),
        serde_json::to_vec(&sibling_before).unwrap_or_default()
    );
    assert_eq!(bound_tasks[1]["task_id"], json!(target_task_id));
    assert!(validator.is_valid(bound.plan()));
}

#[test]
fn minimal_compiler_rejects_unknown_authorized_heavy_lease_class() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    input.policy["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY", "GPU"]);
    let mut budget = ModelCallBudget::new(1, 1_000);

    let Err(error) = compiler.compile(&input, &mut budget) else {
        panic!("unknown heavy lease class must fail closed");
    };
    assert!(matches!(
        error,
        PlanCompilationError::InvalidInput(message)
            if message.contains("unknown policy.resources.heavy_leases class")
                && message.contains("GPU")
    ));
}

#[test]
fn minimal_compiler_two_task_split_requires_evidence_and_is_linear() {
    let rejected_backend = RecordingBackend::new(vec![response(two_task_proposal(false))]);
    let validator = validator();
    let rejected_compiler = compiler(&rejected_backend, &validator);
    let mut rejected_input = compilation_input();
    rejected_input.max_model_calls = 1;
    let mut rejected_budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        rejected_compiler.compile(&rejected_input, &mut rejected_budget),
        Err(PlanCompilationError::ProposalRejected { .. })
    ));

    let backend = RecordingBackend::new(vec![response(two_task_proposal(true))]);
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile two task: {error}"));
    let tasks = result.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("tasks must be array"));
    assert_eq!(tasks.len(), 2);
    assert!(
        tasks[0]["dependencies"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(tasks[1]["dependencies"][0], tasks[0]["task_id"]);
    assert_eq!(
        result.plan().as_value()["edges"][0]["kind"],
        json!("produces_for")
    );
    assert!(validator.is_valid(result.plan()));
}

#[test]
fn minimal_compiler_uses_bounded_exact_handles_not_repository_dump() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));

    let requests = lock(&backend.requests);
    let user_message = &requests[0].messages[1].content;
    assert!(user_message.contains("SettingsForm"));
    assert!(!user_message.contains("FULL_REPOSITORY_DUMP"));
    let handles = result.compilation_evidence().exact_evidence();
    assert!(handles.iter().any(|handle| {
        handle.source_uri == "repo://repo.app/src/settings/SettingsForm.tsx"
            && handle.source_digest == "sha256:settings-form-current"
    }));
}

#[test]
fn minimal_compiler_unknown_path_becomes_explicit_evidence_requirement() {
    let backend = RecordingBackend::new(vec![response(unknown_path_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let task = &result.plan().as_value()["tasks"][0];

    assert!(task["scope"]["files"].as_array().is_some_and(Vec::is_empty));
    assert_eq!(
        task["scope"]["scope_resolution"],
        json!("bounded_discovery")
    );
    assert!(
        task["evidence_requirements"]
            .as_array()
            .is_some_and(|requirements| {
                requirements.iter().any(|requirement| {
                    requirement["query"]
                        .as_str()
                        .is_some_and(|query| query.contains("UnknownSettings.tsx"))
                })
            })
    );
    assert_eq!(task["permissions"], json!(["read"]));
}

#[test]
fn minimal_compiler_malformed_proposal_retries_once_and_charges_outer_budget() {
    let backend = RecordingBackend::new(vec![response("not-json"), response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(2, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));

    assert_eq!(backend.complete_calls(), 2);
    assert_eq!(budget.remaining_calls(), 0);
    assert_eq!(result.compilation_evidence().model_attempts().len(), 2);
    assert!(!result.compilation_evidence().model_attempts()[0].accepted);
    assert!(result.compilation_evidence().model_attempts()[1].accepted);
}

#[test]
fn minimal_compiler_outer_budget_blocks_hidden_retry_before_backend_dispatch() {
    let backend = RecordingBackend::new(vec![response("not-json"), response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler.compile(&input, &mut budget),
        Err(PlanCompilationError::Policy(_))
    ));
    assert_eq!(backend.complete_calls(), 1);
}

#[test]
fn minimal_compiler_model_cannot_widen_permissions_or_replace_pins() {
    let malicious = json!({
        "tasks": [{
            "title": "Unsafe edit",
            "objective": "Try to widen authority.",
            "rationale": "malicious fixture",
            "files": ["src/settings/SettingsForm.tsx"],
            "symbols": ["SettingsForm"],
            "evidence_queries": [],
            "expected_change": "unsafe",
            "permissions": ["destructive", "secret_use"],
            "action_policy": {
                "secret_refs": [{
                    "secret_ref_id": "secret.attacker",
                    "provider": "macos_keychain",
                    "purpose": "attacker-selected authority",
                    "injection": "temporary_file",
                    "target": "attacker-target"
                }]
            }
        }]
    })
    .to_string();
    let rejected_backend = RecordingBackend::new(vec![response(malicious)]);
    let validator = validator();
    let rejected_compiler = compiler(&rejected_backend, &validator);
    let mut rejected_input = compilation_input();
    rejected_input.max_model_calls = 1;
    let mut rejected_budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        rejected_compiler.compile(&rejected_input, &mut rejected_budget),
        Err(PlanCompilationError::ProposalRejected { .. })
    ));

    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let expected_role = input.role.clone();
    let expected_skill = input.skills[0].clone();
    let expected_tool = input.tools[0].clone();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let task = &result.plan().as_value()["tasks"][0];
    assert_eq!(task["role"], expected_role);
    assert_eq!(task["skills"][0], expected_skill);
    assert_eq!(task["tools"][0], expected_tool);
    assert_eq!(
        task["permissions"],
        json!(["read", "repo_write", "process_exec"])
    );
}

#[test]
fn minimal_compiler_validator_rejection_returns_no_candidate() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    input
        .policy
        .as_object_mut()
        .unwrap_or_else(|| panic!("policy fixture must be object"))
        .remove("filesystem");
    let mut budget = ModelCallBudget::new(1, 1_000);
    assert!(matches!(
        compiler.compile(&input, &mut budget),
        Err(PlanCompilationError::ValidationRejected(_))
    ));
}

#[test]
fn minimal_compiler_result_and_compilation_evidence_are_digest_deterministic() {
    let validator = validator();
    let input = compilation_input();
    let left_backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let right_backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let left_compiler = compiler(&left_backend, &validator);
    let right_compiler = compiler(&right_backend, &validator);
    let mut left_budget = ModelCallBudget::new(1, 1_000);
    let mut right_budget = ModelCallBudget::new(1, 1_000);
    let left = left_compiler
        .compile(&input, &mut left_budget)
        .unwrap_or_else(|error| panic!("left compile: {error}"));
    let right = right_compiler
        .compile(&input, &mut right_budget)
        .unwrap_or_else(|error| panic!("right compile: {error}"));

    assert_eq!(left.plan_digest(), right.plan_digest());
    assert_eq!(
        left.compilation_evidence_digest(),
        right.compilation_evidence_digest()
    );
    assert_eq!(
        left.plan().canonical_bytes().unwrap_or_default(),
        right.plan().canonical_bytes().unwrap_or_default()
    );
}

#[test]
fn minimal_compiler_deterministic_fake_backend_fixture_passes() {
    let backend =
        DeterministicFakeBackend::new(fake_capabilities(), vec![response(one_task_proposal())])
            .unwrap_or_else(|error| panic!("fake backend: {error}"));
    backend
        .load(ModelLoadProfile {
            context_tokens: 8_000,
            output_reserve_tokens: 1_024,
            startup_timeout_ms: 1_000,
            provider_call_timeout_ms: 1_000,
        })
        .unwrap_or_else(|error| panic!("load fake backend: {error}"));
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let input = compilation_input();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("fake compile: {error}"));
    assert!(validator.is_valid(result.plan()));
    backend
        .unload()
        .unwrap_or_else(|error| panic!("unload fake backend: {error}"));
}
