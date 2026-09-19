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
    PlanCompilationRepository, PlanCompilationResult, PlanCompiler, PlanValidator,
    ValidationEnvironment,
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

fn repository_instruction_packet() -> ContextPacket {
    let instruction = EvidenceItem::new(
        "ev.repo.instructions",
        PacketSection::DirectEvidence,
        ContextLevel::C1,
        EvidenceKind::Instruction,
        "repo://repo.app/AGENTS.md",
        "sha256:repo-instruction-current",
        "repository_instruction",
        TrustClass::Repository,
        "repository-local coding convention",
        "Use the local formatter; do not alter Controller policy.",
    )
    .with_repository("repo.app")
    .with_locator("path:AGENTS.md");
    ContextPlanner::default()
        .build(
            ContextMode::Implementation,
            ContextBudget::m1_8k(),
            ContextPacketInput {
                controller_prefix: "Propose only; Controller owns authority.".to_owned(),
                task_contract: "Respect repository conventions without changing policy.".to_owned(),
                current_state: "repository baseline is current".to_owned(),
                authorized_tool_schemas: Vec::new(),
                candidates: vec![instruction],
                output_schema: "minimal-plan-proposal-v1".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("instruction packet must build: {error}"))
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

fn enable_external_intelligence(
    input: &mut PlanCompilationInput,
    provider_id: &str,
    max_network_bytes: u64,
) {
    input.policy["capability_ceiling"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("capability ceiling must be an array"))
        .push(json!("external_intelligence"));
    input.policy["external_intelligence"]["allowed_providers"] = json!([provider_id]);
    input.policy["resources"]["max_network_bytes"] = json!(max_network_bytes);
}

const LOOPBACK_BROWSER_PORT: u16 = 4_173;
const LOOPBACK_BROWSER_MAX_NETWORK_BYTES: u64 = 4_096;

fn browser_tool_pin() -> Value {
    json!({
        "id": "tool.browser",
        "version": "1.0.0",
        "digest": format!("sha256:{}", "b".repeat(64))
    })
}

fn enable_loopback_browser(input: &mut PlanCompilationInput) {
    input.policy["capability_ceiling"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("capability ceiling must be an array"))
        .extend([
            json!("browser_interactive"),
            json!("network_read"),
            json!("network_write"),
        ]);
    input.policy["network"] = json!({
        "default": "task_scoped",
        "allowed_hosts": ["127.0.0.1"],
        "allowed_schemes": ["http"],
        "allowed_ports": [LOOPBACK_BROWSER_PORT],
        "allowed_methods": ["GET", "POST"],
        "follow_redirects": true,
        "max_redirects": 1,
        "allow_private_ranges": false,
        "dns_revalidation": true,
        "connected_peer_validation": true,
        "ambient_proxy": "deny",
        "allow_task_loopback": true
    });
    input.policy["resources"]["max_network_bytes"] = json!(LOOPBACK_BROWSER_MAX_NETWORK_BYTES);
    input.policy["resources"]["heavy_leases"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("heavy leases must be an array"))
        .push(json!("BROWSER"));
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

fn two_read_only_browser_tasks_proposal() -> String {
    json!({
        "tasks": [
            {
                "title": "Capture inventory baseline",
                "objective": "Resolve the current inventory baseline before browser verification.",
                "rationale": "The proposed browser fixture path is intentionally outside bounded source evidence.",
                "files": ["src/browser/InventoryBaseline.ts"],
                "symbols": ["InventoryBaseline"],
                "evidence_queries": [],
                "expected_change": "Exact baseline evidence for the loopback application."
            },
            {
                "title": "Verify inventory flow in the browser",
                "objective": "Verify the loopback inventory flow after the baseline task completes.",
                "rationale": "Browser verification requires Controller-bound loopback authority only on this task.",
                "files": ["src/browser/InventoryBrowserFlow.ts"],
                "symbols": ["InventoryBrowserFlow"],
                "evidence_queries": [],
                "expected_change": "Browser verification evidence for the loopback inventory flow."
            }
        ]
    })
    .to_string()
}

fn compile_loopback_browser_source(
    configure: impl FnOnce(&mut PlanCompilationInput),
) -> PlanCompilationResult {
    let backend = RecordingBackend::new(vec![response(two_read_only_browser_tasks_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_loopback_browser(&mut input);
    configure(&mut input);
    let mut budget = ModelCallBudget::new(1, 1_000);
    compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile loopback browser source: {error}"))
}

fn assert_loopback_browser_binding_rejected(
    configure: impl FnOnce(&mut PlanCompilationInput),
    message_fragment: &str,
) {
    let source = compile_loopback_browser_source(configure);
    let validator = validator();
    let target_task_id = source.plan().as_value()["tasks"][1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("target task id"));
    let Err(error) = source.bind_controller_loopback_browser(
        &validator,
        target_task_id,
        &browser_tool_pin(),
        LOOPBACK_BROWSER_PORT,
        LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
    ) else {
        panic!("loopback browser binding must fail closed");
    };
    assert!(matches!(
        error,
        PlanCompilationError::ControllerBindingRejected(message)
            if message.contains(message_fragment)
    ));
}

fn assert_loopback_browser_authority(
    sibling: &Value,
    target: &Value,
    browser_tool_pin: &Value,
    source_target_approvals: &Value,
) {
    let sibling_leases = sibling["resource_budget"]["heavy_leases"]
        .as_array()
        .unwrap_or_else(|| panic!("sibling heavy leases"));
    let target_leases = target["resource_budget"]["heavy_leases"]
        .as_array()
        .unwrap_or_else(|| panic!("target heavy leases"));
    let target_permissions = target["permissions"]
        .as_array()
        .unwrap_or_else(|| panic!("target permissions"));
    let target_tools = target["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("target tools"));

    assert!(target_leases.contains(&json!("BROWSER")));
    assert!(!target_leases.contains(&json!("MODEL")));
    assert!(!sibling_leases.contains(&json!("BROWSER")));
    assert!(sibling_leases.contains(&json!("MODEL")));
    assert!(target_permissions.contains(&json!("browser_interactive")));
    assert!(target_permissions.contains(&json!("network_read")));
    assert!(target_permissions.contains(&json!("network_write")));
    assert!(!target_permissions.contains(&json!("repo_write")));
    assert_eq!(target_tools.last(), Some(browser_tool_pin));
    assert_eq!(
        target["action_policy"]["network"],
        json!({
            "default": "task_scoped",
            "allowed_hosts": ["127.0.0.1"],
            "allowed_schemes": ["http"],
            "allowed_ports": [LOOPBACK_BROWSER_PORT],
            "allowed_methods": ["GET", "POST"],
            "follow_redirects": true,
            "max_redirects": 1,
            "allow_private_ranges": false,
            "dns_revalidation": true,
            "connected_peer_validation": true,
            "ambient_proxy": "deny",
            "allow_task_loopback": true
        })
    );
    assert_eq!(
        target["resource_budget"]["max_network_bytes"],
        json!(LOOPBACK_BROWSER_MAX_NETWORK_BYTES)
    );
    assert_eq!(target["resource_budget"]["max_model_calls"], json!(0));
    assert_eq!(
        target["action_policy"]["approval_required_permissions"],
        *source_target_approvals
    );
}

fn assert_loopback_browser_fail_closed_lifecycle(target: &Value) {
    let rules = target["next_state_rules"]
        .as_array()
        .unwrap_or_else(|| panic!("next state rules"));
    let unknown_action_rules = rules
        .iter()
        .filter(|rule| rule["event"] == json!("unknown_action"))
        .collect::<Vec<_>>();
    assert_eq!(unknown_action_rules.len(), 1);
    assert_eq!(unknown_action_rules[0]["transition"], json!("reconcile"));
    assert_eq!(
        unknown_action_rules[0]["guards"],
        json!(["plan_revision_active"])
    );
    let execution_failure_rules = rules
        .iter()
        .filter(|rule| rule["event"] == json!("execution_failure"))
        .collect::<Vec<_>>();
    assert_eq!(execution_failure_rules.len(), 1);
    assert_eq!(execution_failure_rules[0]["transition"], json!("block"));
    assert_eq!(
        target["failure_policy"]["on_execution_failure"],
        json!("block")
    );
    assert_eq!(target["rollback"]["mode"], json!("compensating_action"));
    assert_eq!(
        target["rollback"]["verification_steps"][0]["evidence_type"],
        json!("browser_compensation_receipt")
    );
    let compensation_artifact_id = target["rollback"]["verification_steps"][0]["artifact_id"]
        .as_str()
        .unwrap_or_else(|| panic!("browser compensation artifact id"));
    let compensation_artifact = target["expected_artifacts"]
        .as_array()
        .unwrap_or_else(|| panic!("expected artifacts"))
        .iter()
        .find(|artifact| artifact["artifact_id"] == json!(compensation_artifact_id))
        .unwrap_or_else(|| panic!("linked browser compensation artifact"));
    assert_eq!(compensation_artifact["kind"], json!("evidence"));
    assert_eq!(compensation_artifact["required"], json!(false));
    assert!(
        compensation_artifact["locator"].as_str().is_some_and(
            |locator| locator.starts_with("controller://rollback/browser-compensation/")
        )
    );
    let rollback_procedure = target["rollback"]["procedure"]
        .as_str()
        .unwrap_or_else(|| panic!("rollback procedure"));
    assert!(rollback_procedure.contains("No automatic compensation is authorized"));
    assert!(
        rollback_procedure.contains("First reconcile the exact original browser write outcome")
    );
    assert!(rollback_procedure.contains("fresh Controller-governed compensating action"));
    assert!(rollback_procedure.contains("never replay an unknown write"));
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
fn repository_instruction_refs_remain_untrusted_in_compiled_plan() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    input.context_packet = repository_instruction_packet();
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));

    let instructions = result.plan().as_value()["repositories"][0]["instructions"]
        .as_array()
        .unwrap_or_else(|| panic!("repository instructions must be an array"));
    assert_eq!(instructions.len(), 1);
    assert_eq!(instructions[0]["trust"], json!("untrusted"));
    assert!(validator.is_valid(result.plan()));
}

#[test]
fn compiler_keeps_external_intelligence_disabled_even_when_global_policy_permits_it() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_external_intelligence(&mut input, "remote.reasoner", 4_096);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let result = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let task = &result.plan().as_value()["tasks"][0];

    assert!(
        !task["permissions"]
            .as_array()
            .is_some_and(|permissions| permissions.contains(&json!("external_intelligence")))
    );
    assert_eq!(
        task["action_policy"]["external_intelligence"]["allowed"],
        json!(false)
    );
    assert_eq!(
        task["action_policy"]["external_intelligence"]["allowed_providers"],
        json!([])
    );
    assert_eq!(
        task["action_policy"]["external_intelligence"]["allowed_data_classes"],
        json!([])
    );
    assert_eq!(
        task["action_policy"]["external_intelligence"]["max_payload_bytes"],
        json!(0)
    );
    assert_eq!(task["resource_budget"]["max_network_bytes"], json!(0));
    assert!(validator.is_valid(result.plan()));
}

#[test]
fn controller_external_intelligence_binding_targets_one_task_and_recomputes_provenance() {
    let backend = RecordingBackend::new(vec![response(two_task_proposal(true))]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_external_intelligence(&mut input, "remote.reasoner", 4_096);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let source_tasks = source.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("tasks array"));
    let sibling_before = source_tasks[0].clone();
    let target_task_id = source_tasks[1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("target task id"))
        .to_owned();
    let source_plan_digest = source.plan_digest().to_owned();
    let source_evidence_digest = source.compilation_evidence_digest().to_owned();

    let bound = source
        .bind_controller_external_intelligence(
            &validator,
            &target_task_id,
            "remote.reasoner",
            &["source_slice".to_owned(), "verification".to_owned()],
            1_024,
        )
        .unwrap_or_else(|error| panic!("bind external intelligence: {error}"));
    let bound_tasks = bound.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("bound tasks array"));
    let task = &bound_tasks[1];

    assert_eq!(bound_tasks[0], sibling_before);
    assert!(
        task["permissions"]
            .as_array()
            .is_some_and(|permissions| permissions.contains(&json!("external_intelligence")))
    );
    assert_eq!(
        task["action_policy"]["external_intelligence"],
        json!({
            "allowed": true,
            "allowed_providers": ["remote.reasoner"],
            "allowed_data_classes": ["source_slice", "verification"],
            "whole_repository_export": "deny",
            "raw_logs": false,
            "resolved_secrets": false,
            "tool_authority": "none",
            "max_payload_bytes": 1024
        })
    );
    assert_eq!(task["resource_budget"]["max_network_bytes"], json!(1_024));
    assert!(validator.is_valid(bound.plan()));
    assert_ne!(bound.plan_digest(), source_plan_digest);
    assert_ne!(bound.compilation_evidence_digest(), source_evidence_digest);
    assert_eq!(
        bound.compilation_evidence().plan_digest(),
        bound.plan_digest()
    );
    let bindings = bound
        .compilation_evidence()
        .controller_external_intelligence_bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].source_plan_digest(), source_plan_digest);
    assert_eq!(bindings[0].target_task_id(), target_task_id);
    assert!(bindings[0].binding_digest().starts_with("sha256:"));
}

#[test]
fn controller_external_intelligence_binding_rejects_provider_outside_global_policy() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_external_intelligence(&mut input, "remote.allowed", 4_096);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let target_task_id = source.plan().as_value()["tasks"][0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("compiled task id"));

    assert!(matches!(
        source.bind_controller_external_intelligence(
            &validator,
            target_task_id,
            "remote.denied",
            &["source_slice".to_owned()],
            1_024,
        ),
        Err(PlanCompilationError::ControllerBindingRejected(message))
            if message.contains("does not allow provider")
    ));
}

#[test]
fn controller_external_intelligence_binding_reruns_plan_validation() {
    let backend = RecordingBackend::new(vec![response(one_task_proposal())]);
    let validator = validator();
    let compiler = compiler(&backend, &validator);
    let mut input = compilation_input();
    enable_external_intelligence(&mut input, "remote.reasoner", 4_096);
    let mut budget = ModelCallBudget::new(1, 1_000);
    let source = compiler
        .compile(&input, &mut budget)
        .unwrap_or_else(|error| panic!("compile: {error}"));
    let target_task_id = source.plan().as_value()["tasks"][0]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("compiled task id"));

    assert!(matches!(
        source.bind_controller_external_intelligence(
            &validator,
            target_task_id,
            "remote.reasoner",
            &["entire_machine".to_owned()],
            1_024,
        ),
        Err(PlanCompilationError::ValidationRejected(_))
    ));
}

#[test]
fn controller_loopback_browser_binding_is_validator_clean_and_narrows_authority() {
    let source = compile_loopback_browser_source(|_| {});
    let validator = validator();
    let source_tasks = source.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("source tasks array"));
    let target_task_id = source_tasks[1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("target task id"))
        .to_owned();
    let source_plan_digest = source.plan_digest().to_owned();
    let source_evidence_digest = source.compilation_evidence_digest().to_owned();
    let source_global_approval = source.plan().as_value()["policy"]["approval"].clone();
    let source_target_approvals =
        source_tasks[1]["action_policy"]["approval_required_permissions"].clone();
    let browser_tool_pin = browser_tool_pin();

    assert_eq!(source_tasks[1]["permissions"], json!(["read"]));
    assert_eq!(source_tasks[1]["rollback"]["mode"], json!("none"));
    assert_eq!(
        source_tasks[1]["action_policy"]["browser"]["allowed"],
        json!(false)
    );

    let bound = source
        .bind_controller_loopback_browser(
            &validator,
            &target_task_id,
            &browser_tool_pin,
            LOOPBACK_BROWSER_PORT,
            LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
        )
        .unwrap_or_else(|error| panic!("bind loopback browser: {error}"));
    let bound_tasks = bound.plan().as_value()["tasks"]
        .as_array()
        .unwrap_or_else(|| panic!("bound tasks array"));
    let sibling = &bound_tasks[0];
    let target = &bound_tasks[1];

    assert!(validator.is_valid(bound.plan()));
    assert_loopback_browser_authority(sibling, target, &browser_tool_pin, &source_target_approvals);
    assert_eq!(
        bound.plan().as_value()["policy"]["approval"],
        source_global_approval
    );
    assert!(
        bound.plan().as_value()["policy"]["approval"]["required_permissions"]
            .as_array()
            .is_some_and(|permissions| permissions.contains(&json!("network_write")))
    );
    assert_loopback_browser_fail_closed_lifecycle(target);

    assert_ne!(bound.plan_digest(), source_plan_digest);
    assert_ne!(bound.compilation_evidence_digest(), source_evidence_digest);
    assert_eq!(
        bound.compilation_evidence().plan_digest(),
        bound.plan_digest()
    );
    let bindings = bound
        .compilation_evidence()
        .controller_browser_loopback_bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].source_plan_digest(), source_plan_digest);
    assert_eq!(bindings[0].target_task_id(), target_task_id);
    assert!(bindings[0].binding_digest().starts_with("sha256:"));
}

#[test]
fn controller_loopback_browser_binding_digest_covers_bound_resource_lifecycle() {
    let validator = validator();
    let default_source = compile_loopback_browser_source(|_| {});
    let tightened_source = compile_loopback_browser_source(|input| {
        input.policy["resources"]["max_wall_seconds"] = json!(3_599);
    });
    let default_target = default_source.plan().as_value()["tasks"][1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("default target task id"))
        .to_owned();
    let tightened_target = tightened_source.plan().as_value()["tasks"][1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("tightened target task id"))
        .to_owned();
    assert_eq!(default_target, tightened_target);

    let default_bound = default_source
        .bind_controller_loopback_browser(
            &validator,
            &default_target,
            &browser_tool_pin(),
            LOOPBACK_BROWSER_PORT,
            LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
        )
        .unwrap_or_else(|error| panic!("bind default browser task: {error}"));
    let tightened_bound = tightened_source
        .bind_controller_loopback_browser(
            &validator,
            &tightened_target,
            &browser_tool_pin(),
            LOOPBACK_BROWSER_PORT,
            LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
        )
        .unwrap_or_else(|error| panic!("bind tightened browser task: {error}"));

    assert_eq!(
        default_bound.plan().as_value()["tasks"][1]["failure_policy"]["on_execution_failure"],
        json!("block")
    );
    assert_eq!(
        tightened_bound.plan().as_value()["tasks"][1]["failure_policy"]["on_execution_failure"],
        json!("block")
    );
    assert_eq!(
        default_bound.plan().as_value()["tasks"][1]["resource_budget"]["max_model_calls"],
        json!(0)
    );
    assert_eq!(
        tightened_bound.plan().as_value()["tasks"][1]["resource_budget"]["max_model_calls"],
        json!(0)
    );
    assert_ne!(
        default_bound
            .compilation_evidence()
            .controller_browser_loopback_bindings()[0]
            .binding_digest(),
        tightened_bound
            .compilation_evidence()
            .controller_browser_loopback_bindings()[0]
            .binding_digest()
    );
}

#[test]
fn controller_loopback_browser_binding_rejects_non_exact_sha256_tool_pin() {
    let source = compile_loopback_browser_source(|_| {});
    let validator = validator();
    let target_task_id = source.plan().as_value()["tasks"][1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("target task id"));
    let mut invalid_pin = browser_tool_pin();
    invalid_pin["digest"] = json!(format!("sha256:{}", "g".repeat(64)));

    assert!(matches!(
        source.bind_controller_loopback_browser(
            &validator,
            target_task_id,
            &invalid_pin,
            LOOPBACK_BROWSER_PORT,
            LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
        ),
        Err(PlanCompilationError::ControllerBindingRejected(message))
            if message.contains("exact sha256:<64-hex> digest")
    ));
}

#[test]
fn controller_loopback_browser_binding_rejects_duplicate_or_preexisting_browser_authority() {
    let source = compile_loopback_browser_source(|_| {});
    let validator = validator();
    let target_task_id = source.plan().as_value()["tasks"][1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("target task id"))
        .to_owned();
    let exact_pin = browser_tool_pin();
    let bound = source
        .bind_controller_loopback_browser(
            &validator,
            &target_task_id,
            &exact_pin,
            LOOPBACK_BROWSER_PORT,
            LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
        )
        .unwrap_or_else(|error| panic!("first loopback browser binding: {error}"));
    assert!(matches!(
        bound.bind_controller_loopback_browser(
            &validator,
            &target_task_id,
            &exact_pin,
            LOOPBACK_BROWSER_PORT,
            LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
        ),
        Err(PlanCompilationError::ControllerBindingRejected(message))
            if message.contains("already contains a Controller authority binding")
    ));

    let preexisting_pin = browser_tool_pin();
    let preexisting = compile_loopback_browser_source(|input| {
        input.tools.push(preexisting_pin.clone());
        input.read_tool_id = "tool.browser".to_owned();
    });
    let preexisting_target = preexisting.plan().as_value()["tasks"][1]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("preexisting target task id"));
    assert!(matches!(
        preexisting.bind_controller_loopback_browser(
            &validator,
            preexisting_target,
            &preexisting_pin,
            LOOPBACK_BROWSER_PORT,
            LOOPBACK_BROWSER_MAX_NETWORK_BYTES,
        ),
        Err(PlanCompilationError::ControllerBindingRejected(message))
            if message.contains("already contains the Controller-selected browser tool pin")
    ));
}

#[test]
fn controller_loopback_browser_binding_requires_exact_global_preauthorization() {
    assert_loopback_browser_binding_rejected(
        |input| {
            input.policy["capability_ceiling"]
                .as_array_mut()
                .unwrap_or_else(|| panic!("capability ceiling"))
                .retain(|capability| capability != &json!("browser_interactive"));
        },
        "capability ceiling does not include browser_interactive",
    );
    assert_loopback_browser_binding_rejected(
        |input| input.policy["network"]["allow_task_loopback"] = json!(false),
        "global network policy does not preauthorize exact",
    );
    assert_loopback_browser_binding_rejected(
        |input| input.policy["network"]["allowed_methods"] = json!(["GET"]),
        "global network policy does not preauthorize exact",
    );
    assert_loopback_browser_binding_rejected(
        |input| input.policy["network"]["allowed_ports"] = json!([4_174]),
        "global network policy does not preauthorize exact",
    );
    assert_loopback_browser_binding_rejected(
        |input| input.policy["network"]["follow_redirects"] = json!(false),
        "global network policy does not preauthorize exact",
    );
    assert_loopback_browser_binding_rejected(
        |input| input.policy["network"]["max_redirects"] = json!(0),
        "global network policy does not preauthorize exact",
    );
    assert_loopback_browser_binding_rejected(
        |input| {
            input.policy["resources"]["heavy_leases"]
                .as_array_mut()
                .unwrap_or_else(|| panic!("heavy leases"))
                .retain(|lease| lease != &json!("BROWSER"));
        },
        "global resources do not preauthorize BROWSER",
    );
    assert_loopback_browser_binding_rejected(
        |input| {
            input.policy["resources"]["max_network_bytes"] =
                json!(LOOPBACK_BROWSER_MAX_NETWORK_BYTES - 1);
        },
        "global resources do not preauthorize BROWSER",
    );
    assert_loopback_browser_binding_rejected(
        |input| {
            input.policy["approval"]["required_permissions"]
                .as_array_mut()
                .unwrap_or_else(|| panic!("required permissions"))
                .retain(|permission| permission != &json!("network_write"));
        },
        "must retain network_write approval",
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
