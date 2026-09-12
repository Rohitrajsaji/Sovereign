use serde_json::{Value, json};
use sovereign_plan::{
    DiagnosticCode, PlanIr, PlanValidator, ValidationDiagnostic, ValidationEnvironment,
};

const FIXTURE: &str = include_str!("fixtures/valid_trivial_plan.json");

fn fixture() -> Value {
    match serde_json::from_str(FIXTURE) {
        Ok(value) => value,
        Err(error) => panic!("fixture JSON must parse: {error}"),
    }
}

fn diagnostics(value: Value) -> Vec<ValidationDiagnostic> {
    diagnostics_with_environment(value, ValidationEnvironment::default())
}

fn diagnostics_with_environment(
    value: Value,
    environment: ValidationEnvironment,
) -> Vec<ValidationDiagnostic> {
    let validator = match PlanValidator::new(environment) {
        Ok(validator) => validator,
        Err(error) => panic!("embedded schema must compile: {error}"),
    };
    validator.validate(&PlanIr::from_value(value))
}

fn assert_code(diagnostics: &[ValidationDiagnostic], code: DiagnosticCode) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "expected diagnostic {code}, got {diagnostics:#?}"
    );
}

fn task_mut(value: &mut Value, index: usize) -> &mut Value {
    let Some(tasks) = value["tasks"].as_array_mut() else {
        panic!("fixture tasks must be an array");
    };
    let Some(task) = tasks.get_mut(index) else {
        panic!("task index {index} must exist");
    };
    task
}

fn add_second_task(value: &mut Value, task_id: &str) {
    let mut task = value["tasks"][0].clone();
    task["task_id"] = json!(task_id);
    task["dependencies"] = json!([]);
    task["dependency_bindings"] = json!([]);
    let Some(tasks) = value["tasks"].as_array_mut() else {
        panic!("fixture tasks must be an array");
    };
    tasks.push(task);
}

fn binding(upstream_task_id: &str) -> Value {
    json!({
        "upstream_task_id": upstream_task_id,
        "required_artifact_ids": ["artifact.settings.patch"],
        "required_acceptance_criterion_ids": ["AC.settings-label"],
        "freshness": "same_plan_revision"
    })
}

#[test]
fn valid_trivial_plan_is_accepted() {
    let diagnostics = diagnostics(fixture());
    assert!(diagnostics.is_empty(), "{diagnostics:#?}");
}

#[test]
fn hard_dependency_cycle_is_rejected() {
    let mut value = fixture();
    add_second_task(&mut value, "task.second");
    task_mut(&mut value, 0)["dependencies"] = json!(["task.second"]);
    task_mut(&mut value, 0)["dependency_bindings"] = json!([binding("task.second")]);
    task_mut(&mut value, 1)["dependencies"] = json!(["task.rename-settings-label"]);
    task_mut(&mut value, 1)["dependency_bindings"] = json!([binding("task.rename-settings-label")]);

    assert_code(&diagnostics(value), DiagnosticCode::DependencyCycle);
}

#[test]
fn missing_hard_dependency_is_rejected() {
    let mut value = fixture();
    task_mut(&mut value, 0)["dependencies"] = json!(["task.missing"]);

    let diagnostics = diagnostics(value);
    assert_code(&diagnostics, DiagnosticCode::MissingReference);
    assert_code(&diagnostics, DiagnosticCode::DependencyBinding);
}

#[test]
fn dependency_bindings_are_one_for_one_and_cannot_create_dependencies() {
    let mut missing_binding = fixture();
    add_second_task(&mut missing_binding, "task.second");
    task_mut(&mut missing_binding, 0)["dependencies"] = json!(["task.second"]);
    assert_code(
        &diagnostics(missing_binding),
        DiagnosticCode::DependencyBinding,
    );

    let mut orphan_binding = fixture();
    add_second_task(&mut orphan_binding, "task.second");
    task_mut(&mut orphan_binding, 0)["dependency_bindings"] = json!([binding("task.second")]);
    assert_code(
        &diagnostics(orphan_binding),
        DiagnosticCode::DependencyBinding,
    );
}

#[test]
fn dependency_binding_artifact_and_criterion_refs_must_resolve_upstream() {
    let mut value = fixture();
    add_second_task(&mut value, "task.second");
    task_mut(&mut value, 0)["dependencies"] = json!(["task.second"]);
    task_mut(&mut value, 0)["dependency_bindings"] = json!([{
        "upstream_task_id": "task.second",
        "required_artifact_ids": ["artifact.missing"],
        "required_acceptance_criterion_ids": ["AC.missing"],
        "freshness": "same_plan_revision"
    }]);

    let diagnostics = diagnostics(value);
    let binding_failures = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::DependencyBinding)
        .count();
    assert!(binding_failures >= 2, "{diagnostics:#?}");
}

#[test]
fn execution_evidence_requires_stable_id_satisfaction_and_freshness() {
    for field in ["satisfaction", "freshness"] {
        let mut value = fixture();
        let Some(requirement) = task_mut(&mut value, 0)["evidence_requirements"][0].as_object_mut()
        else {
            panic!("evidence requirement must be object");
        };
        requirement.remove(field);
        assert_code(&diagnostics(value), DiagnosticCode::Schema);
    }

    let mut invalid_id = fixture();
    task_mut(&mut invalid_id, 0)["evidence_requirements"][0]["requirement_id"] = json!("x");
    assert_code(&diagnostics(invalid_id), DiagnosticCode::Schema);
}

#[test]
fn missing_acceptance_evidence_is_rejected() {
    let mut value = fixture();
    task_mut(&mut value, 0)["verification"]["required_evidence_types"] = json!(["test_result"]);
    assert_code(&diagnostics(value), DiagnosticCode::AcceptanceContract);
}

#[test]
fn required_acceptance_criterion_requires_explicit_freshness() {
    let mut value = fixture();
    let Some(criterion) = task_mut(&mut value, 0)["acceptance_criteria"][0].as_object_mut() else {
        panic!("criterion must be object");
    };
    criterion.remove("evidence_freshness");
    assert_code(&diagnostics(value), DiagnosticCode::Schema);
}

#[test]
fn task_permission_cannot_exceed_global_capability_ceiling() {
    let mut value = fixture();
    task_mut(&mut value, 0)["permissions"] =
        json!(["read", "repo_write", "process_exec", "browser_interactive"]);
    assert_code(&diagnostics(value), DiagnosticCode::PermissionPolicy);
}

#[test]
fn task_resource_budget_cannot_exceed_global_or_hardware_ceiling() {
    let mut global_conflict = fixture();
    task_mut(&mut global_conflict, 0)["resource_budget"]["max_peak_rss_mb"] = json!(6000);
    assert_code(
        &diagnostics(global_conflict),
        DiagnosticCode::ResourcePolicy,
    );

    let mut context_conflict = fixture();
    task_mut(&mut context_conflict, 0)["context_budget"]["max_input_tokens"] = json!(16_001);
    assert_code(
        &diagnostics(context_conflict),
        DiagnosticCode::ResourcePolicy,
    );
}

#[test]
fn untrusted_code_is_rejected_when_isolation_is_unavailable() {
    let environment = ValidationEnvironment {
        untrusted_code_isolation_available: false,
        ..ValidationEnvironment::default()
    };
    assert_code(
        &diagnostics_with_environment(fixture(), environment),
        DiagnosticCode::IsolationUnavailable,
    );
}

#[test]
fn command_timeout_cannot_exceed_task_tool_deadline() {
    let mut value = fixture();
    task_mut(&mut value, 0)["verification"]["steps"][1]["command_spec"]["timeout_seconds"] =
        json!(181);
    assert_code(&diagnostics(value), DiagnosticCode::DeadlinePolicy);
}

#[test]
fn task_model_call_deadline_cannot_exceed_global_deadline() {
    let mut value = fixture();
    task_mut(&mut value, 0)["resource_budget"]["max_model_call_seconds"] = json!(181);
    assert_code(&diagnostics(value), DiagnosticCode::ResourcePolicy);
}

#[test]
fn write_like_network_and_browser_scope_require_authority_and_reconciliation() {
    let mut network = fixture();
    task_mut(&mut network, 0)["action_policy"]["network"]["allowed_methods"] = json!(["POST"]);
    let network_diagnostics = diagnostics(network);
    assert_code(&network_diagnostics, DiagnosticCode::PermissionPolicy);
    assert_code(&network_diagnostics, DiagnosticCode::ReconciliationPolicy);

    let mut browser = fixture();
    task_mut(&mut browser, 0)["action_policy"]["browser"]["allowed"] = json!(true);
    assert_code(&diagnostics(browser), DiagnosticCode::PermissionPolicy);
}

#[test]
fn external_intelligence_scope_cannot_exceed_global_or_schema_policy() {
    let mut provider = fixture();
    task_mut(&mut provider, 0)["permissions"] = json!([
        "read",
        "repo_write",
        "process_exec",
        "external_intelligence"
    ]);
    task_mut(&mut provider, 0)["action_policy"]["external_intelligence"] = json!({
        "allowed": true,
        "allowed_providers": ["remote.provider"],
        "allowed_data_classes": ["source_slice"],
        "whole_repository_export": "deny",
        "raw_logs": false,
        "resolved_secrets": false,
        "tool_authority": "none",
        "max_payload_bytes": 1024
    });
    let provider_diagnostics = diagnostics(provider);
    assert_code(&provider_diagnostics, DiagnosticCode::PermissionPolicy);
    assert_code(
        &provider_diagnostics,
        DiagnosticCode::ExternalIntelligencePolicy,
    );

    let mut data_class = fixture();
    task_mut(&mut data_class, 0)["action_policy"]["external_intelligence"]["allowed_data_classes"] =
        json!(["entire_machine"]);
    assert_code(&diagnostics(data_class), DiagnosticCode::Schema);

    let mut payload = fixture();
    payload["policy"]["capability_ceiling"] = json!([
        "read",
        "repo_write",
        "process_exec",
        "external_intelligence"
    ]);
    payload["policy"]["external_intelligence"]["allowed_providers"] = json!(["remote.provider"]);
    task_mut(&mut payload, 0)["permissions"] = json!([
        "read",
        "repo_write",
        "process_exec",
        "external_intelligence"
    ]);
    task_mut(&mut payload, 0)["resource_budget"]["max_network_bytes"] = json!(512);
    task_mut(&mut payload, 0)["action_policy"]["external_intelligence"] = json!({
        "allowed": true,
        "allowed_providers": ["remote.provider"],
        "allowed_data_classes": ["source_slice"],
        "whole_repository_export": "deny",
        "raw_logs": false,
        "resolved_secrets": false,
        "tool_authority": "none",
        "max_payload_bytes": 1024
    });
    assert_code(
        &diagnostics(payload),
        DiagnosticCode::ExternalIntelligencePolicy,
    );
}

#[test]
fn task_revision_and_replan_ceilings_are_enforced() {
    let mut task_count = fixture();
    add_second_task(&mut task_count, "task.second");
    task_count["policy"]["retry"]["max_tasks_per_revision"] = json!(1);
    assert_code(&diagnostics(task_count), DiagnosticCode::RevisionBudget);

    let mut revision = fixture();
    revision["revision"] = json!(5);
    revision["supersedes_revision"] = json!(4);
    assert_code(&diagnostics(revision), DiagnosticCode::RevisionBudget);

    let mut replan = fixture();
    replan["revision"] = json!(4);
    replan["supersedes_revision"] = json!(3);
    replan["policy"]["retry"]["max_plan_revisions"] = json!(10);
    replan["policy"]["retry"]["max_replans_per_scope"] = json!(2);
    assert_code(&diagnostics(replan), DiagnosticCode::RevisionBudget);
}

#[test]
fn mutating_rollback_none_and_unverified_non_none_rollback_are_rejected() {
    let mut no_rollback = fixture();
    task_mut(&mut no_rollback, 0)["rollback"] = json!({
        "mode": "none",
        "procedure": "No rollback.",
        "reason_no_rollback": "fixture"
    });
    assert_code(&diagnostics(no_rollback), DiagnosticCode::RollbackPolicy);

    let mut no_verification = fixture();
    task_mut(&mut no_verification, 0)["rollback"] = json!({
        "mode": "patch_reverse",
        "procedure": "Reverse patch.",
        "verification_steps": []
    });
    assert_code(&diagnostics(no_verification), DiagnosticCode::Schema);
}

#[test]
fn next_state_failure_routing_cannot_contradict_failure_policy() {
    let mut value = fixture();
    let Some(rules) = task_mut(&mut value, 0)["next_state_rules"].as_array_mut() else {
        panic!("next-state rules must be array");
    };
    rules.push(json!({
        "event": "execution_failure",
        "guards": ["plan_revision_active"],
        "transition": "fail"
    }));
    assert_code(&diagnostics(value), DiagnosticCode::FailureRouting);
}

#[test]
fn canonical_digest_is_stable_for_equivalent_object_key_order() {
    let left = PlanIr::from_value(json!({
        "z": [3, {"b": 2, "a": 1}],
        "a": {"y": true, "x": false}
    }));
    let right = PlanIr::from_value(json!({
        "a": {"x": false, "y": true},
        "z": [3, {"a": 1, "b": 2}]
    }));

    let left_bytes = match left.canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => panic!("canonicalize left: {error}"),
    };
    let right_bytes = match right.canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => panic!("canonicalize right: {error}"),
    };
    assert_eq!(left_bytes, right_bytes);

    let left_digest = match left.canonical_digest() {
        Ok(digest) => digest,
        Err(error) => panic!("digest left: {error}"),
    };
    let right_digest = match right.canonical_digest() {
        Ok(digest) => digest,
        Err(error) => panic!("digest right: {error}"),
    };
    assert_eq!(left_digest, right_digest);
}
