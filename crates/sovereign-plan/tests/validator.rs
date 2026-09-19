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

fn assert_diagnostic_at(
    diagnostics: &[ValidationDiagnostic],
    code: DiagnosticCode,
    path: &str,
    message_fragment: &str,
) {
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.code == code
                && diagnostic.path == path
                && diagnostic.message.contains(message_fragment)
        }),
        "expected diagnostic {code} at {path} containing {message_fragment:?}, got {diagnostics:#?}"
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
fn command_verification_requires_process_exec_permission() {
    let mut value = fixture();
    task_mut(&mut value, 0)["permissions"] = json!(["read", "repo_write"]);
    assert_code(&diagnostics(value), DiagnosticCode::PermissionPolicy);
}

#[test]
fn command_verification_requires_build_heavy_resource_authority() {
    let mut value = fixture();
    task_mut(&mut value, 0)["resource_budget"]["heavy_leases"] = json!(["MODEL"]);
    assert_code(&diagnostics(value), DiagnosticCode::ResourcePolicy);
}

#[test]
fn command_tool_and_repository_must_resolve_within_task_scope() {
    let mut wrong_tool = fixture();
    task_mut(&mut wrong_tool, 0)["verification"]["steps"][1]["command_spec"]["tool_id"] =
        json!("tool.missing");
    assert_code(&diagnostics(wrong_tool), DiagnosticCode::MissingReference);

    let mut wrong_repository = fixture();
    task_mut(&mut wrong_repository, 0)["verification"]["steps"][1]["command_spec"]["repository_id"] =
        json!("repo.other");
    assert_code(
        &diagnostics(wrong_repository),
        DiagnosticCode::MissingReference,
    );
}

#[test]
fn command_working_directory_cannot_escape_repository_scope() {
    let mut value = fixture();
    task_mut(&mut value, 0)["verification"]["steps"][1]["command_spec"]["working_dir_relative"] =
        json!("../outside");
    assert_code(&diagnostics(value), DiagnosticCode::Schema);
}

#[test]
fn command_shell_and_literal_environment_follow_global_process_policy() {
    let mut shell = fixture();
    task_mut(&mut shell, 0)["verification"]["steps"][1]["command_spec"]["mode"] =
        json!("shell_explicit");
    assert_code(&diagnostics(shell), DiagnosticCode::PermissionPolicy);

    let mut env = fixture();
    task_mut(&mut env, 0)["verification"]["steps"][1]["command_spec"]["literal_env"] =
        json!({"CI": "1", "UNAUTHORIZED": "1"});
    assert_code(&diagnostics(env), DiagnosticCode::PermissionPolicy);
}

#[test]
fn command_secret_environment_must_resolve_task_secret_ref() {
    let mut value = fixture();
    task_mut(&mut value, 0)["verification"]["steps"][1]["command_spec"]["secret_env"] =
        json!({"TOKEN": "secret.missing"});
    assert_code(&diagnostics(value), DiagnosticCode::MissingReference);

    let mut allowed = fixture();
    task_mut(&mut allowed, 0)["action_policy"]["secret_refs"] = json!([{
        "secret_ref_id": "secret.test-token",
        "provider": "environment",
        "purpose": "fixture command authentication",
        "injection": "environment",
        "target": "TOKEN"
    }]);
    task_mut(&mut allowed, 0)["verification"]["steps"][1]["command_spec"]["secret_env"] =
        json!({"TOKEN": "secret.test-token"});
    let diagnostics = diagnostics(allowed);
    assert!(
        !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::MissingReference),
        "{diagnostics:#?}"
    );
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

fn enable_browser_scope(value: &mut serde_json::Value, host: &str, port: u64) {
    value["policy"]["capability_ceiling"] = json!([
        "read",
        "repo_write",
        "process_exec",
        "browser_interactive",
        "network_read"
    ]);
    value["policy"]["network"] = json!({
        "default": "task_scoped",
        "allowed_hosts": [host],
        "allowed_schemes": ["http"],
        "allowed_ports": [port],
        "allowed_methods": ["GET"],
        "follow_redirects": false,
        "max_redirects": 0,
        "allow_private_ranges": false,
        "dns_revalidation": true,
        "connected_peer_validation": true,
        "ambient_proxy": "deny",
        "allow_task_loopback": false
    });
    value["policy"]["resources"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY", "BROWSER"]);
    task_mut(value, 0)["permissions"] = json!([
        "read",
        "repo_write",
        "process_exec",
        "browser_interactive",
        "network_read"
    ]);
    task_mut(value, 0)["action_policy"]["network"] = json!({
        "default": "task_scoped",
        "allowed_hosts": [host],
        "allowed_schemes": ["http"],
        "allowed_ports": [port],
        "allowed_methods": ["GET"],
        "follow_redirects": false,
        "max_redirects": 0,
        "allow_private_ranges": false,
        "dns_revalidation": true,
        "connected_peer_validation": true,
        "ambient_proxy": "deny",
        "allow_task_loopback": false
    });
    task_mut(value, 0)["action_policy"]["browser"]["allowed"] = json!(true);
    task_mut(value, 0)["action_policy"]["browser"]["allowed_domains"] = json!([host]);
    task_mut(value, 0)["resource_budget"]["heavy_leases"] =
        json!(["MODEL", "BUILD_HEAVY", "BROWSER"]);
}

#[test]
fn browser_requires_browser_resource_and_network_scope_narrowing() {
    let mut valid = fixture();
    enable_browser_scope(&mut valid, "example.test", 8080);
    let valid_diagnostics = diagnostics(valid.clone());
    assert!(
        !valid_diagnostics.iter().any(|diagnostic| matches!(
            diagnostic.code,
            DiagnosticCode::PermissionPolicy | DiagnosticCode::ResourcePolicy
        )),
        "{valid_diagnostics:#?}"
    );

    let mut no_lease = valid.clone();
    task_mut(&mut no_lease, 0)["resource_budget"]["heavy_leases"] = json!(["MODEL", "BUILD_HEAVY"]);
    assert_code(&diagnostics(no_lease), DiagnosticCode::ResourcePolicy);

    let mut host_escape = valid.clone();
    task_mut(&mut host_escape, 0)["action_policy"]["browser"]["allowed_domains"] =
        json!(["other.test"]);
    assert_code(&diagnostics(host_escape), DiagnosticCode::PermissionPolicy);

    let mut method_escape = valid.clone();
    method_escape["policy"]["network"]["allowed_methods"] = json!([]);
    assert_code(
        &diagnostics(method_escape),
        DiagnosticCode::PermissionPolicy,
    );

    let mut wildcard = valid.clone();
    wildcard["policy"]["network"]["allowed_hosts"] = json!(["*.example.test"]);
    task_mut(&mut wildcard, 0)["action_policy"]["network"]["allowed_hosts"] =
        json!(["*.example.test"]);
    task_mut(&mut wildcard, 0)["action_policy"]["browser"]["allowed_domains"] =
        json!(["*.example.test"]);
    assert_code(&diagnostics(wildcard), DiagnosticCode::PermissionPolicy);

    let mut private_ranges = valid;
    task_mut(&mut private_ranges, 0)["action_policy"]["network"]["allow_private_ranges"] =
        json!(true);
    assert_code(
        &diagnostics(private_ranges),
        DiagnosticCode::PermissionPolicy,
    );
}

#[test]
fn browser_task_loopback_requires_exact_literal_port_and_global_ceiling() {
    let mut value = fixture();
    enable_browser_scope(&mut value, "127.0.0.1", 3000);
    task_mut(&mut value, 0)["action_policy"]["network"]["allow_task_loopback"] = json!(true);
    assert_code(
        &diagnostics(value.clone()),
        DiagnosticCode::PermissionPolicy,
    );

    value["policy"]["network"]["allow_task_loopback"] = json!(true);
    let valid = diagnostics(value.clone());
    assert!(
        !valid.iter().any(|diagnostic| matches!(
            diagnostic.code,
            DiagnosticCode::PermissionPolicy | DiagnosticCode::ResourcePolicy
        )),
        "{valid:#?}"
    );

    task_mut(&mut value, 0)["action_policy"]["network"]["allowed_hosts"] = json!(["localhost"]);
    task_mut(&mut value, 0)["action_policy"]["browser"]["allowed_domains"] = json!(["localhost"]);
    value["policy"]["network"]["allowed_hosts"] = json!(["localhost"]);
    assert_code(&diagnostics(value), DiagnosticCode::PermissionPolicy);
}

#[test]
fn browser_download_root_is_coherent_with_task_and_global_download_authority() {
    let valid = valid_browser_download_plan();
    let valid_diagnostics = diagnostics(valid.clone());
    assert!(
        !valid_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::PermissionPolicy),
        "{valid_diagnostics:#?}"
    );

    let mut denied_absent = fixture();
    enable_browser_scope(&mut denied_absent, "example.test", 8080);
    let browser = task_mut(&mut denied_absent, 0)["action_policy"]["browser"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("browser policy must be an object"));
    browser.remove("download_root");
    let denied_absent_diagnostics = diagnostics(denied_absent);
    assert!(
        !denied_absent_diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("/action_policy/browser/download_root")
        }),
        "deny + absent root must be accepted: {denied_absent_diagnostics:#?}"
    );

    let mut denied_null = fixture();
    enable_browser_scope(&mut denied_null, "example.test", 8080);
    task_mut(&mut denied_null, 0)["action_policy"]["browser"]["download_root"] = Value::Null;
    let denied_null_diagnostics = diagnostics(denied_null);
    assert!(
        !denied_null_diagnostics.iter().any(|diagnostic| {
            diagnostic
                .path
                .ends_with("/action_policy/browser/download_root")
        }),
        "deny + null root must be accepted: {denied_null_diagnostics:#?}"
    );

    let mut denied_with_root = fixture();
    enable_browser_scope(&mut denied_with_root, "example.test", 8080);
    task_mut(&mut denied_with_root, 0)["action_policy"]["browser"]["download_root"] =
        json!("downloads");
    let denied_with_root_diagnostics = diagnostics(denied_with_root);
    assert_diagnostic_at(
        &denied_with_root_diagnostics,
        DiagnosticCode::PermissionPolicy,
        "/tasks/0/action_policy/browser/download_root",
        "denied browser downloads cannot carry a download root",
    );

    let mut no_global_ceiling = valid.clone();
    no_global_ceiling["policy"]["browser"]["downloads"] = json!("deny");
    let no_global_ceiling_diagnostics = diagnostics(no_global_ceiling);
    assert_diagnostic_at(
        &no_global_ceiling_diagnostics,
        DiagnosticCode::PermissionPolicy,
        "/tasks/0/action_policy/browser/downloads",
        "exceed the global browser download ceiling",
    );

    for missing_root in [None, Some(Value::Null)] {
        let mut missing = valid.clone();
        let browser = task_mut(&mut missing, 0)["action_policy"]["browser"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("browser policy must be an object"));
        match missing_root {
            Some(value) => {
                browser.insert("download_root".to_owned(), value);
            }
            None => {
                browser.remove("download_root");
            }
        }
        let missing_diagnostics = diagnostics(missing);
        assert_diagnostic_at(
            &missing_diagnostics,
            DiagnosticCode::PermissionPolicy,
            "/tasks/0/action_policy/browser/download_root",
            "require a strict relative download root",
        );
    }
}

#[test]
fn browser_download_root_rejects_non_normal_or_platform_prefixed_components() {
    let valid = valid_browser_download_plan();
    for root in [
        "",
        "   ",
        ".",
        "..",
        "../escape",
        "/absolute",
        "nested/../escape",
        "./relative",
        "nested/./downloads",
        "nested//downloads",
        "nested/downloads/",
        "C:/absolute",
        r"C:\absolute",
        r"nested\..\escape",
    ] {
        let mut invalid_root = valid.clone();
        task_mut(&mut invalid_root, 0)["action_policy"]["browser"]["download_root"] = json!(root);
        let invalid_diagnostics = diagnostics(invalid_root);
        assert_diagnostic_at(
            &invalid_diagnostics,
            DiagnosticCode::PermissionPolicy,
            "/tasks/0/action_policy/browser/download_root",
            "non-empty strict relative path",
        );
    }
}

fn valid_browser_download_plan() -> Value {
    let mut value = fixture();
    enable_browser_scope(&mut value, "example.test", 8080);
    value["policy"]["browser"]["downloads"] = json!("task_scoped");
    task_mut(&mut value, 0)["action_policy"]["browser"]["downloads"] = json!("task_scoped");
    task_mut(&mut value, 0)["action_policy"]["browser"]["download_root"] =
        json!("artifacts/browser-downloads");
    value
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

    let mut independent_scope_history = fixture();
    independent_scope_history["revision"] = json!(4);
    independent_scope_history["supersedes_revision"] = json!(3);
    independent_scope_history["policy"]["retry"]["max_plan_revisions"] = json!(10);
    independent_scope_history["policy"]["retry"]["max_replans_per_scope"] = json!(2);
    assert!(diagnostics(independent_scope_history).is_empty());
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

#[test]
fn compiler_validator_dependency_bindings_require_required_upstream_outputs() {
    let mut optional_artifact = fixture();
    add_second_task(&mut optional_artifact, "task.second");
    task_mut(&mut optional_artifact, 0)["dependencies"] = json!(["task.second"]);
    task_mut(&mut optional_artifact, 0)["dependency_bindings"] = json!([binding("task.second")]);
    task_mut(&mut optional_artifact, 1)["expected_artifacts"][0]["required"] = json!(false);
    assert_code(
        &diagnostics(optional_artifact),
        DiagnosticCode::DependencyBinding,
    );

    let mut optional_criterion = fixture();
    add_second_task(&mut optional_criterion, "task.second");
    task_mut(&mut optional_criterion, 0)["dependencies"] = json!(["task.second"]);
    task_mut(&mut optional_criterion, 0)["dependency_bindings"] = json!([binding("task.second")]);
    task_mut(&mut optional_criterion, 1)["acceptance_criteria"][0]["required"] = json!(false);
    assert_code(
        &diagnostics(optional_criterion),
        DiagnosticCode::DependencyBinding,
    );
}

#[test]
fn compiler_validator_requires_governed_evaluators_for_evaluator_pass_and_diff() {
    let mut evidence = fixture();
    task_mut(&mut evidence, 0)["evidence_requirements"][0]["satisfaction"] =
        json!("evaluator_pass");
    task_mut(&mut evidence, 0)["evidence_requirements"][0]["evaluator"] =
        json!("untrusted.evaluator");
    assert_code(&diagnostics(evidence), DiagnosticCode::EvidenceContract);

    let mut verification = fixture();
    task_mut(&mut verification, 0)["verification"]["steps"][0]["evaluator"] =
        json!("untrusted.evaluator");
    assert_code(
        &diagnostics(verification),
        DiagnosticCode::AcceptanceContract,
    );

    let mut governed = fixture();
    task_mut(&mut governed, 0)["evidence_requirements"][0]["satisfaction"] =
        json!("evaluator_pass");
    task_mut(&mut governed, 0)["evidence_requirements"][0]["evaluator"] = json!(format!(
        "governed:absence.zero-hit@1.0.0#sha256:{}",
        "a".repeat(64)
    ));
    let diagnostics = diagnostics(governed);
    assert!(
        !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::EvidenceContract),
        "{diagnostics:#?}"
    );
}

#[test]
fn compiler_validator_verification_links_are_bidirectional_and_step_ids_unique() {
    let mut orphan = fixture();
    let mut extra = task_mut(&mut orphan, 0)["verification"]["steps"][0].clone();
    extra["step_id"] = json!("verify.orphan-extra");
    task_mut(&mut orphan, 0)["verification"]["steps"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("steps array"))
        .push(extra);
    assert_code(&diagnostics(orphan), DiagnosticCode::AcceptanceContract);

    let mut duplicate = fixture();
    let extra = task_mut(&mut duplicate, 0)["verification"]["steps"][0].clone();
    task_mut(&mut duplicate, 0)["verification"]["steps"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("steps array"))
        .push(extra);
    assert_code(&diagnostics(duplicate), DiagnosticCode::DuplicateId);
}
