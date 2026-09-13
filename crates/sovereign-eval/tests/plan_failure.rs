use serde_json::{Value, json};
use sovereign_controller::{
    FailureClassificationKind, FailureClassifier, StableContractInvalidation,
};
use sovereign_plan::{PlanRevisionDiff, ReplanScope, smallest_replan_scope_tasks};

fn task(task_id: &str, dependencies: &[&str]) -> Value {
    json!({
        "task_id": task_id,
        "dependencies": dependencies,
        "dependency_bindings": dependencies.iter().map(|upstream| json!({
            "upstream_task_id": upstream,
            "required_artifact_ids": [format!("artifact.{upstream}")],
            "required_acceptance_criterion_ids": [format!("AC.{upstream}")],
            "freshness": "carry_forward_if_inputs_unchanged"
        })).collect::<Vec<_>>(),
        "implementation_contract": {
            "preconditions": [],
            "assumptions": [],
            "inputs": [format!("input:{task_id}")],
            "outputs": [format!("output:{task_id}")],
            "invariants": []
        },
        "acceptance_criteria": [{
            "criterion_id": format!("AC.{task_id}"),
            "description": "accepted",
            "kind": "artifact",
            "verification_step_ids": [format!("verify.{task_id}")],
            "evidence_type": "artifact_result",
            "evidence_freshness": "carry_forward_if_inputs_unchanged",
            "required": true
        }],
        "expected_artifacts": [{
            "artifact_id": format!("artifact.{task_id}"),
            "kind": "evidence",
            "locator": "fixture",
            "required": true
        }]
    })
}

fn plan() -> Value {
    let mut p1 = task("P1", &[]);
    p1["implementation_contract"]["assumptions"] = json!([{
        "assumption_id": "ASSUME.api-exists",
        "text": "The planned API exists at the observed source locator.",
        "invalidation_scope": "task",
        "basis_evidence": [{
            "evidence_id": "ev.api.old",
            "digest": "sha256:old",
            "locator": "path:src/api.rs",
            "trust": "observed",
            "freshness": "fixture"
        }],
        "fingerprints": ["sha256:old"]
    }]);
    let p2 = task("P2", &["P1"]);
    let p3 = task("P3", &[]);
    let p4 = task("P4", &["P2"]);
    json!({
        "plan_id": "plan.fixture",
        "revision": 1,
        "supersedes_revision": Value::Null,
        "tasks": [p1, p2, p3, p4]
    })
}

#[test]
fn compiler_test_runtime_failure_without_verified_clause_stays_execution_failure() {
    let classification = FailureClassifier::classify_verified(&plan(), "P2", &[])
        .unwrap_or_else(|error| panic!("classification: {error}"));
    assert_eq!(
        classification.kind,
        FailureClassificationKind::ExecutionFailure
    );
    assert!(classification.scope.is_none());
    assert!(classification.affected_task_ids.is_empty());
}

#[test]
fn missing_planned_api_with_changed_stable_fingerprint_triggers_task_replan() {
    let classification = FailureClassifier::classify_verified(
        &plan(),
        "P1",
        &[StableContractInvalidation {
            contract_id: "ASSUME.api-exists".to_owned(),
            evidence_refs: vec!["ev.api.current".to_owned()],
            observed_fingerprints: vec!["sha256:new".to_owned()],
        }],
    )
    .unwrap_or_else(|error| panic!("classification: {error}"));
    assert_eq!(classification.kind, FailureClassificationKind::PlanFailure);
    assert_eq!(classification.scope, Some(ReplanScope::Task));
    assert_eq!(classification.affected_task_ids, vec!["P1"]);
}

#[test]
fn unchanged_assumption_fingerprint_cannot_be_promoted_to_plan_failure() {
    let Err(error) = FailureClassifier::classify_verified(
        &plan(),
        "P1",
        &[StableContractInvalidation {
            contract_id: "ASSUME.api-exists".to_owned(),
            evidence_refs: vec!["ev.api.current".to_owned()],
            observed_fingerprints: vec!["sha256:old".to_owned()],
        }],
    ) else {
        panic!("unchanged fingerprint must remain execution failure authority-wise");
    };
    assert!(error.to_string().contains("not falsified"));
}

#[test]
fn changed_producer_binding_replans_exact_descendant_branch_and_preserves_unrelated_branch() {
    let classification = FailureClassifier::classify_verified(
        &plan(),
        "P2",
        &[StableContractInvalidation {
            contract_id: "binding:P2:P1".to_owned(),
            evidence_refs: vec!["binding-proof".to_owned()],
            observed_fingerprints: Vec::new(),
        }],
    )
    .unwrap_or_else(|error| panic!("classification: {error}"));
    assert_eq!(classification.scope, Some(ReplanScope::DependencyBranch));
    assert_eq!(classification.affected_task_ids, vec!["P1", "P2", "P4"]);
    assert!(!classification.affected_task_ids.contains(&"P3".to_owned()));
}

#[test]
fn smallest_scope_is_computed_only_from_dependencies_dag() {
    assert_eq!(
        smallest_replan_scope_tasks(&plan(), "P1", ReplanScope::DependencyBranch)
            .unwrap_or_else(|error| panic!("scope: {error}")),
        vec!["P1", "P2", "P4"]
    );
    assert_eq!(
        smallest_replan_scope_tasks(&plan(), "P2", ReplanScope::Task)
            .unwrap_or_else(|error| panic!("scope: {error}")),
        vec!["P2"]
    );
}

#[test]
fn revision_diff_rejects_matching_ids_when_authorized_affected_contract_was_not_replanned() {
    let previous = plan();
    let mut next = previous.clone();
    next["revision"] = json!(2);
    next["supersedes_revision"] = json!(1);
    let Err(error) = PlanRevisionDiff::between(
        &previous,
        &next,
        ReplanScope::Task,
        &["ASSUME.api-exists".to_owned()],
        &["P1".to_owned()],
    ) else {
        panic!("matching task id alone must not satisfy supersession");
    };
    assert!(error.contains("affected tasks unchanged"));
}

#[test]
fn revision_diff_rejects_changes_to_unaffected_branch() {
    let previous = plan();
    let mut next = previous.clone();
    next["revision"] = json!(2);
    next["supersedes_revision"] = json!(1);
    next["tasks"][0]["implementation_contract"]["outputs"] = json!(["corrected P1"]);
    next["tasks"][2]["implementation_contract"]["outputs"] = json!(["illicit P3 change"]);
    let Err(error) = PlanRevisionDiff::between(
        &previous,
        &next,
        ReplanScope::Task,
        &["ASSUME.api-exists".to_owned()],
        &["P1".to_owned()],
    ) else {
        panic!("unaffected P3 must remain immutable");
    };
    assert!(error.contains("unaffected task P3"));
}

#[test]
fn plan_invariant_resolves_to_full_plan_scope_but_runtime_authority_still_requires_controller_revalidation()
 {
    let mut document = plan();
    document["tasks"][1]["implementation_contract"]["invariants"] = json!([{
        "clause_id": "INV.architecture-root",
        "text": "The root architecture invariant remains true."
    }]);
    let classification = FailureClassifier::classify_verified(
        &document,
        "P2",
        &[StableContractInvalidation {
            contract_id: "INV.architecture-root".to_owned(),
            evidence_refs: vec!["verified-controller-evidence".to_owned()],
            observed_fingerprints: Vec::new(),
        }],
    )
    .unwrap_or_else(|error| panic!("classification: {error}"));
    assert_eq!(classification.scope, Some(ReplanScope::Plan));
    assert_eq!(
        classification.affected_task_ids,
        vec!["P1", "P2", "P3", "P4"]
    );
}

#[test]
fn dependency_branch_replan_rejects_disconnected_new_task() {
    let previous = plan();
    let mut next = previous.clone();
    next["revision"] = json!(2);
    next["supersedes_revision"] = json!(1);
    for index in [0_usize, 1, 3] {
        next["tasks"][index]["implementation_contract"]["outputs"] =
            json!([format!("replanned-{index}")]);
    }
    next["tasks"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("tasks array"))
        .push(task("P5", &[]));
    let Err(error) = PlanRevisionDiff::between(
        &previous,
        &next,
        ReplanScope::DependencyBranch,
        &["binding:P2:P1".to_owned()],
        &["P1".to_owned(), "P2".to_owned(), "P4".to_owned()],
    ) else {
        panic!("disconnected new task must not widen a dependency-branch replan");
    };
    assert!(error.contains("outside the affected branch"));
}

#[test]
fn dependency_branch_replan_rejects_sibling_added_through_unaffected_upstream() {
    let previous = plan();
    let mut next = previous.clone();
    next["revision"] = json!(2);
    next["supersedes_revision"] = json!(1);
    for index in [1_usize, 3] {
        next["tasks"][index]["implementation_contract"]["outputs"] =
            json!([format!("replanned-{index}")]);
    }
    next["tasks"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("tasks array"))
        .push(task("P2b", &["P1"]));
    let Err(error) = PlanRevisionDiff::between(
        &previous,
        &next,
        ReplanScope::DependencyBranch,
        &["binding:P4:P2".to_owned()],
        &["P2".to_owned(), "P4".to_owned()],
    ) else {
        panic!("unaffected upstream P1 must not bridge a sibling task into the replanned branch");
    };
    assert!(error.contains("outside the affected branch"));
}

#[test]
fn dependency_branch_replan_allows_connected_split_task() {
    let previous = plan();
    let mut next = previous.clone();
    next["revision"] = json!(2);
    next["supersedes_revision"] = json!(1);
    for index in [0_usize, 1, 3] {
        next["tasks"][index]["implementation_contract"]["outputs"] =
            json!([format!("replanned-{index}")]);
    }
    next["tasks"][3]["dependencies"] = json!(["P2", "P2b"]);
    next["tasks"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("tasks array"))
        .push(task("P2b", &["P1"]));
    let diff = PlanRevisionDiff::between(
        &previous,
        &next,
        ReplanScope::DependencyBranch,
        &["binding:P2:P1".to_owned()],
        &["P1".to_owned(), "P2".to_owned(), "P4".to_owned()],
    )
    .unwrap_or_else(|error| panic!("connected split must remain in branch: {error}"));
    assert_eq!(diff.added_task_ids, vec!["P2b"]);
}
