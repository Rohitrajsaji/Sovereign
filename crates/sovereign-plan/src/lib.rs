//! Normative Plan IR v1.2 representation and deterministic validation.

mod compiler;
mod depth;
mod replan;

pub use compiler::{
    CompilationEvidence, CompilationEvidenceHandle, ControllerBindingEvidence,
    ControllerExternalIntelligenceBindingEvidence, GovernedEvaluatorRef, M3PlanningInput,
    ModelAttemptEvidence, PLAN_COMPILATION_SCHEMA_VERSION, PlanCompilationError,
    PlanCompilationInput, PlanCompilationRepository, PlanCompilationResult, PlanCompiler,
    PreauthorizedManualGate, SuppliedPlanningSourceKind, SuppliedPlanningSourceRef,
};
pub use depth::{DepthClassifier, DepthDecision, DepthFeatureInput, DepthFeatures, ExecutionDepth};
pub use replan::{
    PlanAssumption, PlanAssumptionEvidence, PlanReplanInput, PlanRevisionDiff, ReplanScope,
    smallest_replan_scope_tasks,
};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::path::{Component, Path};

const PLAN_SCHEMA: &str = include_str!("../../../schemas/plan-ir-v1.json");
pub const PLAN_IR_VERSION: &str = "1.2";

/// Candidate immutable Plan IR document. Authority is gained only after a
/// [`PlanValidator`] accepts it and the Controller activates it.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanIr {
    document: Value,
}

impl PlanIr {
    /// Parses a candidate Plan IR document without granting it execution
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns the underlying JSON parse error when `bytes` is not JSON.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes).map(|document| Self { document })
    }

    #[must_use]
    pub fn from_value(document: Value) -> Self {
        Self { document }
    }

    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.document
    }

    #[must_use]
    pub fn into_value(self) -> Value {
        self.document
    }

    /// Produces deterministic JSON bytes by recursively sorting object keys.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the canonical JSON value cannot be
    /// encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&canonicalize(&self.document))
    }

    /// Returns the SHA-256 of deterministic canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if canonical JSON encoding fails.
    pub fn canonical_digest(&self) -> Result<String, serde_json::Error> {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes()?);
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

/// Stable diagnostic categories returned by deterministic Plan validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticCode {
    Schema,
    DuplicateId,
    MissingReference,
    DependencyCycle,
    DependencyBinding,
    EvidenceContract,
    AcceptanceContract,
    PermissionPolicy,
    ResourcePolicy,
    IsolationUnavailable,
    DeadlinePolicy,
    ReconciliationPolicy,
    ExternalIntelligencePolicy,
    RevisionBudget,
    RollbackPolicy,
    FailureRouting,
}

impl DiagnosticCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "PLAN-SCHEMA",
            Self::DuplicateId => "PLAN-DUPLICATE-ID",
            Self::MissingReference => "PLAN-MISSING-REFERENCE",
            Self::DependencyCycle => "PLAN-DEPENDENCY-CYCLE",
            Self::DependencyBinding => "PLAN-DEPENDENCY-BINDING",
            Self::EvidenceContract => "PLAN-EVIDENCE-CONTRACT",
            Self::AcceptanceContract => "PLAN-ACCEPTANCE-CONTRACT",
            Self::PermissionPolicy => "PLAN-PERMISSION-POLICY",
            Self::ResourcePolicy => "PLAN-RESOURCE-POLICY",
            Self::IsolationUnavailable => "PLAN-ISOLATION-UNAVAILABLE",
            Self::DeadlinePolicy => "PLAN-DEADLINE-POLICY",
            Self::ReconciliationPolicy => "PLAN-RECONCILIATION-POLICY",
            Self::ExternalIntelligencePolicy => "PLAN-EXTERNAL-INTELLIGENCE-POLICY",
            Self::RevisionBudget => "PLAN-REVISION-BUDGET",
            Self::RollbackPolicy => "PLAN-ROLLBACK-POLICY",
            Self::FailureRouting => "PLAN-FAILURE-ROUTING",
        }
    }
}

impl Display for DiagnosticCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One deterministic validation failure. The JSON pointer path is advisory;
/// the stable code is intended for machine routing and test assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationDiagnostic {
    pub code: DiagnosticCode,
    pub path: String,
    pub message: String,
}

impl ValidationDiagnostic {
    fn new(code: DiagnosticCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Runtime capabilities that are external to a Plan IR candidate but must be
/// known before activation can be considered safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationEnvironment {
    pub untrusted_code_isolation_available: bool,
    pub max_context_tokens: u64,
}

impl Default for ValidationEnvironment {
    fn default() -> Self {
        Self {
            untrusted_code_isolation_available: true,
            max_context_tokens: 16_000,
        }
    }
}

/// Error returned when the frozen normative schema itself cannot be compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorBuildError(String);

impl Display for ValidatorBuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ValidatorBuildError {}

/// Deterministic structural and semantic gate for Plan IR v1.2.
pub struct PlanValidator {
    schema: jsonschema::Validator,
    environment: ValidationEnvironment,
}

impl PlanValidator {
    /// Compiles the embedded frozen Plan IR v1.2 schema with no remote/file
    /// resolver features enabled in the crate dependency.
    ///
    /// # Errors
    ///
    /// Returns [`ValidatorBuildError`] if the embedded schema cannot be parsed
    /// or compiled.
    pub fn new(environment: ValidationEnvironment) -> Result<Self, ValidatorBuildError> {
        let schema: Value = serde_json::from_str(PLAN_SCHEMA)
            .map_err(|error| ValidatorBuildError(format!("parse Plan IR schema: {error}")))?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|error| ValidatorBuildError(format!("compile Plan IR schema: {error}")))?;
        Ok(Self {
            schema: validator,
            environment,
        })
    }

    /// Runs normative structural validation followed by deterministic semantic
    /// validation. Structural failure short-circuits semantic traversal so a
    /// malformed document never reaches authority logic.
    #[must_use]
    pub fn validate(&self, plan: &PlanIr) -> Vec<ValidationDiagnostic> {
        let mut diagnostics: Vec<_> = self
            .schema
            .iter_errors(plan.as_value())
            .map(|error| {
                ValidationDiagnostic::new(
                    DiagnosticCode::Schema,
                    error.instance_path().to_string(),
                    error.to_string(),
                )
            })
            .collect();
        if !diagnostics.is_empty() {
            diagnostics.sort_by(|left, right| {
                (&left.path, &left.message).cmp(&(&right.path, &right.message))
            });
            return diagnostics;
        }

        validate_semantics(plan.as_value(), self.environment, &mut diagnostics);
        diagnostics.sort_by(|left, right| {
            (left.code, &left.path, &left.message).cmp(&(right.code, &right.path, &right.message))
        });
        diagnostics
    }

    #[must_use]
    pub fn is_valid(&self, plan: &PlanIr) -> bool {
        self.validate(plan).is_empty()
    }
}

fn validate_semantics(
    document: &Value,
    environment: ValidationEnvironment,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    validate_revision_budgets(document, diagnostics);
    let Some(tasks) = document.get("tasks").and_then(Value::as_array) else {
        return;
    };

    let requirements = string_id_set(document, "requirements", "requirement_id");
    let repositories = string_id_set(document, "repositories", "repository_id");
    let mut task_map: BTreeMap<&str, &Value> = BTreeMap::new();
    for (index, task) in tasks.iter().enumerate() {
        let Some(task_id) = task.get("task_id").and_then(Value::as_str) else {
            continue;
        };
        if task_map.insert(task_id, task).is_some() {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::DuplicateId,
                format!("/tasks/{index}/task_id"),
                format!("duplicate task id {task_id}"),
            ));
        }
    }

    validate_dependency_graph(tasks, &task_map, diagnostics);
    validate_edges(document, &task_map, diagnostics);

    let global_permissions = string_set_at(document, &["policy", "capability_ceiling"]);
    let global_resources = document.pointer("/policy/resources");
    for (index, task) in tasks.iter().enumerate() {
        let path = format!("/tasks/{index}");
        validate_task_references(
            task,
            &path,
            &task_map,
            &requirements,
            &repositories,
            diagnostics,
        );
        validate_evidence_and_acceptance(task, &path, diagnostics);
        validate_command_specs(task, &path, document, diagnostics);
        validate_permissions(task, &path, &global_permissions, document, diagnostics);
        validate_resources(task, &path, global_resources, environment, diagnostics);
        validate_deadlines(task, &path, diagnostics);
        validate_isolation(task, &path, environment, diagnostics);
        validate_rollback(task, &path, diagnostics);
        validate_failure_routing(task, &path, diagnostics);
    }
}

fn validate_command_specs(
    task: &Value,
    path: &str,
    document: &Value,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let task_tools = task
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tool| tool.get("id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let scoped_repositories = strings_at(task, &["scope", "repositories"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let task_permissions = strings_at(task, &["permissions"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let allowed_literal_env = strings_at(document, &["policy", "process", "allowed_env_names"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let shell_mode = document
        .pointer("/policy/process/shell_mode")
        .and_then(Value::as_str);
    let secret_refs = task
        .pointer("/action_policy/secret_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|secret| secret.get("secret_ref_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();

    for (index, step) in task
        .pointer("/verification/steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(command) = step.get("command_spec") else {
            continue;
        };
        let command_path = format!("{path}/verification/steps/{index}/command_spec");
        if !task_permissions.contains("process_exec") {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::PermissionPolicy,
                &command_path,
                "command verification requires process_exec permission",
            ));
        }
        if let Some(tool_id) = command.get("tool_id").and_then(Value::as_str)
            && !task_tools.contains(tool_id)
        {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::MissingReference,
                format!("{command_path}/tool_id"),
                format!("command tool {tool_id} does not resolve to one of task.tools"),
            ));
        }
        if let Some(repository_id) = command.get("repository_id").and_then(Value::as_str)
            && !scoped_repositories.contains(repository_id)
        {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::MissingReference,
                format!("{command_path}/repository_id"),
                format!("command repository {repository_id} is outside task scope"),
            ));
        }
        if command.get("mode").and_then(Value::as_str) == Some("shell_explicit")
            && shell_mode != Some("explicit_task_only")
        {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::PermissionPolicy,
                format!("{command_path}/mode"),
                "shell_explicit command is forbidden by the global process shell policy",
            ));
        }
        if let Some(literal_env) = command.get("literal_env").and_then(Value::as_object) {
            for name in literal_env.keys() {
                if !allowed_literal_env.contains(name.as_str()) {
                    diagnostics.push(ValidationDiagnostic::new(
                        DiagnosticCode::PermissionPolicy,
                        format!("{command_path}/literal_env/{name}"),
                        format!(
                            "literal environment name {name} is outside the global process policy"
                        ),
                    ));
                }
            }
        }
        if let Some(secret_env) = command.get("secret_env").and_then(Value::as_object) {
            for (name, secret_ref) in secret_env {
                if secret_ref
                    .as_str()
                    .is_none_or(|secret_ref| !secret_refs.contains(secret_ref))
                {
                    diagnostics.push(ValidationDiagnostic::new(
                        DiagnosticCode::MissingReference,
                        format!("{command_path}/secret_env/{name}"),
                        "command secret environment reference does not resolve to task action_policy.secret_refs",
                    ));
                }
            }
        }
    }
}

fn validate_revision_budgets(document: &Value, diagnostics: &mut Vec<ValidationDiagnostic>) {
    let retry = document.pointer("/policy/retry");
    let revision = u64_at(document, &["revision"]).unwrap_or(1);
    let supersedes = document.get("supersedes_revision").and_then(Value::as_u64);
    if revision > 1 && supersedes != revision.checked_sub(1) {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::RevisionBudget,
            "/supersedes_revision",
            "revision N>1 must directly supersede N-1 in the candidate lineage",
        ));
    }
    if let Some(max_revisions) = retry
        .and_then(|value| value.get("max_plan_revisions"))
        .and_then(Value::as_u64)
        && revision > max_revisions
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::RevisionBudget,
            "/revision",
            format!("revision {revision} exceeds max_plan_revisions {max_revisions}"),
        ));
    }
    // `max_replans_per_scope` is a lineage-history budget, not a property of a
    // standalone Plan IR document. The Controller enforces it from durable
    // revision-diff history for the exact affected scope. Treating `revision-1`
    // as one scope's replan count incorrectly rejects independent branch replans.
    let task_count = document
        .get("tasks")
        .and_then(Value::as_array)
        .map_or(0_u64, |tasks| {
            u64::try_from(tasks.len()).unwrap_or(u64::MAX)
        });
    if let Some(max_tasks) = retry
        .and_then(|value| value.get("max_tasks_per_revision"))
        .and_then(Value::as_u64)
        && task_count > max_tasks
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::RevisionBudget,
            "/tasks",
            format!("task count {task_count} exceeds max_tasks_per_revision {max_tasks}"),
        ));
    }
}

fn validate_dependency_graph<'a>(
    tasks: &'a [Value],
    task_map: &BTreeMap<&'a str, &'a Value>,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let mut indegree: BTreeMap<&str, usize> = task_map.keys().map(|id| (*id, 0)).collect();
    let mut outgoing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for (index, task) in tasks.iter().enumerate() {
        let Some(task_id) = task.get("task_id").and_then(Value::as_str) else {
            continue;
        };
        let mut seen = BTreeSet::new();
        for dependency in strings_at(task, &["dependencies"]) {
            if !seen.insert(dependency) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::DuplicateId,
                    format!("/tasks/{index}/dependencies"),
                    format!("dependency {dependency} is duplicated"),
                ));
                continue;
            }
            if !task_map.contains_key(dependency) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::MissingReference,
                    format!("/tasks/{index}/dependencies"),
                    format!("dependency {dependency} does not resolve"),
                ));
                continue;
            }
            if dependency == task_id {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::DependencyCycle,
                    format!("/tasks/{index}/dependencies"),
                    "task cannot depend on itself",
                ));
            }
            if let Some(value) = indegree.get_mut(task_id) {
                *value += 1;
            }
            outgoing.entry(dependency).or_default().push(task_id);
        }
    }

    let mut queue: VecDeque<&str> = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect();
    let mut visited = 0_usize;
    while let Some(id) = queue.pop_front() {
        visited += 1;
        for dependent in outgoing.get(id).into_iter().flatten() {
            if let Some(count) = indegree.get_mut(dependent) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    queue.push_back(dependent);
                }
            }
        }
    }
    if visited != task_map.len() {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::DependencyCycle,
            "/tasks",
            "hard dependency graph contains a cycle",
        ));
    }
}

fn validate_task_references<'a>(
    task: &'a Value,
    path: &str,
    task_map: &BTreeMap<&'a str, &'a Value>,
    requirements: &BTreeSet<&str>,
    repositories: &BTreeSet<&str>,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    for requirement in strings_at(task, &["requirement_ids"]) {
        if !requirements.contains(requirement) {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::MissingReference,
                format!("{path}/requirement_ids"),
                format!("requirement {requirement} does not resolve"),
            ));
        }
    }
    for repository in strings_at(task, &["scope", "repositories"]) {
        if !repositories.contains(repository) {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::MissingReference,
                format!("{path}/scope/repositories"),
                format!("repository {repository} does not resolve"),
            ));
        }
    }

    let dependencies: BTreeSet<_> = strings_at(task, &["dependencies"]).into_iter().collect();
    let Some(bindings) = task.get("dependency_bindings").and_then(Value::as_array) else {
        return;
    };
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (binding_index, binding) in bindings.iter().enumerate() {
        let Some(upstream_id) = binding.get("upstream_task_id").and_then(Value::as_str) else {
            continue;
        };
        *counts.entry(upstream_id).or_default() += 1;
        if !dependencies.contains(upstream_id) {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::DependencyBinding,
                format!("{path}/dependency_bindings/{binding_index}"),
                format!("binding for non-dependency {upstream_id}"),
            ));
        }
        let Some(upstream) = task_map.get(upstream_id) else {
            continue;
        };
        let artifacts: BTreeSet<_> = upstream
            .get("expected_artifacts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|item| item.get("required").and_then(Value::as_bool) == Some(true))
            .filter_map(|item| item.get("artifact_id").and_then(Value::as_str))
            .collect();
        for artifact in strings_at(binding, &["required_artifact_ids"]) {
            if !artifacts.contains(artifact) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::DependencyBinding,
                    format!("{path}/dependency_bindings/{binding_index}/required_artifact_ids"),
                    format!(
                        "artifact {artifact} is not a required output produced by {upstream_id}"
                    ),
                ));
            }
        }
        let criteria: BTreeSet<_> = upstream
            .get("acceptance_criteria")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|item| item.get("required").and_then(Value::as_bool) == Some(true))
            .filter_map(|item| item.get("criterion_id").and_then(Value::as_str))
            .collect();
        for criterion in strings_at(binding, &["required_acceptance_criterion_ids"]) {
            if !criteria.contains(criterion) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::DependencyBinding,
                    format!(
                        "{path}/dependency_bindings/{binding_index}/required_acceptance_criterion_ids"
                    ),
                    format!(
                        "criterion {criterion} is not a required accepted output owned by {upstream_id}"
                    ),
                ));
            }
        }
    }
    for dependency in dependencies {
        if counts.get(dependency).copied() != Some(1) {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::DependencyBinding,
                format!("{path}/dependency_bindings"),
                format!("dependency {dependency} requires exactly one binding"),
            ));
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_evidence_and_acceptance(
    task: &Value,
    path: &str,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let mut evidence_ids = BTreeSet::new();
    for (index, requirement) in task
        .get("evidence_requirements")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if let Some(id) = requirement.get("requirement_id").and_then(Value::as_str)
            && !evidence_ids.insert(id)
        {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::EvidenceContract,
                format!("{path}/evidence_requirements/{index}/requirement_id"),
                format!("duplicate evidence requirement id {id}"),
            ));
        }
        if requirement.get("satisfaction").and_then(Value::as_str) == Some("evaluator_pass") {
            let evaluator = requirement.get("evaluator").and_then(Value::as_str);
            if evaluator.is_none_or(|value| !governed_evaluator(value)) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::EvidenceContract,
                    format!("{path}/evidence_requirements/{index}/evaluator"),
                    "evaluator_pass requires a governed builtin or digest-pinned evaluator",
                ));
            }
        }
    }

    let mut steps = BTreeMap::<&str, &Value>::new();
    for (step_index, step) in task
        .pointer("/verification/steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(step_id) = step.get("step_id").and_then(Value::as_str) else {
            continue;
        };
        if steps.insert(step_id, step).is_some() {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::DuplicateId,
                format!("{path}/verification/steps/{step_index}/step_id"),
                format!("duplicate verification step {step_id}"),
            ));
        }
        if matches!(
            step.get("kind").and_then(Value::as_str),
            Some("assertion" | "diff")
        ) {
            let evaluator = step.get("evaluator").and_then(Value::as_str);
            if evaluator.is_none_or(|value| !governed_evaluator(value)) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/verification/steps/{step_index}/evaluator"),
                    "assertion/diff verification requires a governed builtin or digest-pinned evaluator",
                ));
            }
        }
    }
    let required_evidence: BTreeSet<_> =
        strings_at(task, &["verification", "required_evidence_types"])
            .into_iter()
            .collect();
    let required_artifacts: BTreeSet<_> = task
        .get("expected_artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|artifact| artifact.get("required").and_then(Value::as_bool) == Some(true))
        .filter_map(|artifact| artifact.get("artifact_id").and_then(Value::as_str))
        .collect();
    let mut criterion_ids = BTreeSet::new();
    let mut criteria_by_id = BTreeMap::<&str, &Value>::new();
    for (criterion_index, criterion) in task
        .get("acceptance_criteria")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(criterion_id) = criterion.get("criterion_id").and_then(Value::as_str) else {
            continue;
        };
        if !criterion_ids.insert(criterion_id) {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::DuplicateId,
                format!("{path}/acceptance_criteria/{criterion_index}/criterion_id"),
                format!("duplicate acceptance criterion {criterion_id}"),
            ));
        }
        criteria_by_id.insert(criterion_id, criterion);
        let evidence_type = criterion.get("evidence_type").and_then(Value::as_str);
        if criterion.get("required").and_then(Value::as_bool) == Some(true) {
            if let Some(kind) = evidence_type
                && !required_evidence.contains(kind)
            {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/verification/required_evidence_types"),
                    format!(
                        "required criterion {criterion_id} evidence type {kind} is not required"
                    ),
                ));
            }
            if strings_at(criterion, &["verification_step_ids"]).is_empty() {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/acceptance_criteria/{criterion_index}/verification_step_ids"),
                    format!("required criterion {criterion_id} has no verification step"),
                ));
            }
        }
        for step_id in strings_at(criterion, &["verification_step_ids"]) {
            let Some(step) = steps.get(step_id) else {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/acceptance_criteria/{criterion_index}/verification_step_ids"),
                    format!("verification step {step_id} does not resolve"),
                ));
                continue;
            };
            if !strings_at(step, &["criterion_ids"]).contains(&criterion_id) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/verification/steps"),
                    format!("verification step {step_id} does not bind criterion {criterion_id}"),
                ));
            }
            if step.get("evidence_type").and_then(Value::as_str) != evidence_type {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/verification/steps"),
                    format!(
                        "verification step {step_id} evidence type does not match {criterion_id}"
                    ),
                ));
            }
        }
    }

    for (step_id, step) in &steps {
        for criterion_id in strings_at(step, &["criterion_ids"]) {
            let Some(criterion) = criteria_by_id.get(criterion_id) else {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/verification/steps"),
                    format!(
                        "verification step {step_id} references missing criterion {criterion_id}"
                    ),
                ));
                continue;
            };
            if !strings_at(criterion, &["verification_step_ids"]).contains(step_id) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/verification/steps"),
                    format!(
                        "verification step {step_id} is not linked back from criterion {criterion_id}"
                    ),
                ));
            }
        }
        if step.get("kind").and_then(Value::as_str) == Some("artifact") {
            let artifact_id = step.get("artifact_id").and_then(Value::as_str);
            if artifact_id.is_none_or(|id| !required_artifacts.contains(id)) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::AcceptanceContract,
                    format!("{path}/verification/steps"),
                    format!(
                        "artifact verification step {step_id} must target a required expected artifact"
                    ),
                ));
            }
        }
    }
}

fn validate_permissions(
    task: &Value,
    path: &str,
    global_permissions: &BTreeSet<&str>,
    document: &Value,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let task_permissions: BTreeSet<_> = strings_at(task, &["permissions"]).into_iter().collect();
    for permission in &task_permissions {
        if !global_permissions.contains(permission) {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::PermissionPolicy,
                format!("{path}/permissions"),
                format!("task permission {permission} exceeds global capability ceiling"),
            ));
        }
    }
    if task
        .pointer("/action_policy/write_roots")
        .and_then(Value::as_array)
        .is_some_and(|roots| !roots.is_empty())
        && !task_permissions.contains("repo_write")
        && !task_permissions.contains("sandbox_write")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/write_roots"),
            "write roots require repo_write or sandbox_write permission",
        ));
    }
    if bool_at(task, &["action_policy", "packages", "allowed"]) == Some(true)
        && !task_permissions.contains("package_install")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/packages"),
            "package installation policy requires package_install permission",
        ));
    }
    let browser_allowed = bool_at(task, &["action_policy", "browser", "allowed"]) == Some(true);
    if browser_allowed && !task_permissions.contains("browser_interactive") {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/browser"),
            "browser use requires browser_interactive permission",
        ));
    }
    if browser_allowed {
        validate_browser_network_scope(task, path, document, &task_permissions, diagnostics);
    }
    if task
        .pointer("/action_policy/secret_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| !refs.is_empty())
        && !task_permissions.contains("secret_use")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/secret_refs"),
            "secret references require secret_use permission",
        ));
    }

    let network_methods = strings_at(task, &["action_policy", "network", "allowed_methods"]);
    let has_write_method = network_methods
        .iter()
        .any(|method| matches!(*method, "POST" | "PUT" | "PATCH" | "DELETE"));
    let has_read_method = network_methods
        .iter()
        .any(|method| matches!(*method, "GET" | "HEAD"));
    if has_read_method
        && !task_permissions.contains("network_read")
        && !task_permissions.contains("network_write")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/allowed_methods"),
            "network reads require network_read or network_write permission",
        ));
    }
    if has_write_method
        && !task_permissions.contains("network_write")
        && !task_permissions.contains("external_side_effect")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/allowed_methods"),
            "write-like network actions require network_write or external_side_effect permission",
        ));
    }
    if has_write_method && !has_reconciliation_route(task) {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ReconciliationPolicy,
            format!("{path}/next_state_rules"),
            "write-like network actions require unknown-action reconciliation",
        ));
    }

    validate_external_intelligence(task, path, document, &task_permissions, diagnostics);
}

fn validate_browser_network_scope(
    task: &Value,
    path: &str,
    document: &Value,
    task_permissions: &BTreeSet<&str>,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let task_hosts = strings_at(task, &["action_policy", "network", "allowed_hosts"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let global_hosts = strings_at(document, &["policy", "network", "allowed_hosts"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let task_schemes = strings_at(task, &["action_policy", "network", "allowed_schemes"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let global_schemes = strings_at(document, &["policy", "network", "allowed_schemes"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let task_ports = u64_set_at(task, &["action_policy", "network", "allowed_ports"]);
    let global_ports = u64_set_at(document, &["policy", "network", "allowed_ports"]);
    let browser_domains = strings_at(task, &["action_policy", "browser", "allowed_domains"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    let task_methods = strings_at(task, &["action_policy", "network", "allowed_methods"]);
    let global_methods = strings_at(document, &["policy", "network", "allowed_methods"])
        .into_iter()
        .collect::<BTreeSet<_>>();

    validate_browser_network_baseline(task, path, document, task_permissions, diagnostics);
    if browser_domains.is_empty() || browser_domains.iter().any(|domain| domain.contains('*')) {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/browser/allowed_domains"),
            "browser use requires explicit exact domains without wildcards",
        ));
    }
    if !task_methods
        .iter()
        .any(|method| matches!(*method, "GET" | "HEAD"))
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/allowed_methods"),
            "browser navigation requires GET or HEAD network authority",
        ));
    }
    if task_schemes.is_empty() || task_ports.is_empty() {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network"),
            "browser network scope requires exact allowed scheme and port sets",
        ));
    }
    if browser_domains
        .iter()
        .any(|domain| !task_hosts.contains(domain) || !global_hosts.contains(domain))
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/browser/allowed_domains"),
            "browser domains must be exact members of both task and global network host allowlists",
        ));
    }
    if task_schemes
        .iter()
        .any(|scheme| !global_schemes.contains(scheme))
        || task_ports.iter().any(|port| !global_ports.contains(port))
        || task_methods
            .iter()
            .any(|method| !global_methods.contains(method))
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network"),
            "browser task network scheme/port/method scope exceeds global network ceiling",
        ));
    }
    if bool_at(task, &["action_policy", "network", "allow_private_ranges"]) == Some(true) {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/allow_private_ranges"),
            "browser network policy cannot enable private ranges; use only an exact task-loopback grant",
        ));
    }
    validate_browser_loopback_scope(
        task,
        path,
        document,
        (&task_hosts, &global_hosts, &task_ports, &browser_domains),
        diagnostics,
    );
    validate_browser_download_scope(task, path, document, diagnostics);
}

fn validate_browser_download_scope(
    task: &Value,
    path: &str,
    document: &Value,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let global_mode = document
        .pointer("/policy/browser/downloads")
        .and_then(Value::as_str);
    let task_mode = task
        .pointer("/action_policy/browser/downloads")
        .and_then(Value::as_str);
    let root = task.pointer("/action_policy/browser/download_root");
    match task_mode {
        Some("deny") => {
            if root.is_some_and(|value| !value.is_null()) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::PermissionPolicy,
                    format!("{path}/action_policy/browser/download_root"),
                    "denied browser downloads cannot carry a download root",
                ));
            }
        }
        Some("task_scoped") => {
            if global_mode != Some("task_scoped") {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::PermissionPolicy,
                    format!("{path}/action_policy/browser/downloads"),
                    "task-scoped browser downloads exceed the global browser download ceiling",
                ));
            }
            let Some(root) = root.and_then(Value::as_str) else {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::PermissionPolicy,
                    format!("{path}/action_policy/browser/download_root"),
                    "task-scoped browser downloads require a strict relative download root",
                ));
                return;
            };
            if !is_strict_relative_normal_path(root) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::PermissionPolicy,
                    format!("{path}/action_policy/browser/download_root"),
                    "browser download root must be a non-empty strict relative path without traversal or special components",
                ));
            }
        }
        _ => {}
    }
}

fn is_strict_relative_normal_path(value: &str) -> bool {
    if value.trim().is_empty() || value.contains('\\') {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return false;
    }
    let path = Path::new(value);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return false;
    }
    value
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn validate_browser_network_baseline(
    task: &Value,
    path: &str,
    document: &Value,
    task_permissions: &BTreeSet<&str>,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    if !task_permissions.contains("network_read") && !task_permissions.contains("network_write") {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/permissions"),
            "browser navigation requires network_read or network_write permission",
        ));
    }
    if task
        .pointer("/action_policy/network/default")
        .and_then(Value::as_str)
        == Some("offline")
        || document
            .pointer("/policy/network/default")
            .and_then(Value::as_str)
            == Some("offline")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/default"),
            "browser use requires explicit non-offline task and global network policy",
        ));
    }
}

fn validate_browser_loopback_scope(
    task: &Value,
    path: &str,
    document: &Value,
    scope: (
        &BTreeSet<&str>,
        &BTreeSet<&str>,
        &BTreeSet<u64>,
        &BTreeSet<&str>,
    ),
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let (task_hosts, global_hosts, task_ports, browser_domains) = scope;
    let task_loopback =
        bool_at(task, &["action_policy", "network", "allow_task_loopback"]) == Some(true);
    let global_loopback =
        bool_at(document, &["policy", "network", "allow_task_loopback"]) == Some(true);
    let has_loopback_alias = browser_domains
        .iter()
        .any(|host| is_loopback_hostname_alias(host));
    if has_loopback_alias {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/browser/allowed_domains"),
            "browser loopback scope requires an exact loopback IP literal, not a hostname alias",
        ));
    }
    let browser_uses_loopback = browser_domains
        .iter()
        .any(|host| is_exact_loopback_host(host));
    if browser_uses_loopback && !task_loopback {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/allow_task_loopback"),
            "loopback browser domain requires explicit task-loopback authority",
        ));
    }
    if !task_loopback {
        return;
    }
    if !global_loopback {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/allow_task_loopback"),
            "task loopback authority exceeds the global network ceiling",
        ));
    }
    let loopback_hosts = task_hosts
        .iter()
        .filter(|host| is_exact_loopback_host(host))
        .copied()
        .collect::<BTreeSet<_>>();
    if loopback_hosts.is_empty() || task_ports.is_empty() {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network"),
            "task loopback authority requires an exact loopback IP literal and exact port",
        ));
    }
    if loopback_hosts
        .iter()
        .any(|host| !global_hosts.contains(host))
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::PermissionPolicy,
            format!("{path}/action_policy/network/allowed_hosts"),
            "task loopback host exceeds the global exact-host ceiling",
        ));
    }
}

fn is_loopback_hostname_alias(host: &str) -> bool {
    let canonical = host.trim_end_matches('.').to_ascii_lowercase();
    canonical == "localhost" || canonical.ends_with(".localhost")
}

fn is_exact_loopback_host(host: &str) -> bool {
    let literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let Ok(address) = literal.parse::<IpAddr>() else {
        return false;
    };
    if !address.is_loopback() {
        return false;
    }
    match address {
        IpAddr::V4(address) => host == address.to_string(),
        IpAddr::V6(address) => host == format!("[{address}]"),
    }
}

fn u64_set_at(value: &Value, path: &[&str]) -> BTreeSet<u64> {
    let mut current = value;
    for component in path {
        let Some(next) = current.get(*component) else {
            return BTreeSet::new();
        };
        current = next;
    }
    current
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect()
}

fn validate_external_intelligence(
    task: &Value,
    path: &str,
    document: &Value,
    task_permissions: &BTreeSet<&str>,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let Some(task_policy) = task.pointer("/action_policy/external_intelligence") else {
        return;
    };
    let allowed = task_policy.get("allowed").and_then(Value::as_bool) == Some(true);
    let task_providers: BTreeSet<_> = strings_at(task_policy, &["allowed_providers"])
        .into_iter()
        .collect();
    let global_providers: BTreeSet<_> = strings_at(
        document,
        &["policy", "external_intelligence", "allowed_providers"],
    )
    .into_iter()
    .collect();

    if allowed && !task_permissions.contains("external_intelligence") {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ExternalIntelligencePolicy,
            format!("{path}/action_policy/external_intelligence"),
            "external intelligence requires external_intelligence permission",
        ));
    }
    if task_providers
        .iter()
        .any(|provider| !global_providers.contains(provider))
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ExternalIntelligencePolicy,
            format!("{path}/action_policy/external_intelligence/allowed_providers"),
            "task external provider set exceeds global provider ceiling",
        ));
    }
    let max_payload_bytes = u64_at(task_policy, &["max_payload_bytes"]).unwrap_or(0);
    let task_network_bytes = u64_at(task, &["resource_budget", "max_network_bytes"]);
    let global_network_bytes = u64_at(document, &["policy", "resources", "max_network_bytes"]);
    if task_network_bytes.is_some_and(|ceiling| max_payload_bytes > ceiling)
        || global_network_bytes.is_some_and(|ceiling| max_payload_bytes > ceiling)
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ExternalIntelligencePolicy,
            format!("{path}/action_policy/external_intelligence/max_payload_bytes"),
            "external-intelligence payload ceiling exceeds task/global network-byte budget",
        ));
    }
    if task_policy
        .get("whole_repository_export")
        .and_then(Value::as_str)
        == Some("explicit_grant_only")
        && document
            .pointer("/policy/external_intelligence/raw_repository_export")
            .and_then(Value::as_str)
            != Some("explicit_grant_only")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ExternalIntelligencePolicy,
            format!("{path}/action_policy/external_intelligence/whole_repository_export"),
            "task whole-repository export exceeds global export ceiling",
        ));
    }
    if !allowed
        && (!task_providers.is_empty()
            || !strings_at(task_policy, &["allowed_data_classes"]).is_empty()
            || u64_at(task_policy, &["max_payload_bytes"]).unwrap_or(0) > 0)
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ExternalIntelligencePolicy,
            format!("{path}/action_policy/external_intelligence"),
            "disabled external intelligence must not retain provider/data/payload scope",
        ));
    }
}

fn validate_resources(
    task: &Value,
    path: &str,
    global_resources: Option<&Value>,
    environment: ValidationEnvironment,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    let Some(task_resources) = task.get("resource_budget") else {
        return;
    };
    let has_command_verification = task
        .pointer("/verification/steps")
        .and_then(Value::as_array)
        .is_some_and(|steps| {
            steps
                .iter()
                .any(|step| step.get("kind").and_then(Value::as_str) == Some("command"))
        });
    let task_heavy_leases = strings_at(task_resources, &["heavy_leases"])
        .into_iter()
        .collect::<BTreeSet<_>>();
    if bool_at(task, &["action_policy", "browser", "allowed"]) == Some(true)
        && !task_heavy_leases.contains("BROWSER")
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ResourcePolicy,
            format!("{path}/resource_budget/heavy_leases"),
            "browser use requires BROWSER task resource authority",
        ));
    }
    if has_command_verification && !task_heavy_leases.contains("BUILD_HEAVY") {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ResourcePolicy,
            format!("{path}/resource_budget/heavy_leases"),
            "command verification requires BUILD_HEAVY task resource authority",
        ));
    }
    let scalar_fields = [
        "max_wall_seconds",
        "max_model_calls",
        "max_model_call_seconds",
        "max_tool_actions",
        "max_single_tool_action_seconds",
        "max_peak_rss_mb",
        "max_output_bytes",
        "max_retained_raw_bytes",
        "max_disk_write_mb",
        "max_network_bytes",
        "max_subprocesses",
        "max_child_cpu_seconds",
    ];
    if let Some(global) = global_resources {
        for field in scalar_fields {
            if let (Some(task_value), Some(global_value)) = (
                task_resources.get(field).and_then(Value::as_u64),
                global.get(field).and_then(Value::as_u64),
            ) && task_value > global_value
            {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::ResourcePolicy,
                    format!("{path}/resource_budget/{field}"),
                    format!("task budget {task_value} exceeds global ceiling {global_value}"),
                ));
            }
        }
        let global_leases: BTreeSet<_> =
            strings_at(global, &["heavy_leases"]).into_iter().collect();
        for lease in strings_at(task_resources, &["heavy_leases"]) {
            if !global_leases.contains(lease) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::ResourcePolicy,
                    format!("{path}/resource_budget/heavy_leases"),
                    format!("task heavy lease {lease} exceeds global resource ceiling"),
                ));
            }
        }
    }
    if let Some(tokens) = u64_at(task, &["context_budget", "max_input_tokens"])
        && tokens > environment.max_context_tokens
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::ResourcePolicy,
            format!("{path}/context_budget/max_input_tokens"),
            format!(
                "context budget {tokens} exceeds active hardware ceiling {}",
                environment.max_context_tokens
            ),
        ));
    }
}

fn validate_deadlines(task: &Value, path: &str, diagnostics: &mut Vec<ValidationDiagnostic>) {
    let task_tool_limit =
        u64_at(task, &["resource_budget", "max_single_tool_action_seconds"]).unwrap_or(u64::MAX);
    for (index, step) in task
        .pointer("/verification/steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if let Some(timeout) = u64_at(step, &["command_spec", "timeout_seconds"])
            && timeout > task_tool_limit
        {
            diagnostics.push(ValidationDiagnostic::new(
                DiagnosticCode::DeadlinePolicy,
                format!("{path}/verification/steps/{index}/command_spec/timeout_seconds"),
                format!("command timeout {timeout} exceeds task action deadline {task_tool_limit}"),
            ));
        }
    }
}

fn validate_isolation(
    task: &Value,
    path: &str,
    environment: ValidationEnvironment,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    if environment.untrusted_code_isolation_available {
        return;
    }
    let executes_untrusted = task
        .pointer("/verification/steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|step| {
            step.pointer("/command_spec/program")
                .and_then(Value::as_str)
        })
        .any(program_may_execute_untrusted_code)
        || bool_at(task, &["action_policy", "packages", "allowed"]) == Some(true)
        || bool_at(task, &["action_policy", "browser", "allowed"]) == Some(true);
    if executes_untrusted {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::IsolationUnavailable,
            path,
            "task may execute untrusted repository/package/browser code but no enforceable isolation backend is available",
        ));
    }
}

fn validate_rollback(task: &Value, path: &str, diagnostics: &mut Vec<ValidationDiagnostic>) {
    let permissions: BTreeSet<_> = strings_at(task, &["permissions"]).into_iter().collect();
    let mutating = permissions.iter().any(|permission| {
        matches!(
            *permission,
            "sandbox_write"
                | "repo_write"
                | "package_install"
                | "network_write"
                | "external_side_effect"
                | "destructive"
        )
    });
    let mode = task.pointer("/rollback/mode").and_then(Value::as_str);
    if mutating && mode == Some("none") {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::RollbackPolicy,
            format!("{path}/rollback/mode"),
            "mutating task cannot declare rollback mode none",
        ));
    }
    if mode != Some("none")
        && task
            .pointer("/rollback/verification_steps")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::RollbackPolicy,
            format!("{path}/rollback/verification_steps"),
            "non-none rollback requires typed verification evidence",
        ));
    }
    for (index, step) in task
        .pointer("/rollback/verification_steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        if matches!(
            step.get("kind").and_then(Value::as_str),
            Some("assertion" | "diff")
        ) {
            let evaluator = step.get("evaluator").and_then(Value::as_str);
            if evaluator.is_none_or(|value| !governed_evaluator(value)) {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::RollbackPolicy,
                    format!("{path}/rollback/verification_steps/{index}/evaluator"),
                    "rollback assertion/diff requires a governed builtin or digest-pinned evaluator",
                ));
            }
        }
    }
}

fn governed_evaluator(value: &str) -> bool {
    if let Some(version) = value
        .strip_prefix("builtin.")
        .and_then(|rest| rest.rsplit_once(".v"))
    {
        return !version.0.is_empty()
            && !version.1.is_empty()
            && version
                .1
                .chars()
                .all(|character| character.is_ascii_digit());
    }
    let Some(rest) = value.strip_prefix("governed:") else {
        return false;
    };
    let Some((identity, digest)) = rest.rsplit_once('#') else {
        return false;
    };
    let Some((evaluator_id, version)) = identity.rsplit_once('@') else {
        return false;
    };
    !evaluator_id.is_empty()
        && !version.is_empty()
        && digest.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
        })
}

fn validate_failure_routing(task: &Value, path: &str, diagnostics: &mut Vec<ValidationDiagnostic>) {
    let max_attempts = u64_at(task, &["failure_policy", "max_attempts"]).unwrap_or(0);
    let same_failure = u64_at(task, &["failure_policy", "same_failure_limit"]).unwrap_or(0);
    if same_failure > max_attempts {
        diagnostics.push(ValidationDiagnostic::new(
            DiagnosticCode::FailureRouting,
            format!("{path}/failure_policy/same_failure_limit"),
            "same_failure_limit cannot exceed max_attempts",
        ));
    }

    let mappings = [
        ("execution_failure", "on_execution_failure"),
        ("plan_failure", "on_plan_failure"),
        ("resource_exhausted", "on_resource_failure"),
        ("unknown_action", "on_unknown_action"),
    ];
    for (event, policy_field) in mappings {
        let expected = task
            .pointer(&format!("/failure_policy/{policy_field}"))
            .and_then(Value::as_str);
        for rule in task
            .get("next_state_rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|rule| rule.get("event").and_then(Value::as_str) == Some(event))
        {
            let actual = rule.get("transition").and_then(Value::as_str);
            if actual != expected {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::FailureRouting,
                    format!("{path}/next_state_rules"),
                    format!(
                        "{event} transition {actual:?} contradicts failure_policy {policy_field}={expected:?}"
                    ),
                ));
            }
        }
    }
}

fn validate_edges(
    document: &Value,
    task_map: &BTreeMap<&str, &Value>,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    for (index, edge) in document
        .get("edges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        for endpoint in ["from", "to"] {
            if let Some(id) = edge.get(endpoint).and_then(Value::as_str)
                && !task_map.contains_key(id)
            {
                diagnostics.push(ValidationDiagnostic::new(
                    DiagnosticCode::MissingReference,
                    format!("/edges/{index}/{endpoint}"),
                    format!("edge endpoint {id} does not resolve to a task"),
                ));
            }
        }
    }
}

fn has_reconciliation_route(task: &Value) -> bool {
    task.pointer("/failure_policy/on_unknown_action")
        .and_then(Value::as_str)
        == Some("reconcile")
        && task
            .get("next_state_rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|rule| {
                rule.get("event").and_then(Value::as_str) == Some("unknown_action")
                    && rule.get("transition").and_then(Value::as_str) == Some("reconcile")
            })
}

fn program_may_execute_untrusted_code(program: &str) -> bool {
    let basename = program.rsplit('/').next().unwrap_or(program);
    matches!(
        basename,
        "npm"
            | "npx"
            | "pnpm"
            | "yarn"
            | "node"
            | "cargo"
            | "rustc"
            | "python"
            | "python3"
            | "pytest"
            | "mvn"
            | "gradle"
            | "gradlew"
            | "make"
            | "cmake"
            | "bash"
            | "sh"
            | "zsh"
    )
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let mut canonical = Map::new();
            for (key, value) in entries {
                canonical.insert(key.clone(), canonicalize(value));
            }
            Value::Object(canonical)
        }
        _ => value.clone(),
    }
}

fn strings_at<'a>(value: &'a Value, path: &[&str]) -> Vec<&'a str> {
    value_at(value, path)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn string_set_at<'a>(value: &'a Value, path: &[&str]) -> BTreeSet<&'a str> {
    strings_at(value, path).into_iter().collect()
}

fn string_id_set<'a>(value: &'a Value, collection: &str, field: &str) -> BTreeSet<&'a str> {
    value
        .get(collection)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get(field).and_then(Value::as_str))
        .collect()
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, segment| current.get(*segment))
}

fn u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    value_at(value, path).and_then(Value::as_u64)
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path).and_then(Value::as_bool)
}
