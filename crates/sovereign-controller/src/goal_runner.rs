use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sovereign_plan::{BrowserAcceptanceContractV1, PlanCompilationResult};
use sovereign_repo::ProjectRegistry;
use sovereign_state::{
    NewJournalEvent, PersistedStateRecord, StateRecordCasAssertion, StateRecordCasMutation,
    StateStore,
};
use std::collections::BTreeMap;

use super::{
    ActivationSummary, CompletionRecordV1, Controller, ControllerError, GOAL_INTENT_SCHEMA_VERSION,
    GoalBrowserGrantV1, GoalIntentV1, completion_record_key, digest_json, required_str,
    required_u32, revision_record_key, sha256_prefixed, validate_completion_publication_event,
};

const GOAL_INTENT_NAMESPACE: &str = "controller.goal_intent";
const GOAL_INTENT_CLAIM_NAMESPACE: &str = "controller.goal_intent_claim";
const GOAL_INTENT_CLAIM_SCHEMA_VERSION: u32 = 1;
const PLAN_FINALIZATION_NAMESPACE: &str = "controller.plan_finalization";
const PLAN_FINALIZATION_SCHEMA_VERSION: u32 = 1;

const GOAL_STATUS_QUEUED: &str = "queued_for_plan_compilation";
const GOAL_STATUS_CLAIMED: &str = "claimed_for_plan_compilation";
const GOAL_STATUS_ACTIVE: &str = "active_plan";
const GOAL_STATUS_COMPLETED: &str = "completed";
const GOAL_STATUS_CANCELLED: &str = "cancelled_before_dispatch";
/// Terminal: the goal could not be planned or a step failed for good.
const GOAL_STATUS_FAILED: &str = "failed";
/// Terminal: the user cancelled the goal after its plan was activated.
const GOAL_STATUS_CANCELLED_ACTIVE: &str = "cancelled";

pub(crate) const GOAL_OUTCOME_NAMESPACE: &str = "controller.goal_outcome";
const GOAL_OUTCOME_SCHEMA_VERSION: u32 = 1;
const PLAN_ABANDONMENT_NAMESPACE: &str = "controller.plan_abandonment";
const PLAN_ABANDONMENT_SCHEMA_VERSION: u32 = 1;
const MAX_GOAL_OUTCOME_DETAIL_BYTES: usize = 2_048;

/// Reason codes recorded in [`GoalOutcomeV1::reason_code`].
pub const GOAL_REASON_COMPILATION_FAILED: &str = "compilation_failed";
pub const GOAL_REASON_COMPILATION_BUDGET_EXHAUSTED: &str = "compilation_budget_exhausted";
pub const GOAL_REASON_TASK_FAILED: &str = "task_failed";
pub const GOAL_REASON_CANCELLED_BY_USER: &str = "cancelled_by_user";
pub const GOAL_REASON_COMPOSITION_ERROR: &str = "composition_error";

/// Revalidates the active goal's durable browser grant against its canonical Plan and
/// compilation evidence. A missing grant is returned only when the active Plan has no browser
/// binding; inconsistent authority fails closed.
#[expect(
    clippy::too_many_lines,
    reason = "durable browser grant checks all current-plan and evidence bindings together"
)]
pub(crate) fn durable_browser_grant_for_plan(
    state: &StateStore,
    plan_document: &Value,
) -> Result<Option<GoalBrowserGrantV1>, ControllerError> {
    let plan_has_browser_authority = plan_document
        .get("tasks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|task| {
            task.get("browser_acceptance")
                .is_some_and(|value| !value.is_null())
                || task
                    .get("permissions")
                    .and_then(Value::as_array)
                    .is_some_and(|permissions| {
                        permissions.iter().any(|permission| {
                            matches!(
                                permission.as_str(),
                                Some("browser_interactive" | "network_read" | "network_write")
                            )
                        })
                    })
        });
    if !plan_has_browser_authority {
        return Ok(None);
    }
    let goal_id = required_str(plan_document, "/goal/goal_id")?;
    let plan_id = required_str(plan_document, "/plan_id")?;
    let plan_revision = required_u32(plan_document, "/revision")?;
    let plan_digest = digest_json(plan_document)?;
    let Some(intent_row) = state
        .state_records(GOAL_INTENT_NAMESPACE)?
        .into_iter()
        .find(|record| record.key == goal_id)
    else {
        return Ok(None);
    };
    let intent = decode_versioned_goal_intent(&intent_row)?;
    if intent.status == GOAL_STATUS_COMPLETED {
        return Ok(None);
    }
    if intent.status != GOAL_STATUS_ACTIVE {
        return Err(ControllerError::InvalidPlan(
            "active browser grant goal intent is not active".to_owned(),
        ));
    }
    let claim_row = state
        .state_records(GOAL_INTENT_CLAIM_NAMESPACE)?
        .into_iter()
        .find(|record| record.key == goal_id)
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "active goal is missing its durable compilation claim".to_owned(),
            )
        })?;
    let claim = decode_versioned_goal_claim(&claim_row)?;
    if claim.status != GoalIntentClaimStatusV1::Active
        || claim.plan_id != plan_id
        || claim.plan_revision != plan_revision
        || claim.plan_digest != plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "active goal claim does not bind the canonical plan".to_owned(),
        ));
    }
    let evidence_key = revision_record_key(plan_id, plan_revision);
    let evidence_json = state
        .get_state("controller.compilation_evidence", &evidence_key)?
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "active goal is missing durable compilation evidence".to_owned(),
            )
        })?;
    let evidence: Value = serde_json::from_str(&evidence_json)?;
    if digest_json(&evidence)? != claim.compilation_evidence_digest {
        return Err(ControllerError::InvalidPlan(
            "active goal compilation evidence digest does not match its claim".to_owned(),
        ));
    }
    let binding_digests = evidence
        .pointer("/controller_browser_loopback_bindings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|binding| binding.get("goal_browser_grant_digest"))
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    match intent.browser_grant {
        Some(grant) => {
            let grant_digest = digest_json(&serde_json::to_value(&grant)?)?;
            if !binding_digests.contains(&grant_digest.as_str()) {
                return Err(ControllerError::InvalidPlan(
                    "active Plan browser authority is not bound to its exact durable goal grant"
                        .to_owned(),
                ));
            }
            let browser_contracts = plan_document
                .get("tasks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|task| task.get("browser_acceptance"))
                .filter(|contract| !contract.is_null())
                .collect::<Vec<_>>();
            let [contract_value] = browser_contracts.as_slice() else {
                return Err(ControllerError::InvalidPlan(
                    "durable browser grant must bind exactly one browser acceptance contract"
                        .to_owned(),
                ));
            };
            let contract: BrowserAcceptanceContractV1 =
                serde_json::from_value((*contract_value).clone())?;
            contract
                .validate()
                .map_err(|error| ControllerError::InvalidPlan(error.to_string()))?;
            if contract.launch != grant.acceptance.launch
                || contract.steps != grant.acceptance.steps
            {
                return Err(ControllerError::InvalidPlan(
                    "active browser acceptance differs from its durable goal grant".to_owned(),
                ));
            }
            Ok(Some(grant))
        }
        None if !binding_digests.is_empty() => Err(ControllerError::InvalidPlan(
            "active Plan has browser authority without an explicit durable goal grant".to_owned(),
        )),
        None => Ok(None),
    }
}

pub(crate) fn plan_has_durable_goal_intent(
    state: &StateStore,
    plan_document: &Value,
) -> Result<bool, ControllerError> {
    let goal_id = required_str(plan_document, "/goal/goal_id")?;
    let Some(record) = state
        .state_records(GOAL_INTENT_NAMESPACE)?
        .into_iter()
        .find(|record| record.key == goal_id)
    else {
        return Ok(false);
    };
    let intent = decode_versioned_goal_intent(&record)?;
    if intent.status == GOAL_STATUS_COMPLETED {
        return Ok(false);
    }
    if intent.status != GOAL_STATUS_ACTIVE {
        return Err(ControllerError::InvalidPlan(
            "active plan goal intent is not active".to_owned(),
        ));
    }
    Ok(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalIntentClaimStatusV1 {
    Claimed,
    Active,
    Completed,
    Released,
    Failed,
    Cancelled,
}

/// How a goal ended without completing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalOutcomeKindV1 {
    Failed,
    Cancelled,
}

/// Why a goal ended without completing. `detail` is bounded and may carry untrusted text
/// (for example a compiler error); clients render it as text only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalOutcomeV1 {
    pub schema_version: u32,
    pub goal_id: String,
    pub kind: GoalOutcomeKindV1,
    pub reason_code: String,
    pub detail: String,
    pub plan_id: Option<String>,
    pub plan_revision: Option<u32>,
    pub recorded_at_ms: i64,
}

/// Retirement record for an active plan whose goal ended as failed or cancelled. It plays the
/// role [`PlanFinalizationV1`] plays for completed plans, without a completion record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAbandonmentV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub goal_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub kind: GoalOutcomeKindV1,
    pub reason_code: String,
    pub goal_intent_version: i64,
    pub goal_intent_digest: String,
    pub goal_claim_version: i64,
    pub goal_claim_digest: String,
    pub checkpoint_generation: i64,
    pub checkpoint_action_sequence: i64,
    pub checkpoint_hash: String,
    pub abandoned_at_ms: i64,
}

/// Reads every recorded goal outcome, oldest first by the millisecond it was recorded. Outcomes
/// recorded in the same millisecond are in goal id order.
///
/// # Errors
/// Returns a state or decoding error.
pub fn goal_outcomes(state: &StateStore) -> Result<Vec<GoalOutcomeV1>, ControllerError> {
    let mut outcomes = state
        .state_records(GOAL_OUTCOME_NAMESPACE)?
        .into_iter()
        .map(|record| {
            let outcome: GoalOutcomeV1 = serde_json::from_str(&record.value_json)?;
            validate_goal_outcome(&record.key, &outcome)?;
            Ok(outcome)
        })
        .collect::<Result<Vec<_>, ControllerError>>()?;
    outcomes.sort_by_key(|outcome| outcome.recorded_at_ms);
    Ok(outcomes)
}

/// A completed goal's verified work, ready to land in the project folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedGoalWorkV1 {
    pub goal_id: String,
    pub natural_language_goal: String,
    pub plan_id: String,
    pub plan_revision: u32,
    /// Each succeeded task's own change set, upstream tasks first.
    pub change_sets: Vec<sovereign_repo::ChangeSet>,
}

/// Returns the verified change sets of a goal the Controller recorded as completed, in dependency
/// order. Returns `None` for any goal that is not completed with a completion record, so only
/// verified work can ever be landed.
///
/// # Errors
/// Returns a state or decoding error, or a fail-closed error for a misbound plan or a task graph
/// with a cycle.
pub fn completed_goal_work(
    state: &StateStore,
    goal_id: &str,
) -> Result<Option<CompletedGoalWorkV1>, ControllerError> {
    let Some(intent_row) = state
        .state_records(GOAL_INTENT_NAMESPACE)?
        .into_iter()
        .find(|record| record.key == goal_id)
    else {
        return Ok(None);
    };
    let intent = decode_versioned_goal_intent(&intent_row)?;
    if intent.status != GOAL_STATUS_COMPLETED {
        return Ok(None);
    }
    let Some(claim_row) = state
        .state_records(GOAL_INTENT_CLAIM_NAMESPACE)?
        .into_iter()
        .find(|record| record.key == goal_id)
    else {
        return Ok(None);
    };
    let claim = decode_versioned_goal_claim(&claim_row)?;
    if claim.status != GoalIntentClaimStatusV1::Completed {
        return Ok(None);
    }
    if state
        .get_state(
            "controller.completion_record",
            &completion_record_key(&claim.plan_id, claim.plan_revision),
        )?
        .is_none()
    {
        return Ok(None);
    }
    let mut tasks = BTreeMap::<String, (Vec<String>, Option<sovereign_repo::ChangeSet>)>::new();
    for record in state.state_records("controller.task")? {
        if !super::key_belongs_to_revision(&record.key, &claim.plan_id, claim.plan_revision) {
            continue;
        }
        let runtime: Value = serde_json::from_str(&record.value_json)?;
        if runtime.get("state").and_then(Value::as_str) != Some("succeeded") {
            return Err(ControllerError::InvalidPlan(format!(
                "completed goal {goal_id} has a task that did not succeed"
            )));
        }
        let task_id = required_str(&runtime, "/task/task_id")?.to_owned();
        let dependencies = runtime
            .pointer("/task/dependencies")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let change_set = match runtime.get("change_set") {
            Some(value) if !value.is_null() => {
                let change_set: sovereign_repo::ChangeSet = serde_json::from_value(value.clone())?;
                if change_set.plan_id != claim.plan_id
                    || change_set.plan_revision != claim.plan_revision
                    || change_set.task_id != task_id
                {
                    return Err(ControllerError::InvalidPlan(format!(
                        "task {task_id} change set is bound to another plan or task"
                    )));
                }
                Some(change_set)
            }
            _ => None,
        };
        tasks.insert(task_id, (dependencies, change_set));
    }
    // Upstream tasks first; ties broken by task id for a stable order.
    let mut ordered = Vec::with_capacity(tasks.len());
    let mut placed = std::collections::BTreeSet::<String>::new();
    while placed.len() < tasks.len() {
        let ready = tasks
            .iter()
            .find(|(task_id, (dependencies, _))| {
                !placed.contains(*task_id)
                    && dependencies.iter().all(|dependency| {
                        placed.contains(dependency) || !tasks.contains_key(dependency)
                    })
            })
            .map(|(task_id, _)| task_id.clone());
        let Some(task_id) = ready else {
            return Err(ControllerError::InvalidPlan(format!(
                "completed goal {goal_id} task graph has a cycle"
            )));
        };
        if let Some((_, Some(change_set))) = tasks.get(&task_id) {
            ordered.push(change_set.clone());
        }
        placed.insert(task_id);
    }
    Ok(Some(CompletedGoalWorkV1 {
        goal_id: goal_id.to_owned(),
        natural_language_goal: intent.natural_language_goal,
        plan_id: claim.plan_id,
        plan_revision: claim.plan_revision,
        change_sets: ordered,
    }))
}

fn validate_goal_outcome(record_key: &str, outcome: &GoalOutcomeV1) -> Result<(), ControllerError> {
    if outcome.schema_version != GOAL_OUTCOME_SCHEMA_VERSION
        || outcome.goal_id != record_key
        || outcome.goal_id.trim().is_empty()
        || outcome.reason_code.trim().is_empty()
        || outcome.detail.len() > MAX_GOAL_OUTCOME_DETAIL_BYTES
        || outcome.recorded_at_ms <= 0
        || outcome.plan_id.is_some() != outcome.plan_revision.is_some()
    {
        return Err(ControllerError::InvalidPlan(format!(
            "malformed durable goal outcome {record_key}"
        )));
    }
    Ok(())
}

/// Truncates untrusted detail text to the durable bound on a character boundary.
fn bounded_outcome_detail(detail: &str) -> String {
    if detail.len() <= MAX_GOAL_OUTCOME_DETAIL_BYTES {
        return detail.to_owned();
    }
    let mut end = MAX_GOAL_OUTCOME_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail[..end].to_owned()
}

/// Statuses a goal can reach from the queue without ever holding a live claim.
fn is_unclaimed_terminal_status(status: &str) -> bool {
    matches!(status, GOAL_STATUS_CANCELLED | GOAL_STATUS_FAILED)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalIntentClaimV1 {
    pub schema_version: u32,
    pub goal_id: String,
    pub goal_statement_digest: String,
    pub plan_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub compilation_evidence_digest: String,
    pub status: GoalIntentClaimStatusV1,
    pub claimed_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanFinalizationV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub goal_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub completion_record_key: String,
    pub completion_record_digest: String,
    pub goal_intent_version: i64,
    pub goal_intent_digest: String,
    pub goal_claim_version: i64,
    pub goal_claim_digest: String,
    pub checkpoint_generation: i64,
    pub checkpoint_action_sequence: i64,
    pub checkpoint_hash: String,
    pub finalized_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveGoalBinding {
    goal_id: String,
    goal_statement: String,
    plan_id: String,
    plan_revision: u32,
    plan_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GoalLifecycleRecordVersions {
    intent_version: i64,
    claim_version: Option<i64>,
}

#[cfg(test)]
type FinalizationPreCommitTestHook =
    Box<dyn FnOnce(&mut StateStore) -> Result<(), ControllerError>>;

#[cfg(test)]
std::thread_local! {
    static FINALIZATION_PRE_COMMIT_TEST_HOOK: std::cell::RefCell<Option<FinalizationPreCommitTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_finalization_pre_commit_test_hook(
    hook: impl FnOnce(&mut StateStore) -> Result<(), ControllerError> + 'static,
) {
    FINALIZATION_PRE_COMMIT_TEST_HOOK.with(|slot| {
        let previous = slot.borrow_mut().replace(Box::new(hook));
        assert!(
            previous.is_none(),
            "finalization pre-commit test hook already set"
        );
    });
}

#[cfg(test)]
fn run_finalization_pre_commit_test_hook(state: &mut StateStore) -> Result<(), ControllerError> {
    FINALIZATION_PRE_COMMIT_TEST_HOOK
        .with(|slot| slot.borrow_mut().take().map_or(Ok(()), |hook| hook(state)))
}

impl Controller {
    pub(crate) fn validated_goal_intents_for_status(
        &self,
    ) -> Result<Vec<GoalIntentV1>, ControllerError> {
        self.validate_persisted_goal_lifecycle_versions()?;
        let intents = self.read_validated_goal_intents()?;
        let claims = self.read_validated_goal_claims()?;
        validate_claim_set(&intents, &claims)?;
        Ok(intents)
    }

    /// Returns the oldest queued durable goal intent using submission time and goal id as a stable
    /// tie-breaker. Malformed lifecycle rows or conflicting in-flight claims fail closed.
    ///
    /// # Errors
    /// Returns a durable-state/validation error when queued-goal truth is malformed or ambiguous.
    pub fn next_queued_goal_intent(&self) -> Result<Option<GoalIntentV1>, ControllerError> {
        self.validate_persisted_goal_lifecycle_versions()?;
        let mut intents = self.read_validated_goal_intents()?;
        let claims = self.read_validated_goal_claims()?;
        validate_claim_set(&intents, &claims)?;

        if self.canonical_active_goal_binding()?.is_some()
            || intents.iter().any(|intent| {
                matches!(
                    intent.status.as_str(),
                    GOAL_STATUS_CLAIMED | GOAL_STATUS_ACTIVE
                )
            })
        {
            return Ok(None);
        }

        intents.retain(|intent| intent.status == GOAL_STATUS_QUEUED);
        intents.sort_by(|left, right| {
            (left.submitted_at_ms, left.goal_id.as_str())
                .cmp(&(right.submitted_at_ms, right.goal_id.as_str()))
        });
        Ok(intents.into_iter().next())
    }

    /// Claims the exact next queued goal, binds the claim to one compiler-owned result, and
    /// activates only that result through the canonical Controller activation path.
    ///
    /// A crash after the claim but before the post-activation lifecycle transition is repaired by
    /// [`Self::reconcile_queued_goal_lifecycle`]. A synchronous activation failure with no durable
    /// active plan releases the claim back to the queue; any partial/conflicting active state fails
    /// closed instead of being overwritten.
    ///
    /// # Errors
    /// Returns a fail-closed validation/state/activation error for stale queue selection, binding
    /// mismatch, conflicting claims, or ordinary Controller activation failure.
    #[allow(clippy::too_many_lines)]
    pub fn activate_queued_goal_intent(
        &mut self,
        goal_id: &str,
        compilation: PlanCompilationResult,
        registry: &ProjectRegistry,
    ) -> Result<ActivationSummary, ControllerError> {
        self.reconcile_queued_goal_lifecycle()?;
        if self.canonical_active_goal_binding()?.is_some() {
            return Err(ControllerError::InvalidPlan(
                "cannot claim a queued goal while a canonical active plan exists".to_owned(),
            ));
        }

        let next = self.next_queued_goal_intent()?.ok_or_else(|| {
            ControllerError::NotReady(
                "no queued goal intent is available for compilation".to_owned(),
            )
        })?;
        if next.goal_id != goal_id {
            return Err(ControllerError::NotReady(format!(
                "queued goal {goal_id} is not the next durable intent"
            )));
        }

        let plan = compilation.plan().as_value();
        if compilation.plan().canonical_digest()? != compilation.plan_digest() {
            return Err(ControllerError::InvalidPlan(
                "queued-goal compilation digest does not match canonical Plan IR".to_owned(),
            ));
        }
        let compiled_goal_id = required_str(plan, "/goal/goal_id")?;
        let compiled_goal_statement = required_str(plan, "/goal/statement")?;
        if compiled_goal_id != next.goal_id || compiled_goal_statement != next.natural_language_goal
        {
            return Err(ControllerError::InvalidPlan(
                "queued-goal compilation is not bound to the exact durable goal id and statement"
                    .to_owned(),
            ));
        }
        let plan_id = required_str(plan, "/plan_id")?.to_owned();
        let plan_revision = required_u32(plan, "/revision")?;
        let now = super::unix_millis()?;
        let claim = GoalIntentClaimV1 {
            schema_version: GOAL_INTENT_CLAIM_SCHEMA_VERSION,
            goal_id: next.goal_id.clone(),
            goal_statement_digest: sha256_prefixed(next.natural_language_goal.as_bytes()),
            plan_id: plan_id.clone(),
            plan_revision,
            plan_digest: compilation.plan_digest().to_owned(),
            compilation_evidence_digest: compilation.compilation_evidence_digest().to_owned(),
            status: GoalIntentClaimStatusV1::Claimed,
            claimed_at_ms: now,
            updated_at_ms: now,
        };
        validate_claim_binding(&next, &claim)?;
        self.persist_goal_lifecycle_transition(
            with_goal_status(next.clone(), GOAL_STATUS_CLAIMED),
            claim.clone(),
            "goal_intent_claimed",
            json!({
                "goal_id": claim.goal_id,
                "plan_id": claim.plan_id,
                "plan_revision": claim.plan_revision,
                "plan_digest": claim.plan_digest,
                "compilation_evidence_digest": claim.compilation_evidence_digest,
            }),
        )?;
        super::recovery_test_hook("after_goal_claim_commit");

        let activation = match self.activate(compilation, registry) {
            Ok(activation) => activation,
            Err(error) => {
                match self.canonical_active_goal_binding()? {
                    None => {
                        let mut released = claim;
                        released.status = GoalIntentClaimStatusV1::Released;
                        released.updated_at_ms = super::unix_millis()?;
                        self.persist_goal_lifecycle_transition(
                            with_goal_status(next, GOAL_STATUS_QUEUED),
                            released,
                            "goal_intent_claim_released",
                            json!({"reason": "activation_failed_before_canonical_active_plan"}),
                        )?;
                    }
                    Some(active) => {
                        validate_active_claim_binding(&active, &claim)?;
                        // Preserve the durable claimed state. Restart reconciliation will promote it
                        // only after revalidating the canonical active plan and checkpoint/recovery.
                    }
                }
                return Err(error);
            }
        };

        let active = self.canonical_active_goal_binding()?.ok_or_else(|| {
            ControllerError::InvalidPlan(
                "activation succeeded without a canonical active plan binding".to_owned(),
            )
        })?;
        validate_active_claim_binding(&active, &claim)?;
        if activation.plan_id != claim.plan_id
            || activation.revision != claim.plan_revision
            || activation.plan_digest != claim.plan_digest
        {
            return Err(ControllerError::InvalidPlan(
                "activation summary differs from queued-goal claim binding".to_owned(),
            ));
        }

        let mut active_claim = claim;
        active_claim.status = GoalIntentClaimStatusV1::Active;
        active_claim.updated_at_ms = super::unix_millis()?;
        self.persist_goal_lifecycle_transition(
            with_goal_status(next, GOAL_STATUS_ACTIVE),
            active_claim,
            "goal_intent_activated",
            json!({
                "plan_id": activation.plan_id,
                "plan_revision": activation.revision,
                "plan_digest": activation.plan_digest,
                "execution_epoch": activation.execution_epoch,
            }),
        )?;
        super::recovery_test_hook("after_goal_activation_lifecycle_commit");
        self.checkpoint_now()?;
        Ok(activation)
    }

    /// Reconciles a crash-interrupted queued-goal claim against the canonical active plan.
    ///
    /// Claimed intents with no active plan are safely released back to the queue. Claimed intents
    /// whose exact claim matches the recovered active plan are promoted to active. If a canonical
    /// completion record already exists, reconciliation completes the intent instead. Any malformed
    /// or conflicting claim/intent/plan combination fails closed.
    ///
    /// # Errors
    /// Returns a durable-state or integrity error when lifecycle truth is ambiguous or conflicting.
    #[allow(clippy::too_many_lines)]
    pub fn reconcile_queued_goal_lifecycle(
        &mut self,
    ) -> Result<Option<GoalIntentV1>, ControllerError> {
        self.validate_persisted_goal_lifecycle_versions()?;
        let intents = self.read_validated_goal_intents()?;
        let claims = self.read_validated_goal_claims()?;
        validate_claim_set(&intents, &claims)?;
        let active = self.canonical_active_goal_binding()?;

        let mut live = claims
            .iter()
            .filter(|claim| {
                matches!(
                    claim.status,
                    GoalIntentClaimStatusV1::Claimed | GoalIntentClaimStatusV1::Active
                )
            })
            .collect::<Vec<_>>();
        live.sort_by(|left, right| left.goal_id.cmp(&right.goal_id));
        if live.len() > 1 {
            return Err(ControllerError::InvalidPlan(
                "multiple live queued-goal claims exist".to_owned(),
            ));
        }

        let Some(active) = active else {
            let Some(claim) = live.first().copied() else {
                if intents.iter().any(|intent| {
                    matches!(
                        intent.status.as_str(),
                        GOAL_STATUS_CLAIMED | GOAL_STATUS_ACTIVE
                    )
                }) {
                    return Err(ControllerError::InvalidPlan(
                        "claimed/active goal intent exists without a live durable claim".to_owned(),
                    ));
                }
                return Ok(None);
            };
            if claim.status != GoalIntentClaimStatusV1::Claimed {
                return Err(ControllerError::InvalidPlan(
                    "active queued-goal claim exists without a canonical active plan".to_owned(),
                ));
            }
            let intent = intent_by_id(&intents, &claim.goal_id)?;
            if intent.status != GOAL_STATUS_CLAIMED {
                return Err(ControllerError::InvalidPlan(
                    "interrupted queued-goal claim has mismatched intent status".to_owned(),
                ));
            }
            validate_claim_binding(intent, claim)?;
            let mut released = claim.clone();
            released.status = GoalIntentClaimStatusV1::Released;
            released.updated_at_ms = super::unix_millis()?;
            let queued = with_goal_status(intent.clone(), GOAL_STATUS_QUEUED);
            self.persist_goal_lifecycle_transition(
                queued.clone(),
                released,
                "goal_intent_claim_reconciled_to_queue",
                json!({"reason": "no_canonical_active_plan"}),
            )?;
            return Ok(Some(queued));
        };

        let matching_claim = claims.iter().find(|claim| claim.goal_id == active.goal_id);
        let Some(claim) = matching_claim else {
            if live
                .first()
                .is_some_and(|claim| claim.goal_id != active.goal_id)
            {
                return Err(ControllerError::InvalidPlan(
                    "live queued-goal claim conflicts with the canonical active plan".to_owned(),
                ));
            }
            // Active plans created outside the queued-goal runner remain valid and untouched.
            return Ok(None);
        };
        let intent = intent_by_id(&intents, &claim.goal_id)?;
        validate_claim_binding(intent, claim)?;
        validate_active_claim_binding(&active, claim)?;

        let completion = self.completion_record()?;
        if let Some(record) = completion.as_ref() {
            validate_completion_binding(record, &active, claim)?;
            if intent.status == GOAL_STATUS_COMPLETED
                && claim.status == GoalIntentClaimStatusV1::Completed
            {
                return Ok(Some(intent.clone()));
            }
            if !matches!(
                intent.status.as_str(),
                GOAL_STATUS_CLAIMED | GOAL_STATUS_ACTIVE
            ) || !matches!(
                claim.status,
                GoalIntentClaimStatusV1::Claimed | GoalIntentClaimStatusV1::Active
            ) {
                return Err(ControllerError::InvalidPlan(
                    "completion record conflicts with queued-goal lifecycle status".to_owned(),
                ));
            }
            let completed =
                self.persist_completed_goal_intent(intent.clone(), claim.clone(), record)?;
            self.checkpoint_now()?;
            return Ok(Some(completed));
        }

        match (intent.status.as_str(), claim.status) {
            (GOAL_STATUS_ACTIVE, GoalIntentClaimStatusV1::Active) => Ok(Some(intent.clone())),
            (GOAL_STATUS_CLAIMED, GoalIntentClaimStatusV1::Claimed) => {
                let mut active_claim = claim.clone();
                active_claim.status = GoalIntentClaimStatusV1::Active;
                active_claim.updated_at_ms = super::unix_millis()?;
                let active_intent = with_goal_status(intent.clone(), GOAL_STATUS_ACTIVE);
                self.persist_goal_lifecycle_transition(
                    active_intent.clone(),
                    active_claim,
                    "goal_intent_claim_reconciled_to_active",
                    json!({
                        "plan_id": active.plan_id,
                        "plan_revision": active.plan_revision,
                        "plan_digest": active.plan_digest,
                    }),
                )?;
                self.checkpoint_now()?;
                Ok(Some(active_intent))
            }
            _ => Err(ControllerError::InvalidPlan(
                "queued-goal intent and claim lifecycle statuses conflict".to_owned(),
            )),
        }
    }

    /// Completes the canonical active goal first, then durably transitions its queued-goal intent
    /// and exact claim to completed. The lifecycle transition can never precede `complete_goal`.
    ///
    /// # Errors
    /// Returns the ordinary completion error, or a fail-closed lifecycle/binding error.
    pub fn complete_queued_goal_intent(
        &mut self,
        registry: &ProjectRegistry,
    ) -> Result<CompletionRecordV1, ControllerError> {
        self.reconcile_queued_goal_lifecycle()?;
        let active = self.canonical_active_goal_binding()?.ok_or_else(|| {
            ControllerError::InvalidPlan(
                "no canonical active plan for queued-goal completion".to_owned(),
            )
        })?;
        let intents = self.read_validated_goal_intents()?;
        let claims = self.read_validated_goal_claims()?;
        validate_claim_set(&intents, &claims)?;
        let intent = intent_by_id(&intents, &active.goal_id)?.clone();
        let claim = claims
            .iter()
            .find(|candidate| candidate.goal_id == active.goal_id)
            .cloned()
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "canonical active plan lacks its queued-goal claim".to_owned(),
                )
            })?;
        if intent.status == GOAL_STATUS_COMPLETED
            && claim.status == GoalIntentClaimStatusV1::Completed
        {
            return self.completion_record()?.ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "completed queued-goal lifecycle lacks canonical completion record".to_owned(),
                )
            });
        }
        if intent.status != GOAL_STATUS_ACTIVE || claim.status != GoalIntentClaimStatusV1::Active {
            return Err(ControllerError::InvalidPlan(
                "queued-goal completion requires exact active intent and claim".to_owned(),
            ));
        }
        validate_claim_binding(&intent, &claim)?;
        validate_active_claim_binding(&active, &claim)?;

        let completion = self.complete_goal(registry)?;
        validate_completion_binding(&completion, &active, &claim)?;
        self.persist_completed_goal_intent(intent, claim, &completion)?;
        super::recovery_test_hook("after_goal_completion_lifecycle_commit");
        self.checkpoint_now()?;
        Ok(completion)
    }

    /// Retires a durably completed queued-goal plan without discarding any revision-scoped
    /// task/attempt/evidence history. The active pointer triad is removed only in the same CAS
    /// transaction that marks the exact revision completed and publishes a finalization record.
    ///
    /// # Errors
    /// Fails closed unless completion, queued-goal lifecycle, recovery clearance, the terminal
    /// checkpoint, active pointer versions, and revision lifecycle all bind the same plan revision.
    #[allow(clippy::too_many_lines)]
    pub fn finalize_completed_active_plan(
        &mut self,
    ) -> Result<PlanFinalizationV1, ControllerError> {
        self.reconcile_queued_goal_lifecycle()?;
        let active = self.canonical_active_goal_binding()?.ok_or_else(|| {
            ControllerError::InvalidPlan(
                "completed-plan finalization requires a canonical active plan".to_owned(),
            )
        })?;
        let completion = self.completion_record()?.ok_or_else(|| {
            ControllerError::NotReady(
                "completed-plan finalization requires canonical goal completion".to_owned(),
            )
        })?;
        validate_completion_publication_event(&self.state, &completion)?;
        self.require_completion_recovery_clear()?;

        let intents = self.read_validated_goal_intents()?;
        let claims = self.read_validated_goal_claims()?;
        validate_claim_set(&intents, &claims)?;
        let intent = intent_by_id(&intents, &active.goal_id)?;
        let claim = claims
            .iter()
            .find(|candidate| candidate.goal_id == active.goal_id)
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "completed active plan lacks its queued-goal claim".to_owned(),
                )
            })?;
        if intent.status != GOAL_STATUS_COMPLETED
            || claim.status != GoalIntentClaimStatusV1::Completed
        {
            return Err(ControllerError::NotReady(
                "completed-plan finalization requires completed goal intent and claim".to_owned(),
            ));
        }
        validate_claim_binding(intent, claim)?;
        validate_active_claim_binding(&active, claim)?;
        validate_completion_binding(&completion, &active, claim)?;

        self.checkpoint_now()?;
        let checkpoint = self
            .state
            .latest_valid_checkpoint_integrity()?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "completed-plan finalization lacks a trusted terminal checkpoint".to_owned(),
                )
            })?;
        if checkpoint.action_sequence != self.state.latest_journal_sequence()? {
            return Err(ControllerError::InvalidPlan(
                "terminal checkpoint does not cover the latest controller journal sequence"
                    .to_owned(),
            ));
        }

        let plan_record = persisted_state_record(&self.state, "controller.plan", "active")?;
        let plan_document_record =
            persisted_state_record(&self.state, "controller.plan_document", "active")?;
        let baseline_record =
            persisted_state_record(&self.state, "controller.repository_baseline", "active")?;
        let lifecycle_key = revision_record_key(&active.plan_id, active.plan_revision);
        let lifecycle_record = persisted_state_record(
            &self.state,
            "controller.plan_revision_lifecycle",
            &lifecycle_key,
        )?;
        validate_active_revision_lifecycle(&lifecycle_record, &active)?;
        let intent_record =
            persisted_state_record(&self.state, GOAL_INTENT_NAMESPACE, &intent.goal_id)?;
        let claim_record =
            persisted_state_record(&self.state, GOAL_INTENT_CLAIM_NAMESPACE, &claim.goal_id)?;
        let completion_state_record = persisted_state_record(
            &self.state,
            "controller.completion_record",
            &completion_record_key(&active.plan_id, active.plan_revision),
        )?;

        if self
            .state
            .get_state(PLAN_FINALIZATION_NAMESPACE, &lifecycle_key)?
            .is_some()
        {
            return Err(ControllerError::InvalidPlan(
                "completed-plan finalization record already exists while plan is still active"
                    .to_owned(),
            ));
        }

        let completion_record_key = completion_record_key(&active.plan_id, active.plan_revision);
        let completion_record_digest = completion.canonical_digest()?;
        let finalization = PlanFinalizationV1 {
            schema_version: PLAN_FINALIZATION_SCHEMA_VERSION,
            plan_id: active.plan_id.clone(),
            goal_id: active.goal_id.clone(),
            plan_revision: active.plan_revision,
            plan_digest: active.plan_digest.clone(),
            completion_record_key,
            completion_record_digest: completion_record_digest.clone(),
            goal_intent_version: intent_record.version,
            goal_intent_digest: sha256_prefixed(intent_record.value_json.as_bytes()),
            goal_claim_version: claim_record.version,
            goal_claim_digest: sha256_prefixed(claim_record.value_json.as_bytes()),
            checkpoint_generation: checkpoint.generation,
            checkpoint_action_sequence: checkpoint.action_sequence,
            checkpoint_hash: checkpoint.checkpoint_hash.clone(),
            finalized_at_ms: super::unix_millis()?,
        };
        validate_plan_finalization(&lifecycle_key, &finalization)?;
        let finalization_json = serde_json::to_string(&finalization)?;
        let finalization_digest = digest_json(&serde_json::to_value(&finalization)?)?;
        let lifecycle_json = serde_json::to_string(&json!({
            "plan_id": active.plan_id,
            "revision": active.plan_revision,
            "plan_digest": active.plan_digest,
            "status": "completed",
            "superseded_by_revision": Value::Null,
            "superseded_by_digest": Value::Null,
            "completion_record_digest": completion_record_digest,
            "terminal_checkpoint_generation": checkpoint.generation,
            "terminal_checkpoint_action_sequence": checkpoint.action_sequence,
            "terminal_checkpoint_hash": checkpoint.checkpoint_hash,
            "finalization_record_digest": finalization_digest,
        }))?;
        let event_payload = serde_json::to_string(&json!({
            "plan_id": finalization.plan_id,
            "goal_id": finalization.goal_id,
            "plan_revision": finalization.plan_revision,
            "plan_digest": finalization.plan_digest,
            "completion_record_digest": finalization.completion_record_digest,
            "finalization_record_digest": finalization_digest,
            "terminal_checkpoint_generation": finalization.checkpoint_generation,
            "terminal_checkpoint_action_sequence": finalization.checkpoint_action_sequence,
            "terminal_checkpoint_hash": finalization.checkpoint_hash,
        }))?;
        let seed = sha256_prefixed(
            format!(
                "plan_finalized\0{}\0{}\0{}",
                lifecycle_key, checkpoint.action_sequence, event_payload
            )
            .as_bytes(),
        );
        let event_id = format!("controller.{}", &seed[7..27]);
        #[cfg(test)]
        run_finalization_pre_commit_test_hook(&mut self.state)?;
        super::recovery_test_hook("before_completed_plan_finalization_commit");
        self.state
            .compare_and_apply_state_records_with_events_guarded(
                Some(checkpoint.action_sequence),
                &[
                    StateRecordCasAssertion {
                        namespace: GOAL_INTENT_NAMESPACE,
                        key: &intent.goal_id,
                        expected_version: intent_record.version,
                        expected_value_json: Some(&intent_record.value_json),
                        expected_value_digest: Some(&finalization.goal_intent_digest),
                    },
                    StateRecordCasAssertion {
                        namespace: GOAL_INTENT_CLAIM_NAMESPACE,
                        key: &claim.goal_id,
                        expected_version: claim_record.version,
                        expected_value_json: Some(&claim_record.value_json),
                        expected_value_digest: Some(&finalization.goal_claim_digest),
                    },
                    StateRecordCasAssertion {
                        namespace: "controller.completion_record",
                        key: &finalization.completion_record_key,
                        expected_version: completion_state_record.version,
                        expected_value_json: Some(&completion_state_record.value_json),
                        expected_value_digest: Some(&sha256_prefixed(
                            completion_state_record.value_json.as_bytes(),
                        )),
                    },
                ],
                &[
                    StateRecordCasMutation {
                        namespace: "controller.plan",
                        key: "active",
                        expected_version: Some(plan_record.version),
                        value_json: None,
                    },
                    StateRecordCasMutation {
                        namespace: "controller.plan_document",
                        key: "active",
                        expected_version: Some(plan_document_record.version),
                        value_json: None,
                    },
                    StateRecordCasMutation {
                        namespace: "controller.repository_baseline",
                        key: "active",
                        expected_version: Some(baseline_record.version),
                        value_json: None,
                    },
                    StateRecordCasMutation {
                        namespace: "controller.plan_revision_lifecycle",
                        key: &lifecycle_key,
                        expected_version: Some(lifecycle_record.version),
                        value_json: Some(&lifecycle_json),
                    },
                    StateRecordCasMutation {
                        namespace: PLAN_FINALIZATION_NAMESPACE,
                        key: &lifecycle_key,
                        expected_version: None,
                        value_json: Some(&finalization_json),
                    },
                ],
                &[NewJournalEvent {
                    event_id: &event_id,
                    entity_type: "controller",
                    entity_id: &lifecycle_key,
                    event_kind: "plan_finalized",
                    payload_json: &event_payload,
                }],
            )?;
        super::recovery_test_hook("after_completed_plan_finalization_commit");
        self.active = None;
        Ok(finalization)
    }

    pub(crate) fn validate_no_active_plan_history(&self) -> Result<(), ControllerError> {
        validate_finalized_plan_history(&self.state)
    }

    fn read_validated_goal_intents(&self) -> Result<Vec<GoalIntentV1>, ControllerError> {
        self.state
            .state_records(GOAL_INTENT_NAMESPACE)?
            .into_iter()
            .map(|record| decode_versioned_goal_intent(&record))
            .collect()
    }

    fn read_validated_goal_claims(&self) -> Result<Vec<GoalIntentClaimV1>, ControllerError> {
        self.state
            .state_records(GOAL_INTENT_CLAIM_NAMESPACE)?
            .into_iter()
            .map(|record| decode_versioned_goal_claim(&record))
            .collect()
    }

    fn validate_persisted_goal_lifecycle_versions(&self) -> Result<(), ControllerError> {
        let intent_records = self.state.state_records(GOAL_INTENT_NAMESPACE)?;
        let claim_records = self.state.state_records(GOAL_INTENT_CLAIM_NAMESPACE)?;
        for intent_record in &intent_records {
            let intent = decode_versioned_goal_intent(intent_record)?;
            let matching_claim = claim_records
                .iter()
                .find(|claim_record| claim_record.key == intent.goal_id);
            if let Some(claim_record) = matching_claim {
                let claim = decode_versioned_goal_claim(claim_record)?;
                if claim.status == GoalIntentClaimStatusV1::Released
                    && is_unclaimed_terminal_status(&intent.status)
                {
                    // A released claim went back to the queue; the terminal transition then
                    // advanced only the intent.
                    if intent_record.version != claim_record.version + 2 {
                        return Err(ControllerError::InvalidPlan(format!(
                            "terminal goal intent {} and its released claim have conflicting record versions",
                            intent.goal_id
                        )));
                    }
                } else {
                    validate_goal_lifecycle_record_versions(GoalLifecycleRecordVersions {
                        intent_version: intent_record.version,
                        claim_version: Some(claim_record.version),
                    })?;
                }
            } else {
                let queued = intent.status == GOAL_STATUS_QUEUED && intent_record.version == 1;
                let unclaimed_terminal =
                    is_unclaimed_terminal_status(&intent.status) && intent_record.version == 2;
                if !queued && !unclaimed_terminal {
                    return Err(ControllerError::InvalidPlan(format!(
                        "goal intent {} lacks its durable claim at record version {}",
                        intent.goal_id, intent_record.version
                    )));
                }
            }
        }
        for claim_record in &claim_records {
            if !intent_records
                .iter()
                .any(|intent_record| intent_record.key == claim_record.key)
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "orphan durable goal claim {}",
                    claim_record.key
                )));
            }
        }
        Ok(())
    }

    fn canonical_active_goal_binding(&self) -> Result<Option<ActiveGoalBinding>, ControllerError> {
        let active_record = self.state.get_state("controller.plan", "active")?;
        let active_document = self.state.get_state("controller.plan_document", "active")?;
        match (active_record, active_document) {
            (None, None) => {
                if self.active.is_some() {
                    return Err(ControllerError::InvalidPlan(
                        "in-memory active plan exists without canonical durable active plan"
                            .to_owned(),
                    ));
                }
                Ok(None)
            }
            (Some(_), None) | (None, Some(_)) => Err(ControllerError::InvalidPlan(
                "canonical active plan record/document pair is incomplete".to_owned(),
            )),
            (Some(raw_record), Some(raw_document)) => {
                if self.active.is_none() {
                    return Err(ControllerError::NotReady(
                        "canonical active plan must be recovered before queued-goal reconciliation"
                            .to_owned(),
                    ));
                }
                let record: Value = serde_json::from_str(&raw_record)?;
                let document: Value = serde_json::from_str(&raw_document)?;
                let binding = ActiveGoalBinding {
                    goal_id: required_str(&record, "/goal_id")?.to_owned(),
                    goal_statement: required_str(&document, "/goal/statement")?.to_owned(),
                    plan_id: required_str(&record, "/plan_id")?.to_owned(),
                    plan_revision: required_u32(&record, "/revision")?,
                    plan_digest: required_str(&record, "/plan_digest")?.to_owned(),
                };
                if required_str(&document, "/goal/goal_id")? != binding.goal_id
                    || required_str(&document, "/plan_id")? != binding.plan_id
                    || required_u32(&document, "/revision")? != binding.plan_revision
                    || digest_json(&document)? != binding.plan_digest
                {
                    return Err(ControllerError::InvalidPlan(
                        "canonical active plan record does not match canonical plan document"
                            .to_owned(),
                    ));
                }
                if let Some(active) = self.active.as_ref()
                    && (active.goal_id != binding.goal_id
                        || active.plan_id != binding.plan_id
                        || active.revision != binding.plan_revision
                        || active.plan_digest != binding.plan_digest)
                {
                    return Err(ControllerError::InvalidPlan(
                        "in-memory active plan conflicts with canonical durable active plan"
                            .to_owned(),
                    ));
                }
                Ok(Some(binding))
            }
        }
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "lifecycle transition owns the exact canonical intent and claim values"
    )]
    fn persist_goal_lifecycle_transition(
        &mut self,
        intent: GoalIntentV1,
        claim: GoalIntentClaimV1,
        event_kind: &str,
        payload: Value,
    ) -> Result<(), ControllerError> {
        validate_goal_intent(&intent.goal_id, &intent)?;
        validate_goal_claim(&claim.goal_id, &claim)?;
        if intent.goal_id != claim.goal_id {
            return Err(ControllerError::InvalidPlan(
                "goal lifecycle transition mixes different intent and claim ids".to_owned(),
            ));
        }
        let versions = self.validate_goal_lifecycle_transition_precondition(&intent, &claim)?;
        let intent_json = serde_json::to_string(&intent)?;
        let claim_json = serde_json::to_string(&claim)?;
        let mut payload = payload;
        let payload_object = payload.as_object_mut().ok_or_else(|| {
            ControllerError::InvalidPlan(
                "goal lifecycle journal payload must be a JSON object".to_owned(),
            )
        })?;
        payload_object.insert(
            "expected_intent_version".to_owned(),
            json!(versions.intent_version),
        );
        payload_object.insert(
            "expected_claim_version".to_owned(),
            versions.claim_version.map_or(Value::Null, Value::from),
        );
        let payload_json = serde_json::to_string(&payload)?;
        let seed = sha256_prefixed(
            format!(
                "{}\0{}\0{}\0{}",
                event_kind,
                intent.goal_id,
                self.state.latest_journal_sequence()?,
                payload_json
            )
            .as_bytes(),
        );
        let event_id = format!("controller.{}", &seed[7..27]);
        let mutations =
            goal_lifecycle_cas_mutations(&intent.goal_id, versions, &intent_json, &claim_json);
        self.state.compare_and_apply_state_records_with_events(
            &mutations,
            &[NewJournalEvent {
                event_id: &event_id,
                entity_type: "controller",
                entity_id: &intent.goal_id,
                event_kind,
                payload_json: &payload_json,
            }],
        )?;
        Ok(())
    }

    fn validate_goal_lifecycle_transition_precondition(
        &self,
        next_intent: &GoalIntentV1,
        next_claim: &GoalIntentClaimV1,
    ) -> Result<GoalLifecycleRecordVersions, ControllerError> {
        let intent_record = self
            .state
            .state_records(GOAL_INTENT_NAMESPACE)?
            .into_iter()
            .find(|record| record.key == next_intent.goal_id)
            .ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "goal lifecycle transition references missing intent {}",
                    next_intent.goal_id
                ))
            })?;
        let current_intent = decode_versioned_goal_intent(&intent_record)?;
        let claim_record = self
            .state
            .state_records(GOAL_INTENT_CLAIM_NAMESPACE)?
            .into_iter()
            .find(|record| record.key == next_intent.goal_id);
        let current_claim = claim_record
            .as_ref()
            .map(decode_versioned_goal_claim)
            .transpose()?;
        let versions = GoalLifecycleRecordVersions {
            intent_version: intent_record.version,
            claim_version: claim_record.as_ref().map(|record| record.version),
        };
        validate_goal_lifecycle_record_versions(versions)?;

        let valid = match (next_intent.status.as_str(), next_claim.status) {
            (GOAL_STATUS_CLAIMED, GoalIntentClaimStatusV1::Claimed) => {
                current_intent.status == GOAL_STATUS_QUEUED
                    && current_claim
                        .as_ref()
                        .is_none_or(|claim| claim.status == GoalIntentClaimStatusV1::Released)
            }
            (GOAL_STATUS_QUEUED, GoalIntentClaimStatusV1::Released) => {
                current_intent.status == GOAL_STATUS_CLAIMED
                    && current_claim.as_ref().is_some_and(|claim| {
                        claim.status == GoalIntentClaimStatusV1::Claimed
                            && same_claim_binding(claim, next_claim)
                    })
            }
            (GOAL_STATUS_ACTIVE, GoalIntentClaimStatusV1::Active) => {
                current_intent.status == GOAL_STATUS_CLAIMED
                    && current_claim.as_ref().is_some_and(|claim| {
                        claim.status == GoalIntentClaimStatusV1::Claimed
                            && same_claim_binding(claim, next_claim)
                    })
            }
            (GOAL_STATUS_COMPLETED, GoalIntentClaimStatusV1::Completed) => {
                matches!(
                    current_intent.status.as_str(),
                    GOAL_STATUS_CLAIMED | GOAL_STATUS_ACTIVE
                ) && current_claim.as_ref().is_some_and(|claim| {
                    matches!(
                        claim.status,
                        GoalIntentClaimStatusV1::Claimed | GoalIntentClaimStatusV1::Active
                    ) && same_claim_binding(claim, next_claim)
                })
            }
            _ => false,
        };
        if !valid {
            return Err(ControllerError::InvalidPlan(format!(
                "stale or conflicting queued-goal lifecycle transition for {}",
                next_intent.goal_id
            )));
        }
        Ok(versions)
    }

    fn persist_completed_goal_intent(
        &mut self,
        intent: GoalIntentV1,
        mut claim: GoalIntentClaimV1,
        completion: &CompletionRecordV1,
    ) -> Result<GoalIntentV1, ControllerError> {
        claim.status = GoalIntentClaimStatusV1::Completed;
        claim.updated_at_ms = super::unix_millis()?;
        let completed = with_goal_status(intent, GOAL_STATUS_COMPLETED);
        self.persist_goal_lifecycle_transition(
            completed.clone(),
            claim,
            "goal_intent_completed",
            json!({
                "plan_id": completion.plan_id,
                "plan_revision": completion.plan_revision,
                "plan_digest": completion.plan_digest,
                "completion_record_digest": completion.canonical_digest()?,
            }),
        )?;
        Ok(completed)
    }

    /// Cancels a goal. A queued goal ends at once as cancelled. An active goal gets a durable
    /// goal-level cancellation request that stops in-flight work at its next cancellation check;
    /// the next production step then ends the goal as cancelled and the queue moves on. Ending
    /// states are idempotent.
    ///
    /// # Errors
    /// Returns `NotReady` while the goal is claimed for compilation (retry after the step), and
    /// fails closed when the goal is missing or bound to another plan.
    pub fn cancel_goal_intent(
        &mut self,
        goal_id: &str,
        principal: &str,
    ) -> Result<GoalIntentV1, ControllerError> {
        super::validate_durable_action_lifecycle_states(&self.state)?;
        let principal = principal.trim();
        if goal_id.is_empty() || principal.is_empty() {
            return Err(ControllerError::InvalidPlan(
                "goal cancellation requires a goal id and principal".to_owned(),
            ));
        }
        let raw = self
            .state
            .get_state(GOAL_INTENT_NAMESPACE, goal_id)?
            .ok_or_else(|| ControllerError::NotReady(format!("goal {goal_id} is not durable")))?;
        let intent: GoalIntentV1 = serde_json::from_str(&raw)?;
        if intent.goal_id != goal_id {
            return Err(ControllerError::InvalidPlan(
                "goal intent id does not match its record key".to_owned(),
            ));
        }
        match intent.status.as_str() {
            GOAL_STATUS_CANCELLED
            | GOAL_STATUS_COMPLETED
            | GOAL_STATUS_FAILED
            | GOAL_STATUS_CANCELLED_ACTIVE => Ok(intent),
            GOAL_STATUS_QUEUED => self.end_queued_goal(
                goal_id,
                GoalOutcomeKindV1::Cancelled,
                GOAL_REASON_CANCELLED_BY_USER,
                "Cancelled before it started.",
                principal,
            ),
            GOAL_STATUS_ACTIVE => {
                let active_goal = self
                    .active
                    .as_ref()
                    .map(|active| active.goal_id.clone())
                    .ok_or_else(|| {
                        ControllerError::NotReady(
                            "active goal intent has no in-memory plan".to_owned(),
                        )
                    })?;
                if active_goal != goal_id {
                    return Err(ControllerError::InvalidPlan(
                        "active plan is bound to a different goal".to_owned(),
                    ));
                }
                self.request_goal_cancellation(&format!("cancelled by {principal}"))?;
                Ok(intent)
            }
            GOAL_STATUS_CLAIMED => Err(ControllerError::NotReady(
                "goal is claimed for compilation; cancel after the current step".to_owned(),
            )),
            other => Err(ControllerError::InvalidPlan(format!(
                "goal status {other} cannot be cancelled"
            ))),
        }
    }

    /// Ends a queued goal as failed, for example when its input cannot be composed. Only the
    /// queued goal is touched; the queue moves on at the next step.
    ///
    /// # Errors
    /// Returns `NotReady` when the goal is not queued, or a state/validation error.
    pub fn fail_queued_goal_intent(
        &mut self,
        goal_id: &str,
        reason_code: &str,
        detail: &str,
    ) -> Result<GoalIntentV1, ControllerError> {
        self.end_queued_goal(
            goal_id,
            GoalOutcomeKindV1::Failed,
            reason_code,
            detail,
            "sovereign",
        )
    }

    /// Moves a goal that holds no live claim from the queue to a terminal status, together with
    /// its outcome record, in one compare-and-swap transition. A released claim is asserted
    /// unchanged; the intent alone advances.
    #[expect(
        clippy::too_many_lines,
        reason = "one atomic terminal transition validates intent, claim, and outcome together"
    )]
    fn end_queued_goal(
        &mut self,
        goal_id: &str,
        kind: GoalOutcomeKindV1,
        reason_code: &str,
        detail: &str,
        principal: &str,
    ) -> Result<GoalIntentV1, ControllerError> {
        self.validate_persisted_goal_lifecycle_versions()?;
        let intent_record = persisted_state_record(&self.state, GOAL_INTENT_NAMESPACE, goal_id)?;
        let intent = decode_versioned_goal_intent(&intent_record)?;
        if intent.status != GOAL_STATUS_QUEUED {
            return Err(ControllerError::NotReady(format!(
                "goal {goal_id} is not queued"
            )));
        }
        let claim_record = self
            .state
            .state_records(GOAL_INTENT_CLAIM_NAMESPACE)?
            .into_iter()
            .find(|record| record.key == goal_id);
        if let Some(record) = claim_record.as_ref() {
            let claim = decode_versioned_goal_claim(record)?;
            if claim.status != GoalIntentClaimStatusV1::Released {
                return Err(ControllerError::InvalidPlan(format!(
                    "queued goal {goal_id} holds a live claim"
                )));
            }
        }
        if self
            .state
            .get_state(GOAL_OUTCOME_NAMESPACE, goal_id)?
            .is_some()
        {
            return Err(ControllerError::InvalidPlan(format!(
                "goal {goal_id} already has a recorded outcome"
            )));
        }
        let status = match kind {
            GoalOutcomeKindV1::Failed => GOAL_STATUS_FAILED,
            GoalOutcomeKindV1::Cancelled => GOAL_STATUS_CANCELLED,
        };
        let ended = with_goal_status(intent, status);
        validate_goal_intent(goal_id, &ended)?;
        let outcome = GoalOutcomeV1 {
            schema_version: GOAL_OUTCOME_SCHEMA_VERSION,
            goal_id: goal_id.to_owned(),
            kind,
            reason_code: reason_code.to_owned(),
            detail: bounded_outcome_detail(detail),
            plan_id: None,
            plan_revision: None,
            recorded_at_ms: super::unix_millis()?,
        };
        validate_goal_outcome(goal_id, &outcome)?;
        let intent_json = serde_json::to_string(&ended)?;
        let outcome_json = serde_json::to_string(&outcome)?;
        let event_kind = match kind {
            GoalOutcomeKindV1::Failed => "goal_intent_failed",
            GoalOutcomeKindV1::Cancelled => "goal_intent_cancelled",
        };
        let payload_json = json!({
            "goal_id": goal_id,
            "status": ended.status,
            "reason_code": reason_code,
            "principal": principal,
            "outcome_digest": sha256_prefixed(outcome_json.as_bytes()),
        })
        .to_string();
        let seed = sha256_prefixed(
            format!(
                "{event_kind}\0{goal_id}\0{}\0{payload_json}",
                self.state.latest_journal_sequence()?
            )
            .as_bytes(),
        );
        let event_id = format!("controller.{}", &seed[7..27]);
        let claim_assertion = claim_record.as_ref().map(|record| StateRecordCasAssertion {
            namespace: GOAL_INTENT_CLAIM_NAMESPACE,
            key: goal_id,
            expected_version: record.version,
            expected_value_json: Some(&record.value_json),
            expected_value_digest: None,
        });
        self.state
            .compare_and_apply_state_records_with_events_guarded(
                None,
                claim_assertion.as_slice(),
                &[
                    StateRecordCasMutation {
                        namespace: GOAL_INTENT_NAMESPACE,
                        key: goal_id,
                        expected_version: Some(intent_record.version),
                        value_json: Some(&intent_json),
                    },
                    StateRecordCasMutation {
                        namespace: GOAL_OUTCOME_NAMESPACE,
                        key: goal_id,
                        expected_version: None,
                        value_json: Some(&outcome_json),
                    },
                ],
                &[NewJournalEvent {
                    event_id: &event_id,
                    entity_type: "controller",
                    entity_id: goal_id,
                    event_kind,
                    payload_json: &payload_json,
                }],
            )?;
        if self.active.is_some() {
            self.checkpoint_now()?;
        }
        Ok(ended)
    }

    /// Ends the active goal as failed or cancelled and retires its plan in one transaction:
    /// the goal intent and claim move to terminal statuses, the active pointer triad is removed,
    /// the revision lifecycle becomes `abandoned`, and an abandonment record plus a goal outcome
    /// are published. Every revision-scoped task, attempt, and evidence record is kept.
    ///
    /// # Errors
    /// Returns `NotReady` while anything is still in flight, and fails closed unless the
    /// lifecycle, claim, checkpoint, and active pointers all bind the same plan revision.
    #[expect(
        clippy::too_many_lines,
        reason = "plan abandonment validates and commits one atomic retirement transition"
    )]
    pub(crate) fn abandon_active_goal(
        &mut self,
        kind: GoalOutcomeKindV1,
        reason_code: &str,
        detail: &str,
    ) -> Result<GoalOutcomeV1, ControllerError> {
        self.reconcile_queued_goal_lifecycle()?;
        let active = self.canonical_active_goal_binding()?.ok_or_else(|| {
            ControllerError::InvalidPlan(
                "plan abandonment requires a canonical active plan".to_owned(),
            )
        })?;
        if self.completion_record()?.is_some() {
            return Err(ControllerError::NotReady(
                "a completed plan is finalized, not abandoned".to_owned(),
            ));
        }
        self.require_abandonment_recovery_clear()?;

        let intents = self.read_validated_goal_intents()?;
        let claims = self.read_validated_goal_claims()?;
        validate_claim_set(&intents, &claims)?;
        let intent = intent_by_id(&intents, &active.goal_id)?.clone();
        let claim = claims
            .iter()
            .find(|candidate| candidate.goal_id == active.goal_id)
            .cloned()
            .ok_or_else(|| {
                ControllerError::InvalidPlan("active plan lacks its queued-goal claim".to_owned())
            })?;
        if intent.status != GOAL_STATUS_ACTIVE || claim.status != GoalIntentClaimStatusV1::Active {
            return Err(ControllerError::InvalidPlan(
                "plan abandonment requires exact active intent and claim".to_owned(),
            ));
        }
        validate_claim_binding(&intent, &claim)?;
        validate_active_claim_binding(&active, &claim)?;

        self.checkpoint_now()?;
        let checkpoint = self
            .state
            .latest_valid_checkpoint_integrity()?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "plan abandonment lacks a trusted terminal checkpoint".to_owned(),
                )
            })?;
        if checkpoint.action_sequence != self.state.latest_journal_sequence()? {
            return Err(ControllerError::InvalidPlan(
                "terminal checkpoint does not cover the latest controller journal sequence"
                    .to_owned(),
            ));
        }

        let plan_record = persisted_state_record(&self.state, "controller.plan", "active")?;
        let plan_document_record =
            persisted_state_record(&self.state, "controller.plan_document", "active")?;
        let baseline_record =
            persisted_state_record(&self.state, "controller.repository_baseline", "active")?;
        let lifecycle_key = revision_record_key(&active.plan_id, active.plan_revision);
        let lifecycle_record = persisted_state_record(
            &self.state,
            "controller.plan_revision_lifecycle",
            &lifecycle_key,
        )?;
        validate_active_revision_lifecycle(&lifecycle_record, &active)?;
        let intent_record =
            persisted_state_record(&self.state, GOAL_INTENT_NAMESPACE, &intent.goal_id)?;
        let claim_record =
            persisted_state_record(&self.state, GOAL_INTENT_CLAIM_NAMESPACE, &claim.goal_id)?;
        if self
            .state
            .get_state(PLAN_ABANDONMENT_NAMESPACE, &lifecycle_key)?
            .is_some()
            || self
                .state
                .get_state(PLAN_FINALIZATION_NAMESPACE, &lifecycle_key)?
                .is_some()
            || self
                .state
                .get_state(GOAL_OUTCOME_NAMESPACE, &intent.goal_id)?
                .is_some()
        {
            return Err(ControllerError::InvalidPlan(
                "plan retirement record already exists while plan is still active".to_owned(),
            ));
        }

        let now = super::unix_millis()?;
        let (intent_status, claim_status) = match kind {
            GoalOutcomeKindV1::Failed => (GOAL_STATUS_FAILED, GoalIntentClaimStatusV1::Failed),
            GoalOutcomeKindV1::Cancelled => (
                GOAL_STATUS_CANCELLED_ACTIVE,
                GoalIntentClaimStatusV1::Cancelled,
            ),
        };
        let ended_intent = with_goal_status(intent.clone(), intent_status);
        let mut ended_claim = claim.clone();
        ended_claim.status = claim_status;
        ended_claim.updated_at_ms = now.max(claim.updated_at_ms);
        validate_goal_intent(&ended_intent.goal_id, &ended_intent)?;
        validate_goal_claim(&ended_claim.goal_id, &ended_claim)?;
        let intent_json = serde_json::to_string(&ended_intent)?;
        let claim_json = serde_json::to_string(&ended_claim)?;

        let outcome = GoalOutcomeV1 {
            schema_version: GOAL_OUTCOME_SCHEMA_VERSION,
            goal_id: active.goal_id.clone(),
            kind,
            reason_code: reason_code.to_owned(),
            detail: bounded_outcome_detail(detail),
            plan_id: Some(active.plan_id.clone()),
            plan_revision: Some(active.plan_revision),
            recorded_at_ms: now,
        };
        validate_goal_outcome(&outcome.goal_id, &outcome)?;
        let outcome_json = serde_json::to_string(&outcome)?;

        let abandonment = PlanAbandonmentV1 {
            schema_version: PLAN_ABANDONMENT_SCHEMA_VERSION,
            plan_id: active.plan_id.clone(),
            goal_id: active.goal_id.clone(),
            plan_revision: active.plan_revision,
            plan_digest: active.plan_digest.clone(),
            kind,
            reason_code: reason_code.to_owned(),
            goal_intent_version: intent_record.version + 1,
            goal_intent_digest: sha256_prefixed(intent_json.as_bytes()),
            goal_claim_version: claim_record.version + 1,
            goal_claim_digest: sha256_prefixed(claim_json.as_bytes()),
            checkpoint_generation: checkpoint.generation,
            checkpoint_action_sequence: checkpoint.action_sequence,
            checkpoint_hash: checkpoint.checkpoint_hash.clone(),
            abandoned_at_ms: now,
        };
        validate_plan_abandonment(&lifecycle_key, &abandonment)?;
        let abandonment_json = serde_json::to_string(&abandonment)?;
        let abandonment_digest = digest_json(&serde_json::to_value(&abandonment)?)?;
        let lifecycle_json = serde_json::to_string(&json!({
            "plan_id": active.plan_id,
            "revision": active.plan_revision,
            "plan_digest": active.plan_digest,
            "status": "abandoned",
            "superseded_by_revision": Value::Null,
            "superseded_by_digest": Value::Null,
            "abandonment_kind": kind,
            "abandonment_record_digest": abandonment_digest,
            "terminal_checkpoint_generation": checkpoint.generation,
            "terminal_checkpoint_action_sequence": checkpoint.action_sequence,
            "terminal_checkpoint_hash": checkpoint.checkpoint_hash,
        }))?;
        let event_payload = serde_json::to_string(&json!({
            "plan_id": abandonment.plan_id,
            "goal_id": abandonment.goal_id,
            "plan_revision": abandonment.plan_revision,
            "plan_digest": abandonment.plan_digest,
            "kind": kind,
            "reason_code": reason_code,
            "abandonment_record_digest": abandonment_digest,
            "terminal_checkpoint_generation": abandonment.checkpoint_generation,
            "terminal_checkpoint_action_sequence": abandonment.checkpoint_action_sequence,
            "terminal_checkpoint_hash": abandonment.checkpoint_hash,
        }))?;
        let seed = sha256_prefixed(
            format!(
                "plan_abandoned\0{}\0{}\0{}",
                lifecycle_key, checkpoint.action_sequence, event_payload
            )
            .as_bytes(),
        );
        let event_id = format!("controller.{}", &seed[7..27]);
        super::recovery_test_hook("before_plan_abandonment_commit");
        self.state
            .compare_and_apply_state_records_with_events_guarded(
                Some(checkpoint.action_sequence),
                &[],
                &[
                    StateRecordCasMutation {
                        namespace: GOAL_INTENT_NAMESPACE,
                        key: &intent.goal_id,
                        expected_version: Some(intent_record.version),
                        value_json: Some(&intent_json),
                    },
                    StateRecordCasMutation {
                        namespace: GOAL_INTENT_CLAIM_NAMESPACE,
                        key: &claim.goal_id,
                        expected_version: Some(claim_record.version),
                        value_json: Some(&claim_json),
                    },
                    StateRecordCasMutation {
                        namespace: "controller.plan",
                        key: "active",
                        expected_version: Some(plan_record.version),
                        value_json: None,
                    },
                    StateRecordCasMutation {
                        namespace: "controller.plan_document",
                        key: "active",
                        expected_version: Some(plan_document_record.version),
                        value_json: None,
                    },
                    StateRecordCasMutation {
                        namespace: "controller.repository_baseline",
                        key: "active",
                        expected_version: Some(baseline_record.version),
                        value_json: None,
                    },
                    StateRecordCasMutation {
                        namespace: "controller.plan_revision_lifecycle",
                        key: &lifecycle_key,
                        expected_version: Some(lifecycle_record.version),
                        value_json: Some(&lifecycle_json),
                    },
                    StateRecordCasMutation {
                        namespace: PLAN_ABANDONMENT_NAMESPACE,
                        key: &lifecycle_key,
                        expected_version: None,
                        value_json: Some(&abandonment_json),
                    },
                    StateRecordCasMutation {
                        namespace: GOAL_OUTCOME_NAMESPACE,
                        key: &outcome.goal_id,
                        expected_version: None,
                        value_json: Some(&outcome_json),
                    },
                ],
                &[NewJournalEvent {
                    event_id: &event_id,
                    entity_type: "controller",
                    entity_id: &lifecycle_key,
                    event_kind: "plan_abandoned",
                    payload_json: &event_payload,
                }],
            )?;
        super::recovery_test_hook("after_plan_abandonment_commit");
        self.active = None;
        Ok(outcome)
    }
}

fn persisted_state_record(
    state: &StateStore,
    namespace: &str,
    key: &str,
) -> Result<PersistedStateRecord, ControllerError> {
    state
        .state_records(namespace)?
        .into_iter()
        .find(|record| record.key == key)
        .ok_or_else(|| {
            ControllerError::InvalidPlan(format!(
                "required durable state record {namespace}/{key} is missing"
            ))
        })
}

fn validate_active_revision_lifecycle(
    record: &PersistedStateRecord,
    active: &ActiveGoalBinding,
) -> Result<(), ControllerError> {
    let value: Value = serde_json::from_str(&record.value_json)?;
    if record.key != revision_record_key(&active.plan_id, active.plan_revision)
        || required_str(&value, "/plan_id")? != active.plan_id
        || required_u32(&value, "/revision")? != active.plan_revision
        || required_str(&value, "/plan_digest")? != active.plan_digest
        || required_str(&value, "/status")? != "active"
    {
        return Err(ControllerError::InvalidPlan(
            "active plan revision lifecycle is malformed or misbound".to_owned(),
        ));
    }
    Ok(())
}

fn validate_plan_finalization(
    record_key: &str,
    finalization: &PlanFinalizationV1,
) -> Result<(), ControllerError> {
    if finalization.schema_version != PLAN_FINALIZATION_SCHEMA_VERSION
        || finalization.plan_id.trim().is_empty()
        || finalization.goal_id.trim().is_empty()
        || finalization.plan_revision == 0
        || record_key != revision_record_key(&finalization.plan_id, finalization.plan_revision)
        || !finalization.plan_digest.starts_with("sha256:")
        || finalization.completion_record_key
            != completion_record_key(&finalization.plan_id, finalization.plan_revision)
        || !finalization.completion_record_digest.starts_with("sha256:")
        || finalization.goal_intent_version <= 0
        || !finalization.goal_intent_digest.starts_with("sha256:")
        || finalization.goal_claim_version <= 0
        || !finalization.goal_claim_digest.starts_with("sha256:")
        || finalization.checkpoint_generation <= 0
        || finalization.checkpoint_action_sequence < 0
        || finalization.checkpoint_hash.trim().is_empty()
        || finalization.finalized_at_ms <= 0
    {
        return Err(ControllerError::InvalidPlan(format!(
            "malformed completed-plan finalization {record_key}"
        )));
    }
    Ok(())
}

fn validate_plan_abandonment(
    record_key: &str,
    abandonment: &PlanAbandonmentV1,
) -> Result<(), ControllerError> {
    if abandonment.schema_version != PLAN_ABANDONMENT_SCHEMA_VERSION
        || abandonment.plan_id.trim().is_empty()
        || abandonment.goal_id.trim().is_empty()
        || abandonment.plan_revision == 0
        || record_key != revision_record_key(&abandonment.plan_id, abandonment.plan_revision)
        || !abandonment.plan_digest.starts_with("sha256:")
        || abandonment.reason_code.trim().is_empty()
        || abandonment.goal_intent_version <= 0
        || !abandonment.goal_intent_digest.starts_with("sha256:")
        || abandonment.goal_claim_version <= 0
        || !abandonment.goal_claim_digest.starts_with("sha256:")
        || abandonment.checkpoint_generation <= 0
        || abandonment.checkpoint_action_sequence < 0
        || abandonment.checkpoint_hash.trim().is_empty()
        || abandonment.abandoned_at_ms <= 0
    {
        return Err(ControllerError::InvalidPlan(format!(
            "malformed plan abandonment {record_key}"
        )));
    }
    Ok(())
}

/// Validates one retired-by-abandonment revision: the abandonment record, its terminal
/// checkpoint, the exact terminal goal intent and claim it bound, its goal outcome, its revision
/// lifecycle, and its single publication event.
#[expect(
    clippy::too_many_lines,
    reason = "abandonment history binds record, checkpoint, lifecycle, goal, and event together"
)]
fn validate_abandonment_history_record(
    state: &StateStore,
    revision: &Value,
    lifecycle: &Value,
    abandonment_record: &PersistedStateRecord,
) -> Result<(), ControllerError> {
    let abandonment: PlanAbandonmentV1 = serde_json::from_str(&abandonment_record.value_json)?;
    validate_plan_abandonment(&abandonment_record.key, &abandonment)?;
    if required_str(revision, "/plan_id")? != abandonment.plan_id
        || required_u32(revision, "/revision")? != abandonment.plan_revision
        || required_str(revision, "/plan_digest")? != abandonment.plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "plan abandonment does not bind its immutable plan revision".to_owned(),
        ));
    }
    let plan_document = revision.get("plan_document").ok_or_else(|| {
        ControllerError::InvalidPlan("plan revision lacks canonical plan document".to_owned())
    })?;
    if required_str(plan_document, "/goal/goal_id")? != abandonment.goal_id
        || digest_json(plan_document)? != abandonment.plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "plan abandonment goal/document binding is invalid".to_owned(),
        ));
    }

    let checkpoint = state
        .checkpoint_integrity_by_generation(abandonment.checkpoint_generation)?
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "plan abandonment terminal checkpoint is missing".to_owned(),
            )
        })?;
    if checkpoint.action_sequence != abandonment.checkpoint_action_sequence
        || checkpoint.checkpoint_hash != abandonment.checkpoint_hash
    {
        return Err(ControllerError::InvalidPlan(
            "plan abandonment terminal checkpoint binding is invalid".to_owned(),
        ));
    }
    let checkpoint_is_trusted =
        state
            .latest_valid_checkpoint_ancestry()?
            .into_iter()
            .any(|trusted| {
                trusted.generation == abandonment.checkpoint_generation
                    && trusted.action_sequence == abandonment.checkpoint_action_sequence
                    && trusted.checkpoint_hash == abandonment.checkpoint_hash
            });
    if !checkpoint_is_trusted {
        return Err(ControllerError::InvalidPlan(
            "plan abandonment terminal checkpoint is absent from trusted checkpoint ancestry"
                .to_owned(),
        ));
    }

    let intent_record = persisted_state_record(state, GOAL_INTENT_NAMESPACE, &abandonment.goal_id)?;
    let claim_record =
        persisted_state_record(state, GOAL_INTENT_CLAIM_NAMESPACE, &abandonment.goal_id)?;
    if intent_record.version != abandonment.goal_intent_version
        || sha256_prefixed(intent_record.value_json.as_bytes()) != abandonment.goal_intent_digest
        || claim_record.version != abandonment.goal_claim_version
        || sha256_prefixed(claim_record.value_json.as_bytes()) != abandonment.goal_claim_digest
    {
        return Err(ControllerError::InvalidPlan(
            "plan abandonment queued-goal record binding is stale".to_owned(),
        ));
    }
    let intent = decode_versioned_goal_intent(&intent_record)?;
    let claim = decode_versioned_goal_claim(&claim_record)?;
    let (expected_intent_status, expected_claim_status) = match abandonment.kind {
        GoalOutcomeKindV1::Failed => (GOAL_STATUS_FAILED, GoalIntentClaimStatusV1::Failed),
        GoalOutcomeKindV1::Cancelled => (
            GOAL_STATUS_CANCELLED_ACTIVE,
            GoalIntentClaimStatusV1::Cancelled,
        ),
    };
    if intent.status != expected_intent_status || claim.status != expected_claim_status {
        return Err(ControllerError::InvalidPlan(
            "plan abandonment queued-goal lifecycle is not terminal".to_owned(),
        ));
    }
    validate_claim_binding(&intent, &claim)?;
    let active = ActiveGoalBinding {
        goal_id: abandonment.goal_id.clone(),
        goal_statement: required_str(plan_document, "/goal/statement")?.to_owned(),
        plan_id: abandonment.plan_id.clone(),
        plan_revision: abandonment.plan_revision,
        plan_digest: abandonment.plan_digest.clone(),
    };
    validate_active_claim_binding(&active, &claim)?;

    let outcome_raw = state
        .get_state(GOAL_OUTCOME_NAMESPACE, &abandonment.goal_id)?
        .ok_or_else(|| {
            ControllerError::InvalidPlan("plan abandonment lacks its goal outcome".to_owned())
        })?;
    let outcome: GoalOutcomeV1 = serde_json::from_str(&outcome_raw)?;
    validate_goal_outcome(&abandonment.goal_id, &outcome)?;
    if outcome.kind != abandonment.kind
        || outcome.reason_code != abandonment.reason_code
        || outcome.plan_id.as_deref() != Some(abandonment.plan_id.as_str())
        || outcome.plan_revision != Some(abandonment.plan_revision)
    {
        return Err(ControllerError::InvalidPlan(
            "plan abandonment goal outcome binding is invalid".to_owned(),
        ));
    }

    let abandonment_digest = digest_json(&serde_json::to_value(&abandonment)?)?;
    if required_str(lifecycle, "/abandonment_record_digest")? != abandonment_digest
        || lifecycle
            .get("terminal_checkpoint_generation")
            .and_then(Value::as_i64)
            != Some(abandonment.checkpoint_generation)
        || lifecycle
            .get("terminal_checkpoint_action_sequence")
            .and_then(Value::as_i64)
            != Some(abandonment.checkpoint_action_sequence)
        || required_str(lifecycle, "/terminal_checkpoint_hash")? != abandonment.checkpoint_hash
    {
        return Err(ControllerError::InvalidPlan(
            "abandoned lifecycle does not bind the exact plan abandonment record".to_owned(),
        ));
    }

    let expected_publication_sequence = abandonment
        .checkpoint_action_sequence
        .checked_add(1)
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "plan abandonment checkpoint action sequence cannot advance".to_owned(),
            )
        })?;
    let mut matching = 0_usize;
    for event in state.journal()? {
        if event.event_kind != "plan_abandoned"
            || event.entity_type != "controller"
            || event.entity_id != abandonment_record.key
        {
            continue;
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        if required_str(&payload, "/abandonment_record_digest")? != abandonment_digest
            || required_str(&payload, "/goal_id")? != abandonment.goal_id
            || required_str(&payload, "/plan_digest")? != abandonment.plan_digest
            || event.sequence != expected_publication_sequence
        {
            return Err(ControllerError::InvalidPlan(
                "plan_abandoned event is misbound".to_owned(),
            ));
        }
        matching = matching.saturating_add(1);
    }
    if matching != 1 {
        return Err(ControllerError::InvalidPlan(format!(
            "plan abandonment requires exactly one plan_abandoned event, found {matching}"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_finalized_plan_history(state: &StateStore) -> Result<(), ControllerError> {
    if state.get_state("controller.plan", "active")?.is_some() {
        return Err(ControllerError::InvalidPlan(
            "no-active validation found a durable active plan".to_owned(),
        ));
    }
    if state
        .get_state("controller.plan_document", "active")?
        .is_some()
        || state
            .get_state("controller.repository_baseline", "active")?
            .is_some()
    {
        return Err(ControllerError::InvalidPlan(
            "inactive Controller retains a partial active plan pointer set".to_owned(),
        ));
    }

    let revisions = state.state_records("controller.plan_revision")?;
    let lifecycles = state.state_records("controller.plan_revision_lifecycle")?;
    let finalizations = state.state_records(PLAN_FINALIZATION_NAMESPACE)?;
    let abandonments = state.state_records(PLAN_ABANDONMENT_NAMESPACE)?;
    if revisions.is_empty() {
        if !lifecycles.is_empty() || !finalizations.is_empty() || !abandonments.is_empty() {
            return Err(ControllerError::InvalidPlan(
                "plan lifecycle/finalization history exists without plan revision history"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    if revisions.len() != lifecycles.len() {
        return Err(ControllerError::InvalidPlan(
            "plan revision history and lifecycle history cardinality differ".to_owned(),
        ));
    }

    let mut max_revision_by_plan = BTreeMap::<String, u32>::new();
    // A plan terminates in exactly one revision, either completed or abandoned.
    let mut completed_revision_by_plan = BTreeMap::<String, u32>::new();
    let mut revision_chain_by_plan =
        BTreeMap::<String, BTreeMap<u32, (String, Value, Value)>>::new();
    let mut completed_count = 0_usize;
    let mut abandoned_count = 0_usize;
    for revision_record in &revisions {
        let revision: Value = serde_json::from_str(&revision_record.value_json)?;
        let plan_id = required_str(&revision, "/plan_id")?.to_owned();
        let plan_revision = required_u32(&revision, "/revision")?;
        let plan_digest = required_str(&revision, "/plan_digest")?.to_owned();
        let expected_key = revision_record_key(&plan_id, plan_revision);
        if revision_record.key != expected_key {
            return Err(ControllerError::InvalidPlan(
                "plan revision durable key does not match revision identity".to_owned(),
            ));
        }
        max_revision_by_plan
            .entry(plan_id.clone())
            .and_modify(|revision| *revision = (*revision).max(plan_revision))
            .or_insert(plan_revision);

        let lifecycle_record = lifecycles
            .iter()
            .find(|candidate| candidate.key == expected_key)
            .ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "plan revision {expected_key} lacks lifecycle history"
                ))
            })?;
        let lifecycle: Value = serde_json::from_str(&lifecycle_record.value_json)?;
        if required_str(&lifecycle, "/plan_id")? != plan_id
            || required_u32(&lifecycle, "/revision")? != plan_revision
            || required_str(&lifecycle, "/plan_digest")? != plan_digest
        {
            return Err(ControllerError::InvalidPlan(format!(
                "plan revision lifecycle {expected_key} is misbound"
            )));
        }
        let plan_document = revision.get("plan_document").ok_or_else(|| {
            ControllerError::InvalidPlan(format!(
                "plan revision {expected_key} lacks canonical plan document"
            ))
        })?;
        if required_str(plan_document, "/plan_id")? != plan_id
            || required_u32(plan_document, "/revision")? != plan_revision
            || digest_json(plan_document)? != plan_digest
        {
            return Err(ControllerError::InvalidPlan(format!(
                "plan revision {expected_key} canonical document is misbound"
            )));
        }
        if revision_chain_by_plan
            .entry(plan_id.clone())
            .or_default()
            .insert(
                plan_revision,
                (plan_digest.clone(), revision.clone(), lifecycle.clone()),
            )
            .is_some()
        {
            return Err(ControllerError::InvalidPlan(format!(
                "plan {plan_id} has duplicate durable revision {plan_revision}"
            )));
        }
        match required_str(&lifecycle, "/status")? {
            "superseded" => {
                if finalizations
                    .iter()
                    .chain(abandonments.iter())
                    .any(|candidate| candidate.key == expected_key)
                {
                    return Err(ControllerError::InvalidPlan(
                        "superseded revision unexpectedly has a retirement record".to_owned(),
                    ));
                }
            }
            "abandoned" => {
                abandoned_count = abandoned_count.saturating_add(1);
                if completed_revision_by_plan
                    .insert(plan_id.clone(), plan_revision)
                    .is_some()
                {
                    return Err(ControllerError::InvalidPlan(format!(
                        "plan {plan_id} has multiple terminal revisions"
                    )));
                }
                if finalizations
                    .iter()
                    .any(|candidate| candidate.key == expected_key)
                {
                    return Err(ControllerError::InvalidPlan(
                        "abandoned revision unexpectedly has a finalization record".to_owned(),
                    ));
                }
                let abandonment_record = abandonments
                    .iter()
                    .find(|candidate| candidate.key == expected_key)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(format!(
                            "abandoned revision {expected_key} lacks its abandonment record"
                        ))
                    })?;
                validate_abandonment_history_record(
                    state,
                    &revision,
                    &lifecycle,
                    abandonment_record,
                )?;
            }
            "completed" => {
                completed_count = completed_count.saturating_add(1);
                if completed_revision_by_plan
                    .insert(plan_id.clone(), plan_revision)
                    .is_some()
                {
                    return Err(ControllerError::InvalidPlan(format!(
                        "plan {plan_id} has multiple completed revisions"
                    )));
                }
                let finalization_record = finalizations
                    .iter()
                    .find(|candidate| candidate.key == expected_key)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(format!(
                            "completed revision {expected_key} lacks finalization authority"
                        ))
                    })?;
                validate_finalization_history_record(
                    state,
                    &revision,
                    &lifecycle,
                    finalization_record,
                )?;
            }
            "active" => {
                return Err(ControllerError::InvalidPlan(
                    "active revision lifecycle exists without active plan pointers".to_owned(),
                ));
            }
            other => {
                return Err(ControllerError::InvalidPlan(format!(
                    "unknown plan revision lifecycle status {other}"
                )));
            }
        }
    }

    if finalizations.len() != completed_count {
        return Err(ControllerError::InvalidPlan(
            "orphan or duplicate plan finalization records exist".to_owned(),
        ));
    }
    if abandonments.len() != abandoned_count {
        return Err(ControllerError::InvalidPlan(
            "orphan or duplicate plan abandonment records exist".to_owned(),
        ));
    }
    for (plan_id, max_revision) in &max_revision_by_plan {
        if completed_revision_by_plan.get(plan_id) != Some(max_revision) {
            return Err(ControllerError::InvalidPlan(format!(
                "plan {plan_id} does not terminate in exactly its latest terminal revision"
            )));
        }
    }
    for (plan_id, history) in revision_chain_by_plan {
        let max_revision = *max_revision_by_plan.get(&plan_id).ok_or_else(|| {
            ControllerError::InvalidPlan(format!(
                "plan {plan_id} revision chain lacks a maximum revision"
            ))
        })?;
        if history.len()
            != usize::try_from(max_revision).map_err(|_| {
                ControllerError::InvalidPlan(format!(
                    "plan {plan_id} revision count exceeds platform limits"
                ))
            })?
        {
            return Err(ControllerError::InvalidPlan(format!(
                "plan {plan_id} revision history is not contiguous from revision 1"
            )));
        }
        for plan_revision in 1..=max_revision {
            let (plan_digest, revision, lifecycle) =
                history.get(&plan_revision).ok_or_else(|| {
                    ControllerError::InvalidPlan(format!(
                        "plan {plan_id} is missing durable revision {plan_revision}"
                    ))
                })?;
            let plan_document = revision.get("plan_document").ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "plan {plan_id} revision {plan_revision} lacks canonical plan document"
                ))
            })?;
            if plan_revision == 1 {
                if !plan_document
                    .get("supersedes_revision")
                    .is_some_and(Value::is_null)
                    || revision
                        .get("previous_plan_digest")
                        .is_some_and(|value| !value.is_null())
                {
                    return Err(ControllerError::InvalidPlan(format!(
                        "plan {plan_id} revision 1 has invalid supersession ancestry"
                    )));
                }
            } else {
                let previous_revision = plan_revision - 1;
                let previous_digest = &history
                    .get(&previous_revision)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(format!(
                            "plan {plan_id} revision {plan_revision} lacks predecessor {previous_revision}"
                        ))
                    })?
                    .0;
                if plan_document
                    .get("supersedes_revision")
                    .and_then(Value::as_u64)
                    != Some(u64::from(previous_revision))
                    || revision.get("previous_plan_digest").and_then(Value::as_str)
                        != Some(previous_digest.as_str())
                {
                    return Err(ControllerError::InvalidPlan(format!(
                        "plan {plan_id} revision {plan_revision} does not bind its exact predecessor"
                    )));
                }
            }

            if plan_revision < max_revision {
                let next_revision = plan_revision + 1;
                let next_digest = &history
                    .get(&next_revision)
                    .ok_or_else(|| {
                        ControllerError::InvalidPlan(format!(
                            "plan {plan_id} revision {plan_revision} lacks successor {next_revision}"
                        ))
                    })?
                    .0;
                if required_str(lifecycle, "/status")? != "superseded"
                    || lifecycle
                        .get("superseded_by_revision")
                        .and_then(Value::as_u64)
                        != Some(u64::from(next_revision))
                    || lifecycle
                        .get("superseded_by_digest")
                        .and_then(Value::as_str)
                        != Some(next_digest.as_str())
                {
                    return Err(ControllerError::InvalidPlan(format!(
                        "plan {plan_id} revision {plan_revision} supersession chain is misbound"
                    )));
                }
            } else if !matches!(
                required_str(lifecycle, "/status")?,
                "completed" | "abandoned"
            ) || !lifecycle
                .get("superseded_by_revision")
                .is_some_and(Value::is_null)
                || !lifecycle
                    .get("superseded_by_digest")
                    .is_some_and(Value::is_null)
                || completed_revision_by_plan.get(&plan_id) != Some(&plan_revision)
                || required_str(lifecycle, "/plan_digest")? != plan_digest
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "plan {plan_id} latest revision {plan_revision} is not exactly completed or abandoned"
                )));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_finalization_history_record(
    state: &StateStore,
    revision: &Value,
    lifecycle: &Value,
    finalization_record: &PersistedStateRecord,
) -> Result<(), ControllerError> {
    let finalization: PlanFinalizationV1 = serde_json::from_str(&finalization_record.value_json)?;
    validate_plan_finalization(&finalization_record.key, &finalization)?;
    if required_str(revision, "/plan_id")? != finalization.plan_id
        || required_u32(revision, "/revision")? != finalization.plan_revision
        || required_str(revision, "/plan_digest")? != finalization.plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "plan finalization does not bind its immutable plan revision".to_owned(),
        ));
    }
    let plan_document = revision.get("plan_document").ok_or_else(|| {
        ControllerError::InvalidPlan("plan revision lacks canonical plan document".to_owned())
    })?;
    if required_str(plan_document, "/goal/goal_id")? != finalization.goal_id
        || digest_json(plan_document)? != finalization.plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "plan finalization goal/document binding is invalid".to_owned(),
        ));
    }

    let completion_raw = state
        .get_state(
            "controller.completion_record",
            &finalization.completion_record_key,
        )?
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "plan finalization lacks its canonical completion record".to_owned(),
            )
        })?;
    let completion: CompletionRecordV1 = serde_json::from_str(&completion_raw)?;
    if completion.canonical_digest()? != finalization.completion_record_digest
        || completion.plan_id != finalization.plan_id
        || completion.goal_id != finalization.goal_id
        || completion.plan_revision != finalization.plan_revision
        || completion.plan_digest != finalization.plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "plan finalization completion binding is invalid".to_owned(),
        ));
    }
    super::validate_completion_record_cas(state, &completion)?;
    super::validate_completion_checkpoint_ancestry(state, &completion)?;
    validate_completion_publication_event(state, &completion)?;

    let checkpoint = state
        .checkpoint_integrity_by_generation(finalization.checkpoint_generation)?
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "plan finalization terminal checkpoint is missing".to_owned(),
            )
        })?;
    if checkpoint.action_sequence != finalization.checkpoint_action_sequence
        || checkpoint.checkpoint_hash != finalization.checkpoint_hash
        || finalization.checkpoint_generation <= completion.checkpoint.generation
        || finalization.checkpoint_action_sequence < completion.checkpoint.action_sequence
    {
        return Err(ControllerError::InvalidPlan(
            "plan finalization terminal checkpoint binding is invalid".to_owned(),
        ));
    }
    let checkpoint_is_trusted =
        state
            .latest_valid_checkpoint_ancestry()?
            .into_iter()
            .any(|trusted| {
                trusted.generation == finalization.checkpoint_generation
                    && trusted.action_sequence == finalization.checkpoint_action_sequence
                    && trusted.checkpoint_hash == finalization.checkpoint_hash
            });
    if !checkpoint_is_trusted {
        return Err(ControllerError::InvalidPlan(
            "plan finalization terminal checkpoint is absent from trusted checkpoint ancestry"
                .to_owned(),
        ));
    }

    let intent_record =
        persisted_state_record(state, GOAL_INTENT_NAMESPACE, &finalization.goal_id)?;
    let claim_record =
        persisted_state_record(state, GOAL_INTENT_CLAIM_NAMESPACE, &finalization.goal_id)?;
    if intent_record.version != finalization.goal_intent_version
        || sha256_prefixed(intent_record.value_json.as_bytes()) != finalization.goal_intent_digest
        || claim_record.version != finalization.goal_claim_version
        || sha256_prefixed(claim_record.value_json.as_bytes()) != finalization.goal_claim_digest
    {
        return Err(ControllerError::InvalidPlan(
            "plan finalization queued-goal record binding is stale".to_owned(),
        ));
    }
    let intent = decode_versioned_goal_intent(&intent_record)?;
    let claim = decode_versioned_goal_claim(&claim_record)?;
    if intent.status != GOAL_STATUS_COMPLETED || claim.status != GoalIntentClaimStatusV1::Completed
    {
        return Err(ControllerError::InvalidPlan(
            "plan finalization queued-goal lifecycle is not completed".to_owned(),
        ));
    }
    validate_claim_binding(&intent, &claim)?;
    let active = ActiveGoalBinding {
        goal_id: finalization.goal_id.clone(),
        goal_statement: required_str(plan_document, "/goal/statement")?.to_owned(),
        plan_id: finalization.plan_id.clone(),
        plan_revision: finalization.plan_revision,
        plan_digest: finalization.plan_digest.clone(),
    };
    validate_active_claim_binding(&active, &claim)?;
    validate_completion_binding(&completion, &active, &claim)?;

    let finalization_digest = digest_json(&serde_json::to_value(&finalization)?)?;
    if required_str(lifecycle, "/completion_record_digest")?
        != finalization.completion_record_digest
        || required_str(lifecycle, "/finalization_record_digest")? != finalization_digest
        || lifecycle
            .get("terminal_checkpoint_generation")
            .and_then(Value::as_i64)
            != Some(finalization.checkpoint_generation)
        || lifecycle
            .get("terminal_checkpoint_action_sequence")
            .and_then(Value::as_i64)
            != Some(finalization.checkpoint_action_sequence)
        || required_str(lifecycle, "/terminal_checkpoint_hash")? != finalization.checkpoint_hash
    {
        return Err(ControllerError::InvalidPlan(
            "completed lifecycle does not bind the exact plan finalization record".to_owned(),
        ));
    }
    validate_finalization_publication_event(state, &finalization_record.key, &finalization)?;
    Ok(())
}

fn validate_finalization_publication_event(
    state: &StateStore,
    record_key: &str,
    finalization: &PlanFinalizationV1,
) -> Result<(), ControllerError> {
    let finalization_digest = digest_json(&serde_json::to_value(finalization)?)?;
    let expected_publication_sequence = finalization
        .checkpoint_action_sequence
        .checked_add(1)
        .ok_or_else(|| {
            ControllerError::InvalidPlan(
                "plan finalization checkpoint action sequence cannot advance".to_owned(),
            )
        })?;
    let mut matching = 0_usize;
    for event in state.journal()? {
        if event.event_kind != "plan_finalized" {
            continue;
        }
        if event.entity_type != "controller" || event.entity_id != record_key {
            continue;
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        if required_str(&payload, "/plan_id")? == finalization.plan_id
            && required_u32(&payload, "/plan_revision")? == finalization.plan_revision
        {
            if required_str(&payload, "/goal_id")? != finalization.goal_id
                || required_str(&payload, "/plan_digest")? != finalization.plan_digest
                || required_str(&payload, "/completion_record_digest")?
                    != finalization.completion_record_digest
                || required_str(&payload, "/finalization_record_digest")? != finalization_digest
                || payload
                    .get("terminal_checkpoint_generation")
                    .and_then(Value::as_i64)
                    != Some(finalization.checkpoint_generation)
                || payload
                    .get("terminal_checkpoint_action_sequence")
                    .and_then(Value::as_i64)
                    != Some(finalization.checkpoint_action_sequence)
                || required_str(&payload, "/terminal_checkpoint_hash")?
                    != finalization.checkpoint_hash
                || event.sequence != expected_publication_sequence
            {
                return Err(ControllerError::InvalidPlan(
                    "plan_finalized event is misbound".to_owned(),
                ));
            }
            matching = matching.saturating_add(1);
        }
    }
    if matching != 1 {
        return Err(ControllerError::InvalidPlan(format!(
            "plan finalization requires exactly one plan_finalized event, found {matching}"
        )));
    }
    Ok(())
}

fn validate_goal_intent(record_key: &str, intent: &GoalIntentV1) -> Result<(), ControllerError> {
    if intent.schema_version != GOAL_INTENT_SCHEMA_VERSION
        || intent.goal_id != record_key
        || intent.goal_id.trim().is_empty()
        || intent.natural_language_goal.trim().is_empty()
        || intent.submitted_at_ms <= 0
        || !matches!(
            intent.status.as_str(),
            GOAL_STATUS_QUEUED
                | GOAL_STATUS_CLAIMED
                | GOAL_STATUS_ACTIVE
                | GOAL_STATUS_COMPLETED
                | GOAL_STATUS_CANCELLED
                | GOAL_STATUS_FAILED
                | GOAL_STATUS_CANCELLED_ACTIVE
        )
    {
        return Err(ControllerError::InvalidPlan(format!(
            "malformed durable queued-goal intent {record_key}"
        )));
    }
    if let Some(grant) = &intent.browser_grant {
        grant.acceptance.validate().map_err(|error| {
            ControllerError::InvalidPlan(format!("malformed durable browser grant: {error}"))
        })?;
        let binding = serde_json::json!({
            "schema_version": grant.schema_version,
            "goal_id": intent.goal_id,
            "granted_at_ms": grant.granted_at_ms,
            "acceptance": grant.acceptance,
        });
        let expected_digest = digest_json(&binding)?;
        let expected_id = format!("browser-grant-{}", &expected_digest[7..23]);
        if grant.schema_version != 1
            || grant.granted_at_ms != intent.submitted_at_ms
            || grant.grant_id != expected_id
        {
            return Err(ControllerError::InvalidPlan(format!(
                "durable browser grant does not bind the exact goal intent {record_key}"
            )));
        }
    }
    Ok(())
}

fn goal_lifecycle_cas_mutations<'a>(
    goal_id: &'a str,
    versions: GoalLifecycleRecordVersions,
    intent_json: &'a str,
    claim_json: &'a str,
) -> [StateRecordCasMutation<'a>; 2] {
    [
        StateRecordCasMutation {
            namespace: GOAL_INTENT_NAMESPACE,
            key: goal_id,
            expected_version: Some(versions.intent_version),
            value_json: Some(intent_json),
        },
        StateRecordCasMutation {
            namespace: GOAL_INTENT_CLAIM_NAMESPACE,
            key: goal_id,
            expected_version: versions.claim_version,
            value_json: Some(claim_json),
        },
    ]
}

fn decode_versioned_goal_intent(
    record: &PersistedStateRecord,
) -> Result<GoalIntentV1, ControllerError> {
    if record.version <= 0 {
        return Err(ControllerError::InvalidPlan(format!(
            "durable goal intent {} has non-positive state-record version {}",
            record.key, record.version
        )));
    }
    let intent: GoalIntentV1 = serde_json::from_str(&record.value_json)?;
    validate_goal_intent(&record.key, &intent)?;
    Ok(intent)
}

fn validate_goal_claim(record_key: &str, claim: &GoalIntentClaimV1) -> Result<(), ControllerError> {
    if claim.schema_version != GOAL_INTENT_CLAIM_SCHEMA_VERSION
        || claim.goal_id != record_key
        || claim.goal_id.trim().is_empty()
        || !claim.goal_statement_digest.starts_with("sha256:")
        || claim.plan_id.trim().is_empty()
        || !claim.plan_digest.starts_with("sha256:")
        || !claim.compilation_evidence_digest.starts_with("sha256:")
        || claim.claimed_at_ms <= 0
        || claim.updated_at_ms < claim.claimed_at_ms
    {
        return Err(ControllerError::InvalidPlan(format!(
            "malformed durable queued-goal claim {record_key}"
        )));
    }
    Ok(())
}

fn decode_versioned_goal_claim(
    record: &PersistedStateRecord,
) -> Result<GoalIntentClaimV1, ControllerError> {
    if record.version <= 0 {
        return Err(ControllerError::InvalidPlan(format!(
            "durable goal claim {} has non-positive state-record version {}",
            record.key, record.version
        )));
    }
    let claim: GoalIntentClaimV1 = serde_json::from_str(&record.value_json)?;
    validate_goal_claim(&record.key, &claim)?;
    Ok(claim)
}

fn validate_goal_lifecycle_record_versions(
    versions: GoalLifecycleRecordVersions,
) -> Result<(), ControllerError> {
    if versions.intent_version <= 0 {
        return Err(ControllerError::InvalidPlan(
            "durable goal intent has a non-positive state-record version".to_owned(),
        ));
    }
    if let Some(claim_version) = versions.claim_version
        && (claim_version <= 0 || versions.intent_version != claim_version + 1)
    {
        return Err(ControllerError::InvalidPlan(format!(
            "queued-goal intent/claim record versions conflict: intent={}, claim={claim_version}",
            versions.intent_version
        )));
    }
    Ok(())
}

fn validate_claim_set(
    intents: &[GoalIntentV1],
    claims: &[GoalIntentClaimV1],
) -> Result<(), ControllerError> {
    let live_claims = claims
        .iter()
        .filter(|claim| {
            matches!(
                claim.status,
                GoalIntentClaimStatusV1::Claimed | GoalIntentClaimStatusV1::Active
            )
        })
        .count();
    if live_claims > 1 {
        return Err(ControllerError::InvalidPlan(
            "multiple live durable queued-goal claims exist".to_owned(),
        ));
    }
    let live_intents = intents
        .iter()
        .filter(|intent| {
            matches!(
                intent.status.as_str(),
                GOAL_STATUS_CLAIMED | GOAL_STATUS_ACTIVE
            )
        })
        .count();
    if live_intents > 1 {
        return Err(ControllerError::InvalidPlan(
            "multiple claimed/active durable goal intents exist".to_owned(),
        ));
    }
    for claim in claims {
        let intent = intent_by_id(intents, &claim.goal_id)?;
        validate_claim_binding(intent, claim)?;
        match claim.status {
            GoalIntentClaimStatusV1::Claimed if intent.status != GOAL_STATUS_CLAIMED => {
                return Err(ControllerError::InvalidPlan(
                    "claimed goal claim does not have claimed intent status".to_owned(),
                ));
            }
            GoalIntentClaimStatusV1::Active if intent.status != GOAL_STATUS_ACTIVE => {
                return Err(ControllerError::InvalidPlan(
                    "active goal claim does not have active intent status".to_owned(),
                ));
            }
            GoalIntentClaimStatusV1::Completed if intent.status != GOAL_STATUS_COMPLETED => {
                return Err(ControllerError::InvalidPlan(
                    "completed goal claim does not have completed intent status".to_owned(),
                ));
            }
            GoalIntentClaimStatusV1::Released
                if intent.status != GOAL_STATUS_QUEUED
                    && !is_unclaimed_terminal_status(&intent.status) =>
            {
                return Err(ControllerError::InvalidPlan(
                    "released goal claim does not have queued intent status".to_owned(),
                ));
            }
            GoalIntentClaimStatusV1::Failed if intent.status != GOAL_STATUS_FAILED => {
                return Err(ControllerError::InvalidPlan(
                    "failed goal claim does not have failed intent status".to_owned(),
                ));
            }
            GoalIntentClaimStatusV1::Cancelled if intent.status != GOAL_STATUS_CANCELLED_ACTIVE => {
                return Err(ControllerError::InvalidPlan(
                    "cancelled goal claim does not have cancelled intent status".to_owned(),
                ));
            }
            _ => {}
        }
    }
    for intent in intents.iter().filter(|intent| {
        matches!(
            intent.status.as_str(),
            GOAL_STATUS_CLAIMED
                | GOAL_STATUS_ACTIVE
                | GOAL_STATUS_COMPLETED
                | GOAL_STATUS_CANCELLED_ACTIVE
        )
    }) {
        if !claims.iter().any(|claim| claim.goal_id == intent.goal_id) {
            return Err(ControllerError::InvalidPlan(format!(
                "goal intent {} has lifecycle status {} without a durable claim",
                intent.goal_id, intent.status
            )));
        }
    }
    Ok(())
}

fn validate_claim_binding(
    intent: &GoalIntentV1,
    claim: &GoalIntentClaimV1,
) -> Result<(), ControllerError> {
    if claim.goal_id != intent.goal_id
        || claim.goal_statement_digest != sha256_prefixed(intent.natural_language_goal.as_bytes())
    {
        return Err(ControllerError::InvalidPlan(
            "queued-goal claim does not bind the exact durable intent".to_owned(),
        ));
    }
    Ok(())
}

fn validate_active_claim_binding(
    active: &ActiveGoalBinding,
    claim: &GoalIntentClaimV1,
) -> Result<(), ControllerError> {
    if active.goal_id != claim.goal_id
        || sha256_prefixed(active.goal_statement.as_bytes()) != claim.goal_statement_digest
        || active.plan_id != claim.plan_id
        || active.plan_revision != claim.plan_revision
        || active.plan_digest != claim.plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "queued-goal claim conflicts with the canonical active plan".to_owned(),
        ));
    }
    Ok(())
}

fn same_claim_binding(left: &GoalIntentClaimV1, right: &GoalIntentClaimV1) -> bool {
    left.goal_id == right.goal_id
        && left.goal_statement_digest == right.goal_statement_digest
        && left.plan_id == right.plan_id
        && left.plan_revision == right.plan_revision
        && left.plan_digest == right.plan_digest
        && left.compilation_evidence_digest == right.compilation_evidence_digest
        && left.claimed_at_ms == right.claimed_at_ms
}

fn validate_completion_binding(
    completion: &CompletionRecordV1,
    active: &ActiveGoalBinding,
    claim: &GoalIntentClaimV1,
) -> Result<(), ControllerError> {
    if completion.goal_id != claim.goal_id
        || completion.goal_id != active.goal_id
        || completion.plan_id != claim.plan_id
        || completion.plan_id != active.plan_id
        || completion.plan_revision != claim.plan_revision
        || completion.plan_revision != active.plan_revision
        || completion.plan_digest != claim.plan_digest
        || completion.plan_digest != active.plan_digest
    {
        return Err(ControllerError::InvalidPlan(
            "canonical completion record conflicts with queued-goal claim".to_owned(),
        ));
    }
    Ok(())
}

fn intent_by_id<'a>(
    intents: &'a [GoalIntentV1],
    goal_id: &str,
) -> Result<&'a GoalIntentV1, ControllerError> {
    let mut matching = intents.iter().filter(|intent| intent.goal_id == goal_id);
    let intent = matching.next().ok_or_else(|| {
        ControllerError::InvalidPlan(format!(
            "queued-goal claim references unknown intent {goal_id}"
        ))
    })?;
    if matching.next().is_some() {
        return Err(ControllerError::InvalidPlan(format!(
            "duplicate durable goal intent id {goal_id}"
        )));
    }
    Ok(intent)
}

fn with_goal_status(mut intent: GoalIntentV1, status: &str) -> GoalIntentV1 {
    status.clone_into(&mut intent.status);
    intent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(goal_id: &str, submitted_at_ms: i64) -> GoalIntentV1 {
        GoalIntentV1 {
            schema_version: GOAL_INTENT_SCHEMA_VERSION,
            goal_id: goal_id.to_owned(),
            natural_language_goal: format!("goal {goal_id}"),
            status: GOAL_STATUS_QUEUED.to_owned(),
            submitted_at_ms,
            browser_grant: None,
        }
    }

    #[test]
    fn claim_binding_rejects_statement_drift() {
        let intent = intent("goal-a", 1);
        let claim = GoalIntentClaimV1 {
            schema_version: GOAL_INTENT_CLAIM_SCHEMA_VERSION,
            goal_id: intent.goal_id.clone(),
            goal_statement_digest: sha256_prefixed(b"different goal"),
            plan_id: "plan-a".to_owned(),
            plan_revision: 1,
            plan_digest: sha256_prefixed(b"plan"),
            compilation_evidence_digest: sha256_prefixed(b"evidence"),
            status: GoalIntentClaimStatusV1::Released,
            claimed_at_ms: 1,
            updated_at_ms: 1,
        };
        assert!(validate_claim_binding(&intent, &claim).is_err());
    }

    #[test]
    fn multiple_live_claims_fail_closed() {
        let first = intent("goal-a", 1);
        let second = intent("goal-b", 2);
        let claims = [first.clone(), second.clone()].map(|intent| GoalIntentClaimV1 {
            schema_version: GOAL_INTENT_CLAIM_SCHEMA_VERSION,
            goal_id: intent.goal_id.clone(),
            goal_statement_digest: sha256_prefixed(intent.natural_language_goal.as_bytes()),
            plan_id: format!("plan-{}", intent.goal_id),
            plan_revision: 1,
            plan_digest: sha256_prefixed(intent.goal_id.as_bytes()),
            compilation_evidence_digest: sha256_prefixed(b"evidence"),
            status: GoalIntentClaimStatusV1::Claimed,
            claimed_at_ms: 1,
            updated_at_ms: 1,
        });
        let claimed_intents = [
            with_goal_status(first, GOAL_STATUS_CLAIMED),
            with_goal_status(second, GOAL_STATUS_CLAIMED),
        ];
        assert!(validate_claim_set(&claimed_intents, &claims).is_err());
    }

    #[test]
    fn lifecycle_record_versions_require_intent_exactly_one_ahead_of_claim() {
        assert!(
            validate_goal_lifecycle_record_versions(GoalLifecycleRecordVersions {
                intent_version: 2,
                claim_version: Some(1),
            })
            .is_ok()
        );
        assert!(
            validate_goal_lifecycle_record_versions(GoalLifecycleRecordVersions {
                intent_version: 3,
                claim_version: Some(1),
            })
            .is_err()
        );
        assert!(
            validate_goal_lifecycle_record_versions(GoalLifecycleRecordVersions {
                intent_version: 0,
                claim_version: None,
            })
            .is_err()
        );
    }

    #[test]
    fn lifecycle_compound_cas_requires_exact_intent_version_and_absent_first_claim() {
        let first = goal_lifecycle_cas_mutations(
            "goal-a",
            GoalLifecycleRecordVersions {
                intent_version: 1,
                claim_version: None,
            },
            "intent",
            "claim",
        );
        assert_eq!(first[0].expected_version, Some(1));
        assert_eq!(first[1].expected_version, None);

        let advance = goal_lifecycle_cas_mutations(
            "goal-a",
            GoalLifecycleRecordVersions {
                intent_version: 2,
                claim_version: Some(1),
            },
            "intent",
            "claim",
        );
        assert_eq!(advance[0].expected_version, Some(2));
        assert_eq!(advance[1].expected_version, Some(1));
    }
}
