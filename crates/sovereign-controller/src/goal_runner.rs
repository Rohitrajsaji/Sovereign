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

/// Revalidates the active goal's durable browser grant against its canonical Plan and
/// compilation evidence. A missing grant is returned only when the active Plan has no browser
/// binding; inconsistent authority fails closed.
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
            match matching_claim {
                Some(claim_record) => {
                    let _ = decode_versioned_goal_claim(claim_record)?;
                    validate_goal_lifecycle_record_versions(GoalLifecycleRecordVersions {
                        intent_version: intent_record.version,
                        claim_version: Some(claim_record.version),
                    })?;
                }
                None => {
                    if intent.status != GOAL_STATUS_QUEUED || intent_record.version != 1 {
                        return Err(ControllerError::InvalidPlan(format!(
                            "goal intent {} lacks its durable claim at record version {}",
                            intent.goal_id, intent_record.version
                        )));
                    }
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
    if revisions.is_empty() {
        if !lifecycles.is_empty() || !finalizations.is_empty() {
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
    let mut completed_revision_by_plan = BTreeMap::<String, u32>::new();
    let mut revision_chain_by_plan =
        BTreeMap::<String, BTreeMap<u32, (String, Value, Value)>>::new();
    let mut completed_count = 0_usize;
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
                    .any(|candidate| candidate.key == expected_key)
                {
                    return Err(ControllerError::InvalidPlan(
                        "superseded revision unexpectedly has a finalization record".to_owned(),
                    ));
                }
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
    for (plan_id, max_revision) in &max_revision_by_plan {
        if completed_revision_by_plan.get(plan_id) != Some(max_revision) {
            return Err(ControllerError::InvalidPlan(format!(
                "plan {plan_id} does not terminate in exactly its latest completed revision"
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
            } else if required_str(lifecycle, "/status")? != "completed"
                || !lifecycle
                    .get("superseded_by_revision")
                    .is_some_and(Value::is_null)
                || !lifecycle
                    .get("superseded_by_digest")
                    .is_some_and(Value::is_null)
                || completed_revision_by_plan.get(&plan_id) != Some(&plan_revision)
                || required_str(lifecycle, "/plan_digest")? != plan_digest
            {
                return Err(ControllerError::InvalidPlan(format!(
                    "plan {plan_id} latest revision {plan_revision} is not exactly completed"
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
            GOAL_STATUS_QUEUED | GOAL_STATUS_CLAIMED | GOAL_STATUS_ACTIVE | GOAL_STATUS_COMPLETED
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
    if let Some(claim_version) = versions.claim_version {
        if claim_version <= 0 || versions.intent_version != claim_version + 1 {
            return Err(ControllerError::InvalidPlan(format!(
                "queued-goal intent/claim record versions conflict: intent={}, claim={claim_version}",
                versions.intent_version
            )));
        }
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
            GoalIntentClaimStatusV1::Released if intent.status != GOAL_STATUS_QUEUED => {
                return Err(ControllerError::InvalidPlan(
                    "released goal claim does not have queued intent status".to_owned(),
                ));
            }
            _ => {}
        }
    }
    for intent in intents.iter().filter(|intent| {
        matches!(
            intent.status.as_str(),
            GOAL_STATUS_CLAIMED | GOAL_STATUS_ACTIVE | GOAL_STATUS_COMPLETED
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
    intent.status = status.to_owned();
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
