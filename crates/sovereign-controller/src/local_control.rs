//! Constrained local control facade for CLI/dashboard clients.
//!
//! This module deliberately exposes only Controller-owned control transitions and read models.
//! It has no tool dispatch, action authorization, or alternate persistence surface.

use super::{
    APPROVAL_REQUEST_NAMESPACE, APPROVAL_REQUEST_SCHEMA_VERSION, ApprovalDecisionV1,
    ApprovalRequestStatusV1, ApprovalRequestV1, AttemptState, Controller, ControllerError,
    ControllerStatusView, ExecutionControlV1, GoalIntentV1, RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
    RecoveryManager, RecoveryProcessLease, RollbackStatusV1, TaskState, WorktreeLifecycle,
    decode_persisted_repository_baseline_set, decode_verification_records,
    process_lease_is_terminal, rollback_records, unix_millis,
    validate_durable_action_lifecycle_states,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sovereign_repo::ProjectRegistry;
use sovereign_state::StateStore;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub const LOCAL_CONTROL_READ_MODEL_SCHEMA_VERSION: u32 = 1;

/// Durable checkpoint coordinates shown by the local control read model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalControlCheckpointProjection {
    pub generation: i64,
    pub previous_hash: Option<String>,
    pub checkpoint_hash: String,
    pub payload_digest: String,
    pub action_sequence: i64,
    pub created_at_ms: i64,
}

/// Durable recovery facts relevant to whether local mutation may safely continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalControlRecoveryProjection {
    pub execution_epoch: i64,
    pub checkpoint: Option<LocalControlCheckpointProjection>,
    pub unknown_action_ids: Vec<String>,
    pub unresolved_action_ids: Vec<String>,
    pub pending_recovery_action_ids: Vec<String>,
    pub nonterminal_process_leases: Vec<RecoveryProcessLease>,
    pub unresolved_rollback_ids: Vec<String>,
    pub reconciling_task_ids: Vec<String>,
    pub conflicted_worktree_task_ids: Vec<String>,
    pub mutation_blocked: bool,
}

/// Additive typed local-control projection over the existing durable Controller status view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalControlReadModel {
    pub schema_version: u32,
    pub status: ControllerStatusView,
    pub plan_revisions: Vec<Value>,
    pub verifications: Vec<Value>,
    pub pending_approvals: Vec<ApprovalRequestV1>,
    pub blocked_approvals: Vec<ApprovalRequestV1>,
    pub recovery: LocalControlRecoveryProjection,
}

pub type LocalControlCheckpointV1 = LocalControlCheckpointProjection;
pub type LocalControlRecoveryProjectionV1 = LocalControlRecoveryProjection;
pub type LocalControlReadModelV1 = LocalControlReadModel;

/// Local command/read facade. The Controller remains the sole lifecycle and mutation authority.
pub struct LocalControl {
    controller: Controller,
}

impl Controller {
    /// Reopens local Controller authority from the canonical `StateStore`.
    ///
    /// With no active plan, wrapping the durable store is sufficient. With an active plan, this
    /// rebuilds only the `ProjectRegistry` identity from the durable repository baseline and then
    /// delegates all runtime reconstruction/reconciliation to `RecoveryManager`.
    ///
    /// # Errors
    /// Fails closed when active-plan integrity, baseline identity, repository registration, or
    /// ordinary Controller recovery cannot be proven.
    pub fn reopen_local(state: StateStore) -> Result<Self, ControllerError> {
        validate_durable_action_lifecycle_states(&state)?;
        if state.get_state("controller.plan", "active")?.is_none() {
            return Ok(Self::new(state));
        }

        state.recovery_integrity_check()?;
        let raw_document = state
            .get_state("controller.plan_document", "active")?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "active local control restart lacks durable canonical plan document".to_owned(),
                )
            })?;
        let plan_document: Value = serde_json::from_str(&raw_document)?;
        let baseline_json = state
            .get_state("controller.repository_baseline", "active")?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(
                    "active local control restart lacks durable repository baseline".to_owned(),
                )
            })?;
        let baseline_set =
            decode_persisted_repository_baseline_set(&baseline_json, &plan_document)?;
        let mut registry = ProjectRegistry::new();
        for (repository_id, baseline) in baseline_set.repositories {
            registry.register(repository_id, &baseline.snapshot.root)?;
        }
        let (controller, _) = RecoveryManager::recover(state, &registry)?;
        Ok(controller)
    }
}

impl LocalControl {
    /// Wraps an already constructed Controller without exposing it back to clients.
    const fn from_controller(controller: Controller) -> Self {
        Self { controller }
    }

    /// Reopens local control from the canonical `StateStore` through Controller bootstrap/recovery.
    ///
    /// # Errors
    /// Returns the fail-closed Controller bootstrap/recovery error.
    pub fn reopen(state: StateStore) -> Result<Self, ControllerError> {
        Controller::reopen_local(state).map(Self::from_controller)
    }

    /// Opens the canonical state for a strictly read-only local projection without running
    /// restart recovery. If a caller later invokes a mutation method on this value, the facade
    /// first reconstructs active Controller authority through `RecoveryManager`.
    #[must_use]
    pub fn read_only(state: StateStore) -> Self {
        Self::from_controller(Controller::new(state))
    }

    /// Returns the durable status plus typed local approval/recovery projections.
    ///
    /// # Errors
    /// Fails closed on malformed/corrupt Controller-owned durable records.
    pub fn read_model(&self) -> Result<LocalControlReadModel, ControllerError> {
        let status = self.controller.durable_status()?;
        let active = durable_active_read(&self.controller)?;
        let pending_approvals = pending_approvals(&self.controller)?;
        Ok(LocalControlReadModel {
            schema_version: LOCAL_CONTROL_READ_MODEL_SCHEMA_VERSION,
            status,
            plan_revisions: plan_revisions(&self.controller)?,
            verifications: current_verifications(&self.controller, active.as_ref())?,
            blocked_approvals: blocked_approvals(
                &self.controller,
                active.as_ref(),
                &pending_approvals,
            )?,
            pending_approvals,
            recovery: recovery_projection(&self.controller, active.as_ref())?,
        })
    }

    fn ensure_mutation_authority(&mut self) -> Result<(), ControllerError> {
        validate_durable_action_lifecycle_states(&self.controller.state)?;
        if self.controller.active.is_some()
            || self
                .controller
                .state
                .get_state("controller.plan", "active")?
                .is_none()
        {
            return Ok(());
        }
        let state = StateStore::open(self.controller.state.path())?;
        self.controller = Controller::reopen_local(state)?;
        Ok(())
    }

    /// Delegates natural-language goal submission to the Controller-owned durable transition.
    ///
    /// # Errors
    /// Returns the underlying Controller validation/persistence error.
    pub fn submit_goal(&mut self, goal: &str) -> Result<GoalIntentV1, ControllerError> {
        self.ensure_mutation_authority()?;
        self.controller.submit_goal_intent(goal)
    }

    /// Delegates pause to the Controller-owned durable transition.
    ///
    /// # Errors
    /// Returns the underlying Controller validation/persistence error.
    pub fn pause(&mut self, reason: Option<&str>) -> Result<ExecutionControlV1, ControllerError> {
        self.ensure_mutation_authority()?;
        self.controller.pause(reason)
    }

    /// Delegates resume to the Controller-owned durable transition.
    ///
    /// # Errors
    /// Returns the underlying Controller validation/persistence error.
    pub fn resume(&mut self) -> Result<ExecutionControlV1, ControllerError> {
        self.ensure_mutation_authority()?;
        self.controller.resume()
    }

    /// Delegates one exact approval response to the Controller. The caller supplies no action
    /// payload, executable, destination, policy, or dispatch authority.
    ///
    /// # Errors
    /// Returns the Controller's exact approval validation/persistence error.
    pub fn respond_to_approval(
        &mut self,
        request_id: &str,
        decision: ApprovalDecisionV1,
        decided_by: &str,
    ) -> Result<ApprovalRequestV1, ControllerError> {
        self.ensure_mutation_authority()?;
        self.controller
            .respond_to_approval(request_id, decision, decided_by)
    }
}

struct DurableActiveRead {
    plan_id: String,
    revision: u32,
    plan_digest: String,
    policy_digest: String,
    repository_roots: BTreeMap<String, PathBuf>,
    tasks: BTreeMap<String, super::TaskRuntime>,
    attempts: BTreeMap<String, super::AttemptRuntime>,
}

fn durable_active_read(
    controller: &Controller,
) -> Result<Option<DurableActiveRead>, ControllerError> {
    let Some(raw_plan) = controller.state.get_state("controller.plan", "active")? else {
        return Ok(None);
    };
    let plan_record: Value = serde_json::from_str(&raw_plan)?;
    let plan_id = super::required_str(&plan_record, "/plan_id")?.to_owned();
    let revision = super::required_u32(&plan_record, "/revision")?;
    let plan_digest = super::required_str(&plan_record, "/plan_digest")?;
    let raw_document = controller
        .state
        .get_state("controller.plan_document", "active")?
        .ok_or_else(|| {
            ControllerError::InvalidPlan("durable canonical plan document is missing".to_owned())
        })?;
    let plan_document: Value = serde_json::from_str(&raw_document)?;
    if super::digest_json(&plan_document)? != plan_digest {
        return Err(ControllerError::InvalidPlan(
            "durable canonical plan document digest does not match active plan".to_owned(),
        ));
    }
    let policy_digest = super::digest_json(
        plan_document
            .get("policy")
            .ok_or_else(|| ControllerError::InvalidPlan("plan policy is missing".to_owned()))?,
    )?;
    let plan_tasks = super::required_array(&plan_document, "/tasks")?;
    let plan_task_map = plan_tasks
        .iter()
        .map(|task| Ok((super::required_str(task, "/task_id")?.to_owned(), task)))
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    let mut tasks = BTreeMap::new();
    for (task_id, plan_task) in &plan_task_map {
        let key = super::revision_scoped_key(&plan_id, revision, task_id);
        let raw = controller
            .state
            .get_state("controller.task", &key)?
            .ok_or_else(|| {
                ControllerError::InvalidPlan(format!("durable active task {task_id} is missing"))
            })?;
        let runtime: super::TaskRuntime = serde_json::from_str(&raw)?;
        if runtime.task_contract_digest != super::digest_json(plan_task)?
            || runtime.task != **plan_task
        {
            return Err(ControllerError::InvalidPlan(format!(
                "durable task {task_id} contract is stale or altered"
            )));
        }
        tasks.insert(task_id.clone(), runtime);
    }
    let attempts = controller
        .state
        .state_records("controller.attempt")?
        .into_iter()
        .filter_map(|record| {
            super::logical_key_for_revision(&record.key, &plan_id, revision)
                .map(|attempt_id| (attempt_id, record.value_json))
        })
        .map(|(attempt_id, raw)| {
            let attempt: super::AttemptRuntime = serde_json::from_str(&raw)?;
            if !tasks.contains_key(&attempt.task_id) {
                return Err(ControllerError::InvalidPlan(format!(
                    "active attempt {attempt_id} belongs to a superseded task"
                )));
            }
            Ok((attempt_id, attempt))
        })
        .collect::<Result<BTreeMap<_, _>, ControllerError>>()?;
    let baseline_raw = controller
        .state
        .get_state("controller.repository_baseline", "active")?
        .ok_or_else(|| {
            ControllerError::InvalidPlan("durable repository baseline is missing".to_owned())
        })?;
    let baseline_set = decode_persisted_repository_baseline_set(&baseline_raw, &plan_document)?;
    let repository_roots = baseline_set
        .repositories
        .into_iter()
        .map(|(repository_id, baseline)| (repository_id, baseline.snapshot.root))
        .collect();
    Ok(Some(DurableActiveRead {
        plan_id,
        revision,
        plan_digest: plan_digest.to_owned(),
        policy_digest,
        repository_roots,
        tasks,
        attempts,
    }))
}

fn plan_revisions(controller: &Controller) -> Result<Vec<Value>, ControllerError> {
    controller
        .state
        .state_records("controller.plan_revision")?
        .into_iter()
        .map(|record| Ok(serde_json::from_str(&record.value_json)?))
        .collect()
}

fn current_verifications(
    controller: &Controller,
    active: Option<&DurableActiveRead>,
) -> Result<Vec<Value>, ControllerError> {
    let records = decode_verification_records(&controller.state)?;
    let Some(active) = active else {
        return Ok(Vec::new());
    };
    let mut verifications = Vec::new();
    for verification in records {
        if verification.plan_id == active.plan_id
            && verification.plan_revision == active.revision
            && verification.plan_digest == active.plan_digest
        {
            verifications.push(serde_json::to_value(verification)?);
        }
    }
    Ok(verifications)
}

fn approval_requests(controller: &Controller) -> Result<Vec<ApprovalRequestV1>, ControllerError> {
    controller
        .state
        .state_records(APPROVAL_REQUEST_NAMESPACE)?
        .into_iter()
        .map(|record| {
            let request: ApprovalRequestV1 = serde_json::from_str(&record.value_json)?;
            if request.schema_version != APPROVAL_REQUEST_SCHEMA_VERSION {
                return Err(ControllerError::InvalidPlan(format!(
                    "unsupported durable approval request schema version {}",
                    request.schema_version
                )));
            }
            Ok(request)
        })
        .collect()
}

fn pending_approvals(controller: &Controller) -> Result<Vec<ApprovalRequestV1>, ControllerError> {
    let mut pending = approval_requests(controller)?
        .into_iter()
        .filter(|request| request.status == ApprovalRequestStatusV1::Pending)
        .collect::<Vec<_>>();
    pending.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(pending)
}

fn blocked_approvals(
    controller: &Controller,
    active: Option<&DurableActiveRead>,
    pending: &[ApprovalRequestV1],
) -> Result<Vec<ApprovalRequestV1>, ControllerError> {
    let Some(active) = active else {
        return Ok(Vec::new());
    };
    let execution_epoch = controller.state.current_execution_epoch()?;
    let now_ms = unix_millis()?;
    let mut blocked = Vec::new();
    for request in pending {
        if request.plan_id != active.plan_id
            || request.plan_revision != active.revision
            || request.policy_digest != active.policy_digest
            || request.execution_epoch != execution_epoch
            || now_ms >= request.expires_at_ms
            || !active.tasks.contains_key(&request.task_id)
        {
            continue;
        }
        let Some(action) = controller.state.action_record(&request.action_id)? else {
            continue;
        };
        if action.state == "authorized"
            && action.payload_digest == request.payload_digest
            && action.policy_digest == request.policy_digest
            && action.execution_epoch == request.execution_epoch
        {
            blocked.push(request.clone());
        }
    }
    blocked.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(blocked)
}

fn recovery_projection(
    controller: &Controller,
    active: Option<&DurableActiveRead>,
) -> Result<LocalControlRecoveryProjection, ControllerError> {
    let execution_epoch = controller.state.current_execution_epoch()?;
    let checkpoint = controller
        .state
        .latest_valid_checkpoint_integrity()?
        .map(|record| LocalControlCheckpointProjection {
            generation: record.generation,
            previous_hash: record.previous_hash,
            checkpoint_hash: record.checkpoint_hash,
            payload_digest: record.payload_digest,
            action_sequence: record.action_sequence,
            created_at_ms: record.created_at_ms,
        });

    validate_durable_action_lifecycle_states(&controller.state)?;
    let action_records = controller.state.action_records()?;
    let mut unknown_action_ids = action_records
        .iter()
        .filter(|record| record.state == "unknown")
        .map(|record| record.action_id.clone())
        .collect::<Vec<_>>();
    unknown_action_ids.sort();
    let mut unresolved_action_ids = action_records
        .iter()
        .filter(|record| matches!(record.state.as_str(), "dispatched" | "observed" | "unknown"))
        .map(|record| record.action_id.clone())
        .collect::<Vec<_>>();
    unresolved_action_ids.sort();

    let pending_recovery_action_ids =
        pending_recovery_actions(controller, active, &action_records)?;

    let nonterminal_process_leases = nonterminal_process_leases(controller)?;
    let mut unresolved_rollback_ids = rollback_records(&controller.state)?
        .into_iter()
        .filter(|record| {
            matches!(
                record.status,
                RollbackStatusV1::Prepared | RollbackStatusV1::Unknown
            )
        })
        .map(|record| record.rollback_id)
        .collect::<Vec<_>>();
    unresolved_rollback_ids.sort();

    let mut reconciling_task_ids = BTreeSet::new();
    let mut conflicted_worktree_task_ids = BTreeSet::new();
    if let Some(active) = active {
        for (task_id, task) in &active.tasks {
            if task.state == TaskState::ReconcilingUnknown {
                reconciling_task_ids.insert(task_id.clone());
            }
            if task.worktree_state == Some(WorktreeLifecycle::Conflict) {
                conflicted_worktree_task_ids.insert(task_id.clone());
            }
        }
    }
    let reconciling_task_ids = reconciling_task_ids.into_iter().collect::<Vec<_>>();
    let conflicted_worktree_task_ids = conflicted_worktree_task_ids.into_iter().collect::<Vec<_>>();

    let mutation_blocked = !unresolved_action_ids.is_empty()
        || !nonterminal_process_leases.is_empty()
        || !unresolved_rollback_ids.is_empty()
        || !reconciling_task_ids.is_empty()
        || !conflicted_worktree_task_ids.is_empty();

    Ok(LocalControlRecoveryProjection {
        execution_epoch,
        checkpoint,
        unknown_action_ids,
        unresolved_action_ids,
        pending_recovery_action_ids,
        nonterminal_process_leases,
        unresolved_rollback_ids,
        reconciling_task_ids,
        conflicted_worktree_task_ids,
        mutation_blocked,
    })
}

fn pending_recovery_actions(
    controller: &Controller,
    active: Option<&DurableActiveRead>,
    actions: &[sovereign_state::PersistedActionRecord],
) -> Result<Vec<String>, ControllerError> {
    let Some(active) = active else {
        return Ok(Vec::new());
    };
    let intents = controller
        .state
        .state_records("controller.action_intent")?
        .into_iter()
        .map(|record| {
            let raw: super::PersistedActionIntent = serde_json::from_str(&record.value_json)?;
            let repository_root = active.repository_roots.get(&raw.repository_id).ok_or_else(|| {
                ControllerError::InvalidPlan(format!(
                    "durable action intent {} references repository {} outside the active baseline set",
                    raw.action_id, raw.repository_id
                ))
            })?;
            let intent = super::normalize_persisted_action_intent(raw, repository_root)?;
            Ok((record.key, intent))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, ControllerError>>()?;
    let actions = actions
        .iter()
        .cloned()
        .map(|record| (record.action_id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut pending = Vec::new();
    for (attempt_id, attempt) in &active.attempts {
        if !matches!(
            attempt.state,
            AttemptState::Executing | AttemptState::Verifying
        ) {
            continue;
        }
        let next = intents
            .values()
            .filter(|intent| intent.attempt_id == *attempt_id)
            .max_by(|left, right| left.action_id.cmp(&right.action_id));
        if let Some(intent) = next
            && actions.get(&intent.action_id).is_some_and(|action| {
                matches!(action.state.as_str(), "prepared" | "authorized" | "failed")
            })
        {
            pending.push(intent.action_id.clone());
        }
    }
    for (action_id, action) in &actions {
        if !matches!(action.state.as_str(), "prepared" | "authorized" | "failed")
            || pending.contains(action_id)
        {
            continue;
        }
        let Some(intent) = intents.get(action_id) else {
            continue;
        };
        let origin_interrupted = active
            .attempts
            .get(&intent.attempt_id)
            .is_some_and(|attempt| {
                attempt.task_id == intent.task_id && attempt.state == AttemptState::Interrupted
            });
        let task_planned = active
            .tasks
            .get(&intent.task_id)
            .is_some_and(|task| task.state == TaskState::Planned);
        if origin_interrupted && task_planned {
            pending.push(action_id.clone());
        }
    }
    pending.sort();
    pending.dedup();
    Ok(pending)
}

fn nonterminal_process_leases(
    controller: &Controller,
) -> Result<Vec<RecoveryProcessLease>, ControllerError> {
    let mut leases = Vec::new();
    for record in controller.state.state_records("controller.process_lease")? {
        let lease: RecoveryProcessLease = serde_json::from_str(&record.value_json)?;
        if lease.schema_version != RECOVERY_PROCESS_LEASE_SCHEMA_VERSION {
            return Err(ControllerError::InvalidPlan(format!(
                "unsupported durable process-lease schema version {}",
                lease.schema_version
            )));
        }
        if !process_lease_is_terminal(&lease) {
            leases.push(lease);
        }
    }
    leases.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
    Ok(leases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sovereign_state::NewActionRecord;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state(label: &str) -> (PathBuf, StateStore) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "sovereign-local-control-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap_or_else(|error| panic!("temp dir: {error}"));
        let path = root.join("state.sqlite3");
        let state = StateStore::open(&path).unwrap_or_else(|error| panic!("state: {error}"));
        (root, state)
    }

    fn fixture_approval(epoch: i64) -> ApprovalRequestV1 {
        let digest = format!("sha256:{}", "d".repeat(64));
        ApprovalRequestV1 {
            schema_version: APPROVAL_REQUEST_SCHEMA_VERSION,
            request_id: "approval.pending".to_owned(),
            action_id: "action.approval".to_owned(),
            plan_id: "plan.fixture".to_owned(),
            plan_revision: 1,
            task_id: "task.fixture".to_owned(),
            permission_class: "external_side_effect".to_owned(),
            payload_digest: digest.clone(),
            destination_digest: None,
            executable_digest: digest.clone(),
            policy_digest: digest,
            execution_epoch: epoch,
            nonce: "nonce.fixture".to_owned(),
            requested_at_ms: 1,
            action_expires_at_ms: 10_000,
            expires_at_ms: 5_000,
            status: ApprovalRequestStatusV1::Pending,
            decided_by: None,
            decided_at_ms: None,
            claim_id: None,
        }
    }

    fn seed_recovery_blockers(state: &mut StateStore, epoch: i64) -> RecoveryProcessLease {
        let digest = format!("sha256:{}", "a".repeat(64));
        state
            .insert_action_record(NewActionRecord {
                action_id: "action.unknown",
                state: "unknown",
                payload_digest: &digest,
                policy_digest: &digest,
                execution_epoch: epoch,
                event_id: "event.unknown",
                event_kind: "unknown_fixture",
                payload_json: "{}",
            })
            .unwrap_or_else(|error| panic!("unknown action: {error}"));
        let lease = RecoveryProcessLease {
            schema_version: RECOVERY_PROCESS_LEASE_SCHEMA_VERSION,
            lease_id: "lease.nonterminal".to_owned(),
            task_id: "task.fixture".to_owned(),
            attempt_id: "attempt.fixture".to_owned(),
            action_id: "action.lease".to_owned(),
            process_group_id: None,
            leader_identity: None,
            state: "active".to_owned(),
        };
        state
            .put_state(
                "controller.process_lease",
                "action.lease",
                &serde_json::to_string(&lease)
                    .unwrap_or_else(|error| panic!("lease json: {error}")),
            )
            .unwrap_or_else(|error| panic!("lease state: {error}"));
        state
            .put_state(
                "controller.rollback",
                "rollback.fixture",
                &json!({
                    "schema_version": super::super::ROLLBACK_RECORD_SCHEMA_VERSION,
                    "rollback_id": "rollback.unresolved",
                    "original_action_id": "action.original",
                    "original_result_digest": digest,
                    "rollback_action_id": "action.rollback",
                    "plan_id": "plan.fixture",
                    "plan_revision": 1,
                    "task_id": "task.fixture",
                    "attempt_id": "attempt.fixture",
                    "execution_epoch": epoch,
                    "mode": "replace_literal",
                    "path": "src/lib.rs",
                    "original_source_digest": format!("sha256:{}", "b".repeat(64)),
                    "original_post_digest": format!("sha256:{}", "c".repeat(64)),
                    "verification_evaluator": "fixture",
                    "status": "prepared",
                    "verification_evidence_id": null,
                    "verification_artifact_digest": null
                })
                .to_string(),
            )
            .unwrap_or_else(|error| panic!("rollback state: {error}"));
        lease
    }

    #[test]
    fn read_model_projects_durable_recovery_blockers_without_mutating_state() {
        let (root, mut state) = temp_state("recovery-projection");
        let epoch = state
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("epoch: {error}"));
        let lease = seed_recovery_blockers(&mut state, epoch);
        let approval = fixture_approval(epoch);
        state
            .put_state(
                APPROVAL_REQUEST_NAMESPACE,
                &approval.request_id,
                &serde_json::to_string(&approval)
                    .unwrap_or_else(|error| panic!("approval json: {error}")),
            )
            .unwrap_or_else(|error| panic!("approval state: {error}"));
        let before = state
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal before: {error}"));

        let control = LocalControl::from_controller(Controller::new(state));
        let view = control
            .read_model()
            .unwrap_or_else(|error| panic!("read model: {error}"));
        let after = control
            .controller
            .state
            .latest_journal_sequence()
            .unwrap_or_else(|error| panic!("journal after: {error}"));

        assert_eq!(view.schema_version, LOCAL_CONTROL_READ_MODEL_SCHEMA_VERSION);
        assert!(view.plan_revisions.is_empty());
        assert!(view.verifications.is_empty());
        assert_eq!(view.recovery.execution_epoch, epoch);
        assert!(view.recovery.checkpoint.is_none());
        assert_eq!(
            view.recovery.unknown_action_ids,
            vec!["action.unknown".to_owned()]
        );
        assert_eq!(
            view.recovery.unresolved_action_ids,
            vec!["action.unknown".to_owned()]
        );
        assert!(view.recovery.pending_recovery_action_ids.is_empty());
        assert_eq!(view.recovery.nonterminal_process_leases, vec![lease]);
        assert_eq!(
            view.recovery.unresolved_rollback_ids,
            vec!["rollback.unresolved".to_owned()]
        );
        assert!(view.recovery.reconciling_task_ids.is_empty());
        assert!(view.recovery.conflicted_worktree_task_ids.is_empty());
        assert!(view.recovery.mutation_blocked);
        assert_eq!(view.pending_approvals, vec![approval]);
        assert!(view.blocked_approvals.is_empty());
        assert_eq!(
            before, after,
            "local read model mutated authoritative state"
        );

        drop(control);
        let _ = fs::remove_dir_all(root);
    }
}
