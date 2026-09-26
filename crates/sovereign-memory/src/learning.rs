use super::{
    MemoryError, MemoryKind, MemoryProvenance, MemoryRecord, MemoryScope, MemoryStatus,
    MemoryTrust, NewMemoryRecord, capture_record_in_state, load_record_tx, normalize_new_record,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_state::StateStore;
use std::collections::BTreeSet;

/// A procedural candidate requires at least two distinct Controller-verified
/// successful episodes before it can be proposed as reusable evidence.
pub const PROCEDURE_CANDIDATE_SUPPORT_THRESHOLD: usize = 2;

const MAX_WORKFLOW_STEPS: usize = 16;
const MAX_WORKFLOW_STEP_BYTES: usize = 1_024;
const MAX_WORKFLOW_SUMMARY_BYTES: usize = 4_096;

/// A bounded reusable workflow description. It deliberately contains no
/// permission, policy, requirement, tool-grant, or completion-authority fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPattern {
    /// Stable human/domain subject used for governed-precedence conflict checks.
    pub subject: String,
    pub summary: String,
    pub steps: Vec<String>,
}

/// Frozen M4-T04 name for the reusable workflow description.
pub type ProcedurePattern = WorkflowPattern;

/// Durable Controller evidence proving the outcome that an episode refers to.
/// The memory layer revalidates every supplied key against Controller state and
/// append-only journal evidence before recording a verified success or failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ControllerEpisodeOutcomeProof {
    VerifiedSuccess {
        verification_record_key: String,
        verification_id: String,
    },
    FailedAttempt {
        failure_record_key: String,
        failure_signature: String,
    },
}

/// Controller-owned task/attempt binding consumed by [`EpisodeRecorder`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerEpisodeProof {
    pub plan_id: String,
    pub plan_revision: u32,
    pub plan_digest: String,
    pub task_id: String,
    pub task_contract_digest: String,
    pub attempt_id: String,
    pub task_record_key: String,
    pub attempt_record_key: String,
    pub outcome: ControllerEpisodeOutcomeProof,
}

/// One request to capture a Controller-bound episode in project memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeCapture {
    pub scope: MemoryScope,
    pub procedure: Option<ProcedurePattern>,
    pub proof: ControllerEpisodeProof,
    pub observed_at_ms: i64,
}

/// A reusable workflow candidate backed by repeated verified episodes.
///
/// This remains memory evidence only. There is intentionally no method here to
/// grant permissions, rewrite requirements, register a skill, or alter policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcedureCandidate {
    pub workflow_signature: String,
    pub supporting_verified_episodes: usize,
    pub supporting_episode_ids: Vec<String>,
    pub record: MemoryRecord,
}

/// Result of one episode capture. Failed episodes never return a procedure
/// candidate. Verified successes may return one only after repeated support.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpisodeCaptureResult {
    pub episode: MemoryRecord,
    pub candidate: Option<ProcedureCandidate>,
}

/// Records Controller-proven outcomes as episodic memory and proposes bounded
/// procedural candidates only after repeated deterministic verification.
pub struct EpisodeRecorder<'a> {
    state: &'a mut StateStore,
}

#[derive(Debug)]
enum DurableOutcome {
    VerifiedSuccess {
        verification_id: String,
        evidence_ids: Vec<String>,
        repair_origin: Option<ValidatedRepairOrigin>,
    },
    FailedAttempt {
        failure_signature: String,
        evidence_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ValidatedRepairOrigin {
    prior_attempt_id: String,
    failure_record_digest: String,
    repair_packet_digest: String,
}

impl<'a> EpisodeRecorder<'a> {
    #[must_use]
    pub fn new(state: &'a mut StateStore) -> Self {
        Self { state }
    }

    /// Revalidates Controller authority, records one episodic outcome, and when
    /// applicable returns a repeated-success procedural candidate.
    ///
    /// # Errors
    /// Returns a fail-closed error when Controller state/journal bindings do not
    /// prove the requested outcome, workflow input is malformed, or persistence
    /// fails.
    pub fn record(
        &mut self,
        capture: &EpisodeCapture,
    ) -> Result<EpisodeCaptureResult, MemoryError> {
        validate_capture(capture)?;
        let workflow_signature = capture
            .procedure
            .as_ref()
            .map(workflow_signature)
            .transpose()?;
        let durable = validate_controller_outcome(self.state, &capture.proof)?;
        let episode = self.capture_episode(capture, workflow_signature.as_deref(), &durable)?;

        let candidate = if matches!(durable, DurableOutcome::VerifiedSuccess { .. }) {
            match (capture.procedure.as_ref(), workflow_signature.as_deref()) {
                (Some(procedure), Some(signature)) => {
                    self.procedure_candidate(capture, procedure, signature)?
                }
                _ => None,
            }
        } else {
            None
        };
        Ok(EpisodeCaptureResult { episode, candidate })
    }

    fn capture_episode(
        &mut self,
        capture: &EpisodeCapture,
        workflow_signature: Option<&str>,
        outcome: &DurableOutcome,
    ) -> Result<MemoryRecord, MemoryError> {
        let (outcome_name, predicate_prefix, confidence, evidence_ids, outcome_payload) =
            match outcome {
                DurableOutcome::VerifiedSuccess {
                    verification_id,
                    evidence_ids,
                    repair_origin,
                } => (
                    "verified_success",
                    "verified_success",
                    100,
                    evidence_ids.clone(),
                    json!({
                        "verification_id": verification_id,
                        "repair_origin": repair_origin,
                    }),
                ),
                DurableOutcome::FailedAttempt {
                    failure_signature,
                    evidence_ids,
                } => (
                    "failed_attempt",
                    "failed_attempt",
                    100,
                    evidence_ids.clone(),
                    json!({"failure_signature": failure_signature}),
                ),
            };
        let id = stable_id(
            "episode",
            &[
                &capture.proof.plan_id,
                &capture.proof.plan_revision.to_string(),
                &capture.proof.task_id,
                &capture.proof.attempt_id,
                outcome_name,
            ],
        );
        let subject = workflow_signature.map_or_else(
            || format!("controller.task:{}", capture.proof.task_id),
            |signature| format!("learning.workflow:{signature}"),
        );
        let assertion = serde_json::to_string(&json!({
            "schema_version": 1,
            "outcome": outcome_name,
            "workflow_signature": workflow_signature,
            "procedure": capture.procedure,
            "proof": capture.proof,
            "outcome_proof": outcome_payload,
        }))
        .map_err(|error| {
            MemoryError::InvalidRecord(format!("episode serialization failed: {error}"))
        })?;
        let new_record = NewMemoryRecord {
            id: id.clone(),
            kind: MemoryKind::Episodic,
            scope: capture.scope.clone(),
            subject,
            predicate: format!("{predicate_prefix}:{}", capture.proof.attempt_id),
            conflict_key: format!("learning.episode:{id}"),
            assertion,
            trust: MemoryTrust::Observed,
            confidence,
            provenance: MemoryProvenance {
                source_evidence_ids: evidence_ids,
                producing_task_id: Some(capture.proof.task_id.clone()),
                producing_attempt_id: Some(capture.proof.attempt_id.clone()),
                repository_revision: None,
                source_fingerprints: Vec::new(),
            },
            expires_at_ms: None,
            invalidation_predicates: Vec::new(),
        };
        capture_or_existing(self.state, new_record, capture.observed_at_ms)
    }

    #[allow(clippy::too_many_lines)]
    fn procedure_candidate(
        &mut self,
        capture: &EpisodeCapture,
        procedure: &ProcedurePattern,
        workflow_signature: &str,
    ) -> Result<Option<ProcedureCandidate>, MemoryError> {
        let subject = format!("learning.workflow:{workflow_signature}");
        let candidates = self.state.transaction(|tx| {
            let mut statement = tx.prepare(
                "SELECT memory_id FROM memory_records \
                 WHERE kind='episodic' AND status='active' AND subject=?1 \
                   AND predicate LIKE 'verified_success:%' \
                 ORDER BY created_at_ms ASC, memory_id ASC",
            )?;
            let rows = statement.query_map([subject], |row| row.get::<_, String>(0))?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row?);
            }
            drop(statement);
            let mut records = Vec::new();
            for id in ids {
                let Some(record) = load_record_tx(tx, &id)? else {
                    continue;
                };
                records.push(record);
            }
            Ok(records)
        })?;
        let capture_scope = canonical_scope(&capture.scope);
        let mut unique_attempts = BTreeSet::new();
        let mut support = Vec::new();
        for record in candidates {
            if record.scope != capture_scope || record.trust != MemoryTrust::Observed {
                continue;
            }
            let Ok(assertion) = serde_json::from_str::<Value>(&record.assertion) else {
                continue;
            };
            if assertion.get("schema_version").and_then(Value::as_u64) != Some(1)
                || assertion.get("outcome").and_then(Value::as_str) != Some("verified_success")
                || assertion.get("workflow_signature").and_then(Value::as_str)
                    != Some(workflow_signature)
            {
                continue;
            }
            let Ok(stored_procedure) = serde_json::from_value::<ProcedurePattern>(
                assertion.get("procedure").cloned().unwrap_or(Value::Null),
            ) else {
                continue;
            };
            if &stored_procedure != procedure {
                continue;
            }
            let Ok(proof) = serde_json::from_value::<ControllerEpisodeProof>(
                assertion.get("proof").cloned().unwrap_or(Value::Null),
            ) else {
                continue;
            };
            if !matches!(
                proof.outcome,
                ControllerEpisodeOutcomeProof::VerifiedSuccess { .. }
            ) {
                continue;
            }
            let expected_id = stable_id(
                "episode",
                &[
                    &proof.plan_id,
                    &proof.plan_revision.to_string(),
                    &proof.task_id,
                    &proof.attempt_id,
                    "verified_success",
                ],
            );
            if record.id != expected_id
                || !matches!(
                    validate_controller_outcome(self.state, &proof),
                    Ok(DurableOutcome::VerifiedSuccess { .. })
                )
            {
                continue;
            }
            if unique_attempts.insert(proof.attempt_id.clone()) {
                support.push(record.id);
            }
        }
        if support.len() < PROCEDURE_CANDIDATE_SUPPORT_THRESHOLD {
            return Ok(None);
        }

        let scope_signature = scope_signature(&capture.scope)?;
        let candidate_id = stable_id("procedure", &[workflow_signature, &scope_signature]);
        let assertion = serde_json::to_string(&json!({
            "schema_version": 1,
            "candidate_only": true,
            "promotion_state": "requires_governed_approval",
            "workflow_signature": workflow_signature,
            "summary": procedure.summary,
            "steps": procedure.steps,
            "minimum_verified_support": PROCEDURE_CANDIDATE_SUPPORT_THRESHOLD,
        }))
        .map_err(|error| {
            MemoryError::InvalidRecord(format!("procedure candidate serialization failed: {error}"))
        })?;

        if let Some(existing) = self
            .state
            .transaction(|tx| load_record_tx(tx, &candidate_id))?
        {
            let expected_conflict_key = format!("learning.procedure:{workflow_signature}");
            let stable_provenance = existing.provenance.producing_task_id.is_none()
                && existing.provenance.producing_attempt_id.is_none()
                && existing.provenance.repository_revision.is_none()
                && existing.provenance.source_fingerprints.is_empty()
                && existing.provenance.source_evidence_ids.len()
                    == PROCEDURE_CANDIDATE_SUPPORT_THRESHOLD
                && existing
                    .provenance
                    .source_evidence_ids
                    .iter()
                    .all(|source_id| {
                        source_id
                            .strip_prefix("memory:")
                            .is_some_and(|episode_id| support.iter().any(|id| id == episode_id))
                    });
            if existing.kind != MemoryKind::ProceduralCandidate
                || existing.status != MemoryStatus::Active
                || existing.scope != capture_scope
                || existing.subject != procedure.subject
                || existing.predicate != "procedure"
                || existing.conflict_key != expected_conflict_key
                || existing.assertion != assertion
                || existing.trust != MemoryTrust::Observed
                || existing.confidence != 90
                || !stable_provenance
            {
                return Err(MemoryError::InvalidRecord(format!(
                    "learning memory {candidate_id} already exists with invalid procedural-candidate content"
                )));
            }
            super::projection::drain_projection_outbox_state(self.state)
                .map_err(|error| MemoryError::ProjectionPending(error.to_string()))?;
            return Ok(Some(ProcedureCandidate {
                workflow_signature: workflow_signature.to_owned(),
                supporting_verified_episodes: support.len(),
                supporting_episode_ids: support,
                record: existing,
            }));
        }

        let retained_support = support
            .iter()
            .take(PROCEDURE_CANDIDATE_SUPPORT_THRESHOLD)
            .cloned()
            .collect::<Vec<_>>();
        let record = NewMemoryRecord {
            id: candidate_id,
            kind: MemoryKind::ProceduralCandidate,
            scope: capture_scope,
            subject: procedure.subject.clone(),
            predicate: "procedure".to_owned(),
            conflict_key: format!("learning.procedure:{workflow_signature}"),
            assertion,
            trust: MemoryTrust::Observed,
            confidence: 90,
            provenance: MemoryProvenance {
                source_evidence_ids: retained_support
                    .iter()
                    .map(|id| format!("memory:{id}"))
                    .collect(),
                producing_task_id: None,
                producing_attempt_id: None,
                repository_revision: None,
                source_fingerprints: Vec::new(),
            },
            expires_at_ms: None,
            invalidation_predicates: Vec::new(),
        };
        let record = capture_or_existing(self.state, record, capture.observed_at_ms)?;
        Ok(Some(ProcedureCandidate {
            workflow_signature: workflow_signature.to_owned(),
            supporting_verified_episodes: support.len(),
            supporting_episode_ids: support,
            record,
        }))
    }
}

fn validate_capture(capture: &EpisodeCapture) -> Result<(), MemoryError> {
    if let Some(procedure) = &capture.procedure {
        validate_nonempty("workflow subject", &procedure.subject)?;
        validate_nonempty("workflow summary", &procedure.summary)?;
        if procedure.summary.len() > MAX_WORKFLOW_SUMMARY_BYTES {
            return Err(MemoryError::InvalidRecord(
                "workflow summary exceeds hard byte bound".to_owned(),
            ));
        }
        if procedure.steps.is_empty() || procedure.steps.len() > MAX_WORKFLOW_STEPS {
            return Err(MemoryError::InvalidRecord(format!(
                "workflow must contain 1..={MAX_WORKFLOW_STEPS} steps"
            )));
        }
        for step in &procedure.steps {
            validate_nonempty("workflow step", step)?;
            if step.len() > MAX_WORKFLOW_STEP_BYTES {
                return Err(MemoryError::InvalidRecord(
                    "workflow step exceeds hard byte bound".to_owned(),
                ));
            }
        }
    }
    for (field, value) in [
        ("plan_id", capture.proof.plan_id.as_str()),
        ("plan_digest", capture.proof.plan_digest.as_str()),
        ("task_id", capture.proof.task_id.as_str()),
        (
            "task_contract_digest",
            capture.proof.task_contract_digest.as_str(),
        ),
        ("attempt_id", capture.proof.attempt_id.as_str()),
        ("task_record_key", capture.proof.task_record_key.as_str()),
        (
            "attempt_record_key",
            capture.proof.attempt_record_key.as_str(),
        ),
    ] {
        validate_nonempty(field, value)?;
    }
    if capture.observed_at_ms < 0 {
        return Err(MemoryError::InvalidRecord(
            "episode timestamp must be non-negative".to_owned(),
        ));
    }
    Ok(())
}

fn validate_controller_outcome(
    state: &StateStore,
    proof: &ControllerEpisodeProof,
) -> Result<DurableOutcome, MemoryError> {
    let expected_task_key =
        revision_scoped_key(&proof.plan_id, proof.plan_revision, &proof.task_id);
    let expected_attempt_key =
        revision_scoped_key(&proof.plan_id, proof.plan_revision, &proof.attempt_id);
    if proof.task_record_key != expected_task_key
        || proof.attempt_record_key != expected_attempt_key
    {
        return Err(MemoryError::InvalidRecord(
            "Controller task/attempt proof keys are not revision-scoped to the claimed plan"
                .to_owned(),
        ));
    }
    let attempt_raw = state
        .get_state("controller.attempt", &proof.attempt_record_key)?
        .ok_or_else(|| {
            MemoryError::InvalidRecord("Controller attempt proof is missing".to_owned())
        })?;
    let attempt: Value = serde_json::from_str(&attempt_raw).map_err(|error| {
        MemoryError::InvalidRecord(format!("Controller attempt proof is malformed: {error}"))
    })?;
    if value_str(&attempt, "task_id") != Some(proof.task_id.as_str())
        || value_str(&attempt, "attempt_id") != Some(proof.attempt_id.as_str())
        || value_str(&attempt, "task_contract_digest") != Some(proof.task_contract_digest.as_str())
    {
        return Err(MemoryError::InvalidRecord(
            "Controller attempt proof binding does not match episode".to_owned(),
        ));
    }

    match &proof.outcome {
        ControllerEpisodeOutcomeProof::VerifiedSuccess {
            verification_record_key,
            verification_id,
        } => validate_verified_success(
            state,
            proof,
            &attempt,
            verification_record_key,
            verification_id,
        ),
        ControllerEpisodeOutcomeProof::FailedAttempt {
            failure_record_key,
            failure_signature,
        } => validate_failed_attempt(
            state,
            proof,
            &attempt,
            failure_record_key,
            failure_signature,
        ),
    }
}

fn validate_verified_success(
    state: &StateStore,
    proof: &ControllerEpisodeProof,
    attempt: &Value,
    verification_record_key: &str,
    verification_id: &str,
) -> Result<DurableOutcome, MemoryError> {
    if value_str(attempt, "state") != Some("succeeded") {
        return Err(MemoryError::InvalidRecord(
            "failed/non-succeeded attempt cannot be learned as verified success".to_owned(),
        ));
    }
    validate_nonempty("verification_record_key", verification_record_key)?;
    validate_nonempty("verification_id", verification_id)?;
    if verification_record_key
        != revision_scoped_key(&proof.plan_id, proof.plan_revision, verification_id)
    {
        return Err(MemoryError::InvalidRecord(
            "Controller verification key is not revision-scoped to the claimed plan".to_owned(),
        ));
    }
    let task_raw = state
        .get_state("controller.task", &proof.task_record_key)?
        .ok_or_else(|| MemoryError::InvalidRecord("Controller task proof is missing".to_owned()))?;
    let task: Value = serde_json::from_str(&task_raw).map_err(|error| {
        MemoryError::InvalidRecord(format!("Controller task proof is malformed: {error}"))
    })?;
    if value_str(&task, "state") != Some("succeeded")
        || value_str(&task, "task_contract_digest") != Some(proof.task_contract_digest.as_str())
    {
        return Err(MemoryError::InvalidRecord(
            "Controller task is not a succeeded matching contract".to_owned(),
        ));
    }

    let raw = state
        .get_state("controller.verification", verification_record_key)?
        .ok_or_else(|| {
            MemoryError::InvalidRecord("Controller verification proof is missing".to_owned())
        })?;
    let verification: Value = serde_json::from_str(&raw).map_err(|error| {
        MemoryError::InvalidRecord(format!(
            "Controller verification proof is malformed: {error}"
        ))
    })?;
    let revision = verification
        .get("plan_revision")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let passed = verification.get("passed").and_then(Value::as_bool);
    if value_str(&verification, "verification_id") != Some(verification_id)
        || value_str(&verification, "plan_id") != Some(proof.plan_id.as_str())
        || revision != Some(proof.plan_revision)
        || value_str(&verification, "plan_digest") != Some(proof.plan_digest.as_str())
        || value_str(&verification, "task_id") != Some(proof.task_id.as_str())
        || value_str(&verification, "task_contract_digest")
            != Some(proof.task_contract_digest.as_str())
        || value_str(&verification, "attempt_id") != Some(proof.attempt_id.as_str())
        || passed != Some(true)
    {
        return Err(MemoryError::InvalidRecord(
            "Controller verification does not prove this successful episode".to_owned(),
        ));
    }
    // Verification artifacts are published through `ArtifactStore`, whose
    // canonical CAS digest is the bare lowercase SHA-256 hex string. Bind the
    // persisted Controller verification bytes to that exact journal digest.
    let verification_digest = sha256_hex(raw.as_bytes());
    if !verification_journal_proves_pass(state, proof, verification_id, &verification_digest)? {
        return Err(MemoryError::InvalidRecord(
            "Controller verification lacks append-only passed journal evidence".to_owned(),
        ));
    }
    let mut evidence_ids = verification
        .get("evidence_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    evidence_ids.push(format!("controller.verification:{verification_id}"));
    evidence_ids.sort();
    evidence_ids.dedup();
    let repair_origin = validate_repair_origin(state, proof, attempt)?;
    Ok(DurableOutcome::VerifiedSuccess {
        verification_id: verification_id.to_owned(),
        evidence_ids,
        repair_origin,
    })
}

fn verification_journal_proves_pass(
    state: &StateStore,
    proof: &ControllerEpisodeProof,
    verification_id: &str,
    verification_digest: &str,
) -> Result<bool, MemoryError> {
    Ok(state.journal()?.into_iter().any(|event| {
        if event.entity_type != "controller"
            || !matches!(
                event.event_kind.as_str(),
                "verification_recorded" | "recovery_verification_recorded"
            )
            || event.entity_id != verification_id
        {
            return false;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&event.payload_json) else {
            return false;
        };
        payload.get("passed").and_then(Value::as_bool) == Some(true)
            && value_str(&payload, "plan_id") == Some(proof.plan_id.as_str())
            && payload.get("plan_revision").and_then(Value::as_u64)
                == Some(u64::from(proof.plan_revision))
            && value_str(&payload, "plan_digest") == Some(proof.plan_digest.as_str())
            && value_str(&payload, "task_id") == Some(proof.task_id.as_str())
            && value_str(&payload, "task_contract_digest")
                == Some(proof.task_contract_digest.as_str())
            && value_str(&payload, "attempt_id") == Some(proof.attempt_id.as_str())
            && value_str(&payload, "artifact_digest") == Some(verification_digest)
    }))
}

fn validate_failed_attempt(
    state: &StateStore,
    proof: &ControllerEpisodeProof,
    attempt: &Value,
    failure_record_key: &str,
    failure_signature: &str,
) -> Result<DurableOutcome, MemoryError> {
    if value_str(attempt, "state") != Some("failed") {
        return Err(MemoryError::InvalidRecord(
            "failure episode requires a durably failed Controller attempt".to_owned(),
        ));
    }
    validate_nonempty("failure_record_key", failure_record_key)?;
    validate_nonempty("failure_signature", failure_signature)?;
    let expected_failure_key = revision_scoped_key(
        &proof.plan_id,
        proof.plan_revision,
        &format!("{}:{}", proof.task_id, proof.attempt_id),
    );
    if failure_record_key != expected_failure_key {
        return Err(MemoryError::InvalidRecord(
            "Controller FailureRecord key is not revision-scoped to the claimed attempt".to_owned(),
        ));
    }
    let raw = state
        .get_state("controller.failure_record", failure_record_key)?
        .ok_or_else(|| {
            MemoryError::InvalidRecord("Controller FailureRecord proof is missing".to_owned())
        })?;
    let failure: Value = serde_json::from_str(&raw).map_err(|error| {
        MemoryError::InvalidRecord(format!("Controller FailureRecord is malformed: {error}"))
    })?;
    let revision = failure
        .get("plan_revision")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    if value_str(&failure, "plan_id") != Some(proof.plan_id.as_str())
        || revision != Some(proof.plan_revision)
        || value_str(&failure, "plan_digest") != Some(proof.plan_digest.as_str())
        || value_str(&failure, "task_id") != Some(proof.task_id.as_str())
        || value_str(&failure, "task_contract_digest") != Some(proof.task_contract_digest.as_str())
        || value_str(&failure, "attempt_id") != Some(proof.attempt_id.as_str())
        || value_str(&failure, "signature") != Some(failure_signature)
    {
        return Err(MemoryError::InvalidRecord(
            "Controller FailureRecord does not prove this failed episode".to_owned(),
        ));
    }
    let expected_digest = sha256_prefixed(raw.as_bytes());
    let journal_proves_failure = state.journal()?.into_iter().any(|event| {
        if event.entity_type != "controller" || event.event_kind != "failure_recorded" {
            return false;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&event.payload_json) else {
            return false;
        };
        value_str(&payload, "record_key") == Some(failure_record_key)
            && value_str(&payload, "failure_record_digest") == Some(expected_digest.as_str())
    });
    if !journal_proves_failure {
        return Err(MemoryError::InvalidRecord(
            "Controller FailureRecord lacks append-only digest binding".to_owned(),
        ));
    }
    let mut evidence_ids = failure
        .get("evidence_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    evidence_ids.push(format!("controller.failure:{failure_record_key}"));
    evidence_ids.sort();
    evidence_ids.dedup();
    Ok(DurableOutcome::FailedAttempt {
        failure_signature: failure_signature.to_owned(),
        evidence_ids,
    })
}

fn validate_repair_origin(
    state: &StateStore,
    proof: &ControllerEpisodeProof,
    attempt: &Value,
) -> Result<Option<ValidatedRepairOrigin>, MemoryError> {
    let Some(origin) = attempt
        .get("repair_origin")
        .filter(|value| !value.is_null())
    else {
        return Ok(None);
    };
    if origin.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(MemoryError::InvalidRecord(
            "repair episode has unsupported repair_origin schema".to_owned(),
        ));
    }
    let prior_attempt_id = required_value_str(origin, "prior_attempt_id")?;
    let failure_record_digest = required_value_str(origin, "failure_record_digest")?;
    let repair_packet_digest = required_value_str(origin, "repair_packet_digest")?;
    let failure_key = revision_scoped_key(
        &proof.plan_id,
        proof.plan_revision,
        &format!("{}:{prior_attempt_id}", proof.task_id),
    );
    let failure_raw = state
        .get_state("controller.failure_record", &failure_key)?
        .ok_or_else(|| {
            MemoryError::InvalidRecord("repair episode prior FailureRecord is missing".to_owned())
        })?;
    if sha256_prefixed(failure_raw.as_bytes()) != failure_record_digest {
        return Err(MemoryError::InvalidRecord(
            "repair episode prior FailureRecord digest does not match repair_origin".to_owned(),
        ));
    }
    let failure: Value = serde_json::from_str(&failure_raw).map_err(|error| {
        MemoryError::InvalidRecord(format!("repair prior FailureRecord is malformed: {error}"))
    })?;
    if value_str(&failure, "plan_id") != Some(proof.plan_id.as_str())
        || failure.get("plan_revision").and_then(Value::as_u64)
            != Some(u64::from(proof.plan_revision))
        || value_str(&failure, "plan_digest") != Some(proof.plan_digest.as_str())
        || value_str(&failure, "task_id") != Some(proof.task_id.as_str())
        || value_str(&failure, "task_contract_digest") != Some(proof.task_contract_digest.as_str())
        || value_str(&failure, "attempt_id") != Some(prior_attempt_id.as_str())
    {
        return Err(MemoryError::InvalidRecord(
            "repair episode prior FailureRecord binding is inconsistent".to_owned(),
        ));
    }

    let mut packet_key = None;
    let mut failure_journal_bound = false;
    for event in state.journal()? {
        if event.entity_type != "controller" {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&event.payload_json) else {
            continue;
        };
        if event.event_kind == "failure_recorded"
            && value_str(&payload, "record_key") == Some(failure_key.as_str())
            && value_str(&payload, "failure_record_digest") == Some(failure_record_digest.as_str())
        {
            failure_journal_bound = true;
        }
        if event.event_kind == "repair_packet_built"
            && value_str(&payload, "plan_id") == Some(proof.plan_id.as_str())
            && payload.get("plan_revision").and_then(Value::as_u64)
                == Some(u64::from(proof.plan_revision))
            && value_str(&payload, "plan_digest") == Some(proof.plan_digest.as_str())
            && value_str(&payload, "task_id") == Some(proof.task_id.as_str())
            && value_str(&payload, "prior_attempt_id") == Some(prior_attempt_id.as_str())
            && value_str(&payload, "failure_record_digest") == Some(failure_record_digest.as_str())
            && value_str(&payload, "repair_packet_digest") == Some(repair_packet_digest.as_str())
        {
            packet_key = value_str(&payload, "packet_key").map(str::to_owned);
        }
    }
    if !failure_journal_bound {
        return Err(MemoryError::InvalidRecord(
            "repair episode prior FailureRecord lacks append-only digest binding".to_owned(),
        ));
    }
    let packet_key = packet_key.ok_or_else(|| {
        MemoryError::InvalidRecord(
            "repair episode lacks a matching durable repair-packet journal binding".to_owned(),
        )
    })?;
    let packet_raw = state
        .get_state("controller.repair_packet", &packet_key)?
        .ok_or_else(|| {
            MemoryError::InvalidRecord("repair episode repair packet is missing".to_owned())
        })?;
    if sha256_prefixed(packet_raw.as_bytes()) != repair_packet_digest {
        return Err(MemoryError::InvalidRecord(
            "repair episode repair packet digest does not match repair_origin".to_owned(),
        ));
    }
    Ok(Some(ValidatedRepairOrigin {
        prior_attempt_id,
        failure_record_digest,
        repair_packet_digest,
    }))
}

fn capture_or_existing(
    state: &mut StateStore,
    mut record: NewMemoryRecord,
    now_ms: i64,
) -> Result<MemoryRecord, MemoryError> {
    normalize_new_record(&mut record);
    if let Some(existing) = state.transaction(|tx| load_record_tx(tx, &record.id))? {
        if existing.kind == record.kind
            && existing.scope == record.scope
            && existing.subject == record.subject
            && existing.predicate == record.predicate
            && existing.conflict_key == record.conflict_key
            && existing.assertion == record.assertion
            && existing.trust == record.trust
            && existing.confidence == record.confidence
            && existing.provenance == record.provenance
        {
            super::projection::drain_projection_outbox_state(state)
                .map_err(|error| MemoryError::ProjectionPending(error.to_string()))?;
            return Ok(existing);
        }
        return Err(MemoryError::InvalidRecord(format!(
            "learning memory {} already exists with different content",
            record.id
        )));
    }
    capture_record_in_state(state, record, now_ms)
}

fn workflow_signature(pattern: &WorkflowPattern) -> Result<String, MemoryError> {
    let encoded = serde_json::to_vec(pattern).map_err(|error| {
        MemoryError::InvalidRecord(format!("workflow signature serialization failed: {error}"))
    })?;
    Ok(sha256_prefixed(&encoded))
}

fn scope_signature(scope: &MemoryScope) -> Result<String, MemoryError> {
    let canonical_scope = canonical_scope(scope);
    let encoded = serde_json::to_vec(&canonical_scope).map_err(|error| {
        MemoryError::InvalidRecord(format!("memory scope serialization failed: {error}"))
    })?;
    Ok(sha256_prefixed(&encoded))
}

fn canonical_scope(scope: &MemoryScope) -> MemoryScope {
    let mut canonical = scope.clone();
    canonical.role_visibility.sort();
    canonical.role_visibility.dedup();
    canonical
}

fn revision_scoped_key(plan_id: &str, revision: u32, logical_key: &str) -> String {
    format!("{plan_id}@r{revision}:{logical_key}")
}

fn stable_id(kind: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    for part in parts {
        hasher.update([0]);
        hasher.update(part.as_bytes());
    }
    format!("memory.{kind}.sha256:{:x}", hasher.finalize())
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn value_str<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn required_value_str(value: &Value, field: &str) -> Result<String, MemoryError> {
    let result = value_str(value, field).ok_or_else(|| {
        MemoryError::InvalidRecord(format!("{field} must be present in Controller proof"))
    })?;
    validate_nonempty(field, result)?;
    Ok(result.to_owned())
}

fn validate_nonempty(field: &str, value: &str) -> Result<(), MemoryError> {
    if value.trim().is_empty() {
        return Err(MemoryError::InvalidRecord(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}
