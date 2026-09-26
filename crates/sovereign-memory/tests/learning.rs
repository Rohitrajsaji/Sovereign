use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sovereign_memory::{
    ControllerEpisodeOutcomeProof, ControllerEpisodeProof, EpisodeCapture, EpisodeRecorder,
    MemoryKind, MemoryLifecycle, MemoryManager, MemoryProvenance, MemoryScope, MemoryScopeKind,
    MemoryTrust, NewMemoryRecord, ProcedurePattern,
};
use sovereign_state::{NewJournalEvent, StateStore};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const NOW: i64 = 1_900_000_000_000;
const PLAN_ID: &str = "plan.learning";
const PLAN_DIGEST: &str = "sha256:plan-learning";
const TASK_ID: &str = "task.learning";
const TASK_CONTRACT: &str = "sha256:task-learning";

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-memory-learning-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap_or_else(|error| panic!("create test dir: {error}"));
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("state.sqlite3")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scope(project_id: &str) -> MemoryScope {
    MemoryScope {
        project_id: project_id.to_owned(),
        repository_id: Some("repo.learning".to_owned()),
        kind: MemoryScopeKind::Project,
        agent_id: None,
        role_visibility: Vec::new(),
    }
}

fn procedure() -> ProcedurePattern {
    ProcedurePattern {
        subject: "workflow.inventory-repair".to_owned(),
        summary: "Repair the inventory flow and verify the deterministic contract".to_owned(),
        steps: vec![
            "inspect the exact failure evidence".to_owned(),
            "apply the bounded repair and rerun verification".to_owned(),
        ],
    }
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

fn workflow_signature(pattern: &ProcedurePattern) -> String {
    let bytes = serde_json::to_vec(pattern)
        .unwrap_or_else(|error| panic!("serialize workflow signature: {error}"));
    sha256_prefixed(&bytes)
}

fn revision_key(plan_id: &str, revision: u32, logical_key: &str) -> String {
    format!("{plan_id}@r{revision}:{logical_key}")
}

fn put_json(state: &mut StateStore, namespace: &str, key: &str, value: &Value) {
    let raw = serde_json::to_string(value)
        .unwrap_or_else(|error| panic!("serialize {namespace}/{key}: {error}"));
    state
        .put_state(namespace, key, &raw)
        .unwrap_or_else(|error| panic!("put {namespace}/{key}: {error}"));
}

fn append_event(
    state: &mut StateStore,
    event_id: &str,
    entity_id: &str,
    event_kind: &str,
    payload: &Value,
) {
    let raw = serde_json::to_string(payload)
        .unwrap_or_else(|error| panic!("serialize journal payload: {error}"));
    state
        .append_event(NewJournalEvent {
            event_id,
            entity_type: "controller",
            entity_id,
            event_kind,
            payload_json: &raw,
        })
        .unwrap_or_else(|error| panic!("append {event_kind}: {error}"));
}

fn seed_task(state: &mut StateStore, plan_id: &str, revision: u32, task_state: &str) {
    let task_key = revision_key(plan_id, revision, TASK_ID);
    put_json(
        state,
        "controller.task",
        &task_key,
        &json!({
            "task_id": TASK_ID,
            "state": task_state,
            "task_contract_digest": TASK_CONTRACT,
        }),
    );
}

fn success_proof(
    state: &mut StateStore,
    plan_id: &str,
    revision: u32,
    plan_digest: &str,
    attempt_id: &str,
) -> ControllerEpisodeProof {
    success_proof_with_journal_binding(
        state,
        plan_id,
        revision,
        plan_digest,
        attempt_id,
        attempt_id,
    )
}

fn success_proof_with_journal_binding(
    state: &mut StateStore,
    plan_id: &str,
    revision: u32,
    plan_digest: &str,
    attempt_id: &str,
    journal_attempt_id: &str,
) -> ControllerEpisodeProof {
    seed_task(state, plan_id, revision, "succeeded");
    let attempt_key = revision_key(plan_id, revision, attempt_id);
    put_json(
        state,
        "controller.attempt",
        &attempt_key,
        &json!({
            "task_id": TASK_ID,
            "attempt_id": attempt_id,
            "state": "succeeded",
            "task_contract_digest": TASK_CONTRACT,
            "repair_origin": null,
        }),
    );
    let verification_id = format!("verification.{attempt_id}");
    let verification_key = revision_key(plan_id, revision, &verification_id);
    let verification = json!({
        "schema_version": 1,
        "verification_id": verification_id,
        "plan_id": plan_id,
        "plan_revision": revision,
        "plan_digest": plan_digest,
        "task_id": TASK_ID,
        "task_contract_digest": TASK_CONTRACT,
        "attempt_id": attempt_id,
        "passed": true,
        "evidence_ids": [format!("evidence.{attempt_id}")],
    });
    let verification_raw = serde_json::to_string(&verification)
        .unwrap_or_else(|error| panic!("serialize verification: {error}"));
    state
        .put_state(
            "controller.verification",
            &verification_key,
            &verification_raw,
        )
        .unwrap_or_else(|error| panic!("put verification: {error}"));
    append_event(
        state,
        &format!("event.verification.{attempt_id}"),
        verification
            .get("verification_id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("verification id missing")),
        "verification_recorded",
        &json!({
            "passed": true,
            "plan_id": plan_id,
            "plan_revision": revision,
            "plan_digest": plan_digest,
            "task_id": TASK_ID,
            "task_contract_digest": TASK_CONTRACT,
            "attempt_id": journal_attempt_id,
            "artifact_digest": sha256_hex(verification_raw.as_bytes()),
        }),
    );
    ControllerEpisodeProof {
        plan_id: plan_id.to_owned(),
        plan_revision: revision,
        plan_digest: plan_digest.to_owned(),
        task_id: TASK_ID.to_owned(),
        task_contract_digest: TASK_CONTRACT.to_owned(),
        attempt_id: attempt_id.to_owned(),
        task_record_key: revision_key(plan_id, revision, TASK_ID),
        attempt_record_key: attempt_key,
        outcome: ControllerEpisodeOutcomeProof::VerifiedSuccess {
            verification_record_key: verification_key,
            verification_id: format!("verification.{attempt_id}"),
        },
    }
}

fn failed_proof(state: &mut StateStore, attempt_id: &str) -> ControllerEpisodeProof {
    seed_task(state, PLAN_ID, 1, "failed");
    let attempt_key = revision_key(PLAN_ID, 1, attempt_id);
    put_json(
        state,
        "controller.attempt",
        &attempt_key,
        &json!({
            "task_id": TASK_ID,
            "attempt_id": attempt_id,
            "state": "failed",
            "task_contract_digest": TASK_CONTRACT,
        }),
    );
    let failure_key = revision_key(PLAN_ID, 1, &format!("{TASK_ID}:{attempt_id}"));
    let failure = json!({
        "schema_version": 1,
        "plan_id": PLAN_ID,
        "plan_revision": 1,
        "plan_digest": PLAN_DIGEST,
        "task_id": TASK_ID,
        "task_contract_digest": TASK_CONTRACT,
        "attempt_id": attempt_id,
        "signature": format!("failure.{attempt_id}"),
        "evidence_refs": [format!("evidence.failure.{attempt_id}")],
    });
    let failure_raw = serde_json::to_string(&failure)
        .unwrap_or_else(|error| panic!("serialize failure: {error}"));
    state
        .put_state("controller.failure_record", &failure_key, &failure_raw)
        .unwrap_or_else(|error| panic!("put failure: {error}"));
    append_event(
        state,
        &format!("event.failure.{attempt_id}"),
        attempt_id,
        "failure_recorded",
        &json!({
            "record_key": failure_key,
            "failure_record_digest": sha256_prefixed(failure_raw.as_bytes()),
        }),
    );
    ControllerEpisodeProof {
        plan_id: PLAN_ID.to_owned(),
        plan_revision: 1,
        plan_digest: PLAN_DIGEST.to_owned(),
        task_id: TASK_ID.to_owned(),
        task_contract_digest: TASK_CONTRACT.to_owned(),
        attempt_id: attempt_id.to_owned(),
        task_record_key: revision_key(PLAN_ID, 1, TASK_ID),
        attempt_record_key: attempt_key,
        outcome: ControllerEpisodeOutcomeProof::FailedAttempt {
            failure_record_key: failure_key,
            failure_signature: format!("failure.{attempt_id}"),
        },
    }
}

fn capture(scope: MemoryScope, proof: ControllerEpisodeProof) -> EpisodeCapture {
    EpisodeCapture {
        scope,
        procedure: Some(procedure()),
        proof,
        observed_at_ms: NOW,
    }
}

fn memory_count(db: &Path, kind: &str) -> i64 {
    let connection = Connection::open(db).unwrap_or_else(|error| panic!("open observer: {error}"));
    connection
        .query_row(
            "SELECT COUNT(*) FROM memory_records WHERE kind=?1",
            [kind],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count {kind}: {error}"))
}

#[test]
fn learning_failed_attempt_never_promotes_as_success() {
    let temp = TestDir::new("failed-never-promotes");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    for (offset, attempt_id) in ["attempt.failed.1", "attempt.failed.2"]
        .into_iter()
        .enumerate()
    {
        let proof = failed_proof(&mut state, attempt_id);
        let mut request = capture(scope("project.learning"), proof);
        request.observed_at_ms += i64::try_from(offset).unwrap_or(0);
        let result = EpisodeRecorder::new(&mut state)
            .record(&request)
            .unwrap_or_else(|error| panic!("record failed episode: {error}"));
        assert!(result.candidate.is_none());
        assert!(result.episode.predicate.starts_with("failed_attempt:"));
    }
    drop(state);
    assert_eq!(memory_count(&temp.db(), "procedural_candidate"), 0);
}

#[test]
fn learning_repeated_verified_pattern_creates_candidate_and_replay_is_idempotent() {
    let temp = TestDir::new("repeated-verified");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let proof_one = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.success.1");
    let first_capture = capture(scope("project.learning"), proof_one);
    let first = EpisodeRecorder::new(&mut state)
        .record(&first_capture)
        .unwrap_or_else(|error| panic!("record first success: {error}"));
    assert!(first.candidate.is_none());

    let replay = EpisodeRecorder::new(&mut state)
        .record(&first_capture)
        .unwrap_or_else(|error| panic!("replay first success: {error}"));
    assert_eq!(replay.episode.id, first.episode.id);
    assert!(replay.candidate.is_none());

    let proof_two = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.success.2");
    let second = EpisodeRecorder::new(&mut state)
        .record(&capture(scope("project.learning"), proof_two))
        .unwrap_or_else(|error| panic!("record second success: {error}"));
    let candidate = second
        .candidate
        .unwrap_or_else(|| panic!("second distinct verified success must create candidate"));
    let initial_provenance = candidate.record.provenance.clone();
    assert_eq!(candidate.supporting_verified_episodes, 2);
    assert_eq!(candidate.supporting_episode_ids.len(), 2);
    assert_eq!(candidate.record.kind, MemoryKind::ProceduralCandidate);
    assert_eq!(candidate.record.trust, MemoryTrust::Observed);

    let proof_three = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.success.3");
    let mut third_capture = capture(scope("project.learning"), proof_three);
    third_capture.observed_at_ms = NOW - 1_000;
    let third = EpisodeRecorder::new(&mut state)
        .record(&third_capture)
        .unwrap_or_else(|error| panic!("record third success: {error}"));
    let third_candidate = third
        .candidate
        .unwrap_or_else(|| panic!("third success should reuse candidate"));
    assert_eq!(third_candidate.record.id, candidate.record.id);
    assert_eq!(third_candidate.record.provenance, initial_provenance);
    assert_eq!(third_candidate.supporting_verified_episodes, 3);
    assert_eq!(third_candidate.supporting_episode_ids.len(), 3);
    assert!(
        third_candidate
            .supporting_episode_ids
            .contains(&third.episode.id)
    );
}

#[test]
fn learning_verification_journal_must_match_exact_task_contract_and_attempt() {
    let temp = TestDir::new("verification-journal-binding");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let proof = success_proof_with_journal_binding(
        &mut state,
        PLAN_ID,
        1,
        PLAN_DIGEST,
        "attempt.binding",
        "attempt.other",
    );
    let Err(error) =
        EpisodeRecorder::new(&mut state).record(&capture(scope("project.learning"), proof))
    else {
        panic!("mismatched verification journal attempt binding must fail closed");
    };
    assert!(
        error
            .to_string()
            .contains("lacks append-only passed journal evidence")
    );
}

#[test]
fn learning_revision_one_bare_keys_cannot_claim_scoped_controller_proof() {
    let temp = TestDir::new("revision-one-bare-proof");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let mut proof = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.scoped");
    proof.task_record_key = TASK_ID.to_owned();
    proof.attempt_record_key = proof.attempt_id.clone();
    let Err(error) =
        EpisodeRecorder::new(&mut state).record(&capture(scope("project.learning"), proof))
    else {
        panic!("bare revision-one proof keys must not claim canonical scoped records");
    };
    assert!(error.to_string().contains("not revision-scoped"));
}

#[test]
fn learning_generic_memory_cannot_spoof_candidate_support() {
    let temp = TestDir::new("spoof-support");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let genuine = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.real");
    drop(state);

    let pattern = procedure();
    let signature = workflow_signature(&pattern);
    let mut memory =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("memory: {error}"));
    memory
        .capture(
            NewMemoryRecord {
                id: "memory.spoof".to_owned(),
                kind: MemoryKind::Episodic,
                scope: scope("project.learning"),
                subject: format!("learning.workflow:{signature}"),
                predicate: "verified_success:attempt.spoof".to_owned(),
                conflict_key: "learning.episode:spoof".to_owned(),
                assertion: json!({
                    "schema_version": 1,
                    "outcome": "verified_success",
                    "workflow_signature": signature,
                    "procedure": pattern,
                })
                .to_string(),
                trust: MemoryTrust::Observed,
                confidence: 100,
                provenance: MemoryProvenance {
                    source_evidence_ids: vec!["evidence.spoof".to_owned()],
                    producing_task_id: Some(TASK_ID.to_owned()),
                    producing_attempt_id: Some("attempt.spoof".to_owned()),
                    repository_revision: None,
                    source_fingerprints: Vec::new(),
                },
                expires_at_ms: None,
                invalidation_predicates: Vec::new(),
            },
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture spoof: {error}"));
    drop(memory);

    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("reopen: {error}"));
    let result = EpisodeRecorder::new(&mut state)
        .record(&capture(scope("project.learning"), genuine))
        .unwrap_or_else(|error| panic!("record real support: {error}"));
    assert!(result.candidate.is_none());
}

#[test]
fn learning_governed_decision_precedes_candidate_and_governed_trust_is_restricted() {
    let temp = TestDir::new("governed-precedence");
    let pattern = procedure();
    let mut memory =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("memory: {error}"));
    memory
        .capture(
            NewMemoryRecord {
                id: "memory.governed.workflow".to_owned(),
                kind: MemoryKind::GovernedKnowledge,
                scope: scope("project.learning"),
                subject: pattern.subject.clone(),
                predicate: "procedure".to_owned(),
                conflict_key: "governed.workflow.inventory-repair".to_owned(),
                assertion: "manual approval required; do not promote automatically".to_owned(),
                trust: MemoryTrust::Governed,
                confidence: 100,
                provenance: MemoryProvenance {
                    source_evidence_ids: vec!["evidence.governed".to_owned()],
                    producing_task_id: None,
                    producing_attempt_id: None,
                    repository_revision: None,
                    source_fingerprints: Vec::new(),
                },
                expires_at_ms: None,
                invalidation_predicates: Vec::new(),
            },
            NOW,
        )
        .unwrap_or_else(|error| panic!("capture governed: {error}"));
    let invalid = NewMemoryRecord {
        id: "memory.invalid-governed".to_owned(),
        kind: MemoryKind::ProceduralCandidate,
        scope: scope("project.learning"),
        subject: "invalid".to_owned(),
        predicate: "procedure".to_owned(),
        conflict_key: "invalid".to_owned(),
        assertion: "must fail".to_owned(),
        trust: MemoryTrust::Governed,
        confidence: 100,
        provenance: MemoryProvenance {
            source_evidence_ids: vec!["evidence.invalid".to_owned()],
            producing_task_id: None,
            producing_attempt_id: None,
            repository_revision: None,
            source_fingerprints: Vec::new(),
        },
        expires_at_ms: None,
        invalidation_predicates: Vec::new(),
    };
    let Err(error) = memory.capture(invalid, NOW + 1) else {
        panic!("procedural candidate must not claim governed trust");
    };
    assert!(
        error
            .to_string()
            .contains("reserved for governed_knowledge")
    );
    drop(memory);

    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("state: {error}"));
    let one = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.governed.1");
    let two = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.governed.2");
    EpisodeRecorder::new(&mut state)
        .record(&capture(scope("project.learning"), one))
        .unwrap_or_else(|error| panic!("first support: {error}"));
    let second = EpisodeRecorder::new(&mut state)
        .record(&capture(scope("project.learning"), two))
        .unwrap_or_else(|error| panic!("second support: {error}"));
    let candidate = second
        .candidate
        .unwrap_or_else(|| panic!("candidate missing"));
    assert!(!candidate.record.normal_injection);
    assert_eq!(
        candidate.record.exclusion_reason.as_deref(),
        Some("contradicts_governed")
    );
}

#[test]
fn learning_tampered_verification_row_fails_digest_binding() {
    let temp = TestDir::new("verification-tamper");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let proof = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.tampered");
    let verification_key = match &proof.outcome {
        ControllerEpisodeOutcomeProof::VerifiedSuccess {
            verification_record_key,
            ..
        } => verification_record_key.clone(),
        ControllerEpisodeOutcomeProof::FailedAttempt { .. } => panic!("expected success proof"),
    };
    let raw = state
        .get_state("controller.verification", &verification_key)
        .unwrap_or_else(|error| panic!("read verification: {error}"))
        .unwrap_or_else(|| panic!("verification missing"));
    let mut tampered: Value =
        serde_json::from_str(&raw).unwrap_or_else(|error| panic!("decode verification: {error}"));
    tampered["evidence_ids"] = json!(["evidence.rewritten-after-journal"]);
    put_json(
        &mut state,
        "controller.verification",
        &verification_key,
        &tampered,
    );
    let Err(error) =
        EpisodeRecorder::new(&mut state).record(&capture(scope("project.learning"), proof))
    else {
        panic!("tampered verification must fail closed");
    };
    assert!(
        error
            .to_string()
            .contains("lacks append-only passed journal evidence")
    );
}

#[test]
fn learning_scope_is_canonical_for_duplicate_replay_and_candidate_identity() {
    let temp = TestDir::new("scope-canonical");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let proof_one = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.scope.1");
    let mut unsorted = scope("project.learning");
    unsorted.role_visibility = vec![
        "reviewer".to_owned(),
        "builder".to_owned(),
        "reviewer".to_owned(),
    ];
    let first_capture = capture(unsorted, proof_one);
    let first = EpisodeRecorder::new(&mut state)
        .record(&first_capture)
        .unwrap_or_else(|error| panic!("first scope capture: {error}"));

    let mut canonical = first_capture.clone();
    canonical.scope.role_visibility = vec!["builder".to_owned(), "reviewer".to_owned()];
    let replay = EpisodeRecorder::new(&mut state)
        .record(&canonical)
        .unwrap_or_else(|error| panic!("canonical replay: {error}"));
    assert_eq!(first.episode.id, replay.episode.id);

    let proof_two = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.scope.2");
    let candidate = EpisodeRecorder::new(&mut state)
        .record(&capture(canonical.scope.clone(), proof_two))
        .unwrap_or_else(|error| panic!("second scope support: {error}"))
        .candidate
        .unwrap_or_else(|| panic!("candidate missing"));

    let other_plan = "plan.learning.other";
    let other_digest = "sha256:plan-learning-other";
    let other_one = success_proof(&mut state, other_plan, 2, other_digest, "attempt.other.1");
    let other_two = success_proof(&mut state, other_plan, 2, other_digest, "attempt.other.2");
    EpisodeRecorder::new(&mut state)
        .record(&capture(scope("project.other"), other_one))
        .unwrap_or_else(|error| panic!("other first: {error}"));
    let other_candidate = EpisodeRecorder::new(&mut state)
        .record(&capture(scope("project.other"), other_two))
        .unwrap_or_else(|error| panic!("other second: {error}"))
        .candidate
        .unwrap_or_else(|| panic!("other candidate missing"));
    assert_ne!(candidate.record.id, other_candidate.record.id);
}

#[test]
fn learning_existing_episode_replay_drains_projection_outbox() {
    let temp = TestDir::new("projection-replay");
    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let proof = success_proof(&mut state, PLAN_ID, 1, PLAN_DIGEST, "attempt.projection");
    let request = capture(scope("project.learning"), proof);
    let episode = EpisodeRecorder::new(&mut state)
        .record(&request)
        .unwrap_or_else(|error| panic!("first record: {error}"))
        .episode;
    drop(state);

    let connection =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("observer: {error}"));
    connection
        .execute(
            "INSERT INTO memory_projection_outbox(\
                 schema_version, projection_kind, memory_id, canonical_updated_at_ms, enqueued_at_ms\
             ) VALUES (1, 'memory_fts_v1', ?1, ?2, ?2) \
             ON CONFLICT(projection_kind, memory_id) DO UPDATE SET \
                 canonical_updated_at_ms=excluded.canonical_updated_at_ms, \
                 enqueued_at_ms=excluded.enqueued_at_ms",
            rusqlite::params![episode.id, NOW + 10],
        )
        .unwrap_or_else(|error| panic!("enqueue projection retry: {error}"));
    drop(connection);

    let mut state = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("reopen: {error}"));
    EpisodeRecorder::new(&mut state)
        .record(&request)
        .unwrap_or_else(|error| panic!("replay record: {error}"));
    drop(state);
    let connection = Connection::open(temp.db()).unwrap_or_else(|error| panic!("observe: {error}"));
    let pending: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM memory_projection_outbox WHERE memory_id=?1",
            [episode.id],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count pending projection: {error}"));
    assert_eq!(pending, 0);
}
