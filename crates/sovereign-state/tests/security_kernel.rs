use rusqlite::Connection;
use sovereign_state::{
    ActionTransition, NewActionRecord, NewCheckpointIntegrityRecord, NewJournalEvent, StateStore,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-state-security-{label}-{}-{nonce}",
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

#[test]
fn exact_action_authorization_and_transitions_are_atomic_and_epoch_bound() {
    let temp = TestDir::new("action");
    let mut store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let epoch = store
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch: {error}"));
    assert_eq!(epoch, 0);

    let authorized_sequence = store
        .insert_action_record(NewActionRecord {
            action_id: "action_test",
            state: "authorized",
            payload_digest: "sha256:payload",
            policy_digest: "sha256:policy",
            execution_epoch: epoch,
            event_id: "event_authorized",
            event_kind: "authorized",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    assert_eq!(authorized_sequence, 1);

    let dispatched_sequence = store
        .transition_action_with_event(ActionTransition {
            action_id: "action_test",
            expected_state: "authorized",
            next_state: "dispatched",
            expected_epoch: epoch,
            event_id: "event_dispatched",
            event_kind: "dispatched",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("dispatch: {error}"));
    assert_eq!(dispatched_sequence, 2);
    let record = store
        .action_record("action_test")
        .unwrap_or_else(|error| panic!("record: {error}"))
        .unwrap_or_else(|| panic!("missing action"));
    assert_eq!(record.state, "dispatched");
    assert_eq!(record.last_event_sequence, 2);

    assert!(
        store
            .transition_action_with_event(ActionTransition {
                action_id: "action_test",
                expected_state: "authorized",
                next_state: "observed",
                expected_epoch: epoch,
                event_id: "event_stale_state",
                event_kind: "observed",
                payload_json: "{}",
            })
            .is_err()
    );
    assert_eq!(store.latest_journal_sequence().unwrap_or(-1), 2);

    let next_epoch = store
        .advance_execution_epoch()
        .unwrap_or_else(|error| panic!("advance epoch: {error}"));
    assert_eq!(next_epoch, 1);
    assert!(
        store
            .transition_action_with_event(ActionTransition {
                action_id: "action_test",
                expected_state: "dispatched",
                next_state: "observed",
                expected_epoch: next_epoch,
                event_id: "event_wrong_epoch",
                event_kind: "observed",
                payload_json: "{}",
            })
            .is_err()
    );
    assert_eq!(store.latest_journal_sequence().unwrap_or(-1), 2);
}

#[test]
fn checkpoint_hash_chain_is_monotonic_and_corrupt_tail_falls_back_only_to_valid_floor() {
    let temp = TestDir::new("checkpoint");
    let mut store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let sequence = store
        .append_event(NewJournalEvent {
            event_id: "event_one",
            entity_type: "test",
            entity_id: "test_one",
            event_kind: "seed",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("seed event: {error}"));
    assert_eq!(sequence, 1);

    let first = store
        .append_checkpoint_integrity(NewCheckpointIntegrityRecord {
            payload_digest: "sha256:checkpoint-one",
            action_sequence: sequence,
        })
        .unwrap_or_else(|error| panic!("first checkpoint: {error}"));
    let second = store
        .append_checkpoint_integrity(NewCheckpointIntegrityRecord {
            payload_digest: "sha256:checkpoint-two",
            action_sequence: sequence,
        })
        .unwrap_or_else(|error| panic!("second checkpoint: {error}"));
    assert_eq!(first.generation, 1);
    assert_eq!(second.generation, 2);
    assert_eq!(
        second.previous_hash.as_deref(),
        Some(first.checkpoint_hash.as_str())
    );
    let validated = store
        .validate_checkpoint_integrity_floor(sequence)
        .unwrap_or_else(|error| panic!("validate chain: {error}"))
        .unwrap_or_else(|| panic!("missing valid checkpoint"));
    assert_eq!(validated.generation, 2);

    drop(store);
    let connection =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("raw open: {error}"));
    connection
        .execute(
            "INSERT INTO checkpoint_integrity(generation, previous_hash, checkpoint_hash, payload_digest, action_sequence, created_at_ms) VALUES (3, ?1, 'sha256:corrupt', 'sha256:tail', 1, 0)",
            [second.checkpoint_hash.as_str()],
        )
        .unwrap_or_else(|error| panic!("insert corrupt tail: {error}"));
    drop(connection);

    let mut store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("reopen: {error}"));
    let fallback = store
        .validate_checkpoint_integrity_floor(sequence)
        .unwrap_or_else(|error| panic!("fallback: {error}"))
        .unwrap_or_else(|| panic!("missing fallback"));
    assert_eq!(fallback.generation, 2);

    let newer_sequence = store
        .append_event(NewJournalEvent {
            event_id: "event_two",
            entity_type: "test",
            entity_id: "test_two",
            event_kind: "newer",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("newer event: {error}"));
    assert_eq!(newer_sequence, 2);
    assert!(
        store
            .validate_checkpoint_integrity_floor(newer_sequence)
            .is_err()
    );
}

#[test]
fn missing_checkpoint_blocks_nonzero_authoritative_journal_sequence() {
    let temp = TestDir::new("missing-floor");
    let mut store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let sequence = store
        .append_event(NewJournalEvent {
            event_id: "event_uncheckpointed",
            entity_type: "test",
            entity_id: "test_uncheckpointed",
            event_kind: "mutation",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("event: {error}"));
    assert!(store.validate_checkpoint_integrity_floor(sequence).is_err());
}
