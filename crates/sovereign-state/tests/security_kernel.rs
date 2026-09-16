use rusqlite::Connection;
use sovereign_state::{
    ActionTransition, CURRENT_SCHEMA_VERSION, MIGRATIONS, MigrationRunner, NewActionRecord,
    NewCheckpointIntegrityRecord, NewJournalEvent, StateStore,
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
            result_digest: None,
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
                result_digest: None,
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
                result_digest: None,
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

#[test]
fn committed_action_requires_durable_result_reference() {
    let temp = TestDir::new("committed-result");
    let mut store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let epoch = store
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch: {error}"));
    store
        .insert_action_record(NewActionRecord {
            action_id: "action_receipt",
            state: "authorized",
            payload_digest: "sha256:payload",
            policy_digest: "sha256:policy",
            execution_epoch: epoch,
            event_id: "event_receipt_authorized",
            event_kind: "authorized",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    store
        .transition_action_with_event(ActionTransition {
            action_id: "action_receipt",
            expected_state: "authorized",
            next_state: "dispatched",
            expected_epoch: epoch,
            event_id: "event_receipt_dispatched",
            event_kind: "dispatched",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("dispatch: {error}"));
    store
        .transition_action_with_event(ActionTransition {
            action_id: "action_receipt",
            expected_state: "dispatched",
            next_state: "observed",
            expected_epoch: epoch,
            event_id: "event_receipt_observed",
            event_kind: "observed",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("observe: {error}"));
    assert!(
        store
            .transition_action_with_event(ActionTransition {
                action_id: "action_receipt",
                expected_state: "observed",
                next_state: "committed",
                expected_epoch: epoch,
                event_id: "event_receipt_commit_without_result",
                event_kind: "committed",
                payload_json: "{}",
                result_digest: None,
            })
            .is_err()
    );
    let record = store
        .action_record("action_receipt")
        .unwrap_or_else(|error| panic!("record: {error}"))
        .unwrap_or_else(|| panic!("missing action"));
    assert_eq!(record.state, "observed");
    assert!(record.result_digest.is_none());
}

#[test]
fn observed_action_recovery_becomes_unknown_before_epoch_advance() {
    let temp = TestDir::new("observed-recovery");
    let mut store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    let epoch = store
        .current_execution_epoch()
        .unwrap_or_else(|error| panic!("epoch: {error}"));
    store
        .insert_action_record(NewActionRecord {
            action_id: "action_observed_crash",
            state: "authorized",
            payload_digest: "sha256:payload",
            policy_digest: "sha256:policy",
            execution_epoch: epoch,
            event_id: "event_observed_authorized",
            event_kind: "authorized",
            payload_json: "{}",
        })
        .unwrap_or_else(|error| panic!("authorize: {error}"));
    store
        .transition_action_with_event(ActionTransition {
            action_id: "action_observed_crash",
            expected_state: "authorized",
            next_state: "dispatched",
            expected_epoch: epoch,
            event_id: "event_observed_dispatched",
            event_kind: "dispatched",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("dispatch: {error}"));
    store
        .transition_action_with_event(ActionTransition {
            action_id: "action_observed_crash",
            expected_state: "dispatched",
            next_state: "observed",
            expected_epoch: epoch,
            event_id: "event_observed_result",
            event_kind: "observed",
            payload_json: "{}",
            result_digest: None,
        })
        .unwrap_or_else(|error| panic!("observe: {error}"));

    store
        .recover_nonterminal_action_as_unknown(
            "action_observed_crash",
            &["observed"],
            "event_observed_recovered_unknown",
            "{\"reason\":\"restart_after_observed_before_terminal_commit\"}",
        )
        .unwrap_or_else(|error| panic!("recover observed as unknown: {error}"));
    let record = store
        .action_record("action_observed_crash")
        .unwrap_or_else(|error| panic!("record: {error}"))
        .unwrap_or_else(|| panic!("missing recovered action"));
    assert_eq!(record.state, "unknown");
    assert_eq!(
        store
            .current_execution_epoch()
            .unwrap_or_else(|error| panic!("epoch after recovery: {error}")),
        epoch
    );
    assert_eq!(
        store
            .journal()
            .unwrap_or_else(|error| panic!("journal: {error}"))
            .last()
            .map(|event| event.event_kind.as_str()),
        Some("unknown")
    );
}

#[test]
fn version_two_database_upgrades_in_place_to_single_canonical_version_three() {
    let temp = TestDir::new("v2-upgrade");
    let db = temp.db();
    let mut connection =
        Connection::open(&db).unwrap_or_else(|error| panic!("open raw v2: {error}"));
    MigrationRunner::apply(&mut connection, &MIGRATIONS[..2])
        .unwrap_or_else(|error| panic!("apply v2: {error}"));
    connection
        .execute(
            "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) VALUES ('compat', 'kept', '{\"v\":2}', 1, 1)",
            [],
        )
        .unwrap_or_else(|error| panic!("seed v2: {error}"));
    drop(connection);

    let store = StateStore::open(&db).unwrap_or_else(|error| panic!("upgrade: {error}"));
    assert_eq!(store.schema_version().unwrap_or(-1), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        store.get_state("compat", "kept").unwrap_or_default(),
        Some("{\"v\":2}".to_owned())
    );
    assert_eq!(store.current_execution_epoch().unwrap_or(-1), 0);
}

#[test]
fn migration_manifest_has_one_version_three_and_matches_runtime() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join("manifest.json");
    let bytes = fs::read(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    let manifest: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("manifest json: {error}"));
    assert_eq!(
        manifest["current_version"].as_i64(),
        Some(CURRENT_SCHEMA_VERSION)
    );
    let migrations = manifest["migrations"]
        .as_array()
        .unwrap_or_else(|| panic!("migrations array"));
    let v3 = migrations
        .iter()
        .filter(|entry| entry["version"].as_i64() == Some(3))
        .collect::<Vec<_>>();
    assert_eq!(v3.len(), 1);
    assert_eq!(v3[0]["path"].as_str(), Some("0003_security_kernel.sql"));
    assert_eq!(
        MIGRATIONS
            .iter()
            .filter(|migration| migration.version == 3)
            .count(),
        1
    );
}
