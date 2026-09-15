use rusqlite::Connection;
use sovereign_state::{
    CURRENT_SCHEMA_VERSION, MIGRATIONS, MigrationRunner, SecurityAuditEventV1, StateStore,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-state-audit-budget-recovery-{label}-{}-{nonce}",
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

fn audit_event(index: i64) -> SecurityAuditEventV1 {
    SecurityAuditEventV1 {
        actor_id: "controller:prime".to_owned(),
        plan_id: Some("plan:m6".to_owned()),
        task_id: Some("M6-T06".to_owned()),
        attempt_id: Some(format!("attempt:{index}")),
        action_id: Some(format!("action:{index}")),
        execution_epoch: Some(7),
        decision: "allow".to_owned(),
        action: "authorized_mutation".to_owned(),
        policy_digest: "sha256:policy".to_owned(),
        config_digest: "sha256:config".to_owned(),
        tool_digest: "sha256:tool".to_owned(),
        approval_provenance_digest: Some("sha256:approval".to_owned()),
        evidence_provenance_digest: Some(format!("sha256:evidence-{index}")),
        occurred_at_ms: 1_700_000_000_000 + index,
        result: "authorized".to_owned(),
    }
}

fn append_events(path: &Path, count: i64) {
    let mut store = StateStore::open(path).unwrap_or_else(|error| panic!("open: {error}"));
    let mut log = store.security_audit_log();
    for index in 1..=count {
        log.append(&audit_event(index))
            .unwrap_or_else(|error| panic!("append {index}: {error}"));
    }
    log.verify_chain()
        .unwrap_or_else(|error| panic!("verify seeded chain: {error}"));
}

#[test]
fn audit_budget_recovery_append_verify_restart_and_sqlite_integrity_are_durable() {
    let temp = TestDir::new("durable");
    let db = temp.db();
    {
        let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
        let mut log = store.security_audit_log();
        let first = log
            .append(&audit_event(1))
            .unwrap_or_else(|error| panic!("append first: {error}"));
        let second = log
            .append(&audit_event(2))
            .unwrap_or_else(|error| panic!("append second: {error}"));
        assert_eq!(first.event_count, 1);
        assert_eq!(second.event_count, 2);
        assert_ne!(first.head_digest, second.head_digest);
        assert_eq!(
            log.head().unwrap_or_else(|error| panic!("head: {error}")),
            second
        );
        assert_eq!(
            log.verify_chain()
                .unwrap_or_else(|error| panic!("verify: {error}")),
            second
        );
        log.verify_prefix(&first)
            .unwrap_or_else(|error| panic!("first head remains prefix: {error}"));
        log.verify_prefix(&second)
            .unwrap_or_else(|error| panic!("second head remains prefix: {error}"));
    }

    let mut reopened = StateStore::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
    reopened
        .recovery_integrity_check()
        .unwrap_or_else(|error| panic!("SQLite integrity: {error}"));
    let durable = reopened
        .security_audit_log()
        .verify_chain()
        .unwrap_or_else(|error| panic!("verify reopened: {error}"));
    assert_eq!(durable.event_count, 2);
}

#[test]
fn audit_budget_recovery_checkpoint_head_must_remain_an_exact_prefix() {
    let temp = TestDir::new("prefix");
    let db = temp.db();
    let checkpoint_head = {
        let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
        let mut log = store.security_audit_log();
        log.append(&audit_event(1))
            .unwrap_or_else(|error| panic!("append 1: {error}"));
        let head = log
            .append(&audit_event(2))
            .unwrap_or_else(|error| panic!("append 2: {error}"));
        log.append(&audit_event(3))
            .unwrap_or_else(|error| panic!("append 3: {error}"));
        log.verify_prefix(&head)
            .unwrap_or_else(|error| panic!("live prefix: {error}"));
        head
    };

    let connection = Connection::open(&db).unwrap_or_else(|error| panic!("raw open: {error}"));
    connection
        .execute_batch(
            "DROP TRIGGER security_audit_events_no_update;\
             UPDATE security_audit_events SET event_digest='sha256:forked' WHERE sequence=2;",
        )
        .unwrap_or_else(|error| panic!("fork checkpoint prefix: {error}"));
    drop(connection);

    let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
    assert!(
        store
            .security_audit_log()
            .verify_prefix(&checkpoint_head)
            .is_err()
    );
}

#[test]
fn audit_budget_recovery_detects_mutation_reorder_and_missing_tail() {
    let mutated = TestDir::new("mutation");
    append_events(&mutated.db(), 3);
    {
        let connection = Connection::open(mutated.db())
            .unwrap_or_else(|error| panic!("open mutation db: {error}"));
        connection
            .execute_batch(
                "DROP TRIGGER security_audit_events_no_update;\
                 UPDATE security_audit_events SET policy_digest='sha256:tampered' WHERE sequence=2;",
            )
            .unwrap_or_else(|error| panic!("mutate audit row: {error}"));
    }
    let mut store =
        StateStore::open(mutated.db()).unwrap_or_else(|error| panic!("reopen mutation: {error}"));
    assert!(store.security_audit_log().verify_chain().is_err());

    let reordered = TestDir::new("reorder");
    append_events(&reordered.db(), 3);
    {
        let connection = Connection::open(reordered.db())
            .unwrap_or_else(|error| panic!("open reorder db: {error}"));
        connection
            .execute_batch(
                "DROP TRIGGER security_audit_events_no_update;\
                 UPDATE security_audit_events SET sequence=-sequence WHERE sequence IN (1, 2);\
                 UPDATE security_audit_events SET sequence=CASE sequence WHEN -1 THEN 2 WHEN -2 THEN 1 END WHERE sequence IN (-1, -2);",
            )
            .unwrap_or_else(|error| panic!("reorder audit rows: {error}"));
    }
    let mut store =
        StateStore::open(reordered.db()).unwrap_or_else(|error| panic!("reopen reorder: {error}"));
    assert!(store.security_audit_log().verify_chain().is_err());

    let truncated = TestDir::new("missing-tail");
    append_events(&truncated.db(), 3);
    {
        let connection = Connection::open(truncated.db())
            .unwrap_or_else(|error| panic!("open truncated db: {error}"));
        connection
            .execute_batch(
                "DROP TRIGGER security_audit_events_no_delete;\
                 DELETE FROM security_audit_events WHERE sequence=3;",
            )
            .unwrap_or_else(|error| panic!("delete audit tail: {error}"));
    }
    let mut store = StateStore::open(truncated.db())
        .unwrap_or_else(|error| panic!("reopen truncated: {error}"));
    assert!(store.security_audit_log().verify_chain().is_err());
}

#[test]
fn audit_budget_recovery_v6_database_upgrades_to_v7_without_losing_state() {
    let temp = TestDir::new("v6-upgrade");
    let db = temp.db();
    let mut connection =
        Connection::open(&db).unwrap_or_else(|error| panic!("open raw v6: {error}"));
    MigrationRunner::apply(&mut connection, &MIGRATIONS[..6])
        .unwrap_or_else(|error| panic!("apply v6: {error}"));
    connection
        .execute(
            "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) \
             VALUES ('compat', 'v6-kept', '{\"v\":6}', 1, 1)",
            [],
        )
        .unwrap_or_else(|error| panic!("seed v6: {error}"));
    drop(connection);

    let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("upgrade: {error}"));
    assert_eq!(store.schema_version().unwrap_or(-1), CURRENT_SCHEMA_VERSION);
    assert_eq!(
        store.get_state("compat", "v6-kept").unwrap_or_default(),
        Some("{\"v\":6}".to_owned())
    );
    let head = store
        .security_audit_log()
        .verify_chain()
        .unwrap_or_else(|error| panic!("verify empty v7 chain: {error}"));
    assert_eq!(head.event_count, 0);
    assert_eq!(
        head.head_digest,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );
}

#[test]
fn audit_budget_recovery_v7_manifest_matches_runtime_migration() {
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
    let manifest_v7 = migrations
        .iter()
        .filter(|entry| entry["version"].as_i64() == Some(7))
        .collect::<Vec<_>>();
    assert_eq!(manifest_v7.len(), 1);
    assert_eq!(
        manifest_v7[0]["path"].as_str(),
        Some("0007_security_audit.sql")
    );
    assert_eq!(
        MIGRATIONS
            .iter()
            .filter(|migration| migration.version == 7)
            .count(),
        1
    );
}
