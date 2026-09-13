use rusqlite::Connection;
use sovereign_memory::{
    MemoryKind, MemoryLifecycle, MemoryManager, MemoryProvenance, MemoryQuery, MemoryRetriever,
    MemoryScope, MemoryScopeKind, MemoryTrust, NewMemoryRecord,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const NOW: i64 = 1_800_000_000_000;
const CRASH_CHILD_DB_ENV: &str = "SOVEREIGN_PROJECTION_CRASH_CHILD_DB";
const CREATE_FTS_SQL: &str = "CREATE VIRTUAL TABLE memory_fts_projection USING fts5(\
    memory_id UNINDEXED, project_id UNINDEXED, repository_id UNINDEXED, kind UNINDEXED, \
    trust UNINDEXED, status UNINDEXED, conflict_key, subject, predicate, assertion, tokenize = 'unicode61'\
)";

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-memory-projection-{label}-{}-{nonce}",
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

fn record(id: &str, assertion: &str) -> NewMemoryRecord {
    NewMemoryRecord {
        id: id.to_owned(),
        kind: MemoryKind::Episodic,
        scope: MemoryScope {
            project_id: "project-a".to_owned(),
            repository_id: None,
            kind: MemoryScopeKind::Project,
            agent_id: None,
            role_visibility: Vec::new(),
        },
        subject: format!("subject-{id}"),
        predicate: "fact".to_owned(),
        conflict_key: format!("subject-{id}\u{1f}fact"),
        assertion: assertion.to_owned(),
        trust: MemoryTrust::Observed,
        confidence: 90,
        provenance: MemoryProvenance {
            source_evidence_ids: vec![format!("evidence.{id}")],
            producing_task_id: Some("task.fixture".to_owned()),
            producing_attempt_id: Some("attempt.fixture".to_owned()),
            repository_revision: None,
            source_fingerprints: Vec::new(),
        },
        expires_at_ms: None,
        invalidation_predicates: Vec::new(),
    }
}

fn projection_count(db: &Path, memory_id: &str) -> i64 {
    let connection = Connection::open(db).unwrap_or_else(|error| panic!("open observer: {error}"));
    connection
        .query_row(
            "SELECT COUNT(*) FROM memory_fts_projection WHERE memory_id=?1",
            [memory_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("projection count: {error}"))
}

fn enqueue_refresh(db: &Path, memory_id: &str, at_ms: i64) {
    let connection = Connection::open(db).unwrap_or_else(|error| panic!("open enqueue: {error}"));
    connection
        .execute(
            "INSERT INTO memory_projection_outbox(\
                 schema_version, projection_kind, memory_id, canonical_updated_at_ms, enqueued_at_ms\
             ) VALUES (1, 'memory_fts_v1', ?1, ?2, ?2) \
             ON CONFLICT(projection_kind, memory_id) DO UPDATE SET \
                 canonical_updated_at_ms=excluded.canonical_updated_at_ms, \
                 enqueued_at_ms=excluded.enqueued_at_ms",
            rusqlite::params![memory_id, at_ms],
        )
        .unwrap_or_else(|error| panic!("enqueue refresh: {error}"));
}

fn recreate_projection_table(db: &Path) {
    let connection =
        Connection::open(db).unwrap_or_else(|error| panic!("open projection repair: {error}"));
    connection
        .execute(CREATE_FTS_SQL, [])
        .unwrap_or_else(|error| panic!("recreate projection table: {error}"));
}

#[test]
fn projection_crash_child_capture() {
    let Some(db) = std::env::var_os(CRASH_CHILD_DB_ENV) else {
        return;
    };
    let db = PathBuf::from(db);
    let mut manager =
        MemoryManager::open(&db).unwrap_or_else(|error| panic!("child open: {error}"));
    let observer =
        Connection::open(&db).unwrap_or_else(|error| panic!("child observer open: {error}"));
    observer
        .execute("DROP TABLE memory_fts_projection", [])
        .unwrap_or_else(|error| panic!("drop derived projection: {error}"));
    drop(observer);
    let Err(error) = manager.capture(record("mem.crash", "crashmarker canonical survives"), NOW)
    else {
        panic!("projection failure must surface after canonical commit");
    };
    assert!(
        error.to_string().contains("canonical memory committed"),
        "post-commit failure must not imply canonical rollback: {error}"
    );
    std::process::abort();
}

#[test]
fn projection_canonical_survives_forced_kill_then_startup_replay() {
    let temp = TestDir::new("crash-replay");
    {
        let _manager =
            MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("prime open: {error}"));
    }

    let test_binary =
        std::env::current_exe().unwrap_or_else(|error| panic!("current exe: {error}"));
    let status = Command::new(test_binary)
        .arg("--exact")
        .arg("projection_crash_child_capture")
        .arg("--nocapture")
        .env(CRASH_CHILD_DB_ENV, temp.db())
        .env("RUST_BACKTRACE", "0")
        .status()
        .unwrap_or_else(|error| panic!("spawn crash child: {error}"));
    assert!(!status.success(), "child must terminate at the crash seam");

    let observer =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("open crash observer: {error}"));
    let canonical: i64 = observer
        .query_row(
            "SELECT COUNT(*) FROM memory_records WHERE memory_id='mem.crash'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    let queued: i64 = observer
        .query_row(
            "SELECT COUNT(*) FROM memory_projection_outbox WHERE memory_id='mem.crash'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    let projection_table: i64 = observer
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_fts_projection'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    assert_eq!(canonical, 1, "canonical transaction must survive the crash");
    assert_eq!(
        queued, 1,
        "refresh intent must commit with canonical memory"
    );
    assert_eq!(projection_table, 0, "derived projection was unavailable");
    drop(observer);

    recreate_projection_table(&temp.db());
    let mut manager = MemoryManager::open(temp.db())
        .unwrap_or_else(|error| panic!("reopen after crash: {error}"));
    assert!(manager.projection_outbox().unwrap_or_default().is_empty());
    let mut retriever = MemoryRetriever::new(&mut manager);
    let result = retriever
        .retrieve(&MemoryQuery::ordinary("project-a", "crashmarker"), NOW + 1)
        .unwrap_or_else(|error| panic!("retrieve after replay: {error}"));
    assert_eq!(result.synopses.len(), 1);
    assert_eq!(result.synopses[0].memory_id, "mem.crash");
}

#[test]
fn projection_duplicate_delivery_is_idempotent() {
    let temp = TestDir::new("duplicate-delivery");
    {
        let mut manager =
            MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
        manager
            .capture(record("mem.duplicate", "duplicate marker"), NOW)
            .unwrap_or_else(|error| panic!("capture: {error}"));
    }
    assert_eq!(projection_count(&temp.db(), "mem.duplicate"), 1);

    enqueue_refresh(&temp.db(), "mem.duplicate", NOW + 1);
    enqueue_refresh(&temp.db(), "mem.duplicate", NOW + 2);
    {
        let mut manager =
            MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("replay one: {error}"));
        assert!(manager.projection_outbox().unwrap_or_default().is_empty());
        assert_eq!(manager.drain_projection_outbox().unwrap_or(usize::MAX), 0);
    }
    assert_eq!(projection_count(&temp.db(), "mem.duplicate"), 1);

    enqueue_refresh(&temp.db(), "mem.duplicate", NOW + 3);
    let _manager =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("replay two: {error}"));
    assert_eq!(projection_count(&temp.db(), "mem.duplicate"), 1);
}

#[test]
fn projection_damaged_missing_orphan_fts_rebuilds_from_canonical() {
    let temp = TestDir::new("repair");
    {
        let mut manager =
            MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
        manager
            .capture(record("mem.a", "alpha canonical"), NOW)
            .unwrap_or_else(|error| panic!("capture a: {error}"));
        manager
            .capture(record("mem.b", "beta canonical"), NOW + 1)
            .unwrap_or_else(|error| panic!("capture b: {error}"));
    }

    let connection =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("open corruptor: {error}"));
    connection
        .execute(
            "DELETE FROM memory_fts_projection WHERE memory_id IN ('mem.a', 'mem.b')",
            [],
        )
        .unwrap_or_else(|error| panic!("delete projections: {error}"));
    connection
        .execute(
            "INSERT INTO memory_fts_projection(\
                 memory_id, project_id, repository_id, kind, trust, status, conflict_key, subject, predicate, assertion\
             ) VALUES (\
                 'mem.a', 'project-a', '', 'episodic', 'observed', 'active', 'wrong', 'wrong', 'fact', 'corrupted'\
             )",
            [],
        )
        .unwrap_or_else(|error| panic!("insert mismatch: {error}"));
    connection
        .execute(
            "INSERT INTO memory_fts_projection(\
                 memory_id, project_id, repository_id, kind, trust, status, conflict_key, subject, predicate, assertion\
             ) VALUES (\
                 'mem.orphan', 'project-a', '', 'episodic', 'observed', 'active', 'orphan', 'orphan', 'fact', 'orphan'\
             )",
            [],
        )
        .unwrap_or_else(|error| panic!("insert orphan: {error}"));
    drop(connection);

    let mut manager =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("repairing reopen: {error}"));
    assert!(manager.projection_repairs().unwrap_or_default().is_empty());
    let repair = manager
        .repair_projection("test_detected_projection_corruption")
        .unwrap_or_else(|error| panic!("repair projection: {error}"))
        .unwrap_or_else(|| panic!("explicit mismatch repair must create a repair record"));
    assert_eq!(repair.state, "completed");
    assert!(repair.mismatch_count > 0);
    assert!(repair.completed_at_ms.is_some());
    assert!(manager.projection_outbox().unwrap_or_default().is_empty());
    drop(manager);

    let observer = Connection::open(temp.db())
        .unwrap_or_else(|error| panic!("open repaired observer: {error}"));
    let canonical_rows: i64 = observer
        .query_row("SELECT COUNT(*) FROM memory_records", [], |row| row.get(0))
        .unwrap_or(-1);
    let projection_rows: i64 = observer
        .query_row("SELECT COUNT(*) FROM memory_fts_projection", [], |row| {
            row.get(0)
        })
        .unwrap_or(-1);
    let orphan_rows: i64 = observer
        .query_row(
            "SELECT COUNT(*) FROM memory_fts_projection WHERE memory_id='mem.orphan'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    let alpha_assertion: String = observer
        .query_row(
            "SELECT assertion FROM memory_fts_projection WHERE memory_id='mem.a'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_default();
    assert_eq!(projection_rows, canonical_rows);
    assert_eq!(orphan_rows, 0);
    assert_eq!(alpha_assertion, "alpha canonical");
}

#[test]
fn projection_pending_repair_is_resumed_instead_of_duplicated() {
    let temp = TestDir::new("pending-repair-resume");
    let mut manager =
        MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
    manager
        .capture(record("mem.pending", "pending repair marker"), NOW)
        .unwrap_or_else(|error| panic!("capture: {error}"));

    let connection =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("open repair seeder: {error}"));
    connection
        .execute(
            "INSERT INTO memory_projection_repairs(\
                 schema_version, repair_id, projection_kind, reason, state, canonical_row_count, \
                 projection_row_count, mismatch_count, detected_at_ms, completed_at_ms\
             ) VALUES (1, 'repair.pending', 'memory_fts_v1', 'interrupted-r1', 'pending', 1, 0, 1, ?1, NULL)",
            [NOW + 1],
        )
        .unwrap_or_else(|error| panic!("seed pending repair: {error}"));
    drop(connection);

    let repair = manager
        .repair_projection("retry-after-r2-failure")
        .unwrap_or_else(|error| panic!("resume pending repair: {error}"))
        .unwrap_or_else(|| panic!("pending repair must be resumed"));
    assert_eq!(repair.repair_id, "repair.pending");
    assert_eq!(repair.state, "completed");
    let repairs = manager.projection_repairs().unwrap_or_default();
    assert_eq!(
        repairs.len(),
        1,
        "retry must not create a second pending repair"
    );
}

#[test]
fn projection_missing_canonical_outbox_reference_fails_closed_and_is_retained() {
    let temp = TestDir::new("missing-canonical");
    {
        let _manager =
            MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("prime open: {error}"));
    }
    let connection =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("open corruptor: {error}"));
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap_or_else(|error| panic!("disable FK only for corruption fixture: {error}"));
    connection
        .execute(
            "INSERT INTO memory_projection_outbox(\
                 schema_version, projection_kind, memory_id, canonical_updated_at_ms, enqueued_at_ms\
             ) VALUES (1, 'memory_fts_v1', 'mem.missing', ?1, ?1)",
            [NOW],
        )
        .unwrap_or_else(|error| panic!("seed corrupt outbox: {error}"));
    drop(connection);

    let Err(error) = MemoryManager::open(temp.db()) else {
        panic!("missing canonical row must fail closed");
    };
    assert!(
        error
            .to_string()
            .contains("missing canonical memory mem.missing"),
        "unexpected fail-closed error: {error}"
    );
    let observer = Connection::open(temp.db())
        .unwrap_or_else(|error| panic!("open retained observer: {error}"));
    let retained: i64 = observer
        .query_row(
            "SELECT COUNT(*) FROM memory_projection_outbox WHERE memory_id='mem.missing'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    assert_eq!(retained, 1, "corrupt refresh evidence must not be consumed");
}

#[test]
fn projection_status_refresh_reflects_latest_canonical_state() {
    let temp = TestDir::new("status-refresh");
    {
        let mut manager =
            MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
        manager
            .capture(record("mem.status", "status marker"), NOW)
            .unwrap_or_else(|error| panic!("capture: {error}"));
        manager
            .deprecate("mem.status", NOW + 1)
            .unwrap_or_else(|error| panic!("deprecate: {error}"));
    }
    let observer =
        Connection::open(temp.db()).unwrap_or_else(|error| panic!("open observer: {error}"));
    let projected_status: String = observer
        .query_row(
            "SELECT status FROM memory_fts_projection WHERE memory_id='mem.status'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_default();
    assert_eq!(projected_status, "deprecated");
}

#[test]
fn projection_no_fallback_db_or_store() {
    let temp = TestDir::new("single-store");
    {
        let mut manager =
            MemoryManager::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
        manager
            .capture(record("mem.single", "single store marker"), NOW)
            .unwrap_or_else(|error| panic!("capture: {error}"));
    }
    let entries = fs::read_dir(&temp.0)
        .unwrap_or_else(|error| panic!("read test dir: {error}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("dir entry: {error}"))
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert!(!entries.is_empty());
    assert!(
        entries.iter().all(|name| name.starts_with("state.sqlite3")),
        "memory projection must not create a fallback database/store: {entries:?}"
    );
}
