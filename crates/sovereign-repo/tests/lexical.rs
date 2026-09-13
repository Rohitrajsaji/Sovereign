use sovereign_repo::{
    IndexConfig, LexicalQuery, LexicalRetriever, ProjectRegistry, RepositoryIntelligence,
    ResourceHealthLevel,
};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestRepo(PathBuf);

impl TestRepo {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "sovereign-repo-lexical-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("src")).unwrap_or_else(|error| panic!("mkdir: {error}"));
        git(&path, &["init", "-q"]);
        fs::write(
            path.join("src/lib.rs"),
            "pub fn alpha() -> &'static str { \"indexed needle\" }\n",
        )
        .unwrap_or_else(|error| panic!("write lib: {error}"));
        fs::write(path.join("README.md"), "documentation needle\n")
            .unwrap_or_else(|error| panic!("write readme: {error}"));
        git(&path, &["add", "."]);
        git(&path, &["commit", "-q", "-m", "fixture"]);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn db_path(&self) -> PathBuf {
        self.0.with_extension("fts.sqlite3")
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let db = self.db_path();
        let _ = fs::remove_file(&db);
        let _ = fs::remove_file(format!("{}-wal", db.display()));
        let _ = fs::remove_file(format!("{}-shm", db.display()));
    }
}

fn git(root: &Path, args: &[&str]) {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let status = Command::new("git")
        .current_dir(root)
        .env_clear()
        .env("PATH", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Sovereign Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@sovereign.invalid")
        .env("GIT_COMMITTER_NAME", "Sovereign Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@sovereign.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(status.success());
}

fn registry(repo: &TestRepo) -> ProjectRegistry {
    let mut registry = ProjectRegistry::new();
    registry
        .register("repo.fixture", repo.path())
        .unwrap_or_else(|error| panic!("register: {error}"));
    registry
}

fn retriever<'a>(
    registry: &'a ProjectRegistry,
    repo: &TestRepo,
    config: IndexConfig,
) -> LexicalRetriever<'a> {
    LexicalRetriever::open(registry, "repo.fixture", repo.db_path(), config)
        .unwrap_or_else(|error| panic!("open lexical: {error}"))
}

#[test]
fn lexical_incremental_refresh_indexes_dirty_worktree_and_removes_deleted_files() {
    let repo = TestRepo::new("incremental");
    let registry = registry(&repo);
    let mut lexical = retriever(&registry, &repo, IndexConfig::default());
    let first = lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("rebuild: {error}"));
    assert_eq!(first.snapshot.indexed_files, 2);

    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn alpha(){ /* dirty kiwi */ }\n",
    )
    .unwrap_or_else(|error| panic!("edit: {error}"));
    fs::write(repo.path().join("new.rs"), "pub fn fresh(){ /* kiwi */ }\n")
        .unwrap_or_else(|error| panic!("new: {error}"));
    fs::remove_file(repo.path().join("README.md"))
        .unwrap_or_else(|error| panic!("remove: {error}"));

    let report = lexical
        .refresh()
        .unwrap_or_else(|error| panic!("refresh: {error}"));
    assert_eq!(report.changed_files, 2);
    assert_eq!(report.deleted_files, 1);
    assert!(report.invalidated_rows >= 2);
    let hits = lexical
        .search(&LexicalQuery {
            text: "kiwi",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("search: {error}"));
    assert_eq!(hits.len(), 2);
    assert!(
        hits.iter()
            .all(|hit| hit.source_digest.starts_with("sha256:"))
    );
    assert!(
        hits.iter()
            .all(|hit| hit.relative_path != PathBuf::from("README.md"))
    );
}

#[test]
fn lexical_stale_hit_is_rejected_and_exact_source_is_refreshed_before_return() {
    let repo = TestRepo::new("stale");
    let registry = registry(&repo);
    let mut lexical = retriever(&registry, &repo, IndexConfig::default());
    lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("rebuild: {error}"));
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn alpha() -> &'static str { \"replacement mango\" }\n",
    )
    .unwrap_or_else(|error| panic!("edit: {error}"));

    let stale_term = lexical
        .search(&LexicalQuery {
            text: "indexed",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("stale search: {error}"));
    assert!(stale_term.is_empty());
    let fresh = lexical
        .search(&LexicalQuery {
            text: "mango",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("fresh search: {error}"));
    assert_eq!(fresh.len(), 1);
    let current =
        fs::read(repo.path().join("src/lib.rs")).unwrap_or_else(|error| panic!("read: {error}"));
    let expected = sha256(&current);
    assert_eq!(fresh[0].source_digest, expected);
}

#[test]
fn lexical_first_query_for_new_term_refreshes_git_invisible_ignored_source() {
    let repo = TestRepo::new("ignored-first-query");
    fs::write(repo.path().join(".gitignore"), "ignored.rs\n")
        .unwrap_or_else(|error| panic!("write gitignore: {error}"));
    git(repo.path(), &["add", ".gitignore"]);
    git(repo.path(), &["commit", "-q", "-m", "ignore fixture"]);

    let registry = registry(&repo);
    let mut lexical = retriever(&registry, &repo, IndexConfig::default());
    lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("rebuild: {error}"));
    let before = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("before snapshot: {error}"));

    fs::write(
        repo.path().join("ignored.rs"),
        "pub fn invisible() { /* newlyintroducedterm */ }\n",
    )
    .unwrap_or_else(|error| panic!("write ignored source: {error}"));
    let after = registry
        .snapshot("repo.fixture")
        .unwrap_or_else(|error| panic!("after snapshot: {error}"));
    assert_eq!(before.head, after.head);
    assert_eq!(before.branch, after.branch);
    assert_eq!(before.dirty_digest, after.dirty_digest);

    let hits = lexical
        .search(&LexicalQuery {
            text: "newlyintroducedterm",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("first search: {error}"));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].relative_path, PathBuf::from("ignored.rs"));
    assert!(hits[0].source_digest.starts_with("sha256:"));
}

#[test]
fn lexical_large_file_chunking_respects_per_chunk_and_per_file_caps() {
    let repo = TestRepo::new("chunk-cap");
    let mut giant = String::new();
    for index in 0..200 {
        writeln!(
            giant,
            "fn symbol_{index}() {{ /* repeated searchabletoken */ }}"
        )
        .unwrap_or_else(|error| panic!("format giant fixture: {error}"));
    }
    fs::write(repo.path().join("src/giant.rs"), giant)
        .unwrap_or_else(|error| panic!("giant: {error}"));
    let registry = registry(&repo);
    let config = IndexConfig {
        max_chunk_bytes: 128,
        max_chunks_per_file: 3,
        ..IndexConfig::default()
    };
    let mut lexical = retriever(&registry, &repo, config);
    lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("rebuild: {error}"));
    let hits = lexical
        .search(&LexicalQuery {
            text: "searchabletoken",
            max_hits: 20,
        })
        .unwrap_or_else(|error| panic!("search: {error}"));
    let giant_hits: Vec<_> = hits
        .iter()
        .filter(|hit| hit.relative_path == PathBuf::from("src/giant.rs"))
        .collect();
    assert!(giant_hits.len() <= 3);
    assert!(giant_hits.iter().all(|hit| hit.content.len() <= 128));
}

#[test]
fn lexical_snapshot_publishes_only_after_delta_rows_are_invalidated() {
    let repo = TestRepo::new("publish-order");
    let registry = registry(&repo);
    let mut lexical = retriever(&registry, &repo, IndexConfig::default());
    let first = lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("rebuild: {error}"));
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn beta(){ /* cobalt */ }\n",
    )
    .unwrap_or_else(|error| panic!("edit: {error}"));
    let second = lexical
        .refresh()
        .unwrap_or_else(|error| panic!("refresh: {error}"));
    assert!(second.invalidated_rows > 0);
    assert!(second.snapshot.generation > first.snapshot.generation);
    let old = lexical
        .search(&LexicalQuery {
            text: "indexed",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("old search: {error}"));
    assert!(old.is_empty());
    let current_snapshot = lexical
        .snapshot()
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    assert_eq!(current_snapshot, Some(second.snapshot));
}

#[test]
fn lexical_rebuild_is_derived_and_reproducible_from_source() {
    let repo = TestRepo::new("rebuildable");
    let registry = registry(&repo);
    let mut lexical = retriever(&registry, &repo, IndexConfig::default());
    let first = lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("first: {error}"));
    let first_hits = lexical
        .search(&LexicalQuery {
            text: "needle",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("first search: {error}"));
    let second = lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("second: {error}"));
    let second_hits = lexical
        .search(&LexicalQuery {
            text: "needle",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("second search: {error}"));
    assert_eq!(
        first.snapshot.source_manifest_digest,
        second.snapshot.source_manifest_digest
    );
    assert_eq!(first_hits, second_hits);
}

#[test]
fn lexical_incompatible_schema_drops_old_layout_and_rebuilds_from_source() {
    let repo = TestRepo::new("schema-rebuild");
    let registry = registry(&repo);
    let connection = rusqlite::Connection::open(repo.db_path())
        .unwrap_or_else(|error| panic!("open index db: {error}"));
    connection
        .execute_batch(
            "CREATE TABLE metadata(key TEXT PRIMARY KEY, value_int INTEGER, snapshot_json TEXT);
             INSERT INTO metadata(key, value_int) VALUES('schema_version', 0);
             CREATE TABLE files(legacy_path TEXT PRIMARY KEY, legacy_hash TEXT);
             INSERT INTO files VALUES('legacy.rs', 'old');
             CREATE TABLE chunks(legacy_id INTEGER PRIMARY KEY, body TEXT);
             INSERT INTO chunks(body) VALUES('legacyterm');
             CREATE INDEX chunks_path_idx ON chunks(body);
             CREATE VIRTUAL TABLE chunks_fts USING fts5(body);
             INSERT INTO chunks_fts(body) VALUES('legacyterm');",
        )
        .unwrap_or_else(|error| panic!("create legacy schema: {error}"));
    drop(connection);

    let mut reopened = retriever(&registry, &repo, IndexConfig::default());
    assert_eq!(
        reopened
            .snapshot()
            .unwrap_or_else(|error| panic!("snapshot after reopen: {error}")),
        None
    );
    let rebuilt_hits = reopened
        .search(&LexicalQuery {
            text: "needle",
            max_hits: 8,
        })
        .unwrap_or_else(|error| panic!("search after rebuild: {error}"));
    assert_eq!(rebuilt_hits.len(), 2);
    assert!(
        reopened
            .snapshot()
            .unwrap_or_else(|error| panic!("rebuilt snapshot: {error}"))
            .is_some()
    );
}

#[test]
fn lexical_resource_policy_and_medium_large_calibration_are_explicit_and_bounded() {
    let repo = TestRepo::new("calibration");
    let payload = "calibration lexical corpus payload ".repeat(1024);
    for index in 0..256 {
        fs::write(
            repo.path().join("src").join(format!("fixture_{index}.rs")),
            format!("pub fn fixture_{index}() {{ /* {payload} */ }}\n"),
        )
        .unwrap_or_else(|error| panic!("fixture write: {error}"));
    }
    let registry = registry(&repo);
    let config = IndexConfig {
        batch_files: 16,
        page_cache_kib: 2 * 1024,
        ..IndexConfig::default()
    };
    let mut lexical = retriever(&registry, &repo, config.clone());
    let report = lexical
        .rebuild()
        .unwrap_or_else(|error| panic!("rebuild: {error}"));
    assert!(report.calibration.source_bytes > 8 * 1024 * 1024);
    assert!(report.calibration.index_bytes > 0);
    assert!(report.calibration.wall_time_micros > 0);
    assert!(report.calibration.cpu_time_micros.is_some());
    assert!(report.calibration.peak_process_rss_bytes.is_some());
    assert!(report.calibration.peak_batch_source_bytes > 0);
    assert_eq!(report.calibration.batch_file_limit, 16);
    assert_eq!(report.calibration.page_cache_kib, 2 * 1024);
    assert_eq!(report.resource_health.level, ResourceHealthLevel::Healthy);
    assert!(report.resource_health.page_cache_kib <= 8 * 1024);
    assert!(report.resource_health.process_fts_cache_reserved_kib <= 16 * 1024);
    assert_eq!(
        report.resource_health.sqlite_aggregate_cache_target_kib,
        32 * 1024
    );
    assert_eq!(
        report.resource_health.sqlite_aggregate_cache_hard_limit_kib,
        64 * 1024
    );
    assert_eq!(
        report.resource_health.sqlite_hard_headroom_after_fts_kib,
        48 * 1024
    );
    assert_eq!(report.resource_health.mmap_size_bytes, 0);
    assert!(report.resource_health.wal_autocheckpoint_pages > 0);
    assert!(report.resource_health.event.is_none());

    let connection = rusqlite::Connection::open(repo.db_path())
        .unwrap_or_else(|error| panic!("open calibration index db: {error}"));
    let page_size_bytes: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("read SQLite page size: {error}"));
    let wal_soft_checkpoint_bytes =
        page_size_bytes.saturating_mul(report.resource_health.wal_autocheckpoint_pages);
    assert_eq!(wal_soft_checkpoint_bytes, 64 * 1024 * 1024);

    println!(
        "M2_T01_CALIBRATION={} source_manifest_digest={} page_size_bytes={} wal_soft_checkpoint_bytes={}",
        serde_json::to_string(&report.calibration)
            .unwrap_or_else(|error| panic!("serialize calibration: {error}")),
        report.snapshot.source_manifest_digest,
        page_size_bytes,
        wal_soft_checkpoint_bytes
    );
    println!(
        "M2_T01_RESOURCE_HEALTH={}",
        serde_json::to_string(&report.resource_health)
            .unwrap_or_else(|error| panic!("serialize resource health: {error}"))
    );

    fs::write(
        repo.path().join("src/fixture_0.rs"),
        "pub fn fixture_0() { /* calibration incremental refresh delta */ }\n",
    )
    .unwrap_or_else(|error| panic!("incremental fixture edit: {error}"));
    let incremental = lexical
        .refresh()
        .unwrap_or_else(|error| panic!("incremental refresh: {error}"));
    assert_eq!(incremental.changed_files, 1);
    assert_eq!(incremental.deleted_files, 0);
    assert!(incremental.calibration.wall_time_micros > 0);
    assert!(incremental.calibration.cpu_time_micros.is_some());
    assert!(incremental.calibration.peak_process_rss_bytes.is_some());
    println!(
        "M2_T01_INCREMENTAL_CALIBRATION={} source_manifest_digest={}",
        serde_json::to_string(&incremental.calibration)
            .unwrap_or_else(|error| panic!("serialize incremental calibration: {error}")),
        incremental.snapshot.source_manifest_digest
    );
}

#[test]
fn lexical_multiple_connections_keep_fts_process_cache_bounded() {
    let repo = TestRepo::new("multi-cache");
    let registry = registry(&repo);
    let config = IndexConfig {
        page_cache_kib: 2 * 1024,
        ..IndexConfig::default()
    };
    let first = retriever(&registry, &repo, config.clone());
    let second = retriever(&registry, &repo, config);
    let first_health = first
        .resource_health()
        .unwrap_or_else(|error| panic!("first health: {error}"));
    let second_health = second
        .resource_health()
        .unwrap_or_else(|error| panic!("second health: {error}"));
    assert!(first_health.process_fts_cache_reserved_kib >= 4 * 1024);
    assert!(second_health.process_fts_cache_reserved_kib <= 16 * 1024);
    assert_eq!(second_health.process_fts_cache_hard_limit_kib, 16 * 1024);
    assert_eq!(second_health.page_cache_hard_limit_kib, 8 * 1024);

    let too_large = IndexConfig {
        page_cache_kib: 8 * 1024 + 1,
        ..IndexConfig::default()
    };
    assert!(LexicalRetriever::open(&registry, "repo.fixture", repo.db_path(), too_large).is_err());
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}
