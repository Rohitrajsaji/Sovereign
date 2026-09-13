use crate::{
    ProjectRegistry, RepoError, RepositoryIntelligence, collect_regular_files, sha256_prefixed,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

const INDEX_SCHEMA_VERSION: i64 = 1;
const DEFAULT_MAX_FILES: usize = 50_000;
const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_MAX_CHUNK_BYTES: usize = 8 * 1024;
const DEFAULT_MAX_CHUNKS_PER_FILE: usize = 256;
const DEFAULT_BATCH_FILES: usize = 64;
const DEFAULT_PAGE_CACHE_KIB: i64 = 1024;
const FTS_CONNECTION_CACHE_HARD_KIB: i64 = 8 * 1024;
const FTS_PROCESS_CACHE_HARD_KIB: i64 = 16 * 1024;
const SQLITE_AGGREGATE_CACHE_TARGET_KIB: i64 = 32 * 1024;
const SQLITE_AGGREGATE_CACHE_HARD_KIB: i64 = 64 * 1024;
const DEFAULT_WAL_AUTOCHECKPOINT_PAGES: i64 = 16_384;
const WAL_HEALTH_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SEARCH_REFRESHES: usize = 2;

static FTS_PROCESS_CACHE_RESERVED_KIB: AtomicI64 = AtomicI64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexConfig {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_chunk_bytes: usize,
    pub max_chunks_per_file: usize,
    pub batch_files: usize,
    pub page_cache_kib: i64,
    pub wal_autocheckpoint_pages: i64,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            max_chunks_per_file: DEFAULT_MAX_CHUNKS_PER_FILE,
            batch_files: DEFAULT_BATCH_FILES,
            page_cache_kib: DEFAULT_PAGE_CACHE_KIB,
            wal_autocheckpoint_pages: DEFAULT_WAL_AUTOCHECKPOINT_PAGES,
        }
    }
}

impl IndexConfig {
    fn validate(&self) -> Result<(), RepoError> {
        if self.max_files == 0
            || self.max_file_bytes == 0
            || self.max_chunk_bytes == 0
            || self.max_chunks_per_file == 0
            || self.batch_files == 0
            || self.page_cache_kib <= 0
            || self.page_cache_kib > FTS_CONNECTION_CACHE_HARD_KIB
            || self.wal_autocheckpoint_pages <= 0
        {
            return Err(RepoError::InvalidSearch(
                "lexical index bounds/cache/WAL settings must be positive and per-connection FTS cache <=8 MiB"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexSnapshot {
    pub repository_id: String,
    pub generation: u64,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub dirty_digest: String,
    pub source_manifest_digest: String,
    pub indexed_files: usize,
    pub indexed_chunks: usize,
    pub source_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexicalHit {
    pub repository_id: String,
    pub relative_path: PathBuf,
    pub source_digest: String,
    pub chunk_ordinal: u32,
    pub start_line: u64,
    pub end_line: u64,
    pub content: String,
    pub bm25_score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalQuery<'a> {
    pub text: &'a str,
    pub max_hits: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshReport {
    pub changed_files: usize,
    pub deleted_files: usize,
    pub unchanged_files: usize,
    pub invalidated_rows: usize,
    pub indexed_chunks: usize,
    pub snapshot: IndexSnapshot,
    pub calibration: IndexCalibration,
    pub resource_health: IndexResourceHealth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexCalibration {
    pub source_bytes: u64,
    pub index_bytes: u64,
    pub wal_bytes: u64,
    pub wall_time_micros: u64,
    pub cpu_time_micros: Option<u64>,
    pub peak_process_rss_bytes: Option<u64>,
    pub peak_batch_source_bytes: u64,
    pub batch_file_limit: usize,
    pub page_cache_kib: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceHealthLevel {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexResourceHealth {
    pub level: ResourceHealthLevel,
    pub page_cache_kib: i64,
    pub page_cache_hard_limit_kib: i64,
    pub process_fts_cache_reserved_kib: i64,
    pub process_fts_cache_hard_limit_kib: i64,
    pub sqlite_aggregate_cache_target_kib: i64,
    pub sqlite_aggregate_cache_hard_limit_kib: i64,
    pub sqlite_hard_headroom_after_fts_kib: i64,
    pub mmap_size_bytes: i64,
    pub wal_autocheckpoint_pages: i64,
    pub wal_bytes: u64,
    pub event: Option<String>,
}

#[derive(Debug)]
struct FtsCacheReservation {
    kib: i64,
}

impl Drop for FtsCacheReservation {
    fn drop(&mut self) {
        FTS_PROCESS_CACHE_RESERVED_KIB.fetch_sub(self.kib, Ordering::AcqRel);
    }
}

pub struct LexicalRetriever<'a> {
    registry: &'a ProjectRegistry,
    repository_id: String,
    db_path: PathBuf,
    connection: Connection,
    config: IndexConfig,
    cache_reservation: FtsCacheReservation,
}

impl<'a> LexicalRetriever<'a> {
    /// Opens or creates a rebuildable lexical index for one registered repository.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for an unknown repository, invalid resource bounds,
    /// filesystem failures, or `SQLite` setup/schema failures.
    pub fn open(
        registry: &'a ProjectRegistry,
        repository_id: &str,
        db_path: impl AsRef<Path>,
        config: IndexConfig,
    ) -> Result<Self, RepoError> {
        config.validate()?;
        let _ = registry
            .repository(repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(repository_id.to_owned()))?;
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let cache_reservation = reserve_fts_cache(config.page_cache_kib)?;
        let connection = Connection::open(&db_path).map_err(sqlite_error)?;
        configure_connection(&connection, &config, cache_reservation.kib)?;
        prepare_schema(&connection)?;
        Ok(Self {
            registry,
            repository_id: repository_id.to_owned(),
            db_path,
            connection,
            config,
            cache_reservation,
        })
    }

    /// Discards all derived rows and rebuilds the index from current source truth.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] when source scanning, hashing, `SQLite` writes, or
    /// snapshot publication fails.
    pub fn rebuild(&mut self) -> Result<RefreshReport, RepoError> {
        let transaction = self.connection.transaction().map_err(sqlite_error)?;
        transaction
            .execute("DELETE FROM chunks_fts", [])
            .map_err(sqlite_error)?;
        transaction
            .execute("DELETE FROM chunks", [])
            .map_err(sqlite_error)?;
        transaction
            .execute("DELETE FROM files", [])
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        self.refresh()
    }

    /// Incrementally invalidates changed/deleted rows, reindexes changed files,
    /// then publishes a fresh source-fingerprint snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] when repository truth cannot be read, `SQLite` work
    /// fails, or the new snapshot cannot be published.
    pub fn refresh(&mut self) -> Result<RefreshReport, RepoError> {
        let started = Instant::now();
        let mut resource_sampler = ResourceSampler::start();
        let repository = self
            .registry
            .repository(&self.repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(self.repository_id.clone()))?;
        let exact_snapshot = self.registry.snapshot(&self.repository_id)?;
        let current = scan_sources(&repository.root, &self.config)?;
        resource_sampler.sample();
        let existing = load_manifest(&self.connection)?;

        let current_paths: BTreeSet<_> = current.keys().cloned().collect();
        let existing_paths: BTreeSet<_> = existing.keys().cloned().collect();
        let deleted: Vec<_> = existing_paths.difference(&current_paths).cloned().collect();
        let changed: Vec<_> = current
            .iter()
            .filter_map(|(path, source)| {
                (existing.get(path) != Some(&source.digest)).then_some(path.clone())
            })
            .collect();
        let unchanged_files = current.len().saturating_sub(changed.len());

        let mut invalidated_rows = 0usize;
        let mut indexed_chunks = 0usize;
        let mut peak_batch_source_bytes = 0u64;
        for batch in changed.chunks(self.config.batch_files) {
            let batch_bytes = batch.iter().fold(0u64, |total, path| {
                total.saturating_add(current.get(path).map_or(0, |source| source.byte_len))
            });
            peak_batch_source_bytes = peak_batch_source_bytes.max(batch_bytes);
            let transaction = self.connection.transaction().map_err(sqlite_error)?;
            for path in batch {
                invalidated_rows =
                    invalidated_rows.saturating_add(invalidate_path(&transaction, path)?);
                let source = current.get(path).ok_or_else(|| {
                    RepoError::InvalidSearch("changed source disappeared during refresh".to_owned())
                })?;
                indexed_chunks = indexed_chunks.saturating_add(index_source(
                    &transaction,
                    path,
                    source,
                    &self.config,
                )?);
            }
            transaction.commit().map_err(sqlite_error)?;
            resource_sampler.sample();
        }

        if !deleted.is_empty() {
            let transaction = self.connection.transaction().map_err(sqlite_error)?;
            for path in &deleted {
                invalidated_rows =
                    invalidated_rows.saturating_add(invalidate_path(&transaction, path)?);
            }
            transaction.commit().map_err(sqlite_error)?;
            resource_sampler.sample();
        }

        let indexed_chunks_total: usize = self
            .connection
            .query_row("SELECT count(*) FROM chunks", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        let source_bytes = current
            .values()
            .fold(0u64, |total, source| total.saturating_add(source.byte_len));
        let generation = next_generation(&self.connection)?;
        let manifest_digest = manifest_digest(&current);
        let snapshot = IndexSnapshot {
            repository_id: self.repository_id.clone(),
            generation,
            head: exact_snapshot.head,
            branch: exact_snapshot.branch,
            dirty_digest: exact_snapshot.dirty_digest,
            source_manifest_digest: manifest_digest,
            indexed_files: current.len(),
            indexed_chunks: indexed_chunks_total,
            source_bytes,
        };
        publish_snapshot(&self.connection, &snapshot)?;
        resource_sampler.sample();

        let (calibration, resource_health) = self.calibration(
            started,
            resource_sampler,
            source_bytes,
            peak_batch_source_bytes,
        )?;
        Ok(RefreshReport {
            changed_files: changed.len(),
            deleted_files: deleted.len(),
            unchanged_files,
            invalidated_rows,
            indexed_chunks,
            snapshot,
            calibration,
            resource_health,
        })
    }

    fn calibration(
        &self,
        started: Instant,
        mut resource_sampler: ResourceSampler,
        source_bytes: u64,
        peak_batch_source_bytes: u64,
    ) -> Result<(IndexCalibration, IndexResourceHealth), RepoError> {
        let resource_health = self.resource_health()?;
        resource_sampler.sample();
        let process_after = process_metrics();
        let calibration = IndexCalibration {
            source_bytes,
            index_bytes: file_size(&self.db_path),
            wal_bytes: resource_health.wal_bytes,
            wall_time_micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            cpu_time_micros: resource_sampler
                .started
                .cpu_time_micros
                .zip(process_after.cpu_time_micros)
                .map(|(before, after)| after.saturating_sub(before)),
            peak_process_rss_bytes: resource_sampler.peak_rss_bytes,
            peak_batch_source_bytes,
            batch_file_limit: self.config.batch_files,
            page_cache_kib: self.cache_reservation.kib,
        };
        Ok((calibration, resource_health))
    }

    /// Returns the last fully published lexical snapshot, if one exists.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for `SQLite` or snapshot-deserialization failures.
    pub fn snapshot(&self) -> Result<Option<IndexSnapshot>, RepoError> {
        self.connection
            .query_row(
                "SELECT snapshot_json FROM metadata WHERE key = 'snapshot'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .map(|json| serde_json::from_str(&json).map_err(RepoError::Serialization))
            .transpose()
    }

    /// Runs FTS5/BM25 retrieval and validates every candidate against current
    /// source hashes. Any stale source triggers a bounded incremental refresh
    /// before results are returned.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for invalid query bounds, source refresh failures,
    /// or `SQLite` query failures.
    pub fn search(&mut self, query: &LexicalQuery<'_>) -> Result<Vec<LexicalHit>, RepoError> {
        if query.text.trim().is_empty() || query.max_hits == 0 {
            return Err(RepoError::InvalidSearch(
                "lexical query text and max_hits must be non-empty/positive".to_owned(),
            ));
        }
        let repository_root = self
            .registry
            .repository(&self.repository_id)
            .ok_or_else(|| RepoError::UnknownRepository(self.repository_id.clone()))?
            .root
            .clone();
        let mut refreshes = 0usize;
        loop {
            if !self.source_manifest_is_current(&repository_root)? {
                if refreshes >= MAX_SEARCH_REFRESHES {
                    return Err(source_race_error());
                }
                self.refresh()?;
                refreshes = refreshes.saturating_add(1);
                continue;
            }

            let hits = self.raw_search(query)?;
            let hits_current = hits_match_current_source(&repository_root, &hits)?;
            let manifest_still_current = self.source_manifest_is_current(&repository_root)?;
            if hits_current && manifest_still_current {
                return Ok(hits);
            }
            if refreshes >= MAX_SEARCH_REFRESHES {
                return Err(source_race_error());
            }
            self.refresh()?;
            refreshes = refreshes.saturating_add(1);
        }
    }

    fn source_manifest_is_current(&self, repository_root: &Path) -> Result<bool, RepoError> {
        let current_sources = scan_sources(repository_root, &self.config)?;
        let published = self.snapshot()?;
        Ok(published.as_ref().is_some_and(|snapshot| {
            snapshot.source_manifest_digest == manifest_digest(&current_sources)
                && snapshot.indexed_files == current_sources.len()
        }))
    }

    /// Captures the configured/observed `SQLite` cache, mmap, and WAL footprint.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] when `SQLite` resource PRAGMAs cannot be read.
    pub fn resource_health(&self) -> Result<IndexResourceHealth, RepoError> {
        let page_cache: i64 = self
            .connection
            .query_row("PRAGMA cache_size", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        let page_cache_kib = i64::try_from(page_cache.unsigned_abs()).unwrap_or(i64::MAX);
        let mmap_size_bytes: i64 = self
            .connection
            .query_row("PRAGMA mmap_size", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        let wal_autocheckpoint_pages: i64 = self
            .connection
            .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        let wal_bytes = file_size(&PathBuf::from(format!("{}-wal", self.db_path.display())));
        let process_fts_cache_reserved_kib = FTS_PROCESS_CACHE_RESERVED_KIB.load(Ordering::Acquire);
        let degraded = page_cache_kib > FTS_CONNECTION_CACHE_HARD_KIB
            || process_fts_cache_reserved_kib > FTS_PROCESS_CACHE_HARD_KIB
            || wal_bytes >= WAL_HEALTH_BYTES;
        Ok(IndexResourceHealth {
            level: if degraded {
                ResourceHealthLevel::Degraded
            } else {
                ResourceHealthLevel::Healthy
            },
            page_cache_kib,
            page_cache_hard_limit_kib: FTS_CONNECTION_CACHE_HARD_KIB,
            process_fts_cache_reserved_kib,
            process_fts_cache_hard_limit_kib: FTS_PROCESS_CACHE_HARD_KIB,
            sqlite_aggregate_cache_target_kib: SQLITE_AGGREGATE_CACHE_TARGET_KIB,
            sqlite_aggregate_cache_hard_limit_kib: SQLITE_AGGREGATE_CACHE_HARD_KIB,
            sqlite_hard_headroom_after_fts_kib: SQLITE_AGGREGATE_CACHE_HARD_KIB
                .saturating_sub(FTS_PROCESS_CACHE_HARD_KIB),
            mmap_size_bytes,
            wal_autocheckpoint_pages,
            wal_bytes,
            event: degraded.then(|| {
                format!(
                    "repository_index_resource_health page_cache_kib={page_cache_kib} process_fts_cache_reserved_kib={process_fts_cache_reserved_kib} wal_bytes={wal_bytes}"
                )
            }),
        })
    }

    fn raw_search(&self, query: &LexicalQuery<'_>) -> Result<Vec<LexicalHit>, RepoError> {
        let limit = i64::try_from(query.max_hits).unwrap_or(i64::MAX);
        let mut statement = self
            .connection
            .prepare(
                "SELECT c.path, c.source_digest, c.chunk_ordinal, c.start_line, c.end_line, \
                        c.content, bm25(chunks_fts) \
                 FROM chunks_fts \
                 JOIN chunks c ON c.id = chunks_fts.rowid \
                 WHERE chunks_fts MATCH ?1 \
                 ORDER BY bm25(chunks_fts), c.path, c.chunk_ordinal \
                 LIMIT ?2",
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![query.text, limit], |row| {
                Ok(LexicalHit {
                    repository_id: self.repository_id.clone(),
                    relative_path: PathBuf::from(row.get::<_, String>(0)?),
                    source_digest: row.get(1)?,
                    chunk_ordinal: row.get(2)?,
                    start_line: row.get(3)?,
                    end_line: row.get(4)?,
                    content: row.get(5)?,
                    bm25_score: row.get(6)?,
                })
            })
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }
}

#[derive(Debug, Clone)]
struct SourceFile {
    digest: String,
    content: String,
    byte_len: u64,
}

fn configure_connection(
    connection: &Connection,
    config: &IndexConfig,
    reserved_cache_kib: i64,
) -> Result<(), RepoError> {
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "synchronous", "NORMAL")
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "cache_size", -reserved_cache_kib)
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "mmap_size", 0_i64)
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "wal_autocheckpoint", config.wal_autocheckpoint_pages)
        .map_err(sqlite_error)
}

fn prepare_schema(connection: &Connection) -> Result<(), RepoError> {
    let version = connection
        .query_row(
            "SELECT value_int FROM metadata WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .ok()
        .flatten();
    if version != Some(INDEX_SCHEMA_VERSION) {
        drop_derived_schema(connection)?;
    }
    initialize_schema(connection)?;
    connection
        .execute(
            "INSERT INTO metadata(key, value_int) VALUES('schema_version', ?1) \
             ON CONFLICT(key) DO UPDATE SET value_int = excluded.value_int, snapshot_json = NULL",
            [INDEX_SCHEMA_VERSION],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn drop_derived_schema(connection: &Connection) -> Result<(), RepoError> {
    connection
        .execute_batch(
            "DROP TABLE IF EXISTS chunks_fts;
             DROP INDEX IF EXISTS chunks_path_idx;
             DROP TABLE IF EXISTS chunks;
             DROP TABLE IF EXISTS files;
             DROP TABLE IF EXISTS metadata;",
        )
        .map_err(sqlite_error)
}

fn initialize_schema(connection: &Connection) -> Result<(), RepoError> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata(
                key TEXT PRIMARY KEY,
                value_int INTEGER,
                snapshot_json TEXT
            );
            CREATE TABLE IF NOT EXISTS files(
                path TEXT PRIMARY KEY,
                source_digest TEXT NOT NULL,
                byte_len INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chunks(
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL,
                source_digest TEXT NOT NULL,
                chunk_ordinal INTEGER NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                content TEXT NOT NULL,
                UNIQUE(path, chunk_ordinal)
            );
            CREATE INDEX IF NOT EXISTS chunks_path_idx ON chunks(path);
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                path,
                content,
                content='chunks',
                content_rowid='id',
                tokenize='unicode61'
            );",
        )
        .map_err(sqlite_error)
}

fn scan_sources(
    root: &Path,
    config: &IndexConfig,
) -> Result<BTreeMap<PathBuf, SourceFile>, RepoError> {
    let mut paths = Vec::new();
    collect_regular_files(root, Path::new(""), config.max_files, &mut paths)?;
    paths.sort();
    let mut sources = BTreeMap::new();
    for path in paths {
        let absolute = root.join(&path);
        let metadata = fs::metadata(&absolute)?;
        if metadata.len() > config.max_file_bytes {
            continue;
        }
        let bytes = fs::read(&absolute)?;
        let Ok(content) = String::from_utf8(bytes.clone()) else {
            continue;
        };
        sources.insert(
            path,
            SourceFile {
                digest: sha256_prefixed(&bytes),
                byte_len: metadata.len(),
                content,
            },
        );
    }
    Ok(sources)
}

fn load_manifest(connection: &Connection) -> Result<BTreeMap<PathBuf, String>, RepoError> {
    let mut statement = connection
        .prepare("SELECT path, source_digest FROM files ORDER BY path")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                PathBuf::from(row.get::<_, String>(0)?),
                row.get::<_, String>(1)?,
            ))
        })
        .map_err(sqlite_error)?;
    rows.collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(sqlite_error)
}

fn invalidate_path(transaction: &Transaction<'_>, path: &Path) -> Result<usize, RepoError> {
    let path = path.to_string_lossy();
    let ids = {
        let mut statement = transaction
            .prepare("SELECT id FROM chunks WHERE path = ?1")
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map([path.as_ref()], |row| row.get::<_, i64>(0))
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for id in &ids {
        transaction
            .execute("DELETE FROM chunks_fts WHERE rowid = ?1", [id])
            .map_err(sqlite_error)?;
    }
    transaction
        .execute("DELETE FROM chunks WHERE path = ?1", [path.as_ref()])
        .map_err(sqlite_error)?;
    transaction
        .execute("DELETE FROM files WHERE path = ?1", [path.as_ref()])
        .map_err(sqlite_error)?;
    Ok(ids.len())
}

fn index_source(
    transaction: &Transaction<'_>,
    path: &Path,
    source: &SourceFile,
    config: &IndexConfig,
) -> Result<usize, RepoError> {
    let path_text = path.to_string_lossy();
    transaction
        .execute(
            "INSERT INTO files(path, source_digest, byte_len) VALUES(?1, ?2, ?3)",
            params![path_text.as_ref(), source.digest, source.byte_len],
        )
        .map_err(sqlite_error)?;
    let chunks = bounded_chunks(
        &source.content,
        config.max_chunk_bytes,
        config.max_chunks_per_file,
    );
    for (ordinal, chunk) in chunks.iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO chunks(path, source_digest, chunk_ordinal, start_line, end_line, content) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    path_text.as_ref(),
                    source.digest,
                    u32::try_from(ordinal).unwrap_or(u32::MAX),
                    chunk.start_line,
                    chunk.end_line,
                    chunk.content
                ],
            )
            .map_err(sqlite_error)?;
        let rowid = transaction.last_insert_rowid();
        transaction
            .execute(
                "INSERT INTO chunks_fts(rowid, path, content) VALUES(?1, ?2, ?3)",
                params![rowid, path_text.as_ref(), chunk.content],
            )
            .map_err(sqlite_error)?;
    }
    Ok(chunks.len())
}

#[derive(Debug)]
struct Chunk<'a> {
    start_line: u64,
    end_line: u64,
    content: &'a str,
}

fn bounded_chunks(content: &str, max_bytes: usize, max_chunks: usize) -> Vec<Chunk<'_>> {
    if content.is_empty() {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut start_line = 1u64;
    while start < content.len() && chunks.len() < max_chunks {
        let mut end = start.saturating_add(max_bytes).min(content.len());
        while end > start && !content.is_char_boundary(end) {
            end -= 1;
        }
        if end < content.len()
            && let Some(relative_newline) = content[start..end].rfind('\n')
        {
            let line_end = start.saturating_add(relative_newline).saturating_add(1);
            if line_end > start {
                end = line_end;
            }
        }
        if end == start {
            end = content[start..]
                .char_indices()
                .nth(1)
                .map_or(content.len(), |(offset, _)| start.saturating_add(offset));
        }
        let slice = &content[start..end];
        let newline_count = slice.bytes().filter(|byte| *byte == b'\n').count();
        let end_line = start_line
            .saturating_add(u64::try_from(newline_count).unwrap_or(u64::MAX))
            .saturating_sub(u64::from(slice.ends_with('\n')));
        chunks.push(Chunk {
            start_line,
            end_line: end_line.max(start_line),
            content: slice,
        });
        start_line = end_line.saturating_add(1);
        start = end;
    }
    chunks
}

fn manifest_digest(current: &BTreeMap<PathBuf, SourceFile>) -> String {
    let mut bytes = Vec::new();
    for (path, source) in current {
        bytes.extend_from_slice(path.as_os_str().as_encoded_bytes());
        bytes.push(0);
        bytes.extend_from_slice(source.digest.as_bytes());
        bytes.push(0);
    }
    sha256_prefixed(&bytes)
}

fn hits_match_current_source(root: &Path, hits: &[LexicalHit]) -> Result<bool, RepoError> {
    let mut observed = BTreeMap::<PathBuf, Option<String>>::new();
    for hit in hits {
        let current_digest = if let Some(cached) = observed.get(&hit.relative_path) {
            cached.clone()
        } else {
            let absolute = root.join(&hit.relative_path);
            let digest = match fs::symlink_metadata(&absolute) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    Some(sha256_prefixed(&fs::read(&absolute)?))
                }
                Ok(_) => None,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(RepoError::Io(error)),
            };
            observed.insert(hit.relative_path.clone(), digest.clone());
            digest
        };
        if current_digest.as_deref() != Some(hit.source_digest.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn source_race_error() -> RepoError {
    RepoError::InvalidSearch(
        "repository source changed repeatedly during lexical retrieval; bounded refresh budget exhausted"
            .to_owned(),
    )
}

fn reserve_fts_cache(requested_kib: i64) -> Result<FtsCacheReservation, RepoError> {
    let mut current = FTS_PROCESS_CACHE_RESERVED_KIB.load(Ordering::Acquire);
    loop {
        let Some(next) = checked_fts_cache_total(current, requested_kib) else {
            return Err(RepoError::InvalidSearch(format!(
                "process-local FTS cache reservation would exceed {FTS_PROCESS_CACHE_HARD_KIB} KiB hard contribution"
            )));
        };
        match FTS_PROCESS_CACHE_RESERVED_KIB.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(FtsCacheReservation { kib: requested_kib }),
            Err(observed) => current = observed,
        }
    }
}

fn checked_fts_cache_total(current_kib: i64, requested_kib: i64) -> Option<i64> {
    let next = current_kib.checked_add(requested_kib)?;
    (requested_kib > 0 && next <= FTS_PROCESS_CACHE_HARD_KIB).then_some(next)
}

fn next_generation(connection: &Connection) -> Result<u64, RepoError> {
    let current: Option<i64> = connection
        .query_row(
            "SELECT value_int FROM metadata WHERE key = 'generation'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(u64::try_from(current.unwrap_or(0).saturating_add(1)).unwrap_or(u64::MAX))
}

fn publish_snapshot(connection: &Connection, snapshot: &IndexSnapshot) -> Result<(), RepoError> {
    let json = serde_json::to_string(snapshot)?;
    let generation = i64::try_from(snapshot.generation).unwrap_or(i64::MAX);
    let transaction = connection.unchecked_transaction().map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO metadata(key, value_int) VALUES('generation', ?1) \
             ON CONFLICT(key) DO UPDATE SET value_int = excluded.value_int",
            [generation],
        )
        .map_err(sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO metadata(key, snapshot_json) VALUES('snapshot', ?1) \
             ON CONFLICT(key) DO UPDATE SET snapshot_json = excluded.snapshot_json",
            [json],
        )
        .map_err(sqlite_error)?;
    transaction.commit().map_err(sqlite_error)
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcessMetrics {
    cpu_time_micros: Option<u64>,
    rss_bytes: Option<u64>,
}

#[derive(Debug)]
struct ResourceSampler {
    started: ProcessMetrics,
    peak_rss_bytes: Option<u64>,
}

impl ResourceSampler {
    fn start() -> Self {
        let started = process_metrics();
        Self {
            started,
            peak_rss_bytes: started.rss_bytes,
        }
    }

    fn sample(&mut self) {
        if let Some(rss) = process_metrics().rss_bytes {
            self.peak_rss_bytes = Some(self.peak_rss_bytes.map_or(rss, |peak| peak.max(rss)));
        }
    }
}

fn process_metrics() -> ProcessMetrics {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "time=", "-o", "rss=", "-p", &pid])
        .output();
    let Ok(output) = output else {
        return ProcessMetrics::default();
    };
    if !output.status.success() {
        return ProcessMetrics::default();
    }
    let Ok(text) = String::from_utf8(output.stdout) else {
        return ProcessMetrics::default();
    };
    let mut fields = text.split_whitespace();
    let cpu_time_micros = fields.next().and_then(parse_cpu_time_micros);
    let rss_bytes = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kib| kib.saturating_mul(1024));
    ProcessMetrics {
        cpu_time_micros,
        rss_bytes,
    }
}

fn parse_cpu_time_micros(value: &str) -> Option<u64> {
    let (day_part, clock) = if let Some((days, clock)) = value.split_once('-') {
        (days.parse::<u64>().ok()?, clock)
    } else {
        (0, value)
    };
    let parts = clock.split(':').collect::<Vec<_>>();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [minutes, seconds] => (0, minutes.parse::<u64>().ok()?, parse_seconds(seconds)?),
        [hours, minutes, seconds] => (
            hours.parse::<u64>().ok()?,
            minutes.parse::<u64>().ok()?,
            parse_seconds(seconds)?,
        ),
        _ => return None,
    };
    Some(
        day_part
            .saturating_mul(24)
            .saturating_add(hours)
            .saturating_mul(60)
            .saturating_add(minutes)
            .saturating_mul(60_000_000)
            .saturating_add(seconds),
    )
}

fn parse_seconds(value: &str) -> Option<u64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let whole_micros = whole.parse::<u64>().ok()?.saturating_mul(1_000_000);
    let mut fractional = fraction
        .as_bytes()
        .iter()
        .take(6)
        .copied()
        .collect::<Vec<_>>();
    while fractional.len() < 6 {
        fractional.push(b'0');
    }
    let fractional = std::str::from_utf8(&fractional).ok()?.parse::<u64>().ok()?;
    Some(whole_micros.saturating_add(fractional))
}

fn sqlite_error(error: rusqlite::Error) -> RepoError {
    let message = error.to_string();
    drop(error);
    RepoError::InvalidSearch(format!("lexical SQLite error: {message}"))
}

#[cfg(test)]
mod tests {
    use super::{FTS_PROCESS_CACHE_HARD_KIB, checked_fts_cache_total};

    #[test]
    fn lexical_cache_budget_math_reserves_hard_headroom() {
        assert_eq!(checked_fts_cache_total(0, 8 * 1024), Some(8 * 1024));
        assert_eq!(
            checked_fts_cache_total(8 * 1024, 8 * 1024),
            Some(FTS_PROCESS_CACHE_HARD_KIB)
        );
        assert_eq!(checked_fts_cache_total(12 * 1024, 8 * 1024), None);
    }
}
