//! Authoritative `SQLite` state foundation for Sovereign.
//!
//! This milestone intentionally provides persistence primitives rather than
//! Controller semantics.  Current state lives in normalized records while an
//! append-only journal preserves ordered transition evidence.

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use sovereign_types::UnixMillis;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::time::Duration;

const FOUNDATION_SQL: &str = include_str!("../migrations/0001_foundation.sql");
const ARTIFACTS_SQL: &str = include_str!("../migrations/0002_artifacts.sql");
const SECURITY_KERNEL_SQL: &str = include_str!("../migrations/0003_security_kernel.sql");
const MEMORY_SQL: &str = include_str!("../migrations/0004_memory.sql");
const MEMORY_RETRIEVAL_SQL: &str = include_str!("../migrations/0005_memory_retrieval.sql");
const MEMORY_PROJECTION_OUTBOX_SQL: &str =
    include_str!("../migrations/0006_memory_projection_outbox.sql");
const SECURITY_AUDIT_SQL: &str = include_str!("../migrations/0007_security_audit.sql");
const SECURITY_AUDIT_GENESIS_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Current durable schema version implemented by this crate.
pub const CURRENT_SCHEMA_VERSION: i64 = 7;

/// One numbered, transactional durable-state migration.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

impl Migration {
    #[must_use]
    pub fn checksum(self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sql.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Canonical migration set applied to every newly opened Sovereign database.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "foundation",
        sql: FOUNDATION_SQL,
    },
    Migration {
        version: 2,
        name: "artifact_metadata",
        sql: ARTIFACTS_SQL,
    },
    Migration {
        version: 3,
        name: "security_kernel",
        sql: SECURITY_KERNEL_SQL,
    },
    Migration {
        version: 4,
        name: "memory_lifecycle",
        sql: MEMORY_SQL,
    },
    Migration {
        version: 5,
        name: "memory_retrieval",
        sql: MEMORY_RETRIEVAL_SQL,
    },
    Migration {
        version: 6,
        name: "memory_projection_outbox",
        sql: MEMORY_PROJECTION_OUTBOX_SQL,
    },
    Migration {
        version: 7,
        name: "security_audit",
        sql: SECURITY_AUDIT_SQL,
    },
];

/// State-layer errors with enough detail for deterministic diagnostics.
#[derive(Debug)]
pub enum StateError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Clock(std::time::SystemTimeError),
    MigrationChecksum {
        version: i64,
        expected: String,
        actual: String,
    },
    ArtifactSizeMismatch {
        digest: String,
        expected: u64,
        actual: u64,
    },
    InvalidMigrationOrder {
        previous: i64,
        current: i64,
    },
    UnsupportedSchemaVersion {
        found: i64,
        supported: i64,
    },
    Integrity(String),
}

impl Display for StateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "`SQLite` state error: {error}"),
            Self::Io(error) => write!(f, "state I/O error: {error}"),
            Self::Clock(error) => write!(f, "state clock error: {error}"),
            Self::MigrationChecksum {
                version,
                expected,
                actual,
            } => write!(
                f,
                "migration {version} checksum mismatch: expected {expected}, got {actual}"
            ),
            Self::ArtifactSizeMismatch {
                digest,
                expected,
                actual,
            } => write!(
                f,
                "artifact {digest} size mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidMigrationOrder { previous, current } => write!(
                f,
                "migration versions must increase strictly: previous={previous}, current={current}"
            ),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                f,
                "state schema version {found} is newer than this binary supports ({supported})"
            ),
            Self::Integrity(message) => write!(f, "state integrity error: {message}"),
        }
    }
}

impl Error for StateError {}

impl From<rusqlite::Error> for StateError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for StateError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<std::time::SystemTimeError> for StateError {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::Clock(value)
    }
}

/// Ordered journal row returned from authoritative durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEvent {
    pub sequence: i64,
    pub event_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub event_kind: String,
    pub payload_json: String,
    pub occurred_at_ms: i64,
}

/// Input for an append-only event.
#[derive(Debug, Clone, Copy)]
pub struct NewJournalEvent<'a> {
    pub event_id: &'a str,
    pub entity_type: &'a str,
    pub entity_id: &'a str,
    pub event_kind: &'a str,
    pub payload_json: &'a str,
}

/// One normalized current-state write to commit atomically with related journal events.
#[derive(Debug, Clone, Copy)]
pub struct StateRecordUpdate<'a> {
    pub namespace: &'a str,
    pub key: &'a str,
    pub value_json: &'a str,
}

/// Canonical metadata for one published content-addressed artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMetadata {
    pub digest: String,
    pub size_bytes: u64,
    pub created_at_ms: i64,
}

/// Durable authority record for one exact action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedActionRecord {
    pub action_id: String,
    pub state: String,
    pub payload_digest: String,
    pub policy_digest: String,
    pub execution_epoch: i64,
    pub result_digest: Option<String>,
    pub last_event_sequence: i64,
    pub updated_at_ms: i64,
}

/// One current-state record returned for deterministic checkpoint/recovery scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedStateRecord {
    pub namespace: String,
    pub key: String,
    pub value_json: String,
    pub version: i64,
    pub updated_at_ms: i64,
}

/// Exact action authority inserted atomically with its first audit event.
#[derive(Debug, Clone, Copy)]
pub struct NewActionRecord<'a> {
    pub action_id: &'a str,
    pub state: &'a str,
    pub payload_digest: &'a str,
    pub policy_digest: &'a str,
    pub execution_epoch: i64,
    pub event_id: &'a str,
    pub event_kind: &'a str,
    pub payload_json: &'a str,
}

/// Compare-and-transition input for the durable action lifecycle.
#[derive(Debug, Clone, Copy)]
pub struct ActionTransition<'a> {
    pub action_id: &'a str,
    pub expected_state: &'a str,
    pub next_state: &'a str,
    pub expected_epoch: i64,
    pub event_id: &'a str,
    pub event_kind: &'a str,
    pub payload_json: &'a str,
    pub result_digest: Option<&'a str>,
}

/// One immutable generation in the Controller checkpoint hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointIntegrityRecord {
    pub generation: i64,
    pub previous_hash: Option<String>,
    pub checkpoint_hash: String,
    pub payload_digest: String,
    pub action_sequence: i64,
    pub created_at_ms: i64,
}

/// Input for appending one checkpoint integrity generation.
#[derive(Debug, Clone, Copy)]
pub struct NewCheckpointIntegrityRecord<'a> {
    pub payload_digest: &'a str,
    pub action_sequence: i64,
}

/// Versioned security/audit fact persisted without model reasoning or chain-of-thought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditEventV1 {
    pub actor_id: String,
    pub plan_id: Option<String>,
    pub task_id: Option<String>,
    pub attempt_id: Option<String>,
    pub action_id: Option<String>,
    pub execution_epoch: Option<i64>,
    pub decision: String,
    pub action: String,
    pub policy_digest: String,
    pub config_digest: String,
    pub tool_digest: String,
    pub approval_provenance_digest: Option<String>,
    pub evidence_provenance_digest: Option<String>,
    pub occurred_at_ms: i64,
    pub result: String,
}

/// Durable security-audit chain head used to detect truncation as well as row tampering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuditHead {
    pub event_count: i64,
    pub head_digest: String,
}

/// Typed access to the tamper-evident audit log inside the canonical [`StateStore`] database.
pub struct SecurityAuditLog<'a> {
    connection: &'a mut Connection,
}

impl SecurityAuditLog<'_> {
    /// Appends one v1 audit fact after verifying the current durable chain in the same transaction.
    ///
    /// # Errors
    /// Returns [`StateError::Integrity`] for an invalid event or an already-corrupt chain, and
    /// [`StateError::Sqlite`] for persistence failures.
    pub fn append(
        &mut self,
        event: &SecurityAuditEventV1,
    ) -> Result<SecurityAuditHead, StateError> {
        validate_security_audit_event(event)?;
        let transaction = self.connection.transaction()?;
        let head = verify_security_audit_chain(&transaction)?;
        let sequence = head
            .event_count
            .checked_add(1)
            .ok_or_else(|| StateError::Integrity("security audit sequence overflow".to_owned()))?;
        let event_digest = security_audit_digest(sequence, &head.head_digest, event);

        transaction.execute(
            "INSERT INTO security_audit_events(\
                sequence, event_version, actor_id, plan_id, task_id, attempt_id, action_id, \
                execution_epoch, decision, action, policy_digest, config_digest, tool_digest, \
                approval_provenance_digest, evidence_provenance_digest, occurred_at_ms, result, \
                previous_digest, event_digest\
             ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            rusqlite::params![
                sequence,
                event.actor_id.as_str(),
                event.plan_id.as_deref(),
                event.task_id.as_deref(),
                event.attempt_id.as_deref(),
                event.action_id.as_deref(),
                event.execution_epoch,
                event.decision.as_str(),
                event.action.as_str(),
                event.policy_digest.as_str(),
                event.config_digest.as_str(),
                event.tool_digest.as_str(),
                event.approval_provenance_digest.as_deref(),
                event.evidence_provenance_digest.as_deref(),
                event.occurred_at_ms,
                event.result.as_str(),
                head.head_digest.as_str(),
                event_digest.as_str(),
            ],
        )?;
        let updated = transaction.execute(
            "UPDATE security_audit_head SET event_count=?1, head_digest=?2 \
             WHERE singleton=1 AND event_count=?3 AND head_digest=?4",
            (
                sequence,
                event_digest.as_str(),
                head.event_count,
                head.head_digest.as_str(),
            ),
        )?;
        if updated != 1 {
            return Err(StateError::Integrity(
                "security audit head changed while appending".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(SecurityAuditHead {
            event_count: sequence,
            head_digest: event_digest,
        })
    }

    /// Returns the stored durable audit head without asserting chain integrity.
    ///
    /// # Errors
    /// Returns [`StateError`] when the durable head is missing or unreadable.
    pub fn head(&self) -> Result<SecurityAuditHead, StateError> {
        security_audit_head(self.connection)
    }

    /// Verifies every row, parent link, contiguous sequence and the durable tail count/digest.
    ///
    /// # Errors
    /// Returns [`StateError::Integrity`] for mutation, reorder, deletion/truncation, a missing
    /// tail, or head mismatch; returns [`StateError::Sqlite`] on read failure.
    pub fn verify_chain(&self) -> Result<SecurityAuditHead, StateError> {
        verify_security_audit_chain(self.connection)
    }

    /// Verifies that a previously checkpointed audit head is an exact prefix of the current
    /// durable chain. This permits legitimate post-checkpoint audit appends while still detecting
    /// truncation, replacement, or forked history before recovery authorizes another mutation.
    ///
    /// # Errors
    /// Returns [`StateError::Integrity`] when the expected head is malformed, is ahead of the
    /// current durable chain, or its sequence now resolves to a different digest.
    pub fn verify_prefix(&self, expected: &SecurityAuditHead) -> Result<(), StateError> {
        if expected.event_count < 0 || expected.head_digest.trim().is_empty() {
            return Err(StateError::Integrity(
                "checkpoint security audit head is malformed".to_owned(),
            ));
        }
        let current = verify_security_audit_chain(self.connection)?;
        if expected.event_count > current.event_count {
            return Err(StateError::Integrity(format!(
                "checkpoint security audit head count {} exceeds durable count {}",
                expected.event_count, current.event_count
            )));
        }
        if expected.event_count == 0 {
            if expected.head_digest != SECURITY_AUDIT_GENESIS_DIGEST {
                return Err(StateError::Integrity(
                    "checkpoint security audit genesis digest mismatch".to_owned(),
                ));
            }
            return Ok(());
        }
        let observed: Option<String> = self
            .connection
            .query_row(
                "SELECT event_digest FROM security_audit_events WHERE sequence=?1",
                [expected.event_count],
                |row| row.get(0),
            )
            .optional()?;
        if observed.as_deref() != Some(expected.head_digest.as_str()) {
            return Err(StateError::Integrity(
                "checkpoint security audit head is not a prefix of durable history".to_owned(),
            ));
        }
        Ok(())
    }
}

/// `SQLite`-backed authoritative state repository.
pub struct StateStore {
    path: PathBuf,
    connection: Connection,
}

impl StateStore {
    /// Opens or creates a state database, enables WAL durability, and applies
    /// all known numbered migrations transactionally.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the database cannot be opened/configured or
    /// when migration validation/application fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection = Connection::open_with_flags(&path, flags)?;
        configure_connection(&connection)?;
        MigrationRunner::apply(&mut connection, MIGRATIONS)?;

        Ok(Self { path, connection })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the highest successfully applied schema version.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` read failure.
    pub fn schema_version(&self) -> Result<i64, StateError> {
        Ok(self.connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?)
    }

    /// Borrows the canonical database as a typed tamper-evident security audit log.
    #[must_use]
    pub fn security_audit_log(&mut self) -> SecurityAuditLog<'_> {
        SecurityAuditLog {
            connection: &mut self.connection,
        }
    }

    /// Executes a caller-owned transaction.  Any returned error rolls the
    /// entire transaction back before control returns to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] if beginning, running, or committing the
    /// transaction fails.
    pub fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, StateError>,
    ) -> Result<T, StateError> {
        let transaction = self.connection.transaction()?;
        let result = operation(&transaction)?;
        transaction.commit()?;
        Ok(result)
    }

    /// Upserts one normalized current-state record.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on clock or `SQLite` failure.
    pub fn put_state(
        &mut self,
        namespace: &str,
        key: &str,
        value_json: &str,
    ) -> Result<(), StateError> {
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            tx.execute(
                "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) \
                 VALUES (?1, ?2, ?3, 1, ?4) \
                 ON CONFLICT(namespace, record_key) DO UPDATE SET \
                 value_json=excluded.value_json, \
                 version=state_records.version + 1, \
                 updated_at_ms=excluded.updated_at_ms",
                (namespace, key, value_json, now),
            )?;
            Ok(())
        })
    }

    /// Reads one normalized current-state record.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` failure.
    pub fn get_state(&self, namespace: &str, key: &str) -> Result<Option<String>, StateError> {
        Ok(self
            .connection
            .query_row(
                "SELECT value_json FROM state_records WHERE namespace=?1 AND record_key=?2",
                (namespace, key),
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Lists one namespace in stable key order for checkpoint/recovery reconstruction.
    ///
    /// # Errors
    /// Returns [`StateError`] on `SQLite` failure.
    pub fn state_records(&self, namespace: &str) -> Result<Vec<PersistedStateRecord>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT namespace, record_key, value_json, version, updated_at_ms \
             FROM state_records WHERE namespace=?1 ORDER BY record_key ASC",
        )?;
        let rows = statement.query_map([namespace], |row| {
            Ok(PersistedStateRecord {
                namespace: row.get(0)?,
                key: row.get(1)?,
                value_json: row.get(2)?,
                version: row.get(3)?,
                updated_at_ms: row.get(4)?,
            })
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Appends an immutable event and returns its authoritative sequence.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on clock or `SQLite` failure.
    pub fn append_event(&mut self, event: NewJournalEvent<'_>) -> Result<i64, StateError> {
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            tx.execute(
                "INSERT INTO event_journal(\
                    event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    event.event_id,
                    event.entity_type,
                    event.entity_id,
                    event.event_kind,
                    event.payload_json,
                    now,
                ),
            )?;
            Ok(tx.last_insert_rowid())
        })
    }

    /// Atomically upserts current-state records and appends their correlated immutable events.
    /// This prevents crash recovery from observing a state transition without the journal facts
    /// that explain it, or vice versa.
    ///
    /// # Errors
    /// Returns [`StateError`] on clock or `SQLite` failure.
    pub fn put_state_records_with_events(
        &mut self,
        updates: &[StateRecordUpdate<'_>],
        events: &[NewJournalEvent<'_>],
    ) -> Result<Vec<i64>, StateError> {
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            for update in updates {
                tx.execute(
                    "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) \
                     VALUES (?1, ?2, ?3, 1, ?4) \
                     ON CONFLICT(namespace, record_key) DO UPDATE SET \
                     value_json=excluded.value_json, \
                     version=state_records.version + 1, \
                     updated_at_ms=excluded.updated_at_ms",
                    (update.namespace, update.key, update.value_json, now),
                )?;
            }
            let mut sequences = Vec::with_capacity(events.len());
            for event in events {
                tx.execute(
                    "INSERT INTO event_journal(\
                        event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    (
                        event.event_id,
                        event.entity_type,
                        event.entity_id,
                        event.event_kind,
                        event.payload_json,
                        now,
                    ),
                )?;
                sequences.push(tx.last_insert_rowid());
            }
            Ok(sequences)
        })
    }

    /// Returns all events in authoritative sequence order.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` failure.
    pub fn journal(&self) -> Result<Vec<JournalEvent>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms \
             FROM event_journal ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(JournalEvent {
                sequence: row.get(0)?,
                event_id: row.get(1)?,
                entity_type: row.get(2)?,
                entity_id: row.get(3)?,
                event_kind: row.get(4)?,
                payload_json: row.get(5)?,
                occurred_at_ms: row.get(6)?,
            })
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    /// Returns authoritative journal events after one checkpoint sequence.
    ///
    /// # Errors
    /// Returns [`StateError`] on `SQLite` failure.
    pub fn journal_after(&self, sequence: i64) -> Result<Vec<JournalEvent>, StateError> {
        if sequence < 0 {
            return Err(StateError::Integrity(
                "negative recovery journal sequence".to_owned(),
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT sequence, event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms \
             FROM event_journal WHERE sequence>?1 ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map([sequence], |row| {
            Ok(JournalEvent {
                sequence: row.get(0)?,
                event_id: row.get(1)?,
                entity_type: row.get(2)?,
                entity_id: row.get(3)?,
                event_kind: row.get(4)?,
                payload_json: row.get(5)?,
                occurred_at_ms: row.get(6)?,
            })
        })?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    /// Forces a passive WAL checkpoint.  This is useful before making an
    /// exact external fixture backup for migration/recovery tests.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` failure.
    pub fn checkpoint_wal(&self) -> Result<(), StateError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Returns the configured `SQLite` journal mode.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` failure.
    pub fn journal_mode(&self) -> Result<String, StateError> {
        Ok(self
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))?)
    }

    /// Registers metadata for an already-published immutable CAS object.
    /// Re-registering the same digest and size is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] when the stored digest is associated with a
    /// different size, the size cannot fit `SQLite`, or persistence fails.
    pub fn register_artifact(&mut self, digest: &str, size_bytes: u64) -> Result<(), StateError> {
        let size = i64::try_from(size_bytes).map_err(|_| {
            StateError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "artifact size exceeds SQLite INTEGER range",
            ))
        })?;
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT size_bytes FROM artifact_metadata WHERE digest=?1",
                    [digest],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing_size) = existing {
                let existing_size = u64::try_from(existing_size).map_err(|_| {
                    StateError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "negative artifact size in state",
                    ))
                })?;
                if existing_size != size_bytes {
                    return Err(StateError::ArtifactSizeMismatch {
                        digest: digest.to_owned(),
                        expected: existing_size,
                        actual: size_bytes,
                    });
                }
                return Ok(());
            }

            tx.execute(
                "INSERT INTO artifact_metadata(digest, size_bytes, created_at_ms) VALUES (?1, ?2, ?3)",
                (digest, size, now),
            )?;
            Ok(())
        })
    }

    /// Looks up metadata for a published CAS object.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` failure or malformed stored size.
    pub fn artifact_metadata(&self, digest: &str) -> Result<Option<ArtifactMetadata>, StateError> {
        let row: Option<(String, i64, i64)> = self
            .connection
            .query_row(
                "SELECT digest, size_bytes, created_at_ms FROM artifact_metadata WHERE digest=?1",
                [digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;

        row.map(|(digest, size, created_at_ms)| {
            let size_bytes = u64::try_from(size).map_err(|_| {
                StateError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "negative artifact size in state",
                ))
            })?;
            Ok(ArtifactMetadata {
                digest,
                size_bytes,
                created_at_ms,
            })
        })
        .transpose()
    }

    /// Adds a durable logical reference to a registered artifact.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on clock or `SQLite` failure. Foreign-key
    /// enforcement rejects references to unknown artifact digests.
    pub fn add_artifact_reference(
        &mut self,
        reference_id: &str,
        digest: &str,
    ) -> Result<(), StateError> {
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO artifact_references(reference_id, digest, created_at_ms) VALUES (?1, ?2, ?3)",
                (reference_id, digest, now),
            )?;
            Ok(())
        })
    }

    /// Returns whether one exact logical reference protects one exact artifact digest.
    ///
    /// This is a read-only integrity primitive over the existing artifact reference table. It
    /// deliberately does not recreate a missing reference, so callers can fail closed when a
    /// durable authority binding has been deleted or tampered with.
    ///
    /// # Errors
    ///
    /// Returns an error when the database operation fails.
    pub fn artifact_reference_exists(
        &self,
        reference_id: &str,
        digest: &str,
    ) -> Result<bool, StateError> {
        let exists = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifact_references WHERE reference_id=?1 AND digest=?2)",
            (reference_id, digest),
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }

    /// Removes a logical artifact reference while leaving immutable metadata
    /// and CAS bytes untouched for grace-period garbage collection.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` failure.
    pub fn remove_artifact_reference(
        &mut self,
        reference_id: &str,
        digest: &str,
    ) -> Result<(), StateError> {
        self.transaction(|tx| {
            tx.execute(
                "DELETE FROM artifact_references WHERE reference_id=?1 AND digest=?2",
                (reference_id, digest),
            )?;
            Ok(())
        })
    }

    /// Selects old, unreferenced artifact metadata for later garbage
    /// collection. This query never deletes canonical state or object bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] on `SQLite` failure or malformed stored size.
    pub fn unreferenced_artifacts_before(
        &self,
        cutoff_ms: i64,
    ) -> Result<Vec<ArtifactMetadata>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT m.digest, m.size_bytes, m.created_at_ms \
             FROM artifact_metadata m \
             WHERE m.created_at_ms <= ?1 \
               AND NOT EXISTS (SELECT 1 FROM artifact_references r WHERE r.digest=m.digest) \
             ORDER BY m.created_at_ms ASC, m.digest ASC",
        )?;
        let rows = statement.query_map([cutoff_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;

        let mut artifacts = Vec::new();
        for row in rows {
            let (digest, size, created_at_ms) = row?;
            let size_bytes = u64::try_from(size).map_err(|_| {
                StateError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "negative artifact size in state",
                ))
            })?;
            artifacts.push(ArtifactMetadata {
                digest,
                size_bytes,
                created_at_ms,
            });
        }
        Ok(artifacts)
    }
    /// Inserts an exact action authority atomically with its audit event.
    ///
    /// # Errors
    /// Returns an integrity error for negative epochs or any persistence failure.
    pub fn insert_action_record(&mut self, record: NewActionRecord<'_>) -> Result<i64, StateError> {
        if record.execution_epoch < 0 {
            return Err(StateError::Integrity("negative execution epoch".to_owned()));
        }
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let current_epoch: i64 = tx.query_row(
                "SELECT execution_epoch FROM controller_runtime WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            if current_epoch != record.execution_epoch {
                return Err(StateError::Integrity(format!(
                    "stale action authorization epoch: action={}, controller={current_epoch}",
                    record.execution_epoch
                )));
            }
            tx.execute(
                "INSERT INTO action_records(action_id, state, payload_digest, policy_digest, execution_epoch, last_event_sequence, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
                (record.action_id, record.state, record.payload_digest, record.policy_digest, record.execution_epoch, now),
            )?;
            tx.execute(
                "INSERT INTO event_journal(event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms) VALUES (?1, 'action', ?2, ?3, ?4, ?5)",
                (record.event_id, record.action_id, record.event_kind, record.payload_json, now),
            )?;
            let sequence = tx.last_insert_rowid();
            tx.execute(
                "UPDATE action_records SET last_event_sequence=?2, updated_at_ms=?3 WHERE action_id=?1",
                (record.action_id, sequence, now),
            )?;
            Ok(sequence)
        })
    }

    /// Reads one durable action authority record.
    ///
    /// # Errors
    /// Returns [`StateError`] on persistence failure.
    pub fn action_record(
        &self,
        action_id: &str,
    ) -> Result<Option<PersistedActionRecord>, StateError> {
        Ok(self.connection.query_row(
            "SELECT action_id, state, payload_digest, policy_digest, execution_epoch, result_digest, last_event_sequence, updated_at_ms FROM action_records WHERE action_id=?1",
            [action_id],
            |row| Ok(PersistedActionRecord { action_id: row.get(0)?, state: row.get(1)?, payload_digest: row.get(2)?, policy_digest: row.get(3)?, execution_epoch: row.get(4)?, result_digest: row.get(5)?, last_event_sequence: row.get(6)?, updated_at_ms: row.get(7)? }),
        ).optional()?)
    }

    /// Lists current authoritative action records in stable action-id order.
    ///
    /// # Errors
    /// Returns [`StateError`] on persistence failure.
    pub fn action_records(&self) -> Result<Vec<PersistedActionRecord>, StateError> {
        let mut statement = self.connection.prepare(
            "SELECT action_id, state, payload_digest, policy_digest, execution_epoch, result_digest, last_event_sequence, updated_at_ms \
             FROM action_records ORDER BY action_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(PersistedActionRecord {
                action_id: row.get(0)?,
                state: row.get(1)?,
                payload_digest: row.get(2)?,
                policy_digest: row.get(3)?,
                execution_epoch: row.get(4)?,
                result_digest: row.get(5)?,
                last_event_sequence: row.get(6)?,
                updated_at_ms: row.get(7)?,
            })
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Crash-recovery transition for an action whose dispatch was durably recorded but
    /// whose process outcome was not. This transition intentionally validates the stored
    /// action epoch against the current Controller epoch before any recovery epoch advance.
    ///
    /// # Errors
    /// Returns an integrity error unless the action is currently `dispatched` in the
    /// current execution epoch.
    pub fn recover_dispatched_action_as_unknown(
        &mut self,
        action_id: &str,
        event_id: &str,
        payload_json: &str,
    ) -> Result<i64, StateError> {
        self.recover_nonterminal_action_as_unknown(
            action_id,
            &["dispatched"],
            event_id,
            payload_json,
        )
    }

    /// Crash-recovery transition for an action whose externally observed outcome did not reach a
    /// durable terminal state. This is intentionally recovery-only and preserves the original
    /// action execution epoch while converting only the explicitly allowed nonterminal states to
    /// `unknown` before the Controller advances its recovery epoch.
    ///
    /// # Errors
    /// Returns an integrity error unless the action is in one of `allowed_states` in the current
    /// execution epoch.
    pub fn recover_nonterminal_action_as_unknown(
        &mut self,
        action_id: &str,
        allowed_states: &[&str],
        event_id: &str,
        payload_json: &str,
    ) -> Result<i64, StateError> {
        if allowed_states.is_empty()
            || allowed_states
                .iter()
                .any(|state| !matches!(*state, "dispatched" | "observed"))
        {
            return Err(StateError::Integrity(
                "recovery nonterminal action states must be dispatched and/or observed".to_owned(),
            ));
        }
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let controller_epoch: i64 = tx.query_row(
                "SELECT execution_epoch FROM controller_runtime WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let current: Option<(String, i64)> = tx
                .query_row(
                    "SELECT state, execution_epoch FROM action_records WHERE action_id=?1",
                    [action_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((state, action_epoch)) = current else {
                return Err(StateError::Integrity(format!(
                    "unknown recovery action {action_id}"
                )));
            };
            if !allowed_states.contains(&state.as_str()) || action_epoch != controller_epoch {
                return Err(StateError::Integrity(format!(
                    "recovery nonterminal state mismatch for {action_id}: state={state} action_epoch={action_epoch} controller_epoch={controller_epoch}"
                )));
            }
            tx.execute(
                "INSERT INTO event_journal(event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms) \
                 VALUES (?1, 'action', ?2, 'unknown', ?3, ?4)",
                (event_id, action_id, payload_json, now),
            )?;
            let sequence = tx.last_insert_rowid();
            tx.execute(
                "UPDATE action_records SET state='unknown', last_event_sequence=?2, updated_at_ms=?3 WHERE action_id=?1",
                (action_id, sequence, now),
            )?;
            Ok(sequence)
        })
    }

    /// Recovery-only transition for an old-epoch `unknown` action. The original action
    /// epoch is immutable authority evidence; a later Controller epoch may reconcile the
    /// record only after deterministic proof has been obtained.
    ///
    /// # Errors
    /// Returns an integrity error unless the current record is `unknown` and the requested
    /// recovery state is `reconciled`.
    pub fn reconcile_historical_unknown_action(
        &mut self,
        action_id: &str,
        next_state: &str,
        result_digest: Option<&str>,
        event_id: &str,
        event_kind: &str,
        payload_json: &str,
    ) -> Result<i64, StateError> {
        if next_state != "reconciled" {
            return Err(StateError::Integrity(format!(
                "unsupported recovery action state {next_state}"
            )));
        }
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM action_records WHERE action_id=?1",
                    [action_id],
                    |row| row.get(0),
                )
                .optional()?;
            if state.as_deref() != Some("unknown") {
                return Err(StateError::Integrity(format!(
                    "recovery action {action_id} is not currently unknown"
                )));
            }
            if let Some(digest) = result_digest {
                let known: Option<i64> = tx
                    .query_row(
                        "SELECT 1 FROM artifact_metadata WHERE digest=?1",
                        [digest],
                        |row| row.get(0),
                    )
                    .optional()?;
                if known.is_none() {
                    return Err(StateError::Integrity(format!(
                        "recovery result artifact {digest} is not registered"
                    )));
                }
            }
            tx.execute(
                "INSERT INTO event_journal(event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms) \
                 VALUES (?1, 'action', ?2, ?3, ?4, ?5)",
                (event_id, action_id, event_kind, payload_json, now),
            )?;
            let sequence = tx.last_insert_rowid();
            tx.execute(
                "UPDATE action_records SET state=?2, result_digest=COALESCE(?3, result_digest), last_event_sequence=?4, updated_at_ms=?5 WHERE action_id=?1",
                (action_id, next_state, result_digest, sequence, now),
            )?;
            Ok(sequence)
        })
    }

    /// Commits an already recovery-reconciled historical action with its durable result.
    /// The action's original execution epoch remains immutable; current Controller epoch
    /// may be newer because restart invalidates pre-crash leases.
    ///
    /// # Errors
    /// Returns an integrity error unless the action is `reconciled` and has a result digest.
    pub fn commit_historical_reconciled_action(
        &mut self,
        action_id: &str,
        event_id: &str,
        payload_json: &str,
    ) -> Result<i64, StateError> {
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let current: Option<(String, Option<String>)> = tx
                .query_row(
                    "SELECT state, result_digest FROM action_records WHERE action_id=?1",
                    [action_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((state, result_digest)) = current else {
                return Err(StateError::Integrity(format!(
                    "unknown recovery action {action_id}"
                )));
            };
            if state != "reconciled" || result_digest.is_none() {
                return Err(StateError::Integrity(format!(
                    "historical recovery action {action_id} is not reconciled with result evidence"
                )));
            }
            tx.execute(
                "INSERT INTO event_journal(event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms) \
                 VALUES (?1, 'action', ?2, 'committed', ?3, ?4)",
                (event_id, action_id, payload_json, now),
            )?;
            let sequence = tx.last_insert_rowid();
            tx.execute(
                "UPDATE action_records SET state='committed', last_event_sequence=?2, updated_at_ms=?3 WHERE action_id=?1",
                (action_id, sequence, now),
            )?;
            Ok(sequence)
        })
    }

    /// Marks a historical recovery-reconciled action failed after deterministic proof that
    /// its side effect is absent. This preserves `unknown -> reconciled -> failed`.
    ///
    /// # Errors
    /// Returns an integrity error unless the action is currently `reconciled`.
    pub fn fail_historical_reconciled_action(
        &mut self,
        action_id: &str,
        event_id: &str,
        payload_json: &str,
    ) -> Result<i64, StateError> {
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM action_records WHERE action_id=?1",
                    [action_id],
                    |row| row.get(0),
                )
                .optional()?;
            if state.as_deref() != Some("reconciled") {
                return Err(StateError::Integrity(format!(
                    "historical recovery action {action_id} is not reconciled"
                )));
            }
            tx.execute(
                "INSERT INTO event_journal(event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms) \
                 VALUES (?1, 'action', ?2, 'failed', ?3, ?4)",
                (event_id, action_id, payload_json, now),
            )?;
            let sequence = tx.last_insert_rowid();
            tx.execute(
                "UPDATE action_records SET state='failed', last_event_sequence=?2, updated_at_ms=?3 WHERE action_id=?1",
                (action_id, sequence, now),
            )?;
            Ok(sequence)
        })
    }

    /// Atomically compares the expected action state/epoch, appends an event,
    /// and advances the durable state.
    ///
    /// # Errors
    /// Returns [`StateError::Integrity`] on stale state/epoch.
    pub fn transition_action_with_event(
        &mut self,
        transition: ActionTransition<'_>,
    ) -> Result<i64, StateError> {
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let controller_epoch: i64 = tx.query_row(
                "SELECT execution_epoch FROM controller_runtime WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            let current: Option<(String, i64)> = tx.query_row(
                "SELECT state, execution_epoch FROM action_records WHERE action_id=?1",
                [transition.action_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            let Some((state, epoch)) = current else {
                return Err(StateError::Integrity(format!("unknown action {}", transition.action_id)));
            };
            if state != transition.expected_state
                || epoch != transition.expected_epoch
                || controller_epoch != transition.expected_epoch
            {
                return Err(StateError::Integrity(format!("stale action transition for {}: expected state={} epoch={}, actual state={} epoch={}", transition.action_id, transition.expected_state, transition.expected_epoch, state, epoch)));
            }
            tx.execute(
                "INSERT INTO event_journal(event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms) VALUES (?1, 'action', ?2, ?3, ?4, ?5)",
                (transition.event_id, transition.action_id, transition.event_kind, transition.payload_json, now),
            )?;
            let sequence = tx.last_insert_rowid();
            tx.execute(
                "UPDATE action_records SET state=?2, result_digest=COALESCE(?3, result_digest), last_event_sequence=?4, updated_at_ms=?5 WHERE action_id=?1",
                (
                    transition.action_id,
                    transition.next_state,
                    transition.result_digest,
                    sequence,
                    now,
                ),
            )?;
            Ok(sequence)
        })
    }

    /// Returns the latest authoritative journal sequence, or zero when empty.
    ///
    /// # Errors
    /// Returns [`StateError`] on persistence failure.
    pub fn latest_journal_sequence(&self) -> Result<i64, StateError> {
        Ok(self.connection.query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM event_journal",
            [],
            |row| row.get(0),
        )?)
    }

    /// Returns the current monotonic Controller execution epoch.
    ///
    /// # Errors
    /// Returns [`StateError`] on persistence failure.
    pub fn current_execution_epoch(&self) -> Result<i64, StateError> {
        Ok(self.connection.query_row(
            "SELECT execution_epoch FROM controller_runtime WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }

    /// Advances and returns the monotonic Controller execution epoch.
    ///
    /// # Errors
    /// Returns [`StateError`] on persistence failure.
    pub fn advance_execution_epoch(&mut self) -> Result<i64, StateError> {
        self.transaction(|tx| {
            tx.execute(
                "UPDATE controller_runtime SET execution_epoch=execution_epoch+1 WHERE singleton=1",
                [],
            )?;
            Ok(tx.query_row(
                "SELECT execution_epoch FROM controller_runtime WHERE singleton=1",
                [],
                |row| row.get(0),
            )?)
        })
    }

    /// Appends one immutable checkpoint generation linked to its predecessor.
    ///
    /// # Errors
    /// Returns [`StateError`] for invalid input or persistence failure.
    pub fn append_checkpoint_integrity(
        &mut self,
        input: NewCheckpointIntegrityRecord<'_>,
    ) -> Result<CheckpointIntegrityRecord, StateError> {
        if input.action_sequence < 0 {
            return Err(StateError::Integrity(
                "negative checkpoint action sequence".to_owned(),
            ));
        }
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let latest_sequence: i64 = tx.query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM event_journal",
                [],
                |row| row.get(0),
            )?;
            if input.action_sequence != latest_sequence {
                return Err(StateError::Integrity(format!(
                    "checkpoint action sequence mismatch: requested={}, authoritative={latest_sequence}",
                    input.action_sequence
                )));
            }
            let previous: Option<(i64, String)> = tx.query_row(
                "SELECT generation, checkpoint_hash FROM checkpoint_integrity ORDER BY generation DESC LIMIT 1", [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            let generation = previous.as_ref().map_or(1, |(value, _)| value + 1);
            let previous_hash = previous.map(|(_, hash)| hash);
            let checkpoint_hash = checkpoint_hash(generation, previous_hash.as_deref(), input.payload_digest, input.action_sequence);
            tx.execute(
                "INSERT INTO checkpoint_integrity(generation, previous_hash, checkpoint_hash, payload_digest, action_sequence, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (generation, previous_hash.as_deref(), checkpoint_hash.as_str(), input.payload_digest, input.action_sequence, now),
            )?;
            Ok(CheckpointIntegrityRecord { generation, previous_hash, checkpoint_hash, payload_digest: input.payload_digest.to_owned(), action_sequence: input.action_sequence, created_at_ms: now })
        })
    }

    /// Appends a recovery re-anchor after an immutable corrupt/torn checkpoint tail.
    /// The new generation keeps every prior row for audit but cryptographically names the
    /// last trusted generation/hash as its recovery parent. Normal checkpoints after this
    /// row resume a linear chain from the re-anchor.
    ///
    /// # Errors
    /// Returns an integrity error when the trusted checkpoint no longer matches durable state
    /// or when the requested action sequence is not the authoritative journal tail.
    pub fn append_recovery_checkpoint_integrity(
        &mut self,
        input: NewCheckpointIntegrityRecord<'_>,
        trusted_generation: i64,
        trusted_hash: &str,
    ) -> Result<CheckpointIntegrityRecord, StateError> {
        if input.action_sequence < 0 || trusted_generation <= 0 || trusted_hash.trim().is_empty() {
            return Err(StateError::Integrity(
                "invalid recovery checkpoint re-anchor input".to_owned(),
            ));
        }
        let trusted = self
            .checkpoint_integrity_by_generation(trusted_generation)?
            .ok_or_else(|| {
                StateError::Integrity(format!(
                    "trusted checkpoint generation {trusted_generation} is missing"
                ))
            })?;
        if trusted.checkpoint_hash != trusted_hash {
            return Err(StateError::Integrity(
                "trusted recovery checkpoint hash changed".to_owned(),
            ));
        }
        let ancestry = self.latest_valid_checkpoint_ancestry()?;
        if !ancestry.iter().any(|record| {
            record.generation == trusted_generation && record.checkpoint_hash == trusted_hash
        }) {
            return Err(StateError::Integrity(
                "recovery checkpoint parent is not on the current trusted checkpoint ancestry"
                    .to_owned(),
            ));
        }
        let now = UnixMillis::now()?.as_millis();
        self.transaction(|tx| {
            let latest_sequence: i64 = tx.query_row(
                "SELECT COALESCE(MAX(sequence), 0) FROM event_journal",
                [],
                |row| row.get(0),
            )?;
            if input.action_sequence != latest_sequence {
                return Err(StateError::Integrity(format!(
                    "recovery checkpoint action sequence mismatch: requested={}, authoritative={latest_sequence}",
                    input.action_sequence
                )));
            }
            let physical_generation: i64 = tx.query_row(
                "SELECT COALESCE(MAX(generation), 0) FROM checkpoint_integrity",
                [],
                |row| row.get(0),
            )?;
            let generation = physical_generation.saturating_add(1);
            let previous_hash = recovery_anchor(trusted_generation, trusted_hash);
            let checkpoint_hash = checkpoint_hash(
                generation,
                Some(&previous_hash),
                input.payload_digest,
                input.action_sequence,
            );
            tx.execute(
                "INSERT INTO checkpoint_integrity(generation, previous_hash, checkpoint_hash, payload_digest, action_sequence, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    generation,
                    previous_hash.as_str(),
                    checkpoint_hash.as_str(),
                    input.payload_digest,
                    input.action_sequence,
                    now,
                ),
            )?;
            Ok(CheckpointIntegrityRecord {
                generation,
                previous_hash: Some(previous_hash),
                checkpoint_hash,
                payload_digest: input.payload_digest.to_owned(),
                action_sequence: input.action_sequence,
                created_at_ms: now,
            })
        })
    }

    /// Returns one immutable checkpoint generation.
    ///
    /// # Errors
    /// Returns [`StateError`] on persistence failure.
    pub fn checkpoint_integrity_by_generation(
        &self,
        generation: i64,
    ) -> Result<Option<CheckpointIntegrityRecord>, StateError> {
        checkpoint_row(&self.connection, generation)
    }

    /// Returns the cryptographically trusted ancestry of the newest valid checkpoint,
    /// newest first. Recovery-anchor rows follow their explicit trusted generation/hash
    /// parent rather than numerically adjacent physical rows.
    ///
    /// # Errors
    /// Returns an integrity error if any parent link, row hash, or generation ordering is
    /// inconsistent with the trusted chain.
    pub fn latest_valid_checkpoint_ancestry(
        &self,
    ) -> Result<Vec<CheckpointIntegrityRecord>, StateError> {
        let Some(mut current) = latest_valid_checkpoint(&self.connection)? else {
            return Ok(Vec::new());
        };
        let mut ancestry = Vec::new();
        loop {
            let computed = checkpoint_hash(
                current.generation,
                current.previous_hash.as_deref(),
                &current.payload_digest,
                current.action_sequence,
            );
            if computed != current.checkpoint_hash {
                return Err(StateError::Integrity(format!(
                    "checkpoint generation {} has an invalid hash",
                    current.generation
                )));
            }
            let parent = match current.previous_hash.as_deref() {
                None => {
                    if current.generation != 1 {
                        return Err(StateError::Integrity(format!(
                            "checkpoint generation {} has no trusted parent",
                            current.generation
                        )));
                    }
                    ancestry.push(current);
                    break;
                }
                Some(previous) => {
                    let (parent_generation, expected_hash) =
                        if let Some((generation, hash)) = parse_recovery_anchor(previous) {
                            (generation, hash.to_owned())
                        } else {
                            (current.generation.saturating_sub(1), previous.to_owned())
                        };
                    if parent_generation <= 0 || parent_generation >= current.generation {
                        return Err(StateError::Integrity(format!(
                            "checkpoint generation {} has invalid parent generation {parent_generation}",
                            current.generation
                        )));
                    }
                    let parent =
                        checkpoint_row(&self.connection, parent_generation)?.ok_or_else(|| {
                            StateError::Integrity(format!(
                                "checkpoint parent generation {parent_generation} is missing"
                            ))
                        })?;
                    if parent.checkpoint_hash != expected_hash {
                        return Err(StateError::Integrity(format!(
                            "checkpoint generation {} parent hash does not match generation {parent_generation}",
                            current.generation
                        )));
                    }
                    parent
                }
            };
            ancestry.push(current);
            current = parent;
        }
        Ok(ancestry)
    }

    /// Returns the newest checkpoint row without asserting its integrity.
    ///
    /// # Errors
    /// Returns [`StateError`] on persistence failure.
    pub fn latest_checkpoint_integrity(
        &self,
    ) -> Result<Option<CheckpointIntegrityRecord>, StateError> {
        let generation: Option<i64> = self.connection.query_row(
            "SELECT MAX(generation) FROM checkpoint_integrity",
            [],
            |row| row.get(0),
        )?;
        generation
            .map(|value| checkpoint_row(&self.connection, value))
            .transpose()
            .map(Option::flatten)
    }

    /// Returns the newest contiguous hash-valid checkpoint generation without requiring
    /// its journal sequence to equal the current authoritative sequence. Recovery uses
    /// this as a floor and then replays/reconciles later authoritative journal/state.
    ///
    /// # Errors
    /// Returns an integrity error when checkpoint rows exist but no valid generation does.
    pub fn latest_valid_checkpoint_integrity(
        &self,
    ) -> Result<Option<CheckpointIntegrityRecord>, StateError> {
        latest_valid_checkpoint(&self.connection)
    }

    /// Runs bounded `SQLite` integrity and foreign-key checks before recovery enables mutation.
    ///
    /// # Errors
    /// Returns [`StateError::Integrity`] unless both checks report a clean database.
    pub fn recovery_integrity_check(&self) -> Result<(), StateError> {
        let quick: String = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if quick != "ok" {
            return Err(StateError::Integrity(format!(
                "SQLite quick_check failed: {quick}"
            )));
        }
        let foreign_key_failures: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_check",
            [],
            |row| row.get(0),
        )?;
        if foreign_key_failures != 0 {
            return Err(StateError::Integrity(format!(
                "SQLite foreign_key_check reported {foreign_key_failures} violation(s)"
            )));
        }
        Ok(())
    }

    /// Validates the checkpoint chain and exact action-journal sequence floor.
    /// Corrupt newest generations may fall back only to the last contiguous valid
    /// generation. A sequence mismatch blocks mutation.
    ///
    /// # Errors
    /// Returns [`StateError::Integrity`] when no trustworthy floor matches.
    pub fn validate_checkpoint_integrity_floor(
        &self,
        expected_action_sequence: i64,
    ) -> Result<Option<CheckpointIntegrityRecord>, StateError> {
        let latest_valid = latest_valid_checkpoint(&self.connection)?;
        if let Some(record) = latest_valid.as_ref() {
            if record.action_sequence != expected_action_sequence {
                return Err(StateError::Integrity(format!(
                    "checkpoint action sequence mismatch: checkpoint={}, authoritative={expected_action_sequence}",
                    record.action_sequence
                )));
            }
        } else if expected_action_sequence != 0 {
            return Err(StateError::Integrity(format!(
                "missing checkpoint for authoritative action sequence {expected_action_sequence}"
            )));
        }
        Ok(latest_valid)
    }
}

/// Numbered transactional migration executor.
pub struct MigrationRunner;

impl MigrationRunner {
    /// Applies migrations that have not yet been recorded.  Every migration
    /// body and its metadata row commit atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StateError`] for invalid ordering, checksum drift, or any
    /// `SQLite` failure.  A failed migration body is rolled back entirely.
    pub fn apply(connection: &mut Connection, migrations: &[Migration]) -> Result<(), StateError> {
        ensure_migration_table(connection)?;
        validate_order(migrations)?;
        let supported = migrations.last().map_or(0, |migration| migration.version);
        let found: i64 = connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        if found > supported {
            return Err(StateError::UnsupportedSchemaVersion { found, supported });
        }

        for migration in migrations {
            let expected = migration.checksum();
            let existing: Option<String> = connection
                .query_row(
                    "SELECT checksum FROM schema_migrations WHERE version=?1",
                    [migration.version],
                    |row| row.get(0),
                )
                .optional()?;

            if let Some(actual) = existing {
                if actual != expected {
                    return Err(StateError::MigrationChecksum {
                        version: migration.version,
                        expected,
                        actual,
                    });
                }
                continue;
            }

            let applied_at = UnixMillis::now()?.as_millis();
            let transaction = connection.transaction()?;
            transaction.execute_batch(migration.sql)?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at_ms) \
                 VALUES (?1, ?2, ?3, ?4)",
                (migration.version, migration.name, expected, applied_at),
            )?;
            transaction.commit()?;
        }

        Ok(())
    }
}

fn ensure_migration_table(connection: &Connection) -> Result<(), StateError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (\
            version INTEGER PRIMARY KEY, \
            name TEXT NOT NULL, \
            checksum TEXT NOT NULL, \
            applied_at_ms INTEGER NOT NULL\
         ) STRICT;",
    )?;
    Ok(())
}

fn validate_order(migrations: &[Migration]) -> Result<(), StateError> {
    let mut previous = 0;
    for migration in migrations {
        if migration.version <= previous {
            return Err(StateError::InvalidMigrationOrder {
                previous,
                current: migration.version,
            });
        }
        previous = migration.version;
    }
    Ok(())
}

#[derive(Debug)]
struct PersistedSecurityAuditEvent {
    sequence: i64,
    event_version: i64,
    event: SecurityAuditEventV1,
    previous_digest: String,
    event_digest: String,
}

fn validate_security_audit_event(event: &SecurityAuditEventV1) -> Result<(), StateError> {
    require_audit_value("actor_id", &event.actor_id)?;
    for (label, value) in [
        ("plan_id", event.plan_id.as_deref()),
        ("task_id", event.task_id.as_deref()),
        ("attempt_id", event.attempt_id.as_deref()),
        ("action_id", event.action_id.as_deref()),
        (
            "approval_provenance_digest",
            event.approval_provenance_digest.as_deref(),
        ),
        (
            "evidence_provenance_digest",
            event.evidence_provenance_digest.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            require_audit_value(label, value)?;
        }
    }
    if event.execution_epoch.is_some_and(|epoch| epoch < 0) {
        return Err(StateError::Integrity(
            "security audit execution_epoch must be non-negative".to_owned(),
        ));
    }
    if event.occurred_at_ms < 0 {
        return Err(StateError::Integrity(
            "security audit occurred_at_ms must be non-negative".to_owned(),
        ));
    }
    require_audit_value("decision", &event.decision)?;
    require_audit_value("action", &event.action)?;
    require_audit_value("policy_digest", &event.policy_digest)?;
    require_audit_value("config_digest", &event.config_digest)?;
    require_audit_value("tool_digest", &event.tool_digest)?;
    require_audit_value("result", &event.result)?;
    Ok(())
}

fn require_audit_value(label: &str, value: &str) -> Result<(), StateError> {
    if value.trim().is_empty() {
        return Err(StateError::Integrity(format!(
            "security audit {label} must not be blank"
        )));
    }
    Ok(())
}

fn security_audit_head(connection: &Connection) -> Result<SecurityAuditHead, StateError> {
    connection
        .query_row(
            "SELECT event_count, head_digest FROM security_audit_head WHERE singleton=1",
            [],
            |row| {
                Ok(SecurityAuditHead {
                    event_count: row.get(0)?,
                    head_digest: row.get(1)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| StateError::Integrity("security audit head is missing".to_owned()))
}

fn verify_security_audit_chain(connection: &Connection) -> Result<SecurityAuditHead, StateError> {
    let head = security_audit_head(connection)?;
    if head.event_count < 0 {
        return Err(StateError::Integrity(
            "security audit head has negative event count".to_owned(),
        ));
    }

    let mut statement = connection.prepare(
        "SELECT sequence, event_version, actor_id, plan_id, task_id, attempt_id, action_id, \
                execution_epoch, decision, action, policy_digest, config_digest, tool_digest, \
                approval_provenance_digest, evidence_provenance_digest, occurred_at_ms, result, \
                previous_digest, event_digest \
         FROM security_audit_events ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map([], security_audit_from_row)?;
    let mut expected_sequence = 1_i64;
    let mut observed_count = 0_i64;
    let mut previous_digest = SECURITY_AUDIT_GENESIS_DIGEST.to_owned();

    for row in rows {
        let row = row?;
        if row.sequence != expected_sequence {
            return Err(StateError::Integrity(format!(
                "security audit sequence discontinuity: expected {expected_sequence}, got {}",
                row.sequence
            )));
        }
        if row.event_version != 1 {
            return Err(StateError::Integrity(format!(
                "security audit event {} has unsupported version {}",
                row.sequence, row.event_version
            )));
        }
        validate_security_audit_event(&row.event)?;
        if row.previous_digest != previous_digest {
            return Err(StateError::Integrity(format!(
                "security audit event {} parent digest mismatch",
                row.sequence
            )));
        }
        let computed = security_audit_digest(row.sequence, &row.previous_digest, &row.event);
        if computed != row.event_digest {
            return Err(StateError::Integrity(format!(
                "security audit event {} digest mismatch",
                row.sequence
            )));
        }

        observed_count = observed_count
            .checked_add(1)
            .ok_or_else(|| StateError::Integrity("security audit row count overflow".to_owned()))?;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| StateError::Integrity("security audit sequence overflow".to_owned()))?;
        previous_digest = row.event_digest;
    }

    if observed_count != head.event_count {
        return Err(StateError::Integrity(format!(
            "security audit tail count mismatch: durable={}, observed={observed_count}",
            head.event_count
        )));
    }
    if previous_digest != head.head_digest {
        return Err(StateError::Integrity(
            "security audit durable head digest does not match event tail".to_owned(),
        ));
    }
    Ok(head)
}

fn security_audit_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PersistedSecurityAuditEvent> {
    Ok(PersistedSecurityAuditEvent {
        sequence: row.get(0)?,
        event_version: row.get(1)?,
        event: SecurityAuditEventV1 {
            actor_id: row.get(2)?,
            plan_id: row.get(3)?,
            task_id: row.get(4)?,
            attempt_id: row.get(5)?,
            action_id: row.get(6)?,
            execution_epoch: row.get(7)?,
            decision: row.get(8)?,
            action: row.get(9)?,
            policy_digest: row.get(10)?,
            config_digest: row.get(11)?,
            tool_digest: row.get(12)?,
            approval_provenance_digest: row.get(13)?,
            evidence_provenance_digest: row.get(14)?,
            occurred_at_ms: row.get(15)?,
            result: row.get(16)?,
        },
        previous_digest: row.get(17)?,
        event_digest: row.get(18)?,
    })
}

fn security_audit_digest(
    sequence: i64,
    previous_digest: &str,
    event: &SecurityAuditEventV1,
) -> String {
    let mut hasher = Sha256::new();
    hash_audit_text(&mut hasher, "domain", Some("sovereign-security-audit-v1"));
    hash_audit_i64(&mut hasher, "event_version", Some(1));
    hash_audit_i64(&mut hasher, "sequence", Some(sequence));
    hash_audit_text(&mut hasher, "previous_digest", Some(previous_digest));
    hash_audit_text(&mut hasher, "actor_id", Some(&event.actor_id));
    hash_audit_text(&mut hasher, "plan_id", event.plan_id.as_deref());
    hash_audit_text(&mut hasher, "task_id", event.task_id.as_deref());
    hash_audit_text(&mut hasher, "attempt_id", event.attempt_id.as_deref());
    hash_audit_text(&mut hasher, "action_id", event.action_id.as_deref());
    hash_audit_i64(&mut hasher, "execution_epoch", event.execution_epoch);
    hash_audit_text(&mut hasher, "decision", Some(&event.decision));
    hash_audit_text(&mut hasher, "action", Some(&event.action));
    hash_audit_text(&mut hasher, "policy_digest", Some(&event.policy_digest));
    hash_audit_text(&mut hasher, "config_digest", Some(&event.config_digest));
    hash_audit_text(&mut hasher, "tool_digest", Some(&event.tool_digest));
    hash_audit_text(
        &mut hasher,
        "approval_provenance_digest",
        event.approval_provenance_digest.as_deref(),
    );
    hash_audit_text(
        &mut hasher,
        "evidence_provenance_digest",
        event.evidence_provenance_digest.as_deref(),
    );
    hash_audit_i64(&mut hasher, "occurred_at_ms", Some(event.occurred_at_ms));
    hash_audit_text(&mut hasher, "result", Some(&event.result));
    format!("sha256:{:x}", hasher.finalize())
}

fn hash_audit_text(hasher: &mut Sha256, label: &str, value: Option<&str>) {
    hash_audit_bytes(hasher, label.as_bytes());
    match value {
        Some(value) => {
            hasher.update([1_u8]);
            hash_audit_bytes(hasher, value.as_bytes());
        }
        None => hasher.update([0_u8]),
    }
}

fn hash_audit_i64(hasher: &mut Sha256, label: &str, value: Option<i64>) {
    hash_audit_bytes(hasher, label.as_bytes());
    match value {
        Some(value) => {
            hasher.update([1_u8]);
            hasher.update(value.to_be_bytes());
        }
        None => hasher.update([0_u8]),
    }
}

fn hash_audit_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn checkpoint_hash(
    generation: i64,
    previous_hash: Option<&str>,
    payload_digest: &str,
    action_sequence: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(generation.to_be_bytes());
    hasher.update(previous_hash.unwrap_or("GENESIS").as_bytes());
    hasher.update(payload_digest.as_bytes());
    hasher.update(action_sequence.to_be_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn recovery_anchor(generation: i64, checkpoint_hash: &str) -> String {
    format!("RECOVERY:{generation}:{checkpoint_hash}")
}

fn latest_valid_checkpoint(
    connection: &Connection,
) -> Result<Option<CheckpointIntegrityRecord>, StateError> {
    let mut statement = connection.prepare(
        "SELECT generation, previous_hash, checkpoint_hash, payload_digest, action_sequence, created_at_ms \
         FROM checkpoint_integrity ORDER BY generation ASC",
    )?;
    let rows = statement.query_map([], checkpoint_from_row)?;
    let mut latest_valid: Option<CheckpointIntegrityRecord> = None;
    let mut expected_generation = 1_i64;
    let mut previous_hash: Option<String> = None;
    let mut broken = false;
    let mut row_count = 0_i64;
    let mut trusted_hashes = BTreeMap::new();
    for row in rows {
        row_count += 1;
        let record = row?;
        let hash_valid = record.checkpoint_hash
            == checkpoint_hash(
                record.generation,
                record.previous_hash.as_deref(),
                &record.payload_digest,
                record.action_sequence,
            );
        if !broken
            && record.generation == expected_generation
            && record.previous_hash == previous_hash
            && hash_valid
        {
            previous_hash = Some(record.checkpoint_hash.clone());
            expected_generation = record.generation.saturating_add(1);
            trusted_hashes.insert(record.generation, record.checkpoint_hash.clone());
            latest_valid = Some(record);
            continue;
        }
        broken = true;
        let anchor_valid = record
            .previous_hash
            .as_deref()
            .and_then(parse_recovery_anchor)
            .and_then(|(generation, hash)| {
                trusted_hashes
                    .get(&generation)
                    .map(|trusted_hash| trusted_hash == hash)
            })
            .unwrap_or(false);
        if anchor_valid && hash_valid {
            previous_hash = Some(record.checkpoint_hash.clone());
            expected_generation = record.generation.saturating_add(1);
            trusted_hashes.insert(record.generation, record.checkpoint_hash.clone());
            latest_valid = Some(record);
            broken = false;
        }
    }
    if row_count > 0 && latest_valid.is_none() {
        return Err(StateError::Integrity(
            "checkpoint chain has no valid generation".to_owned(),
        ));
    }
    Ok(latest_valid)
}

fn parse_recovery_anchor(value: &str) -> Option<(i64, &str)> {
    let rest = value.strip_prefix("RECOVERY:")?;
    let (generation, hash) = rest.split_once(':')?;
    let generation = generation.parse().ok()?;
    if generation <= 0 || hash.is_empty() {
        return None;
    }
    Some((generation, hash))
}

fn checkpoint_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CheckpointIntegrityRecord> {
    Ok(CheckpointIntegrityRecord {
        generation: row.get(0)?,
        previous_hash: row.get(1)?,
        checkpoint_hash: row.get(2)?,
        payload_digest: row.get(3)?,
        action_sequence: row.get(4)?,
        created_at_ms: row.get(5)?,
    })
}

fn checkpoint_row(
    connection: &Connection,
    generation: i64,
) -> Result<Option<CheckpointIntegrityRecord>, StateError> {
    Ok(connection.query_row(
        "SELECT generation, previous_hash, checkpoint_hash, payload_digest, action_sequence, created_at_ms FROM checkpoint_integrity WHERE generation=?1",
        [generation], checkpoint_from_row,
    ).optional()?)
}

fn configure_connection(connection: &Connection) -> Result<(), StateError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "wal_autocheckpoint", 1000_i64)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "sovereign-state-{label}-{}-{nonce}",
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
    fn fresh_database_is_wal_and_explicit_version() {
        let temp = TestDir::new("fresh");
        let store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
        assert_eq!(store.schema_version().unwrap_or(-1), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            store.journal_mode().unwrap_or_default().to_lowercase(),
            "wal"
        );
    }

    #[test]
    fn migrations_are_idempotent() {
        let temp = TestDir::new("idempotent");
        drop(StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open 1: {error}")));
        let store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open 2: {error}"));
        assert_eq!(store.schema_version().unwrap_or(-1), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn future_schema_version_is_rejected_without_mutating_existing_state() {
        let temp = TestDir::new("future-schema");
        let db = temp.db();
        let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
        store
            .put_state("fixture", "preserved", "{\"value\":1}")
            .unwrap_or_else(|error| panic!("seed fixture: {error}"));
        store
            .checkpoint_wal()
            .unwrap_or_else(|error| panic!("checkpoint fixture: {error}"));
        drop(store);

        let connection = Connection::open(&db).unwrap_or_else(|error| panic!("raw open: {error}"));
        connection
            .execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at_ms) VALUES (?1, 'future', 'future-checksum', 1)",
                [CURRENT_SCHEMA_VERSION + 1],
            )
            .unwrap_or_else(|error| panic!("seed future migration: {error}"));
        drop(connection);

        let error = StateStore::open(&db)
            .err()
            .unwrap_or_else(|| panic!("future schema unexpectedly opened"));
        assert!(matches!(
            error,
            StateError::UnsupportedSchemaVersion {
                found,
                supported
            } if found == CURRENT_SCHEMA_VERSION + 1 && supported == CURRENT_SCHEMA_VERSION
        ));

        let connection =
            Connection::open(&db).unwrap_or_else(|error| panic!("verify open: {error}"));
        let preserved: String = connection
            .query_row(
                "SELECT value_json FROM state_records WHERE namespace='fixture' AND record_key='preserved'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("read preserved fixture: {error}"));
        let max_version: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|error| panic!("read max migration: {error}"));
        assert_eq!(preserved, "{\"value\":1}");
        assert_eq!(max_version, CURRENT_SCHEMA_VERSION + 1);
    }

    #[test]
    fn failed_migration_rolls_back_and_prior_backup_remains_readable() {
        const BROKEN: Migration = Migration {
            version: CURRENT_SCHEMA_VERSION + 1,
            name: "broken_fixture",
            sql: "CREATE TABLE should_rollback(value TEXT); INSERT INTO missing_table VALUES (1);",
        };

        let temp = TestDir::new("rollback");
        let db = temp.db();
        let backup = temp.0.join("pre-failure.sqlite3");
        let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
        store
            .put_state("fixture", "key", "{\"ok\":true}")
            .unwrap_or_else(|error| panic!("put: {error}"));
        store
            .checkpoint_wal()
            .unwrap_or_else(|error| panic!("checkpoint: {error}"));
        drop(store);
        fs::copy(&db, &backup).unwrap_or_else(|error| panic!("backup copy: {error}"));

        let mut connection =
            Connection::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
        configure_connection(&connection).unwrap_or_else(|error| panic!("configure: {error}"));
        let mut migrations = MIGRATIONS.to_vec();
        migrations.push(BROKEN);
        assert!(MigrationRunner::apply(&mut connection, &migrations).is_err());
        let rolled_back: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='should_rollback'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(rolled_back, 0);
        drop(connection);

        let current = StateStore::open(&db).unwrap_or_else(|error| panic!("current: {error}"));
        let copied = StateStore::open(&backup).unwrap_or_else(|error| panic!("backup: {error}"));
        assert_eq!(
            current.get_state("fixture", "key").unwrap_or_default(),
            Some("{\"ok\":true}".to_owned())
        );
        assert_eq!(
            copied.get_state("fixture", "key").unwrap_or_default(),
            Some("{\"ok\":true}".to_owned())
        );
    }

    #[test]
    fn memory_migration_has_exact_v3_backup_and_transactional_rollback_fixture() {
        const BROKEN_MEMORY_V4: Migration = Migration {
            version: 4,
            name: "broken_memory_v4_fixture",
            sql: "CREATE TABLE memory_partial(value TEXT); INSERT INTO definitely_missing_memory_table VALUES (1);",
        };

        let temp = TestDir::new("memory-migration-rollback");
        let db = temp.db();
        let backup = temp.0.join("pre-memory-v3.sqlite3");
        let mut connection =
            Connection::open(&db).unwrap_or_else(|error| panic!("open v3 fixture: {error}"));
        configure_connection(&connection).unwrap_or_else(|error| panic!("configure: {error}"));
        MigrationRunner::apply(&mut connection, &MIGRATIONS[..3])
            .unwrap_or_else(|error| panic!("apply v3: {error}"));
        connection
            .execute(
                "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) VALUES ('fixture', 'before-memory', '{\"preserved\":true}', 1, 1)",
                [],
            )
            .unwrap_or_else(|error| panic!("seed v3: {error}"));
        connection
            .execute(
                "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) VALUES ('memory', 'ambiguous-pre-v4', '{\"subject\":\"must-not-import\"}', 1, 1)",
                [],
            )
            .unwrap_or_else(|error| panic!("seed ambiguous pre-v4 state: {error}"));
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap_or_else(|error| panic!("checkpoint: {error}"));
        drop(connection);
        fs::copy(&db, &backup).unwrap_or_else(|error| panic!("backup: {error}"));

        let backup_connection =
            Connection::open(&backup).unwrap_or_else(|error| panic!("open backup: {error}"));
        let backup_version: i64 = backup_connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap_or(-1);
        assert_eq!(backup_version, 3);
        drop(backup_connection);

        let mut failed_v4 =
            Connection::open(&db).unwrap_or_else(|error| panic!("open failed-v4: {error}"));
        configure_connection(&failed_v4)
            .unwrap_or_else(|error| panic!("configure failed-v4: {error}"));
        let mut broken_v4_path = MIGRATIONS[..3].to_vec();
        broken_v4_path.push(BROKEN_MEMORY_V4);
        assert!(MigrationRunner::apply(&mut failed_v4, &broken_v4_path).is_err());
        let partial: i64 = failed_v4
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_partial'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(partial, 0);
        let version_after_failed_v4: i64 = failed_v4
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap_or(-1);
        assert_eq!(version_after_failed_v4, 3);
        let preserved_after_failed_v4: String = failed_v4
            .query_row(
                "SELECT value_json FROM state_records WHERE namespace='fixture' AND record_key='before-memory'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_default();
        assert_eq!(preserved_after_failed_v4, "{\"preserved\":true}");
        drop(failed_v4);

        let mut upgraded =
            Connection::open(&db).unwrap_or_else(|error| panic!("open upgrade: {error}"));
        configure_connection(&upgraded)
            .unwrap_or_else(|error| panic!("configure upgrade: {error}"));
        MigrationRunner::apply(&mut upgraded, MIGRATIONS)
            .unwrap_or_else(|error| panic!("apply memory: {error}"));
        let memory_table: i64 = upgraded
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_records'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(memory_table, 1);
        let fabricated_memory: i64 = upgraded
            .query_row("SELECT COUNT(*) FROM memory_records", [], |row| row.get(0))
            .unwrap_or(-1);
        assert_eq!(fabricated_memory, 0);

        drop(upgraded);

        let migrated_backup =
            StateStore::open(&backup).unwrap_or_else(|error| panic!("migrate backup: {error}"));
        assert_eq!(
            migrated_backup
                .get_state("fixture", "before-memory")
                .unwrap_or_default(),
            Some("{\"preserved\":true}".to_owned())
        );
        assert_eq!(
            migrated_backup.schema_version().unwrap_or(-1),
            CURRENT_SCHEMA_VERSION
        );
    }

    #[test]
    fn projection_outbox_migration_seeds_v5_memory_and_rolls_back_atomically() {
        const BROKEN_MEMORY_V6: Migration = Migration {
            version: 6,
            name: "broken_memory_v6_fixture",
            sql: "CREATE TABLE projection_partial(value TEXT); INSERT INTO definitely_missing_projection_table VALUES (1);",
        };

        let temp = TestDir::new("projection-outbox-migration");
        let db = temp.db();
        let backup = temp.0.join("pre-projection-v5.sqlite3");
        let mut connection =
            Connection::open(&db).unwrap_or_else(|error| panic!("open v5 fixture: {error}"));
        configure_connection(&connection).unwrap_or_else(|error| panic!("configure: {error}"));
        MigrationRunner::apply(&mut connection, &MIGRATIONS[..5])
            .unwrap_or_else(|error| panic!("apply v5: {error}"));
        connection
            .execute(
                "INSERT INTO memory_records(\
                    memory_id, kind, project_id, scope_kind, subject, predicate, conflict_key, assertion, \
                    trust, confidence_legacy_real, confidence, status, created_at_ms, updated_at_ms, \
                    version, normal_injection, lineage_id, content_digest\
                 ) VALUES (\
                    'mem.v5', 'episodic', 'project-a', 'project', 'subject', 'fact', 'subject'||char(31)||'fact', \
                    'canonical projection seed', 'observed', 0.8, 80, 'active', 10, 10, 1, 1, 'mem.v5', 'sha256:v5'\
                 )",
                [],
            )
            .unwrap_or_else(|error| panic!("seed v5 memory: {error}"));
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap_or_else(|error| panic!("checkpoint v5: {error}"));
        drop(connection);
        fs::copy(&db, &backup).unwrap_or_else(|error| panic!("backup v5: {error}"));

        let mut failed =
            Connection::open(&db).unwrap_or_else(|error| panic!("open broken v6: {error}"));
        configure_connection(&failed)
            .unwrap_or_else(|error| panic!("configure broken v6: {error}"));
        let mut broken_path = MIGRATIONS[..5].to_vec();
        broken_path.push(BROKEN_MEMORY_V6);
        assert!(MigrationRunner::apply(&mut failed, &broken_path).is_err());
        let partial: i64 = failed
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='projection_partial'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(partial, 0);
        let outbox_after_failure: i64 = failed
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='memory_projection_outbox'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(outbox_after_failure, 0);
        let version_after_failure: i64 = failed
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap_or(-1);
        assert_eq!(version_after_failure, 5);
        drop(failed);

        let mut upgraded =
            Connection::open(&db).unwrap_or_else(|error| panic!("open real v6: {error}"));
        configure_connection(&upgraded)
            .unwrap_or_else(|error| panic!("configure real v6: {error}"));
        MigrationRunner::apply(&mut upgraded, MIGRATIONS)
            .unwrap_or_else(|error| panic!("apply real v6: {error}"));
        let seeded: i64 = upgraded
            .query_row(
                "SELECT COUNT(*) FROM memory_projection_outbox WHERE projection_kind='memory_fts_v1' AND memory_id='mem.v5'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(seeded, 1);
        let projection_rows: i64 = upgraded
            .query_row("SELECT COUNT(*) FROM memory_fts_projection", [], |row| {
                row.get(0)
            })
            .unwrap_or(-1);
        assert_eq!(
            projection_rows, 0,
            "v6 must rebuild only from durable outbox/canonical state"
        );
        drop(upgraded);

        let migrated_backup =
            StateStore::open(&backup).unwrap_or_else(|error| panic!("migrate v5 backup: {error}"));
        assert_eq!(
            migrated_backup.schema_version().unwrap_or(-1),
            CURRENT_SCHEMA_VERSION
        );
        let seeded_backup: i64 = migrated_backup
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_projection_outbox WHERE memory_id='mem.v5'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(-1);
        assert_eq!(seeded_backup, 1);
    }

    #[test]
    fn failed_transaction_publishes_no_partial_state() {
        let temp = TestDir::new("transaction");
        let mut store = StateStore::open(temp.db()).unwrap_or_else(|error| panic!("open: {error}"));
        let result: Result<(), StateError> = store.transaction(|tx| {
            tx.execute(
                "INSERT INTO state_records(namespace, record_key, value_json, version, updated_at_ms) \
                 VALUES ('test', 'a', '{}', 1, 1)",
                [],
            )?;
            tx.execute("INSERT INTO definitely_missing_table VALUES (1)", [])?;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(store.get_state("test", "a").unwrap_or_default(), None);
    }

    #[test]
    fn event_journal_is_ordered_durable_and_append_only() {
        let temp = TestDir::new("journal");
        let db = temp.db();
        {
            let mut store = StateStore::open(&db).unwrap_or_else(|error| panic!("open: {error}"));
            for index in 1..=3 {
                let event_id = format!("event_{index}");
                store
                    .append_event(NewJournalEvent {
                        event_id: &event_id,
                        entity_type: "task",
                        entity_id: "task_001",
                        event_kind: "fixture",
                        payload_json: "{}",
                    })
                    .unwrap_or_else(|error| panic!("append: {error}"));
            }
        }

        let store = StateStore::open(&db).unwrap_or_else(|error| panic!("reopen: {error}"));
        let events = store
            .journal()
            .unwrap_or_else(|error| panic!("journal: {error}"));
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(events[0].event_id, "event_1");

        let update = store.connection.execute(
            "UPDATE event_journal SET event_kind='changed' WHERE sequence=1",
            [],
        );
        assert!(update.is_err());
        let delete = store
            .connection
            .execute("DELETE FROM event_journal WHERE sequence=1", []);
        assert!(delete.is_err());
    }
}
