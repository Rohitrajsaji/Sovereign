//! Authoritative `SQLite` state foundation for Sovereign.
//!
//! This milestone intentionally provides persistence primitives rather than
//! Controller semantics.  Current state lives in normalized records while an
//! append-only journal preserves ordered transition evidence.

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use sovereign_types::UnixMillis;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::time::Duration;

const FOUNDATION_SQL: &str = include_str!("../migrations/0001_foundation.sql");
const ARTIFACTS_SQL: &str = include_str!("../migrations/0002_artifacts.sql");
const SECURITY_KERNEL_SQL: &str = include_str!("../migrations/0003_security_kernel.sql");

/// Current durable schema version implemented by this crate.
pub const CURRENT_SCHEMA_VERSION: i64 = 3;

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
    pub last_event_sequence: i64,
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
            "SELECT action_id, state, payload_digest, policy_digest, execution_epoch, last_event_sequence, updated_at_ms FROM action_records WHERE action_id=?1",
            [action_id],
            |row| Ok(PersistedActionRecord { action_id: row.get(0)?, state: row.get(1)?, payload_digest: row.get(2)?, policy_digest: row.get(3)?, execution_epoch: row.get(4)?, last_event_sequence: row.get(5)?, updated_at_ms: row.get(6)? }),
        ).optional()?)
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
                "UPDATE action_records SET state=?2, last_event_sequence=?3, updated_at_ms=?4 WHERE action_id=?1",
                (transition.action_id, transition.next_state, sequence, now),
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
        let mut statement = self.connection.prepare("SELECT generation, previous_hash, checkpoint_hash, payload_digest, action_sequence, created_at_ms FROM checkpoint_integrity ORDER BY generation ASC")?;
        let rows = statement.query_map([], checkpoint_from_row)?;
        let mut previous_hash: Option<String> = None;
        let mut expected_generation = 1_i64;
        let mut latest_valid = None;
        for row in rows {
            let record = row?;
            let valid = record.generation == expected_generation
                && record.previous_hash == previous_hash
                && record.checkpoint_hash
                    == checkpoint_hash(
                        record.generation,
                        record.previous_hash.as_deref(),
                        &record.payload_digest,
                        record.action_sequence,
                    );
            if !valid {
                break;
            }
            previous_hash = Some(record.checkpoint_hash.clone());
            expected_generation += 1;
            latest_valid = Some(record);
        }
        let row_count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM checkpoint_integrity", [], |row| {
                    row.get(0)
                })?;
        if row_count > 0 && latest_valid.is_none() {
            return Err(StateError::Integrity(
                "checkpoint chain has no valid generation".to_owned(),
            ));
        }
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
    fn failed_migration_rolls_back_and_prior_backup_remains_readable() {
        const BROKEN: Migration = Migration {
            version: 4,
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
