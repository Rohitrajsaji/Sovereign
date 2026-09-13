//! Canonical provenance-aware durable memory lifecycle for Sovereign.
//!
//! Memory is evidence, never authority.  This crate owns typed memory semantics
//! while [`sovereign_state::StateStore`] remains the one durable `SQLite`
//! authority.  M4-T01 deliberately does not add lexical/semantic retrieval;
//! it only exposes a bounded lifecycle-level view of records that are safe for
//! later context injection.

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sovereign_state::{StateError, StateStore};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

/// Durable schema version for the public `MemoryRecord` contract.
pub const MEMORY_RECORD_SCHEMA_VERSION: u32 = 1;

/// `SQLite` schema version that first contains canonical memory tables.
pub const MEMORY_STATE_SCHEMA_VERSION: i64 = 4;

/// Typed durable memory classes from the frozen architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    GovernedKnowledge,
    ValidatedProjectFact,
    Episodic,
    ProceduralCandidate,
    PreferenceContext,
}

impl MemoryKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GovernedKnowledge => "governed_knowledge",
            Self::ValidatedProjectFact => "validated_project_fact",
            Self::Episodic => "episodic",
            Self::ProceduralCandidate => "procedural_candidate",
            Self::PreferenceContext => "preference_context",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "governed_knowledge" => Ok(Self::GovernedKnowledge),
            "validated_project_fact" => Ok(Self::ValidatedProjectFact),
            "episodic" => Ok(Self::Episodic),
            "procedural_candidate" => Ok(Self::ProceduralCandidate),
            "preference_context" => Ok(Self::PreferenceContext),
            other => Err(StateError::Integrity(format!(
                "unknown durable memory kind {other:?}"
            ))),
        }
    }
}

/// Scope class for one durable memory.
///
/// `Shared` means shared between agents/roles inside the named project.  It is
/// intentionally not a cross-project global scope, preserving project
/// isolation by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScopeKind {
    Project,
    Agent,
    Shared,
}

impl MemoryScopeKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Agent => "agent",
            Self::Shared => "shared",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "project" => Ok(Self::Project),
            "agent" => Ok(Self::Agent),
            "shared" => Ok(Self::Shared),
            other => Err(StateError::Integrity(format!(
                "unknown durable memory scope {other:?}"
            ))),
        }
    }
}

/// Uniform project/agent/shared scope and role visibility envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryScope {
    pub project_id: String,
    pub kind: MemoryScopeKind,
    pub agent_id: Option<String>,
    /// Empty means visible to every role otherwise permitted by this scope.
    pub role_visibility: Vec<String>,
}

/// Provenance trust attached to a memory record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTrust {
    Governed,
    Validated,
    Observed,
    Unreviewed,
}

impl MemoryTrust {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Governed => "governed",
            Self::Validated => "validated",
            Self::Observed => "observed",
            Self::Unreviewed => "unreviewed",
        }
    }

    const fn precedence(self) -> u8 {
        match self {
            Self::Governed => 4,
            Self::Validated => 3,
            Self::Observed => 2,
            Self::Unreviewed => 1,
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "governed" => Ok(Self::Governed),
            "validated" => Ok(Self::Validated),
            "observed" => Ok(Self::Observed),
            "unreviewed" => Ok(Self::Unreviewed),
            other => Err(StateError::Integrity(format!(
                "unknown durable memory trust {other:?}"
            ))),
        }
    }
}

/// Durable lifecycle status.  Conflict is orthogonal: two records can remain
/// `Active` while both point to an unresolved conflict set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    Active,
    Stale,
    Superseded,
    Deprecated,
    Expired,
    Archived,
}

impl MemoryStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Superseded => "superseded",
            Self::Deprecated => "deprecated",
            Self::Expired => "expired",
            Self::Archived => "archived",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "active" => Ok(Self::Active),
            "stale" => Ok(Self::Stale),
            "superseded" => Ok(Self::Superseded),
            "deprecated" => Ok(Self::Deprecated),
            "expired" => Ok(Self::Expired),
            "archived" => Ok(Self::Archived),
            other => Err(StateError::Integrity(format!(
                "unknown durable memory status {other:?}"
            ))),
        }
    }
}

/// Smallest practical source keys used to invalidate repository-derived facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFingerprintKind {
    FileBlob,
    Symbol,
    DependencyManifest,
    CommandToolVersion,
    RepositoryCommitRange,
}

impl SourceFingerprintKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FileBlob => "file_blob",
            Self::Symbol => "symbol",
            Self::DependencyManifest => "dependency_manifest",
            Self::CommandToolVersion => "command_tool_version",
            Self::RepositoryCommitRange => "repository_commit_range",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "file_blob" => Ok(Self::FileBlob),
            "symbol" => Ok(Self::Symbol),
            "dependency_manifest" => Ok(Self::DependencyManifest),
            "command_tool_version" => Ok(Self::CommandToolVersion),
            "repository_commit_range" => Ok(Self::RepositoryCommitRange),
            other => Err(StateError::Integrity(format!(
                "unknown durable source fingerprint kind {other:?}"
            ))),
        }
    }
}

/// One exact source fingerprint bound to memory provenance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceFingerprint {
    pub kind: SourceFingerprintKind,
    pub key: String,
    pub digest: String,
}

/// Governed invalidation predicate retained with every memory class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationPredicateKind {
    FingerprintChanged,
    RepositoryRevisionChanged,
    ExpiresAt,
}

impl InvalidationPredicateKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FingerprintChanged => "fingerprint_changed",
            Self::RepositoryRevisionChanged => "repository_revision_changed",
            Self::ExpiresAt => "expires_at",
        }
    }

    fn parse(value: &str) -> Result<Self, StateError> {
        match value {
            "fingerprint_changed" => Ok(Self::FingerprintChanged),
            "repository_revision_changed" => Ok(Self::RepositoryRevisionChanged),
            "expires_at" => Ok(Self::ExpiresAt),
            other => Err(StateError::Integrity(format!(
                "unknown durable invalidation predicate kind {other:?}"
            ))),
        }
    }
}

/// One deterministic invalidation condition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvalidationPredicate {
    pub kind: InvalidationPredicateKind,
    pub key: String,
    pub expected_value: Option<String>,
}

/// Uniform provenance carried by every memory class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProvenance {
    pub source_evidence_ids: Vec<String>,
    pub producing_task_id: Option<String>,
    pub producing_attempt_id: Option<String>,
    pub repository_id: Option<String>,
    pub repository_revision: Option<String>,
    pub source_fingerprints: Vec<SourceFingerprint>,
}

/// Canonical durable memory record contract v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub schema_version: u32,
    pub id: String,
    pub kind: MemoryKind,
    pub scope: MemoryScope,
    pub subject: String,
    pub predicate: String,
    pub assertion: String,
    pub trust: MemoryTrust,
    pub confidence: f64,
    pub status: MemoryStatus,
    pub provenance: MemoryProvenance,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub validated_at_ms: Option<i64>,
    pub version: u64,
    pub supersedes: Option<String>,
    pub superseded_by: Option<String>,
    pub expires_at_ms: Option<i64>,
    pub invalidation_predicates: Vec<InvalidationPredicate>,
    pub access_count: u64,
    pub last_accessed_at_ms: Option<i64>,
    pub conflict_set_id: Option<String>,
    pub normal_injection: bool,
    pub exclusion_reason: Option<String>,
}

/// Caller-owned input for first capture of a durable memory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewMemoryRecord {
    pub id: String,
    pub kind: MemoryKind,
    pub scope: MemoryScope,
    pub subject: String,
    pub predicate: String,
    pub assertion: String,
    pub trust: MemoryTrust,
    pub confidence: f64,
    pub provenance: MemoryProvenance,
    pub expires_at_ms: Option<i64>,
    pub invalidation_predicates: Vec<InvalidationPredicate>,
}

/// Access envelope used only to prove lifecycle/scope eligibility at M4-T01.
/// Lexical ranking and compact synopses belong to M4-T02.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccessScope<'a> {
    pub project_id: &'a str,
    pub agent_id: Option<&'a str>,
    pub role_id: Option<&'a str>,
}

/// One exact fingerprint update published after repository refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintChange {
    pub kind: SourceFingerprintKind,
    pub key: String,
    /// `None` means the source disappeared and every record bound to this key
    /// is stale.  `Some` only invalidates records whose stored digest differs.
    pub current_digest: Option<String>,
}

/// Memory-facing repository delta publication.  It carries only exact
/// fingerprint/revision facts; it does not duplicate repository truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRepositoryDelta {
    pub repository_id: String,
    pub current_revision: Option<String>,
    pub changed_fingerprints: Vec<FingerprintChange>,
}

/// Durable unresolved/resolved contradiction set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryConflictSet {
    pub id: String,
    pub project_id: String,
    pub repository_id: Option<String>,
    pub subject: String,
    pub predicate: String,
    pub created_at_ms: i64,
    pub resolved_at_ms: Option<i64>,
    pub member_ids: Vec<String>,
}

/// Memory-layer failures.  Deterministic validation errors are separated from
/// SQLite/state failures for clear Controller diagnostics.
#[derive(Debug)]
pub enum MemoryError {
    InvalidRecord(String),
    NotFound(String),
    InvalidTransition(String),
    State(StateError),
}

impl Display for MemoryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecord(message) => write!(f, "invalid memory record: {message}"),
            Self::NotFound(id) => write!(f, "memory record {id:?} was not found"),
            Self::InvalidTransition(message) => {
                write!(f, "invalid memory lifecycle transition: {message}")
            }
            Self::State(error) => write!(f, "memory durable-state error: {error}"),
        }
    }
}

impl Error for MemoryError {}

impl From<StateError> for MemoryError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

/// Canonical lifecycle mutation surface introduced by M4-T01.
pub trait MemoryLifecycle {
    /// Captures one new record and deterministically reconciles contradictions.
    ///
    /// # Errors
    /// Returns an error for invalid provenance/scope, contradictory governed
    /// truth without explicit supersession, or durable-state failure.
    fn capture(
        &mut self,
        record: NewMemoryRecord,
        now_ms: i64,
    ) -> Result<MemoryRecord, MemoryError>;

    /// Explicit governed replacement.  A governed contradiction may never
    /// silently become parallel active truth.
    ///
    /// # Errors
    /// Returns an error unless the previous record is active governed truth
    /// with the same identity envelope, or when durable persistence fails.
    fn replace_governed(
        &mut self,
        previous_id: &str,
        replacement: NewMemoryRecord,
        now_ms: i64,
    ) -> Result<MemoryRecord, MemoryError>;

    /// Applies exact repository fingerprint/revision changes before later
    /// retrieval can inject obsolete facts.
    ///
    /// # Errors
    /// Returns an error for malformed delta facts or durable-state failure.
    fn apply_repository_delta(
        &mut self,
        delta: &MemoryRepositoryDelta,
        now_ms: i64,
    ) -> Result<Vec<String>, MemoryError>;

    /// Materializes due TTL expiry into durable status.
    ///
    /// # Errors
    /// Returns an error for an invalid timestamp or durable-state failure.
    fn expire_due(&mut self, now_ms: i64) -> Result<Vec<String>, MemoryError>;

    /// Deprecates a current record without deleting its provenance.
    ///
    /// # Errors
    /// Returns an error for an unknown/invalid transition or durable-state
    /// failure.
    fn deprecate(&mut self, memory_id: &str, now_ms: i64) -> Result<(), MemoryError>;

    /// Archives a record as retained history.
    ///
    /// # Errors
    /// Returns an error for an unknown/invalid transition or durable-state
    /// failure.
    fn archive(&mut self, memory_id: &str, now_ms: i64) -> Result<(), MemoryError>;
}

/// Provenance/freshness-governed memory manager backed by canonical
/// [`StateStore`] tables.
pub struct MemoryManager {
    state: StateStore,
}

impl MemoryManager {
    /// Opens the canonical state database and constructs the memory manager.
    ///
    /// # Errors
    /// Returns a durable-state error if opening/migrating the database fails.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MemoryError> {
        Self::new(StateStore::open(path)?)
    }

    /// Binds memory semantics to an existing canonical state store.
    ///
    /// # Errors
    /// Fails closed if the required memory migration is not present.
    pub fn new(state: StateStore) -> Result<Self, MemoryError> {
        let version = state.schema_version()?;
        if version < MEMORY_STATE_SCHEMA_VERSION {
            return Err(MemoryError::InvalidRecord(format!(
                "state schema {version} predates required memory schema {MEMORY_STATE_SCHEMA_VERSION}"
            )));
        }
        Ok(Self { state })
    }

    /// Returns one durable record by ID.
    ///
    /// # Errors
    /// Returns a durable-state error for malformed/corrupt rows or `SQLite`
    /// failures.
    pub fn record(&mut self, memory_id: &str) -> Result<Option<MemoryRecord>, MemoryError> {
        let record = self.state.transaction(|tx| load_record_tx(tx, memory_id))?;
        Ok(record)
    }

    /// Returns one durable conflict set and its stable member list.
    ///
    /// # Errors
    /// Returns a durable-state error for malformed/corrupt rows or `SQLite`
    /// failures.
    pub fn conflict_set(
        &mut self,
        conflict_set_id: &str,
    ) -> Result<Option<MemoryConflictSet>, MemoryError> {
        Ok(self
            .state
            .transaction(|tx| load_conflict_set_tx(tx, conflict_set_id))?)
    }

    /// Returns only active, fresh, non-conflicted, non-demoted records visible
    /// in the requested project/agent/role scope.  This is an eligibility view,
    /// not M4-T02 lexical retrieval.
    ///
    /// # Errors
    /// Returns an error when expiry reconciliation or durable reads fail.
    pub fn injectable_records(
        &mut self,
        access: MemoryAccessScope<'_>,
        now_ms: i64,
    ) -> Result<Vec<MemoryRecord>, MemoryError> {
        validate_nonempty("access project_id", access.project_id)?;
        let _ = self.expire_due(now_ms)?;
        let project_id = access.project_id.to_owned();
        let records = self.state.transaction(|tx| {
            let mut statement = tx.prepare(
                "SELECT memory_id FROM memory_records \
                 WHERE project_id=?1 AND status='active' AND normal_injection=1 \
                   AND conflict_set_id IS NULL \
                   AND (expires_at_ms IS NULL OR expires_at_ms>?2) \
                 ORDER BY memory_id ASC",
            )?;
            let rows =
                statement.query_map(params![project_id, now_ms], |row| row.get::<_, String>(0))?;
            let mut ids: Vec<String> = Vec::new();
            for row in rows {
                ids.push(row?);
            }
            drop(statement);
            let mut records = Vec::with_capacity(ids.len());
            for id in ids {
                let record = load_record_tx(tx, &id)?.ok_or_else(|| {
                    StateError::Integrity(format!(
                        "eligible memory {id} disappeared inside snapshot transaction"
                    ))
                })?;
                records.push(record);
            }
            Ok(records)
        })?;
        Ok(records
            .into_iter()
            .filter(|record| scope_permits(&record.scope, access))
            .collect())
    }

    fn transition_status(
        &mut self,
        memory_id: &str,
        next: MemoryStatus,
        reason: &'static str,
        allowed_current: &[MemoryStatus],
        now_ms: i64,
    ) -> Result<(), MemoryError> {
        validate_timestamp(now_ms)?;
        let id = memory_id.to_owned();
        let conflict_id = self.state.transaction(|tx| {
            let current = load_record_tx(tx, &id)?
                .ok_or_else(|| StateError::Integrity(format!("unknown memory {id}")))?;
            if !allowed_current.contains(&current.status) {
                return Err(StateError::Integrity(format!(
                    "memory {id} cannot transition from {} to {}",
                    current.status.as_str(),
                    next.as_str(),
                )));
            }
            tx.execute(
                "UPDATE memory_records SET status=?2, updated_at_ms=?3, normal_injection=0, exclusion_reason=?4 WHERE memory_id=?1",
                params![id, next.as_str(), now_ms, reason],
            )?;
            Ok(current.conflict_set_id)
        })?;
        if let Some(conflict_id) = conflict_id {
            self.state
                .transaction(|tx| resolve_conflict_if_unambiguous(tx, &conflict_id, now_ms))?;
        }
        Ok(())
    }
}

impl MemoryLifecycle for MemoryManager {
    fn capture(
        &mut self,
        mut record: NewMemoryRecord,
        now_ms: i64,
    ) -> Result<MemoryRecord, MemoryError> {
        normalize_new_record(&mut record);
        validate_new_record(&record, now_ms)?;
        let id = record.id.clone();
        self.state.transaction(|tx| {
            insert_record_tx(tx, &record, now_ms, 1, None)?;
            reconcile_contradictions_tx(tx, &id, now_ms)?;
            Ok(())
        })?;
        self.record(&id)?.ok_or_else(|| {
            MemoryError::State(StateError::Integrity(format!(
                "captured memory {id} is missing"
            )))
        })
    }

    fn replace_governed(
        &mut self,
        previous_id: &str,
        mut replacement: NewMemoryRecord,
        now_ms: i64,
    ) -> Result<MemoryRecord, MemoryError> {
        normalize_new_record(&mut replacement);
        validate_new_record(&replacement, now_ms)?;
        if replacement.kind != MemoryKind::GovernedKnowledge
            || replacement.trust != MemoryTrust::Governed
        {
            return Err(MemoryError::InvalidTransition(
                "governed replacement requires governed_knowledge with governed trust".to_owned(),
            ));
        }
        let previous_id = previous_id.to_owned();
        let replacement_id = replacement.id.clone();
        if previous_id == replacement_id {
            return Err(MemoryError::InvalidTransition(
                "replacement must use a new immutable memory id".to_owned(),
            ));
        }
        let conflict_to_reconcile = self.state.transaction(|tx| {
            let previous = load_record_tx(tx, &previous_id)?
                .ok_or_else(|| StateError::Integrity(format!("unknown memory {previous_id}")))?;
            if previous.kind != MemoryKind::GovernedKnowledge
                || previous.trust != MemoryTrust::Governed
                || previous.status != MemoryStatus::Active
                || previous.superseded_by.is_some()
            {
                return Err(StateError::Integrity(format!(
                    "memory {previous_id} is not an active unsuperseded governed record"
                )));
            }
            if previous.scope != replacement.scope
                || previous.subject != replacement.subject
                || previous.predicate != replacement.predicate
                || previous.provenance.repository_id != replacement.provenance.repository_id
            {
                return Err(StateError::Integrity(
                    "governed replacement must retain scope/repository/subject/predicate identity"
                        .to_owned(),
                ));
            }
            let next_version = previous
                .version
                .checked_add(1)
                .ok_or_else(|| StateError::Integrity("memory version overflow".to_owned()))?;
            insert_record_tx(
                tx,
                &replacement,
                now_ms,
                next_version,
                Some(&previous_id),
            )?;
            tx.execute(
                "UPDATE memory_records SET status='superseded', superseded_by_id=?2, updated_at_ms=?3, normal_injection=0, exclusion_reason='superseded' WHERE memory_id=?1",
                params![previous_id, replacement_id, now_ms],
            )?;
            reconcile_contradictions_tx(tx, &replacement_id, now_ms)?;
            Ok(previous.conflict_set_id)
        })?;
        if let Some(conflict_id) = conflict_to_reconcile {
            self.state
                .transaction(|tx| resolve_conflict_if_unambiguous(tx, &conflict_id, now_ms))?;
        }
        self.record(&replacement_id)?.ok_or_else(|| {
            MemoryError::State(StateError::Integrity(format!(
                "replacement memory {replacement_id} is missing"
            )))
        })
    }

    fn apply_repository_delta(
        &mut self,
        delta: &MemoryRepositoryDelta,
        now_ms: i64,
    ) -> Result<Vec<String>, MemoryError> {
        validate_timestamp(now_ms)?;
        validate_nonempty("repository_id", &delta.repository_id)?;
        for change in &delta.changed_fingerprints {
            validate_nonempty("fingerprint key", &change.key)?;
            if let Some(digest) = change.current_digest.as_deref() {
                validate_nonempty("current fingerprint digest", digest)?;
            }
        }
        let repository_id = delta.repository_id.clone();
        let current_revision = delta.current_revision.clone();
        let changes = delta.changed_fingerprints.clone();
        let (stale_ids, conflict_ids) = self.state.transaction(|tx| {
            let mut stale_ids = BTreeSet::new();
            for change in &changes {
                let mut statement = tx.prepare(
                    "SELECT r.memory_id \
                     FROM memory_records r \
                     JOIN memory_source_fingerprints f ON f.memory_id=r.memory_id \
                     WHERE r.repository_id=?1 AND r.status='active' \
                       AND f.fingerprint_kind=?2 AND f.fingerprint_key=?3 \
                       AND (?4 IS NULL OR f.fingerprint_digest<>?4) \
                     ORDER BY r.memory_id ASC",
                )?;
                let rows = statement.query_map(
                    params![
                        repository_id,
                        change.kind.as_str(),
                        change.key,
                        change.current_digest
                    ],
                    |row| row.get::<_, String>(0),
                )?;
                for row in rows {
                    stale_ids.insert(row?);
                }
            }
            if let Some(revision) = current_revision.as_deref() {
                let mut statement = tx.prepare(
                    "SELECT DISTINCT r.memory_id \
                     FROM memory_records r \
                     JOIN memory_invalidation_predicates p ON p.memory_id=r.memory_id \
                     WHERE r.repository_id=?1 AND r.status='active' \
                       AND r.repository_revision IS NOT NULL AND r.repository_revision<>?2 \
                       AND p.predicate_kind='repository_revision_changed' \
                     ORDER BY r.memory_id ASC",
                )?;
                let rows = statement.query_map(params![repository_id, revision], |row| row.get(0))?;
                for row in rows {
                    stale_ids.insert(row?);
                }
            }

            let mut conflicts = BTreeSet::new();
            for id in &stale_ids {
                let conflict_id: Option<String> = tx
                    .query_row(
                        "SELECT conflict_set_id FROM memory_records WHERE memory_id=?1",
                        [id],
                        |row| row.get(0),
                    )
                    .optional()?
                    .flatten();
                if let Some(conflict_id) = conflict_id {
                    conflicts.insert(conflict_id);
                }
                tx.execute(
                    "UPDATE memory_records SET status='stale', updated_at_ms=?2, normal_injection=0, exclusion_reason='source_fingerprint_changed' WHERE memory_id=?1",
                    params![id, now_ms],
                )?;
            }
            Ok((stale_ids.into_iter().collect::<Vec<_>>(), conflicts))
        })?;
        for conflict_id in conflict_ids {
            self.state
                .transaction(|tx| resolve_conflict_if_unambiguous(tx, &conflict_id, now_ms))?;
        }
        Ok(stale_ids)
    }

    fn expire_due(&mut self, now_ms: i64) -> Result<Vec<String>, MemoryError> {
        validate_timestamp(now_ms)?;
        let (expired, conflicts) = self.state.transaction(|tx| {
            let mut statement = tx.prepare(
                "SELECT memory_id, conflict_set_id FROM memory_records \
                 WHERE status='active' AND expires_at_ms IS NOT NULL AND expires_at_ms<=?1 \
                 ORDER BY memory_id ASC",
            )?;
            let rows = statement.query_map([now_ms], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?;
            let mut expired = Vec::new();
            let mut conflicts = BTreeSet::new();
            for row in rows {
                let (id, conflict_id) = row?;
                expired.push(id);
                if let Some(conflict_id) = conflict_id {
                    conflicts.insert(conflict_id);
                }
            }
            for id in &expired {
                tx.execute(
                    "UPDATE memory_records SET status='expired', updated_at_ms=?2, normal_injection=0, exclusion_reason='expired' WHERE memory_id=?1",
                    params![id, now_ms],
                )?;
            }
            Ok((expired, conflicts))
        })?;
        for conflict_id in conflicts {
            self.state
                .transaction(|tx| resolve_conflict_if_unambiguous(tx, &conflict_id, now_ms))?;
        }
        Ok(expired)
    }

    fn deprecate(&mut self, memory_id: &str, now_ms: i64) -> Result<(), MemoryError> {
        self.transition_status(
            memory_id,
            MemoryStatus::Deprecated,
            "deprecated",
            &[MemoryStatus::Active, MemoryStatus::Stale],
            now_ms,
        )
    }

    fn archive(&mut self, memory_id: &str, now_ms: i64) -> Result<(), MemoryError> {
        self.transition_status(
            memory_id,
            MemoryStatus::Archived,
            "archived",
            &[
                MemoryStatus::Stale,
                MemoryStatus::Superseded,
                MemoryStatus::Deprecated,
                MemoryStatus::Expired,
            ],
            now_ms,
        )
    }
}

fn normalize_new_record(record: &mut NewMemoryRecord) {
    record.scope.role_visibility.sort();
    record.scope.role_visibility.dedup();
    record.provenance.source_evidence_ids.sort();
    record.provenance.source_evidence_ids.dedup();
    record.provenance.source_fingerprints.sort();
    record.provenance.source_fingerprints.dedup();
    record.invalidation_predicates.sort();
    record.invalidation_predicates.dedup();
}

fn validate_new_record(record: &NewMemoryRecord, now_ms: i64) -> Result<(), MemoryError> {
    validate_timestamp(now_ms)?;
    for (field, value) in [
        ("id", record.id.as_str()),
        ("project_id", record.scope.project_id.as_str()),
        ("subject", record.subject.as_str()),
        ("predicate", record.predicate.as_str()),
        ("assertion", record.assertion.as_str()),
    ] {
        validate_nonempty(field, value)?;
    }
    match record.scope.kind {
        MemoryScopeKind::Agent => {
            let agent = record.scope.agent_id.as_deref().ok_or_else(|| {
                MemoryError::InvalidRecord("agent scope requires agent_id".to_owned())
            })?;
            validate_nonempty("agent_id", agent)?;
        }
        MemoryScopeKind::Project | MemoryScopeKind::Shared => {
            if record.scope.agent_id.is_some() {
                return Err(MemoryError::InvalidRecord(
                    "only agent scope may carry agent_id".to_owned(),
                ));
            }
        }
    }
    for role in &record.scope.role_visibility {
        validate_nonempty("role_visibility", role)?;
    }
    if !record.confidence.is_finite() || !(0.0..=1.0).contains(&record.confidence) {
        return Err(MemoryError::InvalidRecord(
            "confidence must be finite and within 0..=1".to_owned(),
        ));
    }
    if record.kind == MemoryKind::GovernedKnowledge && record.trust != MemoryTrust::Governed {
        return Err(MemoryError::InvalidRecord(
            "governed_knowledge requires governed trust".to_owned(),
        ));
    }
    if record.kind == MemoryKind::ValidatedProjectFact && record.trust != MemoryTrust::Validated {
        return Err(MemoryError::InvalidRecord(
            "validated_project_fact requires validated trust".to_owned(),
        ));
    }
    if matches!(record.trust, MemoryTrust::Governed | MemoryTrust::Validated)
        && record.provenance.source_evidence_ids.is_empty()
    {
        return Err(MemoryError::InvalidRecord(
            "governed/validated memory requires explicit source evidence provenance".to_owned(),
        ));
    }
    if record.trust == MemoryTrust::Validated
        && record.provenance.repository_id.is_some()
        && record.provenance.source_fingerprints.is_empty()
    {
        return Err(MemoryError::InvalidRecord(
            "repository-backed validated memory requires a source fingerprint".to_owned(),
        ));
    }
    if record.provenance.repository_revision.is_some() && record.provenance.repository_id.is_none()
    {
        return Err(MemoryError::InvalidRecord(
            "repository_revision requires repository_id".to_owned(),
        ));
    }
    if let Some(expires_at) = record.expires_at_ms
        && expires_at <= now_ms
    {
        return Err(MemoryError::InvalidRecord(
            "new memory expiry must be in the future".to_owned(),
        ));
    }
    for evidence_id in &record.provenance.source_evidence_ids {
        validate_nonempty("source evidence id", evidence_id)?;
    }
    for fingerprint in &record.provenance.source_fingerprints {
        validate_nonempty("fingerprint key", &fingerprint.key)?;
        validate_nonempty("fingerprint digest", &fingerprint.digest)?;
    }
    for predicate in &record.invalidation_predicates {
        validate_nonempty("invalidation predicate key", &predicate.key)?;
    }
    Ok(())
}

fn validate_nonempty(field: &str, value: &str) -> Result<(), MemoryError> {
    if value.trim().is_empty() {
        return Err(MemoryError::InvalidRecord(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn validate_timestamp(value: i64) -> Result<(), MemoryError> {
    if value < 0 {
        return Err(MemoryError::InvalidRecord(
            "timestamp must be non-negative".to_owned(),
        ));
    }
    Ok(())
}

fn insert_record_tx(
    tx: &Transaction<'_>,
    record: &NewMemoryRecord,
    now_ms: i64,
    version: u64,
    supersedes: Option<&str>,
) -> Result<(), StateError> {
    let version = i64::try_from(version)
        .map_err(|_| StateError::Integrity("memory version exceeds SQLite INTEGER".to_owned()))?;
    let validated_at = (record.trust == MemoryTrust::Validated).then_some(now_ms);
    tx.execute(
        "INSERT INTO memory_records(\
            memory_id, kind, project_id, scope_kind, agent_id, subject, predicate, assertion, \
            trust, confidence, status, repository_id, repository_revision, producing_task_id, \
            producing_attempt_id, created_at_ms, updated_at_ms, validated_at_ms, version, \
            supersedes_id, expires_at_ms, normal_injection\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'active', ?11, ?12, ?13, ?14, ?15, ?15, ?16, ?17, ?18, ?19, 1)",
        params![
            record.id,
            record.kind.as_str(),
            record.scope.project_id,
            record.scope.kind.as_str(),
            record.scope.agent_id,
            record.subject,
            record.predicate,
            record.assertion,
            record.trust.as_str(),
            record.confidence,
            record.provenance.repository_id,
            record.provenance.repository_revision,
            record.provenance.producing_task_id,
            record.provenance.producing_attempt_id,
            now_ms,
            validated_at,
            version,
            supersedes,
            record.expires_at_ms,
        ],
    )?;
    for role in &record.scope.role_visibility {
        tx.execute(
            "INSERT INTO memory_role_visibility(memory_id, role_id) VALUES (?1, ?2)",
            params![record.id, role],
        )?;
    }
    for evidence_id in &record.provenance.source_evidence_ids {
        tx.execute(
            "INSERT INTO memory_source_evidence(memory_id, evidence_id) VALUES (?1, ?2)",
            params![record.id, evidence_id],
        )?;
    }
    for fingerprint in &record.provenance.source_fingerprints {
        tx.execute(
            "INSERT INTO memory_source_fingerprints(memory_id, fingerprint_kind, fingerprint_key, fingerprint_digest) VALUES (?1, ?2, ?3, ?4)",
            params![
                record.id,
                fingerprint.kind.as_str(),
                fingerprint.key,
                fingerprint.digest
            ],
        )?;
    }
    for predicate in &record.invalidation_predicates {
        tx.execute(
            "INSERT INTO memory_invalidation_predicates(memory_id, predicate_kind, predicate_key, expected_value) VALUES (?1, ?2, ?3, ?4)",
            params![
                record.id,
                predicate.kind.as_str(),
                predicate.key,
                predicate.expected_value
            ],
        )?;
    }
    Ok(())
}

struct StoredMemoryRow {
    id: String,
    kind: String,
    project_id: String,
    scope_kind: String,
    agent_id: Option<String>,
    subject: String,
    predicate: String,
    assertion: String,
    trust: String,
    confidence: f64,
    status: String,
    repository_id: Option<String>,
    repository_revision: Option<String>,
    producing_task_id: Option<String>,
    producing_attempt_id: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
    validated_at_ms: Option<i64>,
    version: i64,
    supersedes: Option<String>,
    superseded_by: Option<String>,
    expires_at_ms: Option<i64>,
    access_count: i64,
    last_accessed_at_ms: Option<i64>,
    conflict_set_id: Option<String>,
    normal_injection: i64,
    exclusion_reason: Option<String>,
}

fn stored_memory_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMemoryRow> {
    Ok(StoredMemoryRow {
        id: row.get(0)?,
        kind: row.get(1)?,
        project_id: row.get(2)?,
        scope_kind: row.get(3)?,
        agent_id: row.get(4)?,
        subject: row.get(5)?,
        predicate: row.get(6)?,
        assertion: row.get(7)?,
        trust: row.get(8)?,
        confidence: row.get(9)?,
        status: row.get(10)?,
        repository_id: row.get(11)?,
        repository_revision: row.get(12)?,
        producing_task_id: row.get(13)?,
        producing_attempt_id: row.get(14)?,
        created_at_ms: row.get(15)?,
        updated_at_ms: row.get(16)?,
        validated_at_ms: row.get(17)?,
        version: row.get(18)?,
        supersedes: row.get(19)?,
        superseded_by: row.get(20)?,
        expires_at_ms: row.get(21)?,
        access_count: row.get(22)?,
        last_accessed_at_ms: row.get(23)?,
        conflict_set_id: row.get(24)?,
        normal_injection: row.get(25)?,
        exclusion_reason: row.get(26)?,
    })
}

fn load_record_tx(
    tx: &Transaction<'_>,
    memory_id: &str,
) -> Result<Option<MemoryRecord>, StateError> {
    let stored = tx
        .query_row(
            "SELECT memory_id, kind, project_id, scope_kind, agent_id, subject, predicate, assertion, \
                    trust, confidence, status, repository_id, repository_revision, producing_task_id, \
                    producing_attempt_id, created_at_ms, updated_at_ms, validated_at_ms, version, \
                    supersedes_id, superseded_by_id, expires_at_ms, access_count, last_accessed_at_ms, \
                    conflict_set_id, normal_injection, exclusion_reason \
             FROM memory_records WHERE memory_id=?1",
            [memory_id],
            stored_memory_row,
        )
        .optional()?;
    stored.map(|row| build_memory_record(tx, row)).transpose()
}

fn build_memory_record(
    tx: &Transaction<'_>,
    row: StoredMemoryRow,
) -> Result<MemoryRecord, StateError> {
    let role_visibility = string_children(
        tx,
        "SELECT role_id FROM memory_role_visibility WHERE memory_id=?1 ORDER BY role_id ASC",
        &row.id,
    )?;
    let source_evidence_ids = string_children(
        tx,
        "SELECT evidence_id FROM memory_source_evidence WHERE memory_id=?1 ORDER BY evidence_id ASC",
        &row.id,
    )?;
    let source_fingerprints = fingerprint_children(tx, &row.id)?;
    let invalidation_predicates = invalidation_children(tx, &row.id)?;
    let version = u64::try_from(row.version)
        .map_err(|_| StateError::Integrity(format!("negative memory version for {}", row.id)))?;
    let access_count = u64::try_from(row.access_count).map_err(|_| {
        StateError::Integrity(format!("negative memory access count for {}", row.id))
    })?;
    Ok(MemoryRecord {
        schema_version: MEMORY_RECORD_SCHEMA_VERSION,
        id: row.id,
        kind: MemoryKind::parse(&row.kind)?,
        scope: MemoryScope {
            project_id: row.project_id,
            kind: MemoryScopeKind::parse(&row.scope_kind)?,
            agent_id: row.agent_id,
            role_visibility,
        },
        subject: row.subject,
        predicate: row.predicate,
        assertion: row.assertion,
        trust: MemoryTrust::parse(&row.trust)?,
        confidence: row.confidence,
        status: MemoryStatus::parse(&row.status)?,
        provenance: MemoryProvenance {
            source_evidence_ids,
            producing_task_id: row.producing_task_id,
            producing_attempt_id: row.producing_attempt_id,
            repository_id: row.repository_id,
            repository_revision: row.repository_revision,
            source_fingerprints,
        },
        created_at_ms: row.created_at_ms,
        updated_at_ms: row.updated_at_ms,
        validated_at_ms: row.validated_at_ms,
        version,
        supersedes: row.supersedes,
        superseded_by: row.superseded_by,
        expires_at_ms: row.expires_at_ms,
        invalidation_predicates,
        access_count,
        last_accessed_at_ms: row.last_accessed_at_ms,
        conflict_set_id: row.conflict_set_id,
        normal_injection: row.normal_injection == 1,
        exclusion_reason: row.exclusion_reason,
    })
}

fn string_children(
    tx: &Transaction<'_>,
    sql: &str,
    memory_id: &str,
) -> Result<Vec<String>, StateError> {
    let mut statement = tx.prepare(sql)?;
    let rows = statement.query_map([memory_id], |row| row.get(0))?;
    let mut values = Vec::new();
    for row in rows {
        values.push(row?);
    }
    Ok(values)
}

fn fingerprint_children(
    tx: &Transaction<'_>,
    memory_id: &str,
) -> Result<Vec<SourceFingerprint>, StateError> {
    let mut statement = tx.prepare(
        "SELECT fingerprint_kind, fingerprint_key, fingerprint_digest \
         FROM memory_source_fingerprints WHERE memory_id=?1 \
         ORDER BY fingerprint_kind ASC, fingerprint_key ASC",
    )?;
    let rows = statement.query_map([memory_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut values = Vec::new();
    for row in rows {
        let (kind, key, digest) = row?;
        values.push(SourceFingerprint {
            kind: SourceFingerprintKind::parse(&kind)?,
            key,
            digest,
        });
    }
    Ok(values)
}

fn invalidation_children(
    tx: &Transaction<'_>,
    memory_id: &str,
) -> Result<Vec<InvalidationPredicate>, StateError> {
    let mut statement = tx.prepare(
        "SELECT predicate_kind, predicate_key, expected_value \
         FROM memory_invalidation_predicates WHERE memory_id=?1 \
         ORDER BY predicate_kind ASC, predicate_key ASC",
    )?;
    let rows = statement.query_map([memory_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut values = Vec::new();
    for row in rows {
        let (kind, key, expected_value) = row?;
        values.push(InvalidationPredicate {
            kind: InvalidationPredicateKind::parse(&kind)?,
            key,
            expected_value,
        });
    }
    Ok(values)
}

fn reconcile_contradictions_tx(
    tx: &Transaction<'_>,
    memory_id: &str,
    now_ms: i64,
) -> Result<(), StateError> {
    let current = load_record_tx(tx, memory_id)?
        .ok_or_else(|| StateError::Integrity(format!("unknown memory {memory_id}")))?;
    let mut statement = tx.prepare(
        "SELECT memory_id FROM memory_records \
         WHERE memory_id<>?1 AND project_id=?2 AND scope_kind=?3 AND agent_id IS ?4 \
           AND repository_id IS ?5 AND subject=?6 AND predicate=?7 AND status='active' \
         ORDER BY memory_id ASC",
    )?;
    let rows = statement.query_map(
        params![
            current.id,
            current.scope.project_id,
            current.scope.kind.as_str(),
            current.scope.agent_id,
            current.provenance.repository_id,
            current.subject,
            current.predicate,
        ],
        |row| row.get::<_, String>(0),
    )?;
    let mut related_ids = Vec::new();
    for row in rows {
        related_ids.push(row?);
    }
    drop(statement);

    let current_assertion = normalized_assertion(&current.assertion);
    for related_id in related_ids {
        let Some(related) = load_record_tx(tx, &related_id)? else {
            continue;
        };
        if !role_scopes_overlap(
            &current.scope.role_visibility,
            &related.scope.role_visibility,
        ) || normalized_assertion(&related.assertion) == current_assertion
        {
            continue;
        }
        let current_rank = current.trust.precedence();
        let related_rank = related.trust.precedence();
        match current_rank.cmp(&related_rank) {
            Ordering::Equal => {
                if current.trust == MemoryTrust::Governed {
                    return Err(StateError::Integrity(format!(
                        "governed memory {} contradicts active governed memory {}; explicit supersession is required",
                        current.id, related.id
                    )));
                }
                create_or_extend_conflict_tx(tx, &current, &related, now_ms)?;
            }
            Ordering::Greater => {
                exclude_lower_trust_tx(tx, &related.id, current.trust, now_ms)?;
            }
            Ordering::Less => {
                exclude_lower_trust_tx(tx, &current.id, related.trust, now_ms)?;
            }
        }
    }
    Ok(())
}

fn exclude_lower_trust_tx(
    tx: &Transaction<'_>,
    memory_id: &str,
    higher_trust: MemoryTrust,
    now_ms: i64,
) -> Result<(), StateError> {
    let reason = format!("contradicts_{}", higher_trust.as_str());
    tx.execute(
        "UPDATE memory_records SET normal_injection=0, exclusion_reason=?2, updated_at_ms=?3 WHERE memory_id=?1 AND status='active'",
        params![memory_id, reason, now_ms],
    )?;
    Ok(())
}

fn create_or_extend_conflict_tx(
    tx: &Transaction<'_>,
    left: &MemoryRecord,
    right: &MemoryRecord,
    now_ms: i64,
) -> Result<(), StateError> {
    let conflict_id = left
        .conflict_set_id
        .clone()
        .or_else(|| right.conflict_set_id.clone())
        .unwrap_or_else(|| conflict_set_id(left));
    tx.execute(
        "INSERT OR IGNORE INTO memory_conflict_sets(conflict_set_id, project_id, repository_id, subject, predicate, created_at_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            conflict_id,
            left.scope.project_id,
            left.provenance.repository_id,
            left.subject,
            left.predicate,
            now_ms,
        ],
    )?;
    for id in [&left.id, &right.id] {
        tx.execute(
            "INSERT OR IGNORE INTO memory_conflict_members(conflict_set_id, memory_id) VALUES (?1, ?2)",
            params![conflict_id, id],
        )?;
        tx.execute(
            "UPDATE memory_records SET conflict_set_id=?2, normal_injection=0, exclusion_reason=COALESCE(exclusion_reason, 'conflict'), updated_at_ms=?3 WHERE memory_id=?1",
            params![id, conflict_id, now_ms],
        )?;
    }
    Ok(())
}

fn resolve_conflict_if_unambiguous(
    tx: &Transaction<'_>,
    conflict_set_id: &str,
    now_ms: i64,
) -> Result<(), StateError> {
    let mut statement = tx.prepare(
        "SELECT r.memory_id, r.exclusion_reason \
         FROM memory_conflict_members m \
         JOIN memory_records r ON r.memory_id=m.memory_id \
         WHERE m.conflict_set_id=?1 AND r.status='active' \
         ORDER BY r.memory_id ASC",
    )?;
    let rows = statement.query_map([conflict_set_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    let mut active = Vec::new();
    for row in rows {
        active.push(row?);
    }
    drop(statement);
    if active.len() > 1 {
        return Ok(());
    }
    tx.execute(
        "UPDATE memory_conflict_sets SET resolved_at_ms=COALESCE(resolved_at_ms, ?2) WHERE conflict_set_id=?1",
        params![conflict_set_id, now_ms],
    )?;
    if let Some((remaining_id, reason)) = active.first() {
        let was_only_conflict = reason.as_deref() == Some("conflict");
        tx.execute(
            "UPDATE memory_records SET conflict_set_id=NULL, normal_injection=?2, exclusion_reason=?3, updated_at_ms=?4 WHERE memory_id=?1",
            params![
                remaining_id,
                i64::from(was_only_conflict),
                if was_only_conflict { None::<String> } else { reason.clone() },
                now_ms
            ],
        )?;
    }
    Ok(())
}

fn load_conflict_set_tx(
    tx: &Transaction<'_>,
    conflict_set_id: &str,
) -> Result<Option<MemoryConflictSet>, StateError> {
    type ConflictScalar = (
        String,
        String,
        Option<String>,
        String,
        String,
        i64,
        Option<i64>,
    );
    let scalar: Option<ConflictScalar> = tx
        .query_row(
            "SELECT conflict_set_id, project_id, repository_id, subject, predicate, created_at_ms, resolved_at_ms \
             FROM memory_conflict_sets WHERE conflict_set_id=?1",
            [conflict_set_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((id, project_id, repository_id, subject, predicate, created_at_ms, resolved_at_ms)) =
        scalar
    else {
        return Ok(None);
    };
    let member_ids = string_children(
        tx,
        "SELECT memory_id FROM memory_conflict_members WHERE conflict_set_id=?1 ORDER BY memory_id ASC",
        &id,
    )?;
    Ok(Some(MemoryConflictSet {
        id,
        project_id,
        repository_id,
        subject,
        predicate,
        created_at_ms,
        resolved_at_ms,
        member_ids,
    }))
}

fn conflict_set_id(record: &MemoryRecord) -> String {
    let mut hasher = Sha256::new();
    for part in [
        record.scope.project_id.as_str(),
        record.scope.kind.as_str(),
        record.scope.agent_id.as_deref().unwrap_or(""),
        record.provenance.repository_id.as_deref().unwrap_or(""),
        record.subject.as_str(),
        record.predicate.as_str(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("conflict:sha256:{:x}", hasher.finalize())
}

fn normalized_assertion(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn role_scopes_overlap(left: &[String], right: &[String]) -> bool {
    left.is_empty()
        || right.is_empty()
        || left
            .iter()
            .any(|left_role| right.binary_search(left_role).is_ok())
}

fn scope_permits(scope: &MemoryScope, access: MemoryAccessScope<'_>) -> bool {
    if scope.project_id != access.project_id {
        return false;
    }
    if scope.kind == MemoryScopeKind::Agent && scope.agent_id.as_deref() != access.agent_id {
        return false;
    }
    scope.role_visibility.is_empty()
        || access.role_id.is_some_and(|role| {
            scope
                .role_visibility
                .binary_search_by(|candidate| candidate.as_str().cmp(role))
                .is_ok()
        })
}
