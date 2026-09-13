//! Canonical provenance-aware durable memory lifecycle for Sovereign.
//!
//! Memory is evidence, never authority.  This crate owns typed memory semantics
//! while [`sovereign_state::StateStore`] remains the one durable `SQLite`
//! authority.  M4-T01 deliberately does not add lexical/semantic retrieval;
//! it only exposes a bounded lifecycle-level view of records that are safe for
//! later context injection.

use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sovereign_state::{StateError, StateStore};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

mod projection;
mod retrieval;

pub use projection::{ProjectionOutbox, ProjectionRepair};

pub use retrieval::{
    FailureSignatureFilter, MemoryConflictSynopsis, MemoryExpansion, MemoryExpansionHandle,
    MemoryGraphNeighborhood, MemoryQuery, MemoryQueryMode, MemoryRetrievalPhase,
    MemoryRetrievalResult, MemoryRetrievalStage, MemoryRetrievalTrace, MemoryRetriever,
    MemorySynopsis,
};

/// Durable schema version for the public `MemoryRecord` contract.
pub const MEMORY_RECORD_SCHEMA_VERSION: u32 = 1;

/// `SQLite` schema version that first contains canonical memory tables.
pub const MEMORY_STATE_SCHEMA_VERSION: i64 = 6;

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
    /// Optional repository boundary inside the project. `None` is project-wide.
    pub repository_id: Option<String>,
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
    pub repository_revision: Option<String>,
    pub source_fingerprints: Vec<SourceFingerprint>,
}

/// Canonical durable memory record contract v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub schema_version: u32,
    pub id: String,
    pub lineage_id: String,
    pub kind: MemoryKind,
    pub scope: MemoryScope,
    pub subject: String,
    pub predicate: String,
    pub conflict_key: String,
    pub assertion: String,
    pub content_digest: String,
    pub trust: MemoryTrust,
    /// Integer confidence percentage in the inclusive range `0..=100`.
    pub confidence: u8,
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
    /// Stable scoped contradiction key. Records sharing this key are compared.
    pub conflict_key: String,
    pub assertion: String,
    pub trust: MemoryTrust,
    /// Integer confidence percentage in the inclusive range `0..=100`.
    pub confidence: u8,
    pub provenance: MemoryProvenance,
    pub expires_at_ms: Option<i64>,
    pub invalidation_predicates: Vec<InvalidationPredicate>,
}

/// Access envelope used only to prove lifecycle/scope eligibility at M4-T01.
/// Lexical ranking and compact synopses belong to M4-T02.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccessScope<'a> {
    pub project_id: &'a str,
    pub repository_id: Option<&'a str>,
    pub agent_id: Option<&'a str>,
    pub role_id: Option<&'a str>,
}

/// One exact fingerprint update published after repository refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintChange {
    pub kind: SourceFingerprintKind,
    pub key: String,
    /// Exact prior digest. `None` means the source was newly added.
    pub old_digest: Option<String>,
    /// Exact current digest. `None` means the source disappeared.
    pub new_digest: Option<String>,
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
    pub conflict_key: String,
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
    ProjectionPending(String),
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
            Self::ProjectionPending(message) => write!(
                f,
                "canonical memory committed; projection refresh remains pending: {message}"
            ),
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
    pub fn new(mut state: StateStore) -> Result<Self, MemoryError> {
        let version = state.schema_version()?;
        if version < MEMORY_STATE_SCHEMA_VERSION {
            return Err(MemoryError::InvalidRecord(format!(
                "state schema {version} predates required memory schema {MEMORY_STATE_SCHEMA_VERSION}"
            )));
        }
        state.transaction(backfill_memory_envelope_tx)?;
        let mut manager = Self { state };
        projection::initialize_projection(&mut manager)?;
        Ok(manager)
    }

    fn finish_projection_after_canonical_commit(&mut self) -> Result<(), MemoryError> {
        self.drain_projection_outbox()
            .map(|_| ())
            .map_err(|error| MemoryError::ProjectionPending(error.to_string()))
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
        self.state.transaction(|tx| {
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
            journal_memory_record_tx(tx, &id, "status_transition", reason, now_ms)?;
            if let Some(conflict_id) = current.conflict_set_id.as_deref() {
                resolve_conflict_if_unambiguous(tx, conflict_id, now_ms)?;
            }
            reconsider_demotions_tx(tx, &current, now_ms)?;
            Ok(())
        })?;
        self.finish_projection_after_canonical_commit()?;
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
            journal_memory_record_tx(tx, &id, "captured", "capture", now_ms)?;
            Ok(())
        })?;
        self.finish_projection_after_canonical_commit()?;
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
        self.state.transaction(|tx| {
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
                || previous.conflict_key != replacement.conflict_key
            {
                return Err(StateError::Integrity(
                    "governed replacement must retain scope/subject/predicate/conflict identity"
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
            journal_memory_record_tx(
                tx,
                &previous_id,
                "superseded",
                "governed_replacement",
                now_ms,
            )?;
            reconcile_contradictions_tx(tx, &replacement_id, now_ms)?;
            journal_memory_record_tx(
                tx,
                &replacement_id,
                "governed_replacement",
                "supersession",
                now_ms,
            )?;
            if let Some(conflict_id) = previous.conflict_set_id.as_deref() {
                resolve_conflict_if_unambiguous(tx, conflict_id, now_ms)?;
            }
            Ok(())
        })?;
        self.finish_projection_after_canonical_commit()?;
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
            if change.old_digest.is_none() && change.new_digest.is_none() {
                return Err(MemoryError::InvalidRecord(
                    "fingerprint change must carry an old or new digest".to_owned(),
                ));
            }
            if let Some(digest) = change.old_digest.as_deref() {
                validate_nonempty("old fingerprint digest", digest)?;
            }
            if let Some(digest) = change.new_digest.as_deref() {
                validate_nonempty("new fingerprint digest", digest)?;
            }
        }
        let repository_id = delta.repository_id.clone();
        let current_revision = delta.current_revision.clone();
        let changes = delta.changed_fingerprints.clone();
        let stale_ids = self.state.transaction(|tx| {
            let mut stale_ids = BTreeSet::new();
            for change in &changes {
                let Some(old_digest) = change.old_digest.as_deref() else {
                    continue;
                };
                if change.new_digest.as_deref() == Some(old_digest) {
                    continue;
                }
                let mut statement = tx.prepare(
                    "SELECT r.memory_id \
                     FROM memory_records r \
                     JOIN memory_source_fingerprints f ON f.memory_id=r.memory_id \
                     WHERE r.repository_id=?1 AND r.status='active' \
                       AND f.fingerprint_kind=?2 AND f.fingerprint_key=?3 \
                       AND f.fingerprint_digest=?4 \
                     ORDER BY r.memory_id ASC",
                )?;
                let rows = statement.query_map(
                    params![
                        repository_id,
                        change.kind.as_str(),
                        change.key,
                        old_digest
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

            let mut transitioned = Vec::new();
            for id in &stale_ids {
                let current = load_record_tx(tx, id)?.ok_or_else(|| {
                    StateError::Integrity(format!("memory {id} disappeared before staling"))
                })?;
                tx.execute(
                    "UPDATE memory_records SET status='stale', updated_at_ms=?2, normal_injection=0, exclusion_reason='source_fingerprint_changed' WHERE memory_id=?1",
                    params![id, now_ms],
                )?;
                journal_memory_record_tx(
                    tx,
                    id,
                    "stale",
                    "source_fingerprint_changed",
                    now_ms,
                )?;
                transitioned.push(current);
            }
            for current in &transitioned {
                if let Some(conflict_id) = current.conflict_set_id.as_deref() {
                    resolve_conflict_if_unambiguous(tx, conflict_id, now_ms)?;
                }
                reconsider_demotions_tx(tx, current, now_ms)?;
            }
            Ok(stale_ids.into_iter().collect::<Vec<_>>())
        })?;
        self.finish_projection_after_canonical_commit()?;
        Ok(stale_ids)
    }

    fn expire_due(&mut self, now_ms: i64) -> Result<Vec<String>, MemoryError> {
        validate_timestamp(now_ms)?;
        let expired = self.state.transaction(|tx| {
            let mut statement = tx.prepare(
                "SELECT memory_id, conflict_set_id FROM memory_records \
                 WHERE status='active' AND expires_at_ms IS NOT NULL AND expires_at_ms<=?1 \
                 ORDER BY memory_id ASC",
            )?;
            let rows = statement.query_map([now_ms], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?;
            let mut expired = Vec::new();
            let mut transitioned = Vec::new();
            for row in rows {
                let (id, _) = row?;
                expired.push(id);
            }
            drop(statement);
            for id in &expired {
                let current = load_record_tx(tx, id)?.ok_or_else(|| {
                    StateError::Integrity(format!("memory {id} disappeared before expiry"))
                })?;
                tx.execute(
                    "UPDATE memory_records SET status='expired', updated_at_ms=?2, normal_injection=0, exclusion_reason='expired' WHERE memory_id=?1",
                    params![id, now_ms],
                )?;
                journal_memory_record_tx(tx, id, "expired", "expiry", now_ms)?;
                transitioned.push(current);
            }
            for current in &transitioned {
                if let Some(conflict_id) = current.conflict_set_id.as_deref() {
                    resolve_conflict_if_unambiguous(tx, conflict_id, now_ms)?;
                }
                reconsider_demotions_tx(tx, current, now_ms)?;
            }
            Ok(expired)
        })?;
        self.finish_projection_after_canonical_commit()?;
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
        ("conflict_key", record.conflict_key.as_str()),
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
    if record.confidence > 100 {
        return Err(MemoryError::InvalidRecord(
            "confidence must be within 0..=100".to_owned(),
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
        && record.scope.repository_id.is_some()
        && record.provenance.source_fingerprints.is_empty()
    {
        return Err(MemoryError::InvalidRecord(
            "repository-backed validated memory requires a source fingerprint".to_owned(),
        ));
    }
    if record.provenance.repository_revision.is_some() && record.scope.repository_id.is_none() {
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

fn decode_confidence(value: i64, legacy_value: f64, memory_id: &str) -> Result<u8, StateError> {
    let confidence = u8::try_from(value).map_err(|_| {
        StateError::Integrity(format!(
            "memory {memory_id} has confidence outside 0..=100 durable range"
        ))
    })?;
    if confidence > 100 || !legacy_value.is_finite() {
        return Err(StateError::Integrity(format!(
            "memory {memory_id} has invalid durable confidence"
        )));
    }
    if ((legacy_value * 100.0) - f64::from(confidence)).abs() > 1e-9 {
        return Err(StateError::Integrity(format!(
            "memory {memory_id} durable confidence representations disagree"
        )));
    }
    Ok(confidence)
}

fn lineage_root_tx(
    tx: &Transaction<'_>,
    memory_id: &str,
    supersedes: Option<&str>,
) -> Result<String, StateError> {
    let mut root = memory_id.to_owned();
    let mut cursor = supersedes.map(str::to_owned);
    let mut seen = BTreeSet::from([memory_id.to_owned()]);
    while let Some(current) = cursor {
        if !seen.insert(current.clone()) {
            return Err(StateError::Integrity(format!(
                "memory lineage cycle detected at {current}"
            )));
        }
        root.clone_from(&current);
        cursor = tx
            .query_row(
                "SELECT supersedes_id FROM memory_records WHERE memory_id=?1",
                [&current],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .ok_or_else(|| {
                StateError::Integrity(format!(
                    "memory lineage references missing predecessor {current}"
                ))
            })?;
    }
    Ok(root)
}

#[allow(clippy::too_many_arguments)]
fn record_content_digest(
    kind: MemoryKind,
    scope: &MemoryScope,
    subject: &str,
    predicate: &str,
    conflict_key: &str,
    assertion: &str,
    trust: MemoryTrust,
    confidence: u8,
    provenance: &MemoryProvenance,
) -> Result<String, StateError> {
    let payload = json!({
        "kind": kind.as_str(),
        "scope": scope,
        "subject": subject,
        "predicate": predicate,
        "conflict_key": conflict_key,
        "assertion": assertion,
        "trust": trust.as_str(),
        "confidence": confidence,
        "provenance": provenance,
    });
    let encoded = serde_json::to_vec(&payload).map_err(|error| {
        StateError::Integrity(format!(
            "memory content digest serialization failed: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn append_memory_event_tx(
    tx: &Transaction<'_>,
    entity_id: &str,
    entity_type: &str,
    event_kind: &str,
    payload: &serde_json::Value,
    now_ms: i64,
) -> Result<(), StateError> {
    let payload_json = serde_json::to_string(payload).map_err(|error| {
        StateError::Integrity(format!(
            "memory journal payload serialization failed: {error}"
        ))
    })?;
    let next_sequence: i64 = tx.query_row(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM event_journal",
        [],
        |row| row.get(0),
    )?;
    let mut hasher = Sha256::new();
    for part in [
        entity_type.as_bytes(),
        entity_id.as_bytes(),
        event_kind.as_bytes(),
        &now_ms.to_be_bytes(),
        &next_sequence.to_be_bytes(),
        payload_json.as_bytes(),
    ] {
        hasher.update(part);
        hasher.update([0]);
    }
    let event_id = format!("memory-event:sha256:{:x}", hasher.finalize());
    tx.execute(
        "INSERT INTO event_journal(event_id, entity_type, entity_id, event_kind, payload_json, occurred_at_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event_id,
            entity_type,
            entity_id,
            event_kind,
            payload_json,
            now_ms
        ],
    )?;
    Ok(())
}

fn journal_memory_record_tx(
    tx: &Transaction<'_>,
    memory_id: &str,
    event_kind: &str,
    reason: &str,
    now_ms: i64,
) -> Result<(), StateError> {
    let record = load_record_tx(tx, memory_id)?
        .ok_or_else(|| StateError::Integrity(format!("unknown memory {memory_id} for journal")))?;
    append_memory_event_tx(
        tx,
        memory_id,
        "memory",
        event_kind,
        &json!({
            "memory_id": record.id,
            "lineage_id": record.lineage_id,
            "kind": record.kind.as_str(),
            "trust": record.trust.as_str(),
            "status": record.status.as_str(),
            "content_digest": record.content_digest,
            "conflict_set_id": record.conflict_set_id,
            "normal_injection": record.normal_injection,
            "reason": reason,
            "schema_version": record.schema_version,
        }),
        now_ms,
    )
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
    let confidence = i64::from(record.confidence);
    let confidence_legacy_real = f64::from(record.confidence) / 100.0;
    let lineage_id = if let Some(previous_id) = supersedes {
        let lineage: String = tx.query_row(
            "SELECT lineage_id FROM memory_records WHERE memory_id=?1",
            [previous_id],
            |row| row.get(0),
        )?;
        if lineage.is_empty() {
            return Err(StateError::Integrity(format!(
                "memory predecessor {previous_id} has no durable lineage"
            )));
        }
        lineage
    } else {
        record.id.clone()
    };
    let content_digest = record_content_digest(
        record.kind,
        &record.scope,
        &record.subject,
        &record.predicate,
        &record.conflict_key,
        &record.assertion,
        record.trust,
        record.confidence,
        &record.provenance,
    )?;
    tx.execute(
        "INSERT INTO memory_records(\
            memory_id, kind, project_id, scope_kind, agent_id, subject, predicate, conflict_key, assertion, \
            trust, confidence_legacy_real, confidence, status, repository_id, repository_revision, producing_task_id, \
            producing_attempt_id, created_at_ms, updated_at_ms, validated_at_ms, version, \
            supersedes_id, expires_at_ms, normal_injection, lineage_id, content_digest\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'active', ?13, ?14, ?15, ?16, ?17, ?17, ?18, ?19, ?20, ?21, 1, ?22, ?23)",
        params![
            record.id,
            record.kind.as_str(),
            record.scope.project_id,
            record.scope.kind.as_str(),
            record.scope.agent_id,
            record.subject,
            record.predicate,
            record.conflict_key,
            record.assertion,
            record.trust.as_str(),
            confidence_legacy_real,
            confidence,
            record.scope.repository_id,
            record.provenance.repository_revision,
            record.provenance.producing_task_id,
            record.provenance.producing_attempt_id,
            now_ms,
            validated_at,
            version,
            supersedes,
            record.expires_at_ms,
            lineage_id,
            content_digest,
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
    conflict_key: String,
    assertion: String,
    trust: String,
    confidence_legacy_real: f64,
    confidence: i64,
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
    lineage_id: String,
    content_digest: String,
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
        conflict_key: row.get(7)?,
        assertion: row.get(8)?,
        trust: row.get(9)?,
        confidence_legacy_real: row.get(10)?,
        confidence: row.get(11)?,
        status: row.get(12)?,
        repository_id: row.get(13)?,
        repository_revision: row.get(14)?,
        producing_task_id: row.get(15)?,
        producing_attempt_id: row.get(16)?,
        created_at_ms: row.get(17)?,
        updated_at_ms: row.get(18)?,
        validated_at_ms: row.get(19)?,
        version: row.get(20)?,
        supersedes: row.get(21)?,
        superseded_by: row.get(22)?,
        expires_at_ms: row.get(23)?,
        access_count: row.get(24)?,
        last_accessed_at_ms: row.get(25)?,
        conflict_set_id: row.get(26)?,
        normal_injection: row.get(27)?,
        exclusion_reason: row.get(28)?,
        lineage_id: row.get(29)?,
        content_digest: row.get(30)?,
    })
}

fn load_stored_memory_row_tx(
    tx: &Transaction<'_>,
    memory_id: &str,
) -> Result<Option<StoredMemoryRow>, StateError> {
    Ok(tx
        .query_row(
            "SELECT memory_id, kind, project_id, scope_kind, agent_id, subject, predicate, conflict_key, assertion, \
                    trust, confidence_legacy_real, confidence, status, repository_id, repository_revision, producing_task_id, \
                    producing_attempt_id, created_at_ms, updated_at_ms, validated_at_ms, version, \
                    supersedes_id, superseded_by_id, expires_at_ms, access_count, last_accessed_at_ms, \
                    conflict_set_id, normal_injection, exclusion_reason, lineage_id, content_digest \
             FROM memory_records WHERE memory_id=?1",
            [memory_id],
            stored_memory_row,
        )
        .optional()?)
}

fn backfill_memory_envelope_tx(tx: &Transaction<'_>) -> Result<(), StateError> {
    let mut statement = tx.prepare(
        "SELECT memory_id FROM memory_records \
         WHERE lineage_id='' OR content_digest='' ORDER BY memory_id ASC",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row?);
    }
    drop(statement);

    for id in ids {
        let row = load_stored_memory_row_tx(tx, &id)?.ok_or_else(|| {
            StateError::Integrity(format!(
                "memory {id} disappeared during v5 envelope backfill"
            ))
        })?;
        let confidence = decode_confidence(row.confidence, row.confidence_legacy_real, &row.id)?;
        let lineage_id = lineage_root_tx(tx, &row.id, row.supersedes.as_deref())?;
        if !row.lineage_id.is_empty() && row.lineage_id != lineage_id {
            return Err(StateError::Integrity(format!(
                "memory {} lineage changed during v5 envelope backfill",
                row.id
            )));
        }
        let scope = MemoryScope {
            project_id: row.project_id.clone(),
            repository_id: row.repository_id.clone(),
            kind: MemoryScopeKind::parse(&row.scope_kind)?,
            agent_id: row.agent_id.clone(),
            role_visibility: string_children(
                tx,
                "SELECT role_id FROM memory_role_visibility WHERE memory_id=?1 ORDER BY role_id ASC",
                &row.id,
            )?,
        };
        let provenance = MemoryProvenance {
            source_evidence_ids: string_children(
                tx,
                "SELECT evidence_id FROM memory_source_evidence WHERE memory_id=?1 ORDER BY evidence_id ASC",
                &row.id,
            )?,
            producing_task_id: row.producing_task_id.clone(),
            producing_attempt_id: row.producing_attempt_id.clone(),
            repository_revision: row.repository_revision.clone(),
            source_fingerprints: fingerprint_children(tx, &row.id)?,
        };
        let content_digest = record_content_digest(
            MemoryKind::parse(&row.kind)?,
            &scope,
            &row.subject,
            &row.predicate,
            &row.conflict_key,
            &row.assertion,
            MemoryTrust::parse(&row.trust)?,
            confidence,
            &provenance,
        )?;
        if !row.content_digest.is_empty() && row.content_digest != content_digest {
            return Err(StateError::Integrity(format!(
                "memory {} content changed during v5 envelope backfill",
                row.id
            )));
        }
        tx.execute(
            "UPDATE memory_records SET lineage_id=?2, content_digest=?3 WHERE memory_id=?1",
            params![row.id, lineage_id, content_digest],
        )?;
        append_memory_event_tx(
            tx,
            &row.id,
            "memory",
            "canonical_envelope_backfilled",
            &json!({
                "memory_id": row.id,
                "lineage_id": lineage_id,
                "content_digest": content_digest,
                "schema_version": MEMORY_RECORD_SCHEMA_VERSION,
            }),
            row.updated_at_ms,
        )?;
    }
    Ok(())
}

fn load_record_tx(
    tx: &Transaction<'_>,
    memory_id: &str,
) -> Result<Option<MemoryRecord>, StateError> {
    let stored = load_stored_memory_row_tx(tx, memory_id)?;
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
    let confidence = decode_confidence(row.confidence, row.confidence_legacy_real, &row.id)?;
    let expected_lineage_id = lineage_root_tx(tx, &row.id, row.supersedes.as_deref())?;
    if row.lineage_id != expected_lineage_id {
        return Err(StateError::Integrity(format!(
            "memory {} durable lineage mismatch: stored={:?} expected={:?}",
            row.id, row.lineage_id, expected_lineage_id
        )));
    }
    let kind = MemoryKind::parse(&row.kind)?;
    let scope_kind = MemoryScopeKind::parse(&row.scope_kind)?;
    let trust = MemoryTrust::parse(&row.trust)?;
    let status = MemoryStatus::parse(&row.status)?;
    let scope = MemoryScope {
        project_id: row.project_id,
        repository_id: row.repository_id,
        kind: scope_kind,
        agent_id: row.agent_id,
        role_visibility,
    };
    let provenance = MemoryProvenance {
        source_evidence_ids,
        producing_task_id: row.producing_task_id,
        producing_attempt_id: row.producing_attempt_id,
        repository_revision: row.repository_revision,
        source_fingerprints,
    };
    let expected_content_digest = record_content_digest(
        kind,
        &scope,
        &row.subject,
        &row.predicate,
        &row.conflict_key,
        &row.assertion,
        trust,
        confidence,
        &provenance,
    )?;
    if row.content_digest != expected_content_digest {
        return Err(StateError::Integrity(format!(
            "memory {} durable content digest mismatch",
            row.id
        )));
    }
    Ok(MemoryRecord {
        schema_version: MEMORY_RECORD_SCHEMA_VERSION,
        id: row.id,
        lineage_id: row.lineage_id,
        kind,
        scope,
        subject: row.subject,
        predicate: row.predicate,
        conflict_key: row.conflict_key,
        assertion: row.assertion,
        content_digest: row.content_digest,
        trust,
        confidence,
        status,
        provenance,
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
    values.sort();
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
    let mut current = load_record_tx(tx, memory_id)?
        .ok_or_else(|| StateError::Integrity(format!("unknown memory {memory_id}")))?;
    let mut statement = tx.prepare(
        "SELECT memory_id FROM memory_records \
         WHERE memory_id<>?1 AND project_id=?2 AND scope_kind=?3 AND agent_id IS ?4 \
           AND repository_id IS ?5 AND status='active' \
           AND ((subject=?6 AND predicate=?7) OR conflict_key=?8) \
         ORDER BY memory_id ASC",
    )?;
    let rows = statement.query_map(
        params![
            current.id,
            current.scope.project_id,
            current.scope.kind.as_str(),
            current.scope.agent_id,
            current.scope.repository_id,
            current.subject,
            current.predicate,
            current.conflict_key,
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
                current = load_record_tx(tx, memory_id)?.ok_or_else(|| {
                    StateError::Integrity(format!(
                        "memory {memory_id} disappeared while reconciling contradictions"
                    ))
                })?;
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
    let changed = tx.execute(
        "UPDATE memory_records SET normal_injection=0, exclusion_reason=?2, updated_at_ms=?3 WHERE memory_id=?1 AND status='active'",
        params![memory_id, reason, now_ms],
    )?;
    if changed != 0 {
        journal_memory_record_tx(tx, memory_id, "trust_demoted", &reason, now_ms)?;
    }
    Ok(())
}

fn create_or_extend_conflict_tx(
    tx: &Transaction<'_>,
    left: &MemoryRecord,
    right: &MemoryRecord,
    now_ms: i64,
) -> Result<(), StateError> {
    let relation_key = contradiction_relation_key(left, right)?;
    let conflict_id = match (&left.conflict_set_id, &right.conflict_set_id) {
        (Some(left_id), Some(right_id)) if left_id != right_id => {
            let (target, source) = if left_id <= right_id {
                (left_id.as_str(), right_id.as_str())
            } else {
                (right_id.as_str(), left_id.as_str())
            };
            merge_conflict_sets_tx(tx, target, source, now_ms)?;
            target.to_owned()
        }
        (Some(id), _) | (_, Some(id)) => id.clone(),
        (None, None) => conflict_set_id(left, right, &relation_key),
    };
    tx.execute(
        "INSERT OR IGNORE INTO memory_conflict_sets(conflict_set_id, project_id, repository_id, conflict_key, subject, predicate, created_at_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            conflict_id,
            left.scope.project_id,
            left.scope.repository_id,
            relation_key,
            left.subject,
            left.predicate,
            now_ms,
        ],
    )?;
    append_memory_event_tx(
        tx,
        &conflict_id,
        "memory_conflict",
        "created_or_extended",
        &json!({
            "conflict_set_id": conflict_id,
            "conflict_key": relation_key,
            "left_memory_id": left.id,
            "right_memory_id": right.id,
        }),
        now_ms,
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
        journal_memory_record_tx(tx, id, "conflict_member", "unresolved_conflict", now_ms)?;
    }
    Ok(())
}

fn merge_conflict_sets_tx(
    tx: &Transaction<'_>,
    target_id: &str,
    source_id: &str,
    now_ms: i64,
) -> Result<(), StateError> {
    if target_id == source_id {
        return Ok(());
    }
    for conflict_id in [target_id, source_id] {
        let state: Option<Option<i64>> = tx
            .query_row(
                "SELECT resolved_at_ms FROM memory_conflict_sets WHERE conflict_set_id=?1",
                [conflict_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?;
        match state {
            Some(None) => {}
            Some(Some(_)) => {
                return Err(StateError::Integrity(format!(
                    "cannot merge resolved memory conflict set {conflict_id}"
                )));
            }
            None => {
                return Err(StateError::Integrity(format!(
                    "missing memory conflict set {conflict_id} during merge"
                )));
            }
        }
    }

    let mut statement = tx.prepare(
        "SELECT memory_id FROM memory_conflict_members WHERE conflict_set_id=?1 ORDER BY memory_id ASC",
    )?;
    let rows = statement.query_map([source_id], |row| row.get::<_, String>(0))?;
    let mut source_members = Vec::new();
    for row in rows {
        source_members.push(row?);
    }
    drop(statement);

    for memory_id in &source_members {
        tx.execute(
            "INSERT OR IGNORE INTO memory_conflict_members(conflict_set_id, memory_id) VALUES (?1, ?2)",
            params![target_id, memory_id],
        )?;
        let changed = tx.execute(
            "UPDATE memory_records SET conflict_set_id=?2, updated_at_ms=?3 \
             WHERE memory_id=?1 AND status='active' AND conflict_set_id=?4",
            params![memory_id, target_id, now_ms, source_id],
        )?;
        if changed != 0 {
            journal_memory_record_tx(
                tx,
                memory_id,
                "conflict_member_merged",
                "connected_conflict_sets_merged",
                now_ms,
            )?;
        }
    }
    tx.execute(
        "UPDATE memory_conflict_sets SET resolved_at_ms=?2 WHERE conflict_set_id=?1 AND resolved_at_ms IS NULL",
        params![source_id, now_ms],
    )?;
    append_memory_event_tx(
        tx,
        source_id,
        "memory_conflict",
        "merged",
        &json!({
            "source_conflict_set_id": source_id,
            "target_conflict_set_id": target_id,
        }),
        now_ms,
    )?;
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
    append_memory_event_tx(
        tx,
        conflict_set_id,
        "memory_conflict",
        "resolved",
        &json!({"conflict_set_id": conflict_set_id}),
        now_ms,
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
        journal_memory_record_tx(
            tx,
            remaining_id,
            "conflict_resolved_member",
            "conflict_resolved",
            now_ms,
        )?;
    }
    Ok(())
}

fn reconsider_demotions_tx(
    tx: &Transaction<'_>,
    departed: &MemoryRecord,
    now_ms: i64,
) -> Result<(), StateError> {
    let mut statement = tx.prepare(
        "SELECT memory_id FROM memory_records \
         WHERE project_id=?1 AND scope_kind=?2 AND agent_id IS ?3 AND repository_id IS ?4 \
           AND status='active' AND exclusion_reason LIKE 'contradicts_%' \
           AND ((subject=?5 AND predicate=?6) OR conflict_key=?7) \
         ORDER BY memory_id ASC",
    )?;
    let rows = statement.query_map(
        params![
            departed.scope.project_id,
            departed.scope.kind.as_str(),
            departed.scope.agent_id,
            departed.scope.repository_id,
            departed.subject,
            departed.predicate,
            departed.conflict_key,
        ],
        |row| row.get::<_, String>(0),
    )?;
    let mut candidates = Vec::new();
    for row in rows {
        candidates.push(row?);
    }
    drop(statement);

    for candidate_id in candidates {
        let Some(candidate) = load_record_tx(tx, &candidate_id)? else {
            continue;
        };
        if candidate.conflict_set_id.is_some() {
            continue;
        }
        let mut related_statement = tx.prepare(
            "SELECT memory_id FROM memory_records \
             WHERE memory_id<>?1 AND project_id=?2 AND scope_kind=?3 AND agent_id IS ?4 \
               AND repository_id IS ?5 AND status='active' \
               AND ((subject=?6 AND predicate=?7) OR conflict_key=?8) \
             ORDER BY memory_id ASC",
        )?;
        let related_rows = related_statement.query_map(
            params![
                candidate.id,
                candidate.scope.project_id,
                candidate.scope.kind.as_str(),
                candidate.scope.agent_id,
                candidate.scope.repository_id,
                candidate.subject,
                candidate.predicate,
                candidate.conflict_key,
            ],
            |row| row.get::<_, String>(0),
        )?;
        let mut related_ids = Vec::new();
        for row in related_rows {
            related_ids.push(row?);
        }
        drop(related_statement);

        let candidate_assertion = normalized_assertion(&candidate.assertion);
        let mut still_demoted = false;
        for related_id in related_ids {
            let Some(related) = load_record_tx(tx, &related_id)? else {
                continue;
            };
            if related.trust.precedence() > candidate.trust.precedence()
                && role_scopes_overlap(
                    &candidate.scope.role_visibility,
                    &related.scope.role_visibility,
                )
                && normalized_assertion(&related.assertion) != candidate_assertion
            {
                still_demoted = true;
                break;
            }
        }
        if !still_demoted {
            tx.execute(
                "UPDATE memory_records SET normal_injection=1, exclusion_reason=NULL, updated_at_ms=?2 \
                 WHERE memory_id=?1 AND status='active' AND conflict_set_id IS NULL",
                params![candidate.id, now_ms],
            )?;
            journal_memory_record_tx(
                tx,
                &candidate.id,
                "trust_demotion_cleared",
                "higher_trust_evidence_no_longer_current",
                now_ms,
            )?;
        }
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
        String,
        i64,
        Option<i64>,
    );
    let scalar: Option<ConflictScalar> = tx
        .query_row(
            "SELECT conflict_set_id, project_id, repository_id, conflict_key, subject, predicate, created_at_ms, resolved_at_ms \
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
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        id,
        project_id,
        repository_id,
        conflict_key,
        subject,
        predicate,
        created_at_ms,
        resolved_at_ms,
    )) = scalar
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
        conflict_key,
        subject,
        predicate,
        created_at_ms,
        resolved_at_ms,
        member_ids,
    }))
}

fn contradiction_relation_key(
    left: &MemoryRecord,
    right: &MemoryRecord,
) -> Result<String, StateError> {
    if left.conflict_key == right.conflict_key {
        return Ok(left.conflict_key.clone());
    }
    if left.subject == right.subject && left.predicate == right.predicate {
        return Ok(format!("{}\u{1f}{}", left.subject, left.predicate));
    }
    Err(StateError::Integrity(format!(
        "memories {} and {} do not share a contradiction relation",
        left.id, right.id
    )))
}

fn conflict_set_id(left: &MemoryRecord, right: &MemoryRecord, relation_key: &str) -> String {
    let mut hasher = Sha256::new();
    let (first_id, second_id) = if left.id <= right.id {
        (left.id.as_str(), right.id.as_str())
    } else {
        (right.id.as_str(), left.id.as_str())
    };
    for part in [
        left.scope.project_id.as_str(),
        left.scope.kind.as_str(),
        left.scope.agent_id.as_deref().unwrap_or(""),
        left.scope.repository_id.as_deref().unwrap_or(""),
        relation_key,
        first_id,
        second_id,
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
    if let Some(repository_id) = access.repository_id
        && scope.repository_id.as_deref() != Some(repository_id)
    {
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
