use super::{
    MemoryAccessScope, MemoryConflictSet, MemoryError, MemoryKind, MemoryLifecycle, MemoryManager,
    MemoryRecord, MemoryStatus, MemoryTrust, SourceFingerprintKind, load_record_tx, scope_permits,
    validate_nonempty, validate_timestamp,
};
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use sovereign_state::StateError;
use std::cmp::Ordering;
use std::collections::BTreeSet;

pub const MEMORY_SYNOPSIS_SCHEMA_VERSION: u32 = 1;
const MAX_MEMORY_RESULTS_HARD: usize = 32;
const MAX_MEMORY_TOKENS_HARD: u32 = 2_048;
const MAX_MEMORY_CANDIDATES_HARD: usize = 128;
const MAX_GRAPH_NEIGHBORS_HARD: usize = 16;
const MAX_SYNOPSIS_TOKENS: u32 = 192;
const MAX_PROVENANCE_HANDLES: usize = 4;
const MAX_CONFLICT_MEMBER_HANDLES_HARD: usize = 16;
const MAX_CONFLICT_MEMBER_SCAN_HARD: usize = 128;

/// Retrieval mode controls whether non-current historical/conflicted records
/// are admissible. Ordinary mode is fail-closed for fact injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryQueryMode {
    Ordinary,
    History,
    Conflict,
}

/// Deterministic episodic failure key evaluated before broad lexical search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSignatureFilter {
    pub normalized_signature: String,
    pub tool: String,
    pub runtime_version: Option<String>,
    pub symbol: Option<String>,
    pub task_kind: Option<String>,
}

/// Bounded memory retrieval request. No semantic/embedder field exists at M4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryQuery {
    pub project_id: String,
    pub repository_id: Option<String>,
    pub agent_id: Option<String>,
    pub role_id: Option<String>,
    pub text: String,
    pub kinds: Vec<MemoryKind>,
    pub minimum_trust: Option<MemoryTrust>,
    pub mode: MemoryQueryMode,
    pub failure_signature: Option<FailureSignatureFilter>,
    pub allow_lexical_fallback: bool,
    pub max_results: usize,
    pub max_tokens: u32,
}

impl MemoryQuery {
    /// Creates an ordinary project-scoped lexical query with conservative caps.
    #[must_use]
    pub fn ordinary(project_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            repository_id: None,
            agent_id: None,
            role_id: None,
            text: text.into(),
            kinds: Vec::new(),
            minimum_trust: None,
            mode: MemoryQueryMode::Ordinary,
            failure_signature: None,
            allow_lexical_fallback: true,
            max_results: 8,
            max_tokens: 768,
        }
    }
}

/// Stable handle used to expand a compact memory without treating recall as
/// authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryExpansionHandle {
    pub memory_id: String,
    pub content_digest: String,
    pub evidence_ids: Vec<String>,
    pub evidence_handle_count: usize,
}

/// Prompt-safe compact memory projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySynopsis {
    pub schema_version: u32,
    pub memory_id: String,
    pub lineage_id: String,
    pub kind: MemoryKind,
    pub project_id: String,
    pub repository_id: Option<String>,
    pub subject: String,
    pub predicate: String,
    pub trust: MemoryTrust,
    pub confidence: u8,
    pub status: MemoryStatus,
    pub version: u64,
    pub source_fresh: bool,
    pub conflicted: bool,
    pub rendered: String,
    pub token_cost: u32,
    pub expansion: MemoryExpansionHandle,
}

/// Compact unresolved contradiction statement. It carries both/all visible
/// provenance handles instead of silently selecting one assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryConflictSynopsis {
    pub conflict_set_id: String,
    pub conflict_key: String,
    pub project_id: String,
    pub repository_id: Option<String>,
    pub statement: String,
    pub member_handles: Vec<MemoryExpansionHandle>,
    pub member_handles_truncated: bool,
    pub token_cost: u32,
}

/// Full selected memory expansion bound to one provenance evidence ID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryExpansion {
    pub selected_evidence_id: String,
    pub record: MemoryRecord,
}

/// Ordered retrieval stages retained for deterministic audit evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRetrievalPhase {
    EpisodicExact,
    ProjectionRead,
    Lexical,
    ScopeFreshnessFilter,
    TrustOrder,
    ConflictLookup,
    TokenCap,
}

/// One bounded stage in a memory retrieval trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRetrievalStage {
    pub phase: MemoryRetrievalPhase,
    pub candidates: usize,
    pub selected: usize,
    pub detail: String,
}

/// Complete deterministic trace for a single retrieval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRetrievalTrace {
    pub stages: Vec<MemoryRetrievalStage>,
    pub used_episodic_exact: bool,
    pub lexical_fallback_used: bool,
    pub semantic_used: bool,
    pub max_results: usize,
    pub max_tokens: u32,
    pub selected_tokens: u32,
    pub excluded_noncurrent: usize,
}

/// Compact retrieval result. Historical/conflict material is separated from
/// ordinary fact synopses by type and mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRetrievalResult {
    pub synopses: Vec<MemorySynopsis>,
    pub conflicts: Vec<MemoryConflictSynopsis>,
    pub trace: MemoryRetrievalTrace,
}

/// Bounded anchor-required graph expansion over durable memory relationships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryGraphNeighborhood {
    pub anchor: MemorySynopsis,
    pub neighbors: Vec<MemorySynopsis>,
    pub observed_neighbors: usize,
    pub limit: usize,
    pub truncated: bool,
}

struct CandidateScan {
    ranked: Vec<(MemoryRecord, f64)>,
    stages: Vec<MemoryRetrievalStage>,
    used_episodic_exact: bool,
    lexical_fallback_used: bool,
    projection_rows: usize,
}

/// Filter/signature/lexical-first retriever over canonical memory records and
/// a rebuildable FTS5 projection. It intentionally owns no embedder.
pub struct MemoryRetriever<'a> {
    manager: &'a mut MemoryManager,
}

impl<'a> MemoryRetriever<'a> {
    #[must_use]
    pub const fn new(manager: &'a mut MemoryManager) -> Self {
        Self { manager }
    }

    /// Retrieves compact memory evidence under scope/freshness/trust/token caps.
    ///
    /// # Errors
    /// Returns an error for invalid bounds/query input or durable-state/FTS
    /// failures.
    pub fn retrieve(
        &mut self,
        query: &MemoryQuery,
        now_ms: i64,
    ) -> Result<MemoryRetrievalResult, MemoryError> {
        validate_query(query, now_ms)?;
        let _ = self.manager.expire_due(now_ms)?;
        let max_results = query.max_results.min(MAX_MEMORY_RESULTS_HARD);
        let max_tokens = query.max_tokens.min(MAX_MEMORY_TOKENS_HARD);
        let access = access_scope(query);

        if query.mode == MemoryQueryMode::Conflict {
            return self.retrieve_conflict_result(query, access, max_results, max_tokens);
        }

        let CandidateScan {
            mut ranked,
            mut stages,
            used_episodic_exact,
            lexical_fallback_used,
            projection_rows,
        } = self.collect_ranked_candidates(query, access, now_ms)?;

        let before_filters = ranked.len();
        ranked.retain(|(record, _)| record_allowed(query, access, record, now_ms));
        let excluded_noncurrent = if query.mode == MemoryQueryMode::Ordinary {
            before_filters.saturating_sub(ranked.len())
        } else {
            0
        };
        stages.push(MemoryRetrievalStage {
            phase: MemoryRetrievalPhase::ScopeFreshnessFilter,
            candidates: before_filters,
            selected: ranked.len(),
            detail: format!(
                "project/repository/role/agent/kind/freshness filters;projection_rows={projection_rows}"
            ),
        });

        sort_ranked_candidates(&mut ranked);
        stages.push(MemoryRetrievalStage {
            phase: MemoryRetrievalPhase::TrustOrder,
            candidates: ranked.len(),
            selected: ranked.len().min(max_results),
            detail: "governed > validated > observed > unreviewed, then lexical rank/confidence/id"
                .to_owned(),
        });

        let (synopses, selected_tokens) = select_synopses(ranked, max_results, max_tokens);
        stages.push(MemoryRetrievalStage {
            phase: MemoryRetrievalPhase::TokenCap,
            candidates: before_filters,
            selected: synopses.len(),
            detail: format!("selected_tokens={selected_tokens};max_tokens={max_tokens}"),
        });

        Ok(MemoryRetrievalResult {
            synopses,
            conflicts: Vec::new(),
            trace: MemoryRetrievalTrace {
                stages,
                used_episodic_exact,
                lexical_fallback_used,
                semantic_used: false,
                max_results,
                max_tokens,
                selected_tokens,
                excluded_noncurrent,
            },
        })
    }

    fn retrieve_conflict_result(
        &mut self,
        query: &MemoryQuery,
        access: MemoryAccessScope<'_>,
        max_results: usize,
        max_tokens: u32,
    ) -> Result<MemoryRetrievalResult, MemoryError> {
        let conflicts = self.retrieve_conflicts(query, access, max_results, max_tokens)?;
        let selected_tokens = conflicts.iter().fold(0_u32, |sum, conflict| {
            sum.saturating_add(conflict.token_cost)
        });
        let stages = vec![
            MemoryRetrievalStage {
                phase: MemoryRetrievalPhase::ConflictLookup,
                candidates: conflicts.len(),
                selected: conflicts.len(),
                detail: "explicit unresolved-conflict query; ordinary fact injection bypassed"
                    .to_owned(),
            },
            MemoryRetrievalStage {
                phase: MemoryRetrievalPhase::TokenCap,
                candidates: conflicts.len(),
                selected: conflicts.len(),
                detail: format!("selected_tokens={selected_tokens};max_tokens={max_tokens}"),
            },
        ];
        Ok(MemoryRetrievalResult {
            synopses: Vec::new(),
            conflicts,
            trace: MemoryRetrievalTrace {
                stages,
                used_episodic_exact: false,
                lexical_fallback_used: false,
                semantic_used: false,
                max_results,
                max_tokens,
                selected_tokens,
                excluded_noncurrent: 0,
            },
        })
    }

    fn collect_ranked_candidates(
        &mut self,
        query: &MemoryQuery,
        access: MemoryAccessScope<'_>,
        now_ms: i64,
    ) -> Result<CandidateScan, MemoryError> {
        let mut stages = Vec::new();
        let mut ranked = Vec::new();
        let mut used_episodic_exact = false;

        if let Some(filter) = query.failure_signature.as_ref() {
            let exact = self.exact_failure_candidates(query, access, filter, now_ms)?;
            used_episodic_exact = !exact.is_empty();
            stages.push(MemoryRetrievalStage {
                phase: MemoryRetrievalPhase::EpisodicExact,
                candidates: exact.len(),
                selected: exact.len(),
                detail: "normalized signature/repository/tool/runtime/symbol/task filters evaluated before FTS"
                    .to_owned(),
            });
            ranked.extend(exact.into_iter().map(|record| (record, 0.0_f64)));
        }

        if !ranked.is_empty() {
            return Ok(CandidateScan {
                ranked,
                stages,
                used_episodic_exact,
                lexical_fallback_used: false,
                projection_rows: 0,
            });
        }
        if query.failure_signature.is_some() && !query.allow_lexical_fallback {
            return Ok(CandidateScan {
                ranked,
                stages,
                used_episodic_exact,
                lexical_fallback_used: false,
                projection_rows: 0,
            });
        }

        let projection_rows = self
            .manager
            .state
            .transaction(projection_row_count_tx)
            .map_err(MemoryError::from)?;
        stages.push(MemoryRetrievalStage {
            phase: MemoryRetrievalPhase::ProjectionRead,
            candidates: projection_rows,
            selected: projection_rows,
            detail: "derived FTS5 projection read without query-time corpus rewrite".to_owned(),
        });
        let fallback_text =
            query
                .failure_signature
                .as_ref()
                .map_or(query.text.as_str(), |filter| {
                    if query.text.trim().is_empty() {
                        filter.normalized_signature.as_str()
                    } else {
                        query.text.as_str()
                    }
                });
        let fts_query = lexical_query(fallback_text)?;
        let ranked = self.lexical_candidates(query, access, &fts_query, now_ms)?;
        stages.push(MemoryRetrievalStage {
            phase: MemoryRetrievalPhase::Lexical,
            candidates: ranked.len(),
            selected: ranked.len(),
            detail: "bounded FTS5 candidate search; no semantic/embedder fanout".to_owned(),
        });
        Ok(CandidateScan {
            ranked,
            stages,
            used_episodic_exact,
            lexical_fallback_used: query.failure_signature.is_some(),
            projection_rows,
        })
    }

    /// Expands a selected memory only when the caller presents the exact scoped
    /// compact handle and one evidence ID carried by that handle.
    ///
    /// # Errors
    /// Returns an error when the record/evidence handle is unknown or durable
    /// state cannot be updated.
    pub fn expand_by_evidence(
        &mut self,
        access: MemoryAccessScope<'_>,
        handle: &MemoryExpansionHandle,
        evidence_id: &str,
        now_ms: i64,
    ) -> Result<MemoryExpansion, MemoryError> {
        validate_timestamp(now_ms)?;
        validate_nonempty("memory_id", &handle.memory_id)?;
        validate_nonempty("content_digest", &handle.content_digest)?;
        validate_nonempty("evidence_id", evidence_id)?;
        if !handle
            .evidence_ids
            .iter()
            .any(|candidate| candidate == evidence_id)
        {
            return Err(MemoryError::InvalidRecord(format!(
                "evidence {evidence_id} is not present in the selected compact memory handle"
            )));
        }
        let memory_id = handle.memory_id.clone();
        let expected_content_digest = handle.content_digest.clone();
        let evidence_id = evidence_id.to_owned();
        let record = self.manager.state.transaction(|tx| {
            let record = load_record_tx(tx, &memory_id)?
                .ok_or_else(|| StateError::Integrity(format!("unknown memory {memory_id}")))?;
            if !scope_permits(&record.scope, access) {
                return Err(StateError::Integrity(format!(
                    "memory {memory_id} is not visible in the requested access scope"
                )));
            }
            if record.content_digest != expected_content_digest {
                return Err(StateError::Integrity(format!(
                    "memory {memory_id} content digest does not match the selected compact handle"
                )));
            }
            if expansion_handle(&record) != *handle {
                return Err(StateError::Integrity(format!(
                    "memory {memory_id} compact expansion handle no longer matches durable provenance"
                )));
            }
            if record
                .provenance
                .source_evidence_ids
                .binary_search(&evidence_id)
                .is_err()
            {
                return Err(StateError::Integrity(format!(
                    "evidence {evidence_id} is not provenance for memory {memory_id}"
                )));
            }
            tx.execute(
                "UPDATE memory_records SET access_count=access_count+1, last_accessed_at_ms=?2 WHERE memory_id=?1",
                params![memory_id, now_ms],
            )?;
            load_record_tx(tx, &memory_id)?.ok_or_else(|| {
                StateError::Integrity(format!("expanded memory {memory_id} disappeared"))
            })
        })?;
        Ok(MemoryExpansion {
            selected_evidence_id: evidence_id,
            record,
        })
    }

    /// Expands a bounded durable relationship neighborhood. A concrete anchor
    /// is mandatory; broad graph fanout is rejected.
    ///
    /// # Errors
    /// Returns an error when the anchor is absent/invisible or durable reads
    /// fail.
    pub fn graph_neighborhood(
        &mut self,
        access: MemoryAccessScope<'_>,
        anchor_id: Option<&str>,
        requested_limit: usize,
        now_ms: i64,
    ) -> Result<MemoryGraphNeighborhood, MemoryError> {
        validate_timestamp(now_ms)?;
        let anchor_id = anchor_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                MemoryError::InvalidRecord("graph expansion requires an anchor".into())
            })?;
        let _ = self.manager.expire_due(now_ms)?;
        let anchor = self
            .manager
            .record(anchor_id)?
            .ok_or_else(|| MemoryError::NotFound(anchor_id.to_owned()))?;
        if !scope_permits(&anchor.scope, access) {
            return Err(MemoryError::NotFound(anchor_id.to_owned()));
        }
        let limit = requested_limit.clamp(1, MAX_GRAPH_NEIGHBORS_HARD);
        let anchor_owned = anchor.id.clone();
        let producing_task_id = anchor.provenance.producing_task_id.clone();
        let conflict_set_id = anchor.conflict_set_id.clone();
        let supersedes = anchor.supersedes.clone();
        let superseded_by = anchor.superseded_by.clone();
        let symbol_keys = anchor
            .provenance
            .source_fingerprints
            .iter()
            .filter(|fingerprint| fingerprint.kind == SourceFingerprintKind::Symbol)
            .map(|fingerprint| fingerprint.key.clone())
            .collect::<BTreeSet<_>>();
        let candidate_ids = self.manager.state.transaction(|tx| {
            graph_candidate_ids(
                tx,
                &anchor_owned,
                producing_task_id.as_deref(),
                conflict_set_id.as_deref(),
                supersedes.as_deref(),
                superseded_by.as_deref(),
                &symbol_keys,
            )
        })?;
        let observed_neighbors = candidate_ids.len();
        let mut neighbors = Vec::new();
        for id in candidate_ids.into_iter().take(limit) {
            let Some(record) = self.manager.record(&id)? else {
                continue;
            };
            if scope_permits(&record.scope, access)
                && let Some(synopsis) = synopsis_for(&record, MAX_SYNOPSIS_TOKENS)
            {
                neighbors.push(synopsis);
            }
        }
        let anchor_synopsis = synopsis_for(&anchor, MAX_SYNOPSIS_TOKENS).ok_or_else(|| {
            MemoryError::InvalidRecord("anchor cannot fit compact synopsis".to_owned())
        })?;
        Ok(MemoryGraphNeighborhood {
            anchor: anchor_synopsis,
            neighbors,
            observed_neighbors,
            limit,
            truncated: observed_neighbors > limit,
        })
    }

    fn exact_failure_candidates(
        &mut self,
        query: &MemoryQuery,
        access: MemoryAccessScope<'_>,
        filter: &FailureSignatureFilter,
        now_ms: i64,
    ) -> Result<Vec<MemoryRecord>, MemoryError> {
        let project_id = query.project_id.clone();
        let repository_id = query.repository_id.clone();
        let signature = filter.normalized_signature.clone();
        let task_kind = filter.task_kind.clone();
        let ids = self.manager.state.transaction(|tx| {
            let mut statement = tx.prepare(
                "SELECT memory_id FROM memory_records \
                 WHERE project_id=?1 AND kind='episodic' AND subject=?2 \
                   AND (?3 IS NULL OR repository_id=?3) \
                   AND (?4 IS NULL OR predicate=?4) \
                 ORDER BY memory_id ASC LIMIT 128",
            )?;
            let rows = statement.query_map(
                params![project_id, signature, repository_id, task_kind],
                |row| row.get::<_, String>(0),
            )?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row?);
            }
            Ok(ids)
        })?;
        let mut records = Vec::new();
        for id in ids {
            let Some(record) = self.manager.record(&id)? else {
                continue;
            };
            if !record_allowed(query, access, &record, now_ms) {
                continue;
            }
            if failure_fingerprints_match(&record, filter) {
                records.push(record);
            }
        }
        Ok(records)
    }

    fn lexical_candidates(
        &mut self,
        query: &MemoryQuery,
        access: MemoryAccessScope<'_>,
        fts_query: &str,
        now_ms: i64,
    ) -> Result<Vec<(MemoryRecord, f64)>, MemoryError> {
        let project_id = query.project_id.clone();
        let repository_id = query.repository_id.clone();
        let agent_id = query.agent_id.clone();
        let role_id = query.role_id.clone();
        let ordinary = query.mode == MemoryQueryMode::Ordinary;
        let candidates = self.manager.state.transaction(|tx| {
            let sql = if ordinary {
                "SELECT r.memory_id, bm25(memory_fts_projection) \
                 FROM memory_fts_projection \
                 JOIN memory_records r ON r.memory_id=memory_fts_projection.memory_id \
                 WHERE memory_fts_projection MATCH ?1 AND r.project_id=?2 \
                   AND (?3 IS NULL OR r.repository_id=?3) \
                   AND (r.scope_kind<>'agent' OR r.agent_id IS ?4) \
                   AND (NOT EXISTS (SELECT 1 FROM memory_role_visibility rv WHERE rv.memory_id=r.memory_id) \
                        OR (?5 IS NOT NULL AND EXISTS (SELECT 1 FROM memory_role_visibility rv WHERE rv.memory_id=r.memory_id AND rv.role_id=?5))) \
                   AND r.status='active' AND r.normal_injection=1 AND r.conflict_set_id IS NULL \
                   AND (r.expires_at_ms IS NULL OR r.expires_at_ms>?6) \
                 ORDER BY bm25(memory_fts_projection) ASC, r.memory_id ASC LIMIT 128"
            } else {
                "SELECT r.memory_id, bm25(memory_fts_projection) \
                 FROM memory_fts_projection \
                 JOIN memory_records r ON r.memory_id=memory_fts_projection.memory_id \
                 WHERE memory_fts_projection MATCH ?1 AND r.project_id=?2 \
                   AND (?3 IS NULL OR r.repository_id=?3) \
                   AND (r.scope_kind<>'agent' OR r.agent_id IS ?4) \
                   AND (NOT EXISTS (SELECT 1 FROM memory_role_visibility rv WHERE rv.memory_id=r.memory_id) \
                        OR (?5 IS NOT NULL AND EXISTS (SELECT 1 FROM memory_role_visibility rv WHERE rv.memory_id=r.memory_id AND rv.role_id=?5))) \
                   AND ?6>=0 \
                 ORDER BY bm25(memory_fts_projection) ASC, r.memory_id ASC LIMIT 128"
            };
            let mut statement = tx.prepare(sql)?;
            let rows = statement.query_map(
                params![fts_query, project_id, repository_id, agent_id, role_id, now_ms],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?)),
            )?;
            let mut values = Vec::new();
            for row in rows {
                values.push(row?);
            }
            Ok(values)
        })?;
        let mut records = Vec::new();
        for (id, score) in candidates {
            if let Some(record) = self.manager.record(&id)?
                && scope_permits(&record.scope, access)
            {
                records.push((record, score));
            }
        }
        Ok(records)
    }

    fn retrieve_conflicts(
        &mut self,
        query: &MemoryQuery,
        access: MemoryAccessScope<'_>,
        max_results: usize,
        max_tokens: u32,
    ) -> Result<Vec<MemoryConflictSynopsis>, MemoryError> {
        let project_id = query.project_id.clone();
        let repository_id = query.repository_id.clone();
        let pattern = format!("%{}%", escape_like(query.text.trim()));
        let ids = self.manager.state.transaction(|tx| {
            let mut statement = tx.prepare(
                "SELECT c.conflict_set_id FROM memory_conflict_sets c \
                 WHERE c.project_id=?1 AND c.resolved_at_ms IS NULL \
                   AND (?2 IS NULL OR c.repository_id=?2) \
                   AND (\
                       ?3='%%' \
                       OR c.conflict_key LIKE ?3 ESCAPE '\\' \
                       OR c.subject LIKE ?3 ESCAPE '\\' \
                       OR c.predicate LIKE ?3 ESCAPE '\\' \
                       OR EXISTS (\
                           SELECT 1 FROM memory_conflict_members m \
                           JOIN memory_records r ON r.memory_id=m.memory_id \
                           WHERE m.conflict_set_id=c.conflict_set_id \
                             AND r.status='active' \
                             AND (\
                                 r.conflict_key LIKE ?3 ESCAPE '\\' \
                                 OR r.subject LIKE ?3 ESCAPE '\\' \
                                 OR r.predicate LIKE ?3 ESCAPE '\\' \
                                 OR r.assertion LIKE ?3 ESCAPE '\\'\
                             )\
                       )\
                   ) \
                 ORDER BY c.conflict_set_id ASC LIMIT 32",
            )?;
            let rows = statement.query_map(params![project_id, repository_id, pattern], |row| {
                row.get::<_, String>(0)
            })?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row?);
            }
            Ok(ids)
        })?;
        let mut remaining = max_tokens;
        let mut conflicts = Vec::new();
        for id in ids.into_iter().take(max_results) {
            let Some(conflict) = self.manager.conflict_set(&id)? else {
                continue;
            };
            let Some(synopsis) = self.conflict_synopsis(query, &conflict, access, remaining)?
            else {
                continue;
            };
            if synopsis.token_cost > remaining {
                break;
            }
            remaining = remaining.saturating_sub(synopsis.token_cost);
            conflicts.push(synopsis);
        }
        Ok(conflicts)
    }

    fn conflict_synopsis(
        &mut self,
        query: &MemoryQuery,
        conflict: &MemoryConflictSet,
        access: MemoryAccessScope<'_>,
        available_tokens: u32,
    ) -> Result<Option<MemoryConflictSynopsis>, MemoryError> {
        if conflict.member_ids.len() > MAX_CONFLICT_MEMBER_SCAN_HARD {
            return Ok(None);
        }
        let mut handles = Vec::new();
        let mut assertions = Vec::new();
        let mut member_handles_truncated = false;
        for id in &conflict.member_ids {
            let Some(record) = self.manager.record(id)? else {
                continue;
            };
            if record.status != MemoryStatus::Active {
                continue;
            }
            if !scope_permits(&record.scope, access) {
                return Ok(None);
            }
            if !record_matches_query_filters(query, &record) {
                continue;
            }
            if handles.len() >= MAX_CONFLICT_MEMBER_HANDLES_HARD {
                member_handles_truncated = true;
                continue;
            }
            assertions.push(format!(
                "{}={}",
                record.id,
                compact_text(&record.assertion, 96)
            ));
            handles.push(expansion_handle(&record));
        }
        if handles.len() < 2 {
            return Ok(None);
        }
        let statement = format!(
            "UNRESOLVED MEMORY CONFLICT [{}] {} :: {} | provenance={}",
            conflict.conflict_key,
            conflict.subject,
            assertions.join(" <> "),
            handles
                .iter()
                .map(|handle| format!("{}:{:?}", handle.memory_id, handle.evidence_ids))
                .collect::<Vec<_>>()
                .join(" ; ")
        );
        let token_cost = token_cost(&statement);
        if token_cost > available_tokens {
            return Ok(None);
        }
        Ok(Some(MemoryConflictSynopsis {
            conflict_set_id: conflict.id.clone(),
            conflict_key: conflict.conflict_key.clone(),
            project_id: conflict.project_id.clone(),
            repository_id: conflict.repository_id.clone(),
            statement,
            member_handles: handles,
            member_handles_truncated,
            token_cost,
        }))
    }
}

fn sort_ranked_candidates(ranked: &mut [(MemoryRecord, f64)]) {
    ranked.sort_by(|(left, left_score), (right, right_score)| {
        right
            .trust
            .precedence()
            .cmp(&left.trust.precedence())
            .then_with(|| {
                left_score
                    .partial_cmp(right_score)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| right.confidence.cmp(&left.confidence))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn select_synopses(
    ranked: Vec<(MemoryRecord, f64)>,
    max_results: usize,
    max_tokens: u32,
) -> (Vec<MemorySynopsis>, u32) {
    let mut remaining_tokens = max_tokens;
    let mut selected = Vec::new();
    for (record, _) in ranked.into_iter().take(max_results) {
        let per_item = remaining_tokens.min(MAX_SYNOPSIS_TOKENS);
        if per_item == 0 {
            break;
        }
        let Some(compact) = synopsis_for(&record, per_item) else {
            continue;
        };
        if compact.token_cost > remaining_tokens {
            break;
        }
        remaining_tokens = remaining_tokens.saturating_sub(compact.token_cost);
        selected.push(compact);
    }
    (selected, max_tokens.saturating_sub(remaining_tokens))
}

fn validate_query(query: &MemoryQuery, now_ms: i64) -> Result<(), MemoryError> {
    validate_timestamp(now_ms)?;
    validate_nonempty("project_id", &query.project_id)?;
    if query.mode != MemoryQueryMode::Conflict
        && query.text.trim().is_empty()
        && query.failure_signature.is_none()
    {
        return Err(MemoryError::InvalidRecord(
            "memory retrieval requires lexical text or an exact failure signature".to_owned(),
        ));
    }
    if query.max_results == 0 || query.max_tokens == 0 {
        return Err(MemoryError::InvalidRecord(
            "memory retrieval result/token bounds must be positive".to_owned(),
        ));
    }
    if let Some(filter) = query.failure_signature.as_ref() {
        validate_nonempty("normalized failure signature", &filter.normalized_signature)?;
        validate_nonempty("failure tool", &filter.tool)?;
    }
    Ok(())
}

fn access_scope(query: &MemoryQuery) -> MemoryAccessScope<'_> {
    MemoryAccessScope {
        project_id: &query.project_id,
        repository_id: query.repository_id.as_deref(),
        agent_id: query.agent_id.as_deref(),
        role_id: query.role_id.as_deref(),
    }
}

fn record_allowed(
    query: &MemoryQuery,
    access: MemoryAccessScope<'_>,
    record: &MemoryRecord,
    now_ms: i64,
) -> bool {
    if !scope_permits(&record.scope, access) {
        return false;
    }
    if !record_matches_query_filters(query, record) {
        return false;
    }
    match query.mode {
        MemoryQueryMode::Ordinary => {
            record.status == MemoryStatus::Active
                && record.normal_injection
                && record.conflict_set_id.is_none()
                && record.expires_at_ms.is_none_or(|expiry| expiry > now_ms)
        }
        MemoryQueryMode::History => true,
        MemoryQueryMode::Conflict => false,
    }
}

fn record_matches_query_filters(query: &MemoryQuery, record: &MemoryRecord) -> bool {
    if !query.kinds.is_empty() && !query.kinds.contains(&record.kind) {
        return false;
    }
    if let Some(minimum) = query.minimum_trust
        && record.trust.precedence() < minimum.precedence()
    {
        return false;
    }
    true
}

fn failure_fingerprints_match(record: &MemoryRecord, filter: &FailureSignatureFilter) -> bool {
    let tool_match = record
        .provenance
        .source_fingerprints
        .iter()
        .any(|fingerprint| {
            fingerprint.kind == SourceFingerprintKind::CommandToolVersion
                && fingerprint.key == filter.tool
                && filter
                    .runtime_version
                    .as_ref()
                    .is_none_or(|version| fingerprint.digest == *version)
        });
    if !tool_match {
        return false;
    }
    filter.symbol.as_ref().is_none_or(|symbol| {
        record
            .provenance
            .source_fingerprints
            .iter()
            .any(|fingerprint| {
                fingerprint.kind == SourceFingerprintKind::Symbol && fingerprint.key == *symbol
            })
    })
}

fn projection_row_count_tx(tx: &Transaction<'_>) -> Result<usize, StateError> {
    tx.query_row("SELECT COUNT(*) FROM memory_fts_projection", [], |row| {
        row.get::<_, usize>(0)
    })
    .map_err(StateError::from)
}

fn lexical_query(text: &str) -> Result<String, MemoryError> {
    let mut terms = text
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|term| !term.is_empty())
        .take(16)
        .map(|term| format!("\"{term}\""))
        .collect::<Vec<_>>();
    terms.sort();
    terms.dedup();
    if terms.is_empty() {
        return Err(MemoryError::InvalidRecord(
            "lexical memory query contains no searchable terms".to_owned(),
        ));
    }
    Ok(terms.join(" OR "))
}

fn synopsis_for(record: &MemoryRecord, max_tokens: u32) -> Option<MemorySynopsis> {
    let evidence_ids = record
        .provenance
        .source_evidence_ids
        .iter()
        .take(MAX_PROVENANCE_HANDLES)
        .cloned()
        .collect::<Vec<_>>();
    let prefix = format!(
        "MEMORY EVIDENCE id={} trust={} status={} kind={} subject={} predicate={} evidence={:?} assertion=",
        record.id,
        record.trust.as_str(),
        record.status.as_str(),
        record.kind.as_str(),
        record.subject,
        record.predicate,
        evidence_ids
    );
    let prefix_tokens = token_cost(&prefix);
    if prefix_tokens >= max_tokens {
        return None;
    }
    let assertion_budget = max_tokens.saturating_sub(prefix_tokens);
    let assertion = truncate_for_tokens(&record.assertion, assertion_budget);
    let rendered = format!("{prefix}{assertion}");
    let token_cost = token_cost(&rendered);
    Some(MemorySynopsis {
        schema_version: MEMORY_SYNOPSIS_SCHEMA_VERSION,
        memory_id: record.id.clone(),
        lineage_id: record.lineage_id.clone(),
        kind: record.kind,
        project_id: record.scope.project_id.clone(),
        repository_id: record.scope.repository_id.clone(),
        subject: record.subject.clone(),
        predicate: record.predicate.clone(),
        trust: record.trust,
        confidence: record.confidence,
        status: record.status,
        version: record.version,
        source_fresh: record.status == MemoryStatus::Active,
        conflicted: record.conflict_set_id.is_some(),
        rendered,
        token_cost,
        expansion: expansion_handle(record),
    })
}

fn expansion_handle(record: &MemoryRecord) -> MemoryExpansionHandle {
    MemoryExpansionHandle {
        memory_id: record.id.clone(),
        content_digest: record.content_digest.clone(),
        evidence_ids: record
            .provenance
            .source_evidence_ids
            .iter()
            .take(MAX_PROVENANCE_HANDLES)
            .cloned()
            .collect(),
        evidence_handle_count: record.provenance.source_evidence_ids.len(),
    }
}

fn token_cost(text: &str) -> u32 {
    u32::try_from(text.len())
        .unwrap_or(u32::MAX)
        .saturating_add(3)
        / 4
}

fn truncate_for_tokens(text: &str, tokens: u32) -> String {
    let max_bytes = usize::try_from(tokens.saturating_mul(4)).unwrap_or(usize::MAX);
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn compact_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

fn escape_like(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[allow(clippy::too_many_arguments)]
fn graph_candidate_ids(
    tx: &Transaction<'_>,
    anchor_id: &str,
    producing_task_id: Option<&str>,
    conflict_set_id: Option<&str>,
    supersedes: Option<&str>,
    superseded_by: Option<&str>,
    symbol_keys: &BTreeSet<String>,
) -> Result<Vec<String>, StateError> {
    let mut ids = BTreeSet::new();
    if let Some(id) = supersedes {
        ids.insert(id.to_owned());
    }
    if let Some(id) = superseded_by {
        ids.insert(id.to_owned());
    }
    if let Some(conflict_set_id) = conflict_set_id {
        let mut statement = tx.prepare(
            "SELECT memory_id FROM memory_conflict_members WHERE conflict_set_id=?1 AND memory_id<>?2 ORDER BY memory_id ASC",
        )?;
        let rows = statement.query_map(params![conflict_set_id, anchor_id], |row| {
            row.get::<_, String>(0)
        })?;
        for row in rows {
            ids.insert(row?);
        }
    }
    if let Some(task_id) = producing_task_id {
        let mut statement = tx.prepare(
            "SELECT memory_id FROM memory_records WHERE producing_task_id=?1 AND memory_id<>?2 ORDER BY memory_id ASC LIMIT 64",
        )?;
        let rows =
            statement.query_map(params![task_id, anchor_id], |row| row.get::<_, String>(0))?;
        for row in rows {
            ids.insert(row?);
        }
    }
    for symbol in symbol_keys {
        let mut statement = tx.prepare(
            "SELECT memory_id FROM memory_source_fingerprints \
             WHERE fingerprint_kind='symbol' AND fingerprint_key=?1 AND memory_id<>?2 \
             ORDER BY memory_id ASC LIMIT 64",
        )?;
        let rows =
            statement.query_map(params![symbol, anchor_id], |row| row.get::<_, String>(0))?;
        for row in rows {
            ids.insert(row?);
        }
    }
    Ok(ids.into_iter().take(MAX_MEMORY_CANDIDATES_HARD).collect())
}
