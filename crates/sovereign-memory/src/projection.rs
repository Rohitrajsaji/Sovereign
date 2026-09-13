use super::{MemoryError, MemoryManager};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sovereign_state::StateError;
use std::time::{SystemTime, UNIX_EPOCH};

const PROJECTION_KIND: &str = "memory_fts_v1";
const OUTBOX_SCHEMA_VERSION: u32 = 1;
const REPAIR_SCHEMA_VERSION: u32 = 1;
const MAX_OUTBOX_BATCH_HARD: usize = 128;

/// Durable refresh intent for one derived memory projection row.
///
/// The outbox carries no searchable payload. Delivery always rereads current
/// canonical memory, so duplicate or delayed delivery cannot become a second
/// source of truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionOutbox {
    pub schema_version: u32,
    pub projection_kind: String,
    pub memory_id: String,
    pub canonical_updated_at_ms: i64,
    pub enqueued_at_ms: i64,
}

/// Durable provenance for a projection consistency repair/rebuild.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionRepair {
    pub schema_version: u32,
    pub repair_id: String,
    pub projection_kind: String,
    pub reason: String,
    pub state: String,
    pub canonical_row_count: i64,
    pub projection_row_count: i64,
    pub mismatch_count: i64,
    pub detected_at_ms: i64,
    pub completed_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionConsistency {
    canonical_rows: i64,
    projection_rows: i64,
    mismatches: i64,
}

impl MemoryManager {
    /// Returns the durable pending projection refresh intents in deterministic
    /// delivery order.
    ///
    /// # Errors
    /// Returns a durable-state error for malformed rows or `SQLite` failure.
    pub fn projection_outbox(&mut self) -> Result<Vec<ProjectionOutbox>, MemoryError> {
        Ok(self.state.transaction(load_outbox_tx)?)
    }

    /// Returns durable projection-repair provenance in creation order.
    ///
    /// # Errors
    /// Returns a durable-state error for malformed rows or `SQLite` failure.
    pub fn projection_repairs(&mut self) -> Result<Vec<ProjectionRepair>, MemoryError> {
        Ok(self.state.transaction(load_repairs_tx)?)
    }

    /// Idempotently drains all pending refresh intents in bounded batches.
    /// Every delivery rereads the current canonical row and replaces at most one
    /// derived FTS row for the memory ID before deleting that outbox intent in
    /// the same transaction.
    ///
    /// # Errors
    /// Returns a durable-state error if any refresh transaction fails. The
    /// uncommitted intent remains durable for retry.
    pub fn drain_projection_outbox(&mut self) -> Result<usize, MemoryError> {
        drain_projection_outbox_state(&mut self.state)
    }

    /// Detects a derived-projection mismatch, writes durable pending repair
    /// provenance, then rebuilds exclusively from canonical memory.
    ///
    /// Returns `None` when the projection already matches canonical state.
    ///
    /// # Errors
    /// Returns a validation/state error if the reason is empty or repair fails.
    pub fn repair_projection(
        &mut self,
        reason: &str,
    ) -> Result<Option<ProjectionRepair>, MemoryError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(MemoryError::InvalidRecord(
                "projection repair reason must not be empty".to_owned(),
            ));
        }
        if let Some(repair_id) = self.state.transaction(oldest_pending_repair_id_tx)? {
            complete_repair(self, &repair_id)?;
            return self
                .projection_repairs()?
                .into_iter()
                .find(|candidate| candidate.repair_id == repair_id)
                .map(Some)
                .ok_or_else(|| {
                    MemoryError::State(StateError::Integrity(format!(
                        "completed projection repair {repair_id} disappeared"
                    )))
                });
        }
        let consistency = self.state.transaction(projection_consistency_tx)?;
        if consistency.mismatches == 0 && consistency.canonical_rows == consistency.projection_rows
        {
            return Ok(None);
        }
        let detected_at_ms = system_now_ms()?;
        let repair = self
            .state
            .transaction(|tx| begin_repair_tx(tx, reason, consistency, detected_at_ms))?;
        complete_repair(self, &repair.repair_id)?;
        let completed = self
            .projection_repairs()?
            .into_iter()
            .find(|candidate| candidate.repair_id == repair.repair_id)
            .ok_or_else(|| {
                MemoryError::State(StateError::Integrity(format!(
                    "completed projection repair {} disappeared",
                    repair.repair_id
                )))
            })?;
        Ok(Some(completed))
    }
}

pub(super) fn drain_projection_outbox_state(
    state: &mut sovereign_state::StateStore,
) -> Result<usize, MemoryError> {
    let mut refreshed = 0usize;
    loop {
        let delivered = state.transaction(drain_outbox_batch_tx)?;
        refreshed = refreshed.checked_add(delivered).ok_or_else(|| {
            MemoryError::State(StateError::Integrity(
                "projection refresh count overflow".to_owned(),
            ))
        })?;
        if delivered < MAX_OUTBOX_BATCH_HARD {
            break;
        }
    }
    Ok(refreshed)
}

pub(super) fn initialize_projection(manager: &mut MemoryManager) -> Result<(), MemoryError> {
    loop {
        let pending = manager.state.transaction(oldest_pending_repair_id_tx)?;
        let Some(repair_id) = pending else {
            break;
        };
        complete_repair(manager, &repair_id)?;
    }

    manager.drain_projection_outbox()?;
    Ok(())
}

fn drain_outbox_batch_tx(tx: &Transaction<'_>) -> Result<usize, StateError> {
    let mut statement = tx.prepare(
        "SELECT memory_id FROM memory_projection_outbox \
         WHERE projection_kind=?1 \
         ORDER BY enqueued_at_ms ASC, memory_id ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            PROJECTION_KIND,
            i64::try_from(MAX_OUTBOX_BATCH_HARD).unwrap_or(128)
        ],
        |row| row.get::<_, String>(0),
    )?;
    let mut memory_ids = Vec::new();
    for row in rows {
        memory_ids.push(row?);
    }
    drop(statement);

    for memory_id in &memory_ids {
        refresh_projection_row_tx(tx, memory_id)?;
    }
    Ok(memory_ids.len())
}

fn refresh_projection_row_tx(tx: &Transaction<'_>, memory_id: &str) -> Result<(), StateError> {
    let canonical = tx
        .query_row(
            "SELECT memory_id, project_id, COALESCE(repository_id, ''), kind, trust, status, \
                    conflict_key, subject, predicate, assertion \
             FROM memory_records WHERE memory_id=?1",
            [memory_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        memory_id,
        project_id,
        repository_id,
        kind,
        trust,
        status,
        conflict_key,
        subject,
        predicate,
        assertion,
    )) = canonical
    else {
        return Err(StateError::Integrity(format!(
            "projection outbox references missing canonical memory {memory_id}"
        )));
    };
    tx.execute(
        "DELETE FROM memory_fts_projection WHERE memory_id=?1",
        [&memory_id],
    )?;
    tx.execute(
        "INSERT INTO memory_fts_projection(\
             memory_id, project_id, repository_id, kind, trust, status, conflict_key, subject, predicate, assertion\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            memory_id,
            project_id,
            repository_id,
            kind,
            trust,
            status,
            conflict_key,
            subject,
            predicate,
            assertion,
        ],
    )?;
    tx.execute(
        "DELETE FROM memory_projection_outbox WHERE projection_kind=?1 AND memory_id=?2",
        params![PROJECTION_KIND, memory_id],
    )?;
    Ok(())
}

fn projection_consistency_tx(tx: &Transaction<'_>) -> Result<ProjectionConsistency, StateError> {
    let canonical_row_count: i64 =
        tx.query_row("SELECT COUNT(*) FROM memory_records", [], |row| row.get(0))?;
    let projection_row_count: i64 =
        tx.query_row("SELECT COUNT(*) FROM memory_fts_projection", [], |row| {
            row.get(0)
        })?;
    let row_mismatch_count: i64 = tx.query_row(
        "SELECT \
           (SELECT COUNT(*) FROM memory_records r WHERE NOT EXISTS (\
               SELECT 1 FROM memory_fts_projection p \
               WHERE p.memory_id=r.memory_id \
                 AND p.project_id=r.project_id \
                 AND p.repository_id=COALESCE(r.repository_id, '') \
                 AND p.kind=r.kind AND p.trust=r.trust AND p.status=r.status \
                 AND p.conflict_key=r.conflict_key AND p.subject=r.subject \
                 AND p.predicate=r.predicate AND p.assertion=r.assertion\
           )) + \
           (SELECT COUNT(*) FROM memory_fts_projection p WHERE NOT EXISTS (\
               SELECT 1 FROM memory_records r \
               WHERE r.memory_id=p.memory_id \
                 AND r.project_id=p.project_id \
                 AND COALESCE(r.repository_id, '')=p.repository_id \
                 AND r.kind=p.kind AND r.trust=p.trust AND r.status=p.status \
                 AND r.conflict_key=p.conflict_key AND r.subject=p.subject \
                 AND r.predicate=p.predicate AND r.assertion=p.assertion\
           ))",
        [],
        |row| row.get(0),
    )?;
    let count_delta = (canonical_row_count - projection_row_count).abs();
    Ok(ProjectionConsistency {
        canonical_rows: canonical_row_count,
        projection_rows: projection_row_count,
        mismatches: row_mismatch_count.max(count_delta),
    })
}

fn begin_repair_tx(
    tx: &Transaction<'_>,
    reason: &str,
    consistency: ProjectionConsistency,
    detected_at_ms: i64,
) -> Result<ProjectionRepair, StateError> {
    let sequence: i64 = tx.query_row(
        "SELECT COUNT(*) + 1 FROM memory_projection_repairs",
        [],
        |row| row.get(0),
    )?;
    let repair_id = format!("memory_fts_v1:{detected_at_ms}:{sequence}");
    tx.execute(
        "INSERT INTO memory_projection_repairs(\
             schema_version, repair_id, projection_kind, reason, state, canonical_row_count, \
             projection_row_count, mismatch_count, detected_at_ms, completed_at_ms\
         ) VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6, ?7, ?8, NULL)",
        params![
            i64::from(REPAIR_SCHEMA_VERSION),
            repair_id,
            PROJECTION_KIND,
            reason,
            consistency.canonical_rows,
            consistency.projection_rows,
            consistency.mismatches,
            detected_at_ms,
        ],
    )?;
    Ok(ProjectionRepair {
        schema_version: REPAIR_SCHEMA_VERSION,
        repair_id,
        projection_kind: PROJECTION_KIND.to_owned(),
        reason: reason.to_owned(),
        state: "pending".to_owned(),
        canonical_row_count: consistency.canonical_rows,
        projection_row_count: consistency.projection_rows,
        mismatch_count: consistency.mismatches,
        detected_at_ms,
        completed_at_ms: None,
    })
}

fn complete_repair(manager: &mut MemoryManager, repair_id: &str) -> Result<(), MemoryError> {
    let completed_at_ms = system_now_ms()?;
    let repair_id = repair_id.to_owned();
    manager.state.transaction(|tx| {
        let pending: Option<String> = tx
            .query_row(
                "SELECT state FROM memory_projection_repairs \
                 WHERE repair_id=?1 AND projection_kind=?2",
                params![repair_id, PROJECTION_KIND],
                |row| row.get(0),
            )
            .optional()?;
        match pending.as_deref() {
            Some("completed") => return Ok(()),
            Some("pending") => {}
            Some(other) => {
                return Err(StateError::Integrity(format!(
                    "unknown projection repair state {other:?}"
                )));
            }
            None => {
                return Err(StateError::Integrity(format!(
                    "unknown projection repair {repair_id}"
                )));
            }
        }

        tx.execute("DELETE FROM memory_fts_projection", [])?;
        tx.execute(
            "INSERT INTO memory_fts_projection(\
                 memory_id, project_id, repository_id, kind, trust, status, conflict_key, subject, predicate, assertion\
             ) \
             SELECT memory_id, project_id, COALESCE(repository_id, ''), kind, trust, status, \
                    conflict_key, subject, predicate, assertion \
             FROM memory_records ORDER BY memory_id ASC",
            [],
        )?;
        tx.execute(
            "DELETE FROM memory_projection_outbox WHERE projection_kind=?1",
            [PROJECTION_KIND],
        )?;
        let changed = tx.execute(
            "UPDATE memory_projection_repairs \
             SET state='completed', completed_at_ms=?2 \
             WHERE repair_id=?1 AND projection_kind=?3 AND state='pending'",
            params![repair_id, completed_at_ms, PROJECTION_KIND],
        )?;
        if changed != 1 {
            return Err(StateError::Integrity(format!(
                "projection repair {repair_id} completion updated {changed} rows"
            )));
        }
        Ok(())
    })?;
    Ok(())
}

fn oldest_pending_repair_id_tx(tx: &Transaction<'_>) -> Result<Option<String>, StateError> {
    Ok(tx
        .query_row(
            "SELECT repair_id FROM memory_projection_repairs \
             WHERE projection_kind=?1 AND state='pending' \
             ORDER BY detected_at_ms ASC, repair_id ASC LIMIT 1",
            [PROJECTION_KIND],
            |row| row.get(0),
        )
        .optional()?)
}

fn load_outbox_tx(tx: &Transaction<'_>) -> Result<Vec<ProjectionOutbox>, StateError> {
    let mut statement = tx.prepare(
        "SELECT schema_version, projection_kind, memory_id, canonical_updated_at_ms, enqueued_at_ms \
         FROM memory_projection_outbox ORDER BY enqueued_at_ms ASC, memory_id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut values = Vec::new();
    for row in rows {
        let (schema_version, projection_kind, memory_id, canonical_updated_at_ms, enqueued_at_ms) =
            row?;
        if schema_version != i64::from(OUTBOX_SCHEMA_VERSION) {
            return Err(StateError::Integrity(format!(
                "unknown projection outbox schema version {schema_version}"
            )));
        }
        values.push(ProjectionOutbox {
            schema_version: OUTBOX_SCHEMA_VERSION,
            projection_kind,
            memory_id,
            canonical_updated_at_ms,
            enqueued_at_ms,
        });
    }
    Ok(values)
}

fn load_repairs_tx(tx: &Transaction<'_>) -> Result<Vec<ProjectionRepair>, StateError> {
    let mut statement = tx.prepare(
        "SELECT schema_version, repair_id, projection_kind, reason, state, canonical_row_count, \
                projection_row_count, mismatch_count, detected_at_ms, completed_at_ms \
         FROM memory_projection_repairs ORDER BY detected_at_ms ASC, repair_id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, i64>(8)?,
            row.get::<_, Option<i64>>(9)?,
        ))
    })?;
    let mut values = Vec::new();
    for row in rows {
        let (
            schema_version,
            repair_id,
            projection_kind,
            reason,
            state,
            canonical_row_count,
            projection_row_count,
            mismatch_count,
            detected_at_ms,
            completed_at_ms,
        ) = row?;
        if schema_version != i64::from(REPAIR_SCHEMA_VERSION) {
            return Err(StateError::Integrity(format!(
                "unknown projection repair schema version {schema_version}"
            )));
        }
        values.push(ProjectionRepair {
            schema_version: REPAIR_SCHEMA_VERSION,
            repair_id,
            projection_kind,
            reason,
            state,
            canonical_row_count,
            projection_row_count,
            mismatch_count,
            detected_at_ms,
            completed_at_ms,
        });
    }
    Ok(values)
}

fn system_now_ms() -> Result<i64, MemoryError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(StateError::Clock)?;
    i64::try_from(duration.as_millis()).map_err(|_| {
        MemoryError::State(StateError::Integrity(
            "system timestamp exceeds SQLite INTEGER".to_owned(),
        ))
    })
}
