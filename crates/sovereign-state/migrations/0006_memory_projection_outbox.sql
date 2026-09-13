CREATE TABLE memory_projection_outbox (
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    projection_kind TEXT NOT NULL CHECK (projection_kind = 'memory_fts_v1'),
    memory_id TEXT NOT NULL REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    canonical_updated_at_ms INTEGER NOT NULL CHECK (canonical_updated_at_ms >= 0),
    enqueued_at_ms INTEGER NOT NULL CHECK (enqueued_at_ms >= 0),
    PRIMARY KEY (projection_kind, memory_id)
) STRICT;

CREATE TABLE memory_projection_repairs (
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    repair_id TEXT PRIMARY KEY,
    projection_kind TEXT NOT NULL CHECK (projection_kind = 'memory_fts_v1'),
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    canonical_row_count INTEGER NOT NULL CHECK (canonical_row_count >= 0),
    projection_row_count INTEGER NOT NULL CHECK (projection_row_count >= 0),
    mismatch_count INTEGER NOT NULL CHECK (mismatch_count >= 0),
    detected_at_ms INTEGER NOT NULL CHECK (detected_at_ms >= 0),
    completed_at_ms INTEGER,
    CHECK (
        (state = 'pending' AND completed_at_ms IS NULL)
        OR (state = 'completed' AND completed_at_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX memory_projection_outbox_enqueue_idx
ON memory_projection_outbox(projection_kind, enqueued_at_ms, memory_id);

CREATE INDEX memory_projection_repairs_state_idx
ON memory_projection_repairs(projection_kind, state, detected_at_ms, repair_id);

CREATE UNIQUE INDEX memory_projection_repairs_one_pending_idx
ON memory_projection_repairs(projection_kind)
WHERE state = 'pending';

CREATE TRIGGER memory_projection_repairs_no_delete
BEFORE DELETE ON memory_projection_repairs
BEGIN
    SELECT RAISE(ABORT, 'memory projection repair records are durable provenance');
END;

CREATE TRIGGER memory_projection_outbox_after_insert
AFTER INSERT ON memory_records
BEGIN
    INSERT INTO memory_projection_outbox(
        schema_version,
        projection_kind,
        memory_id,
        canonical_updated_at_ms,
        enqueued_at_ms
    ) VALUES (1, 'memory_fts_v1', NEW.memory_id, NEW.updated_at_ms, NEW.updated_at_ms)
    ON CONFLICT(projection_kind, memory_id) DO UPDATE SET
        canonical_updated_at_ms = excluded.canonical_updated_at_ms,
        enqueued_at_ms = excluded.enqueued_at_ms;
END;

CREATE TRIGGER memory_projection_outbox_after_searchable_update
AFTER UPDATE OF
    project_id,
    repository_id,
    kind,
    trust,
    status,
    conflict_key,
    subject,
    predicate,
    assertion
ON memory_records
BEGIN
    INSERT INTO memory_projection_outbox(
        schema_version,
        projection_kind,
        memory_id,
        canonical_updated_at_ms,
        enqueued_at_ms
    ) VALUES (1, 'memory_fts_v1', NEW.memory_id, NEW.updated_at_ms, NEW.updated_at_ms)
    ON CONFLICT(projection_kind, memory_id) DO UPDATE SET
        canonical_updated_at_ms = excluded.canonical_updated_at_ms,
        enqueued_at_ms = excluded.enqueued_at_ms;
END;

-- v5's FTS is disposable derived state.  v6 deliberately empties it and
-- seeds refresh intents from canonical memory so startup reconstruction proves
-- that the canonical store, not stale projection payload, is authoritative.
DELETE FROM memory_fts_projection;

INSERT INTO memory_projection_outbox(
    schema_version,
    projection_kind,
    memory_id,
    canonical_updated_at_ms,
    enqueued_at_ms
)
SELECT
    1,
    'memory_fts_v1',
    memory_id,
    updated_at_ms,
    updated_at_ms
FROM memory_records
ORDER BY memory_id ASC;
