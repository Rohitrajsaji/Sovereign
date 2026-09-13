ALTER TABLE memory_records
ADD COLUMN conflict_key TEXT NOT NULL DEFAULT '';

UPDATE memory_records
SET conflict_key = subject || char(31) || predicate
WHERE conflict_key = '';

-- v4 stored confidence as REAL 0..1. v5 makes the canonical durable contract
-- an integer percentage while retaining the exact legacy value for checksum-
-- compatible migration of already-created v4 databases.
ALTER TABLE memory_records
RENAME COLUMN confidence TO confidence_legacy_real;

ALTER TABLE memory_records
ADD COLUMN confidence INTEGER NOT NULL DEFAULT 0
CHECK (confidence >= 0 AND confidence <= 100);

CREATE TEMP TABLE memory_confidence_migration_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO memory_confidence_migration_guard(valid)
SELECT CASE
    WHEN EXISTS (
        SELECT 1
        FROM memory_records
        WHERE confidence_legacy_real < 0.0
           OR confidence_legacy_real > 1.0
           OR abs((confidence_legacy_real * 100.0) - round(confidence_legacy_real * 100.0)) > 0.000000001
    ) THEN 0
    ELSE 1
END;

UPDATE memory_records
SET confidence = CAST(round(confidence_legacy_real * 100.0) AS INTEGER);

DROP TABLE memory_confidence_migration_guard;

ALTER TABLE memory_records
ADD COLUMN lineage_id TEXT NOT NULL DEFAULT '';

WITH RECURSIVE memory_lineage(memory_id, lineage_id) AS (
    SELECT memory_id, memory_id
    FROM memory_records
    WHERE supersedes_id IS NULL
    UNION ALL
    SELECT child.memory_id, parent.lineage_id
    FROM memory_records child
    JOIN memory_lineage parent ON child.supersedes_id = parent.memory_id
)
UPDATE memory_records
SET lineage_id = (
    SELECT memory_lineage.lineage_id
    FROM memory_lineage
    WHERE memory_lineage.memory_id = memory_records.memory_id
)
WHERE lineage_id = '';

CREATE TEMP TABLE memory_lineage_migration_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO memory_lineage_migration_guard(valid)
SELECT CASE WHEN EXISTS (
    SELECT 1 FROM memory_records WHERE lineage_id = ''
) THEN 0 ELSE 1 END;

DROP TABLE memory_lineage_migration_guard;

-- Cryptographic content digests for pre-v5 rows are deterministically backfilled
-- by sovereign-memory when it first binds to the canonical StateStore. New v5
-- writes must always provide the durable digest directly.
ALTER TABLE memory_records
ADD COLUMN content_digest TEXT NOT NULL DEFAULT '';

ALTER TABLE memory_conflict_sets
ADD COLUMN conflict_key TEXT NOT NULL DEFAULT '';

UPDATE memory_conflict_sets
SET conflict_key = subject || char(31) || predicate
WHERE conflict_key = '';

CREATE INDEX memory_records_conflict_key_idx
ON memory_records(project_id, repository_id, scope_kind, agent_id, conflict_key, status);

CREATE TRIGGER memory_records_conflict_key_required_insert
BEFORE INSERT ON memory_records
WHEN NEW.conflict_key = ''
BEGIN
    SELECT RAISE(ABORT, 'memory conflict_key is required');
END;

CREATE TRIGGER memory_records_lineage_required_insert
BEFORE INSERT ON memory_records
WHEN NEW.lineage_id = ''
BEGIN
    SELECT RAISE(ABORT, 'memory lineage_id is required');
END;

CREATE TRIGGER memory_records_content_digest_required_insert
BEFORE INSERT ON memory_records
WHEN NEW.content_digest = ''
BEGIN
    SELECT RAISE(ABORT, 'memory content_digest is required');
END;

CREATE TRIGGER memory_records_confidence_consistent_insert
BEFORE INSERT ON memory_records
WHEN abs((NEW.confidence_legacy_real * 100.0) - NEW.confidence) > 0.000000001
BEGIN
    SELECT RAISE(ABORT, 'memory confidence representations disagree');
END;

CREATE TRIGGER memory_records_confidence_consistent_update
BEFORE UPDATE OF confidence, confidence_legacy_real ON memory_records
WHEN abs((NEW.confidence_legacy_real * 100.0) - NEW.confidence) > 0.000000001
BEGIN
    SELECT RAISE(ABORT, 'memory confidence representations disagree');
END;

CREATE TRIGGER memory_records_conflict_key_required_update
BEFORE UPDATE OF conflict_key ON memory_records
WHEN NEW.conflict_key = ''
BEGIN
    SELECT RAISE(ABORT, 'memory conflict_key is required');
END;

CREATE TRIGGER memory_conflict_sets_conflict_key_required_insert
BEFORE INSERT ON memory_conflict_sets
WHEN NEW.conflict_key = ''
BEGIN
    SELECT RAISE(ABORT, 'memory conflict-set conflict_key is required');
END;

CREATE VIRTUAL TABLE memory_fts_projection USING fts5(
    memory_id UNINDEXED,
    project_id UNINDEXED,
    repository_id UNINDEXED,
    kind UNINDEXED,
    trust UNINDEXED,
    status UNINDEXED,
    conflict_key,
    subject,
    predicate,
    assertion,
    tokenize = 'unicode61'
);

INSERT INTO memory_fts_projection(
    memory_id,
    project_id,
    repository_id,
    kind,
    trust,
    status,
    conflict_key,
    subject,
    predicate,
    assertion
)
SELECT
    memory_id,
    project_id,
    COALESCE(repository_id, ''),
    kind,
    trust,
    status,
    conflict_key,
    subject,
    predicate,
    assertion
FROM memory_records
ORDER BY memory_id ASC;
