CREATE TABLE action_records (
    action_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch >= 0),
    result_digest TEXT REFERENCES artifact_metadata(digest) ON DELETE RESTRICT,
    last_event_sequence INTEGER NOT NULL CHECK (last_event_sequence >= 0),
    updated_at_ms INTEGER NOT NULL,
    CHECK (state <> 'committed' OR result_digest IS NOT NULL)
) STRICT;

CREATE TABLE controller_runtime (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch >= 0)
) STRICT;
INSERT INTO controller_runtime(singleton, execution_epoch) VALUES (1, 0);

CREATE TABLE checkpoint_integrity (
    generation INTEGER PRIMARY KEY,
    previous_hash TEXT,
    checkpoint_hash TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    action_sequence INTEGER NOT NULL CHECK (action_sequence >= 0),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TRIGGER action_records_no_delete
BEFORE DELETE ON action_records
BEGIN
    SELECT RAISE(ABORT, 'action records are durable authority state');
END;

CREATE TRIGGER checkpoint_integrity_no_update
BEFORE UPDATE ON checkpoint_integrity
BEGIN
    SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable');
END;

CREATE TRIGGER checkpoint_integrity_no_delete
BEFORE DELETE ON checkpoint_integrity
BEGIN
    SELECT RAISE(ABORT, 'checkpoint integrity rows are immutable');
END;
