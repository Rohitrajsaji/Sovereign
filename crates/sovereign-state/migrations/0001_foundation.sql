CREATE TABLE state_records (
    namespace TEXT NOT NULL,
    record_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, record_key)
) STRICT;

CREATE TABLE event_journal (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at_ms INTEGER NOT NULL
) STRICT;

CREATE TRIGGER event_journal_no_update
BEFORE UPDATE ON event_journal
BEGIN
    SELECT RAISE(ABORT, 'event_journal is append-only');
END;

CREATE TRIGGER event_journal_no_delete
BEFORE DELETE ON event_journal
BEGIN
    SELECT RAISE(ABORT, 'event_journal is append-only');
END;

