CREATE TABLE security_audit_events (
    sequence INTEGER PRIMARY KEY,
    event_version INTEGER NOT NULL CHECK (event_version = 1),
    actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
    plan_id TEXT,
    task_id TEXT,
    attempt_id TEXT,
    action_id TEXT,
    execution_epoch INTEGER CHECK (execution_epoch IS NULL OR execution_epoch >= 0),
    decision TEXT NOT NULL CHECK (length(trim(decision)) > 0),
    action TEXT NOT NULL CHECK (length(trim(action)) > 0),
    policy_digest TEXT NOT NULL CHECK (length(trim(policy_digest)) > 0),
    config_digest TEXT NOT NULL CHECK (length(trim(config_digest)) > 0),
    tool_digest TEXT NOT NULL CHECK (length(trim(tool_digest)) > 0),
    approval_provenance_digest TEXT,
    evidence_provenance_digest TEXT,
    occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    result TEXT NOT NULL CHECK (length(trim(result)) > 0),
    previous_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE security_audit_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    event_count INTEGER NOT NULL CHECK (event_count >= 0),
    head_digest TEXT NOT NULL
) STRICT;

INSERT INTO security_audit_head(singleton, event_count, head_digest)
VALUES (
    1,
    0,
    'sha256:0000000000000000000000000000000000000000000000000000000000000000'
);

CREATE TRIGGER security_audit_events_no_update
BEFORE UPDATE ON security_audit_events
BEGIN
    SELECT RAISE(ABORT, 'security audit events are immutable');
END;

CREATE TRIGGER security_audit_events_no_delete
BEFORE DELETE ON security_audit_events
BEGIN
    SELECT RAISE(ABORT, 'security audit events are append-only');
END;

CREATE TRIGGER security_audit_head_no_delete
BEFORE DELETE ON security_audit_head
BEGIN
    SELECT RAISE(ABORT, 'security audit head is durable authority state');
END;
