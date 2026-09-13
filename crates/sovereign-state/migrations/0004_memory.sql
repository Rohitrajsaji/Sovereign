CREATE TABLE memory_conflict_sets (
    conflict_set_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    repository_id TEXT,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    resolved_at_ms INTEGER
) STRICT;

CREATE TABLE memory_records (
    memory_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN (
        'governed_knowledge',
        'validated_project_fact',
        'episodic',
        'procedural_candidate',
        'preference_context'
    )),
    project_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('project', 'agent', 'shared')),
    agent_id TEXT,
    subject TEXT NOT NULL,
    predicate TEXT NOT NULL,
    assertion TEXT NOT NULL,
    trust TEXT NOT NULL CHECK (trust IN ('governed', 'validated', 'observed', 'unreviewed')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    status TEXT NOT NULL CHECK (status IN (
        'active', 'stale', 'superseded', 'deprecated', 'expired', 'archived'
    )),
    repository_id TEXT,
    repository_revision TEXT,
    producing_task_id TEXT,
    producing_attempt_id TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    validated_at_ms INTEGER,
    version INTEGER NOT NULL CHECK (version >= 1),
    supersedes_id TEXT REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    superseded_by_id TEXT REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    expires_at_ms INTEGER,
    access_count INTEGER NOT NULL DEFAULT 0 CHECK (access_count >= 0),
    last_accessed_at_ms INTEGER,
    conflict_set_id TEXT REFERENCES memory_conflict_sets(conflict_set_id) ON DELETE RESTRICT,
    normal_injection INTEGER NOT NULL DEFAULT 1 CHECK (normal_injection IN (0, 1)),
    exclusion_reason TEXT,
    CHECK (
        (scope_kind = 'agent' AND agent_id IS NOT NULL AND length(agent_id) > 0)
        OR (scope_kind <> 'agent' AND agent_id IS NULL)
    ),
    CHECK ((trust <> 'validated') OR validated_at_ms IS NOT NULL),
    CHECK ((normal_injection = 1 AND exclusion_reason IS NULL) OR normal_injection = 0)
) STRICT;

CREATE TABLE memory_role_visibility (
    memory_id TEXT NOT NULL REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    role_id TEXT NOT NULL,
    PRIMARY KEY (memory_id, role_id)
) STRICT;

CREATE TABLE memory_source_evidence (
    memory_id TEXT NOT NULL REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (memory_id, evidence_id)
) STRICT;

CREATE TABLE memory_source_fingerprints (
    memory_id TEXT NOT NULL REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    fingerprint_kind TEXT NOT NULL CHECK (fingerprint_kind IN (
        'file_blob',
        'symbol',
        'dependency_manifest',
        'command_tool_version',
        'repository_commit_range'
    )),
    fingerprint_key TEXT NOT NULL,
    fingerprint_digest TEXT NOT NULL,
    PRIMARY KEY (memory_id, fingerprint_kind, fingerprint_key)
) STRICT;

CREATE TABLE memory_invalidation_predicates (
    memory_id TEXT NOT NULL REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    predicate_kind TEXT NOT NULL CHECK (predicate_kind IN (
        'fingerprint_changed',
        'repository_revision_changed',
        'expires_at'
    )),
    predicate_key TEXT NOT NULL,
    expected_value TEXT,
    PRIMARY KEY (memory_id, predicate_kind, predicate_key)
) STRICT;

CREATE TABLE memory_conflict_members (
    conflict_set_id TEXT NOT NULL REFERENCES memory_conflict_sets(conflict_set_id) ON DELETE RESTRICT,
    memory_id TEXT NOT NULL REFERENCES memory_records(memory_id) ON DELETE RESTRICT,
    PRIMARY KEY (conflict_set_id, memory_id)
) STRICT;

CREATE INDEX memory_records_scope_subject_idx
ON memory_records(project_id, scope_kind, agent_id, repository_id, subject, predicate, status);

CREATE INDEX memory_records_injection_idx
ON memory_records(project_id, status, normal_injection, expires_at_ms);

CREATE INDEX memory_source_fingerprints_lookup_idx
ON memory_source_fingerprints(fingerprint_kind, fingerprint_key, fingerprint_digest, memory_id);

CREATE INDEX memory_conflict_members_memory_idx
ON memory_conflict_members(memory_id, conflict_set_id);

CREATE TRIGGER memory_records_no_delete
BEFORE DELETE ON memory_records
BEGIN
    SELECT RAISE(ABORT, 'memory records are durable provenance');
END;

CREATE TRIGGER memory_conflict_sets_no_delete
BEFORE DELETE ON memory_conflict_sets
BEGIN
    SELECT RAISE(ABORT, 'memory conflict sets are durable provenance');
END;
