CREATE TABLE artifact_metadata (
    digest TEXT PRIMARY KEY,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE artifact_references (
    reference_id TEXT NOT NULL,
    digest TEXT NOT NULL REFERENCES artifact_metadata(digest) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (reference_id, digest)
) STRICT;

CREATE INDEX artifact_references_digest_idx
ON artifact_references(digest);

CREATE INDEX artifact_metadata_created_idx
ON artifact_metadata(created_at_ms);
