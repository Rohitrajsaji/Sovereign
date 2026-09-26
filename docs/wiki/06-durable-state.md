# Durable state

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Authoritative execution state is a SQLite database opened by `StateStore` (`crates/sovereign-state/src/lib.rs`). `CURRENT_SCHEMA_VERSION` is `7`. The migration list is `MIGRATIONS`, checked against `migrations/manifest.json`.

On 2026-09-25 the gitignored file `.sovereign/state.sqlite3` had `schema_migrations` rows 1 through 7 and zero rows in `state_records`, `event_journal`, `action_records`, and `checkpoint_integrity`. `PRAGMA user_version` was `0`. Sovereign tracks schema in `schema_migrations`, not in `user_version`. That file is a local runtime database, not evidence of a completed goal. Do not commit it (`.gitignore` ignores `*.sqlite3`).

## Connection pragmas

`configure_connection` sets `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=FULL`, and `wal_autocheckpoint=1000`. `checkpoint_wal` runs `PRAGMA wal_checkpoint(TRUNCATE)`. WAL sidecars (`-wal`, `-shm`) are expected beside a live database.

## Migrations

| Version | File | Creates |
| --- | --- | --- |
| 1 | `migrations/0001_foundation.sql` | `state_records` (namespace, record_key, value_json, version, updated_at_ms), append-only `event_journal` with update and delete triggers |
| 2 | `migrations/0002_artifacts.sql` | `artifact_metadata`, `artifact_references` |
| 3 | `migrations/0003_security_kernel.sql` | `action_records`, `controller_runtime` (epoch singleton, starts at 0), `checkpoint_integrity`; action rows cannot be deleted; checkpoint rows cannot be updated or deleted |
| 4 | `migrations/0004_memory.sql` | Memory conflict sets, records, role visibility, source evidence and fingerprints, invalidation predicates, conflict members |
| 5 | `migrations/0005_memory_retrieval.sql` | Conflict key, confidence, lineage, content digest, FTS5 `memory_fts_projection` |
| 6 | `migrations/0006_memory_projection_outbox.sql` | `memory_projection_outbox`, `memory_projection_repairs`, enqueue triggers |
| 7 | `migrations/0007_security_audit.sql` | Hash-chained `security_audit_events` and `security_audit_head` |

`action_records.state = 'committed'` requires a non-null `result_digest` referencing `artifact_metadata`. Actions are bound to `execution_epoch`.

There is no SQL table for budgets or approvals. Those are policy structs stored as `state_records` (for example `controller.approval_request`, `controller.approval_claim`) plus audit provenance. Do not add a shadow approvals database.

## `StateStore` operations

Opening, schema version, transactions, `put_state` / `get_state` / `state_records`, `append_event` / `journal` / `journal_after`.

Compare-and-apply:

- `compare_and_apply_state_records_with_events`
- `compare_and_apply_state_records_with_events_guarded`
- `compare_and_put_state_record_with_event`

Use these for transitions that must not lose a concurrent writer. A plain `put_state` is not a substitute when the caller is racing recovery or another advance.

Artifacts: `register_artifact`, `artifact_metadata`, `add_artifact_reference`, `remove_artifact_reference`, `unreferenced_artifacts_before`. Blob bytes live in `sovereign-evidence::ArtifactStore`, not in SQLite. SQLite stores the digest and reference counts.

Actions: `insert_action_record`, `transition_action_with_event`, `recover_*`, `reconcile_historical_unknown_action`, `commit_historical_reconciled_action`, `fail_historical_reconciled_action`.

Epochs: `current_execution_epoch`, `advance_execution_epoch`.

Checkpoints: `append_checkpoint_integrity`, `append_recovery_checkpoint_integrity`, `latest_valid_checkpoint_ancestry`, `recovery_integrity_check`. The hash covers generation, previous hash, payload digest, and action sequence. A corrupt tail can be anchored with a recovery checkpoint. Ancestry walks skip invalid hashes. A valid older checkpoint is not permission to replay work; see [07-recovery-and-crash.md](07-recovery-and-crash.md).

Audit: `security_audit_log()` returns `SecurityAuditLog` with `append`, `head`, `verify_chain`, and `verify_prefix`. The genesis digest is `SECURITY_AUDIT_GENESIS_DIGEST` in `lib.rs`.

## Namespaces

`state_records.namespace` is a string. Keys inside a namespace are often revision-scoped: `{plan_id}@r{revision}:{logical_key}` via `revision_scoped_key`. Bare keys without `@r` are accepted only for revision 1 under `LegacyRev1Authority`. Superseding a plan leaves old keys in place.

Namespaces confirmed as constants or direct writes:

| Namespace | Owner |
| --- | --- |
| `controller.goal_intent` | goal runner |
| `controller.goal_intent_claim` | goal runner |
| `controller.goal_compilation_budget` | production driver |
| `controller.plan` | active pointer, key `active` |
| `controller.plan_document` | active document |
| `controller.plan_revision` | immutable revisions |
| `controller.plan_revision_diff` | N to N+1 diff |
| `controller.plan_revision_lifecycle` | revision lifecycle |
| `controller.compilation_evidence` | compiler evidence |
| `controller.repository_baseline` | repo baseline |
| `controller.task` | task state |
| `controller.task_capability_grant` | per-task capability grant |
| `controller.task_runtime` | runtime lookup; uncommitted work scopes this by revision |
| `controller.attempt` | attempts |
| `controller.verification` | verification results |
| `controller.evidence_item` | evidence index rows |
| `controller.failure_record` | failure records |
| `controller.repair_packet` | repair packets |
| `controller.completion_record` | completion |
| `controller.plan_finalization` | finalization |
| `controller.integration_checkpoint` | cross-repo gate |
| `controller.action_intent` | pre-dispatch intent |
| `controller.action_reconciliation` | unknown-outcome reconciliation |
| `controller.approval_request` | approval requests |
| `controller.approval_claim` | exact approval claims (`sovereign-tools`) |
| `controller.autonomy_action_charge` | budget charges |
| `controller.rollback` | rollback records |
| `controller.cancellation_request` | cancellation |
| `controller.verification_command_intent` | verification command intent |
| `controller.secret_action_lifecycle` | secret lease lifecycle |
| `controller.process_lease` | process leases |
| `controller.worktree_conflict` | worktree conflicts |
| `controller.offline_node_modules` | offline dependency provenance |
| `controller.resource_lease` | resource leases |
| `controller.resource_pressure` | pressure events |
| `controller.resource_residency` | model and browser residency |
| `controller.resource_governor` | governor snapshot |
| `controller.browser_profile_grant` | browser profile |
| `controller.browser_download_record` | downloads |
| `controller.browser_network_reservation` | browser network reservation |
| `controller.browser_semantic_contract` | semantic contract |
| `controller.browser_semantic_proof` | semantic proof |
| `controller.managed_loopback_app` | managed loopback app |
| `controller.replan_scope_counter` | replan counters |
| `controller.policy`, `controller.permission`, `controller.acceptance` | policy projections read by tests and control surfaces |

This list is the set found by search, not a closed schema. A new namespace needs a schema version constant and a migration story if its shape is durable. Do not overload `value_json` with an unversioned blob.

## Checkpoint manifest versions

Controller constants: `LEGACY_CHECKPOINT_MANIFEST_SCHEMA_VERSION` = 1, `AUTONOMY_SECURITY_CHECKPOINT_MANIFEST_SCHEMA_VERSION` = 2, `CHECKPOINT_MANIFEST_SCHEMA_VERSION` = 3. Recovery must keep reading older manifests. New writers use version 3.

Action intent schema versions in the controller: legacy 2, current `ACTION_INTENT_SCHEMA_VERSION` = 3, repository actions `REPOSITORY_ACTION_INTENT_SCHEMA_VERSION` = 4.

## Content-addressed bytes

`ArtifactStore` writes content-addressed files under a caller-supplied CAS root, using a temp file, fsync where meaningful, and atomic rename, then a SQLite transaction that publishes the digest. Orphan collection uses `unreferenced_artifacts_before`. The architecture's `~/.sovereign/cas/sha256/<prefix>/<digest>` layout is the design default. Confirm the root at the open call.

Ingress redaction happens before retention. `REDACTION_EVENT_SCHEMA_V1` is `sovereign-redaction-event-v1`. Model context receives synopses, not raw logs, unless a governed expansion handle says otherwise ([13-context-memory-roles-skills.md](13-context-memory-roles-skills.md)).
