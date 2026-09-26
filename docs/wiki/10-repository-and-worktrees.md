# Repository and worktrees

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Repository intelligence is `crates/sovereign-repo`. It does not decide permissions. The Controller asks it for snapshots, exact facts, leases, and index hits.

## Registry and baselines

`ProjectRegistry` registers repositories. The production runner uses repository id `repo.local` and optional `SOVEREIGN_PROJECT_CONFIG` (schema version 1).

`RepositorySnapshot` includes `protected_changes_present` when the worktree has staged, unstaged, or untracked user changes. Recovery and in-place edits must not treat that dirtiness as Sovereign's own diff to reset. Architecture invariant 11 forbids `reset --hard`, `clean`, force-push, and overwriting pre-existing user work to recover a task.

Git is pinned: `SYSTEM_GIT_PATH` = `/usr/bin/git`. `hardened_git_command` clears unsafe environment and config. Worktree preparation rejects filters, LFS, promisor remotes, hooks, and local Git config that enables exec or network.

`ExactRetriever` serves exact file and diff evidence. Stale content hashes must refresh rather than be returned as current (`tests/exact_retrieval.rs`).

## Worktrees

`WorktreeLease` (`WORKTREE_LEASE_SCHEMA_VERSION` = 1) is created by `prepare_worktree_lease`, materialized by `materialize_worktree`, checked by `validate_worktree_lease`, and removed by `release_worktree`. Drift fails closed. The lease path is bound to a controller-owned root, not to a model-supplied absolute path.

D3 and D4 mutations default to these worktrees (`M3-T04`). D0 and D1 in-place edits require an explicit project profile, a fingerprint of pre-existing user changes, and a patch that can be rolled back without touching those changes.

`CHANGE_SET_SCHEMA_VERSION` = 2. Composition conflicts use `COMPOSITION_CONFLICT_SCHEMA_VERSION` = 1 and namespace `controller.worktree_conflict`.

Offline `node_modules` materialization is allowed only with provenance (`OFFLINE_NODE_MODULES_PROVENANCE_SCHEMA_VERSION` = 1, namespace `controller.offline_node_modules`). Ceilings in the controller: `MAX_OFFLINE_NODE_MODULES_ENTRIES` = 1_000_000 and `MAX_OFFLINE_NODE_MODULES_BYTES` = 16 GiB. This is not a package install. `package_install` remains a separate capability.

## Lexical index

`src/lexical.rs` is a rebuildable SQLite FTS index (`INDEX_SCHEMA_VERSION` = 1). It is not authoritative state. Deleting it is safe if the builder can rerun; do not store the only copy of a fact there.

| Constant | Value |
| --- | --- |
| `DEFAULT_MAX_FILES` | 50_000 |
| `DEFAULT_MAX_FILE_BYTES` | 2 MiB |
| `DEFAULT_MAX_CHUNK_BYTES` | 8 KiB |
| `DEFAULT_MAX_CHUNKS_PER_FILE` | 256 |
| `DEFAULT_BATCH_FILES` | 64 |
| `FTS_CONNECTION_CACHE_HARD_KIB` | 8 MiB |
| `FTS_PROCESS_CACHE_HARD_KIB` | 16 MiB |
| `SQLITE_AGGREGATE_CACHE_HARD_KIB` | 64 MiB |
| `WAL_HEALTH_BYTES` | 256 MiB |
| `MAX_SEARCH_REFRESHES` | 2 |

Search that hits a stale row refreshes, up to that refresh cap.

## Structural graph

`src/structural.rs` uses tree-sitter for Rust, TypeScript, and TSX (`STRUCTURAL_SCHEMA_VERSION` = 1). Other languages return `StructuralLookup::UnsupportedLanguage`. Do not guess symbols for those languages. File caps match the lexical index (50_000 files, 2 MiB). `DEFAULT_BATCH_FILES` = 32. `MAX_SOURCE_RACE_RETRIES` = 2. A schema fingerprint invalidates the on-disk graph when parsers change.

Workspace pins: `tree-sitter` 0.25.10, `tree-sitter-rust` 0.24.0, `tree-sitter-typescript` 0.23.2.

## Tests

`baseline.rs`, `exact_retrieval.rs`, `lexical.rs`, `structural.rs`, `worktree.rs`. The uncommitted worktree tests cover path shims via `SOVEREIGN_REPO_PATH_SHIM_*`.
