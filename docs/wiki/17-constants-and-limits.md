# Constants and limits

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25). Values were read from the named symbols. If you change one, change this page in the same commit.

This page is the index. Behavior around each limit lives on the topic page.

## Identity and schema

| Symbol | Value | File |
| --- | --- | --- |
| `PLAN_IR_VERSION` | `1.2` | `crates/sovereign-plan/src/lib.rs` |
| `CURRENT_SCHEMA_VERSION` | `7` | `crates/sovereign-state/src/lib.rs` |
| `CHECKPOINT_MANIFEST_SCHEMA_VERSION` | `3` | `crates/sovereign-controller/src/lib.rs` |
| `ACTION_INTENT_SCHEMA_VERSION` | `3` | same |
| `REPOSITORY_ACTION_INTENT_SCHEMA_VERSION` | `4` | same |
| `ROLE_PROFILE_VERSION` | `1.3.0` | `crates/sovereign-controller/src/roles.rs` |
| `CANONICAL_TOOL_VERSION` | `1.0.0` | `crates/sovereign-tools/src/catalog.rs` |
| `MEMORY_STATE_SCHEMA_VERSION` | `6` | `crates/sovereign-memory/src/lib.rs` |
| `COMPILER_VERSION` | `sovereign-local-v1` | `apps/sovereign/src/runner.rs` |

Most other `*_SCHEMA_VERSION` constants in the workspace are `1`. A mismatch fails closed.

## Model and context

| Symbol | Value | File |
| --- | --- | --- |
| `M1_HARD_INPUT_CONTEXT_TOKENS` | 16384 | `crates/sovereign-model/src/lib.rs` |
| `M1_MODEL_OUTPUT_TOKENS` | 512 | `crates/sovereign-controller/src/lib.rs` |
| `M1_MODEL_UNCALIBRATED_ADMISSION_MIB` | 4096 | same |
| `MAX_COMPILER_MODEL_CALLS` | 2 | `crates/sovereign-plan/src/compiler.rs` |
| `EXTERNAL_MAX_OUTPUT_TOKENS` | 1024 | controller `lib.rs` |
| `EXTERNAL_MAX_EVIDENCE_ITEMS` | 16 | same |
| `MAX_LITERAL_BYTES` | 4096 | same |
| `MAX_REPOSITORY_PROPOSAL_BYTES` | 64 KiB | same |
| `ROLE_OUTPUT_TOKEN_CEILING` | 512 | `roles.rs` |
| runner load context / reserve | 8192 / 1536 | `apps/sovereign/src/runner.rs` |

## Compiler shape

| Symbol | Value | File |
| --- | --- | --- |
| `MAX_PROPOSAL_TASKS` | 2 | `compiler.rs` |
| `MAX_M3_TASKS` | 16 | same |
| `MAX_M3_ADDITIONAL_REPOSITORIES` | 8 | same |
| `MAX_M3_ACCEPTANCE` | 4 | same |
| `MAX_PRODUCTION_TASK_CONTRACT_BYTES` | 3000 | `production_driver.rs` |
| `MAX_ADVANCES` | 64 | `runner.rs` |

## M1 / 8 GB profile (`HardwareProfileV1::m1_8gb`)

| Field | Value |
| --- | --- |
| physical memory | 8192 MiB |
| logical CPUs | 8 |
| model slots | 1 |
| controlled working set soft / hard | 4864 / 5632 MiB |
| launch headroom soft / hard | 1536 / 1280 MiB |
| default model input / output reserve | 8192 / 1536 tokens |
| host free disk minimum | 20 GiB |
| Sovereign disk soft / hard | 40 / 60 GiB |
| heavy lease green recovery | 120 s |
| reload cooldown | 30 s |
| oscillation window | 300 s |
| max eviction cycles per window | 1 |
| unknown heavy admission | 3072 MiB |
| unknown heavy jobs / subprocesses | 2 / 2 |
| calibrated build jobs | 4 |
| Rust verification jobs / subprocesses | 1 / min(budget, 3) |

File: `crates/sovereign-policy/src/resources.rs`. Rust verification caps are applied in `admit_rust_verification`, not as profile fields.

## Process, web, browser, Postgres

| Symbol | Value | File |
| --- | --- | --- |
| `WEB_ACQUIRE_MAX_RESPONSE_BYTES` | 8 MiB | `sovereign-tools/src/lib.rs` |
| `WEB_ACQUIRE_MAX_REDIRECTS` | 8 | same |
| `WEB_ACQUIRE_MAX_TIMEOUT_MS` | 60000 | same |
| `MAX_CDP_FRAME_BYTES_HARD` | 4 MiB | `sovereign-tools/src/browser.rs` |
| `MAX_SYNOPSIS_BYTES_HARD` | 256 KiB | same |
| `MAX_DOM_BYTES_HARD` | 512 KiB | same |
| `MAX_DOWNLOAD_BYTES_HARD` | 128 MiB | same |
| `BROWSER_UNKNOWN_ADMISSION_MIB` | 1536 | controller `browser.rs` |
| `MANAGED_LOOPBACK_MAX_LIFETIME_MS` | 30000 | same |
| `MANAGED_LOOPBACK_SUBPROCESS_LIMIT` | 0 | same |
| `MAX_CLIENTS` | 8 | `postgres_broker.rs` |
| `MAX_STREAM_BYTES` | 16 MiB | same |
| control API header / body | 16 KiB / 64 KiB | `apps/sovereign/src/control_api.rs` |

## Repository indexes and skills

| Symbol | Value | File |
| --- | --- | --- |
| lexical/structural max files | 50000 | `lexical.rs`, `structural.rs` |
| max file bytes | 2 MiB | same |
| lexical chunk | 8 KiB, 256 chunks/file | `lexical.rs` |
| FTS process cache hard | 16 MiB | `lexical.rs` |
| WAL health | 256 MiB | `lexical.rs` |
| `MAX_OFFLINE_NODE_MODULES_BYTES` | 16 GiB | controller `lib.rs` |
| `MAX_OFFLINE_NODE_MODULES_ENTRIES` | 1000000 | same |
| `DEFAULT_MAX_SELECTED_SKILLS` | 4 | `skills.rs` |
| `HARD_MAX_SELECTED_SKILLS` | 16 | same |
| `HARD_MAX_SELECTED_BODY_TOKENS` | 3200 | same |
| memory retrieval results / tokens | 32 / 2048 | `memory/src/retrieval.rs` |

## Git pin

`SYSTEM_GIT_PATH` = `/usr/bin/git` in `crates/sovereign-repo/src/lib.rs`.
