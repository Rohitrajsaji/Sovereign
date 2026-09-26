# Code map

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25). Line counts are approximate. Prefer symbol names over line numbers.

Workspace members are declared in [Cargo.toml](../../Cargo.toml). Edition 2024, Rust 1.89, `unsafe_code = forbid`, Clippy `pedantic` plus `unwrap_used` and `expect_used` denied.

## Where to look

| Question | Start here |
| --- | --- |
| Who may change execution state? | `crates/sovereign-controller` |
| Is this plan legal? | `crates/sovereign-plan` `PlanValidator` |
| Where is the row stored? | `crates/sovereign-state` `StateStore` |
| May this action run? | `crates/sovereign-policy` |
| How is a process sandboxed? | `crates/sovereign-tools` `ProcessRunner` |
| Worktree or index? | `crates/sovereign-repo` |
| What may the model see? | `crates/sovereign-context` |
| What is remembered? | `crates/sovereign-memory` |
| How is llama-server launched? | `crates/sovereign-model` |
| Large blobs and redaction? | `crates/sovereign-evidence` |
| CLI or dashboard? | `apps/sovereign` |
| Release and crash tests? | `crates/sovereign-eval` |

## Application

`apps/sovereign` (binary `sovereign`, version `0.1.0`):

| File | Role |
| --- | --- |
| `src/main.rs` | Subcommands: `run`, `doctor`, `goal`, `status`, `evidence`, `eval`, `pause`, `resume`, `approvals`, `approval`, `serve` |
| `src/runner.rs` | Production composition: lock, registry, controller, model, tools, browser, production driver loop (`MAX_ADVANCES` = 64) |
| `src/run_lock.rs` | Kernel file lock sidecar; not durable Controller truth |
| `src/control_api.rs` | Loopback HTTP, token/CSRF/CSP, embedded UI |
| `src/actor.rs` | Single-writer Controller actor and run lock |
| `src/app_data.rs` | Settings and project index |
| `src/execution.rs` | `serve --execute` step and service status |
| `src/doctor.rs` | Onboarding machine checks |
| `ui/` / `ui-dist/` | React UI and committed build |

## Crates

### `sovereign-types`

`src/lib.rs`, `src/interface_contracts.rs`. Typed IDs, `ErrorCode`, `UnixMillis`, and the frozen interface manifest. No product dependencies.

### `sovereign-state`

`StateStore` in `src/lib.rs` (about 3.2k lines), migrations `0001` through `0007`, `src/bin/state-fixture-writer.rs` (writes one journal event, then sleeps; crash fixture). Depends only on `sovereign-types`.

### `sovereign-evidence`

`Redactor` (19 generic credential shapes, `REDACTOR_VERSION_V1` = 1), `EvidenceCapture`, `EvidenceCompressor`, `ArtifactStore`. Depends on state.

### `sovereign-policy`

`src/lib.rs` (about 4.5k lines), `src/resources.rs`, `src/browser.rs`. `Capability`, approvals, command policy, secrets, network and IDNA, `MacSandboxExecBackend`, `HardwareProfileV1`, `M6ResourceGovernor`. `build.rs` compiles `idna_uts46_helper.c` on macOS.

### `sovereign-model`

`ModelBackend`, `LocalOpenAiBackend`, `LlamaServerLaunch`, `DeterministicFakeBackend` in `src/lib.rs`. Binary `src/bin/model-smoke.rs`.

### `sovereign-repo`

| File | Role |
| --- | --- |
| `src/lib.rs` | `ProjectRegistry`, snapshots, exact retrieval, pinned `/usr/bin/git` |
| `src/worktree.rs` | `WorktreeLease`, offline `node_modules` materialization |
| `src/lexical.rs` | Rebuildable SQLite FTS index |
| `src/structural.rs` | tree-sitter symbol and dependency graph (Rust, TypeScript, TSX) |

### `sovereign-context`

| File | Role |
| --- | --- |
| `src/lib.rs` | `ContextPlanner`, `ContextPacket`, levels C0–C3 |
| `src/routing.rs` | `RetrievalRouter` |
| `src/telemetry.rs` | Token and context accounting |
| `src/memory.rs` | Bridge from memory into context evidence |

### `sovereign-memory`

| File | Role |
| --- | --- |
| `src/lib.rs` | `MemoryManager`, records, conflicts, scopes |
| `src/retrieval.rs` | Synopses and bounded expansion |
| `src/projection.rs` | FTS projection outbox and repair |
| `src/learning.rs` | `EpisodeRecorder`; reads controller proof records and does not own them |

### `sovereign-plan`

| File | Role |
| --- | --- |
| `src/lib.rs` | `PlanIr`, `PlanValidator`, cross-repo and browser acceptance contracts. Schema embedded from `schemas/plan-ir-v1.json` |
| `src/compiler.rs` | `PlanCompiler::compile` |
| `src/depth.rs` | `DepthClassifier`, `ExecutionDepth` D0–D4 |
| `src/replan.rs` | `ReplanScope`, smallest-scope revision diff |
| `src/policy.rs` | `local_autonomous_plan_policy` |

### `sovereign-tools`

| File | Role |
| --- | --- |
| `src/lib.rs` | `ProcessRunner`, action receipts, web acquire |
| `src/catalog.rs` | Frozen tools `tool.patch`, `tool.read`, `tool.browser`, `tool.process` at `1.0.0` |
| `src/browser.rs` | CDP adapter and Chrome process-group reap |

Feature `recovery-test-hooks` is defined here and re-exported by the controller for crash tests.

### `sovereign-controller`

Largest crate. `src/lib.rs` is on the order of 38k lines. Modules:

| Module | Role |
| --- | --- |
| `lib.rs` | `Controller`, task and attempt machines, activation, leases, execution, verification, repair, checkpoints, `RecoveryManager` |
| `goal_runner.rs` | Durable goal intent claim, activation, completion, finalization |
| `production_driver.rs` | One-step `advance_production_goal` |
| `browser.rs` | Browser leases, loopback apps, semantic acceptance |
| `postgres_broker.rs` | Unix-only Postgres TCP broker. Does not start Postgres |
| `resources.rs` | Residency coordinator for model and CDP browser |
| `roles.rs` | Role profiles (`ROLE_PROFILE_VERSION` = `1.3.0`) |
| `skills.rs` | Skill manifests and selection ceilings |
| `local_control.rs` | Read model used by CLI and the control API |

Tests: `tests/t07.rs` and `tests/m6_t06_resilience.rs`.

### `sovereign-eval`

`src/lib.rs`, `runner.rs`, `schema.rs`, `release.rs`, `compat.rs`, `local_smoke.rs`. Integration tests live under `tests/`. Fixtures: `fixtures/m9/policy.json`, `tests/fixtures/scenario1/`, `tests/fixtures/product_inventory/`.

## Other trees

| Path | Meaning |
| --- | --- |
| `schemas/` | Frozen JSON contracts: Plan IR, hardware profile, memory record, resource lease and pressure, interface contracts |
| `output/` | Frozen architecture, roadmap, scenarios, amendments, audits. Not generated code |
| `implementation/evidence/` | Per-task closure JSON. Not a runtime database |
| `BUILD_STATE.json` | Roadmap progress index. It lags the post-roadmap commit and the uncommitted diff. See [18-status-blockers-debt.md](18-status-blockers-debt.md) |
| `adapters/scrapling/parser_worker.py` | Optional parser worker. Not the HTTP client |
| `scripts/verify.sh` | fmt, clippy, `cargo test --workspace` |
| `.models/`, `.tools/` | Gitignored local GGUF and llama.cpp build. Not source |
| `research/` | Gitignored reference clones. Not product source |
| `.kilo/worktrees/sideways-conifer` | Detached worktree at the same commit. Not a second product tree |
| `.sovereign/state.sqlite3` | Local runtime DB, gitignored. Inspected 2026-09-25: migrations 1–7 applied, counted data tables empty |

## Uncommitted files (2026-09-25)

The working tree changes the controller, plan, policy, state, tools, repo tests, memory learning, the app runner, and several eval tests. Themes in the diff: revision-scoped runtime lookups, goal-driver kill matrices, model-launch headroom, pinned Rust verification admission (`admit_rust_verification`), and subprocess allowance ceilings. This diff is not a closed milestone.
