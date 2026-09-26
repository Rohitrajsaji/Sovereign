# Status, blockers, and debt

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

## How to read status

Three layers disagree unless you keep them separate:

1. **Frozen roadmap** `output/implementation-plan.json` (`1.4-frozen`, architecture revision `2026-09-12.7`). It lists tasks. It does not record completion.
2. **`BUILD_STATE.json`**, `updated_at` `2026-09-20T03:40:50Z`, `roadmap_version` `1.4-frozen`. `current_task` and `current_gate` are null.
3. **Git.** Last commit `d266399` on 2026-09-24 is after every task-closure commit. The working tree on 2026-09-25 has 34 modified files that no evidence JSON binds.

Trust code and tests over `BUILD_STATE` when they conflict. Trust `BUILD_STATE` over the 2026-09-13 Codex audit.

## Tasks marked completed

`completed_tasks` includes every M0–M6 task, M7-T02, M7-T03, M8-T01, M9-T01 through M9-T04, and PD-T01 through PD-T06. Each points at `implementation/evidence/<id>.json`.

`completed_milestones` stops at **M6**. M7, M8, M9, and the product profile have completed tasks and no milestone object. **Verified** by reading `BUILD_STATE.json`. That is bookkeeping drift, not proof those milestones failed.

## Not completed, and intentionally deferred

Amendment v1.2, still accurate relative to `BUILD_STATE` completed keys:

| Task | Disposition |
| --- | --- |
| M7-T01 | Optional local embeddings. Not in `completed_tasks`. Router tests still say semantic is unavailable in M2. |
| M7-T04 | Optional adaptive browser. Deferred. |
| M8-T02 | Optional CodeGraph adapter. Deferred. |
| M8-T03 | Optional wiki/document graph. Deferred. Not this `docs/wiki`. |

M7-T02 and M7-T03 are completed tasks and are required only for the product profile, not for generic core (`required_for_core` stays false).

## Post-roadmap work

Commit `d266399` (2026-09-24), message "feat: add governed execution, recovery, sandboxing, and runtime integration", is not a roadmap task id. It landed after PD-T04 closed. The uncommitted diff on top of it touches the runner, controller, plan, policy, state, tools, memory learning, and several eval tests. Themes: revision-scoped runtime keys, goal-driver kill matrix, model launch headroom, `admit_rust_verification`, subprocess allowance ceilings.

Do not mark a new task complete in `BUILD_STATE.json` to describe that diff. Do not treat the diff as merged.

## Fresh verification (2026-09-25)

Command: `./scripts/verify.sh` (fmt check, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`).

- fmt and clippy finished (`Finished dev profile` before the test build). No fmt diff and no clippy error were printed.
- Tests then ran on the **uncommitted** tree.
- `apps/sovereign`: 28 passed.
- `sovereign-context` integration tests: 9 + 12 + 2 + 3 + 18 passed. Crate unit tests: 0.
- `sovereign-controller` library tests: **140 passed, 1 failed**, then the script stopped (`set -eu`).
- Failure: `postgres_broker::tests::broker_pins_upstream_identity_rejects_startup_and_never_replays_after_loss` panicked at `postgres_broker.rs:779` because `TcpStream::connect(("127.0.0.1", broker.port()))` succeeded after the broker should have stopped accepting. `postgres_broker.rs` is in the uncommitted diff. **Uncertain** whether this is a logic bug or a timing flake; this session's full script did not retry it inside `verify.sh`.
- Packages after that library target, including `sovereign-controller` integration tests and `sovereign-eval`, did not run inside `verify.sh`.

Follow-up the same day: `cargo test --workspace --exclude sovereign-controller` passed every target it printed, and `cargo test -p sovereign-controller --tests` (skipping the broker test) passed `t07.rs` 137/137 and then failed `m6_t06_resilience.rs` test `controller_inflight_model_cancellation_interrupts_backend_and_keeps_call_consumed` (`Controller never entered model completion`, `m6_t06_resilience.rs` line 1000). Exit 101. The broker test was not retried. **Uncertain** which uncommitted hunk introduced either failure; they were not bisected against `d266399`.

Ignored real-model tests were not run. Recorded Qwen evidence under `implementation/evidence/` is **Historical** relative to this tree until source hashes are rechecked.

## Stale documents

| Document | Problem |
| --- | --- |
| `output/CODEX_RELEASE_AUDIT_2026-09-13.md` | **Historical.** Describes HEAD `02fecec`, 14/41 core tasks, a stub CLI, and an open M1 gate. Later commits closed M1 through PD-T04 and replaced the CLI. Do not use its percentages. |
| `DEVELOPMENT.md`, `MACHINE.md`, `REQUIREMENTS.md`, `NON_GOALS.md`, `SOURCES.md` | Leading `cat > … <<'EOF'` residue. |
| `BUILD_STATE.json` `completed_milestones` | Stops at M6 while later tasks are completed. `updated_at` is before `d266399`. |
| Architecture name `sovereignd` | The binary is `sovereign`. |
| `output/plan-ir.schema.json` vs `schemas/plan-ir-v1.json` | Validator embeds the `schemas/` file. Byte equality was not checked this session (**Uncertain**). |

## Technical debt an agent will feel

- `crates/sovereign-controller/src/lib.rs` is about 38k lines. Search by symbol. Do not refactor it as a drive-by.
- Fail-closed "unsupported schema" errors are the extension points. There is no TODO list in `src/`.
- Approvals and budgets are JSON in `state_records`, not tables. A new table is a migration and a contract change.
- macOS `sandbox-exec` is the only isolation backend. Other hosts deny.
- The local `.sovereign/state.sqlite3` inspected on 2026-09-25 was migrated to version 7 and empty of runtime rows. It is not a demo database.
- Evidence JSON can go stale after later edits. Closure commits say "close M*-T*"; they are not a continuous hash of today's tree.


## Consumer profile `local_consumer_v1`

Amendment: `output/CONSUMER_UX_AMENDMENT_v1.0.md`. Architecture: [21-consumer-ui-and-service.md](21-consumer-ui-and-service.md). User guide: [docs/user-guide.md](../user-guide.md).

Do not update `BUILD_STATE.json` until a CX task closes with evidence.
