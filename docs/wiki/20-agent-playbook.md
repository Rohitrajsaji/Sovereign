# Agent playbook

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Read [README.md](README.md) first, then the topic page for the area you will touch. This page is how to change the tree without breaking its invariants.

## Before editing

1. `git status` and `git diff --stat`. 34 files were already dirty on 2026-09-25. Do not revert them to get a clean tree. Do not commit them unless the user asks.
2. Identify the owning crate using [03-code-map.md](03-code-map.md). Stay inside that boundary. `sovereign-state` must not depend on the controller. The controller must not grow a second plan compiler.
3. Search the symbol you will change. `lib.rs` in the controller is too large to read end to end.
4. Read the test named after the behavior. Crash behavior is specified by `crash_resume.rs`, `t07.rs`, and `m6_t06_resilience.rs`, not by a comment.
5. If the change touches a frozen contract (`output/`, `schemas/plan-ir-v1.json`, `schemas/interface-contracts/v1.json`), stop and ask. Those files are the authority. Code follows them.

## While editing

- A model string, skill, web page, or repository file cannot grant a capability, mark a task complete, or widen a subprocess allowance after the journal row exists.
- New durable JSON needs a schema version constant and a fail-closed reader for older versions. Bump `CURRENT_SCHEMA_VERSION` only with a migration in `crates/sovereign-state/migrations/` and `manifest.json`.
- New `state_records` keys for plan-scoped facts use `revision_scoped_key`. Bare keys are a revision-1 legacy read path.
- Side effects go through `AuthorizedAction` and `ProcessRunner`. Pre-dispatch audit failure denies the spawn.
- After a possible dispatch, missing receipts become `unknown`. Do not retry.
- Do not `reset --hard`, `clean`, or force-push a user repository to make a task recoverable.
- Do not label a cleared environment or a timeout as a sandbox. Isolation is `MacSandboxExecBackend` or a denial.
- Keep `unsafe_code` forbidden. Do not add `unwrap` or `expect`. Clippy pedantic is denied.
- One local model. Do not start a second llama-server to speed tests.
- Postgres broker pins an existing socket. It does not `initdb`.
- Limits in [17-constants-and-limits.md](17-constants-and-limits.md) are frozen behavior. Raising one is a product change.

## Verify

Default gate:

```sh
./scripts/verify.sh
```

On 2026-09-25 that command failed in `broker_pins_upstream_identity_rejects_startup_and_never_replays_after_loss` after fmt and clippy passed. A follow-up of the remaining crates then failed `controller_inflight_model_cancellation_interrupts_backend_and_keeps_call_consumed`. See [15-testing-and-evals.md](15-testing-and-evals.md). If you did not touch those tests, say whether the failures reproduced. Do not ignore them.

Narrower loops while iterating:

```sh
cargo fmt --check
cargo clippy -p sovereign-controller --all-targets -- -D warnings
cargo test -p sovereign-plan --test validator
cargo test -p sovereign-state --lib
```

Real Qwen tests are `#[ignore]`. Do not claim qualification from `DeterministicFakeBackend`.

The app has no browser UI to click except the loopback dashboard. If you change `control_api.rs` or the dashboard HTML, hit `127.0.0.1:7777` with the routes in [14-cli-runner-control-api.md](14-cli-runner-control-api.md). Binding a non-loopback address is a defect.

## Evidence and git

- Do not update `BUILD_STATE.json` or `implementation/evidence/` unless the user asked to close a task and the tests actually passed on this tree.
- Do not commit `.sovereign/`, `.models/`, `.tools/`, `research/`, or `target/`.
- Commit only when asked. Hooks are not optional. No `--no-verify`.
- The detached worktree `.kilo/worktrees/sideways-conifer` is not your working copy.

## Patterns that look helpful and are not

| Tempting change | Why it is wrong |
| --- | --- |
| Treat model "done" as task success | Completion is evidence plus verifier |
| Replay an action because the receipt is missing | That is the unknown-outcome bug |
| Store approvals in a new SQLite table beside `state_records` | Splits authority |
| Read revision N+1 state with a bare key | Legacy exception is revision 1 only |
| Fall back to unsandboxed exec when `sandbox-exec` is missing | Must deny |
| Copy a component out of `research/core/openhuman` or OpenViking Python | License and architecture |
| Start Postgres from the broker so the app works | Breaks the pin and privilege check |
| Load embeddings by default on 8 GB | M7-T01 is deferred; pressure policy forbids casual co-residency |
| Edit `output/SOVEREIGN_ARCHITECTURE.md` to match a shortcut | The shortcut is the defect |
| Use chat history as the plan | State is in SQLite |

## First files for common jobs

| Job | Open |
| --- | --- |
| Goal does not run | `goal_runner.rs`, `production_driver.rs`, `runner.rs` |
| Plan rejected | `PlanValidator`, diagnostic code, `schemas/plan-ir-v1.json` |
| Crash resume wrong | `RecoveryManager`, `crash_resume.rs` |
| Permission bug | `Capability`, `ApprovalClaim`, `kernel` tests |
| Sandbox bug | `MacSandboxExecBackend`, `ProcessRunner` |
| Worktree or index | `worktree.rs`, `lexical.rs`, `structural.rs` |
| Browser or Postgres | `browser.rs`, `postgres_broker.rs` |
| OOM or model will not load | `HardwareProfileV1::m1_8gb`, residency coordinator |
| CLI or dashboard | `main.rs`, `control_api.rs`, `local_control.rs` |
