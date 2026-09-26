# Testing and evals

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

## Gate

[scripts/verify.sh](../../scripts/verify.sh) runs, in order, with `set -eu`:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

It does not pass `--ignored`. Real-model tests stay out of this gate.

### Result on 2026-09-25

`./scripts/verify.sh` exited **101** after about 509 seconds. The tree under test included the uncommitted diff.

| Step | Result |
| --- | --- |
| `cargo fmt --check` | Reached the compile step afterward, so fmt did not fail |
| `cargo clippy --workspace --all-targets -- -D warnings` | `Finished dev profile` in 48.83s. No clippy error was printed |
| `cargo test --workspace` | Stopped at the first failing target |

Targets that finished inside that run:

| Target | Result |
| --- | --- |
| `apps/sovereign` unit tests | 28 passed |
| `sovereign-context` lib | 0 tests |
| `context_metrics`, `context_packet`, `external_advisory`, `memory_history`, `routing` | 9, 12, 2, 3, 18 passed |
| `sovereign-controller` lib | 140 passed, **1 failed** |

Failure: `postgres_broker::tests::broker_pins_upstream_identity_rejects_startup_and_never_replays_after_loss` at `crates/sovereign-controller/src/postgres_broker.rs:779`. The test expected the broker port to reject connections after shutdown. `TcpStream::connect` succeeded. That file is in the uncommitted diff. **Uncertain** whether the assertion is a race or a shutdown bug. `verify.sh` did not retry it.

Because the script stops on the first error, controller integration tests and every later crate were not executed by `verify.sh`. A follow-up run covered them. See below.

Ignored real-model and soak tests were not run. JSON under `implementation/evidence/` is **Historical** until its `source_hashes` are compared to this tree.

## What a test is allowed to prove

`DeterministicFakeBackend` proves control-flow, policy, and recovery. It does not prove Qwen, Metal, or the 8 GB resident set. `M1-real-model-qualification.json` is the recorded real-model bundle from 2026-09-20, not a result from this session.

## Ignored or gated tests

| Test | Needs |
| --- | --- |
| `local_model_smoke`, `compiler_real_smoke`, `m1_real_qualification` | `#[ignore]`. GGUF plus `llama-server` via `SOVEREIGN_MODEL_*` |
| One case in `product_delivery` | `#[ignore]`. Exclusive port 8765 |
| Live Postgres cases | `SOVEREIGN_TEST_LIVE_POSTGRES_OID`, otherwise fake sockets |
| Scrapling path in `web_acquire` | `SOVEREIGN_SCRAPLING_PYTHON` or discovery |
| Crash children | Feature `recovery-test-hooks` on the eval dev-dependency |

Chrome is optional. Many browser tests skip or use fakes when the binary is absent. Confirm the test before treating a skip as a pass.

## Eval crate

`crates/sovereign-eval`:

| Module | Role |
| --- | --- |
| `schema.rs` | `EVAL_SCENARIO_SCHEMA_VERSION` = 1, `EVAL_REPORT_SCHEMA_VERSION` = 1, `M1_8GB_PROFILE_ID` = `m1-8gb` |
| `runner.rs` | Offline profile runner used by `sovereign eval` |
| `release.rs` | Release-suite report checks |
| `compat.rs` | Upgrade compatibility suite |
| `local_smoke.rs` | Local smoke helpers |

CLI accepts only `--profile m1-8gb --offline` or `--suite release --profile m1-8gb --offline`.

## Test files

| Path | Proves |
| --- | --- |
| `sovereign-context/tests/context_metrics.rs` | Token and hit-quality accounting |
| `sovereign-context/tests/context_packet.rs` | C0–C3 budgets, section order, repair packets |
| `sovereign-context/tests/external_advisory.rs` | External text stays untrusted |
| `sovereign-context/tests/memory_history.rs` | Memory enters context as evidence only |
| `sovereign-context/tests/routing.rs` | Exact, lexical, structural order; semantic unavailable |
| `sovereign-controller/tests/t07.rs` | Browser, Postgres, recovery, product matrix |
| `sovereign-controller/tests/m6_t06_resilience.rs` | Rollback, cancellation, audit |
| `sovereign-eval/tests/browser_policy.rs` | Ephemeral browser and demand-load |
| `sovereign-eval/tests/compiler_real_smoke.rs` | Ignored real compiler smoke |
| `sovereign-eval/tests/compiler_vertical_slice.rs` | Natural language to plan with a fake model |
| `sovereign-eval/tests/completion_governance.rs` | Model "done" cannot override a failed verify |
| `sovereign-eval/tests/crash_resume.rs` | Kill and resume, including goal-driver cases |
| `sovereign-eval/tests/cross_repo.rs` | Multi-repo contracts |
| `sovereign-eval/tests/eval_corpus.rs` | Deterministic M9 report |
| `sovereign-eval/tests/external_intelligence_policy.rs` | External escalation fail-closed |
| `sovereign-eval/tests/local_model_smoke.rs` | Ignored real load and unload |
| `sovereign-eval/tests/m1_8gb_resource_sim.rs` | Pressure, caps, cooldown |
| `sovereign-eval/tests/m1_real_qualification.rs` | Ignored full M1 qualification |
| `sovereign-eval/tests/m3_scenario_gate.rs` | Multi-module compile scenarios |
| `sovereign-eval/tests/metrics.rs` | Metric aggregators |
| `sovereign-eval/tests/plan_failure.rs` | Replan scopes |
| `sovereign-eval/tests/product_delivery.rs` | Inventory profile; one ignored live case |
| `sovereign-eval/tests/prompt_injection.rs` | Untrusted text cannot escalate |
| `sovereign-eval/tests/release_suite.rs` | Soak report shape |
| `sovereign-eval/tests/repair_loop.rs` | Fail, defer, targeted repair |
| `sovereign-eval/tests/security_resilience.rs` | Audit chain and sandbox denial |
| `sovereign-eval/tests/upgrade_compat.rs` | DB, plan, and artifact upgrades |
| `sovereign-eval/tests/vertical_slice.rs` | Compile, edit, verify with a fake model |
| `sovereign-eval/tests/web_acquire.rs` | Offline deny and optional Scrapling |
| `sovereign-evidence/tests/compression.rs` | Log compression budgets |
| `sovereign-memory/tests/learning.rs` | Episodes only from controller proof |
| `sovereign-memory/tests/lifecycle.rs` | Isolation and lifecycle |
| `sovereign-memory/tests/projection.rs` | FTS outbox crash repair |
| `sovereign-memory/tests/retrieval.rs` | Filters and synopses |
| `sovereign-model/tests/backend.rs` | Fake and local HTTP contract |
| `sovereign-model/tests/external_intelligence.rs` | Optional external model client |
| `sovereign-plan/tests/compiler_m3.rs` | Multi-module compiler |
| `sovereign-plan/tests/depth.rs` | Depth classifier |
| `sovereign-plan/tests/minimal_compiler.rs` | Minimal compiler |
| `sovereign-plan/tests/validator.rs` | Plan IR validation |
| `sovereign-policy/tests/autonomy.rs` | Budgets |
| `sovereign-policy/tests/browser.rs` | Seatbelt browser policy |
| `sovereign-policy/tests/external_intelligence.rs` | External payload policy |
| `sovereign-policy/tests/kernel.rs` | Capabilities, commands, subprocess caps |
| `sovereign-policy/tests/resources.rs` | M1 profile and admission |
| `sovereign-policy/tests/secret.rs` | Secret broker |
| `sovereign-policy/tests/security.rs` | Injection and path policy |
| `sovereign-repo/tests/baseline.rs` | Snapshots and protected changes |
| `sovereign-repo/tests/exact_retrieval.rs` | Stale hash refresh |
| `sovereign-repo/tests/lexical.rs` | FTS index |
| `sovereign-repo/tests/structural.rs` | tree-sitter graph |
| `sovereign-repo/tests/worktree.rs` | Worktree leases |
| `sovereign-state/tests/audit_budget_recovery.rs` | Audit and budget durability |
| `sovereign-state/tests/process_kill.rs` | WAL survives process death |
| `sovereign-state/tests/security_kernel.rs` | Epochs and action rows |
| `sovereign-tools/tests/browser.rs` | CDP adapter |
| `sovereign-tools/tests/runner.rs` | Runner, isolation, subprocess allowance |
| `sovereign-types/tests/interface_contracts.rs` | Frozen interface manifest |

## Fixtures

| Path | Use |
| --- | --- |
| `crates/sovereign-eval/tests/fixtures/scenario1/` | Settings-form edit scenario and policy JSON |
| `crates/sovereign-eval/tests/fixtures/product_inventory/` | Inventory app, `server.py`, `test_inventory.py`, `RUNBOOK.md` |
| `crates/sovereign-eval/fixtures/m9/policy.json` | M9 policy |
| `crates/sovereign-plan/tests/fixtures/valid_trivial_plan.json` | Validator fixture |

Evidence files in `implementation/evidence/` are closure records (`task`, `status`, `head`, `source_hashes` on later tasks). They are not fixtures the test runner loads automatically.

## Consumer UI and live service

- `scripts/verify-ui.sh`: gen:api freshness, typecheck, ESLint, Vitest+axe, production build, 250 KiB gzip JS budget, and a `/v2` route scan.
- `apps/sovereign/tests/control_api_contract.rs` now spawns the real `sovereign serve` binary on `127.0.0.1:0` and validates live `/v2` bodies against `schemas/control-api-v2.json`, including unauthorized 401 and CSRF 403.
- `execution.rs` `http_goal_pause_restart_and_runlock_do_not_replay_unknown` covers CX-T10 HTTP submit, fixture compile, pause, actor restart, empty unknown actions, and RunLock contention.
- `scripts/e2e.sh` builds `sovereign-e2e-server --features e2e-fixtures` and runs Playwright + axe against installed Chrome. Not part of `verify.sh`.
- CX-T25 real-model HTTP acceptance is `#[ignore]` in `crates/sovereign-eval/tests/consumer_acceptance.rs`. CX-T26 screenshots are a manual capture under `implementation/evidence/CX-T26/` and must not be fabricated.

## Follow-up suite

After `verify.sh` stopped, this session ran `cargo test --workspace --exclude sovereign-controller`, then `cargo test -p sovereign-controller --tests` while skipping `broker_pins_upstream_identity_rejects_startup_and_never_replays_after_loss`. Exit **101** after about 913 seconds, on the uncommitted tree.

- Every non-controller target in that run printed `test result: ok`.
- `crates/sovereign-controller/tests/t07.rs`: 137 passed, 1 filtered (the broker test skipped on purpose).
- `crates/sovereign-controller/tests/m6_t06_resilience.rs`: 3 passed, 1 failed. `controller_inflight_model_cancellation_interrupts_backend_and_keeps_call_consumed` panicked at line 1000 with `Controller never entered model completion`, and the parent thread panicked at line 1031 because the cancellation thread panicked.

The broker shutdown assertion was not retried. Both failures are on the dirty tree. Neither was bisected against commit `d266399`. **Uncertain** which hunk introduced them.

## Baseline fixes on 2026-09-25 (later the same day)

Two failures from the gate run were fixed on the working tree and re-run once each, successfully:

- `broker_pins_upstream_identity_rejects_startup_and_never_replays_after_loss` now asserts `ControllerPostgresBroker::accept_loop_stopped` after the accept thread drops its listener. It no longer calls `TcpStream::connect` on a reusable ephemeral port.
- `controller_inflight_model_cancellation_interrupts_backend_and_keeps_call_consumed` waits 15 seconds for model `complete` to start, covering checkpoint and Seatbelt work before the provider call. The fixture already installs a green pressure probe.

`cargo clippy -p sovereign -p sovereign-controller --all-targets -- -D warnings` passed after those edits.

A later full `./scripts/verify.sh` on the same day (about 1006 s) passed fmt, clippy, both previously failing tests, and every crate through `sovereign-tools` unit tests. It then failed `crates/sovereign-tools/tests/browser.rs` test `real_chrome_contains_page_js_writes_and_worker_network_before_execution` (`safe HEAD subresource was not allowed`). That case talks to live Chrome and is unrelated to CX-T01/CX-T02. Re-run it in isolation before treating it as a product regression.

## CI and Linux baseline (2026-09-26)

`.github/workflows/ci.yml` runs `verify.sh` and `e2e.sh` on macOS arm64, fmt, clippy, and the UI gate on Linux, checks that the committed `ui-dist/` matches a fresh build, and prints `scripts/evidence-freshness.py`.

Clippy now passes on Linux: macOS-only paths gate their lints on `target_os` instead of leaving unused imports.

On Linux, `cargo test --workspace --no-fail-fast` has 26 failures that need macOS or network: `sandbox-exec` (eval corpus, release suite, cross-repo gates, runner D4 and browser cases, `offline_eval_cli`), DNS and IDNA resolution (policy network tests, `web_acquire`), Python/Scrapling, and one Postgres broker socket case. The same 26 fail before and after the 2026-09-26 changes. Treat a new Linux failure outside that set as a regression.

`scripts/evidence-freshness.py` re-hashes every `source_hashes` entry under `implementation/evidence/`. `--strict` exits 1 on stale or missing evidence.
