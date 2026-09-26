# Recovery and crash semantics

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Recovery prefers authoritative SQLite state over resuming from an old checkpoint and trying again. Architecture section 23 is the contract. `RecoveryManager` in `crates/sovereign-controller/src/lib.rs` is the implementation (`recover`, `recover_with_permission_context`).

## What a restart does

1. Validate the latest checkpoint chain and compare plan and task digests with SQLite.
2. Mark orphaned running attempts and processes interrupted.
3. Reap owned children where the process group identity can still be proven.
4. Reconcile every action after the checkpoint's recorded action-journal sequence.
5. Refresh repository baselines and dependency or evidence fingerprints before a task returns to ready.
6. Run `reconcile_queued_goal_lifecycle` before `advance_production_goal` continues a queued goal.

If the newest checkpoint is corrupt, the controller may anchor at generation N−1 with `append_recovery_checkpoint_integrity` and then replay the journal after that point. If replay cannot prove the current diff, action outcomes, plan and task digests, and evidence satisfactions, mutation stays blocked. Corrupt authority blocks mutation (architecture section 24.0 item 10).

## Unknown is not failure

Once a side-effectful action may have crossed the dispatch boundary, a crash or missing receipt yields `unknown`, not `failed`. Automatic replay waits for reconciliation (`reconcile_historical_unknown_action`, namespace `controller.action_reconciliation`). Safe local actions may be re-observed under policy. Dispatched external effects may not.

`TaskState::ReconcilingUnknown` is the task-level form of this wait. `AttemptState::Interrupted` is the attempt-level form after an orphaned run.

Absence of an `ActionReceipt` does not mean the effect did not happen.

## Epoch fencing

`controller_runtime.execution_epoch` starts at 0 and advances through `advance_execution_epoch`. Authorization binds the epoch. A lease or approval from an older epoch is not valid after the epoch moves. Recovery that cannot prove the epoch must fail closed rather than reuse the old claim.

## Checkpoints are mandatory around mutation

The plan's checkpoint policy may add checkpoints. It cannot remove the controller floor: before and after mutation, at attempt end, and at verification, plus a monotonic generation and a hash chain. Other triggers in the architecture: plan activation, attempt start, resource-heavy handoff, a bounded periodic interval, and graceful shutdown.

Manifest schema version currently written is `CHECKPOINT_MANIFEST_SCHEMA_VERSION` = 3. Older manifests remain readable.

## Rollback

Rollback is itself an authorized, budgeted, journaled, verified action (`RollbackRecordV1`, `RollbackExecutor`, namespace `controller.rollback`). A failed or unknown rollback is not success and is not silently retried.

## Crash-test hooks

These environment variables exist so tests can kill a child at a boundary. They are not production configuration.

| Variable prefix | Where |
| --- | --- |
| `SOVEREIGN_RECOVERY_TEST_PAUSE_AT`, `SOVEREIGN_RECOVERY_TEST_PAUSE_MARKER` | `recovery_test_hook`, feature `recovery-test-hooks` on `sovereign-tools` and `sovereign-controller` |
| `SOVEREIGN_GOAL_CRASH_*` | In-crate goal completion and finalization kill worker |
| `SOVEREIGN_PD_T05_V4_CRASH_*` | `crates/sovereign-controller/tests/t07.rs` |
| `SOVEREIGN_M6_T06_ROLLBACK_*` | `tests/m6_t06_resilience.rs` |
| `SOVEREIGN_CRASH_CHILD_*` | `crates/sovereign-eval/tests/crash_resume.rs` |
| `SOVEREIGN_PROJECTION_CRASH_CHILD_DB` | `crates/sovereign-memory/tests/projection.rs` |
| `SOVEREIGN_OFFLINE_DEPENDENCY_CRASH_*` | `tests/t07.rs` |

The feature is not in the default feature set. Eval tests enable it with `sovereign-controller` feature `recovery-test-hooks`. Do not enable it in a release binary to make crashes easier to debug.

Uncommitted tests extend this matrix: `production_goal_driver_completion_record_before_lifecycle_kill_reconciles_once`, `production_goal_driver_completion_and_finalization_forced_kill`, `production_goal_driver_compile_claim_activation_kill_matrix`, `production_goal_driver_task_boundary_kill_is_stable`, and `production_goal_driver_first_repository_dispatch_kill_never_replays_effect`. The last one is the property to preserve: a kill during first repository dispatch must not replay the effect.

`apps/sovereign/src/run_lock.rs` is a separate mechanism. It stops two `sovereign run` processes from sharing one state file. It is not crash recovery and it stores no owner identity in the lock file. See [14-cli-runner-control-api.md](14-cli-runner-control-api.md).

## Process death versus state death

`crates/sovereign-state/src/bin/state-fixture-writer.rs` writes one journal event and sleeps so a test can kill the process and observe WAL durability. `crates/sovereign-state/tests/process_kill.rs` covers that. Killing the process must not delete `action_records` or `event_journal` rows. Triggers forbid those deletes.

## Tests to read before changing recovery

- `crates/sovereign-eval/tests/crash_resume.rs`
- `crates/sovereign-eval/tests/upgrade_compat.rs`
- `crates/sovereign-state/tests/security_kernel.rs`
- `crates/sovereign-state/tests/audit_budget_recovery.rs`
- `crates/sovereign-controller/tests/m6_t06_resilience.rs`
- the kill-matrix sections of `crates/sovereign-controller/tests/t07.rs`

Scenario 4 in [output/PLAN_IR_SCENARIOS.md](../../output/PLAN_IR_SCENARIOS.md) is the narrative form of the restart decision table.
