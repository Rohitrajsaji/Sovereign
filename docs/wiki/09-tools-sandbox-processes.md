# Tools, sandbox, and processes

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Tool execution lives in `crates/sovereign-tools`. Policy decides whether an action may exist. The runner executes only an already authorized action.

## Catalog

Frozen tool identities in `src/catalog.rs`:

| Constant | Id | Version |
| --- | --- | --- |
| `CANONICAL_PATCH_TOOL_ID` | `tool.patch` | `1.0.0` |
| `CANONICAL_READ_TOOL_ID` | `tool.read` | `1.0.0` |
| `CANONICAL_BROWSER_TOOL_ID` | `tool.browser` | `1.0.0` |
| `CANONICAL_PROCESS_TOOL_ID` | `tool.process` | `1.0.0` |

`CANONICAL_TOOL_VERSION` is `1.0.0`. Capability floors are declared next to the schemas. A model-proposed tool name that is not in this catalog does not run.

## Runner

`ProcessRunner<I: ExecutionIsolationBackend>` journaled path:

1. Controller authorizes an `AuthorizedAction` bound to payload, tool identity, root, epoch, and policy digest.
2. The runner writes the pre-dispatch record. If that write fails, it does not spawn.
3. Spawn uses `env_clear()` plus the allowlisted environment, and `process_group(0)`.
4. Output readers are bounded. Overflow is `ResourceLimitKind`. A drain timeout becomes recovery-blocked, not a silent truncate-and-succeed.
5. The receipt is `ActionReceipt` (`ACTION_RECEIPT_SCHEMA` = `sovereign-action-receipt-v1`, schema version 1). A committed action requires a result digest in the artifact store.

`ManagedProcess` tracks the process-group leader. `reap_owned_process_group` sends TERM, then KILL, to the group. `Drop` reaps. `descendant_count` is compared with `command.subprocess_limit`. Excess descendants are terminated. If any may have escaped the group, the outcome is recovery-blocked.

Uncommitted policy work: `admit_rust_verification` on `M6ResourceGovernor` admits an uncalibrated `BUILD_HEAVY` lease with parallel jobs capped at 1 and subprocesses at `min(task budget, 3)`, because one Cargo job needs rustc, clang, and ld. The test `subprocess_allowance_cannot_be_widened_after_journal_authorization` is the invariant: the allowance cannot grow after the journal row exists. `pinned_rust_verification_caps_are_specific_bounded_and_budget_limited` pins the same ceiling.

## Sandbox

`MacSandboxExecBackend` shells out to `/usr/bin/sandbox-exec` with a Seatbelt profile and runs a self-test. `IsolationRequest` in the production runner includes `HOME`, the repository, state and CAS roots, and `network_offline` unless a narrower grant exists.

If `sandbox-exec` is missing, isolation denies. There is no non-macOS sandbox backend in this tree. **Verified:** non-macOS paths fail closed rather than executing unsandboxed. Do not add an allow fallback for Linux CI without a real backend and tests.

Filesystem writes use `AtomicCreate`, `AtomicUpdate`, and `AtomicReplaceGuard`: temp file, then replace, with parent identity rechecked. A symlink swap between planning and commit invalidates the authorization. Controller state and CAS are not general model-write roots.

## Web acquisition

`WEB_ACQUIRE_SCHEMA_VERSION` = 1. Caps: `WEB_ACQUIRE_MAX_RESPONSE_BYTES` = 8 MiB, `WEB_ACQUIRE_MAX_REDIRECTS` = 8, `WEB_ACQUIRE_MAX_TIMEOUT_MS` = 60_000. The HTTP client is Sovereign's. `adapters/scrapling/parser_worker.py` is an optional parser, selected with `SOVEREIGN_SCRAPLING_PYTHON` or discovery. Tests: `crates/sovereign-eval/tests/web_acquire.rs`. Offline deny is the default.

## What the production runner pins

`apps/sovereign/src/runner.rs` resolves `/usr/bin/python3` and optional `cargo` and `node` (`SOVEREIGN_NODE_EXECUTABLE`). Chrome is optional (`SOVEREIGN_CHROME_EXECUTABLE`, default `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`). `MacSandboxExecBackend::detect()` is required before execution resources are built. See [14-cli-runner-control-api.md](14-cli-runner-control-api.md).

## Tests

`crates/sovereign-tools/tests/runner.rs` (including the uncommitted subprocess-allowance cases), `crates/sovereign-policy/tests/kernel.rs`, `crates/sovereign-eval/tests/security_resilience.rs`.
