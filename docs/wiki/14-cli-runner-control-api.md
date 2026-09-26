# CLI, runner, and control API

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

The binary is `sovereign` (`apps/sovereign`, version `0.1.0` from the workspace). It is a client of the Controller. It is not a second state machine.

## State path

Default: `.sovereign/state.sqlite3`, relative to the process working directory for commands other than `run`. Override: `SOVEREIGN_STATE_DB`. `run` resolves the git root first and keeps state relative to that root unless the environment variable is set.

Exit code 2 is the rendered `ErrorCode::InvalidState` path. Success prints the command's text and returns 0.

## Commands

Parsed in `apps/sovereign/src/main.rs`. `run` is dispatched before the state database is opened, because the runner owns locking and composition.

| Command | Effect |
| --- | --- |
| `--version`, `-V` | Prints `sovereign 0.1.0` |
| `help` | Usage text |
| `doctor` | Opens a read model and prints whether execution is paused |
| `goal <text>` | `submit_goal`. Queues only. Does not compile or execute |
| `status` | Pretty-printed read model |
| `evidence` | Evidence section of the read model |
| `eval` | Only `--profile m1-8gb --offline`, or `--suite release --profile m1-8gb --offline` |
| `pause [reason]` | Controller pause |
| `resume` | Controller resume |
| `approvals` | Lists approval requests |
| `approval <id> <approve\|deny> <principal>` | Records a decision |
| `serve [--execute] [--require-token|--no-require-token] [addr]` | Loopback UI and API. Default `127.0.0.1:7777`. `/v1` POSTs require the session token unless `--no-require-token` |
| `run` | Production driver loop. See below |
| `cancel <goal_id> [principal]` | Controller-owned goal cancellation |
| `project add\|list\|use` | Register a git root |
| `service install\|uninstall\|status` | LaunchAgent |
| `app` | Open the local UI |

`eval` profile or suite drift is rejected. The release suite flag shape is checked without implying that every invocation reruns the soak. Read the eval crate before assuming what `eval` executed.

## `run`

`runner::run_command`:

1. Find the git root.
2. `RunLock::acquire` on the state path.
3. Open `ProjectRegistry` for `repo.local` plus optional `SOVEREIGN_PROJECT_CONFIG`.
4. `Controller::reopen_local`.
5. Loop `advance_with_overrides` at most `MAX_ADVANCES` (64) times.

Each advance may probe with empty resources, compile with `LocalOpenAiBackend` and `PlanValidator`, or execute with `MacSandboxExecBackend`, pinned `/usr/bin/python3`, optional cargo and node, and optional Chrome. Execution isolation sets `network_offline` unless a browser or other grant applies. Constants: `MAX_ADDITIONAL_REPOSITORIES` = 8, `MAX_SOURCE_CANDIDATES` = 16, `MAX_SOURCE_CANDIDATE_BYTES` = 16 KiB, `MAX_SOURCE_CANDIDATE_TOTAL_BYTES` = 48 KiB, `COMPILER_VERSION` = `sovereign-local-v1`.

Model launch uses context 8192 and reserve 1536. See [12-model-and-resources.md](12-model-and-resources.md).

## Run lock

`RunLock` creates `.<dbname>.sovereign-run.lock` beside the state file, mode `0600`, and takes a kernel `try_lock`. The file holds no PID and no status. It remains after release. The lock is the kernel lock on the open file descriptor.

Rejected: symlink or hardlink state paths, unsafe sidecars, two live owners of the same canonical database. Different database file names do not contend. This is not recovery and not a leader election protocol. See [07-recovery-and-crash.md](07-recovery-and-crash.md).

## Control API

`apps/sovereign/src/control_api/`. Authentication is loopback binding plus Host and Origin checks, a session cookie, and CSRF on `/v2` POSTs. Do not add a token by binding a non-loopback socket.

| Method | Path |
| --- | --- |
| GET | `/` and `/dashboard` (SPA) |
| GET | `/v1/status` |
| POST | `/v1/goals` body `{goal}` |
| POST | `/v1/control/pause` body `{reason?}` |
| POST | `/v1/control/resume` |
| POST | `/v1/approvals/respond` body `{request_id, decision, principal}` |
| GET | `/v2/session`, `/v2/overview`, `/v2/doctor`, `/v2/projects`, `/v2/goals`, `/v2/events`, `/v2/events/stream`, `/v2/recovery`, `/v2/settings` |
| POST | `/v2/settings` body `{approval_principal?, chrome_path?, node_path?, execute_on_start?}` — AppData only, not Controller state |
| GET | `/v2/artifacts/{digest}`, `/v2/tasks/{key}/diff`, `/v2/approvals/{id}` |

Limits: headers 16 KiB, body 64 KiB. A route that writes SQLite directly is rejected by tests (`rejected_raw_state_route_cannot_mutate_authoritative_journal`). The read model is `LocalControl` / `LOCAL_CONTROL_READ_MODEL_SCHEMA_VERSION` = 1 in `local_control.rs`. Restart reconstructs it from Controller state.

## Tests in the binary

`apps/sovereign` unit tests cover lock contention, goal queueing, pause and resume, dashboard routes, and a two-repository `run --once` path. They are part of `cargo test --workspace`.
