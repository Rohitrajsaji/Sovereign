# Browser and PostgreSQL

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

Browser automation is optional for generic core and required for the `local_full_stack_v1` product profile (`M7-T03`, promoted by amendment v1.2). Adaptive browser-use (`M7-T04`) is deferred. See [18-status-blockers-debt.md](18-status-blockers-debt.md).

## CDP lease

`crates/sovereign-tools/src/browser.rs` launches headless Chrome with `--remote-debugging-pipe`. Debugging is not exposed as a TCP port. The profile is ephemeral unless a persistent profile grant exists (`controller.browser_profile_grant`).

Default binary in the runner: `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, overridable with `SOVEREIGN_CHROME_EXECUTABLE`. The Controller wraps the process in Seatbelt through `MacSandboxExecBackend`. The shell used to set up the pipe is `/bin/sh`.

Hard ceilings:

| Constant | Value |
| --- | --- |
| `MAX_CDP_FRAME_BYTES_HARD` | 4 MiB |
| `MAX_SYNOPSIS_BYTES_HARD` | 256 KiB |
| `MAX_DOM_BYTES_HARD` | 512 KiB |
| `MAX_DOWNLOAD_BYTES_HARD` | 128 MiB |
| `MAX_REQUEST_TIMEOUT_MS` | 60_000 |
| `CDP_INITIALIZATION_TIMEOUT_MS` | 15_000 |
| `MAX_TRACKED_DOWNLOADS` | 128 |
| `MAX_CALLER_CHROME_ARGS` | 128 |
| `PROCESS_BROWSER_CLOSE_GRACE` | 1 second |

Proxy auth constants: realm `sovereign-browser-gateway-v1`, username `sovereign-browser`. Downloads are recorded in `controller.browser_download_record`. `SOVEREIGN_TEST_BROWSER_COMMAND_LOG` is a test hook, not a product log.

Chrome is reaped as a process group (TERM, then KILL), same discipline as other managed processes.

## Controller browser authority

`crates/sovereign-controller/src/browser.rs` owns `ControllerBrowserSession` and `BrowserReadyLeaseV1`. The gateway binds loopback only (`GATEWAY_IO_TIMEOUT` = 30 seconds). Unknown browser admission is `BROWSER_UNKNOWN_ADMISSION_MIB` = 1536.

Managed loopback apps (`controller.managed_loopback_app`):

| Constant | Value |
| --- | --- |
| `MANAGED_LOOPBACK_MAX_LIFETIME_MS` | 30_000 |
| `MANAGED_LOOPBACK_START_OUTPUT_BYTES` | 64 KiB |
| `MANAGED_LOOPBACK_START_DISK_BYTES` | 1 MiB |
| `MANAGED_LOOPBACK_SUBPROCESS_LIMIT` | 0 |
| `MANAGED_LOOPBACK_READY_TIMEOUT` | 5 seconds |

Semantic acceptance contracts and proofs use `controller.browser_semantic_contract` and `controller.browser_semantic_proof`. Plan-side types are `BrowserAcceptanceContractV1` in `sovereign-plan`. A missing browser grant is valid only when the plan has no browser binding. An inconsistent grant fails closed (`durable_browser_grant_for_plan`).

Network for the browser is a reservation (`controller.browser_network_reservation`), not a widening of `NetworkPolicy` to all loopback.

Residency key: `cdp_browser` in `controller.resource_residency`. Pair rules with the model and with heavy builds are in `HardwareProfileV1`. See [12-model-and-resources.md](12-model-and-resources.md).

## PostgreSQL boundary

`postgres_broker.rs` (Unix only) does not start PostgreSQL, install it, or choose a data directory.

What it does:

1. The operator, or a test, already has a Unix socket and a database OID.
2. `Controller::configure_managed_postgres_backend(socket, oid)` pins that socket's device, inode, and owner.
3. The broker listens on loopback TCP. The sandboxed app may talk only to that port.
4. The Controller opens a fresh `UnixStream` as role `sovereign_app_runtime` on database `sovereign_app`.
5. `VERIFY_QUERY` checks the current user, database name, OID, and that the role is not superuser, cannot create databases, roles, or replication, cannot bypass RLS, can log in, has no role memberships, has `CONNECT` without `CREATE` or `TEMP`, and has `USAGE` but not `CREATE` on schema `app`.
6. Bytes are forwarded. They are not replayed. `MAX_CLIENTS` = 8. `MAX_STREAM_BYTES` = 16 MiB. Startup is capped at 4096 bytes.

Live tests look for Homebrew `postgresql@16` and `SOVEREIGN_TEST_LIVE_POSTGRES_OID`. Without that variable they use fake sockets. Do not point the broker at an administrative database to make the inventory app easier.

## Tests

`crates/sovereign-tools/tests/browser.rs`, `crates/sovereign-policy/tests/browser.rs`, `crates/sovereign-eval/tests/browser_policy.rs`, `crates/sovereign-controller/tests/t07.rs`, and the browser portions of `product_delivery.rs`. One product-delivery case is `#[ignore]` because it needs exclusive port 8765.
