# Consumer UI and local service

> Snapshot: uncommitted consumer profile `local_consumer_v1` on 2026-09-25.

The UI and HTTP API are clients. They never write SQLite. Mutations go through `LocalControl` or `Controller` methods on the single-writer actor.

## Topology

`sovereign serve [--execute] [--require-token|--no-require-token] [127.0.0.1:port]` binds loopback only. The HTTP stack lives in `apps/sovereign/src/control_api/` (`parse`, `server`, `routes`, `static_assets`, `sse`). Four workers handle requests. `/v1` POSTs require the session token by default; `--no-require-token` keeps CLI-era tests. Static files come from `build.rs` embedding `ui-dist/` with SHA-256 ETags. `/dashboard` serves the SPA. `GET /v2/events/stream` tails the journal (max 4 clients, 15 s heartbeats). If `ui-dist/` is missing, the binary embeds a one-page fallback.

`serve --execute` runs `ExecutionService::step` inside the actor between commands. Backoff is 1 s, 2 s, cap 10 s while idle, paused, blocked, or deferred. Progress outcomes reset backoff to 0. Unknown outcomes are never retried.

## Token and CSP

At serve start a 32-byte token is written to `~/Library/Application Support/Sovereign/service-token` (mode 0600). `sovereign app` writes a single-use launch code (`launch-code`, mode 0600, 60 s TTL, `apps/sovereign/src/launch_code.rs`) and opens `/?c=<code>`. The service redeems it once and sets `sovereign_session` (`HttpOnly`, `SameSite=Strict`), so the long-lived token never appears in a URL. `GET /?t=<token>` still sets the cookie for the e2e harness. Every `/v2/*` request needs the cookie or a bearer token; a `?t=` query no longer authenticates `/v2`. POSTs also need `X-Sovereign-CSRF` equal to the session token from `GET /v2/session`.

Every response includes:

- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` on API responses

Host and Origin must be loopback. `/v1/*` stays for CLI-era tests. Token is required on `/v1` POSTs unless `--no-require-token` is set.

## App data

`~/Library/Application Support/Sovereign/`:

- `settings-v1.json`
- `projects-v1.json`
- `service-token`
- `projects/<id>/state.sqlite3` and `cas/`
- `logs/`

New project state lives outside the git root. Environment variables still override settings.

## LaunchAgent

`sovereign service install` writes `~/Library/LaunchAgents/dev.sovereign.agent.plist` with `serve --execute 127.0.0.1:7777` and `ThrottleInterval` 30. `sovereign app` installs if needed, issues a launch code, and opens `http://127.0.0.1:7777/?c=<code>` with `/usr/bin/open`.

`logs/stdout.log` and `logs/stderr.log` are capped at 10 MiB (`service_logs.rs`). The newest 2 MiB go to `<name>.1` and the live file is truncated in place so launchd's append handle stays valid. Rotation runs at serve start and every ten minutes. A busy port produces a message naming the address and the next step.

## UI

`apps/sovereign/ui/` is React 19 + TypeScript (strict, `noUncheckedIndexedAccess`), Vite, Tailwind v4, Radix Dialog/Tabs/Tooltip, TanStack Query, React Router hash routes, `@xyflow/react` for the plan DAG, and lucide icons. Hash routes cover welcome, home, projects, goals, approvals, recovery, settings, and diagnostics. Untrusted text is rendered as text nodes. `dangerouslySetInnerHTML` is banned by ESLint. `src/api/generated.ts` is generated from `schemas/control-api-v2.json`.

`scripts/verify-ui.sh` runs `npm ci` when needed, `gen:api` with a freshness check, typecheck, ESLint, Vitest+axe, build, the 250 KiB gzip budget, and a `/v2` route scan when `node` exists. `scripts/verify.sh` calls it, or prints a skip. `scripts/e2e.sh` builds `sovereign-e2e-server` and runs Playwright against installed Chrome. It is not part of `verify.sh`.

`sovereign-e2e-server` (feature `e2e-fixtures`) injects `DeterministicFakeBackend` through `advance_production_step`. Unit tests opt in with a `USE_FIXTURE_BACKEND` marker next to the state file. The production `sovereign` binary must not contain e2e-server strings.

## Tests

- Actor lifecycle and run-lock release: `actor.rs`
- Token, CSRF, concurrency, 413, slow-client isolation, ETag, traversal: `control_api/`
- Live `/v2` schema plus CSRF 403: `apps/sovereign/tests/control_api_contract.rs`
- HTTP submit, pause, restart, RunLock, no unknown replay: `execution.rs` (`http_goal_pause_restart_and_runlock_do_not_replay_unknown`)
- Projects, doctor, model verify, launchd plist: module tests
- Playwright plus axe: `apps/sovereign/ui/e2e/consumer.spec.ts` via `scripts/e2e.sh`
- Real-model consumer acceptance: `crates/sovereign-eval/tests/consumer_acceptance.rs` (`#[ignore]`). Evidence is written to `implementation/evidence/CX-T25.json` only when that test is run on the M1.
- CX-T26 screenshots live in `implementation/evidence/CX-T26/` after a manual first-run. They are not fabricated.
