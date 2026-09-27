# Consumer UI and local service

> Snapshot: consumer profile `local_consumer_v2` (`output/CONSUMER_UX_AMENDMENT_v2.0.md`) on 2026-09-26.

The UI and HTTP API are clients. They never write SQLite. Mutations go through `LocalControl` or `Controller` methods on the single-writer actor. Landing results in a project folder is a repository operation done by the service after the Controller records a goal complete; it is not execution state.

## Topology

`sovereign serve [--execute] [--require-token|--no-require-token] [127.0.0.1:port]` binds loopback only. The HTTP stack is in `apps/sovereign/src/control_api/` (`parse`, `server`, `routes`, `static_assets`, `sse`).

- **Workers.** Four workers handle requests.
- **Static files.** `build.rs` embeds `ui-dist/` with SHA-256 ETags. If `ui-dist/` is missing, the binary embeds a one-page fallback.
- **Event stream.** `GET /v2/events/stream` runs on its own thread, so open pages never hold a request worker.
  - It follows the actor's current project database through `StatePathSource`.
  - It notices a closed page within one 500 ms poll.
  - At most 4 clients; 15 s heartbeats.

**Reads never wait on the actor** (`actor.rs`). HTTP reads open read-only handles on the current project database once the actor marks it ready.

**Commands answer quickly.** A command sent while a long step runs is acknowledged as queued with a ticket, including one sent just before the step starts. Saving "Your edits" and landing count as part of the step. `ServiceShared::pending` lists queued commands until the actor applies them. Cancel interrupts in-flight work at once: it cancels the goal's task handles, or unloads the model during a compile.

`serve --execute` runs `ExecutionService::step` inside the actor between commands. Backoff is 1 s, 2 s, cap 10 s while idle, paused, blocked, or deferred. Progress outcomes reset backoff to 0. Unknown outcomes are never retried. A composition error that repeats three times fails the queued goal (`GOAL_REASON_COMPOSITION_ERROR`). Environment errors, such as a missing model or sandbox, never fail a goal.

Around each step, for a registered project (`actor.rs`, `landing_service.rs`):

- **Before planning, in a managed project,** the person's own edits are saved as a "Your edits" commit, so the plan builds on them. This only happens while no plan is active, because task worktrees are pinned to HEAD.
- **After a plan is finalized,** each completed goal without a landing record is landed. `sovereign_repo::land_change_sets` replays its verified change sets in a temporary worktree and fast-forwards the folder. It never overwrites unsaved edits: a blocked or conflicting result is kept under `refs/sovereign/results/<goal>` for Apply.
- **Records** live in `landings-v1.json` beside the project state. Goals that completed before the file existed are marked `predates_landing` and never applied by surprise.
- **Compiles** for projects without `SOVEREIGN_PROJECT_CONFIG` see up to 12 KiB of the project's own text files, chosen by `runner::automatic_source_candidates`. A single file larger than that is never read. `GET /v2/files` reports `model_limit_bytes`, and the UI flags such files and warns above the composer. The starter's `SOVEREIGN.md` asks the model to keep files under 10 KB and put features in separate files.

## Projects

`projects.rs` and `scaffold.rs`:

- `POST /v2/projects/create {name}` makes `~/Sovereign Projects/<name>` with a static web app starter: `index.html`, `styles.css`, `app.js`, `tests/test_site.py`, `SOVEREIGN.md`, and `README.md`. It then runs `git init` and makes a "Starting point" commit. The project is `managed`.
- `POST /v2/projects/inspect {root?}` describes a folder before anything is saved: whether it has history, the bigger repository around it (`parent_project`), the file count (stopping at 20,000), total size, `large`, and up to five private-looking files (`.env`, keys). No root opens the folder picker. The UI shows this and asks before `open`.
- `POST /v2/projects/open {root?}` adopts a folder, from the path given or the macOS folder picker (`osascript`). A folder without Git gets history and becomes managed. An existing repository is used as it is and never auto-committed.
- **Switching projects.** The actor opens the new project's state before releasing the current one. If it cannot be opened, the current project keeps running, `projects-v1.json` points back at it, and the overview's `project_problem` says why until a switch succeeds.
- `POST /v2/goals/{id}/undo` reverts a landed result with a new commit. While a plan is active, it records `undo_queued` instead. The actor's landing pass runs queued Undos once no plan is active, because moving HEAD under a plan's worktrees could break it. `POST /v2/goals/{id}/apply` retries a kept result.

## Model setup

`model_setup.rs` and `assets/model-manifest-v2.json`:

- `GET /v2/setup` reports:
  - the machine: Apple silicon, memory, and free disk against the 20 GiB working floor;
  - Apple's Command Line Tools, found with `xcode-select -p` so the `/usr/bin` stubs are never run;
  - the model picked for this memory, what is in place, and download progress.
- `POST /v2/setup/model/download` fetches whatever is missing.
  - It uses `/usr/bin/curl` with HTTPS-only redirects and resumes from `<file>.partial`.
  - A file moves into place only after its SHA-256 matches the pin. A marker file stops the 2.5 GB model being re-hashed.
  - Finished paths and the model name are saved in Settings.
- `POST /v2/setup/model/cancel` pauses the download.
- The catalog lists every pinned model with `min_memory_mib`, `recommended_memory_mib`, `starting_estimate_mib`, and a `summary`. The default is the largest model whose recommended memory the Mac has, else the smallest that runs.
- `GET /v2/setup` includes `models`, one card each: installed, selected, queued, fits, recommended.
  - `POST /v2/setup/model/download {model_id?}` fetches a specific model. Only setup's own download (no `model_id`) also selects it.
  - `POST /v2/models/select {model_id, when}` switches `now` or `after_current`. A queued choice (`queued_model_id` in Settings) is applied by the runner when the next request starts compiling, so a plan never changes models halfway.
  - `POST /v2/models/remove {model_id}` deletes a model that is neither in use nor queued.
- `POST /v2/setup/developer-tools/install` opens Apple's installer.
- A runner shipped at `../libexec/llama/llama-server` beside the installed binary is used when it matches the pin.

## Memory admission

MODEL admission needs `estimate + 1536 MiB` of launch reserve free (`compilation_model_admission` and ready-task admission in `sovereign-controller`).

- **Free memory** is `memory_pressure`'s free percentage of the Mac's real memory (`sysctl hw.memsize`). It used to assume 8 GB on every Mac.
- **Estimate.** A measured calibration for this model, runtime, and profile wins. Until three samples exist, the catalog's `starting_estimate_mib` for the model in use applies, capped at the generic 4096 MiB.
- **Waiting.** A deferral keeps `needed_mib` and `free_mib`. The runner publishes them to `ServiceShared`, and goal views turn them into a plain sentence and `progress.memory {short_mib, can_start_anyway}`.
- **Start anyway.** `POST /v2/goals/{id}/start-anyway` lends the waiting request its shortfall plus 128 MiB. It is refused beyond `MAX_MEMORY_ALLOWANCE_MIB` (1024). The allowance is added to measured headroom for MODEL admission only, for that request only, and never persists.

## Versions

- `build.rs` embeds the Git commit. `/v2/session` reports `version`, and Settings → Advanced shows it.
- `serve` writes `service-version` beside the session token.
- `sovereign app`, run from the installed current version, re-points the LaunchAgent at itself when the service reports another version or none. An older copy run by hand never downgrades it.
- `scripts/install-from-source.sh` records its checkout in `~/.sovereign/source-checkout`. `sovereign app` then says when that checkout's `HEAD` differs from the running build.

## Preview and files

`preview.rs` serves the bound project read-only at `http://localhost:7778/p/<random token>/`. It uses any free port when 7778 is taken, on IPv4 and IPv6.

- **Isolation.** `localhost` is a different site from the app on `127.0.0.1`, so the session cookie never reaches the preview and the page cannot script the app. The UI frames it with `sandbox="allow-scripts allow-same-origin allow-forms allow-modals"`. `allow-same-origin` is safe here only because the frame is cross-site, and it gives previewed apps working `localStorage`.
- **Response headers.** Responses carry `frame-ancestors <app origin>`, `connect-src 'self'`, `Cross-Origin-Resource-Policy: same-origin`, and `no-store`.
- **Refused paths.** Hidden paths, `.git`, and symlinks that leave the folder are refused.
- **API.** `GET /v2/preview` gives the URL. `GET /v2/files` and `GET /v2/files/content?path=` back the Files tab (text only, 256 KiB).

## Token and CSP

- **Session token.** At serve start a 32-byte token is written to `~/Library/Application Support/Sovereign/service-token` (mode 0600).
- **Launch code.** `sovereign app` writes a single-use launch code (`launch-code`, mode 0600, 60 s TTL) and opens `/?c=<code>`. The service redeems it once and sets `sovereign_session` (`HttpOnly`, `SameSite=Strict`). `GET /?t=<token>` still sets the cookie for the e2e harness.
- **Authentication.** Every `/v2/*` request needs the cookie or a bearer token. POSTs also need `X-Sovereign-CSRF`.

Every response includes:

- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src <preview origin>; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. Radix's dialog scroll-lock `<style>` is refused by this policy; the app layout never scrolls the body, so nothing is lost.
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` on API responses

## App data and install layout

`~/Library/Application Support/Sovereign/`:

- `settings-v1.json`, `projects-v1.json`, `service-token`, `logs/`
- `projects/<id>/state.sqlite3`, `cas/`, `landings-v1.json`, `landing-scratch/`
- `models/`, `runtime/<runtime id>/`, `downloads/`

The installed app lives in `~/.sovereign/versions/<version>/`, with `current` switched atomically. `~/.local/bin/sovereign` links the current version, and `~/Applications/Sovereign.app` opens it from Spotlight and Launchpad.

`install.sh` and `sovereign update` verify the release tarball against `SHA256SUMS` and hand over to the new binary's `self-install`.
- The version in use is never deleted or replaced. A same-version release is reported as already installed.
- Any other existing copy of that version is moved aside before the new one is moved in, and put back if the move fails.
- `scripts/install-from-source.sh` stages and swaps the same way.
- `sovereign uninstall` never touches project folders.

## LaunchAgent

`self-install` (or `sovereign service install`) writes `~/Library/LaunchAgents/dev.sovereign.agent.plist` with `serve --execute 127.0.0.1:7777` and `ThrottleInterval` 30. Plain `sovereign`, `sovereign app`, and the Sovereign.app launcher all do the same thing:

1. Install the agent if needed.
2. Wait for the port, restarting the agent once if it doesn't answer.
3. Issue a launch code and open the browser.

`logs/stdout.log` and `logs/stderr.log` are capped at 10 MiB (`service_logs.rs`).

## UI

`apps/sovereign/ui/` is React 19 and TypeScript (strict, `noUncheckedIndexedAccess`), built with Vite. It uses Tailwind v4's reset, hand-written tokens and components in `styles.css`, Radix Dialog/Tabs/Tooltip, TanStack Query, and lucide icons. There is no router.

- **`App.tsx`** shows onboarding until setup is done and a project exists. Onboarding can be deferred and is remembered in `localStorage`.
- **`screens/Onboarding.tsx`** has three steps: Welcome, Getting ready, and First project.
- **`screens/Workspace.tsx`** has three parts:
  - the projects sidebar;
  - the conversation (`components/Conversation.tsx`) and composer (`components/Composer.tsx`);
  - the Preview / Files / Details panel (`components/SidePanel.tsx`).
- **`components/Dialogs.tsx`** holds Settings (with Advanced), Help, and New project.
- **Rendering rules.** Untrusted text is always a text node, and `dangerouslySetInnerHTML` is banned by ESLint. `src/api/generated.ts` is generated from `schemas/control-api-v2.json`.

Requests poll every 1.5 s while any is running, because a model call emits no events. The event stream refreshes goals and the overview on every journal event.

A project switch that waits for the current step shows as `switch_project` in the overview's `pending_commands`. Until it applies, reads still come from the previous project, so the workspace shows the chosen project as opening instead of that project's requests, preview, and files. The overview polls, and everything reloads once the switch applies.

`scripts/verify-ui.sh` runs the following when `node` exists:

- `npm ci` when needed;
- `gen:api` with a freshness check;
- typecheck, ESLint, and Vitest with axe;
- the build, the 250 KiB gzip budget, and a `/v2` route scan.

`scripts/e2e.sh` builds `sovereign-e2e-server` and runs Playwright against installed Chrome.

`sovereign-e2e-server` (feature `e2e-fixtures`) starts from a starter project, lands results, runs the preview, and injects `DeterministicFakeBackend`. The production binary must not contain e2e-server strings.

## Tests

- **Actor:** lifecycle, queued commands during a long step, and run-lock release (`actor.rs`).
- **HTTP server:** token, CSRF, concurrency, 413, slow clients, ETag, traversal, and event streams that never starve requests (`control_api/`).
- **Live contract:** `/v2` schema checks, including projects, setup, preview, files, undo, and apply (`apps/sovereign/tests/control_api_contract.rs`).
- **Module tests:**
  - landing with real Git: `landing_service.rs` and `crates/sovereign-repo/tests/landing.rs`;
  - pinned downloads and resume: `model_setup.rs`;
  - install layout: `install.rs`;
  - preview isolation: `preview.rs`;
  - goal wording: `goal_views.rs`.
- **Vitest and axe:** every reply card, onboarding, the preview sandbox, and the composer (`ui/src/test/`).
- **Playwright and axe:** the consumer journey (`ui/e2e/consumer.spec.ts`).
- **Owner acceptance on a Mac with the real model:** `docs/acceptance-v2.md`.
