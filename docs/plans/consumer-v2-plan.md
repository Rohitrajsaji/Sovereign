# Sovereign consumer v2 plan

> Written 2026-09-26 from a code read of branch `claude/festive-lovelace-iubm17` and the owner's answers. Contract: [output/CONSUMER_UX_AMENDMENT_v2.0.md](../../output/CONSUMER_UX_AMENDMENT_v2.0.md). Task ids `CX2-Txx` refer to that amendment.

## Goal

A person who cannot code installs Sovereign with one command, sets it up by following the screen, asks for a small app in plain words, watches it being built, sees it in a preview, and can undo it. No Terminal after install, no developer help.

## Why it feels broken today (root causes)

| Symptom you saw | Root cause | Where |
| --- | --- | --- |
| Many buttons do nothing | Every UI command waits at most 5 s for the Controller actor. While a step compiles or loads the model (minutes with the real model), the actor is busy, the request times out, and the UI swallows the error (`void mutate()` with no error display). | `apps/sovereign/src/actor.rs` `DEFAULT_RECV_TIMEOUT`, `run_actor_loop`; `ui/src/screens/Workspace.tsx` |
| Reads also freeze | Overview, goals, and goal detail are served through the same busy actor. | `apps/sovereign/src/dispatch.rs` |
| Goal stays "queued" | If plan compilation fails, or uses its two model calls, the goal is reported blocked but never marked failed. It stays at the head of the queue. A memory deferral also leaves it queued, with no explanation (fixed on this branch: the reason now shows). | `crates/sovereign-controller/src/production_driver.rs` `advance_queued_compilation` |
| New goals pile up behind it | The queue runs one goal at a time, strictly oldest first (`next_queued_goal_intent`). A stuck head blocks everything. | `crates/sovereign-controller/src/goal_runner.rs` |
| Cancel does nothing | Cancel of an active goal only asks its tasks to stop; the goal stays `active_plan` forever. Cancel during compilation is rejected ("claimed"). And the click usually times out first (row 1). | `goal_runner.rs` `cancel_goal_intent` |
| A failed task freezes everything | When a task fails for good, the step returns `Blocked { FailedTerminal }` every time. The goal never ends and the queue never moves. | `production_driver.rs` |
| Wrong percentage | Progress is hardcoded: queued = 8, anything else = 45, completed = 100. | `Workspace.tsx` `GoalDetailScreen` |
| Status filter shows nothing | Filter values (`queued`, `active`, `cancelled`) do not match real statuses (`queued_for_plan_compilation`, `active_plan`, `cancelled_before_dispatch`). There is no failed status at all. | `Workspace.tsx`, `goal_runner.rs` |
| "Load task diff" shows a strange sample with a `<script>` tag | A test fixture diff is shown whenever the real diff is unavailable. | `Workspace.tsx` |
| Finished work never shows up in the folder | Verified edits happen in a temporary worktree that is deleted after verification. The result is kept only as a change-set record; nothing applies it to the user's folder. | `crates/sovereign-repo/src/worktree.rs`, runner tests |
| UI looks like a developer console | Internal words on screen ("Loopback", "Controller commits", raw status slugs, epochs, digests), raw JSON tabs, no layout hierarchy, a toast that covers content. | `ui/src/**` |

## Milestones

Each milestone ends with: Rust fmt, clippy, and tests; the UI gate; Playwright against the fixture server; screenshots reviewed; commit, push, and a PR update.

### Status (2026-09-26)

M1 through M5 are built and pushed. M6 is done up to the owner's run on a Mac.

- **M1.** Nothing hangs or lies. Its UI item moved into M5.
- **M2.** Projects, invisible Git, landing, Undo, Apply, and the scaffold.
- **M3.** A pinned catalog (Qwen3-4B Q4_K_M at a fixed Hugging Face revision; the llama.cpp b10516 runner), resumable checksum-checked downloads, and the Command Line Tools check.
- **M4.** `install.sh`, `self-install`, `update`, `uninstall`, the `~/Applications/Sovereign.app` launcher, the release workflow, and `install-from-source.sh`.
- **M5.** The new UI: onboarding, conversation, the preview/files/details panel, settings, and help.
- **M6.**
  - The Playwright journey (9 tests) passes against the fixture server in Chromium.
  - Vitest and axe cover every card state.
  - The user guide, troubleshooting, and `docs/acceptance-v2.md` are written.

**Deviation.** The preview frame uses `allow-scripts allow-same-origin allow-forms allow-modals` rather than omitting `allow-same-origin`.

- Without it, previewed apps cannot use `localStorage`, which the starter tells the model to use.
- It is safe because the preview is served from `localhost`, a different site from the app on `127.0.0.1`. The session cookie never reaches it, and the frame cannot touch the app.

**Findings that change later work.**

- Without `SOVEREIGN_PROJECT_CONFIG`, compiles saw no files. The runner now shows the model up to 12 KiB of the project's own files, which fits the 8K compile packet. A project whose main file outgrows that needs a bigger context tier.
- Consumer compiles use the minimal compiler path. Its only acceptance check is the scoped-diff evaluator, so the starter's `tests/test_site.py` is not yet run. A Controller-authored check command is the next quality step.
- Task worktrees are pinned to HEAD, so the folder only changes when no plan is active: before planning and after finalization.
- Each open page's event stream used to hold one of four HTTP workers, stalling buttons for 15 to 30 s with a few tabs open. The stream also tailed the wrong database for registered projects. Both are fixed.
- The fixture model cannot produce file changes, so Undo and Apply are proven by Rust tests with real Git, not by Playwright.

### M1. Nothing hangs, nothing lies (CX2-T01 to T05)

1. **Reads off the actor.** Serve overview, goals, goal detail, events, recovery, and settings from `LocalControl::read_only(StateStore::open(path))` on the HTTP worker threads. SQLite WAL allows concurrent readers. The actor keeps only mutations.
2. **Commands acknowledged at once.** Mutations go to the actor as today, but the HTTP handler never waits more than about 1 s. A busy actor answers `202 Accepted` with "Will apply as soon as the current step reaches a safe point". The actor drains commands between steps.
3. **Interrupt in-flight work.**
   - Before each step, the actor publishes the cancellation handles for the active goal's tasks, and the compile-time model backend, to a shared slot.
   - Cancel and Pause trigger those immediately: the task cancellation handle for execution; unloading the model for a compile in progress (compile calls have no side effects).
   - The durable cancel or pause is then committed by the Controller at the next safe point.
   - The no-replay-of-unknown rule is unchanged.
4. **Terminal goal states.** Add goal status `failed` with a plain reason code, and make cancel of an active goal end as `cancelled`.
   - Compile failure, compile budget exhausted, and a plan whose remaining tasks cannot run (a task `FailedTerminal`, or all remaining tasks cancelled) archive the active plan through a new Controller transition next to `finalize_completed_active_plan`, and mark the goal terminal.
   - The queue then moves on. "Try again" is a new goal carrying the same text.
   - Recovery and restart tests cover a crash in each new transition.
5. **Real progress.** One Rust projection computes, per goal:
   - the phase: waiting, planning, building, checking, done, failed, or cancelled;
   - step x of y, from the task states;
   - the percent;
   - a one-sentence plain-language status.

   The UI only displays it.
6. **Per-goal activity.** Filter journal events to the goal's intent and plan ids, and translate event kinds into plain sentences.
7. **Honest UI.** Every button shows pending, success, and failure. Remove the fake diff. Filters use real statuses.

### M2. Projects without git knowledge (CX2-T06 to T09)

1. **New project:** a name creates `~/Sovereign Projects/<name>`. **Open a folder** uses the native macOS folder dialog (`osascript` `choose folder`, run by the local service in the user's session).
2. **Invisible git.** If the folder is not a repository:
   - `git init`;
   - a repository-local identity (`Sovereign <sovereign@localhost>`);
   - a first commit "Starting point".

   Existing repositories keep today's rules: no touching uncommitted work.
3. **Landing.** When a goal completes, apply its verified change sets (diff plus untracked-file deltas from CAS) to the project folder on top of the recorded base commit, and commit "Sovereign: <request>".
   - Before landing, if the user edited files in a Sovereign-managed project, commit those edits first as "Your edits".
   - For adopted repositories with uncommitted work, stop and ask.
   - Landing never resets or overwrites.
4. **Undo.** `git revert` of the landed commit, which is itself a new commit. Undo refuses, with an explanation, when later edits touch the same lines.
5. **Starter scaffold.** A new, empty project gets a tiny web-app skeleton with a runnable check, so the verifier has something to run. Research first: confirm what verification the compiler produces for an empty folder, and adjust the scaffold to match.

### M3. Zero-setup model (CX2-T10 to T12)

1. **Hardware detection:** Apple Silicon check, RAM (`hw.memsize`), free disk.
2. **Model manifest v2.** RAM tiers:
   - 8 GB: Qwen3-4B Q4_K_M. Pinned: `sha256 7485fe6f…`, 2,497,280,256 bytes, recorded in CX-T26.
   - 16 GB and up: a larger model, enabled only once its checksum is pinned.
   - Unpinned entries are refused (fail closed).
3. **Download.** Uses `/usr/bin/curl` (always present on macOS):
   - resume support;
   - a disk-space precheck against the 20 GiB floor;
   - progress reported to the UI;
   - SHA-256 check before the file is moved into place;
   - offline reuse of files already on disk.
4. **Command Line Tools.** `git` and `python3` on a fresh Mac are stubs until Apple's Command Line Tools are installed. Detect that, and offer the one-click Apple installer (`xcode-select --install`) with a plain explanation and a re-check button.
5. **`llama-server`** ships inside the release tarball, so the only large download is the model.

### M4. Install and release (CX2-T13, T14)

1. **`install.sh`:**
   - checks for macOS on arm64;
   - downloads the latest release tarball and `SHA256SUMS`, and verifies them;
   - installs to `~/.sovereign/bin`;
   - symlinks `~/.local/bin/sovereign` and prints the PATH line if needed;
   - then runs `sovereign`.

   `curl` downloads are not quarantined, so Gatekeeper does not block the unsigned binary.
2. **`sovereign` with no arguments** installs or refreshes the background service and opens the app in the browser with a one-time link.
3. **Updates and removal:**
   - `sovereign update` fetches the newest release, verifies it, swaps it atomically, rewrites the LaunchAgent, and restarts it.
   - `sovereign uninstall` removes the service and binaries, and asks before deleting models and projects' history.
4. **Release workflow on a `v*` tag:**
   - builds the UI and `sovereign` for `aarch64-apple-darwin`;
   - fetches the pinned llama.cpp macOS arm64 build and records its checksum;
   - packages `sovereign-<version>-macos-arm64.tar.gz` and `SHA256SUMS`;
   - uploads them to the GitHub Release.

### M5. The new UI: chat plus live preview (CX2-T15 to T20)

**Principles.**
- Plain words, one primary action per screen.
- Every state has a sentence and a next step.
- Technical detail lives behind "Details".
- Nothing looks clickable unless it is.

**Layout.**
- **Left sidebar:** Sovereign mark, projects list with status dots, "New project", then Settings and Help at the bottom.
- **Center, the conversation for the selected project:**
  - the user's requests as messages;
  - Sovereign's replies as live progress cards. The stepper is Planning → Building → Checking → Done, with step x of y, a real progress bar, a plain sentence, and Cancel;
  - result cards with what changed, "Open preview" and "Undo";
  - failure cards with the reason in plain words and "Try again";
  - approval cards with "Allow" or "Don't allow" and a plain description of the exact action.
- **Composer** at the bottom, with example prompts for new projects.
- **Right panel, collapsible, with tabs:**
  - Preview: the project's app in a sandboxed iframe from a separate loopback origin with no cookies, and a refresh button;
  - Files: a read-only tree and viewer;
  - Details: plan, verification, and a technical log for advanced users.
- **Onboarding, three steps:**
  1. Welcome: what Sovereign is.
  2. Getting ready: system checks, the Command Line Tools prompt, and the model download with progress.
  3. Your first project.
- **Settings:** model and storage, notifications, and an Advanced area (diagnostics, service, paths).

**Design system.**
- System font stack (SF Pro on Mac) with a 4 px spacing scale.
- One accent color, neutral grays, status colors only for status.
- Light and dark mode following the system.
- 8 px radius and focus rings everywhere.
- Radix primitives for dialogs, tabs, and tooltips.

**Security for the preview.**
- Served on its own port with no session cookie and no API.
- The iframe uses `sandbox="allow-scripts allow-forms"`, never `allow-same-origin`, under a CSP that only allows the preview origin.
- Project file contents are always text nodes.

### M6. Quality and acceptance (CX2-T21 to T23)

- Playwright tests of the whole journey against the fixture server: onboarding, new project, request, progress, cancel, failure, then the next request runs, approval, undo, and preview.
- axe accessibility checks on every screen; keyboard-only paths; a 250 KiB gzip budget.
- Documentation: README quickstart, user guide, and troubleshooting ("Waiting for memory", "Command Line Tools", "Something went wrong").
- Owner-run acceptance on an Apple Silicon Mac with the real model (the amendment's six checks).

## What needs your Mac

This container is Linux, so I cannot run `sandbox-exec`, the real model, the LaunchAgent, or the macOS folder dialog. Everything else is built and tested here (Rust unit and integration tests, UI tests, and Playwright against the fixture server in Chromium). You will need to:

1. Run `./scripts/verify.sh` and `scripts/e2e.sh` on the Mac at each milestone.
2. Run the checksum-pinning script once for any model or llama.cpp build I cannot reach from here (Hugging Face and the GitHub API are blocked in this environment).
3. Make the repository public and push a `v0.2.0` tag to publish the first release.
4. Do the CX2-T22 acceptance walk-through.

## Risks

- **Model capability.** A 4B model on 8 GB will manage small apps and edits, not large features. The UI must set expectations with good example prompts, and larger tiers help on 16 GB+ Macs.
- **Controller changes are deep.** New terminal transitions touch plan archival and recovery. Each one gets crash-recovery tests.
- **Verification for non-coders' projects.** Unconfirmed: the compiler may require an existing check to run. The M2 scaffold addresses this; M2 starts with research.
