# Consumer production readiness plan

> Snapshot: HEAD `9f65d40` ("Consumer Grade 1", 2026-09-26). Written from a read of the repo, the wiki, `BUILD_STATE.json`, `output/CONSUMER_UX_AMENDMENT_v1.0.md`, `.cursor/plans/sovereign_consumer_product_bcaab176.plan.md`, and `implementation/evidence/`. Checks run on a Linux container, not the M1. This is a plan, not an amendment. New scope still has to enter through a new file under `output/`.

## Bottom line

The engine (M0–M9, PD-T01–T06) and the consumer shell (CX-T03–T24) exist. A first-time user on the target machine still cannot get a goal from "typed" to "verified" through the product:

1. **The model is never admitted on an 8 GB Mac.** `CX-T25.json` records `completed: false`. Admission deferred because the model lease is always uncalibrated at 4096 MiB (`crates/sovereign-controller/src/lib.rs:9150-9153`, "no durable named-model calibration store yet"), so it needs 5632 MiB of projected headroom. The host had 3686. The recorded real run peaked at about 3.05 GiB RSS (`M1-real-model-qualification.json`, `startup_peak_rss_kb` 3120624), so the estimate is about 1 GiB too high.
2. **CX-T26 is only half proven.** Checklist item 2 is "partial" (the goal stopped at `queued_for_plan_compilation`) and item 3 is "not observed" (`implementation/evidence/CX-T26/notes.json`). The Cursor plan marks every phase completed. That is not true yet.
3. **A consumer cannot install it.** Install is `cargo install --path apps/sovereign`. The user has to find a GGUF and a `llama-server` build themselves. `apps/sovereign/assets/model-manifest-v1.json` has `url`, `sha256`, and `size_bytes` all `null`, and `download_model_response` always errors (`apps/sovereign/src/dispatch.rs:30`).

Everything below is ordered so those three close first.

## What was checked in this session

| Check | Result |
| --- | --- |
| `cargo fmt --check` | Pass |
| `cargo clippy --workspace --all-targets -D warnings` on Linux | **Fail**: `sovereign-policy/src/browser.rs:17` unused `Command`/`Stdio` imports and `:1181` `unused_self`. Code is macOS-gated, so the linter cannot run on non-macOS hosts. |
| `scripts/verify-ui.sh` | Pass: 23 Vitest tests, build is reproducible (same asset hashes as committed `ui-dist/`), 184 KiB gzip JS against the 250 KiB budget, route scan passes |
| `cargo test`, `scripts/e2e.sh`, ignored real-model tests | Not run here (they need `sandbox-exec`, Chrome, and the M1) |
| Last known M1 `verify.sh` (2026-09-25, wiki page 15) | CX-T01/T02 fixed. Failed `real_chrome_contains_page_js_writes_and_worker_network_before_execution` in `crates/sovereign-tools/tests/browser.rs` |

---

## Phase 0: make the product work on the target machine (release blockers)

### P0.1 Measured model calibration. Largest blocker.

- Add a durable named-model calibration record, keyed by model SHA-256, runtime SHA-256, `-c` context, and profile digest, holding measured startup-peak and prefill/decode-peak RSS. Store it in `state_records` under a new namespace and give it a schema version. The residency probe already measures RSS during load.
- Admission uses `calibrated: true` with p95 plus a stated margin only when a matching record exists. Otherwise it stays at 4096.
- Calibration has to produce itself safely. The first calibration run needs an explicit, user-visible "calibrate now" step with its own gate: the host must be green, nothing else is admitted, the run aborts on a `Constrained` band, and the record is written only after an unload proof.
- Do not lower `normal_controlled_working_set_hard_mib` or launch headroom (wiki 12). The fix is a better estimate, not a looser ceiling.
- Re-do the arithmetic before you commit to this. At about 3,100 MiB calibrated, the 1536 MiB soft launch headroom needs about 4.6 GiB of free headroom. The CX-T25 host had 3.6 GiB with 2.8 GiB of swap in use. Calibration alone may not be enough. That leads to P0.2.

### P0.2 Memory guidance and a smaller-footprint fallback

- When admission defers, the UI has to say why in plain words and name what to do ("Close apps to free about 1.1 GB. Sovereign is waiting."). Today this shows up as the `DeferredResource` phase. Show the live headroom, the required headroom, and a retry.
- Decision for the user: whether to ship a second, smaller context tier (for example `-c` 4096 plus reserve) or a smaller quant as a fallback lease when 8192 cannot be admitted. That touches frozen profile numbers, so it needs an amendment.

### P0.3 Close CX-T25 and CX-T26 for real

- Run `crates/sovereign-eval/tests/consumer_acceptance.rs` (`--ignored`) on the M1 after P0.1 and P0.2 until `CX-T25.json` records `completed: true` with fresh source hashes.
- Re-run the CX-T26 manual first-run and capture the missing statuses (compile → plan → execute → verify) and one real approve/deny. Fill the missing screenshot `04-*` (the numbering skips it).
- Only then flip the Cursor plan todos and write CX milestone evidence. Until then, change `p6-acceptance-docs` back to in-progress.

### P0.4 Green gate on the M1

- Root-cause the live-Chrome failure `real_chrome_contains_page_js_writes_and_worker_network_before_execution` ("safe HEAD subresource was not allowed"). Run it in isolation first, per wiki 15. If it depends on the Chrome version, pin the tested Chrome range and have `doctor` report it.
- Get one clean end-to-end `./scripts/verify.sh` plus `scripts/e2e.sh` on the committed tree and record it.
- Add a script that recomputes `source_hashes` for every `implementation/evidence/*.json` and lists stale evidence. Today "Historical" is a judgment call.

### P0.5 How verified work reaches the user

- Confirm and document where a completed goal's change set ends up. `sovereign-repo` has worktree lease, diff, and change-set capture but nothing obviously named for landing (for example "apply to my branch" or "create branch/commit"). A search for land/promote/apply/merge-back found only multi-repo integration views.
- If there is no landing path, build one: an explicit "Apply to branch `sovereign/<goal>`" action that never touches the user's current branch or dirty files (invariant 7), plus a UI diff review before applying. A consumer who cannot get the result out has no product.

---

## Phase 1: installable, updatable, uninstallable

`output/CONSUMER_UX_AMENDMENT_v1.0.md` puts signed distribution and auto-update out of scope. Production consumer release needs them, so this phase needs a new amendment (for example `CONSUMER_DISTRIBUTION_AMENDMENT_v1.0.md`).

1. **Packaging.** A signed and notarized `Sovereign.app` (or `.pkg`) bundling `sovereign`, the pinned `llama-server`, and its dylibs. The recorded runtime is 33,472 bytes, which points to a shim with shared libraries, so ship the whole runtime directory. No Rust or Node on the user's machine.
2. **Model acquisition.** Fill the manifest with the pinned SHA-256 and size. CX-T26 already recorded the model digest `7485fe6f…` and the runtime digest `d0878274…`. Implement download with an explicit confirmation token (the route exists): resumable, hash verified before rename, disk-space precheck against the 20 GiB floor, offline-first (existing files are still accepted). Show the Qwen and llama.cpp licenses in onboarding.
3. **Updates.** At minimum an opt-in "check for updates" against a signed manifest. On update: rewrite the LaunchAgent plist (it pins the absolute binary path, `launch_agent.rs:161`), run `StateStore` migrations with a pre-migration backup, and refuse to downgrade schema 7+. Extend `crates/sovereign-eval/tests/upgrade_compat.rs` to cover `settings-v1.json` and `projects-v1.json` too.
4. **Uninstall.** `service uninstall` only removes the agent. Add a full uninstall that lists and removes app data, the model, and logs, and leaves user repositories alone.
5. **User guide.** Rewrite `docs/user-guide.md` for the packaged flow. `cargo install` moves to a developer section.

---

## Phase 2: operability and resilience of the service

| Item | Why | Where |
| --- | --- | --- |
| Log rotation and size caps | launchd `stdout.log`/`stderr.log` grow without bound | `launch_agent.rs`, `logs/` |
| Structured service log plus redacted "export diagnostics" bundle | Support without asking users for SQLite files | new `/v2/diagnostics/export`, Diagnostics screen |
| Automatic state backup (SQLite online backup) before migrations and daily | One DB per project is the only record | `app_data.rs`, `sovereign-state` |
| Port conflict on 7777 | A silent failure today | `serve`, `sovereign app`, doctor |
| Crash-loop detection | `KeepAlive SuccessfulExit=false` restarts forever | plist `ThrottleInterval` plus a doctor check |
| Sleep/wake, lid close, battery, thermal | Long goals on a laptop | pressure probe, execution-service backoff |
| Disk budget enforcement surfaced | 40/60 GiB limits exist in the profile, not in the UI | Home/Diagnostics |
| Soak test of `serve --execute` for 24 h on the M1 with fixture backend then real model | No evidence of long-run leaks in actor, SSE, or worker pool | `sovereign-eval` release suite |

---

## Phase 3: UX completeness

1. **Notifications.** CX-T23 lists notifications. None are implemented; a search for "notif" in `apps/sovereign/src` and `ui/src` finds nothing. Add in-app toasts from SSE plus macOS notifications (via `osascript` or the future `.app` shell) for approval needed, goal verified, goal blocked, and recovery required.
2. **Status copy for every outcome.** Map every `ProductionAdvanceOutcome` and `ProductionBlockReason` to a sentence and a next action. CX-T26 item 2 depends on this. Add a table test that fails when a new variant has no copy.
3. **Goal authoring help.** Examples, the definition of a "bounded" goal, and pre-submit warnings (for example "needs network" or "needs approval").
4. **Project picker.** Onboarding asks the user to paste a repo path. The packaged app should offer a native folder picker.
5. **Result review.** Diff viewer with per-file view, verification evidence, and the P0.5 apply action on the goal page.
6. **Frontend structure.** Split `ui/src/screens/Workspace.tsx` (8 screens in 586 lines) into one file per screen. Code-split the 583 KB JS chunk (the Vite warning), with `@xyflow/react` as the first lazy chunk.
7. **Test depth.** Four Playwright tests and 23 unit tests is thin. Add e2e for cancel, pause/resume, recovery, settings persistence, SSE reconnect, a 401 after token rotation, and keyboard-only navigation with axe on every route.

---

## Phase 4: security hardening before public release

- **Token in URL.** `GET /?t=<token>` puts the long-lived token in browser history. Use a single-use, short-TTL launch code that is exchanged for the cookie, and rotate the service token on each `sovereign app`.
- **Fuzzing.** `control_api/parse.rs` is a hand-written HTTP parser. Add `cargo-fuzz` targets for it, the Plan IR validator, and the model-response JSON parser.
- **Supply chain.** `cargo-deny` (advisories, licenses, bans) and `npm audit` in CI. Produce an SBOM with each release. Confirm no GPL/AGPL code from `research/`.
- **Sandbox review.** An external review of the Seatbelt profiles and the `AMBIENT_DENY_NAMES` list. Track Apple's deprecation of `sandbox-exec` as a named platform risk, with a stated fallback (deny, per invariant 9).
- **Local-attacker model.** Write down that any local process running as the user can reach loopback with the token file. That is accepted, but it should be written down.
- **Security negatives in CI.** DNS rebinding (bad Host), cross-origin POST, oversize bodies, and path traversal already have unit tests. Run them against the packaged binary too.

---

## Phase 5: engineering hygiene and CI

1. **CI does not exist** (no `.github/`). Add a macOS arm64 workflow: fmt, clippy, `cargo test --workspace`, `verify-ui.sh`, `e2e.sh`. Add a nightly job for slow and soak tests. Real-model tests stay manual on the M1 but upload evidence.
2. **Cross-platform lint.** Fix the two `sovereign-policy/src/browser.rs` cfg-gating errors so clippy passes on Linux too, or declare macOS-only CI explicitly.
3. **Committed build noise.** `apps/sovereign/ui/tsconfig.tsbuildinfo` changes on every build (observed here) and `ui/test-results/.last-run.json` is committed. Gitignore both. Keep `ui-dist/` committed. The build was reproducible here.
4. **Stale docs.** The wiki headers still say "uncommitted work" (now committed in `9f65d40`). `DEVELOPMENT.md`, `MACHINE.md`, `REQUIREMENTS.md`, `NON_GOALS.md`, and `SOURCES.md` begin with `cat > … <<'EOF'` residue. `BUILD_STATE.json` `completed_milestones` stops at M6 and knows nothing of CX.
5. **Gate speed.** `verify.sh` takes about 17 minutes. Split it into `verify-fast` (fmt, clippy, unit tests) and `verify-full`.
6. **`sovereign-controller/src/lib.rs` is 38.5k lines.** Plan a staged, test-neutral extraction (resources/admission, approvals, recovery, integration views) as its own tasks, never as a drive-by.

---

## Phase 6: product decisions only the owner can make

| Decision | Why it matters |
| --- | --- |
| Hardware profiles beyond M1/8 GB | Most target Macs have 16 GB or more and would be held to the 8 GB ceilings. At least add a detected `m-series-16gb` profile with its own calibration. |
| Expected capability of Qwen3-4B | Run the M9 corpus against the real model to publish a real success rate. Today only one real qualification scenario exists. Consumers need to know which goals work. |
| Telemetry | Local-first suggests none. Decide whether opt-in, redacted crash reports are acceptable. |
| Scope of the browser, Postgres, and web acquisition surfaces in v1 consumer | They add Chrome-version and Scrapling dependencies and a failing live test. Consider hiding them behind "advanced" for v1. |
| Deferred M7-T01, M7-T04, M8-T02, M8-T03 | Leave them deferred for v1 unless the capability eval (above) shows retrieval is the bottleneck. |

---

## Suggested order and exit criteria

```
P0.1 calibration ─┬─> P0.2 guidance/fallback ─> P0.3 CX-T25/T26 closed ─┐
P0.4 green gate ──┘                                                     ├─> Phase 1 packaging ─> Phase 4 security ─> release candidate
P0.5 landing path ─────────────────────────────────────────────────────┘
Phase 5 CI starts now, in parallel. Phases 2 and 3 run in parallel after P0.3.
```

**Release candidate is done when:**

- On a stock 8 GB M1 with typical apps open, a new user installs a signed app, downloads and verifies the model, adds a repo, and completes a real goal to verified with no terminal. Recorded as evidence with fresh source hashes.
- CX-T26 items 1–4 are all "pass" with screenshots.
- macOS CI is green on the tagged commit: `verify.sh`, `e2e.sh`, fuzz smoke, `cargo-deny`.
- The 24 h soak shows no RSS growth beyond a stated bound and no replay of an unknown action.
- Update from the previous build and full uninstall have been exercised.
