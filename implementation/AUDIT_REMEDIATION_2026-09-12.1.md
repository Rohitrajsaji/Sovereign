# Sovereign Audit Remediation Checklist — 2026-09-12.1

Status: active build steering. This checklist augments implementation acceptance; it does not redesign or replace the frozen architecture, Plan IR, or roadmap.

Supervisor steering acknowledgment: the interrupted 17:44 UTC audit steering was re-received in the continuation chat and is durable here. Revalidate changed code before crediting any gate; this file remains mandatory through M1 closure and final local release acceptance.

## M1 closure gates

1. **Context accounting and absolute model deadlines**
   - Status: implementation and short real-model accounting smoke verified in `implementation/evidence/M1-model-accounting-remediation.json`; representative full engineering packet remains part of gate 6.
   - Status: **OPEN — required before M1 closure.**
   - Current source owner: `crates/sovereign-model/src/lib.rs`.
   - Reconcile llama.cpp runtime window with explicit input allowance plus generation reserve.
   - Count the exact fully rendered chat/tool/template request before inference, including tool schemas and structured-output schema.
   - Reject a complete rendered request that would consume the reserved generation window.
   - Enforce one absolute wall deadline across connect, write, read headers, body, and provider processing rather than resetting a full timeout on each socket operation.
   - Required tests/evidence: model backend request accounting tests, tool/schema/template overhead fixture, oversized complete request pre-dispatch rejection, stalled/slow HTTP wall-deadline test, representative full-packet real-model evidence.

2. **Durable action outcomes**
   - Status: resolved for the T04 minimum; current evidence is `implementation/evidence/M1-T04.json` and committed source checkpoint `1884f86`.
   - Status: **RESOLVED for M1-T04; revalidated again in Controller/crash-resume integration before M1 closure.**
   - Source: `crates/sovereign-tools/src/lib.rs`, `crates/sovereign-state/migrations/0003_security_kernel.sql`.
   - Tests: `process_runner_refuses_execution_until_exact_action_is_durably_authorized`, `published_receipt_before_state_observation_never_creates_false_commit`, `observed_receipt_survives_restart_and_can_then_commit`, `committed_action_requires_durable_result_reference`.
   - Evidence: `implementation/evidence/M1-T04.json`.
   - An action may become `committed` only after its redacted result/receipt is durably published and the durable action record references that evidence.
   - Preserve the frozen distinction between command success/failure and action-record commitment.
   - Required tests/evidence: crash during execution, after evidence publication/before action-state commit, and after commit; recovery must never expose a committed action without recoverable result evidence.

3. **Cleanup proof**
   - Status: resolved for the T04 minimum with fail-closed recovery blocking when descendant death cannot be proven; richer checkpoint/restart recovery is now closed in M1-T08 with `implementation/evidence/M1-T08.json`.
   - Status: **RESOLVED for M1-T04 minimum.**
   - Source: `crates/sovereign-tools/src/lib.rs`, `crates/sovereign-policy/src/lib.rs`.
   - Tests: `timeout_kills_and_reaps_the_entire_process_group`, `escaped_descendant_holding_output_pipe_is_bounded_and_recovery_blocked`, `output_disk_and_subprocess_ceilings_terminate_bounded_commands`.
   - Evidence: `implementation/evidence/M1-T04.json`.
   - Process-group disappearance alone is not proof that every descendant died.
   - Bound stdout/stderr drain/join time.
   - If the declared isolation/cleanup profile permits a descendant to escape ownership (for example `setsid`), cleanup must be recorded as unproven and recovery/mutation blocked until reconciled.
   - Required tests/evidence: normal descendant cleanup, escaped-session child fixture, inherited-pipe holder fixture, bounded drain timeout, `unknown`/recovery-blocked transition trace.

4. **Version-3 state migration reconciliation**
   - Status: resolved; exactly one canonical runtime/manifest v3 remains and v2→v3 compatibility is tested.
   - Status: **RESOLVED.**
   - Source: canonical `crates/sovereign-state/migrations/0003_security_kernel.sql` plus `manifest.json` and runtime `MIGRATIONS`.
   - Compatibility decision: no persistent project v3 DB existed; v2 is upgraded in place, while a conflicting recorded v3 checksum fails closed.
   - Tests: `version_two_database_upgrades_in_place_to_single_canonical_version_three`, `migration_manifest_has_one_version_three_and_matches_runtime`, migration idempotence/checksum/rollback suite.
   - Evidence: `implementation/evidence/M1-T04.json`.
   - Maintain exactly one runtime/manifest version-3 migration.
   - Preserve already-created databases by an explicit compatibility decision and migration checksum behavior.
   - Required tests/evidence: fresh schema v3, reopen/idempotence, explicit old-v2-to-v3 upgrade, duplicate-version rejection/absence, failed v4 fixture rollback, manifest/runtime agreement.

5. **Isolation capability truthfulness**
   - Status: resolved for the M1 offline macOS profile; selective task networking and a complete read namespace jail remain unavailable rather than best-effort.
   - Status: **RESOLVED for M1-T04 minimum.**
   - Source: `crates/sovereign-policy/src/lib.rs`, `crates/sovereign-tools/src/lib.rs`.
   - Tests: `mac_sandbox_denies_protected_home_read_and_offline_network`, `inherited_sensitive_environment_is_absent_unless_individually_authorized`, `process_exec_does_not_imply_repository_write_and_isolation_binding_is_exact`, pinned-executable tests.
   - Evidence: `implementation/evidence/M1-T04.json`.
   - Runtime capability probes are mandatory; binary presence is not capability proof.
   - Protected credential/controller/system roots remain denied even if nested under the repository root.
   - Action-supplied `PATH` is denied; runner supplies only Controller-approved toolchain `PATH`.
   - No unrestricted-network fallback: the M1 macOS backend admits only the network boundary it can truthfully prove.
   - Required tests/evidence: runtime Seatbelt probe, nested protected-root fixture, PATH-shim fixture, offline network fixture, selective-network request fail-closed fixture.

6. **Representative M1 model qualification**
   - Status: M1-T10 compiler qualification passed on the target machine with exact rendered/schema/output-reserve accounting and current evidence in `implementation/evidence/M1-T10-model-smoke.json`. M1-T07 Controller/edit/deterministic-verification behavior is closed with current evidence in `implementation/evidence/M1-T07.json`, and deterministic checkpoint/restart recovery is closed in `implementation/evidence/M1-T08.json`. Real-Qwen targeted repair plus the combined real-Qwen implementation+repair+restart engineering qualification remain open under M1-T09 and the final M1 engineering packet.
   - Status: **OPEN — required before M1 closure.** Historical M1-T03 short smoke remains valid only for short tool-call viability.
   - Planned proof owners: M1-T10, M1-T07, M1-T08, M1-T09 plus a current real-model full-packet report.
   - Preserve M1-T03 short real tool-call smoke as valid evidence only for short tool-call viability (206 input tokens); do not represent it as an 8k engineering packet.
   - Before M1 closure, exercise representative fully rendered packets with measured total tokens, actual prefill, peak/steady RSS, compressor/swap deltas, a real repository edit, deterministic verification, one bounded repair, and restart/resume.
   - Required evidence is produced by the compiler/controller/repair/restart vertical-slice tasks, not by context-tier loading alone.

## M1-T07 closure update

- M1-T07 is durably complete; current evidence is `implementation/evidence/M1-T07.json` and `BUILD_STATE.json` advances only to M1-T08.
- Current verification includes strict workspace Clippy, 3 Controller unit tests, 18 Controller integration tests, the natural-language compiler→Controller→real local isolated edit→deterministic verifier eval slice, and the full offline workspace suite.
- Revalidated remediation properties include durable action-result semantics, no persisted `ready` bit, Controller-owned compiled model-call ceilings, exact current evidence/dependency bindings, ReadyLease checkpoint/evidence/epoch recomputation before dispatch, and exact preservation of pre-existing staged/unstaged/untracked user work and target file mode.
- M1-T07 does not implement restart/recovery replay or a second repair attempt; those remain M1-T08 and M1-T09 respectively.
- Representative real-model gate 6 remains OPEN; T07 closure must not be represented as the final M1 local-model engineering qualification.

## Product delivery steering

- First product target: web applications and existing-repository engineering work.
- Interfaces: lightweight local dashboard plus CLI, both using the same Controller authority/state.
- Optimization priority: verified success over minimum token use.
- Autonomous local work is allowed within deterministic policy; publication, payments, secret access, and destructive external actions require explicit permission.
- Representative product proof: a local inventory web application with persistent records, validation, create/edit/delete/search, restart durability, browser-flow verification, and setup/run instructions.
- Browser tooling remains optional for generic core and is required only for the web-product profile.
- Product-profile implementation begins only after core M1 closure.

## Evidence discipline

- Historical passing receipts do not prove changed code.
- Each remediated item must cite current tests and current evidence artifacts.
- `BUILD_STATE.json` remains the durable execution pointer.
- Stop at verified release acceptance; do not expand scope indefinitely.
- No publishing, spending, remote pushes, or security weakening are authorized.

## M1-T08 closure update

- M1-T08 is durably complete with current-code evidence in `implementation/evidence/M1-T08.json`; `BUILD_STATE.json` advances only to M1-T09.
- Current verification includes strict workspace Clippy, the state/tools/controller regression suites, the compiler→Controller vertical slice, a 17/17 crash/restart matrix, and the full offline workspace suite. The final independent read-only T08 audit reported no blocker.
- Recovery now uses CAS-verified manifests and explicit trusted checkpoint/re-anchor ancestry; ordered post-checkpoint runtime replay must exactly reproduce authoritative task/attempt state, and repository baseline/plan-validity changes require the latest exact journal binding.
- Pre-mutation recovery is checkpoint-bound to the exact persisted action intent and re-derived action identity, committed edits resume verification only, ambiguous dispatch remains mutation-blocking, and process recovery is fenced by a pre-spawn lease plus PID/PGID/birth identity.
- M1-T08 does not perform a second repair model attempt or recompile a valid plan; that remains M1-T09.
- Representative real-model gate 6 remains **OPEN**. T08 is deterministic restart/recovery closure, not the final real-Qwen implementation+repair+restart engineering qualification.

### M1-T08 post-closure correction — 2026-09-13

- A fresh independent audit after the original T08 closure found two concrete recovery-integrity defects; T09 work was stashed and T08 was corrected before continuing.
- Repository baseline diff content is now self-digest validated in the trusted checkpoint manifest, post-checkpoint durable baseline correlation, and active-plan reconstruction. Older-checkpoint fallback cannot accept tampered `diff_content` paired with an unchanged digest/event and then bypass pre-existing user-hunk protection.
- Recovery now enforces `execution_epoch` monotonicity before reconstruction/reaping/reconciliation using the maximum trusted floor from the checkpoint manifest, durable action authorities, and post-checkpoint Controller epoch events. Direct epoch rollback and fallback below later authoritative epoch both fail closed.
- `crash_resume` expanded from 17 to 20 scenarios and passes 20/20. Strict workspace Clippy, state/tools/controller suites, vertical slice, full offline workspace tests, formatting, and `git diff --check` all pass on the corrected tree.
- The final independent worker-9 read-only re-audit reports no remaining frozen-T08 blocker. `BUILD_STATE.json` remains at M1-T09 and representative real-model gate 6 remains **OPEN**.
