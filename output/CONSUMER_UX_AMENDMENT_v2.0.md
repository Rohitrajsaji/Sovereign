# Sovereign Consumer UX Amendment v2.0

Date: 2026-09-26
Status: accepted additive profile `local_consumer_v2`, approved by the owner on 2026-09-26. Builds on `CONSUMER_UX_AMENDMENT_v1.0.md`. Does not edit `output/implementation-plan.json`, Plan IR, or the stable interface manifest. Adds no execution authority: the Controller remains the only writer of execution state, and the UI cannot grant a capability.

## Audience

People who cannot code, building and changing small apps in a folder on their Mac, with no developer help.

## Owner decisions (2026-09-26)

| Topic | Decision |
| --- | --- |
| Platforms | macOS on Apple Silicon first. Linux later. No Intel build. |
| Install | `curl -fsSL https://raw.githubusercontent.com/Rohitrajsaji/Sovereign/main/install.sh \| sh`, prebuilt binaries on GitHub Releases. No App Store, no Developer ID signing. |
| Model | Downloaded on first run, chosen by hardware (RAM tier). Built-in llama.cpp only; no Ollama or LM Studio. |
| Projects | Invisible git: Sovereign creates or adopts a folder, keeps version history, applies verified results, and offers one-click Undo. |
| UI | Chat-style project workspace with a live preview and file panel. |
| Process | This amendment, then milestone pull requests. |

## Changes to v1.0 scope

v1.0 put signed distribution and auto-update out of scope. v2.0 adds unsigned GitHub Releases distribution with a checksum-verified installer and an explicit `sovereign update`. Signed or notarized distribution stays out of scope.

v1.0 limited hardware to M1/8 GB. v2.0 adds RAM tiers for Apple Silicon Macs. Every tier keeps one resident model, measured admission, and the M1/8 GB profile's ceilings as the floor profile. A larger tier is a new frozen profile object, never an edit of `HardwareProfileV1::m1_8gb`.

## Invariants kept

- Only the Controller commits execution state. HTTP reads use read-only state handles.
- Plan revisions are immutable. The model cannot mark work complete.
- A missing receipt after dispatch is `unknown`, not a retry.
- `sandbox-exec` or deny. Linux support will need its own isolation backend with equal guarantees before it runs anything.
- Sovereign never resets or overwrites pre-existing user work. Landing results and Undo add commits; they never rewrite history. Undo refuses when the user changed the same files afterwards.
- One local model at a time.
- Untrusted text (repository content, model output, previewed apps) is rendered as text or inside a sandboxed, cookie-less origin.

## Tasks

| ID | Depends on | Objective |
| --- | --- | --- |
| CX2-T00 | — | This amendment |
| CX2-T01 | — | HTTP reads never wait on the Controller actor |
| CX2-T02 | CX2-T01 | Commands are acknowledged at once; cancel and pause interrupt in-flight work at a safe point |
| CX2-T03 | — | Goals reach a terminal state: failed (compile failure, budget exhausted, terminal task failure) and cancelled (active goals); the queue always advances |
| CX2-T04 | CX2-T03 | Real progress: phase, step x of y, and percent derived from durable state |
| CX2-T05 | CX2-T01 | Per-goal activity projection |
| CX2-T06 | — | Create a project or adopt a folder through the native macOS folder dialog; invisible git setup |
| CX2-T07 | CX2-T06 | Land a completed goal's verified change sets in the project folder as one commit |
| CX2-T08 | CX2-T07 | One-click Undo of the last landed goal |
| CX2-T09 | CX2-T06 | Starter scaffold so a new, empty project has something the verifier can run |
| CX2-T10 | — | Hardware detection and a RAM-tiered model catalog (manifest v2) |
| CX2-T11 | CX2-T10 | Resumable, checksum-verified model download with progress |
| CX2-T12 | — | Apple Command Line Tools detection with guided install |
| CX2-T13 | — | `install.sh`, `sovereign` opens the app, `sovereign update`, `sovereign uninstall` |
| CX2-T14 | CX2-T13 | Release workflow: tagged macOS arm64 tarball with `llama-server`, checksums |
| CX2-T15 | CX2-T01–T05 | Design system: tokens, type, components, light and dark |
| CX2-T16 | CX2-T15 | App shell: projects sidebar, conversation, side panel |
| CX2-T17 | CX2-T16 | Conversation: requests, plain-language progress, inline approvals, results with Undo |
| CX2-T18 | CX2-T16 | Live preview on a separate cookie-less loopback origin in a sandboxed iframe; file browser |
| CX2-T19 | CX2-T11, CX2-T12, CX2-T16 | Three-step onboarding with no jargon |
| CX2-T20 | CX2-T16 | Settings, Help, and an Advanced area for technical detail |
| CX2-T21 | CX2-T17–T20 | End-to-end tests of the full journey; accessibility; performance budget |
| CX2-T22 | CX2-T21 | Owner-run acceptance on an Apple Silicon Mac with the real model |
| CX2-T23 | CX2-T21 | README quickstart, user guide, troubleshooting |

## Acceptance (CX2-T22)

On a clean Apple Silicon Mac with no developer tools preinstalled, a person who cannot code can:

1. Install with one command and open Sovereign without Terminal afterwards.
2. Finish setup, including the model download, following only on-screen instructions.
3. Create a project, ask for a small app, watch plain-language progress, and see the result in the preview.
4. Cancel a request and see it stop. A later request then runs.
5. See a failed request explained in plain words. A later request then runs.
6. Undo a completed request and see the folder return to its previous state.

## Release boundary

Local only. Publication, spending, secret use, and destructive external actions still require an explicit approval, now worded in plain language. The UI cannot grant a capability.
