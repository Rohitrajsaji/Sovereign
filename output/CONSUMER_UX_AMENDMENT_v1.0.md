# Sovereign Consumer UX Amendment v1.0

Date: 2026-09-25
Status: accepted additive profile `local_consumer_v1`. Does not edit `output/implementation-plan.json`, Plan IR, or the stable interface manifest. Adds no execution authority.

## Scope

A loopback web UI and a background execution service inside `sovereign serve --execute`. The Controller remains the only writer of execution state. The UI and HTTP API are clients of `LocalControl` and Controller methods.

Out of scope: signed distribution, auto-update, hardware profiles beyond M1/8 GB, remote access, concurrent execution of more than one project, M7-T01, and M7-T04.

## Tasks

| ID | Depends on | Objective |
| --- | --- | --- |
| CX-T00 | — | This amendment |
| CX-T01 | — | Broker stop proof does not probe a reusable port |
| CX-T02 | — | In-flight model cancellation test survives suite load |
| CX-T03 | CX-T01, CX-T02 | Threaded loopback HTTP server |
| CX-T04 | CX-T03 | Session token, CSRF, CSP |
| CX-T05 | CX-T03 | Single-writer Controller actor and run lock |
| CX-T06 | CX-T03 | Embedded UI assets |
| CX-T07 | CX-T04 | `schemas/control-api-v2.json` contract tests |
| CX-T08 | CX-T05 | Versioned app settings and project index |
| CX-T09 | CX-T08 | Project registry and activation |
| CX-T10 | CX-T05 | Execution service inside `serve --execute` |
| CX-T11 | CX-T10 | Durable goal cancellation |
| CX-T12 | CX-T07 | Read model, journal tail, SSE, artifact and diff reads |
| CX-T13 | CX-T08 | Doctor checks |
| CX-T14 | CX-T13 | Model asset manifest and verification |
| CX-T15 | CX-T10 | LaunchAgent and `sovereign app` |
| CX-T16 | CX-T06, CX-T07 | UI workspace and generated API types |
| CX-T17 | CX-T16 | Design tokens and accessible components |
| CX-T18 | CX-T17, CX-T13, CX-T14 | Onboarding |
| CX-T19 | CX-T17, CX-T09, CX-T10 | Home and projects |
| CX-T20 | CX-T17, CX-T10 | Goal composer and list |
| CX-T21 | CX-T17, CX-T11, CX-T12 | Goal detail |
| CX-T22 | CX-T17, CX-T12 | Approvals and recovery |
| CX-T23 | CX-T17, CX-T13, CX-T15 | Settings, diagnostics, notifications |
| CX-T24 | CX-T18–CX-T23 | E2E, budgets, security negatives |
| CX-T25 | CX-T24 | Ignored real-model consumer acceptance |
| CX-T26 | CX-T24 | Manual UX checklist |
| CX-T27 | CX-T25 | Wiki and user guide |

## Manual UX checklist (CX-T26)

A first-time user, with model files already present, can:

1. Finish onboarding in under 10 minutes.
2. Submit a goal and understand every status without reading logs.
3. Approve or deny one action and see exactly what will run.
4. Recover the same goal after a forced process restart, with no replay of an unknown action.

## Release boundary

Local only. Publication, spending, secret use, and destructive external actions still require an explicit approval. The UI cannot grant a capability.
