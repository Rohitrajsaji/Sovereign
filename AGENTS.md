# Sovereign

Local-first software-engineering control plane. The model proposes. The Controller commits. Read [docs/wiki/README.md](docs/wiki/README.md) before changing code.

## Invariants

- Only `crates/sovereign-controller` commits execution state. Chat history is not state.
- Plan revisions are immutable. A model cannot mark work complete.
- A missing receipt after dispatch is `unknown`, not a retry.
- Do not reset user git work, weaken `sandbox-exec`, or start a second local model.
- Rust 1.89, `unsafe_code` forbidden, Clippy pedantic denied. Gate: `./scripts/verify.sh`.

On 2026-09-25 CX-T01 and CX-T02 passed inside `./scripts/verify.sh`. That same run later failed the live-Chrome case `real_chrome_contains_page_js_writes_and_worker_network_before_execution`. See [docs/wiki/15-testing-and-evals.md](docs/wiki/15-testing-and-evals.md). The working tree already has unrelated uncommitted edits. Do not revert or commit them unless asked.

UI gate: `scripts/verify-ui.sh` when `node` exists. Do not use `dangerouslySetInnerHTML`. Untrusted text is a text node. Consumer architecture: [docs/wiki/21-consumer-ui-and-service.md](docs/wiki/21-consumer-ui-and-service.md).

Frozen contracts live under `output/` and `schemas/`. `research/`, `.models/`, and `.tools/` are not product source.
