# Environment and commands

> Snapshot: HEAD `d266399` (2026-09-24) plus uncommitted work (+3440/−604 across 34 files, observed 2026-09-25).

## Toolchain

[rust-toolchain.toml](../../rust-toolchain.toml): channel `1.89.0`, profile `minimal`, components `clippy` and `rustfmt`. [DEVELOPMENT.md](../../DEVELOPMENT.md) says the same, and also contains shell residue. `scripts/verify.sh` prepends `~/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin` when `cargo` is not on `PATH`.

Workspace lints in [Cargo.toml](../../Cargo.toml): `unsafe_code = forbid`, `unused_must_use = deny`, Clippy `all`, `pedantic`, `unwrap_used`, and `expect_used` denied.

Pinned crates: `rusqlite` 0.37 with `bundled`, `jsonschema` 0.56, `tree-sitter` 0.25.10, `tree-sitter-rust` 0.24.0, `tree-sitter-typescript` 0.23.2.

## Binaries the product expects

| Binary | Role |
| --- | --- |
| `/usr/bin/git` | Only Git Sovereign will run (`SYSTEM_GIT_PATH`) |
| `/usr/bin/python3` | Pinned by the production runner |
| `/usr/bin/sandbox-exec` | macOS isolation. Missing means deny |
| `llama-server` | Local model. Path from `SOVEREIGN_MODEL_RUNTIME` |
| GGUF file | Default on this machine: `.models/Qwen3-4B-Q4_K_M.gguf` via `SOVEREIGN_MODEL_PATH` |
| Google Chrome | Optional. `SOVEREIGN_CHROME_EXECUTABLE` or the standard app path |
| `node` | Optional. `SOVEREIGN_NODE_EXECUTABLE` |
| Postgres | Not started by Sovereign. Live tests expect Homebrew `postgresql@16` and `SOVEREIGN_TEST_LIVE_POSTGRES_OID` |
| `/bin/sh` | Used to set up the CDP pipe |

Network during `cargo` fetch is a build-time concern. Runtime must stay useful offline after models and tools are present.

## Commands

```sh
./scripts/verify.sh
./scripts/verify-ui.sh
./scripts/e2e.sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p sovereign-controller --lib
cargo test -p sovereign-eval --test crash_resume
cargo run -p sovereign -- doctor
cargo run -p sovereign -- goal "replace the save label"
cargo run -p sovereign -- status
cargo run -p sovereign -- serve 127.0.0.1:7777
cargo run -p sovereign -- run --once
```

`eval` accepts only:

```sh
cargo run -p sovereign -- eval --profile m1-8gb --offline
cargo run -p sovereign -- eval --suite release --profile m1-8gb --offline
```

Ignored real-model tests (not part of `verify.sh`):

```sh
SOVEREIGN_MODEL_RUNTIME=.tools/llama-b10516/llama-b10516/llama-server \
SOVEREIGN_MODEL_PATH=.models/Qwen3-4B-Q4_K_M.gguf \
cargo test -p sovereign-eval --test m1_real_qualification -- --ignored
```

Confirm the llama-server path on disk before using that command. This session did not run ignored tests.

## Environment variables

| Name | Used for |
| --- | --- |
| `SOVEREIGN_STATE_DB` | State database path |
| `SOVEREIGN_PROJECT_CONFIG` | Project configuration JSON |
| `SOVEREIGN_MODEL_RUNTIME` | `llama-server` executable |
| `SOVEREIGN_MODEL_PATH` | GGUF path |
| `SOVEREIGN_MODEL_NAME` | Reported model name |
| `SOVEREIGN_MODEL_PARAMETER_CLASS` | Smoke report |
| `SOVEREIGN_MODEL_QUANTIZATION` | Smoke report |
| `SOVEREIGN_MODEL_SMOKE_REPORT` | Smoke JSON output path |
| `SOVEREIGN_MODEL_EXTRA_ARGS_JSON` | Extra llama-server args |
| `SOVEREIGN_NODE_EXECUTABLE` | Optional Node |
| `SOVEREIGN_CHROME_EXECUTABLE` | Optional Chrome |
| `SOVEREIGN_SCRAPLING_PYTHON` | Optional Scrapling interpreter |
| `SOVEREIGN_T10_SMOKE_REPORT` | Compiler real-smoke report |
| `SOVEREIGN_M1_QUAL_REPORT` | M1 qualification report |
| `SOVEREIGN_TEST_LIVE_POSTGRES_OID` | Live Postgres tests |
| `SOVEREIGN_SECRET_FILE` | Ephemeral secret file handoff |
| `SOVEREIGN_IDNA_UTS46_HELPER` | Build-time path to the IDNA helper |
| `SOVEREIGN_RECOVERY_TEST_PAUSE_AT`, `SOVEREIGN_RECOVERY_TEST_PAUSE_MARKER` | Recovery test hook |
| `SOVEREIGN_GOAL_CRASH_*` | Goal-driver kill tests |
| `SOVEREIGN_PD_T05_V4_CRASH_*` | PD-T05 crash tests |
| `SOVEREIGN_M6_T06_ROLLBACK_*` | Rollback crash tests |
| `SOVEREIGN_CRASH_CHILD_*` | Eval crash-resume children |
| `SOVEREIGN_PROJECTION_CRASH_CHILD_DB` | Memory projection crash child |
| `SOVEREIGN_REPO_PATH_SHIM_*` | Worktree path-shim tests |
| `SOVEREIGN_OFFLINE_DEPENDENCY_CRASH_*` | Offline dependency crash tests |
| `SOVEREIGN_TEST_BROWSER_COMMAND_LOG` | Browser command log in tests |

`HOME`, `PATH`, and `CARGO` are ordinary process environment. Production children start from a cleared environment. Do not export Git or credential variables and expect the child to see them.

## Git hygiene

Ignored: `target/`, `research/`, `.models/`, `.tools/`, `.env`, `*.sqlite`, `*.sqlite3`, WAL sidecars. Do not commit them. Do not commit the detached worktree under `.kilo/`.

The branch observed on 2026-09-25 was `main`, tracking `origin/main`, with 34 modified files uncommitted. Do not commit those unless the user asks.
