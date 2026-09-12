# Sovereign development contract

The implementation authority is the frozen architecture and roadmap under
`output/`.  The workspace is intentionally pinned to Rust 1.89.0 with the
`rustfmt` and `clippy` components.  Runtime functionality must remain local
first; network access during dependency/toolchain acquisition is not a runtime
dependency.

Run all foundation quality gates with:

```sh
./scripts/verify.sh
```

The script executes the roadmap-required formatting, linting and workspace
test gates.  It also finds an already-installed local rustup toolchain when the
user shell has not added `~/.cargo/bin` to `PATH`.

