#!/bin/sh
set -eu

if ! command -v cargo >/dev/null 2>&1; then
    toolchain_bin="$HOME/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin"
    if [ ! -x "$toolchain_bin/cargo" ]; then
        toolchain_bin="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin"
    fi
    if [ ! -x "$toolchain_bin/cargo" ]; then
        echo "cargo not found; install the pinned Rust toolchain from rust-toolchain.toml" >&2
        exit 127
    fi
    PATH="$toolchain_bin:$PATH"
    export PATH
fi

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

if command -v node >/dev/null 2>&1; then
    "$(dirname "$0")/verify-ui.sh"
else
    echo "verify.sh: node is not installed; skipping UI gate" >&2
fi
