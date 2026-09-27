#!/bin/sh
# Builds Sovereign from this checkout and installs it the same way a release is installed:
# ~/.sovereign/versions/dev-<commit>, ~/.local/bin/sovereign, the background service, and the
# app in the browser. The model and its runner are downloaded by the app's first-run setup.
#
# Usage: scripts/install-from-source.sh
# Needs: macOS on Apple silicon and the Rust toolchain from rust-toolchain.toml.
set -eu

[ "$(uname -s)" = "Darwin" ] || { echo "Sovereign runs on macOS." >&2; exit 1; }
command -v cargo >/dev/null 2>&1 || {
    echo "Install Rust first: https://rustup.rs" >&2
    exit 1
}

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
version="dev-$commit"

echo "Building Sovereign ($version). The first build takes a few minutes."
cargo build --release --locked -p sovereign --bin sovereign

destination="$HOME/.sovereign/versions/$version"
rm -rf "$destination"
mkdir -p "$destination/bin"
cp target/release/sovereign "$destination/bin/sovereign"
printf '%s\n' "$version" >"$destination/VERSION"

# `sovereign app` compares this checkout with the running version and says when to reinstall.
printf '%s\n' "$repo" >"$HOME/.sovereign/source-checkout"
"$destination/bin/sovereign" self-install
"$destination/bin/sovereign" app >/dev/null 2>&1 || true
echo "Sovereign is open in your browser. Next time, type: sovereign"
