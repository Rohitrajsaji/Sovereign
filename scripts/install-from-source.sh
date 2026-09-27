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
staging="$HOME/.sovereign/versions/.staging-$version-$$"
aside="$HOME/.sovereign/versions/.replaced-$version-$$"
rm -rf "$staging" "$aside"
mkdir -p "$staging/bin"
cp target/release/sovereign "$staging/bin/sovereign"
printf '%s\n' "$version" >"$staging/VERSION"
# Swap the new build in; the old copy is moved aside first, so a complete version is always on disk.
if [ -e "$destination" ]; then mv "$destination" "$aside"; fi
if ! mv "$staging" "$destination"; then
    if [ -e "$aside" ]; then mv "$aside" "$destination"; fi
    echo "Could not install the new build." >&2
    exit 1
fi
rm -rf "$aside"

# `sovereign app` compares this checkout with the running version and says when to reinstall.
printf '%s\n' "$repo" >"$HOME/.sovereign/source-checkout"
"$destination/bin/sovereign" self-install
"$destination/bin/sovereign" app >/dev/null 2>&1 || true
echo "Sovereign is open in your browser. Next time, type: sovereign"
