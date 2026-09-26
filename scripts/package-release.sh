#!/bin/sh
# Packages a macOS arm64 release: the `sovereign` binary, the pinned llama.cpp runner, and a
# VERSION file, as sovereign-macos-arm64.tar.gz plus SHA256SUMS.
#
# Usage: scripts/package-release.sh <version> <path/to/sovereign> <output-dir>
# Callers: .github/workflows/release.yml. Pins: apps/sovereign/assets/model-manifest-v2.json.
set -eu

version="$1"
binary="$2"
output="$3"
case "$version" in
    "" | .* | *[!A-Za-z0-9._-]*) echo "invalid version: $version" >&2; exit 2 ;;
esac
[ -x "$binary" ] || { echo "missing binary: $binary" >&2; exit 2; }

repo="$(cd "$(dirname "$0")/.." && pwd)"
manifest="$repo/apps/sovereign/assets/model-manifest-v2.json"
pin() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runtime"][sys.argv[2]])' "$manifest" "$1"; }
archive_url="$(pin archive_url)"
archive_sha256="$(pin archive_sha256)"
executable_name="$(pin executable_name)"
executable_sha256="$(pin executable_sha256)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

echo "Fetching the pinned runner $archive_url"
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    --output "$work/runtime.tar.gz" "$archive_url"
actual="$(shasum -a 256 "$work/runtime.tar.gz" | awk '{ print $1 }')"
[ "$actual" = "$archive_sha256" ] || { echo "runner archive checksum mismatch: $actual" >&2; exit 1; }
mkdir -p "$work/runtime"
tar -xzf "$work/runtime.tar.gz" -C "$work/runtime"

runner=""
for candidate in $(find "$work/runtime" -type f -name "$executable_name"); do
    if [ "$(shasum -a 256 "$candidate" | awk '{ print $1 }')" = "$executable_sha256" ]; then
        runner="$candidate"
        break
    fi
done
[ -n "$runner" ] || { echo "no $executable_name matches the pinned checksum" >&2; exit 1; }

stage="$work/stage/sovereign-macos-arm64"
mkdir -p "$stage/bin" "$stage/libexec/llama"
cp "$binary" "$stage/bin/sovereign"
chmod 0755 "$stage/bin/sovereign"
# The runner loads its libraries from its own folder, so the whole folder ships.
cp -R "$(dirname "$runner")/." "$stage/libexec/llama/"
printf '%s\n' "$version" >"$stage/VERSION"

mkdir -p "$output"
tar -czf "$output/sovereign-macos-arm64.tar.gz" -C "$work/stage" sovereign-macos-arm64
(cd "$output" && shasum -a 256 sovereign-macos-arm64.tar.gz >SHA256SUMS)
cat "$output/SHA256SUMS"
