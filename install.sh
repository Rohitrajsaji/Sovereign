#!/bin/sh
# Installs Sovereign on a Mac with Apple silicon:
#
#   curl -fsSL https://raw.githubusercontent.com/Rohitrajsaji/Sovereign/main/install.sh | sh
#
# Downloads the latest release and its SHA256SUMS over HTTPS, refuses a download whose
# checksum does not match, unpacks it to ~/.sovereign/versions/<version>, and hands over to
# `sovereign self-install`, which links ~/.local/bin/sovereign, starts the background
# service, and opens Sovereign in the browser. Nothing is installed system-wide and no
# password is needed. `sovereign uninstall` removes it.
set -eu

REPOSITORY="${SOVEREIGN_REPOSITORY:-Rohitrajsaji/Sovereign}"
BASE_URL="${SOVEREIGN_RELEASE_BASE_URL:-https://github.com/$REPOSITORY/releases/latest/download}"
ASSET="sovereign-macos-arm64.tar.gz"
ROOT_DIR="sovereign-macos-arm64"
INSTALL_ROOT="$HOME/.sovereign"

say() { printf '%s\n' "$*"; }
fail() {
    printf 'Sovereign could not be installed: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "Sovereign runs on macOS."
# Apple silicon, including a terminal running under Rosetta.
if [ "$(uname -m)" != "arm64" ] && [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" != "1" ]; then
    fail "Sovereign needs a Mac with Apple silicon (M1 or later)."
fi
case "$BASE_URL" in
    https://*) ;;
    *) fail "the release address must use https." ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

fetch() {
    /usr/bin/curl --fail --location --silent --show-error \
        --proto '=https' --proto-redir '=https' --max-redirs 10 \
        --connect-timeout 30 --output "$2" "$1" ||
        fail "could not download $1. Check your internet connection and try again."
}

say "Downloading Sovereign..."
fetch "$BASE_URL/SHA256SUMS" "$work/SHA256SUMS"
fetch "$BASE_URL/$ASSET" "$work/$ASSET"

expected="$(awk -v asset="$ASSET" '{ name = $2; sub(/^\*/, "", name); if (name == asset) print tolower($1) }' "$work/SHA256SUMS")"
[ -n "$expected" ] || fail "the release does not list a checksum for $ASSET."
actual="$(/usr/bin/shasum -a 256 "$work/$ASSET" | awk '{ print tolower($1) }')"
[ "$expected" = "$actual" ] || fail "the download did not match its checksum. Try again."

mkdir -p "$INSTALL_ROOT/versions"
staging="$INSTALL_ROOT/versions/.staging-$$"
rm -rf "$staging"
mkdir -p "$staging"
/usr/bin/tar -xzf "$work/$ASSET" -C "$staging" || fail "could not unpack the download."
unpacked="$staging/$ROOT_DIR"
[ -x "$unpacked/bin/sovereign" ] || fail "the download is incomplete."
version="$(tr -d ' \n\r\t' <"$unpacked/VERSION")"
case "$version" in
    "" | .* | *[!A-Za-z0-9._-]*) fail "the release has an invalid version." ;;
esac
destination="$INSTALL_ROOT/versions/$version"
rm -rf "$destination"
mv "$unpacked" "$destination"
rm -rf "$staging"

say "Setting up Sovereign $version..."
"$destination/bin/sovereign" self-install
"$destination/bin/sovereign" app >/dev/null 2>&1 || true
say "Sovereign is open in your browser. Next time, type: sovereign"
