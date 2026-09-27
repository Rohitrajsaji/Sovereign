#!/bin/sh
# Callers: phase acceptance. Not part of verify.sh by default.
# API: builds sovereign-e2e-server and runs Playwright against installed Chrome.
# Schema: schemas/control-api-v2.json.
# User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Then complete Playwright/axe E2E.

set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.rustup/toolchains/1.89.0-aarch64-apple-darwin/bin:$PATH"
cd "$root"
cargo build -p sovereign --bin sovereign-e2e-server --features e2e-fixtures
target_dir="${CARGO_TARGET_DIR:-$root/target}"
bin="$target_dir/debug/sovereign-e2e-server"
e2e_home="$(mktemp -d "${TMPDIR:-/tmp}/sovereign-e2e-home.XXXXXX")"
export HOME="$e2e_home"
export SOVEREIGN_STATE_DB="$e2e_home/.sovereign/state.sqlite3"
mkdir -p "$target_dir"
"$bin" >"$target_dir/e2e-server.out" 2>"$target_dir/e2e-server.err" &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$e2e_home"' EXIT
addr=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ -f "$target_dir/e2e-server.out" ]; then
        addr="$(sed -n 's/^e2e-server //p' "$target_dir/e2e-server.out" | head -n 1)"
        if [ -n "$addr" ]; then
            break
        fi
    fi
    sleep 1
done
if [ -z "$addr" ]; then
    echo "e2e-server did not print a bind address" >&2
    cat "$target_dir/e2e-server.err" >&2 || true
    exit 1
fi
export SOVEREIGN_E2E_URL="http://${addr}"
export SOVEREIGN_E2E_TOKEN="e2e-session-token"
cd "$root/apps/sovereign/ui"
if [ ! -d node_modules ]; then
    npm ci
fi
status=0
npx playwright test || status=$?
if [ "$status" -ne 0 ]; then
    # CI keeps these as an artifact too; printing them makes a failure readable from the log.
    echo "--- e2e server log (last 80 lines)" >&2
    tail -n 80 "$target_dir/e2e-server.err" >&2 || true
    for context in test-results/*/error-context.md; do
        [ -f "$context" ] || continue
        echo "--- $context" >&2
        head -n 120 "$context" >&2
    done
fi
exit "$status"
