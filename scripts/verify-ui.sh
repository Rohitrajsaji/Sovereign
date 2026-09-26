#!/bin/sh
# Callers: scripts/verify.sh when node exists.
# API: UI gate — npm ci, gen:api check, typecheck, lint, test, build, gzip budget.
# Schema: schemas/control-api-v2.json via generated.ts.
# User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Add scripts/verify-ui.sh. It runs npm ci, gen:api with a diff check, typecheck, lint, test, and build.

set -eu
cd "$(dirname "$0")/../apps/sovereign/ui"
if ! command -v node >/dev/null 2>&1; then
    echo "verify-ui.sh: node is not installed; skip UI gate" >&2
    exit 0
fi
if [ ! -d node_modules ]; then
    npm ci
fi
npm run gen:api
node scripts/gen-api.mjs --check
npm run typecheck
npm run lint
npm run test
npm run build
test -f src/api/generated.ts
python3 - <<'PY'
from gzip import compress
from pathlib import Path
root = Path("../ui-dist/assets")
total = sum(len(compress(path.read_bytes(), compresslevel=9)) for path in root.glob("*.js"))
limit = 250 * 1024
if total > limit:
    raise SystemExit(f"ui-dist JS gzip {total} exceeds {limit}")
print(f"ui-dist JS gzip {total} bytes")
js = chr(10).join(path.read_text() for path in root.glob("*.js"))
for forbidden in ("/v1/actions", "/v1/state/"):
    if forbidden in js:
        raise SystemExit(f"SPA contains forbidden {forbidden}")
if "/v2/" not in js:
    raise SystemExit("SPA does not call /v2 routes")
src = Path("src")
for path in src.rglob("*.tsx"):
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        if "dangerouslySetInnerHTML" in line:
            raise SystemExit(f"{path} assigns inner HTML")
print("SPA route scan passed")
PY
