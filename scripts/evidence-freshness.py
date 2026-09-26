#!/usr/bin/env python3
"""Report which closure evidence still matches the working tree.

Every `implementation/evidence/**/*.json` file may bind source files through
`source_hashes` maps (`{"path": "sha256:<hex>"}`), at any depth. This script
re-hashes those files and classifies each evidence file:

- fresh:   every bound file still has the recorded digest
- stale:   at least one bound file changed
- missing: at least one bound file no longer exists
- unbound: the file binds no source hashes, so freshness cannot be checked

Usage:
    scripts/evidence-freshness.py [--strict] [--json] [--verbose] [EVIDENCE ...]

`--strict` exits 1 when any evidence file is stale or missing. The default
exit code is 0, because stale evidence is expected after later commits and is
a review signal, not a build failure. Reads files only and writes nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = ROOT / "implementation" / "evidence"


def collect_source_hashes(value: object, found: dict[str, str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "source_hashes" and isinstance(child, dict):
                for path, digest in child.items():
                    if isinstance(path, str) and isinstance(digest, str):
                        found.setdefault(path, digest)
            else:
                collect_source_hashes(child, found)
    elif isinstance(value, list):
        for child in value:
            collect_source_hashes(child, found)


def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def classify(evidence: Path) -> dict[str, object]:
    try:
        document = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"evidence": str(evidence.relative_to(ROOT)), "status": "unreadable", "error": str(error)}
    bound: dict[str, str] = {}
    collect_source_hashes(document, bound)
    result: dict[str, object] = {
        "evidence": str(evidence.relative_to(ROOT)),
        "task": document.get("task") if isinstance(document, dict) else None,
        "bound_files": len(bound),
        "changed": [],
        "missing": [],
    }
    if not bound:
        result["status"] = "unbound"
        return result
    for relative, recorded in sorted(bound.items()):
        target = (ROOT / relative).resolve()
        if ROOT not in target.parents and target != ROOT:
            result["missing"].append(relative)  # type: ignore[union-attr]
            continue
        if not target.is_file():
            result["missing"].append(relative)  # type: ignore[union-attr]
            continue
        if file_digest(target) != recorded.lower():
            result["changed"].append(relative)  # type: ignore[union-attr]
    if result["missing"]:
        result["status"] = "missing"
    elif result["changed"]:
        result["status"] = "stale"
    else:
        result["status"] = "fresh"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("evidence", nargs="*", type=Path, help="evidence files (default: all)")
    parser.add_argument("--strict", action="store_true", help="exit 1 on stale or missing evidence")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument("--verbose", action="store_true", help="list changed and missing files")
    args = parser.parse_args()

    files = [path.resolve() for path in args.evidence] or sorted(EVIDENCE_DIR.rglob("*.json"))
    results = [classify(path) for path in files]
    counts: dict[str, int] = {}
    for result in results:
        status = str(result["status"])
        counts[status] = counts.get(status, 0) + 1

    if args.json:
        print(json.dumps({"schema_version": 1, "counts": counts, "evidence": results}, indent=2))
    else:
        width = max((len(str(result["evidence"])) for result in results), default=0)
        for result in results:
            line = f"{str(result['status']):<10} {str(result['evidence']):<{width}}"
            if result["status"] in ("stale", "missing"):
                line += f"  changed={len(result['changed'])} missing={len(result['missing'])}"  # type: ignore[arg-type]
            print(line)
            if args.verbose:
                for path in result.get("changed", []):  # type: ignore[union-attr]
                    print(f"    changed  {path}")
                for path in result.get("missing", []):  # type: ignore[union-attr]
                    print(f"    missing  {path}")
        print("summary: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))

    if args.strict and (counts.get("stale") or counts.get("missing") or counts.get("unreadable")):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
