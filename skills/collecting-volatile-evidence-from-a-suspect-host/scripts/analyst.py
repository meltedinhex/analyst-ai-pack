#!/usr/bin/env python3
"""Build an integrity manifest for a volatile-evidence collection.

Walks a collection directory, hashes each artifact (SHA-256), records size and modification
time, and emits a manifest ordered to reflect the order of volatility when artifacts are named
with a numeric prefix. It only reads already-collected files; it does not touch a live host.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path

# Suggested order-of-volatility naming prefixes (RFC 3227)
VOLATILITY_ORDER = [
    "01-memory", "02-network", "03-processes", "04-users", "05-handles", "06-disk",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(collection: str, case: str, host: str) -> dict:
    root = Path(collection)
    artifacts = []
    for f in sorted(root.rglob("*")):
        if f.is_file() and f.name != "manifest.json":
            stat = f.stat()
            artifacts.append({
                "path": str(f.relative_to(root)),
                "sha256": _sha256(f),
                "size": stat.st_size,
                "mtime_utc": _dt.datetime.fromtimestamp(
                    stat.st_mtime, _dt.timezone.utc).isoformat(),
            })
    man = {
        "case": case,
        "host": host,
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "suggested_volatility_order": VOLATILITY_ORDER,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }
    (root / "manifest.json").write_text(json.dumps(man, indent=2), encoding="utf-8")
    return man


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Volatile evidence manifest")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("manifest")
    p.add_argument("collection", help="directory of collected artifacts")
    p.add_argument("--case", default="")
    p.add_argument("--host", default="")
    args = parser.parse_args(argv)
    print(json.dumps(manifest(args.collection, args.case, args.host), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
