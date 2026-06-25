#!/usr/bin/env python3
"""Intake a sample into a content-addressed store with metadata.

Computes SHA-256, copies the sample to a hash-derived path (``<store>/ab/cd/<sha256>``), writes
a JSON metadata record, and appends a chain-of-custody log entry. Intake is idempotent: the same
bytes always land at the same path. It reads the sample as inert bytes and never executes it.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import shutil
import sys
from pathlib import Path


def intake(path: str, store: str, source: str, case: str, analyst: str) -> dict:
    data = Path(path).read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    store_root = Path(store)
    dest_dir = store_root / sha256[:2] / sha256[2:4]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / sha256
    already = dest.exists()
    if not already:
        shutil.copy2(path, dest)

    record = {
        "sha256": sha256,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "size": len(data),
        "original_name": Path(path).name,
        "source": source,
        "case": case,
        "intake_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "stored_path": str(dest),
    }
    (dest_dir / f"{sha256}.meta.json").write_text(json.dumps(record, indent=2),
                                                  encoding="utf-8")

    custody = store_root / "custody.log"
    entry = (f"{record['intake_utc']}\t{analyst}\tINTAKE\t{sha256}\t"
             f"source={source}\tcase={case}\n")
    with custody.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    record["duplicate"] = already
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sample intake into content-addressed store")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("intake")
    p.add_argument("file")
    p.add_argument("--store", default="./samples")
    p.add_argument("--source", default="unknown")
    p.add_argument("--case", default="")
    p.add_argument("--analyst", default="analyst-ai-pack")
    args = parser.parse_args(argv)
    print(json.dumps(intake(args.file, args.store, args.source, args.case, args.analyst),
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
