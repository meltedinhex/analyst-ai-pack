#!/usr/bin/env python3
"""Summarize a Procmon-style CSV operation log into a behavioral profile.

Reads a CSV export (Process Monitor "Save as CSV") with at least Process Name, Operation, Path,
and Detail columns. Categorizes operations, reconstructs the process tree from Process Create
events, and highlights persistence-relevant writes. Parses logs only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter

PERSIST_HINTS = ["\\run", "\\runonce", "currentversion\\run", "\\services\\", "startup"]
LOLBINS = ["powershell", "rundll32", "mshta", "regsvr32", "wscript", "cscript", "cmd.exe",
           "certutil", "bitsadmin"]
RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _category(op: str) -> str:
    op = op.lower()
    if "process" in op or "thread" in op:
        return "process_thread"
    if "reg" in op:
        return "registry"
    if "tcp" in op or "udp" in op or "connect" in op:
        return "network"
    if "file" in op or "create" in op or "write" in op or "read" in op:
        return "file"
    return "other"


def summarize(path: str) -> dict:
    cats: Counter = Counter()
    children = []
    persistence = []
    urls = set()
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            op = row.get("Operation", "")
            target = row.get("Path", "")
            detail = row.get("Detail", "")
            cats[_category(op)] += 1
            if op.lower().startswith("process create"):
                children.append({"parent": row.get("Process Name", ""), "detail": detail})
            low = target.lower()
            if any(h in low for h in PERSIST_HINTS) and "write" in op.lower():
                persistence.append({"op": op, "path": target})
            for u in RE_URL.findall(detail) + RE_URL.findall(target):
                urls.add(u)
    return {
        "operation_categories": dict(cats),
        "process_creates": children[:50],
        "lolbin_children": sorted({b for c in children for b in LOLBINS
                                   if b in c["detail"].lower()}),
        "persistence_writes": persistence[:50],
        "urls": sorted(u.replace("http", "hxxp").replace(".", "[.]") for u in urls),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize Procmon CSV behavior")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("summarize")
    p.add_argument("csv")
    args = parser.parse_args(argv)
    print(json.dumps(summarize(args.csv), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
