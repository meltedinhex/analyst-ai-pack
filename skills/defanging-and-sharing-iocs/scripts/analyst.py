#!/usr/bin/env python3
"""Defang and structure indicators of compromise for safe sharing.

Reads a newline-delimited indicator list, classifies each (url, domain, ipv4, email, hash),
defangs network indicators so they cannot be clicked or resolved, deduplicates, and emits a
structured JSON record. It processes text only; it performs no network lookups.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RE_URL = re.compile(r"^https?://", re.I)
RE_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
RE_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)
RE_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)


def classify(ind: str) -> str:
    if RE_HASH.match(ind):
        return "hash"
    if RE_URL.match(ind):
        return "url"
    if RE_EMAIL.match(ind):
        return "email"
    if RE_IPV4.match(ind):
        return "ipv4"
    if RE_DOMAIN.match(ind):
        return "domain"
    return "unknown"


def defang(ind: str, kind: str) -> str:
    if kind == "hash":
        return ind  # hashes are inert; no defang needed
    out = ind.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace("@", "[at]")
    # defang only the last few dots minimally but consistently: all dots bracketed
    out = out.replace(".", "[.]")
    return out


def process(lines: list[str]) -> dict:
    seen = set()
    records = []
    for raw in lines:
        ind = raw.strip()
        if not ind or ind in seen:
            continue
        seen.add(ind)
        kind = classify(ind)
        records.append({"type": kind, "value": ind, "defanged": defang(ind, kind)})
    return {"count": len(records), "indicators": records}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Defang and structure IOCs")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("defang")
    p.add_argument("file", help="newline-delimited indicator list")
    args = parser.parse_args(argv)
    lines = Path(args.file).read_text(encoding="utf-8-sig", errors="replace").splitlines()
    print(json.dumps(process(lines), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
