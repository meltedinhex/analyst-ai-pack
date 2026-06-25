#!/usr/bin/env python3
"""Plan passive enrichment lookups for a set of indicators.

Reads a JSON object of typed indicators and maps each to appropriate passive enrichment sources,
flagging operational-security cautions (e.g., do not actively resolve). It produces a lookup
plan only; it performs no network requests itself, keeping enrichment opsec-safe by design.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SOURCE_MAP = {
    "hashes": ["sample/AV database (passive)", "sandbox report history"],
    "domains": ["passive DNS", "WHOIS/registration", "domain reputation"],
    "ipv4": ["ASN/geo lookup", "passive DNS (reverse)", "IP reputation"],
    "urls": ["URL reputation", "sandbox URL history"],
    "emails": ["breach/registration data", "phishing reputation"],
}

OPSEC = {
    "domains": "do NOT resolve from your own network; use passive DNS",
    "urls": "do NOT visit; use passive URL intel/sandbox history",
    "ipv4": "avoid active scanning that reveals your interest",
    "hashes": "do not upload sensitive samples to public sandboxes without authorization",
}


def plan(indicators: dict) -> dict:
    out = []
    for kind, values in indicators.items():
        if not values:
            continue
        out.append({
            "type": kind,
            "count": len(values),
            "sources": SOURCE_MAP.get(kind, ["(no mapped source)"]),
            "opsec": OPSEC.get(kind, "use passive sources where possible"),
        })
    return {"lookup_plan": out,
            "principle": "passive enrichment only; corroborate across independent sources"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan IOC enrichment lookups")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("file", help="JSON object of typed indicators")
    args = parser.parse_args(argv)
    raw = json.loads(Path(args.file).read_text(encoding="utf-8"))
    indicators = raw.get("indicators", raw)
    print(json.dumps(plan(indicators), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
