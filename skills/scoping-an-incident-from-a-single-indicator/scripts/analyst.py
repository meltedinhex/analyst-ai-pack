#!/usr/bin/env python3
"""Pivot from a seed indicator across event records to scope an incident.

Reads a JSON list of normalized events (each may contain hosts, accounts, and indicator values)
and performs breadth-first pivoting from a seed value: any event sharing a known entity pulls in
its other entities, expanding the affected set. Produces the involved entities and a sorted
timeline. It reads local JSON only; it touches no live systems.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ENTITY_FIELDS = ["host", "account", "indicator", "src_ip", "dst_ip", "domain", "sha256"]


def _entities(ev: dict) -> set:
    vals = set()
    for f in ENTITY_FIELDS:
        v = ev.get(f)
        if isinstance(v, list):
            vals.update(str(x) for x in v)
        elif v:
            vals.add(str(v))
    return vals


def scope(events: list[dict], seed: str) -> dict:
    known = {seed}
    included_idx = set()
    changed = True
    while changed:
        changed = False
        for i, ev in enumerate(events):
            if i in included_idx:
                continue
            ents = _entities(ev)
            if ents & known:
                included_idx.add(i)
                new = ents - known
                if new:
                    known |= new
                    changed = True

    involved = [events[i] for i in sorted(included_idx)]
    timeline = sorted(involved, key=lambda e: e.get("ts", 0))
    hosts = sorted({str(e["host"]) for e in involved if e.get("host")})
    accounts = sorted({str(e["account"]) for e in involved if e.get("account")})
    return {
        "seed": seed,
        "entities_discovered": sorted(known),
        "affected_hosts": hosts,
        "affected_accounts": accounts,
        "event_count": len(involved),
        "earliest_event": timeline[0] if timeline else None,
        "timeline": timeline,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scope an incident from one indicator")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scope")
    p.add_argument("file", help="JSON list of normalized events")
    p.add_argument("--seed", required=True, help="seed indicator value")
    args = parser.parse_args(argv)
    events = json.loads(Path(args.file).read_text(encoding="utf-8"))
    print(json.dumps(scope(events, args.seed), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
