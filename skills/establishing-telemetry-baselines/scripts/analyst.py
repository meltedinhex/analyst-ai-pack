#!/usr/bin/env python3
"""Build frequency baselines from telemetry and flag rare/first-seen values.

`baseline` computes per-value counts and frequencies for a chosen field from historical telemetry
and writes a JSON baseline. `compare` scores new telemetry against that baseline, flagging
first-seen and rare values. Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path


def _rows(path: str):
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if path.lower().endswith(".json") or text.lstrip()[:1] in "{[":
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    else:
        for row in csv.DictReader(text.splitlines()):
            yield row


def _values(path: str, field: str) -> list[str]:
    out = []
    for row in _rows(path):
        val = row.get(field)
        if val:
            out.append(str(val).lower())
    return out


def baseline(path: str, field: str, out: str) -> dict:
    counts = Counter(_values(path, field))
    total = sum(counts.values())
    data = {"field": field, "total": total, "counts": dict(counts)}
    Path(out).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"baseline_file": out, "distinct_values": len(counts), "total_events": total}


def compare(path: str, field: str, baseline_file: str, rarity: float) -> dict:
    base = json.loads(Path(baseline_file).read_text(encoding="utf-8-sig"))
    counts = base.get("counts", {})
    total = base.get("total", 0) or 1
    current = Counter(_values(path, field))
    first_seen = sorted(v for v in current if v not in counts)
    rare = sorted(v for v in current
                  if v in counts and (counts[v] / total) < rarity)
    return {
        "first_seen_values": first_seen,
        "rare_values": rare,
        "rarity_threshold": rarity,
        "current_distinct": len(current),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Telemetry baselining")
    sub = parser.add_subparsers(dest="cmd", required=True)
    pb = sub.add_parser("baseline")
    pb.add_argument("history")
    pb.add_argument("--field", required=True)
    pb.add_argument("--out", default="baseline.json")
    pc = sub.add_parser("compare")
    pc.add_argument("new")
    pc.add_argument("--field", required=True)
    pc.add_argument("--baseline", required=True)
    pc.add_argument("--rarity", type=float, default=0.01)
    args = parser.parse_args(argv)
    if args.cmd == "baseline":
        print(json.dumps(baseline(args.history, args.field, args.out), indent=2))
    else:
        print(json.dumps(compare(args.new, args.field, args.baseline, args.rarity), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
