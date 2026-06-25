#!/usr/bin/env python3
"""Pivot on a seed IOC set across log records to expand an investigation.

Matches log rows containing any seed IOC, then reports co-occurring hosts, the time range, and new
indicators (not in the seed set) ranked by co-occurrence count. Reads seeds (one per line, plain or
defanged) and logs (CSV/JSON). Parses data only; executes nothing; defangs output indicators.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
RE_HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _refang(s: str) -> str:
    return s.replace("[.]", ".").replace("hxxp", "http").replace("[:]", ":").strip().lower()


def _defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def _load_seeds(path: str) -> set[str]:
    seeds = set()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        v = _refang(line)
        if v:
            seeds.add(v)
    return seeds


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


def _indicators(text: str) -> set[str]:
    out = set()
    out |= {m.lower() for m in RE_IP.findall(text)}
    out |= {m.lower() for m in RE_DOMAIN.findall(text)}
    out |= {m.lower() for m in RE_HASH.findall(text)}
    return out


def pivot(seeds_path: str, logs_path: str) -> dict:
    seeds = _load_seeds(seeds_path)
    hosts = set()
    times = []
    new_counter: Counter = Counter()
    matched = 0
    for row in _rows(logs_path):
        blob = _refang(" ".join(str(v) for v in row.values()))
        row_inds = _indicators(blob)
        if seeds & row_inds:
            matched += 1
            host = (row.get("host") or row.get("Computer") or row.get("hostname")
                    or row.get("src_host") or "")
            if host:
                hosts.add(str(host).lower())
            ts = (row.get("timestamp") or row.get("ts") or row.get("time")
                  or row.get("EventTime") or "")
            if ts:
                times.append(str(ts))
            for ind in row_inds - seeds:
                new_counter[ind] += 1
    new_ranked = [{"indicator": _defang(i), "co_occurrence": c}
                  for i, c in new_counter.most_common(50)]
    return {
        "matched_records": matched,
        "affected_hosts": sorted(hosts),
        "time_range": {"earliest": min(times), "latest": max(times)} if times else {},
        "new_indicators": new_ranked,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pivot on IOCs across logs")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pivot")
    p.add_argument("--seeds", required=True)
    p.add_argument("--logs", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(pivot(args.seeds, args.logs), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
