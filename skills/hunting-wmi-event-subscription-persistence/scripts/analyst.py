#!/usr/bin/env python3
"""Correlate WMI permanent event subscription records and flag suspicious consumers.

Parses Sysmon WMI telemetry (Event IDs 19/20/21) from CSV or JSON-lines, groups filters,
consumers, and bindings, and flags consumers whose payload runs scripts or encoded commands.
Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

SUSPICIOUS = ["powershell", "-enc", "wscript", "cscript", "mshta", "cmd.exe /c", "http",
              "jscript", "vbscript", "scrobj", "regsvr32", "rundll32"]


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


def _get(row: dict, *keys: str) -> str:
    for k in keys:
        if row.get(k):
            return str(row[k])
    return ""


def hunt(path: str) -> dict:
    filters, consumers, bindings = [], [], []
    for row in _rows(path):
        eid = _get(row, "EventID", "event_id", "Id")
        etype = _get(row, "EventType", "Operation").lower()
        if eid == "19" or "wmifilter" in etype:
            filters.append({"name": _get(row, "Name", "Operation"),
                            "query": _get(row, "Query", "query")})
        elif eid == "20" or "wmiconsumer" in etype:
            consumers.append({"name": _get(row, "Name", "Operation"),
                              "destination": _get(row, "Destination", "CommandLineTemplate",
                                                  "ScriptText", "destination")})
        elif eid == "21" or "wmibinding" in etype:
            bindings.append({"consumer": _get(row, "Consumer", "consumer"),
                             "filter": _get(row, "Filter", "filter")})
    flagged = []
    for c in consumers:
        dest = c["destination"].lower()
        hits = [s for s in SUSPICIOUS if s in dest]
        if hits:
            flagged.append({"consumer": c["name"], "indicators": hits,
                            "payload": c["destination"][:200]})
    return {
        "filters": filters, "consumers": consumers, "bindings": bindings,
        "suspicious_consumers": flagged,
        "subscription_complete": bool(filters and consumers and bindings),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt WMI event subscription persistence")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
