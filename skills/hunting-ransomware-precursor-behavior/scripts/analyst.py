#!/usr/bin/env python3
"""Hunt ransomware precursor behavior in Windows process telemetry.

Parses process-creation telemetry (CSV or JSON-lines) and flags recovery-inhibition commands and
security/backup service tampering that precede encryption, correlating co-occurrence per host.
Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

RECOVERY_INHIBIT = [
    "vssadmin delete shadows", "vssadmin.exe delete shadows", "wmic shadowcopy delete",
    "win32_shadowcopy", "wbadmin delete catalog", "wbadmin delete systemstatebackup",
    "bcdedit /set", "recoveryenabled no", "bootstatuspolicy ignoreallfailures",
    "wevtutil cl", "delete shadows /all",
]
SERVICE_TAMPER_VERBS = ["net stop", "sc stop", "sc config", "taskkill", "stop-service",
                        "stop-process"]
TARGET_SERVICES = ["veeam", "backup", "sql", "mssql", "oracle", "exchange", "sophos", "defender",
                   "sentinel", "mcafee", "symantec", "vss", "sqlserver", "acronis"]


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
    recovery, tamper = [], []
    per_host: dict[str, set[str]] = defaultdict(set)
    for row in _rows(path):
        cmd = _get(row, "CommandLine", "command_line")
        host = _get(row, "Computer", "host", "hostname") or "(unknown)"
        low = cmd.lower()
        rhit = [r for r in RECOVERY_INHIBIT if r in low]
        if rhit:
            recovery.append({"host": host, "indicators": rhit, "command_line": cmd[:200]})
            per_host[host].add("recovery_inhibition")
        if any(v in low for v in SERVICE_TAMPER_VERBS):
            svc = [s for s in TARGET_SERVICES if s in low]
            if svc:
                tamper.append({"host": host, "services": svc, "command_line": cmd[:200]})
                per_host[host].add("service_tampering")
    high_priority = sorted(h for h, sigs in per_host.items() if len(sigs) >= 2)
    return {
        "recovery_inhibition": recovery,
        "service_tampering": tamper,
        "high_priority_hosts": high_priority,
        "ransomware_precursor_suspected": bool(recovery or tamper),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt ransomware precursor behavior")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
