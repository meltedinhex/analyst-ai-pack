#!/usr/bin/env python3
"""Hunt scheduled-task persistence abuse in 4698 and schtasks process telemetry.

Parses task-registration (4698) and process-creation events (CSV or JSON-lines) and flags task
actions or schtasks command lines that run script hosts, encoded commands, or binaries from
suspicious paths. Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

SUSPICIOUS_ACTIONS = ["powershell", "-enc", "-encodedcommand", "mshta", "wscript", "cscript",
                      "cmd /c", "cmd.exe /c", "rundll32", "regsvr32", "bitsadmin", "curl",
                      "certutil"]
SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\", "\\public\\", "\\programdata\\",
                    "\\users\\public", "%temp%", "%appdata%"]


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
    findings = []
    for row in _rows(path):
        eid = _get(row, "EventID", "event_id")
        action = _get(row, "TaskContent", "Action", "Command", "CommandLine",
                      "command_line").lower()
        task = _get(row, "TaskName", "task_name")
        if not action:
            continue
        is_task_event = eid == "4698" or "schtasks" in action or task
        if not is_task_event:
            continue
        hits = [a for a in SUSPICIOUS_ACTIONS if a in action]
        path_hits = [p for p in SUSPICIOUS_PATHS if p in action]
        if hits or path_hits:
            findings.append({
                "task": task or "(unnamed)",
                "indicators": hits + [f"path:{p}" for p in path_hits],
                "action": action[:200],
            })
    return {"suspicious_tasks": findings, "total": len(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt scheduled task abuse")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
