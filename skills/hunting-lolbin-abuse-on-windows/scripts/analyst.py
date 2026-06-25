#!/usr/bin/env python3
"""Hunt LOLBin abuse in Windows process-creation telemetry (CSV or JSON lines).

Flags known living-off-the-land binaries used with suspicious arguments and weights by anomalous
parent process. Accepts CSV with Image/CommandLine/ParentImage columns or JSON-lines with the same
keys. Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

LOLBINS = {
    "certutil.exe": ["-urlcache", "-decode", "-encode", "http"],
    "mshta.exe": ["http", "javascript:", "vbscript:"],
    "regsvr32.exe": ["scrobj", "/i:http", "/u"],
    "rundll32.exe": ["javascript:", "url.dll", "shell32.dll,control_rundll"],
    "bitsadmin.exe": ["/transfer", "http"],
    "msiexec.exe": ["http", "/q"],
    "installutil.exe": ["/logfile=", "/u"],
    "wmic.exe": ["process call create", "/node:"],
    "powershell.exe": ["-enc", "downloadstring", "iex", "-w hidden"],
}
SUSPICIOUS_PARENTS = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mshta.exe",
                      "wscript.exe", "cscript.exe", "chrome.exe", "firefox.exe"]


def _basename(path: str) -> str:
    return path.replace("/", "\\").split("\\")[-1].lower()


def _score_event(image: str, cmdline: str, parent: str) -> dict | None:
    img = _basename(image)
    if img not in LOLBINS:
        return None
    low = cmdline.lower()
    hits = [a for a in LOLBINS[img] if a in low]
    if not hits:
        return None
    score = 2 * len(hits)
    reasons = [f"arg:{a}" for a in hits]
    if _basename(parent) in SUSPICIOUS_PARENTS:
        score += 3
        reasons.append(f"parent:{_basename(parent)}")
    return {"image": img, "score": score, "reasons": reasons, "command_line": cmdline[:200]}


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


def hunt(path: str) -> dict:
    findings = []
    for row in _rows(path):
        image = row.get("Image") or row.get("image") or ""
        cmd = row.get("CommandLine") or row.get("command_line") or ""
        parent = row.get("ParentImage") or row.get("parent_image") or ""
        res = _score_event(image, cmd, parent)
        if res:
            findings.append(res)
    findings.sort(key=lambda d: d["score"], reverse=True)
    return {"findings": findings, "total": len(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt LOLBin abuse")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
