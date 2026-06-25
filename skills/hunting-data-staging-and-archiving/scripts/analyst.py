#!/usr/bin/env python3
"""Hunt pre-exfiltration data staging and archiving in Windows telemetry.

Parses process-creation telemetry (CSV or JSON-lines) and flags archive-tool execution with
compression/password flags and archives written to staging directories. Parses telemetry only;
executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

ARCHIVE_TOOLS = ["rar.exe", "winrar.exe", "7z.exe", "7za.exe", "zip.exe", "tar.exe",
                 "wzzip.exe", "makecab.exe"]
ARCHIVE_BUILTINS = ["compress-archive", "tar -c", "tar.exe -c"]
COMPRESS_FLAGS = ["a -", "-hp", "-p", "-r ", "-mx", "a -t", "-ssw"]
STAGING_PATHS = ["\\temp\\", "%temp%", "\\appdata\\", "%appdata%", "\\programdata\\",
                 "\\users\\public", "\\windows\\temp"]
RE_ARCHIVE_FILE = re.compile(r"[^\s\"']+\.(?:rar|7z|zip|tar|gz|cab|r\d{2}|z\d{2})\b", re.I)


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


def _base(p: str) -> str:
    return p.replace("/", "\\").split("\\")[-1].lower()


def hunt(path: str) -> dict:
    findings = []
    for row in _rows(path):
        image = _base(_get(row, "Image", "image"))
        cmd = _get(row, "CommandLine", "command_line")
        low = cmd.lower()
        is_tool = image in ARCHIVE_TOOLS or any(b in low for b in ARCHIVE_BUILTINS)
        if not is_tool:
            continue
        reasons = []
        if any(f in low for f in COMPRESS_FLAGS):
            reasons.append("compression_flags")
        if "-hp" in low or "-p" in low or "-hp" in low:
            reasons.append("password_protected")
        staged = [p for p in STAGING_PATHS if p in low]
        if staged:
            reasons.append("staging_path")
        archives = RE_ARCHIVE_FILE.findall(cmd)
        if reasons or archives:
            findings.append({
                "tool": image or "(builtin)",
                "indicators": reasons,
                "archives": sorted(set(archives))[:5],
                "command_line": cmd[:200],
            })
    return {"staging_events": findings, "total": len(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt data staging and archiving")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
