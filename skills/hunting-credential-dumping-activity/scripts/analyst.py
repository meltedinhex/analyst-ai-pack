#!/usr/bin/env python3
"""Hunt credential-dumping activity in Sysmon ProcessAccess (EID 10) and process telemetry.

Flags LSASS access with high-risk GrantedAccess masks and process events showing comsvcs MiniDump,
procdump, rundll32 MiniDump, or known dumper names. Accepts CSV or JSON-lines. Parses telemetry
only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

RISKY_MASKS = {"0x1010", "0x1410", "0x143a", "0x1438", "0x1fffff", "0x1f3fff"}
DUMP_CMD_PATTERNS = ["comsvcs.dll,minidump", "comsvcs.dll, minidump", "minidump",
                     "procdump", "lsass.dmp", "sekurlsa", "mimikatz", "nanodump",
                     "rundll32.exe c:\\windows\\system32\\comsvcs.dll"]
KNOWN_SECURITY_SRC = ["msmpeng.exe", "mssense.exe", "sensendr.exe", "csfalconservice.exe",
                      "carbonblack", "cb.exe", "wireshark"]


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


def _base(path: str) -> str:
    return path.replace("/", "\\").split("\\")[-1].lower()


def hunt(path: str) -> dict:
    lsass_access, dump_cmds = [], []
    for row in _rows(path):
        target = _base(_get(row, "TargetImage", "target_image"))
        mask = _get(row, "GrantedAccess", "granted_access").lower()
        source = _base(_get(row, "SourceImage", "source_image", "Image", "image"))
        if target == "lsass.exe" and mask:
            risky = mask in RISKY_MASKS
            trusted_src = any(s in source for s in KNOWN_SECURITY_SRC)
            if risky and not trusted_src:
                lsass_access.append({"source": source, "granted_access": mask})
        cmd = _get(row, "CommandLine", "command_line").lower()
        hits = [p for p in DUMP_CMD_PATTERNS if p in cmd]
        if hits:
            dump_cmds.append({"indicators": hits, "command_line": cmd[:200]})
    return {
        "lsass_access_events": lsass_access,
        "dump_command_events": dump_cmds,
        "credential_dumping_suspected": bool(lsass_access or dump_cmds),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt credential dumping")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
