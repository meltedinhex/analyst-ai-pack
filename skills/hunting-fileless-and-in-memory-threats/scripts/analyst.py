#!/usr/bin/env python3
"""Hunt fileless / in-memory threats in PowerShell, process, and registry telemetry.

Parses events (CSV or JSON-lines) and flags in-memory loading patterns (reflective assembly load,
VirtualAlloc/WriteProcessMemory via PowerShell, IEX of decoded blobs), large base64 in script
blocks, and registry-resident encoded payloads. Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

INMEM_PATTERNS = [
    "reflection.assembly]::load", "[system.reflection.assembly]::load",
    "virtualalloc", "writeprocessmemory", "createremotethread", "ntcreatethreadex",
    "invoke-expression", "iex(", "iex (", "downloadstring", "frombase64string",
    "getdelegatefortypeandparameters", "[runtime.interopservices.marshal]",
]
RE_BIGB64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


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
    script_findings, registry_findings = [], []
    for row in _rows(path):
        content = _get(row, "ScriptBlockText", "CommandLine", "command_line", "Message").lower()
        if content:
            hits = [p for p in INMEM_PATTERNS if p in content]
            big_b64 = bool(RE_BIGB64.search(content))
            if hits or big_b64:
                score = 2 * len(hits) + (2 if big_b64 else 0)
                script_findings.append({
                    "indicators": hits + (["large_base64_blob"] if big_b64 else []),
                    "score": score, "preview": content[:160]})
        target = _get(row, "TargetObject", "target_object").lower()
        details = _get(row, "Details", "details")
        if target and ("\\software\\" in target or "\\run" in target) and len(details) > 256:
            if RE_BIGB64.search(details):
                registry_findings.append({"key": target[:160], "value_size": len(details)})
    script_findings.sort(key=lambda d: d["score"], reverse=True)
    return {
        "in_memory_script_findings": script_findings[:100],
        "registry_resident_payloads": registry_findings[:50],
        "fileless_activity_suspected": bool(script_findings or registry_findings),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt fileless / in-memory threats")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
