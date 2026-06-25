#!/usr/bin/env python3
"""Triage Sysmon process-injection telemetry (Event IDs 8 and 10).

Reads a JSON array of normalized Sysmon events and scores cross-process access (EID 10) and
remote-thread creation (EID 8) for injection likelihood, correlating source→target pairs and
flagging high-power access masks. It only reads local JSON; it touches no live systems.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Access rights that enable injection (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, etc.)
INJECT_MASK = 0x0002 | 0x0020 | 0x0008 | 0x0400  # VM_OPERATION/WRITE/THREAD/QUERY (heuristic)
FULL_ACCESS = 0x1F0FFF


def _mask(value) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16)
    except ValueError:
        return 0


def triage(events: list[dict]) -> dict:
    candidates: dict[tuple, dict] = {}
    for ev in events:
        eid = ev.get("event_id")
        src = ev.get("source_image", "?")
        tgt = ev.get("target_image", "?")
        key = (src, tgt, ev.get("target_pid"))
        c = candidates.setdefault(key, {"source": src, "target": tgt,
                                        "target_pid": ev.get("target_pid"),
                                        "remote_thread": False, "vm_access": False,
                                        "score": 0, "reasons": []})
        if eid == 8:
            c["remote_thread"] = True
            c["score"] += 50
            c["reasons"].append("CreateRemoteThread (EID8)")
        elif eid == 10:
            mask = _mask(ev.get("granted_access"))
            if mask == FULL_ACCESS or (mask & INJECT_MASK):
                c["vm_access"] = True
                c["score"] += 30
                c["reasons"].append(f"ProcessAccess mask {hex(mask)}")
        if ev.get("source_parent_image", "").lower().endswith(
                ("powershell.exe", "wscript.exe", "cscript.exe", "winword.exe", "excel.exe")):
            c["score"] += 20
            c["reasons"].append("script/macro-spawned source")

    ranked = sorted(candidates.values(), key=lambda x: x["score"], reverse=True)
    for c in ranked:
        if c["remote_thread"] and c["vm_access"]:
            c["score"] += 20
            c["reasons"].append("write+remote-thread to same target")
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return {"candidates": [c for c in ranked if c["score"] >= 50], "total": len(ranked)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage Sysmon injection events")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("triage")
    p.add_argument("file", help="JSON array of normalized Sysmon events")
    args = parser.parse_args(argv)
    events = json.loads(Path(args.file).read_text(encoding="utf-8"))
    print(json.dumps(triage(events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
