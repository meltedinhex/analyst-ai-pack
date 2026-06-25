#!/usr/bin/env python3
"""Hunt anomalous Windows persistence entries against a fleet baseline.

Reads a JSON list of autostart entries (Run keys, services, scheduled tasks, WMI subscriptions)
and an optional baseline, then scores anomalies: unsigned binaries, user-writable/temp paths,
LOLBin usage, and entries absent from the baseline. It reads local JSON only and touches no
live systems.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

LOLBINS = {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "cmd.exe", "msbuild.exe"}
SUSPECT_PATHS = ("\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\")


def _baseline_keys(baseline: list[dict]) -> set:
    return {(e.get("type"), e.get("name"), e.get("image", "").lower()) for e in baseline}


def hunt(entries: list[dict], baseline: list[dict]) -> dict:
    known = _baseline_keys(baseline)
    results = []
    for e in entries:
        image = e.get("image", "")
        low = image.lower()
        score = 0
        reasons = []
        if (e.get("type"), e.get("name"), low) not in known and known:
            score += 40
            reasons.append("not in baseline")
        if e.get("signed") is False:
            score += 20
            reasons.append("unsigned")
        if any(p in low for p in SUSPECT_PATHS):
            score += 25
            reasons.append("user-writable/temp path")
        if any(low.endswith(b) or b in low for b in LOLBINS):
            score += 15
            reasons.append("LOLBin")
        if e.get("args") and ("-enc" in e["args"].lower() or "frombase64" in e["args"].lower()):
            score += 25
            reasons.append("encoded arguments")
        if score:
            results.append({**{k: e.get(k) for k in ("type", "name", "image")},
                            "score": score, "reasons": reasons})
    results.sort(key=lambda x: x["score"], reverse=True)
    return {"candidates": [r for r in results if r["score"] >= 40], "evaluated": len(entries)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt Windows persistence")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("file", help="JSON list of autostart entries")
    p.add_argument("--baseline", default=None, help="JSON baseline list")
    args = parser.parse_args(argv)
    entries = json.loads(Path(args.file).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else []
    print(json.dumps(hunt(entries, baseline), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
