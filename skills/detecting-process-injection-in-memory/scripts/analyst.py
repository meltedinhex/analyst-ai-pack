#!/usr/bin/env python3
"""Score process-injection candidates from Volatility 3 windows.malfind text output.

Parses malfind's per-region report and ranks processes by injection indicators: RWX protection,
MZ/PE header in private memory, and common shellcode prologue bytes in the hexdump. Parses text
only; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

RE_PID = re.compile(r"\b(?:PID|Pid)\s*[:]?\s*(\d+)", re.I)
RE_PROC = re.compile(r"Process[:]?\s+([^\s]+)", re.I)
RWX = "PAGE_EXECUTE_READWRITE"
SHELLCODE_HINTS = ["55 8b ec", "fc 48 83", "e8 00 00 00 00", "60 89 e5", "31 c0", "eb"]


def score(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    lines = text.splitlines()
    proc_scores: dict[str, dict] = defaultdict(lambda: {"score": 0, "reasons": set(), "pid": None})
    current = None
    for line in lines:
        mproc = RE_PROC.search(line)
        mpid = RE_PID.search(line)
        if mproc:
            current = mproc.group(1)
            proc_scores[current]["pid"] = mpid.group(1) if mpid else proc_scores[current]["pid"]
        if current is None:
            continue
        low = line.lower()
        if RWX.lower() in low:
            proc_scores[current]["score"] += 3
            proc_scores[current]["reasons"].add("rwx_region")
        if "4d 5a" in low or "mz" in low and "this program" in low:
            proc_scores[current]["score"] += 3
            proc_scores[current]["reasons"].add("pe_in_private_memory")
        if "this program cannot be run" in low:
            proc_scores[current]["score"] += 2
            proc_scores[current]["reasons"].add("dos_stub")
        if any(h in low for h in SHELLCODE_HINTS):
            proc_scores[current]["score"] += 1
            proc_scores[current]["reasons"].add("shellcode_prologue")
    ranked = sorted(
        ({"process": k, "pid": v["pid"], "score": v["score"],
          "reasons": sorted(v["reasons"])} for k, v in proc_scores.items() if v["score"] > 0),
        key=lambda d: d["score"], reverse=True,
    )
    return {"candidates": ranked, "total_flagged": len(ranked)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score malfind injection candidates")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("score")
    p.add_argument("malfind_txt")
    args = parser.parse_args(argv)
    print(json.dumps(score(args.malfind_txt), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
