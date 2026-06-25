#!/usr/bin/env python3
"""Detect control-flow flattening and reconstruct original control flow from CFG JSON.

Input JSON describes a function's basic blocks:
{
  "state_var": "eax",
  "blocks": [
    {"id": "A", "succ": ["D"], "in_degree": 1, "state_compare": false,
     "next_state": null},
    {"id": "D", "succ": ["B","C","E"], "in_degree": 5, "state_compare": true},
    {"id": "B", "succ": ["D"], "in_degree": 1, "next_state": "C_const"} ...
  ]
}
Identifies the dispatcher (high in-degree + state_compare) and rebuilds case->next mappings using
each case's next_state. Parses JSON only; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def detect(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    blocks = {b["id"]: b for b in data.get("blocks", [])}
    # Dispatcher: a block that compares the state variable and has the highest in-degree.
    candidates = [b for b in blocks.values() if b.get("state_compare")]
    if not candidates:
        candidates = list(blocks.values())
    dispatcher = max(candidates, key=lambda b: b.get("in_degree", 0), default=None)
    if not dispatcher:
        return {"flattening_detected": False}
    disp_id = dispatcher["id"]
    # Case/relay blocks branch back to the dispatcher.
    cases = [b for b in blocks.values()
             if disp_id in b.get("succ", []) and b["id"] != disp_id]
    deflattened = {}
    for case in cases:
        nxt = case.get("next_state")
        deflattened[case["id"]] = nxt
    covered = set(deflattened) | {disp_id}
    orphans = [bid for bid in blocks if bid not in covered
               and bid not in (data.get("entry"),)]
    return {
        "flattening_detected": len(cases) >= 3,
        "dispatcher": disp_id,
        "state_var": data.get("state_var"),
        "case_count": len(cases),
        "deflattened_transitions": deflattened,
        "unresolved_blocks": orphans,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Defeat control-flow flattening")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("detect")
    p.add_argument("cfg")
    args = parser.parse_args(argv)
    print(json.dumps(detect(args.cfg), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
