#!/usr/bin/env python3
"""Generate a structured threat-hunt plan from a hypothesis.

Takes an ATT&CK technique, a data source, and a lookback window and emits a plan skeleton:
hypothesis statement, data requirements, baseline questions, scope, and the three outcome
branches. This is a planning aid that emits text; it queries no systems.
"""
from __future__ import annotations

import argparse
import json
import sys


def plan(technique: str, datasource: str, window: str, behavior: str) -> dict:
    return {
        "technique": technique,
        "hypothesis": f"If an adversary performs {behavior or '<behavior>'} ({technique}), "
                      f"then I expect to observe related evidence in {datasource}.",
        "data_requirements": {
            "source": datasource,
            "lookback": window,
            "checks": ["source exists", "retention covers window", "fields needed are present"],
        },
        "baseline_questions": [
            "What does normal activity look like for this behavior?",
            "Which hosts/users legitimately exhibit it?",
        ],
        "scope": {"hosts": "<scope>", "time_window": window},
        "outcomes": {
            "finding": "escalate to incident response",
            "detection_gap": "hand to detection engineering",
            "confident_negative": "document hunt and queries for reuse",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a hunt plan")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--technique", required=True)
    p.add_argument("--datasource", required=True)
    p.add_argument("--window", default="14d")
    p.add_argument("--behavior", default="")
    args = parser.parse_args(argv)
    print(json.dumps(plan(args.technique, args.datasource, args.window, args.behavior),
                     indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
