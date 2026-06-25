#!/usr/bin/env python3
"""Compute detection coverage against Atomic Red Team-tested ATT&CK techniques.

Inputs:
- atomics: JSON list of {"technique": "T1059.001", "test": "..."} (or a mapping technique->count).
- detections: JSON list of technique IDs your detections cover (or objects with a "technique" key).
Joins on technique IDs and reports covered/uncovered techniques, ranking gaps by atomic-test count.
Parses data only; executes nothing and never runs an atomic.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _load(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def _atomic_counts(atomics) -> Counter:
    counts: Counter = Counter()
    if isinstance(atomics, dict):
        for tech, val in atomics.items():
            counts[tech] += int(val) if isinstance(val, int) else 1
    else:
        for item in atomics:
            tech = item.get("technique") if isinstance(item, dict) else item
            if tech:
                counts[tech] += 1
    return counts


def _detection_techniques(detections) -> set[str]:
    out = set()
    for item in detections:
        tech = item.get("technique") if isinstance(item, dict) else item
        if tech:
            out.add(tech)
    return out


def coverage(atomics_path: str, detections_path: str) -> dict:
    atomic_counts = _atomic_counts(_load(atomics_path))
    covered_set = _detection_techniques(_load(detections_path))
    tested = set(atomic_counts)
    covered = sorted(tested & covered_set)
    uncovered = sorted(tested - covered_set)
    gap_ranked = sorted(
        ({"technique": t, "atomic_tests": atomic_counts[t]} for t in uncovered),
        key=lambda d: d["atomic_tests"], reverse=True)
    pct = round(100 * len(covered) / len(tested), 1) if tested else 0.0
    return {
        "tested_techniques": len(tested),
        "covered_techniques": covered,
        "uncovered_techniques": uncovered,
        "coverage_percent": pct,
        "gap_priority": gap_ranked,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detection coverage vs atomic tests")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("coverage")
    p.add_argument("--atomics", required=True)
    p.add_argument("--detections", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(coverage(args.atomics, args.detections), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
