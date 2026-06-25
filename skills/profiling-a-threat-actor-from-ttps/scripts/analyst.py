#!/usr/bin/env python3
"""Compare an observed ATT&CK technique set against known-group technique sets.

Computes Jaccard and overlap-coefficient similarity between the observed techniques and each group,
ranking candidate groups and listing overlapping techniques. Inputs: observed (one technique ID per
line) and groups (JSON mapping group->list of technique IDs, or list of {name, techniques}).
Parses data only; executes nothing. TTP overlap is suggestive, not confirmed attribution.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_observed(path: str) -> set[str]:
    out = set()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        v = line.strip().upper()
        if v and v.startswith("T"):
            out.add(v)
    return out


def _load_groups(path: str) -> dict[str, set[str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    groups: dict[str, set[str]] = {}
    if isinstance(data, dict):
        for name, techs in data.items():
            groups[name] = {str(t).upper() for t in techs}
    else:
        for item in data:
            name = item.get("name") or item.get("group")
            techs = item.get("techniques", [])
            if name:
                groups[name] = {str(t).upper() for t in techs}
    return groups


def compare(observed_path: str, groups_path: str) -> dict:
    observed = _load_observed(observed_path)
    groups = _load_groups(groups_path)
    results = []
    for name, techs in groups.items():
        inter = observed & techs
        union = observed | techs
        jaccard = round(len(inter) / len(union), 4) if union else 0.0
        overlap = round(len(inter) / min(len(observed), len(techs)), 4) \
            if observed and techs else 0.0
        if inter:
            results.append({
                "group": name,
                "jaccard": jaccard,
                "overlap_coefficient": overlap,
                "shared_techniques": sorted(inter),
                "shared_count": len(inter),
            })
    results.sort(key=lambda d: (d["overlap_coefficient"], d["jaccard"]), reverse=True)
    return {
        "observed_technique_count": len(observed),
        "candidates": results[:15],
        "confidence_note": "TTP overlap is suggestive only; corroborate with intel before attribution",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Profile a threat actor from TTPs")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("compare")
    p.add_argument("--observed", required=True)
    p.add_argument("--groups", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(compare(args.observed, args.groups), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
