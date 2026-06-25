#!/usr/bin/env python3
"""Score C2 beaconing from connection logs using inter-arrival timing.

Reads a JSON list of connections (``src``, ``dst``, ``ts`` epoch seconds, optional ``bytes``),
groups by source/destination pair, computes inter-arrival intervals, and scores regularity via
the coefficient of variation (jitter tolerant). It reads local JSON only; it makes no network
connections.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path


def _score_pair(timestamps: list[float], sizes: list[int]) -> dict:
    ts = sorted(timestamps)
    intervals = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
    if len(intervals) < 2:
        return {}
    mean = statistics.mean(intervals)
    stdev = statistics.pstdev(intervals)
    cv = stdev / mean if mean else 1.0
    # regularity score: low CV -> high score
    regularity = max(0.0, 1.0 - min(cv, 1.0))
    size_cv = None
    if len([s for s in sizes if s]) >= 2:
        smean = statistics.mean(sizes)
        size_cv = (statistics.pstdev(sizes) / smean) if smean else None
    score = round(regularity * 100)
    if size_cv is not None and size_cv < 0.1:
        score = min(100, score + 15)
    return {
        "events": len(ts),
        "mean_interval_s": round(mean, 1),
        "interval_cv": round(cv, 3),
        "size_cv": round(size_cv, 3) if size_cv is not None else None,
        "beacon_score": score,
    }


def hunt(conns: list[dict], min_events: int) -> dict:
    pairs: dict[tuple, dict] = {}
    for c in conns:
        key = (c.get("src"), c.get("dst"))
        p = pairs.setdefault(key, {"ts": [], "bytes": []})
        p["ts"].append(float(c.get("ts", 0)))
        p["bytes"].append(int(c.get("bytes", 0)))

    results = []
    for (src, dst), data in pairs.items():
        if len(data["ts"]) < min_events:
            continue
        scored = _score_pair(data["ts"], data["bytes"])
        if scored and scored["beacon_score"] >= 60:
            results.append({"src": src, "dst": dst, **scored})
    results.sort(key=lambda x: x["beacon_score"], reverse=True)
    return {"candidates": results, "pairs_evaluated": len(pairs)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt C2 beaconing by timing")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("beacon")
    p.add_argument("file", help="JSON list of connections")
    p.add_argument("--min-events", type=int, default=8)
    args = parser.parse_args(argv)
    conns = json.loads(Path(args.file).read_text(encoding="utf-8"))
    print(json.dumps(hunt(conns, args.min_events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
