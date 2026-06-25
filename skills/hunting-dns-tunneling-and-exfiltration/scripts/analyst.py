#!/usr/bin/env python3
"""Score DNS logs for tunneling and exfiltration indicators.

Reads a JSON list of DNS queries (``query`` name, optional ``qtype``, ``src``), aggregates by
registered domain (last two labels, heuristic), and scores tunneling signals: unique-subdomain
count, average label length, Shannon entropy, and data-bearing record types. It reads local
JSON only; it issues no DNS queries.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

DATA_TYPES = {"TXT", "NULL", "CNAME", "AAAA"}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def registered(domain: str) -> str:
    labels = domain.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def hunt(queries: list[dict]) -> dict:
    by_domain: dict[str, dict] = defaultdict(
        lambda: {"subdomains": set(), "label_lens": [], "entropies": [], "data_type": 0,
                 "count": 0})
    for q in queries:
        name = (q.get("query") or "").lower().rstrip(".")
        if not name:
            continue
        reg = registered(name)
        d = by_domain[reg]
        d["count"] += 1
        sub = name[: -len(reg)].rstrip(".")
        if sub:
            d["subdomains"].add(sub)
            longest = max(sub.split("."), key=len)
            d["label_lens"].append(len(longest))
            d["entropies"].append(entropy(longest))
        if (q.get("qtype") or "A").upper() in DATA_TYPES:
            d["data_type"] += 1

    results = []
    for reg, d in by_domain.items():
        if d["count"] < 5:
            continue
        avg_len = sum(d["label_lens"]) / len(d["label_lens"]) if d["label_lens"] else 0
        avg_ent = sum(d["entropies"]) / len(d["entropies"]) if d["entropies"] else 0
        score = 0
        reasons = []
        if len(d["subdomains"]) > 50:
            score += 30
            reasons.append(f"{len(d['subdomains'])} unique subdomains")
        if avg_len > 25:
            score += 25
            reasons.append(f"avg label len {avg_len:.0f}")
        if avg_ent > 3.5:
            score += 25
            reasons.append(f"avg entropy {avg_ent:.2f}")
        if d["data_type"] > d["count"] * 0.3:
            score += 20
            reasons.append("heavy data-bearing record types")
        if score >= 50:
            results.append({"domain": reg, "count": d["count"],
                            "unique_subdomains": len(d["subdomains"]),
                            "avg_label_len": round(avg_len, 1),
                            "avg_entropy": round(avg_ent, 2),
                            "score": score, "reasons": reasons})
    results.sort(key=lambda x: x["score"], reverse=True)
    return {"candidates": results, "domains_evaluated": len(by_domain)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt DNS tunneling/exfiltration")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("file", help="JSON list of DNS queries")
    args = parser.parse_args(argv)
    queries = json.loads(Path(args.file).read_text(encoding="utf-8"))
    print(json.dumps(hunt(queries), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
