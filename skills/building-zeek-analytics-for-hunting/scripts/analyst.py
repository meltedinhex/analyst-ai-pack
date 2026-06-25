#!/usr/bin/env python3
"""Analyze Zeek logs (conn/dns/http/ssl) for hunting anomalies.

Parses Zeek TSV (#fields header) or JSON-lines logs and surfaces anomalies per log kind: long/large
connections (conn), JA3 rarity (ssl), executable/script downloads and rare user-agents (http), and
long/high-entropy queries (dns). Parses logs only; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _read_zeek(path: str) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows
    # TSV with #fields header
    fields = []
    rows = []
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#") and fields:
            values = line.split("\t")
            rows.append(dict(zip(fields, values)))
    return rows


def _num(v: str, default: float = 0.0) -> float:
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


def analyze(path: str, kind: str) -> dict:
    rows = _read_zeek(path)
    if kind == "conn":
        long_conns = sorted(
            ({"uid": r.get("uid"), "dest": r.get("id.resp_h"),
              "duration": _num(r.get("duration")), "bytes": _num(r.get("orig_bytes"))
              + _num(r.get("resp_bytes"))} for r in rows),
            key=lambda d: (d["duration"], d["bytes"]), reverse=True)[:25]
        return {"kind": "conn", "top_long_or_large_connections": long_conns}
    if kind == "ssl":
        ja3 = Counter(r.get("ja3") for r in rows if r.get("ja3"))
        rare = [{"ja3": j, "count": c} for j, c in ja3.items() if c <= 2]
        return {"kind": "ssl", "rare_ja3": rare[:50], "distinct_ja3": len(ja3)}
    if kind == "http":
        downloads, rare_ua = [], []
        ua_counter = Counter(r.get("user_agent") for r in rows if r.get("user_agent"))
        for r in rows:
            uri = (r.get("uri") or "").lower()
            mime = (r.get("resp_mime_types") or r.get("mime_type") or "").lower()
            if uri.endswith((".exe", ".dll", ".scr", ".ps1", ".hta", ".js")) \
                    or "application/x-dosexec" in mime:
                downloads.append({"host": r.get("host"), "uri": r.get("uri")})
        for ua, c in ua_counter.items():
            if c <= 2:
                rare_ua.append({"user_agent": ua, "count": c})
        return {"kind": "http", "suspicious_downloads": downloads[:50],
                "rare_user_agents": rare_ua[:50]}
    if kind == "dns":
        weird = []
        for r in rows:
            q = r.get("query") or ""
            if len(q) >= 40 or _entropy(q) >= 3.8:
                weird.append({"query": q[:120], "entropy": round(_entropy(q), 2)})
        return {"kind": "dns", "anomalous_queries": weird[:50]}
    return {"error": "unknown kind", "kinds": ["conn", "ssl", "http", "dns"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Zeek logs for hunting")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze")
    p.add_argument("log")
    p.add_argument("--kind", required=True, choices=["conn", "ssl", "http", "dns"])
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.log, args.kind), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
