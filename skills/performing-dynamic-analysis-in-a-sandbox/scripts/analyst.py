#!/usr/bin/env python3
"""Summarize a sandbox behavioral report (CAPE/Cuckoo-style JSON) into capabilities and IOCs.

Reads an already-produced JSON report — it does not detonate anything. Tolerant of partial
schemas: it looks for common keys (processes, signatures, network, dropped) and degrades
gracefully when fields are missing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _get(d: dict, *path, default=None):
    cur = d
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def summarize(report: dict) -> dict:
    processes = _get(report, "behavior", "processes", default=[]) or \
        _get(report, "processes", default=[]) or []
    proc_tree = [{
        "pid": p.get("pid"),
        "name": p.get("process_name") or p.get("name"),
        "command": p.get("command_line") or p.get("commandline"),
        "ppid": p.get("ppid") or p.get("parent_id"),
    } for p in processes][:200]

    signatures = _get(report, "signatures", default=[]) or []
    sigs = [{"name": s.get("name"), "description": s.get("description"),
             "severity": s.get("severity")} for s in signatures]

    net = _get(report, "network", default={}) or {}
    hosts = net.get("hosts", []) or []
    domains = [d.get("domain") if isinstance(d, dict) else d
               for d in net.get("domains", []) or []]
    http = [h.get("uri") or h.get("url") for h in net.get("http", []) or []
            if isinstance(h, dict)]

    dropped = _get(report, "dropped", default=[]) or []
    drops = [{"name": d.get("name"), "sha256": d.get("sha256"),
              "type": d.get("type")} for d in dropped][:200]

    return {
        "process_count": len(processes),
        "process_tree": proc_tree,
        "signatures": sigs,
        "iocs": {
            "hosts": [h.get("ip") if isinstance(h, dict) else h for h in hosts],
            "domains": [d for d in domains if d],
            "urls": [u for u in http if u],
        },
        "dropped_files": drops,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize a sandbox report")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("summarize")
    p.add_argument("report", help="path to sandbox JSON report")
    args = parser.parse_args(argv)

    report = json.loads(Path(args.report).read_text(encoding="utf-8", errors="replace"))
    print(json.dumps(summarize(report), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
