#!/usr/bin/env python3
"""Summarize a capa JSON report into an ATT&CK/MBC capability profile.

Reads capa's JSON output and aggregates matched rules by ATT&CK technique and MBC behavior,
listing rule names and namespaces. It parses an existing report file; it does not run capa or the
sample itself.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def summarize(report: dict) -> dict:
    rules = report.get("rules", {})
    by_attack = defaultdict(list)
    by_mbc = defaultdict(list)
    namespaces = defaultdict(list)
    for name, rule in rules.items():
        meta = rule.get("meta", {})
        for att in meta.get("attack", []) or meta.get("att&ck", []):
            label = att.get("id") or att.get("technique") if isinstance(att, dict) else str(att)
            by_attack[str(label)].append(name)
        for mbc in meta.get("mbc", []):
            label = mbc.get("id") or mbc.get("behavior") if isinstance(mbc, dict) else str(mbc)
            by_mbc[str(label)].append(name)
        ns = meta.get("namespace", "")
        if ns:
            namespaces[ns].append(name)
    return {
        "rule_count": len(rules),
        "by_attack": {k: sorted(v) for k, v in sorted(by_attack.items())},
        "by_mbc": {k: sorted(v) for k, v in sorted(by_mbc.items())},
        "by_namespace": {k: len(v) for k, v in sorted(namespaces.items())},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize a capa JSON report")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("summarize")
    p.add_argument("file", help="capa JSON report")
    args = parser.parse_args(argv)
    report = json.loads(Path(args.file).read_text(encoding="utf-8"))
    print(json.dumps(summarize(report), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
