#!/usr/bin/env python3
"""Lint Suricata/Snort IDS rules for common correctness and noise problems.

Checks each rule line for required metadata (msg, sid, rev, classtype), balanced quotes and
parentheses, duplicate SIDs, and overly short free-floating content matches that tend to cause
false positives. Parses rule text only; executes nothing and does not load any IDS engine.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RE_SID = re.compile(r"\bsid\s*:\s*(\d+)")
RE_REV = re.compile(r"\brev\s*:\s*\d+")
RE_MSG = re.compile(r"\bmsg\s*:\s*\"")
RE_CLASSTYPE = re.compile(r"\bclasstype\s*:")
RE_CONTENT = re.compile(r"content\s*:\s*\"([^\"]*)\"")
ANCHOR_KEYWORDS = ["http.uri", "http.host", "http.header", "tls.sni", "dns.query", "flow:",
                   "offset", "depth", "within", "distance", "http.user_agent", "file.data"]


def _balanced(line: str) -> bool:
    return line.count('"') % 2 == 0 and line.count("(") == line.count(")")


def lint(path: str) -> dict:
    lines = Path(path).read_text(encoding="utf-8-sig", errors="replace").splitlines()
    seen_sids: dict[str, int] = {}
    issues = []
    rule_count = 0
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rule_count += 1
        problems = []
        if not RE_MSG.search(line):
            problems.append("missing msg")
        msid = RE_SID.search(line)
        if not msid:
            problems.append("missing sid")
        else:
            sid = msid.group(1)
            if sid in seen_sids:
                problems.append(f"duplicate sid {sid} (also line {seen_sids[sid]})")
            else:
                seen_sids[sid] = n
        if not RE_REV.search(line):
            problems.append("missing rev")
        if not RE_CLASSTYPE.search(line):
            problems.append("missing classtype")
        if not _balanced(line):
            problems.append("unbalanced quotes/parentheses")
        anchored = any(k in line for k in ANCHOR_KEYWORDS)
        for content in RE_CONTENT.findall(line):
            if len(content) <= 3 and not anchored:
                problems.append(f"short unanchored content '{content}'")
        if problems:
            issues.append({"line": n, "problems": problems})
    return {"rules_checked": rule_count, "issue_count": len(issues), "issues": issues}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint Suricata/Snort rules")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lint")
    p.add_argument("rules")
    args = parser.parse_args(argv)
    result = lint(args.rules)
    print(json.dumps(result, indent=2))
    return 1 if result["issue_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
