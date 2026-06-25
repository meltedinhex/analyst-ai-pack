#!/usr/bin/env python3
"""Scaffold a valid Sigma detection rule skeleton.

Emits a Sigma YAML rule with a pinned logsource, a selection/filter pattern, ATT&CK tags, level,
and a falsepositives list for the analyst to complete. It emits text only; it does not validate
or convert (use sigma-cli for that).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys


def scaffold(title: str, category: str, technique: str, level: str, author: str) -> str:
    today = _dt.date.today().isoformat()
    tag = technique.lower().replace("t", "attack.t", 1) if technique.startswith("T") else technique
    return f"""title: {title}
id: <generate-a-uuid>
status: experimental
description: Detects {title.lower()} (drafted from a hunt finding).
author: {author}
date: {today}
references:
    - <analysis report or hunt link>
logsource:
    product: windows
    category: {category}
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - 'FromBase64String'
    filter_known_good:
        ParentImage|endswith:
            - '\\trusted_admin_tool.exe'
    condition: selection and not filter_known_good
falsepositives:
    - Administrative scripts that legitimately use encoded commands
level: {level}
tags:
    - {tag}
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scaffold a Sigma rule")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scaffold")
    p.add_argument("--title", required=True)
    p.add_argument("--category", default="process_creation")
    p.add_argument("--technique", default="T1059.001")
    p.add_argument("--level", default="high",
                   choices=["informational", "low", "medium", "high", "critical"])
    p.add_argument("--author", default="analyst-ai-pack")
    args = parser.parse_args(argv)
    print(scaffold(args.title, args.category, args.technique, args.level, args.author))
    return 0


if __name__ == "__main__":
    sys.exit(main())
