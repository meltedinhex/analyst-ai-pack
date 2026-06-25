#!/usr/bin/env python3
"""Scan collected Linux persistence artifacts for suspicious entries.

Recursively reads text files under a collected directory and flags persistence-relevant lines
containing download-exec, reverse-shell, suspicious-path, or authorized_keys patterns, grouped by
mechanism inferred from the file path. Reads files statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MECHANISMS = {
    "cron": ["cron", "crontab"],
    "systemd": ["systemd", ".service", ".timer"],
    "rc_profile": [".bashrc", ".bash_profile", ".profile", "rc.local", "/etc/profile"],
    "ssh_keys": ["authorized_keys"],
    "autostart": ["xdg/autostart", ".config/autostart", "init.d"],
}

SUSPICIOUS = [
    re.compile(r"(curl|wget)\s+[^|]+\|\s*(sh|bash)", re.I),
    re.compile(r"base64\s+-d.*\|\s*(sh|bash)", re.I),
    re.compile(r"nc(at)?\s+.*-e\b", re.I),
    re.compile(r"/dev/tcp/\d", re.I),
    re.compile(r"bash\s+-i\b", re.I),
    re.compile(r"python[0-9.]*\s+-c\s+.*socket", re.I),
    re.compile(r"(/tmp/|/dev/shm/)\S+", re.I),
]


def _mechanism(path_str: str) -> str:
    low = path_str.lower()
    for mech, needles in MECHANISMS.items():
        if any(n in low for n in needles):
            return mech
    return "other"


def scan(root: str) -> dict:
    base = Path(root)
    findings = []
    files = [base] if base.is_file() else base.rglob("*")
    for fp in files:
        if not fp.is_file():
            continue
        try:
            text = fp.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            continue
        mech = _mechanism(str(fp))
        for n, line in enumerate(text.splitlines(), 1):
            for pat in SUSPICIOUS:
                if pat.search(line):
                    findings.append({"file": str(fp), "mechanism": mech, "line": n,
                                     "match": line.strip()[:200]})
                    break
            if mech == "ssh_keys" and line.strip().startswith(("ssh-", "ecdsa-", "sk-")):
                findings.append({"file": str(fp), "mechanism": "ssh_keys", "line": n,
                                 "match": "authorized_key: " + line.strip()[:80]})
    by_mech: dict[str, int] = {}
    for f in findings:
        by_mech[f["mechanism"]] = by_mech.get(f["mechanism"], 0) + 1
    return {"findings": findings[:200], "by_mechanism": by_mech, "total": len(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan Linux persistence artifacts")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan")
    p.add_argument("path")
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.path), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
