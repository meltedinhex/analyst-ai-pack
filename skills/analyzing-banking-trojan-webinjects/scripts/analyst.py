#!/usr/bin/env python3
"""Parse banking trojan webinject configs (Zeus/SpyEye-style) into structured entries.

Parses set_url / data_before / data_inject / data_after blocks, extracts the targeted URL pattern
and injected snippet, classifies the injection technique, and extracts/defangs exfil endpoints.
Parses config text only; executes nothing and does not render injected code.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RE_SETURL = re.compile(r"set_url\s+(\S+)(?:\s+(\S+))?", re.I)
RE_BLOCK = re.compile(
    r"data_(before|inject|after)\b(.*?)data_end", re.I | re.S)
RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)

TECHNIQUE_HINTS = {
    "form_grabbing": ["onsubmit", "form", "addeventlistener", "password"],
    "fake_fields": ["ssn", "social security", "pin", "card number", "cvv", "mother",
                    "date of birth", "atm"],
    "mfa_interception": ["otp", "one-time", "token", "2fa", "verification code", "sms code"],
    "balance_manipulation": ["balance", "innerhtml", "replace"],
}


def parse(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    entries = []
    # Split on set_url boundaries to associate each target with its following blocks.
    chunks = re.split(r"(?=set_url\s)", text, flags=re.I)
    for chunk in chunks:
        m = RE_SETURL.search(chunk)
        if not m:
            continue
        target = m.group(1)
        inject = ""
        for bname, body in RE_BLOCK.findall(chunk):
            if bname.lower() == "inject":
                inject = body.strip()
        low = inject.lower()
        techniques = [t for t, needles in TECHNIQUE_HINTS.items()
                      if any(n in low for n in needles)]
        exfil = sorted({u.replace("http", "hxxp").replace(".", "[.]")
                        for u in RE_URL.findall(inject)})
        entries.append({
            "target_url": target,
            "techniques": techniques,
            "exfil_endpoints": exfil,
            "inject_preview": inject[:160],
        })
    targets = sorted({e["target_url"] for e in entries})
    return {
        "webinject_count": len(entries),
        "targeted_url_patterns": targets,
        "entries": entries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse banking trojan webinjects")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("parse")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(parse(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
