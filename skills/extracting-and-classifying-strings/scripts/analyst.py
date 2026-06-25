#!/usr/bin/env python3
"""Extract ASCII and UTF-16LE strings from a binary and classify them.

Scans the inert file for printable ASCII runs and UTF-16LE runs at a minimum length, then buckets
results into investigative categories (urls, ips, paths, registry, mutex/event, commands, apis).
It reads bytes only and never executes the sample.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PRINTABLE = rb"[\x20-\x7e]"


def ascii_strings(data: bytes, min_len: int) -> list[str]:
    pat = re.compile(PRINTABLE + b"{%d,}" % min_len)
    return [m.decode("latin-1") for m in pat.findall(data)]


def unicode_strings(data: bytes, min_len: int) -> list[str]:
    # UTF-16LE: printable byte followed by 0x00, repeated
    pat = re.compile(b"(?:" + PRINTABLE + b"\x00){%d,}" % min_len)
    out = []
    for m in pat.findall(data):
        out.append(m.decode("utf-16-le", errors="replace"))
    return out


CATEGORIES = {
    "urls": re.compile(r"https?://[^\s\"'<>]+", re.I),
    "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "paths": re.compile(r"[a-zA-Z]:\\[^\s\"'<>|]+|/(?:usr|etc|tmp|var|home)/[^\s\"'<>|]+"),
    "registry": re.compile(r"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"'<>|]+", re.I),
    "commands": re.compile(r"\b(?:cmd\.exe|powershell|rundll32|regsvr32|schtasks|net\s+user)\b",
                           re.I),
    "apis": re.compile(r"\b(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary|"
                       r"GetProcAddress|WinExec|URLDownloadToFile)\w*", re.I),
}


def classify(strings: list[str]) -> dict:
    buckets: dict[str, set] = {k: set() for k in CATEGORIES}
    for s in strings:
        for cat, rx in CATEGORIES.items():
            for m in rx.findall(s):
                buckets[cat].add(m)
    return {k: sorted(v) for k, v in buckets.items() if v}


def run(path: str, min_len: int) -> dict:
    data = Path(path).read_bytes()
    a = ascii_strings(data, min_len)
    u = unicode_strings(data, min_len)
    allstr = a + u
    return {
        "ascii_count": len(a),
        "unicode_count": len(u),
        "categorized": classify(allstr),
        "obfuscation_hint": len(allstr) < 20,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract and classify strings")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("strings")
    p.add_argument("file")
    p.add_argument("--min-len", type=int, default=5)
    args = parser.parse_args(argv)
    print(json.dumps(run(args.file, args.min_len), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
