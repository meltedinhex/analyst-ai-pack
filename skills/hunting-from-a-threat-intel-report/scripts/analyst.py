#!/usr/bin/env python3
"""Extract IOCs and ATT&CK technique IDs from a threat-intel report.

Parses report text for defanged/refanged indicators (IPv4, domains, URLs, hashes) and ATT&CK
technique IDs, normalizes and defangs them for safe handling, and ranks indicator classes by the
Pyramid of Pain. It reads a local text file only; it performs no lookups or connections.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# refang first so bracketed indicators are matched
REFANG = [("[.]", "."), ("(.)", "."), ("[dot]", "."), ("hxxp", "http"), ("[:]", ":")]

RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL = re.compile(r"\bhttps?://[^\s)>\]]+", re.I)
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

PYRAMID = {  # higher = more pain for the adversary to change
    "techniques": 6, "tools": 5, "network_artifacts": 4, "domains": 3, "ips": 2, "hashes": 1,
}


def refang(text: str) -> str:
    for a, b in REFANG:
        text = text.replace(a, b)
    return text


def defang(ind: str) -> str:
    return ind.replace("http", "hxxp").replace(".", "[.]")


def extract(text: str) -> dict:
    refanged = refang(text)
    urls = sorted(set(RE_URL.findall(refanged)))
    ips = sorted(set(RE_IPV4.findall(refanged)))
    hashes = sorted(set(RE_MD5.findall(refanged)) | set(RE_SHA1.findall(refanged))
                    | set(RE_SHA256.findall(refanged)))
    # domains: exclude those that are just the host part of found URLs duplicates
    domains = sorted({d for d in RE_DOMAIN.findall(refanged)
                      if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", d)})
    techniques = sorted(set(RE_TECH.findall(text)))
    return {
        "techniques": techniques,
        "indicators": {
            "urls": [defang(u) for u in urls],
            "domains": [defang(d) for d in domains],
            "ips": [ip.replace(".", "[.]") for ip in ips],
            "hashes": hashes,
        },
        "priority_guidance": dict(sorted(PYRAMID.items(), key=lambda kv: kv[1], reverse=True)),
        "note": "Hunt techniques/tools first (high pain); sweep hashes/IPs as a quick pass.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract IOCs/TTPs from a report")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract")
    p.add_argument("file", help="threat-intel report text file")
    args = parser.parse_args(argv)
    text = Path(args.file).read_text(encoding="utf-8-sig", errors="replace")
    print(json.dumps(extract(text), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
