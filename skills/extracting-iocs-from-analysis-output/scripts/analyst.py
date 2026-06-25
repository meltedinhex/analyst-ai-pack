#!/usr/bin/env python3
"""Extract and type indicators of compromise from raw analysis text.

Scans text for URLs, domains, IPv4 addresses, emails, and hashes using validated patterns,
filters common benign noise (RFC1918, localhost, well-known service domains), and deduplicates.
It reads a local text file only and performs no network activity.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RE_URL = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.I)
RE_SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.I)
RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)

BENIGN_DOMAINS = {"microsoft.com", "windows.com", "msftncsi.com", "schemas.xmlsoap.org",
                  "w3.org", "verisign.com", "digicert.com", "localhost"}


def _is_private(ip: str) -> bool:
    parts = [int(x) for x in ip.split(".")]
    return (parts[0] == 10 or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168) or parts[0] == 127)


def _benign_domain(d: str) -> bool:
    return any(d.lower() == b or d.lower().endswith("." + b) for b in BENIGN_DOMAINS)


def extract(text: str) -> dict:
    filtered = []
    urls = sorted(set(RE_URL.findall(text)))
    ips = sorted({ip for ip in RE_IPV4.findall(text) if not _is_private(ip)})
    emails = sorted(set(RE_EMAIL.findall(text)))
    domains = sorted({d for d in RE_DOMAIN.findall(text)
                      if not RE_IPV4.fullmatch(d) and not _benign_domain(d)})
    hashes = sorted(set(RE_SHA256.findall(text)) | set(RE_SHA1.findall(text))
                    | set(RE_MD5.findall(text)))
    return {
        "indicators": {"urls": urls, "domains": domains, "ipv4": ips,
                       "emails": emails, "hashes": hashes},
        "counts": {"urls": len(urls), "domains": len(domains), "ipv4": len(ips),
                   "emails": len(emails), "hashes": len(hashes)},
        "filtered_note": "private IPs and well-known service domains removed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract IOCs from analysis output")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract")
    p.add_argument("file")
    args = parser.parse_args(argv)
    text = Path(args.file).read_text(encoding="utf-8-sig", errors="replace")
    print(json.dumps(extract(text), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
