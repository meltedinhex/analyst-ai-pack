#!/usr/bin/env python3
"""Hunt for malware configuration indicators in a process memory dump.

Scans a raw memory dump for URLs, IPv4:port pairs, mutex-like tokens, and base64 blobs, and
attempts single-byte XOR / base64 decoding of candidate blobs to surface hidden endpoints.
Reads bytes statically; executes nothing. Defangs recovered hosts.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

RE_URL = re.compile(rb"https?://[\x21-\x7e]{4,}")
RE_IPPORT = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b")
RE_MUTEX = re.compile(rb"(?:Global|Local)\\[\x21-\x7e]{4,40}")
RE_B64 = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")


def _defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def _xor_scan(blob: bytes) -> list[str]:
    found = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in blob)
        for m in RE_URL.findall(dec) + RE_IPPORT.findall(dec):
            found.append(f"xor:{key:#04x} {_defang(m.decode('ascii', 'ignore'))}")
    return sorted(set(found))[:20]


def hunt(path: str) -> dict:
    data = Path(path).read_bytes()
    urls = sorted({_defang(m.decode("ascii", "ignore")) for m in RE_URL.findall(data)})
    ipports = sorted({_defang(m.decode("ascii", "ignore")) for m in RE_IPPORT.findall(data)})
    mutexes = sorted({m.decode("ascii", "ignore") for m in RE_MUTEX.findall(data)})
    decoded_hits = []
    for blob in RE_B64.findall(data)[:2000]:
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        for m in RE_URL.findall(raw) + RE_IPPORT.findall(raw):
            decoded_hits.append("b64 " + _defang(m.decode("ascii", "ignore")))
    return {
        "urls": urls[:50],
        "ip_port_pairs": ipports[:50],
        "mutexes": mutexes[:50],
        "base64_decoded_endpoints": sorted(set(decoded_hits))[:50],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt config indicators in a memory dump")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("dump")
    p2 = sub.add_parser("xor")
    p2.add_argument("dump")
    args = parser.parse_args(argv)
    if args.cmd == "xor":
        print(json.dumps({"xor_endpoints": _xor_scan(Path(args.dump).read_bytes())}, indent=2))
    else:
        print(json.dumps(hunt(args.dump), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
