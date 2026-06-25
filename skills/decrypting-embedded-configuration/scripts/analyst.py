#!/usr/bin/env python3
"""Brute-force common embedded-config encryption schemes and score config-like output.

Supports single-byte XOR brute force, multi-byte repeating-key XOR, and RC4. Scores each candidate
plaintext by printable ratio and presence of config tokens, and defangs recovered endpoints. Reads
the ciphertext blob statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CONFIG_TOKENS = [b"http", b".php", b"id=", b"botnet", b"campaign", b".onion", b"User-Agent",
                 b"POST", b"Mozilla"]
RE_IP = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_URL = re.compile(rb"https?://[\x21-\x7e]{4,}")


def _score(data: bytes) -> int:
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (9, 10, 13))
    ratio = printable / max(len(data), 1)
    score = int(ratio * 100)
    score += 10 * sum(1 for t in CONFIG_TOKENS if t in data)
    score += 5 * len(RE_IP.findall(data))
    return score


def _defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def _endpoints(data: bytes) -> list[str]:
    out = {_defang(m.decode("ascii", "ignore")) for m in RE_URL.findall(data)}
    out |= {_defang(m.decode("ascii", "ignore")) for m in RE_IP.findall(data)}
    return sorted(out)


def rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def xor_brute(data: bytes) -> dict:
    best = []
    for key in range(256):
        dec = bytes(b ^ key for b in data)
        best.append((_score(dec), key, dec))
    best.sort(reverse=True, key=lambda t: t[0])
    top = best[:3]
    return {"candidates": [
        {"key": hex(k), "score": s, "endpoints": _endpoints(d),
         "preview": d[:80].decode("ascii", "replace")} for s, k, d in top]}


def xor_key(data: bytes, key: bytes) -> dict:
    dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return {"score": _score(dec), "endpoints": _endpoints(dec),
            "preview": dec[:120].decode("ascii", "replace")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decrypt embedded config blobs")
    sub = parser.add_subparsers(dest="cmd", required=True)
    px = sub.add_parser("xor")
    px.add_argument("file")
    pr = sub.add_parser("rc4")
    pr.add_argument("file")
    pr.add_argument("--key", required=True)
    pk = sub.add_parser("xorkey")
    pk.add_argument("file")
    pk.add_argument("--key", required=True, help="comma list e.g. 0x11,0x22")
    args = parser.parse_args(argv)
    data = Path(args.file).read_bytes()
    if args.cmd == "xor":
        print(json.dumps(xor_brute(data), indent=2))
    elif args.cmd == "rc4":
        dec = rc4(data, args.key.encode())
        print(json.dumps({"score": _score(dec), "endpoints": _endpoints(dec),
                          "preview": dec[:120].decode("ascii", "replace")}, indent=2))
    else:
        key = bytes(int(x, 0) for x in args.key.split(","))
        print(json.dumps(xor_key(data, key), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
