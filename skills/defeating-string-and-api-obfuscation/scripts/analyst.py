#!/usr/bin/env python3
"""Recover XOR-obfuscated strings and resolve API hashes.

Two original utilities for deobfuscation triage:
- ``xor-strings``: brute-force single-byte XOR over a file and surface readable strings.
- ``api-hash``: compute common API-name hashes (ROR13/ROR7/djb2) and match a target constant
  against a provided or built-in list of export names.

Reads bytes/text only; never executes the sample.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_READABLE = re.compile(rb"[\x20-\x7e]{5,}")

COMMON_APIS = [
    "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
    "WriteProcessMemory", "CreateRemoteThread", "CreateProcessA", "WinExec",
    "InternetOpenA", "InternetConnectA", "HttpSendRequestA", "URLDownloadToFileA",
    "RegSetValueExA", "CreateFileA", "WriteFile", "ReadFile", "CloseHandle",
    "GetProcAddress", "ExitProcess", "Sleep", "WSAStartup", "connect", "send", "recv",
]


def _ror(val: int, bits: int, width: int = 32) -> int:
    mask = (1 << width) - 1
    val &= mask
    return ((val >> bits) | (val << (width - bits))) & mask


def hash_ror13(name: str) -> int:
    h = 0
    for ch in name.encode() + b"\x00":
        h = (_ror(h, 13) + ch) & 0xFFFFFFFF
    return h


def hash_ror7(name: str) -> int:
    h = 0
    for ch in name.encode():
        h = (_ror(h, 7) + ch) & 0xFFFFFFFF
    return h


def hash_djb2(name: str) -> int:
    h = 5381
    for ch in name.encode():
        h = ((h * 33) + ch) & 0xFFFFFFFF
    return h


_ALGOS = {"ror13": hash_ror13, "ror7": hash_ror7, "djb2": hash_djb2}


def xor_strings(data: bytes, min_hits: int = 3) -> list[dict]:
    results = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        hits = [m.group(0).decode("ascii", "replace")
                for m in _READABLE.finditer(decoded)]
        interesting = [s for s in hits
                       if re.search(r"https?://|\.dll|\.exe|\\|[A-Z][a-z]+[A-Z]", s)]
        if len(interesting) >= min_hits:
            results.append({"key": hex(key), "samples": interesting[:20],
                            "count": len(interesting)})
    return sorted(results, key=lambda r: r["count"], reverse=True)[:5]


def resolve_hash(algo: str, target: int, names: list[str]) -> list[str]:
    fn = _ALGOS[algo]
    return [n for n in names if fn(n) == (target & 0xFFFFFFFF)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Defeat string/API obfuscation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_x = sub.add_parser("xor-strings", help="brute single-byte XOR for readable strings")
    p_x.add_argument("file")

    p_h = sub.add_parser("api-hash", help="match an API hash to a function name")
    p_h.add_argument("--algo", choices=sorted(_ALGOS), required=True)
    p_h.add_argument("--hash", required=True, help="target hash, e.g. 0x726774C")
    p_h.add_argument("--names", help="optional file of candidate API names (one per line)")

    args = parser.parse_args(argv)
    if args.cmd == "xor-strings":
        data = Path(args.file).read_bytes()
        print(json.dumps(xor_strings(data), indent=2))
        return 0

    names = COMMON_APIS
    if args.names:
        names = [n.strip() for n in Path(args.names).read_text().splitlines() if n.strip()]
    target = int(args.hash, 0)
    matches = resolve_hash(args.algo, target, names)
    print(json.dumps({"algo": args.algo, "hash": hex(target),
                      "matches": matches}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
