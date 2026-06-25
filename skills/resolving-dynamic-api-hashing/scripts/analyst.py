#!/usr/bin/env python3
"""Resolve dynamically hashed API names by brute-forcing hash constants over a wordlist.

Implements common malware API-hash algorithms (ROR13 add, djb2, FNV-1a, CRC32) and matches a list
of observed 32-bit hash constants against a names wordlist. Pure computation over names; never
loads or executes the sample.
"""
from __future__ import annotations

import argparse
import binascii
import json
import sys
from pathlib import Path

DEFAULT_NAMES = [
    "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "CreateRemoteThread", "CreateProcessA", "WinExec", "ExitProcess",
    "GetModuleHandleA", "CreateFileA", "WriteFile", "ReadFile", "InternetOpenA",
    "InternetConnectA", "HttpSendRequestA", "URLDownloadToFileA", "RegSetValueExA",
    "CryptDecrypt", "kernel32.dll", "ntdll.dll", "wininet.dll", "advapi32.dll",
]


def ror32(v: int, n: int) -> int:
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def ror13_add(name: str) -> int:
    h = 0
    for ch in name.encode("ascii", "ignore"):
        h = ror32(h, 13)
        h = (h + ch) & 0xFFFFFFFF
    return h


def djb2(name: str) -> int:
    h = 5381
    for ch in name.encode("ascii", "ignore"):
        h = ((h * 33) + ch) & 0xFFFFFFFF
    return h


def fnv1a(name: str) -> int:
    h = 0x811C9DC5
    for ch in name.encode("ascii", "ignore"):
        h = ((h ^ ch) * 0x01000193) & 0xFFFFFFFF
    return h


def crc32(name: str) -> int:
    return binascii.crc32(name.encode("ascii", "ignore")) & 0xFFFFFFFF


ALGOS = {"ror13": ror13_add, "djb2": djb2, "fnv1a": fnv1a, "crc32": crc32}


def identify(value: int) -> dict:
    matches = {}
    for algo, fn in ALGOS.items():
        for name in DEFAULT_NAMES:
            if fn(name) == value:
                matches.setdefault(algo, []).append(name)
    return {"value": hex(value), "matches": matches,
            "note": "matched against a small seed list; use resolve with a full wordlist"}


def resolve(hashes: list[int], algo: str, names: list[str]) -> dict:
    fn = ALGOS[algo]
    table = {fn(n): n for n in names}
    resolved = {hex(h): table.get(h) for h in hashes}
    return {
        "algorithm": algo,
        "resolved": {k: v for k, v in resolved.items() if v},
        "unresolved": [k for k, v in resolved.items() if not v],
    }


def _read_hashes(path: str) -> list[int]:
    out = []
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line:
            out.append(int(line, 0))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve API hashes")
    sub = parser.add_subparsers(dest="cmd", required=True)
    pid = sub.add_parser("id")
    pid.add_argument("value")
    pr = sub.add_parser("resolve")
    pr.add_argument("hashes_file")
    pr.add_argument("--algo", choices=list(ALGOS), required=True)
    pr.add_argument("--wordlist")
    args = parser.parse_args(argv)
    if args.cmd == "id":
        print(json.dumps(identify(int(args.value, 0)), indent=2))
    else:
        names = (Path(args.wordlist).read_text(encoding="utf-8-sig").split()
                 if args.wordlist else DEFAULT_NAMES)
        print(json.dumps(resolve(_read_hashes(args.hashes_file), args.algo, names), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
