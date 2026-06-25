#!/usr/bin/env python3
"""Identify position-independent code techniques in a shellcode blob.

Scans for GetPC stubs, PEB access (x86/x64), API-hash loops, and stack-string construction, and
infers architecture from the PEB-access form. Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TECHNIQUES = {
    "getpc_call_pop": [b"\xe8\x00\x00\x00\x00"],            # call $+5
    "getpc_fnstenv": [b"\xd9\xee\xd9\x74\x24\xf4"],         # fldz; fnstenv [esp-0xc]
    "peb_access_x86": [b"\x64\xa1\x30\x00\x00\x00", b"\x64\x8b\x0d\x30", b"\x64\x8b\x15\x30"],
    "peb_access_x64": [b"\x65\x48\x8b", b"\x65\x4c\x8b"],   # gs:[..]
    "api_hash_ror13": [b"\xac", b"\xc1\xcf\x0d", b"\xc1\xca\x0d"],  # lodsb; ror reg,13
    "stack_strings": [b"\xc6\x44\x24", b"\xc7\x44\x24"],    # mov byte/dword [esp+x], imm
}


def analyze(path: str) -> dict:
    data = Path(path).read_bytes()
    found = {name: True for name, sigs in TECHNIQUES.items()
             if any(s in data for s in sigs)}
    arch = ("x64" if "peb_access_x64" in found
            else "x86" if "peb_access_x86" in found else "unknown")
    return {
        "size": len(data),
        "techniques": sorted(found.keys()),
        "inferred_arch": arch,
        "uses_peb_walk": "peb_access_x86" in found or "peb_access_x64" in found,
        "uses_api_hashing": "api_hash_ror13" in found,
        "is_position_independent": bool(found),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze position-independent code")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
