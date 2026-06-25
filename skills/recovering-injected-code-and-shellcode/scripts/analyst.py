#!/usr/bin/env python3
"""Identify and triage a carved memory region as an injected PE or raw shellcode.

Detects an embedded MZ/PE header (reporting its offset and architecture) and scans for common
position-independent code markers (GetPC stubs, PEB access, API-hash loops). Reads bytes
statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

MACHINE = {0x14c: "x86", 0x8664: "x64", 0x1c0: "arm", 0xaa64: "arm64"}

PIC_HINTS = {
    "getpc_callpop": [b"\xe8\x00\x00\x00\x00", b"\xd9\xee\xd9\x74\x24\xf4"],  # call$+5, fldz/fnstenv
    "peb_access_x86": [b"\x64\xa1\x30\x00\x00\x00", b"\x64\x8b"],            # fs:[30]
    "peb_access_x64": [b"\x65\x48\x8b", b"\x65\x4c\x8b"],                    # gs:[60]
    "api_hash_loop": [b"\xac", b"\xc1\xcf\x0d", b"\xc1\xca\x0d"],            # lodsb + ror13
}


def _pe_at(data: bytes, off: int) -> dict | None:
    if data[off:off + 2] != b"MZ" or off + 0x40 > len(data):
        return None
    e_lfanew = struct.unpack_from("<I", data, off + 0x3c)[0]
    pe = off + e_lfanew
    if pe + 6 > len(data) or data[pe:pe + 4] != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    return {"offset": off, "machine": MACHINE.get(machine, hex(machine))}


def identify(path: str) -> dict:
    data = Path(path).read_bytes()
    pes = []
    start = 0
    while True:
        idx = data.find(b"MZ", start)
        if idx == -1:
            break
        info = _pe_at(data, idx)
        if info:
            pes.append(info)
        start = idx + 1
        if len(pes) > 20:
            break
    hints = {name: True for name, sigs in PIC_HINTS.items() if any(s in data for s in sigs)}
    return {
        "size": len(data),
        "embedded_pe": pes,
        "is_pe": bool(pes),
        "shellcode_hints": sorted(hints.keys()),
        "likely_raw_shellcode": not pes and bool(hints),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Identify injected PE / shellcode in a region")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("identify")
    p.add_argument("region")
    args = parser.parse_args(argv)
    print(json.dumps(identify(args.region), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
