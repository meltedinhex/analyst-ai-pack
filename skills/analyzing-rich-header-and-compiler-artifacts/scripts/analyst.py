#!/usr/bin/env python3
"""Parse and decode the PE Rich header to fingerprint the build toolchain.

Locates the 'Rich' marker, recovers the XOR key, decodes the DanS-prefixed comp.id entries, and
emits (product_id, build_id, use_count) tuples plus a clustering hash. Reads bytes statically;
executes nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


def _find_rich(data: bytes) -> tuple[int, int] | None:
    # Rich header lives between the DOS stub and PE header (first 0x200 bytes typically).
    head = data[:0x400]
    rich_off = head.rfind(b"Rich")
    if rich_off == -1:
        return None
    key = struct.unpack_from("<I", head, rich_off + 4)[0]
    return rich_off, key


def _find_dans(data: bytes, rich_off: int, key: int) -> int | None:
    # Scan backwards for the XOR-encoded 'DanS' (0x536e6144) signature.
    for off in range(rich_off - 4, 0, -4):
        if struct.unpack_from("<I", data, off)[0] ^ key == 0x536E6144:
            return off
    return None


def rich(path: str) -> dict:
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        return {"error": "not a PE"}
    found = _find_rich(data)
    if not found:
        return {"has_rich_header": False}
    rich_off, key = found
    dans_off = _find_dans(data, rich_off, key)
    if dans_off is None:
        return {"has_rich_header": True, "error": "DanS not found", "xor_key": hex(key)}
    entries = []
    # Entries start after DanS + 3 padding DWORDs, run until the Rich marker.
    off = dans_off + 16
    while off + 8 <= rich_off:
        comp = struct.unpack_from("<I", data, off)[0] ^ key
        count = struct.unpack_from("<I", data, off + 4)[0] ^ key
        product_id = comp >> 16
        build_id = comp & 0xFFFF
        entries.append({"product_id": product_id, "build_id": build_id, "use_count": count})
        off += 8
    fingerprint = hashlib.sha256(
        json.dumps(entries, sort_keys=True).encode()).hexdigest()[:16]
    return {
        "has_rich_header": True,
        "xor_key": hex(key),
        "entry_count": len(entries),
        "entries": entries,
        "toolchain_fingerprint": fingerprint,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode the PE Rich header")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("rich")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(rich(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
