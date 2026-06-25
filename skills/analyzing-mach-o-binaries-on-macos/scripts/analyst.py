#!/usr/bin/env python3
"""Parse a Mach-O (or fat/universal) binary header and key load commands.

Detects fat vs. thin Mach-O, enumerates architecture slices, and parses load commands for linked
dylibs, the main entry point, and the presence of a code signature. Uses stdlib ``struct`` only.
It parses bytes statically and never executes the sample.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECF

LC_LOAD_DYLIB = 0x0C
LC_MAIN = 0x80000028
LC_CODE_SIGNATURE = 0x1D


def _u32(data: bytes, off: int, be: bool) -> int:
    return struct.unpack_from(">I" if be else "<I", data, off)[0]


def parse_thin(data: bytes, base: int) -> dict:
    magic = struct.unpack_from(">I", data, base)[0]
    be = magic in (MH_MAGIC, MH_MAGIC_64)
    is64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    hdr = base
    ncmds = _u32(data, hdr + 16, be)
    off = hdr + (32 if is64 else 28)
    dylibs, signed, entry = [], False, None
    for _ in range(ncmds):
        cmd = _u32(data, off, be)
        cmdsize = _u32(data, off + 4, be)
        if cmdsize == 0:
            break
        if cmd == LC_LOAD_DYLIB:
            name_off = _u32(data, off + 8, be)
            raw = data[off + name_off:off + cmdsize].split(b"\x00", 1)[0]
            dylibs.append(raw.decode("latin-1"))
        elif cmd == (LC_MAIN & 0xFFFFFFFF) or cmd == LC_MAIN:
            entry = "LC_MAIN"
        elif cmd == LC_CODE_SIGNATURE:
            signed = True
        off += cmdsize
    return {"arch": "64-bit" if is64 else "32-bit", "dylibs": dylibs,
            "has_code_signature": signed, "entry": entry}


def parse(path: str) -> dict:
    data = Path(path).read_bytes()
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_CIGAM):
        nfat = struct.unpack_from(">I", data, 4)[0]
        slices = []
        for i in range(nfat):
            entry_off = 8 + i * 20
            offset = struct.unpack_from(">I", data, entry_off + 8)[0]
            slices.append(parse_thin(data, offset))
        return {"format": "fat/universal", "slice_count": nfat, "slices": slices}
    if magic in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64):
        return {"format": "thin Mach-O", **parse_thin(data, 0)}
    return {"error": "not a Mach-O binary"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse Mach-O header/load commands")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("header")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(parse(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
