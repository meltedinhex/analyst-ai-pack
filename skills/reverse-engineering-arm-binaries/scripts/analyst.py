#!/usr/bin/env python3
"""Identify ARM/AArch64 binary architecture, endianness, entry point, and Thumb state.

Parses ELF and Mach-O headers to report the ARM machine type, bitness, endianness, and entry
point, flagging Thumb entry for 32-bit ARM ELF (low bit of e_entry). Reads bytes statically;
executes nothing. Capstone (optional) can be used downstream for actual decoding.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

ELF_MACHINE = {0x28: "ARM (32-bit)", 0xB7: "AArch64 (64-bit)"}
MACHO_CPU = {0x0000000C: "ARM (32-bit)", 0x0100000C: "AArch64 (64-bit)"}


def _parse_elf(data: bytes) -> dict:
    ei_class = data[4]   # 1=32, 2=64
    ei_data = data[5]    # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    if ei_class == 1:
        entry = struct.unpack_from(endian + "I", data, 24)[0]
    else:
        entry = struct.unpack_from(endian + "Q", data, 24)[0]
    thumb = bool(machine == 0x28 and (entry & 1))
    return {
        "format": "ELF",
        "architecture": ELF_MACHINE.get(machine, hex(machine)),
        "endianness": "little" if ei_data == 1 else "big",
        "entry_point": hex(entry & ~1 if thumb else entry),
        "thumb_entry": thumb,
    }


def _parse_macho(data: bytes) -> dict:
    magic = struct.unpack_from("<I", data, 0)[0]
    big = magic in (0xFEEDFACF, 0xFEEDFACE) and data[0] == 0xFE
    endian = ">" if big else "<"
    cputype = struct.unpack_from(endian + "I", data, 4)[0]
    return {
        "format": "Mach-O",
        "architecture": MACHO_CPU.get(cputype, hex(cputype)),
        "endianness": "big" if big else "little",
        "entry_point": "parse LC_MAIN/LC_UNIXTHREAD for entry",
        "thumb_entry": False,
    }


def identify(path: str) -> dict:
    data = Path(path).read_bytes()
    if data[:4] == b"\x7fELF":
        return _parse_elf(data)
    if struct.unpack_from("<I", data, 0)[0] in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        return _parse_macho(data)
    return {"error": "not an ELF or Mach-O binary"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Identify ARM/AArch64 binaries")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("identify")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(identify(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
