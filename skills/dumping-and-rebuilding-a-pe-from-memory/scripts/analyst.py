#!/usr/bin/env python3
"""Inspect and realign a memory-dumped PE toward a loadable layout.

`inspect` reports section raw-vs-virtual alignment and the entry point. `fix` rewrites each
section's PointerToRawData/SizeOfRawData to match its virtual layout (the standard convention for
files reconstructed from memory) and sets AddressOfEntryPoint to a supplied OEP. Operates on file
bytes only; executes nothing. Import reconstruction is left to a dedicated tool.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path


def _pe_offsets(data: bytes):
    if data[:2] != b"MZ":
        raise ValueError("not a PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("bad PE signature")
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt_off = e_lfanew + 24
    sect_off = opt_off + opt_size
    return e_lfanew, opt_off, sect_off, num_sections


def inspect(path: str) -> dict:
    data = Path(path).read_bytes()
    e_lfanew, opt_off, sect_off, num = _pe_offsets(data)
    aoep = struct.unpack_from("<I", data, opt_off + 16)[0]
    sections = []
    aligned = True
    for i in range(num):
        base = sect_off + i * 40
        name = data[base:base + 8].rstrip(b"\x00").decode("latin-1", "ignore")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        if rawptr != vaddr or rawsize != vsize:
            aligned = False
        sections.append({"name": name, "vaddr": hex(vaddr), "vsize": hex(vsize),
                         "rawptr": hex(rawptr), "rawsize": hex(rawsize)})
    return {"entry_point_rva": hex(aoep), "memory_aligned": aligned, "sections": sections}


def fix(path: str, oep: int | None, out: str) -> dict:
    data = bytearray(Path(path).read_bytes())
    e_lfanew, opt_off, sect_off, num = _pe_offsets(data)
    for i in range(num):
        base = sect_off + i * 40
        vsize, vaddr = struct.unpack_from("<II", data, base + 8)
        # Set raw pointer/size to the virtual layout (memory-dump convention).
        struct.pack_into("<II", data, base + 16, vsize, vaddr)
    if oep is not None:
        struct.pack_into("<I", data, opt_off + 16, oep)
    Path(out).write_bytes(bytes(data))
    return {"output": out, "entry_point_rva": hex(oep) if oep is not None else "unchanged",
            "note": "rebuild IAT with an import reconstructor next"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect/realign a dumped PE")
    sub = parser.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("inspect")
    pi.add_argument("file")
    pf = sub.add_parser("fix")
    pf.add_argument("file")
    pf.add_argument("--oep", help="OEP RVA, e.g. 0x1234")
    pf.add_argument("-o", "--out", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "inspect":
        print(json.dumps(inspect(args.file), indent=2))
    else:
        oep = int(args.oep, 0) if args.oep else None
        print(json.dumps(fix(args.file, oep, args.out), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
