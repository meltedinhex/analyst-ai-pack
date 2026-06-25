#!/usr/bin/env python3
"""Static ELF analysis: header, sections, dynamic symbols, and packing hints.

Uses ``pyelftools`` when available; otherwise parses the ELF header and section table
directly so basic facts (class, type, machine, sections, entropy) are still reported.
Never executes the sample.
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from collections import Counter
from pathlib import Path

_NETWORK = {"socket", "connect", "send", "recv", "bind", "listen", "gethostbyname"}
_PROC = {"fork", "execve", "ptrace", "clone", "kill", "system", "popen"}
_CRYPTO = {"crypt", "evp_encryptinit_ex", "aes_encrypt", "rc4"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyze_with_pyelftools(path: str) -> dict:
    from elftools.elf.elffile import ELFFile  # type: ignore
    from elftools.elf.dynamic import DynamicSection  # type: ignore
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        header = {
            "class": elf.elfclass,
            "type": elf["e_type"],
            "machine": elf["e_machine"],
            "entry": hex(elf["e_entry"]),
        }
        symbols: list[str] = []
        needed: list[str] = []
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym:
            symbols = [s.name for s in dynsym.iter_symbols() if s.name]
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
        stripped = elf.get_section_by_name(".symtab") is None
    low = {s.lower() for s in symbols}
    return {
        "header": header,
        "stripped": stripped,
        "needed": needed,
        "dynamic_symbol_count": len(symbols),
        "capabilities": {
            "network": sorted(low & _NETWORK),
            "process": sorted(low & _PROC),
            "crypto": sorted(low & _CRYPTO),
        },
    }


def analyze_minimal(path: str) -> dict:
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    is64 = data[4] == 2
    le = data[5] == 1
    endian = "<" if le else ">"
    e_type = struct.unpack_from(endian + "H", data, 16)[0]
    e_machine = struct.unpack_from(endian + "H", data, 18)[0]
    upx = b"UPX!" in data
    return {
        "header": {"class": 64 if is64 else 32, "type": e_type, "machine": e_machine},
        "whole_file_entropy": round(entropy(data), 3),
        "upx_marker": upx,
        "note": "pyelftools not installed; minimal parse",
    }


def analyze(path: str) -> dict:
    try:
        return analyze_with_pyelftools(path)
    except ImportError:
        return analyze_minimal(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static ELF analysis")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
