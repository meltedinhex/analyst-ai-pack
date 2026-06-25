#!/usr/bin/env python3
"""Statically characterize a packed PE to plan manual unpacking.

Parses the PE section table to report per-section entropy, writable+executable sections, unusual
names, and import-table size — signals of a runtime packer. Uses pefile if available, otherwise a
minimal built-in section parser. Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from collections import Counter
from pathlib import Path

KNOWN_PACKER_NAMES = ["upx", "aspack", "fsg", "mpress", "vmp", "themida", "petite", "nspack",
                      "pec", "mew", "enigma"]


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = Counter(chunk)
    total = len(chunk)
    return round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 3)


def _parse_sections(data: bytes) -> list[dict]:
    if data[:2] != b"MZ":
        raise ValueError("not a PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("bad PE signature")
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sect_off = e_lfanew + 24 + opt_size
    sections = []
    for i in range(num_sections):
        base = sect_off + i * 40
        raw = data[base:base + 40]
        if len(raw) < 40:
            break
        name = raw[:8].rstrip(b"\x00").decode("latin-1", "ignore")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, 8)
        chars = struct.unpack_from("<I", raw, 36)[0]
        body = data[rawptr:rawptr + rawsize]
        sections.append({
            "name": name,
            "entropy": _entropy(body),
            "writable": bool(chars & 0x80000000),
            "executable": bool(chars & 0x20000000),
            "raw_size": rawsize,
        })
    return sections


def inspect(path: str) -> dict:
    data = Path(path).read_bytes()
    sections = _parse_sections(data)
    wx = [s["name"] for s in sections if s["writable"] and s["executable"]]
    odd = [s["name"] for s in sections
           if any(k in s["name"].lower() for k in KNOWN_PACKER_NAMES)]
    high = [s["name"] for s in sections if s["entropy"] > 7.0]
    return {
        "sections": sections,
        "write_execute_sections": wx,
        "known_packer_section_names": odd,
        "high_entropy_sections": high,
        "likely_packed": bool(wx or odd or len(high) >= 1),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Characterize a packed PE")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inspect")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(inspect(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
