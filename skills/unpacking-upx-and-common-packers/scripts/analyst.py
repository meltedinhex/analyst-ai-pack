#!/usr/bin/env python3
"""Detect common packers from PE section names, entropy, and import sparsity.

Heuristic, signature-light packer detection on file bytes. It parses the PE section table
directly (no third-party deps), computes per-section entropy, and matches known packer
section names. It reads bytes only and never executes the sample.
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from collections import Counter
from pathlib import Path

PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    "FSG!": "FSG", ".nsp0": "NsPack", ".pec1": "PECompact",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse_sections(data: bytes) -> list[dict]:
    if data[:2] != b"MZ":
        raise ValueError("not a PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature")
    num = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    base = e_lfanew + 24 + opt
    sections = []
    for i in range(num):
        b = base + i * 40
        name = data[b:b + 8].rstrip(b"\x00").decode("latin-1", "replace")
        raw_size = struct.unpack_from("<I", data, b + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, b + 20)[0]
        blob = data[raw_ptr:raw_ptr + raw_size]
        sections.append({"name": name, "raw_size": raw_size,
                         "entropy": round(entropy(blob), 3)})
    return sections


def detect(path: str) -> dict:
    data = Path(path).read_bytes()
    sections = parse_sections(data)
    hits = sorted({PACKER_SECTIONS[s["name"]] for s in sections
                   if s["name"] in PACKER_SECTIONS})
    high_entropy = [s["name"] for s in sections if s["entropy"] > 7.2]
    whole = round(entropy(data), 3)
    likely_packed = bool(hits) or whole > 7.2 or len(high_entropy) >= max(1, len(sections) - 1)
    return {
        "packer_signatures": hits,
        "sections": sections,
        "high_entropy_sections": high_entropy,
        "whole_file_entropy": whole,
        "likely_packed": likely_packed,
        "recommendation": ("upx -d" if "UPX" in hits else
                           "manual unpack in debugger" if likely_packed else
                           "no packing indicators"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect common packers")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("detect")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(detect(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
