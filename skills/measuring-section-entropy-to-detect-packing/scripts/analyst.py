#!/usr/bin/env python3
"""Measure Shannon entropy of a file and (for PE) its sections to detect packing.

Computes whole-file entropy and sliding-window entropy to locate high-entropy regions, and, when
``pefile`` is available and the input is a PE, per-section entropy with raw/virtual size
comparison. Higher entropy (toward 8.0 bits/byte) indicates compression/encryption. It reads the
inert file and never executes it.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

PACK_THRESHOLD = 7.0


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def window_stats(data: bytes, window: int = 4096) -> tuple[float, float]:
    """Return (peak entropy, fraction of windows above PACK_THRESHOLD)."""
    if len(data) <= window:
        ent = shannon(data)
        return ent, 1.0 if ent > PACK_THRESHOLD else 0.0
    peak = 0.0
    high = 0
    total = 0
    for i in range(0, len(data) - window, window):
        ent = shannon(data[i:i + window])
        peak = max(peak, ent)
        high += ent > PACK_THRESHOLD
        total += 1
    return peak, (high / total if total else 0.0)


def pe_sections(path: str) -> list[dict]:
    try:
        import pefile  # type: ignore
    except ImportError:
        return []
    out = []
    pe = pefile.PE(path)
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("latin-1")
        raw = sec.get_data()
        ent = shannon(raw)
        executable = bool(sec.Characteristics & 0x20000000)  # MEM_EXECUTE
        out.append({
            "name": name,
            "entropy": round(ent, 3),
            "raw_size": sec.SizeOfRawData,
            "virtual_size": sec.Misc_VirtualSize,
            "executable": executable,
            "suspicious": ent > PACK_THRESHOLD and executable,
        })
    return out


def analyze(path: str) -> dict:
    data = Path(path).read_bytes()
    sections = pe_sections(path) if data[:2] == b"MZ" else []
    peak, high_fraction = window_stats(data)
    # Section-level evidence is authoritative; otherwise require a sustained
    # high-entropy fraction (a few high-entropy windows are usually packed resources).
    if sections:
        packed = any(s["suspicious"] for s in sections)
    else:
        packed = high_fraction > 0.5
    return {
        "file_entropy": round(shannon(data), 3),
        "window_peak_entropy": round(peak, 3),
        "high_entropy_window_fraction": round(high_fraction, 3),
        "sections": sections,
        "likely_packed": packed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure entropy / detect packing")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("entropy")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
