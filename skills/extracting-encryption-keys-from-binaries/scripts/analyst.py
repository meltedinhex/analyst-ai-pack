#!/usr/bin/env python3
"""Surface candidate encryption keys in a binary.

Finds key-sized (16/24/32-byte) high-entropy regions and extracts printable hex/base64 strings
that match common key lengths. Reports offsets and candidate types. Reads bytes statically;
executes nothing. Entropy is a heuristic — confirm candidates by attempting decryption.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

KEY_SIZES = (16, 24, 32)
ENTROPY_THRESHOLD = 3.7  # bits over a small window; tuned to flag random-looking blocks
RE_HEXKEY = re.compile(rb"\b[0-9a-fA-F]{32,64}\b")
RE_B64KEY = re.compile(rb"\b[A-Za-z0-9+/]{24,44}={0,2}\b")


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = Counter(chunk)
    total = len(chunk)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _high_entropy_regions(data: bytes) -> list[dict]:
    out = []
    step = 8
    seen_offsets: set[int] = set()
    for size in KEY_SIZES:
        for i in range(0, len(data) - size, step):
            window = data[i:i + size]
            # require byte diversity close to the window size (random key material)
            if len(set(window)) >= size - 2 and _entropy(window) >= ENTROPY_THRESHOLD:
                if all(abs(i - o) >= size for o in seen_offsets):
                    out.append({"offset": i, "size": size,
                                "entropy": round(_entropy(window), 3),
                                "hex": window.hex()})
                    seen_offsets.add(i)
            if len(out) > 200:
                return out
    return out


def keys(path: str) -> dict:
    data = Path(path).read_bytes()
    hex_keys = sorted({m.decode("ascii") for m in RE_HEXKEY.findall(data)})[:50]
    b64_keys = sorted({m.decode("ascii") for m in RE_B64KEY.findall(data)})[:50]
    return {
        "high_entropy_key_candidates": _high_entropy_regions(data)[:50],
        "hex_string_keys": hex_keys,
        "base64_string_keys": b64_keys,
        "note": "confirm any candidate by decrypting known ciphertext; entropy alone is weak",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract candidate keys from a binary")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keys")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(keys(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
