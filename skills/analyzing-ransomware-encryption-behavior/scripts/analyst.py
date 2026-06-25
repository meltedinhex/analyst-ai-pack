#!/usr/bin/env python3
"""Compare plaintext vs ransomware-encrypted test files to extract markers and assess scheme.

Given a directory of original test files and a directory of their encrypted counterparts, it
reports added extensions, entropy change, and any common trailing footer/magic (often where a
wrapped key or IV is stored). Operates on inert test files only.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _common_suffix(blobs: list[bytes], max_len: int = 512) -> bytes:
    if not blobs:
        return b""
    shortest = min(len(b) for b in blobs)
    limit = min(shortest, max_len)
    suffix = bytearray()
    for i in range(1, limit + 1):
        col = {b[-i] for b in blobs}
        if len(col) == 1:
            suffix.insert(0, col.pop())
        else:
            break
    return bytes(suffix)


def compare(plain_dir: str, enc_dir: str) -> dict:
    plain = {p.stem: p for p in Path(plain_dir).iterdir() if p.is_file()}
    enc = [p for p in Path(enc_dir).iterdir() if p.is_file()]

    added_ext = sorted({"".join(p.suffixes) for p in enc})
    enc_blobs = [p.read_bytes() for p in enc]
    footer = _common_suffix(enc_blobs)

    per_file = []
    for p in enc:
        base = p.name
        # strip a possible appended extension to match the plaintext stem
        stem = p.stem
        orig = plain.get(stem)
        row = {
            "encrypted": base,
            "encrypted_entropy": round(entropy(p.read_bytes()), 3),
        }
        if orig:
            row["original"] = orig.name
            row["original_entropy"] = round(entropy(orig.read_bytes()), 3)
            row["size_delta"] = p.stat().st_size - orig.stat().st_size
        per_file.append(row)

    likely_full = all(r.get("encrypted_entropy", 0) > 7.5 for r in per_file)
    return {
        "added_extensions": added_ext,
        "common_footer_len": len(footer),
        "common_footer_hex": footer.hex(),
        "encryption_coverage": "full/high-entropy" if likely_full else "partial/mixed",
        "files": per_file,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare plain vs encrypted test files")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("compare")
    p.add_argument("plain_dir")
    p.add_argument("enc_dir")
    args = parser.parse_args(argv)
    print(json.dumps(compare(args.plain_dir, args.enc_dir), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
