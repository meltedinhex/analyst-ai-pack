#!/usr/bin/env python3
"""Scan a binary for well-known cryptographic constants and tables.

Detects the AES S-box, SHA-256 init/round constants, MD5 init constants, ChaCha/Salsa sigma,
the CRC32 (0xEDB88320) table, and the base64 alphabet by exact byte-pattern match, reporting
offsets. Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

# AES S-box (FIPS 197) first 16 bytes are a stable, distinctive anchor.
AES_SBOX_PREFIX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

# SHA-256 initial hash values H0..H7 (FIPS 180-4), little- and big-endian.
SHA256_H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# MD5 init constants A,B,C,D.
MD5_INIT = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

CHACHA_SIGMA = b"expand 32-byte k"
SALSA_SIGMA16 = b"expand 16-byte k"
BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _ints_le(values: list[int]) -> bytes:
    return b"".join(struct.pack("<I", v) for v in values)


def _ints_be(values: list[int]) -> bytes:
    return b"".join(struct.pack(">I", v) for v in values)


def _crc32_table_prefix() -> bytes:
    poly = 0xEDB88320
    table = []
    for n in range(8):  # first 8 entries are enough to anchor
        c = n
        for _ in range(8):
            c = (poly ^ (c >> 1)) if (c & 1) else (c >> 1)
        table.append(c)
    return _ints_le(table)


def _find_all(data: bytes, needle: bytes, label: str, limit: int = 10) -> list[dict]:
    hits = []
    start = 0
    while len(hits) < limit:
        idx = data.find(needle, start)
        if idx == -1:
            break
        hits.append({"algorithm": label, "offset": idx})
        start = idx + 1
    return hits


def scan(path: str) -> dict:
    data = Path(path).read_bytes()
    findings: list[dict] = []
    findings += _find_all(data, AES_SBOX_PREFIX, "AES S-box")
    findings += _find_all(data, _ints_le(SHA256_H), "SHA-256 init (LE)")
    findings += _find_all(data, _ints_be(SHA256_H), "SHA-256 init (BE)")
    findings += _find_all(data, _ints_le(MD5_INIT), "MD5 init (LE)")
    findings += _find_all(data, _crc32_table_prefix(), "CRC32 table")
    findings += _find_all(data, CHACHA_SIGMA, "ChaCha sigma")
    findings += _find_all(data, SALSA_SIGMA16, "Salsa20 sigma (16)")
    findings += _find_all(data, BASE64_ALPHABET, "Base64 alphabet")
    algos = sorted({f["algorithm"].split(" (")[0] for f in findings})
    return {"algorithms_detected": algos, "constant_hits": findings}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Identify crypto constants in a binary")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
