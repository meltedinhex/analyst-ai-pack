#!/usr/bin/env python3
"""Extract a Cobalt Strike Beacon configuration by brute-forcing the XOR key.

Cobalt Strike Beacon stores its settings as a single-byte XOR-encoded table of TLV entries.
This tool scans candidate keys, locates the decoded table, and parses well-known setting
indices into a readable config. It reads bytes only and never executes the beacon.

This is original code based on the publicly documented config-block layout. It decodes a
limited, well-known subset of settings for analyst triage.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

# Subset of well-known Beacon setting indices (type catalog is public).
SETTINGS = {
    1: "BeaconType",
    2: "Port",
    3: "SleepTime",
    4: "MaxGetSize",
    5: "Jitter",
    7: "PublicKey",
    8: "C2Server",
    9: "UserAgent",
    10: "HttpPostUri",
    12: "HttpGet_Metadata",
    13: "HttpPost_Metadata",
    19: "SpawnTo",
    26: "PipeName",
    37: "Watermark",
    43: "DNS_Idle",
}

TYPE_SHORT = 1
TYPE_INT = 2
TYPE_STR = 3


def _parse_table(buf: bytes) -> dict | None:
    """Parse a decoded settings table. Returns dict or None if it does not look valid."""
    out: dict = {}
    off = 0
    parsed = 0
    while off + 6 <= len(buf):
        index, vtype, length = struct.unpack_from(">HHH", buf, off)
        off += 6
        if index == 0 and vtype == 0 and length == 0:
            break
        if vtype == TYPE_SHORT and length == 2:
            (val,) = struct.unpack_from(">H", buf, off)
        elif vtype == TYPE_INT and length == 4:
            (val,) = struct.unpack_from(">I", buf, off)
        elif vtype == TYPE_STR and 0 < length <= 4096:
            val = buf[off:off + length].rstrip(b"\x00").decode("latin-1", "replace")
        else:
            return None  # malformed -> wrong key
        off += length
        parsed += 1
        name = SETTINGS.get(index, f"Setting_{index}")
        out[name] = val
        if parsed > 128:
            break
    return out if parsed >= 5 else None


def extract_config(data: bytes) -> dict | None:
    """Brute-force the single-byte XOR key and parse the first valid-looking table."""
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        # the table begins with index=1 (BeaconType), type=1 (short), len=2
        marker = struct.pack(">HHH", 1, TYPE_SHORT, 2)
        pos = decoded.find(marker)
        if pos == -1:
            continue
        cfg = _parse_table(decoded[pos:])
        if cfg:
            cfg["_xor_key"] = key
            return cfg
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract Cobalt Strike beacon config")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("parse")
    p.add_argument("file")
    args = parser.parse_args(argv)

    data = Path(args.file).read_bytes()
    cfg = extract_config(data)
    if cfg is None:
        print(json.dumps({"found": False,
                          "note": "no XOR-decoded config table located"}, indent=2))
        return 1
    print(json.dumps({"found": True, "config": cfg}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
