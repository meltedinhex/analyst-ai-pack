#!/usr/bin/env python3
"""Inspect ISO/IMG/VHD container files for hidden/smuggled payloads.

Identifies the container format by signature and carves embedded file signatures (PE, archives,
LNK, scripts) with offsets. Uses pycdlib for full ISO directory listing when available; otherwise
falls back to signature carving. Reads bytes statically; never mounts the image.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import pycdlib  # type: ignore
    HAVE_PYCDLIB = True
except ImportError:
    HAVE_PYCDLIB = False

EMBED_SIGS = [
    (b"MZ", "PE executable"),
    (b"PK\x03\x04", "ZIP/Office"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "LNK shortcut"),
    (b"#!", "script (shebang)"),
    (b"<job", "WSF job"),
    (b"@echo", "batch script"),
]


def _format(data: bytes) -> str:
    if data[0x8001:0x8006] == b"CD001" or b"CD001" in data[:0x10000]:
        return "ISO 9660"
    if data[:8] == b"conectix":
        return "VHD"
    if data[:8] == b"vhdxfile":
        return "VHDX"
    if data[0x36:0x3b] == b"FAT16" or data[0x52:0x57] == b"FAT32":
        return "FAT (IMG)"
    return "unknown"


def _carve(data: bytes) -> list[dict]:
    found = []
    for sig, label in EMBED_SIGS:
        start = 0
        while len(found) < 100:
            idx = data.find(sig, start)
            if idx == -1:
                break
            found.append({"offset": idx, "type": label})
            start = idx + 1
    return found


def _iso_listing(path: str) -> list[str]:
    if not HAVE_PYCDLIB:
        return []
    names = []
    try:
        iso = pycdlib.PyCdlib()
        iso.open(path)
        for child in iso.list_children(iso_path="/"):
            ident = getattr(child.file_identifier(), "decode", lambda *_: "")("utf-8", "ignore")
            if ident and ident not in (".", ".."):
                names.append(ident)
        iso.close()
    except Exception:
        return []
    return names


def inspect(path: str) -> dict:
    data = Path(path).read_bytes()
    carved = _carve(data)
    return {
        "format": _format(data),
        "pycdlib_available": HAVE_PYCDLIB,
        "iso_directory": _iso_listing(path),
        "embedded_signatures": carved,
        "hidden_payload_suspected": any(c["type"].startswith(("PE", "LNK", "script"))
                                        for c in carved),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect ISO/container files")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inspect")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(inspect(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
