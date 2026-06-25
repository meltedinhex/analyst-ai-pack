#!/usr/bin/env python3
"""Carve embedded payloads from OneNote files and reconstruct HTML-smuggling blobs.

For OneNote (and any binary), it scans for embedded file signatures (PE, archives, scripts) and
reports their offsets. For HTML, it locates large base64/byte-array blobs and decodes them to
recover a smuggled payload. It reads bytes/text statically and executes nothing.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

EMBED_SIGS = [
    (b"MZ", "PE executable"),
    (b"PK\x03\x04", "ZIP/Office/JAR"),
    (b"\x1f\x8b", "GZIP"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"%PDF", "PDF"),
    (b"#!", "script (shebang)"),
    (b"<job", "WSF job"),
]

RE_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")
SMUGGLE_HINTS = [b"msSaveOrOpenBlob", b"createObjectURL", b"Uint8Array", b"new Blob",
                 b"download=", b"base64"]


def carve(data: bytes) -> list[dict]:
    found = []
    for sig, label in EMBED_SIGS:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            found.append({"offset": idx, "type": label})
            start = idx + 1
            if len(found) > 50:
                return found
    return found


def html_smuggle(data: bytes) -> dict:
    hints = sorted({h.decode() for h in SMUGGLE_HINTS if h in data})
    decoded = []
    for m in RE_B64_BLOB.findall(data):
        try:
            raw = base64.b64decode(m)
        except (binascii.Error, ValueError):
            continue
        if raw[:2] == b"MZ" or raw[:4] == b"PK\x03\x04" or raw[:4] == b"%PDF":
            decoded.append({"size": len(raw), "carved_type": carve(raw)[:1]})
    return {"smuggling_hints": hints, "decoded_blobs": decoded,
            "likely_smuggling": bool(hints and decoded)}


def analyze(path: str) -> dict:
    data = Path(path).read_bytes()
    return {
        "embedded_signatures": carve(data),
        "html_smuggling": html_smuggle(data),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Carve OneNote / HTML-smuggling payloads")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("carve")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
