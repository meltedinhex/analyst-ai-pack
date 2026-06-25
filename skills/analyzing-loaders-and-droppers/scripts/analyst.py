#!/usr/bin/env python3
"""Analyze a loader/dropper: locate staged payloads and identify decode/download/execution APIs.

Detects embedded PE/archive signatures, scans strings for download/decode/execution APIs and
URLs, and computes Shannon entropy over windows to flag large high-entropy (packed/encrypted)
blobs. Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)

EMBED_SIGS = [(b"MZ", "PE"), (b"PK\x03\x04", "ZIP/Office"), (b"Rar!\x1a\x07", "RAR"),
              (b"\x1f\x8b", "GZIP"), (b"7z\xbc\xaf\x27\x1c", "7z")]

DOWNLOAD_API = ["urldownloadtofile", "internetreadfile", "internetopenurl", "winhttp",
                "httpopenrequest", "wininet"]
DECODE_API = ["cryptdecrypt", "cryptstringtobinary", "base64", "rc4", "xor"]
EXEC_API = ["createprocess", "shellexecute", "winexec", "createremotethread", "loadlibrary",
            "ntcreateuserprocess", "wow64"]


def _strings(data: bytes) -> str:
    parts = [m.decode("ascii", "ignore") for m in ASCII_RE.findall(data)]
    parts += [m.decode("utf-16-le", "ignore") for m in UTF16_RE.findall(data)]
    return "\n".join(parts)


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = Counter(chunk)
    total = len(chunk)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def stage(path: str) -> dict:
    data = Path(path).read_bytes()
    embedded = []
    for sig, label in EMBED_SIGS:
        idx = data.find(sig, 1)  # skip offset 0 (the loader's own header)
        if idx != -1:
            embedded.append({"offset": idx, "type": label})
    win = 4096
    high_entropy = sum(1 for i in range(0, len(data), win)
                       if _entropy(data[i:i + win]) > 7.2)
    blob = _strings(data)
    low = blob.lower()
    urls = sorted({u.replace("http", "hxxp").replace(".", "[.]") for u in RE_URL.findall(blob)})
    return {
        "embedded_signatures": embedded,
        "high_entropy_windows": high_entropy,
        "download_apis": sorted({a for a in DOWNLOAD_API if a in low}),
        "decode_apis": sorted({a for a in DECODE_API if a in low}),
        "execution_apis": sorted({a for a in EXEC_API if a in low}),
        "urls": urls[:50],
        "is_likely_loader": bool(embedded) or bool(urls and any(a in low for a in DOWNLOAD_API)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze loader/dropper staging")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("stage")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(stage(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
