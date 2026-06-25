#!/usr/bin/env python3
"""Deobfuscate malicious PowerShell without executing it.

Decodes ``-EncodedCommand`` (base64 UTF-16LE), peels nested base64 + gzip/deflate layers,
applies a few common string transforms, and extracts IOCs. It transforms text only and never
invokes PowerShell.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import json
import re
import sys
import zlib
from pathlib import Path

_URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def decode_encodedcommand(b64: str) -> str:
    raw = base64.b64decode(b64)
    # -EncodedCommand payloads are UTF-16LE
    try:
        return raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def _try_decompress(raw: bytes) -> str | None:
    for fn in (lambda b: gzip.decompress(b),
               lambda b: zlib.decompress(b),
               lambda b: zlib.decompress(b, -15)):
        try:
            return fn(raw).decode("utf-8", "replace")
        except (OSError, zlib.error, binascii.Error):
            continue
    return None


def peel_layers(text: str, max_depth: int = 6) -> list[str]:
    """Return successive decoded layers, peeling base64(+gzip/deflate) blobs."""
    layers = [text]
    current = text
    for _ in range(max_depth):
        blobs = _B64.findall(current)
        if not blobs:
            break
        blob = max(blobs, key=len)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except binascii.Error:
            break
        decoded = _try_decompress(raw)
        if decoded is None:
            try:
                decoded = raw.decode("utf-16-le")
            except UnicodeDecodeError:
                decoded = raw.decode("utf-8", "replace")
        if not decoded or decoded == current:
            break
        layers.append(decoded)
        current = decoded
    return layers


def neutralize(text: str) -> str:
    """Render execution sinks inert for safe display."""
    text = re.sub(r"\bI`?E`?X\b", "echo", text, flags=re.I)
    text = re.sub(r"\bInvoke-Expression\b", "Write-Output", text, flags=re.I)
    return text


def extract_iocs(text: str) -> dict:
    return {"urls": sorted(set(_URL.findall(text)))}


def deobfuscate(text: str) -> dict:
    layers = peel_layers(text)
    final = neutralize(layers[-1])
    return {
        "layer_count": len(layers),
        "final_script": final,
        "iocs": extract_iocs("\n".join(layers)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deobfuscate PowerShell")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_e = sub.add_parser("decode", help="decode -EncodedCommand")
    p_e.add_argument("--encodedcommand", required=True)

    p_d = sub.add_parser("deobfuscate", help="peel layers from a script file")
    p_d.add_argument("file")

    args = parser.parse_args(argv)
    if args.cmd == "decode":
        print(decode_encodedcommand(args.encodedcommand))
        return 0
    text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    print(json.dumps(deobfuscate(text), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
