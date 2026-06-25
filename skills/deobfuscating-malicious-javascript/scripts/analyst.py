#!/usr/bin/env python3
"""Statically decode common JavaScript obfuscation layers.

Without executing anything, this resolves frequent static encodings: ``\\xHH`` and ``\\uHHHH``
escapes, ``String.fromCharCode(...)`` sequences, and standalone base64 string literals. It also
extracts URLs from the decoded text and defangs them. Intended as a first-pass static aid before
a sandbox (box-js) for dynamic layers.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

RE_HEX = re.compile(r"\\x([0-9a-fA-F]{2})")
RE_UNI = re.compile(r"\\u([0-9a-fA-F]{4})")
RE_FROMCHARCODE = re.compile(r"String\.fromCharCode\(([^)]*)\)", re.I)
RE_B64 = re.compile(r"['\"]([A-Za-z0-9+/]{24,}={0,2})['\"]")
RE_URL = re.compile(r"https?://[^\s'\"<>)]+", re.I)


def _decode_escapes(text: str) -> str:
    text = RE_HEX.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = RE_UNI.sub(lambda m: chr(int(m.group(1), 16)), text)
    return text


def _decode_fromcharcode(text: str) -> str:
    def repl(m: re.Match) -> str:
        parts = re.split(r"[,\s]+", m.group(1).strip())
        chars = []
        for p in parts:
            p = p.strip()
            try:
                chars.append(chr(int(p, 0)))
            except (ValueError, TypeError):
                return m.group(0)
        return '"' + "".join(chars) + '"'
    return RE_FROMCHARCODE.sub(repl, text)


def _decode_b64_literals(text: str) -> list[str]:
    out = []
    for m in RE_B64.finditer(text):
        blob = m.group(1)
        try:
            dec = base64.b64decode(blob).decode("latin-1")
            if sum(c.isprintable() for c in dec) > len(dec) * 0.8:
                out.append(dec)
        except (binascii.Error, ValueError):
            continue
    return out


def _defang(url: str) -> str:
    return url.replace("http", "hxxp").replace(".", "[.]")


def decode(source: str) -> dict:
    stage1 = _decode_escapes(source)
    stage2 = _decode_fromcharcode(stage1)
    b64 = _decode_b64_literals(stage2)
    urls = sorted(set(RE_URL.findall(stage2)) | {u for d in b64 for u in RE_URL.findall(d)})
    return {
        "decoded_preview": stage2[:1500],
        "base64_decoded": b64[:20],
        "urls": [_defang(u) for u in urls],
        "note": "static decode only; use box-js sandbox for eval/Function layers",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Statically decode obfuscated JS")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("decode")
    p.add_argument("file")
    args = parser.parse_args(argv)
    source = Path(args.file).read_text(encoding="utf-8-sig", errors="replace")
    print(json.dumps(decode(source), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
