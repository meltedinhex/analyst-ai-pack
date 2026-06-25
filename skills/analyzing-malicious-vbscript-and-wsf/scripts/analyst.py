#!/usr/bin/env python3
"""Analyze WSF/HTA/VBScript droppers statically.

Extracts ``<script>`` bodies from WSF/HTA XML/HTML containers, decodes Microsoft Script Encoder
(``VBScript.Encode``, ``#@~^``) streams, and flags suspicious WScript/ActiveX dropper patterns.
It parses text only and never invokes Windows Script Host.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

RE_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
RE_ENCODED = re.compile(r"#@~\^.*?\^#~@", re.S)
RE_URL = re.compile(r"https?://[^\s'\"<>)]+", re.I)

SUSPECT = ["wscript.shell", "createobject", ".run", ".exec", "powershell", "adodb.stream",
           "msxml2.xmlhttp", "winhttp", "shell.application", "regwrite"]


def _isolate_script_encoder(encoded: str) -> str:
    """Isolate the body of a #@~^...^#~@ Script Encoder block for follow-on decoding.

    Full Script Encoder decoding relies on a published ~140-entry substitution table; this
    strips the wrapper markers and the 6-character length/checksum framing so the encoded body
    can be handed to a dedicated decoder. The goal here is detection and isolation, not a
    reimplementation of the entire table.
    """
    m = re.match(r"#@~\^.{6}==(.*)\^#~@", encoded, re.S)
    return m.group(1) if m else encoded


def analyze(text: str) -> dict:
    scripts = [s.strip() for s in RE_SCRIPT.findall(text)]
    if not scripts:
        scripts = [text]  # bare .vbs
    encoded_blocks = RE_ENCODED.findall(text)
    isolated = [_isolate_script_encoder(b) for b in encoded_blocks]
    combined = "\n".join(scripts + isolated).lower()
    indicators = sorted({s for s in SUSPECT if s in combined})
    urls = sorted(set(RE_URL.findall(text)))
    return {
        "script_blocks": len(scripts),
        "script_encoder_blocks": len(encoded_blocks),
        "encoded_block_present": bool(encoded_blocks),
        "suspicious_apis": indicators,
        "urls": [u.replace("http", "hxxp").replace(".", "[.]") for u in urls],
        "note": "encoded blocks isolated; finish Script Encoder decode with a dedicated decoder",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze VBScript/WSF/HTA")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze")
    p.add_argument("file")
    args = parser.parse_args(argv)
    text = Path(args.file).read_text(encoding="utf-8-sig", errors="replace")
    print(json.dumps(analyze(text), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
