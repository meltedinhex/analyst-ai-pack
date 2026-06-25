#!/usr/bin/env python3
"""Scaffold a YARA rule from reverse-engineering findings.

Generates a well-structured rule skeleton with ``meta``, placeholder byte-pattern strings, an
optional API-hash constant, and a sensible multi-anchor condition with a PE prefilter. The
analyst fills in the real opcode bytes. This only emits text; it does not scan anything.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys


def scaffold(name: str, api_hash: str | None, author: str) -> str:
    today = _dt.date.today().isoformat()
    hash_line = ""
    hash_cond = ""
    if api_hash:
        val = int(api_hash, 0)
        hash_line = f"        $h_api = {{ {val & 0xFF:02X} {(val >> 8) & 0xFF:02X} " \
                    f"{(val >> 16) & 0xFF:02X} {(val >> 24) & 0xFF:02X} }}  // API hash LE\n"
        hash_cond = " and $h_api"
    return f"""rule {name}
{{
    meta:
        author = "{author}"
        date = "{today}"
        description = "Detects {name} based on reversed code constructs"
        reference = "<analysis report / sample hash>"
        sample_sha256 = "<fill in>"

    strings:
        // Replace with the real decryptor/algorithm opcodes; wildcard volatile operands.
        $code1 = {{ 8A 04 ?? 34 ?? 88 04 ?? 41 3B ?? }}
        $code2 = {{ 0F B6 ?? 33 ?? C1 ?? ?? }}
{hash_line}
    condition:
        // Cheap prefilter then require multiple independent anchors.
        uint16(0) == 0x5A4D and filesize < 5MB and
        (2 of ($code*)){hash_cond}
}}
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scaffold a YARA rule")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scaffold")
    p.add_argument("--name", required=True)
    p.add_argument("--hash", dest="api_hash", default=None,
                   help="optional API-hash constant, e.g. 0xABCDEF12")
    p.add_argument("--author", default="analyst-ai-pack")
    args = parser.parse_args(argv)
    print(scaffold(args.name, args.api_hash, args.author))
    return 0


if __name__ == "__main__":
    sys.exit(main())
