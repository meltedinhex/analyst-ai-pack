#!/usr/bin/env python3
"""Detect the source language of an exotic compiled binary (Nim/Crystal/V/Zig/D).

Scans printable strings for language-specific runtime signatures and scores each language by the
number of corroborating markers. Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{3,}")

SIGNATURES = {
    "Nim": ["nimrtl", "fatal.nim", "@m..nim", "/nim/", "system.nim", "ioselectors",
            "nimframe", "nimcopy"],
    "Crystal": ["crystal-lang", "crystal::", "raise_overflow", "__crystal_main",
                "crystal/once"],
    "V": ["vlib/", "_vinit", "_vcleanup", "v_panic", "tos3(", "builtin.v"],
    "Zig": ["std.builtin", "panic: ", "zig_panic", "std/", "/zig/", "@panic"],
    "D": ["_dmain", "core.runtime", "typeinfo_", "druntime", "rt.lifetime",
          "object.error"],
}


def detect(path: str) -> dict:
    data = Path(path).read_bytes()
    blob = "\n".join(m.decode("latin-1", "ignore") for m in ASCII_RE.findall(data)).lower()
    scores = {}
    evidence = {}
    for lang, markers in SIGNATURES.items():
        hits = sorted({m for m in markers if m in blob})
        if hits:
            scores[lang] = len(hits)
            evidence[lang] = hits
    best = max(scores, key=scores.get) if scores else None
    return {
        "detected_language": best if best and scores[best] >= 2 else "uncertain",
        "scores": scores,
        "evidence": evidence,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect exotic source language")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("detect")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(detect(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
