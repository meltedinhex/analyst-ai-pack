#!/usr/bin/env python3
"""Print curated radare2/rizin command cheatsheets for common RE tasks.

A reference helper that emits real r2/rizin commands grouped by task (analyze, navigate,
disassemble, xrefs, annotate, patch, strings, search). It prints text only and never runs r2 or
any sample.
"""
from __future__ import annotations

import argparse
import json
import sys

CHEATSHEETS = {
    "analyze": [
        ("r2 -e bin.cache=true sample", "open read-only with cache"),
        ("aaa", "analyze all (functions, refs, strings)"),
        ("aflj", "list functions as JSON"),
        ("afl", "list functions"),
        ("iI", "binary info"),
        ("ie", "entrypoints"),
    ],
    "navigate": [
        ("s main", "seek to main"),
        ("s 0x401000", "seek to address"),
        ("s-", "seek backward in history"),
        ("VV", "interactive graph view of current function"),
    ],
    "disassemble": [
        ("pdf", "print disassembly of function"),
        ("pd 20", "print 20 instructions"),
        ("pdc", "pseudo-decompile (if available)"),
        ("pdr", "recursive disassembly"),
    ],
    "xrefs": [
        ("axt 0x401000", "references TO this address"),
        ("axf 0x401000", "references FROM this address"),
        ("afx", "xrefs within the function"),
    ],
    "annotate": [
        ("afn newname", "rename current function"),
        ("CC comment text", "add a comment at current offset"),
        ("f myflag", "set a flag at current offset"),
        ("Cd 4", "define 4-byte data"),
    ],
    "patch": [
        ("r2 -w sample", "open in write mode"),
        ("wa nop", "assemble 'nop' at current offset"),
        ("wx 9090", "write hex bytes"),
        ("pdf", "re-verify the patch"),
    ],
    "strings": [
        ("izj", "strings in data sections (JSON)"),
        ("izzj", "strings in the whole file (JSON)"),
        ("iij", "imports (JSON)"),
    ],
    "search": [
        ("/ pattern", "search for a string"),
        ("/x 4889", "search for hex bytes"),
        ("/R pop rdi", "search for ROP gadget"),
    ],
}


def cheatsheet(topic: str) -> dict:
    if topic == "all":
        return {t: [{"cmd": c, "desc": d} for c, d in items]
                for t, items in CHEATSHEETS.items()}
    items = CHEATSHEETS.get(topic)
    if not items:
        return {"error": "unknown topic", "topics": sorted(CHEATSHEETS)}
    return {topic: [{"cmd": c, "desc": d} for c, d in items]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="radare2/rizin command cheatsheets")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("cheatsheet")
    p.add_argument("topic", nargs="?", default="all")
    args = parser.parse_args(argv)
    print(json.dumps(cheatsheet(args.topic), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
