#!/usr/bin/env python3
"""Triage a PDF's object structure for weaponization indicators.

Scans the raw PDF bytes for high-risk keywords (/JavaScript, /OpenAction, /Launch, /EmbeddedFile,
/URI, etc.), counts indirect objects and streams, and extracts URIs. It parses bytes statically
and never opens the document in a reader, so auto-actions cannot fire.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

KEYWORDS = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
            "/URI", "/RichMedia", "/SubmitForm", "/GoToR", "/ObjStm", "/AcroForm",
            "/XFA", "/JBIG2Decode"]

AUTO_ACTION = {"/OpenAction", "/AA", "/Launch"}

RE_URI = re.compile(rb"/URI\s*\(([^)]*)\)")
RE_OBJ = re.compile(rb"\d+\s+\d+\s+obj")
RE_STREAM = re.compile(rb"\bstream\b")


def _defang(url: str) -> str:
    return url.replace("http", "hxxp").replace(".", "[.]")


def triage(path: str) -> dict:
    data = Path(path).read_bytes()
    if not data.lstrip().startswith(b"%PDF"):
        return {"error": "not a PDF (no %PDF header)"}
    counts = {kw: len(re.findall(re.escape(kw.encode()), data)) for kw in KEYWORDS}
    counts = {k: v for k, v in counts.items() if v}
    uris = sorted({m.decode("latin-1", "replace") for m in RE_URI.findall(data)})
    auto = [kw for kw in AUTO_ACTION if counts.get(kw)]
    has_js = bool(counts.get("/JavaScript") or counts.get("/JS"))
    return {
        "objects": len(RE_OBJ.findall(data)),
        "streams": len(RE_STREAM.findall(data)),
        "risk_keywords": counts,
        "auto_actions": auto,
        "has_javascript": has_js,
        "uris": [_defang(u) for u in uris],
        "weaponized_likely": bool(auto and has_js) or bool(counts.get("/Launch")),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage a malicious PDF")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("triage")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(triage(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
