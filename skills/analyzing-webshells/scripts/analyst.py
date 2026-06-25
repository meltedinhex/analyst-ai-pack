#!/usr/bin/env python3
"""Scan a server-side script for webshell indicators and decode obvious obfuscation.

Detects dynamic-execution sinks, request-input-to-sink flow, and common encoder chains across PHP,
ASP/ASPX, and JSP, then best-effort decodes base64/rot13/gzinflate layers. Reads the file
statically; executes nothing and never deploys the script. Defangs recovered URLs.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import zlib
from pathlib import Path

SINKS = {
    "php": ["eval(", "assert(", "system(", "exec(", "passthru(", "shell_exec(", "popen(",
            "proc_open(", "preg_replace(/.*/e"],
    "aspx": ["eval(", "process.start", "executereader", "createobject(\"wscript.shell\")",
             "scriptengine"],
    "jsp": ["runtime.getruntime().exec", "processbuilder", "scriptengine", ".eval("],
}
INPUT_SOURCES = ["$_get", "$_post", "$_request", "$_cookie", "request.form", "request.querystring",
                 "request.getparameter", "request[", "php://input"]
ENCODERS = ["base64_decode", "gzinflate", "gzuncompress", "str_rot13", "frombase64string",
            "eval(chr", "\\x", "hex2bin", "convert.frombase64string"]
RE_URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)
RE_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def _decode_layers(text: str) -> list[str]:
    out = []
    for blob in RE_B64.findall(text)[:50]:
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        candidate = raw
        try:
            candidate = zlib.decompress(raw, -15)  # gzinflate (raw deflate)
        except zlib.error:
            pass
        printable = candidate.decode("latin-1", "ignore")
        if any(s in printable.lower() for lst in SINKS.values() for s in lst):
            out.append(printable[:200])
    return out[:10]


def scan(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    low = text.lower()
    lang = ("php" if "<?php" in low or path.endswith(".php")
            else "aspx" if path.endswith((".aspx", ".asp")) or "<%@" in low
            else "jsp" if path.endswith(".jsp") or "<%@ page" in low else "unknown")
    sink_set = SINKS.get(lang, [s for lst in SINKS.values() for s in lst])
    sinks = sorted({s.rstrip("(") for s in sink_set if s in low})
    inputs = sorted({i for i in INPUT_SOURCES if i in low})
    encoders = sorted({e for e in ENCODERS if e in low})
    urls = sorted({_defang(u) for u in RE_URL.findall(text)})
    input_reaches_sink = bool(sinks and inputs)
    return {
        "language": lang,
        "execution_sinks": sinks,
        "input_sources": inputs,
        "input_to_sink_flow": input_reaches_sink,
        "encoder_chains": encoders,
        "decoded_layers": _decode_layers(text),
        "urls": urls[:50],
        "is_likely_webshell": bool(sinks and (inputs or encoders)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze a suspected webshell")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
