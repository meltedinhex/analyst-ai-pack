#!/usr/bin/env python3
"""Extract and triage VBA macros from Office documents.

Prefers ``oletools`` (olevba) for robust extraction; falls back to locating ``vbaProject.bin``
inside OOXML (ZIP) containers and flagging suspicious indicators in the raw bytes. Never opens
the document in Office and never executes anything.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

AUTOEXEC = ["AutoOpen", "Document_Open", "AutoClose", "Document_Close",
            "Workbook_Open", "Auto_Open", "Auto_Close"]
SUSPICIOUS = ["Shell", "WScript.Shell", "CreateObject", "powershell", "cmd",
              "URLDownloadToFile", "XMLHTTP", "ADODB.Stream", "Environ",
              "winmgmts", "Base64", "Chr(", "GetObject"]


def _scan_text(text: str) -> dict:
    found_auto = [k for k in AUTOEXEC if k.lower() in text.lower()]
    found_sus = [k for k in SUSPICIOUS if k.lower() in text.lower()]
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>)]+", text)))
    return {"auto_exec": found_auto, "suspicious": found_sus, "urls": urls}


def extract_with_olevba(path: str) -> dict:
    from oletools.olevba import VBA_Parser  # type: ignore
    vp = VBA_Parser(path)
    macros = []
    if vp.detect_vba_macros():
        for _, _, name, code in vp.extract_macros():
            macros.append({"name": name, **_scan_text(code),
                           "lines": code.count("\n") + 1})
    vp.close()
    return {"engine": "olevba", "has_macros": bool(macros), "macros": macros}


def extract_minimal(path: str) -> dict:
    p = Path(path)
    data = p.read_bytes()
    indicators = {}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            vba = [n for n in zf.namelist() if n.lower().endswith("vbaproject.bin")]
            if not vba:
                return {"engine": "minimal", "has_macros": False,
                        "note": "no vbaProject.bin in OOXML container"}
            blob = zf.read(vba[0])
        # vbaProject.bin is OLE/compressed; scan recoverable ASCII for indicators
        text = blob.decode("latin-1", "replace")
        indicators = _scan_text(text)
        return {"engine": "minimal", "has_macros": True,
                "stream": vba[0], "indicators": indicators,
                "note": "install oletools for full VBA source extraction"}
    # legacy OLE2: scan whole file bytes for indicator strings
    text = data.decode("latin-1", "replace")
    return {"engine": "minimal", "has_macros": b"Attribut" in data,
            "indicators": _scan_text(text),
            "note": "legacy OLE2; install oletools for reliable extraction"}


def analyze(path: str) -> dict:
    try:
        return extract_with_olevba(path)
    except ImportError:
        return extract_minimal(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Office macros")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
