#!/usr/bin/env python3
"""Identify a file's true type from magic bytes and structural signatures.

Matches leading and offset-based signatures for common malware-relevant formats (PE, ELF,
Mach-O, PDF, OLE, ZIP/Office, ISO, scripts) and flags mismatches against a claimed extension.
It reads raw bytes only and never opens the file in an application.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# (offset, signature bytes, label)
SIGNATURES = [
    (0, b"MZ", "PE/DOS executable (MZ)"),
    (0, b"\x7fELF", "ELF executable"),
    (0, b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (0, b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (LE)"),
    (0, b"\xca\xfe\xba\xbe", "Mach-O universal/Java class"),
    (0, b"%PDF", "PDF document"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound (legacy Office/MSI)"),
    (0, b"PK\x03\x04", "ZIP / OOXML / JAR / APK"),
    (0, b"Rar!\x1a\x07", "RAR archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (0, b"\x1f\x8b", "GZIP archive"),
    (0, b"#!", "Shebang script"),
    (0, b"<?xml", "XML document"),
    (0, b"<!DOCTYPE html", "HTML document"),
    (0x8001, b"CD001", "ISO 9660 image"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "Windows LNK shortcut"),
]

EXT_EXPECT = {
    ".exe": "PE", ".dll": "PE", ".pdf": "PDF", ".zip": "ZIP", ".docx": "ZIP",
    ".xlsx": "ZIP", ".doc": "OLE", ".xls": "OLE", ".iso": "ISO", ".lnk": "LNK",
    ".elf": "ELF", ".so": "ELF",
}


def identify(path: str) -> dict:
    data = Path(path).read_bytes()
    matches = []
    for off, sig, label in SIGNATURES:
        if data[off:off + len(sig)] == sig:
            matches.append({"offset": off, "type": label})

    ext = Path(path).suffix.lower()
    expected = EXT_EXPECT.get(ext)
    detected_family = matches[0]["type"].split()[0].upper() if matches else None
    mismatch = bool(expected and detected_family and expected not in matches[0]["type"].upper())

    return {
        "detected": matches or [{"type": "unknown (no known signature)"}],
        "claimed_extension": ext or None,
        "extension_mismatch": mismatch,
        "note": "content does not match extension — possible masquerading" if mismatch else "",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Identify file type")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("identify")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(identify(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
