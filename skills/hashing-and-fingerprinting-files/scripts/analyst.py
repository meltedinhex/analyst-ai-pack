#!/usr/bin/env python3
"""Compute cryptographic and structural fingerprints for a file.

Always computes MD5/SHA-1/SHA-256 with stdlib ``hashlib``. If ``pefile`` is available and the
input is a PE, also computes imphash and per-section SHA-256. Optional fuzzy hashes (ssdeep,
TLSH) are included when their libraries are installed. It reads the file as inert bytes and
never executes it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def crypto_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def pe_hashes(path: str) -> dict:
    try:
        import pefile  # type: ignore
    except ImportError:
        return {}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        out = {"imphash": pe.get_imphash() or None}
        sections = {}
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("latin-1")
            sections[name] = hashlib.sha256(sec.get_data()).hexdigest()
        out["section_sha256"] = sections
        return out
    except Exception as exc:  # noqa: BLE001 - pefile raises many types
        return {"pe_error": str(exc)}


def fuzzy_hashes(data: bytes) -> dict:
    out = {}
    try:
        import ssdeep  # type: ignore
        out["ssdeep"] = ssdeep.hash(data)
    except ImportError:
        pass
    try:
        import tlsh  # type: ignore
        out["tlsh"] = tlsh.hash(data)
    except ImportError:
        pass
    return out


def fingerprint(path: str) -> dict:
    data = Path(path).read_bytes()
    result = crypto_hashes(data)
    is_pe = data[:2] == b"MZ"
    if is_pe:
        result.update(pe_hashes(path))
    result.update(fuzzy_hashes(data))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fingerprint a file")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hash")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(fingerprint(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
