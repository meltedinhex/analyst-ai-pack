#!/usr/bin/env python3
"""Static PE analysis: headers, sections, entropy, and import classification.

Uses ``pefile`` when available; falls back to a minimal built-in PE header walk so the tool
still reports sections and entropy without third-party packages. Never executes the sample.
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from collections import Counter
from pathlib import Path

_IMPORT_BUCKETS = {
    "injection": {"virtualallocex", "writeprocessmemory", "createremotethread",
                  "ntunmapviewofsection", "queueuserapc", "setthreadcontext"},
    "network": {"internetopena", "internetopenw", "httpsendrequesta", "winhttpconnect",
                "wsastartup", "connect", "send", "urldownloadtofilea"},
    "crypto": {"cryptencrypt", "cryptdecrypt", "cryptacquirecontexta",
               "cryptgenkey", "bcryptencrypt"},
    "persistence": {"regsetvalueexa", "regsetvalueexw", "createservicea",
                    "createservicew", "schtasks"},
    "evasion": {"isdebuggerpresent", "checkremotedebuggerpresent",
                "gettickcount", "loadlibrarya", "getprocaddress"},
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyze_with_pefile(path: str) -> dict:
    import pefile  # type: ignore
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()
    sections = [{
        "name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
        "vsize": s.Misc_VirtualSize,
        "rawsize": s.SizeOfRawData,
        "entropy": round(s.get_entropy(), 3),
    } for s in pe.sections]
    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode("ascii", "replace"))
    buckets = _classify(imports)
    return {
        "is_dll": pe.is_dll(),
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": sections,
        "import_count": len(imports),
        "import_buckets": buckets,
        "tls_callbacks": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
    }


def _classify(imports: list[str]) -> dict[str, list[str]]:
    low = [i.lower() for i in imports]
    return {bucket: sorted({i for i in low if i in names})
            for bucket, names in _IMPORT_BUCKETS.items()
            if any(i in names for i in low)}


def analyze_minimal(path: str) -> dict:
    """Fallback header walk without pefile: sections + entropy only."""
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("not a PE (no MZ header)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (no PE signature)")
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 24 + opt_size
    sections = []
    for i in range(num_sections):
        base = sec_off + i * 40
        name = data[base:base + 8].rstrip(b"\x00").decode("ascii", "replace")
        raw_size = struct.unpack_from("<I", data, base + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, base + 20)[0]
        blob = data[raw_ptr:raw_ptr + raw_size]
        sections.append({"name": name, "rawsize": raw_size,
                         "entropy": round(entropy(blob), 3)})
    return {"sections": sections, "note": "pefile not installed; minimal parse"}


def analyze(path: str) -> dict:
    try:
        return analyze_with_pefile(path)
    except ImportError:
        return analyze_minimal(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static PE analysis")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
