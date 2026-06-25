#!/usr/bin/env python3
"""Scan a sample's printable strings for sandbox/VM/anti-debug evasion indicators.

Extracts ASCII/UTF-16LE strings and matches them against curated evasion artifact lists. Reports
hits grouped by category. Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

INDICATORS = {
    "anti_vm": ["vmware", "vbox", "virtualbox", "vmtoolsd", "vboxservice", "qemu", "xen",
                "red hat virtio", "vmci", "prl_", "hyperv", "innotek"],
    "anti_sandbox": ["sbiedll", "sandboxie", "cuckoo", "wireshark", "procmon", "vmsrvc",
                     "sample.exe", "malware", "maltest", "john doe"],
    "anti_debug": ["isdebuggerpresent", "checkremotedebuggerpresent",
                   "ntqueryinformationprocess", "outputdebugstring", "ntsetinformationthread",
                   "dbghelp", "blockinput"],
    "timing": ["gettickcount", "queryperformancecounter", "rdtsc",
               "timegettime", "sleep"],
    "fingerprint": ["getusername", "getcomputername", "getsystemmetrics", "globalmemorystatus",
                    "getdiskfreespace", "cpuid", "getadaptersinfo"],
}


def _strings(data: bytes) -> set[str]:
    out = {m.decode("ascii", "ignore").lower() for m in ASCII_RE.findall(data)}
    out |= {m.decode("utf-16-le", "ignore").lower() for m in UTF16_RE.findall(data)}
    return out


def scan(path: str) -> dict:
    blob = " ".join(_strings(Path(path).read_bytes()))
    results = {}
    for cat, needles in INDICATORS.items():
        hits = sorted({n for n in needles if n in blob})
        if hits:
            results[cat] = hits
    return {
        "categories_found": sorted(results.keys()),
        "indicators": results,
        "evasion_suspected": bool(results),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan for sandbox/anti-debug evasion indicators")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
