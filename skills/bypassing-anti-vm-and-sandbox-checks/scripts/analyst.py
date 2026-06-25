#!/usr/bin/env python3
"""Locate anti-VM/sandbox detection routines to plan a bypass.

Scans printable strings and opcode patterns for anti-VM artifacts, timing APIs, CPUID usage, and
environment-fingerprint APIs, reporting offsets to guide patching/hooking. Reads bytes statically;
executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")

ARTIFACT_STRINGS = [b"vmware", b"virtualbox", b"vbox", b"qemu", b"xen", b"vmtoolsd",
                    b"vboxservice", b"sbiedll", b"sandboxie", b"cuckoo", b"prl_", b"hyperv"]
TIMING_APIS = [b"GetTickCount", b"QueryPerformanceCounter", b"timeGetTime"]
FINGERPRINT_APIS = [b"GetAdaptersInfo", b"GetComputerName", b"GetUserName",
                    b"GlobalMemoryStatusEx", b"GetSystemInfo", b"EnumProcesses"]
# Opcode anchors: CPUID (0F A2), RDTSC (0F 31).
CPUID = b"\x0f\xa2"
RDTSC = b"\x0f\x31"


def _find(data: bytes, needle: bytes, ci: bool = True, limit: int = 10) -> list[int]:
    hay = data.lower() if ci else data
    pin = needle.lower() if ci else needle
    out = []
    start = 0
    while len(out) < limit:
        idx = hay.find(pin, start)
        if idx == -1:
            break
        out.append(idx)
        start = idx + 1
    return out


def locate(path: str) -> dict:
    data = Path(path).read_bytes()
    artifacts = {}
    for s in ARTIFACT_STRINGS:
        hits = _find(data, s)
        if hits:
            artifacts[s.decode()] = hits
    timing = {s.decode(): _find(data, s, ci=False) for s in TIMING_APIS
              if _find(data, s, ci=False)}
    fingerprint = {s.decode(): _find(data, s, ci=False) for s in FINGERPRINT_APIS
                   if _find(data, s, ci=False)}
    cpuid_hits = _find(data, CPUID, ci=False, limit=20)
    rdtsc_hits = _find(data, RDTSC, ci=False, limit=20)
    return {
        "anti_vm_artifact_strings": artifacts,
        "timing_apis": timing,
        "fingerprint_apis": fingerprint,
        "cpuid_opcode_offsets": cpuid_hits,
        "rdtsc_opcode_offsets": rdtsc_hits,
        "evasion_checks_present": bool(artifacts or timing or cpuid_hits or rdtsc_hits),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Locate anti-VM/sandbox checks")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("locate")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(locate(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
