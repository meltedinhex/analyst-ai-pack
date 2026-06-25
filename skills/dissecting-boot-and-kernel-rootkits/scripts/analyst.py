#!/usr/bin/env python3
"""Classify bootkit/rootkit artifacts and surface tampering/hooking indicators.

Detects MBR/VBR boot sectors (0x55AA signature), UEFI modules, and kernel drivers, then scans
strings for boot-tampering (Int 13h), kernel hooking (SSDT/IRP/Zw*/Ke*), and DKOM indicators.
Reads bytes statically; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")

KERNEL_IMPORTS = ["ntoskrnl.exe", "hal.dll", "ndis.sys", "fltmgr.sys", "wdfldr.sys"]
HOOK_INDICATORS = ["keservicedescriptortable", "kservicedescriptortable", "iocreatedevice",
                   "ioattachdevice", "psssetcreateprocessnotifyroutine",
                   "psssetloadimagenotifyroutine", "obregistercallbacks", "ssdt", "irp_mj"]
DKOM_INDICATORS = ["eprocess", "activeprocesslinks", "psinitialsystemprocess", "kdblock"]
BOOT_INDICATORS = ["int 13", "\xcd\x13", "invalid partition table", "missing operating system",
                   "bootmgr"]
UEFI_INDICATORS = ["efi_", "gefisystemtable", "bootservices", "runtimeservices",
                   "gizmo_efi", "setvariable"]


def _strings(data: bytes) -> str:
    return "\n".join(m.decode("latin-1", "ignore") for m in ASCII_RE.findall(data)).lower()


def _is_mbr(data: bytes) -> bool:
    return len(data) >= 512 and data[0x1FE:0x200] == b"\x55\xaa"


def _is_pe(data: bytes) -> tuple[bool, int | None]:
    if data[:2] != b"MZ":
        return False, None
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return False, None
    subsystem = struct.unpack_from("<H", data, e_lfanew + 24 + 68)[0]
    return True, subsystem


def classify(path: str) -> dict:
    data = Path(path).read_bytes()
    blob = _strings(data)
    raw_low = data[:4096].lower()
    is_pe, subsystem = _is_pe(data)
    # PE subsystems: 1 native (driver), 10-13 EFI.
    is_driver = is_pe and (subsystem == 1 or any(k in blob for k in KERNEL_IMPORTS))
    is_uefi = is_pe and (subsystem in (10, 11, 12, 13) or any(u in blob for u in UEFI_INDICATORS))
    is_mbr = _is_mbr(data)
    artifact = ("MBR/VBR boot sector" if is_mbr else "UEFI module" if is_uefi
                else "kernel driver" if is_driver else "PE" if is_pe else "unknown")
    return {
        "artifact_type": artifact,
        "is_mbr_vbr": is_mbr,
        "is_uefi_module": is_uefi,
        "is_kernel_driver": is_driver,
        "boot_tampering_indicators": sorted({b for b in BOOT_INDICATORS
                                             if b in blob or b.encode("latin-1") in raw_low}),
        "kernel_hooking_indicators": sorted({h for h in HOOK_INDICATORS if h in blob}),
        "dkom_indicators": sorted({d for d in DKOM_INDICATORS if d in blob}),
        "persistence_vector": ("MBR/VBR overwrite" if is_mbr else "UEFI module/variable" if is_uefi
                               else "driver service" if is_driver else "undetermined"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify bootkit/rootkit artifacts")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("classify")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(classify(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
