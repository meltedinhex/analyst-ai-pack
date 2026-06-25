#!/usr/bin/env python3
"""Check a PE for an embedded Authenticode signature and summarize the certificate blob.

Parses the PE optional-header security data directory (index 4) to detect an embedded PKCS#7
signature (WIN_CERTIFICATE), reporting its presence, size, and revision/type. Deep certificate
parsing and cryptographic verification require a PKCS#7 library / OS tooling; this gives a fast,
dependency-free presence check. It parses bytes statically and never executes the sample.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

WIN_CERT_TYPE = {0x0001: "X509", 0x0002: "PKCS_SIGNED_DATA", 0x0003: "RESERVED",
                 0x0004: "TS_STACK_SIGNED"}


def check(path: str) -> dict:
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        return {"error": "not a PE"}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {"error": "no PE signature"}
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32_plus = magic == 0x20B
    dd_offset = opt + (112 if pe32_plus else 96)
    sec_dir = dd_offset + 4 * 8  # security directory is index 4
    rva, size = struct.unpack_from("<II", data, sec_dir)
    if not rva or not size:
        return {"signed_embedded": False,
                "note": "no embedded signature (may still be catalog-signed)"}
    # For the security directory, 'rva' is a file offset (not an RVA)
    dwlen, wrev, wtype = struct.unpack_from("<IHH", data, rva)
    return {
        "signed_embedded": True,
        "certificate_table_offset": rva,
        "certificate_table_size": size,
        "win_cert_length": dwlen,
        "revision": hex(wrev),
        "type": WIN_CERT_TYPE.get(wtype, hex(wtype)),
        "note": "presence only; verify cryptographically with signtool / "
                "Get-AuthenticodeSignature",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Authenticode signature presence")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(check(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
