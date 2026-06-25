#!/usr/bin/env python3
"""Parse a Windows shell link (.lnk) and recover its command and arguments.

Implements a minimal [MS-SHLLINK] parser using stdlib ``struct``: it validates the header,
reads LinkFlags, and walks the optional StringData section to extract the name, relative path,
working directory, command-line arguments, and icon location. It also reports any data appended
past the structure. It parses bytes statically and never executes the shortcut.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

HEADER_SIZE = 0x4C
LINK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

# LinkFlags bits relevant to StringData (MS-SHLLINK 2.1.1)
F_HAS_LINK_TARGET_IDLIST = 0x00000001
F_HAS_NAME = 0x00000004
F_HAS_RELATIVE_PATH = 0x00000008
F_HAS_WORKING_DIR = 0x00000010
F_HAS_ARGUMENTS = 0x00000020
F_HAS_ICON_LOCATION = 0x00000040
F_IS_UNICODE = 0x00000080


def _read_stringdata(data: bytes, off: int, unicode_: bool) -> tuple[str, int]:
    count = struct.unpack_from("<H", data, off)[0]
    off += 2
    if unicode_:
        raw = data[off:off + count * 2]
        off += count * 2
        return raw.decode("utf-16-le", "replace"), off
    raw = data[off:off + count]
    off += count
    return raw.decode("latin-1", "replace"), off


def parse(path: str) -> dict:
    data = Path(path).read_bytes()
    if len(data) < HEADER_SIZE or struct.unpack_from("<I", data, 0)[0] != HEADER_SIZE:
        return {"error": "not a LNK (bad HeaderSize)"}
    if data[4:20] != LINK_CLSID:
        return {"error": "not a LNK (bad CLSID)"}
    flags = struct.unpack_from("<I", data, 20)[0]
    unicode_ = bool(flags & F_IS_UNICODE)
    off = HEADER_SIZE

    # Skip LinkTargetIDList if present
    if flags & F_HAS_LINK_TARGET_IDLIST:
        idlist_size = struct.unpack_from("<H", data, off)[0]
        off += 2 + idlist_size

    # Skip LinkInfo if present (HasLinkInfo = 0x2)
    if flags & 0x00000002:
        link_info_size = struct.unpack_from("<I", data, off)[0]
        off += link_info_size

    result = {"flags": hex(flags), "unicode": unicode_}
    for bit, key in [(F_HAS_NAME, "name"), (F_HAS_RELATIVE_PATH, "relative_path"),
                     (F_HAS_WORKING_DIR, "working_dir"), (F_HAS_ARGUMENTS, "arguments"),
                     (F_HAS_ICON_LOCATION, "icon_location")]:
        if flags & bit and off < len(data):
            try:
                value, off = _read_stringdata(data, off, unicode_)
                result[key] = value
            except struct.error:
                break

    result["appended_data_bytes"] = max(0, len(data) - off)
    args = result.get("arguments", "")
    result["suspicious"] = any(t in args.lower() for t in
                               ("powershell", "-enc", "cmd", "mshta", "rundll32", "frombase64"))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse a malicious LNK")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("parse")
    p.add_argument("file")
    args = parser.parse_args(argv)
    print(json.dumps(parse(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
