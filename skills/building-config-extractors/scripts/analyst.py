#!/usr/bin/env python3
"""Apply a declarative JSON spec to extract a malware config from a sample.

Spec format:
{
  "blob": {"offset": 0, "length": 256}  OR  {"marker": "CFG0", "length": 256},
  "decode": [{"type": "xor", "key": "0x5a"}, {"type": "base64"}],
  "fields": [{"name": "c2", "offset": 0, "length": 64, "type": "str"},
             {"name": "port", "offset": 64, "type": "u16"},
             {"name": "ip", "offset": 66, "type": "ipv4"}]
}
Reads sample bytes statically; executes nothing. Defangs url/ipv4 string fields.
"""
from __future__ import annotations

import argparse
import base64
import json
import struct
import sys
from pathlib import Path


def _locate_blob(data: bytes, blob: dict) -> bytes:
    length = blob.get("length")
    if "marker" in blob:
        marker = blob["marker"].encode("latin-1")
        idx = data.find(marker)
        if idx == -1:
            raise ValueError("marker not found")
        start = idx + len(marker)
    else:
        start = int(blob.get("offset", 0))
    return data[start:start + length] if length else data[start:]


def _apply_decode(blob: bytes, layers: list[dict]) -> bytes:
    out = blob
    for layer in layers:
        kind = layer["type"]
        if kind == "xor":
            key = layer["key"]
            key_bytes = (bytes([int(key, 0)]) if isinstance(key, str) and key.startswith("0x")
                         else key.encode("latin-1") if isinstance(key, str) else bytes([key]))
            out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(out))
        elif kind == "base64":
            out = base64.b64decode(out + b"===")
        else:
            raise ValueError("unknown decode layer: %s" % kind)
    return out


def _defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def _parse_field(blob: bytes, field: dict):
    off = int(field.get("offset", 0))
    ftype = field.get("type", "str")
    if ftype == "str":
        length = int(field.get("length", 0))
        raw = blob[off:off + length] if length else blob[off:]
        value = raw.split(b"\x00", 1)[0].decode("latin-1", "ignore").strip()
        # Defang only string fields that carry a URL or dotted-quad endpoint.
        if "http" in value or value.count(".") == 3:
            value = _defang(value)
        return value
    if ftype == "u16":
        return struct.unpack_from("<H", blob, off)[0]
    if ftype == "u32":
        return struct.unpack_from("<I", blob, off)[0]
    if ftype == "ipv4":
        return _defang(".".join(str(b) for b in blob[off:off + 4]))
    raise ValueError("unknown field type: %s" % ftype)


def extract(path: str, spec: dict) -> dict:
    data = Path(path).read_bytes()
    blob = _apply_decode(_locate_blob(data, spec["blob"]), spec.get("decode", []))
    config = {field["name"]: _parse_field(blob, field) for field in spec.get("fields", [])}
    return {"config": config}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Spec-driven config extractor")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract")
    p.add_argument("file")
    p.add_argument("--spec", required=True)
    args = parser.parse_args(argv)
    spec = json.loads(Path(args.spec).read_text(encoding="utf-8-sig"))
    print(json.dumps(extract(args.file, spec), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
