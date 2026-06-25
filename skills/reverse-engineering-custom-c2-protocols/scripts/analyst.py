#!/usr/bin/env python3
"""Decode a simple length-prefixed, XOR-obfuscated C2 message stream.

This is a configurable reference decoder for the common framing
``[magic][len LE][opcode][flags][payload]`` with a single-byte XOR over the payload. Adjust the
field sizes/crypto to match the protocol you reversed. It only parses bytes from a capture
file; it makes no network connections.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path


def xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def decode(stream: bytes, key: int, magic: bytes) -> dict:
    messages = []
    off = 0
    n = len(stream)
    while off + 10 <= n:
        if stream[off:off + len(magic)] != magic:
            off += 1
            continue
        p = off + len(magic)
        (length,) = struct.unpack_from("<I", stream, p)
        opcode = stream[p + 4]
        flags = stream[p + 5]
        start = p + 6
        end = start + length
        if end > n:
            break
        payload = xor(stream[start:end], key)
        messages.append({
            "offset": off,
            "opcode": opcode,
            "flags": flags,
            "length": length,
            "payload_preview": payload[:64].decode("latin-1"),
        })
        off = end
    return {"messages": messages, "count": len(messages)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode custom C2 framing")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("decode")
    p.add_argument("file")
    p.add_argument("--key", default="0x00", help="single-byte XOR key, e.g. 0x5a")
    p.add_argument("--magic", default="", help="hex magic prefix, e.g. 4d5a4331")
    args = parser.parse_args(argv)
    stream = Path(args.file).read_bytes()
    magic = bytes.fromhex(args.magic) if args.magic else b""
    print(json.dumps(decode(stream, int(args.key, 0), magic), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
