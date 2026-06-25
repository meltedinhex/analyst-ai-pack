#!/usr/bin/env python3
"""Disassemble and (optionally) emulate raw shellcode.

``disasm`` uses Capstone to linearly disassemble a flat byte blob at a chosen architecture.
``emulate`` uses Unicorn to run the blob in an isolated emulator with bounded instruction
count, capturing executed addresses — useful for self-decoding stubs. Both operate in-process
on the emulator/disassembler; nothing runs on the real CPU as a process.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def disasm(data: bytes, arch: str, base: int, limit: int = 200) -> list[dict]:
    from capstone import (  # type: ignore
        Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
    )
    mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    out = []
    for i, insn in enumerate(md.disasm(data, base)):
        if i >= limit:
            break
        out.append({"addr": hex(insn.address), "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str})
    return out


def emulate(data: bytes, arch: str, base: int, max_insns: int = 5000) -> dict:
    from unicorn import (  # type: ignore
        Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UcError,
    )
    from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_EIP  # type: ignore

    mode = UC_MODE_64 if arch == "x64" else UC_MODE_32
    mu = Uc(UC_ARCH_X86, mode)
    region = 0x10 * 1024 * 1024
    map_base = base & ~0xFFF
    mu.mem_map(map_base, region)
    mu.mem_write(base, data)

    executed: list[int] = []

    def hook_code(uc, address, size, user_data):  # noqa: ANN001
        executed.append(address)
        if len(executed) >= max_insns:
            uc.emu_stop()

    from unicorn import UC_HOOK_CODE  # type: ignore
    mu.hook_add(UC_HOOK_CODE, hook_code)
    error = None
    try:
        mu.emu_start(base, base + len(data), count=max_insns)
    except UcError as exc:
        error = str(exc)
    reg = UC_X86_REG_RIP if arch == "x64" else UC_X86_REG_EIP
    return {
        "instructions_executed": len(executed),
        "first_addrs": [hex(a) for a in executed[:20]],
        "stopped_at": hex(mu.reg_read(reg)),
        "error": error,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Shellcode disasm/emulate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_d = sub.add_parser("disasm")
    p_d.add_argument("file")
    p_d.add_argument("--arch", choices=["x86", "x64"], default="x64")
    p_d.add_argument("--base", default="0x1000")

    p_e = sub.add_parser("emulate")
    p_e.add_argument("file")
    p_e.add_argument("--arch", choices=["x86", "x64"], default="x64")
    p_e.add_argument("--base", default="0x1000")

    args = parser.parse_args(argv)
    data = Path(args.file).read_bytes()
    base = int(args.base, 0)
    try:
        if args.cmd == "disasm":
            print(json.dumps(disasm(data, args.arch, base), indent=2))
        else:
            print(json.dumps(emulate(data, args.arch, base), indent=2))
    except ImportError as exc:
        print(f"missing dependency: {exc} (pip install capstone unicorn)", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
