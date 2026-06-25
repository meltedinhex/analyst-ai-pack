#!/usr/bin/env python3
"""Emulate raw shellcode with Unicorn to trace execution and recover decoded stages.

`prep` reports blob size and Unicorn availability. `emulate` maps the shellcode, sets up a stack,
hooks instruction and memory-write events, runs up to an instruction budget, and reports executed
instruction count and written regions. Unicorn is optional; without it the script still does
static prep. Designed for isolated VMs; emulation contains the code rather than running it natively.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_HOOK_CODE, \
        UC_HOOK_MEM_WRITE, UcError
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_ESP
    HAVE_UNICORN = True
except ImportError:
    HAVE_UNICORN = False

BASE = 0x100000
STACK = 0x300000
STACK_SIZE = 0x10000
MAP_SIZE = 0x200000


def prep(path: str, arch: str) -> dict:
    data = Path(path).read_bytes()
    return {
        "size": len(data),
        "arch": arch,
        "unicorn_available": HAVE_UNICORN,
        "note": "install 'unicorn' to enable emulation" if not HAVE_UNICORN else "ready",
    }


def emulate(path: str, arch: str, max_insns: int) -> dict:
    if not HAVE_UNICORN:
        return {"error": "unicorn not installed", "unicorn_available": False}
    code = Path(path).read_bytes()
    mode = UC_MODE_64 if arch == "x64" else UC_MODE_32
    sp_reg = UC_X86_REG_RSP if arch == "x64" else UC_X86_REG_ESP
    uc = Uc(UC_ARCH_X86, mode)
    uc.mem_map(BASE, MAP_SIZE)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_write(BASE, code)
    uc.reg_write(sp_reg, STACK + STACK_SIZE // 2)

    state = {"insns": 0, "writes": []}

    def hook_code(uc_, address, size, user):  # noqa: ANN001
        state["insns"] += 1
        if state["insns"] >= max_insns:
            uc_.emu_stop()

    def hook_write(uc_, access, address, size, value, user):  # noqa: ANN001
        if address < BASE or address >= BASE + MAP_SIZE:
            return
        state["writes"].append(address)

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
    error = None
    try:
        uc.emu_start(BASE, BASE + len(code))
    except UcError as exc:
        error = str(exc)
    written = sorted(set(state["writes"]))
    return {
        "executed_instructions": state["insns"],
        "self_modified_addresses": [hex(a) for a in written[:50]],
        "wrote_into_code_region": bool(written),
        "stopped_reason": error or "completed or instruction budget reached",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emulate shellcode with Unicorn")
    sub = parser.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("prep")
    pp.add_argument("file")
    pp.add_argument("--arch", choices=["x86", "x64"], default="x64")
    pe = sub.add_parser("emulate")
    pe.add_argument("file")
    pe.add_argument("--arch", choices=["x86", "x64"], default="x64")
    pe.add_argument("--max-insns", type=int, default=200000)
    args = parser.parse_args(argv)
    if args.cmd == "prep":
        print(json.dumps(prep(args.file, args.arch), indent=2))
    else:
        print(json.dumps(emulate(args.file, args.arch, args.max_insns), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
