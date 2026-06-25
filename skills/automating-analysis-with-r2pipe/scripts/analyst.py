#!/usr/bin/env python3
"""Automate radare2/rizin static analysis through r2pipe.

`check` reports tool availability. `summary` opens a binary, runs static analysis (aaa), and
collects functions (aflj), imports (iij), and strings (izj) as JSON. r2pipe is optional; without
it the script reports that automation is unavailable. Drives static analysis commands only and
does not run the sample in a debugger.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys

try:
    import r2pipe  # type: ignore
    HAVE_R2PIPE = True
except ImportError:
    HAVE_R2PIPE = False


def _r2_binary() -> str | None:
    for name in ("radare2", "r2", "rizin"):
        if shutil.which(name):
            return name
    return None


def check() -> dict:
    return {
        "r2pipe_available": HAVE_R2PIPE,
        "r2_binary": _r2_binary(),
        "ready": HAVE_R2PIPE and _r2_binary() is not None,
    }


def _cmdj(r2, command: str):  # noqa: ANN001
    try:
        return r2.cmdj(command) or []
    except Exception:
        return []


def summary(path: str) -> dict:
    if not HAVE_R2PIPE:
        return {"error": "r2pipe not installed", "r2pipe_available": False}
    r2 = r2pipe.open(path, flags=["-2"])  # -2 closes stderr noise
    try:
        r2.cmd("aaa")
        funcs = _cmdj(r2, "aflj")
        imports = _cmdj(r2, "iij")
        strings = _cmdj(r2, "izj")
        result = {
            "function_count": len(funcs),
            "functions": [{"name": f.get("name"), "offset": f.get("offset"),
                           "size": f.get("size")} for f in funcs[:200]],
            "imports": [i.get("name") for i in imports if i.get("name")][:200],
            "strings": [s.get("string") for s in strings if s.get("string")][:200],
        }
    finally:
        r2.quit()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Automate r2/rizin via r2pipe")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    ps = sub.add_parser("summary")
    ps.add_argument("file")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        print(json.dumps(check(), indent=2))
    else:
        print(json.dumps(summary(args.file), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
