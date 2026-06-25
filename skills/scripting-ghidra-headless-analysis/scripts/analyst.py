#!/usr/bin/env python3
"""Generate Ghidra analyzeHeadless commands and post-analysis script skeletons.

`command` builds an analyzeHeadless invocation; `postscript` emits a Jython-compatible Ghidra
script that exports functions and/or strings to JSON. This tool only generates text — it does not
run Ghidra or any sample.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

FUNCTIONS_SNIPPET = '''
def emit_functions():
    fm = currentProgram.getFunctionManager()
    out = []
    for f in fm.getFunctions(True):
        out.append({
            "name": f.getName(),
            "entry": str(f.getEntryPoint()),
            "size": f.getBody().getNumAddresses(),
        })
    return out
'''

STRINGS_SNIPPET = '''
def emit_strings():
    from ghidra.program.model.data import StringDataType
    out = []
    listing = currentProgram.getListing()
    data = listing.getDefinedData(True)
    for d in data:
        if d.getDataType() and "string" in d.getDataType().getName().lower():
            val = d.getValue()
            if val is not None:
                out.append(str(val))
    return out
'''


def command(project: str, name: str, import_dir: str, script: str | None,
            recursive: bool, overwrite: bool) -> dict:
    parts = ["analyzeHeadless", project, name, "-import", import_dir]
    if recursive:
        parts.append("-recursive")
    if overwrite:
        parts.append("-overwrite")
    if script:
        parts += ["-postScript", script]
    cmd = " ".join(shlex.quote(p) for p in parts)
    return {"command": cmd, "note": "run from Ghidra's support/ directory"}


def postscript(out: str, emit: list[str]) -> dict:
    lines = ["# Ghidra post-analysis script (Jython 2). Generated skeleton.",
             "import json", "import os", ""]
    funcs = []
    if "functions" in emit:
        lines.append(FUNCTIONS_SNIPPET)
        funcs.append('"functions": emit_functions()')
    if "strings" in emit:
        lines.append(STRINGS_SNIPPET)
        funcs.append('"strings": emit_strings()')
    lines.append("result = {%s}" % ", ".join(funcs) if funcs else "result = {}")
    lines.append('out_path = currentProgram.getExecutablePath() + ".ghidra.json"')
    lines.append('f = open(os.path.basename(out_path), "w")')
    lines.append("f.write(json.dumps(result, indent=2))")
    lines.append("f.close()")
    Path(out).write_text("\n".join(lines), encoding="utf-8")
    return {"output": out, "emits": emit}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Ghidra headless automation")
    sub = parser.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("command")
    pc.add_argument("--project", required=True)
    pc.add_argument("--name", required=True)
    pc.add_argument("--import", dest="import_dir", required=True)
    pc.add_argument("--script")
    pc.add_argument("--recursive", action="store_true", default=True)
    pc.add_argument("--overwrite", action="store_true", default=True)
    pp = sub.add_parser("postscript")
    pp.add_argument("--out", required=True)
    pp.add_argument("--emit", default="functions,strings")
    args = parser.parse_args(argv)
    if args.cmd == "command":
        print(json.dumps(command(args.project, args.name, args.import_dir, args.script,
                                 args.recursive, args.overwrite), indent=2))
    else:
        print(json.dumps(postscript(args.out, [e.strip() for e in args.emit.split(",")]),
                         indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
