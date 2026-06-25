#!/usr/bin/env python3
"""Generate IDAPython analysis scripts and the headless idat batch command.

`script` emits an IDAPython script that enumerates functions and/or strings and exports JSON.
`batch` builds the `idat -A -S"<script>" <input>` invocation. This tool only generates text — it
does not run IDA or any sample.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

FUNCTIONS_SNIPPET = '''
    import idautils, idc
    for ea in idautils.Functions():
        result["functions"].append({
            "name": idc.get_func_name(ea),
            "start": hex(ea),
        })
'''

STRINGS_SNIPPET = '''
    import idautils
    for s in idautils.Strings():
        result["strings"].append({"ea": hex(s.ea), "value": str(s)})
'''


def script(out: str, emit: list[str]) -> dict:
    keys, body = [], []
    if "functions" in emit:
        keys.append('"functions": []')
        body.append(FUNCTIONS_SNIPPET)
    if "strings" in emit:
        keys.append('"strings": []')
        body.append(STRINGS_SNIPPET)
    text = (
        "# IDAPython analysis script (generated skeleton).\n"
        "import json\n"
        "import ida_pro\n"
        "import ida_auto\n\n"
        "def run():\n"
        "    ida_auto.auto_wait()  # ensure auto-analysis is complete\n"
        "    result = {%s}\n%s"
        "    with open(ida_pro.idainfo_get_path() + '.ida.json', 'w') as fh:\n"
        "        fh.write(json.dumps(result, indent=2))\n\n"
        "run()\n"
        "ida_pro.qexit(0)  # exit IDA after the script in batch mode\n"
    ) % (", ".join(keys), "".join(body))
    Path(out).write_text(text, encoding="utf-8")
    return {"output": out, "emits": emit}


def batch(script_path: str, input_path: str) -> dict:
    # -A: autonomous (no dialogs), -S: run script, then the input file.
    cmd = f'idat -A -S{shlex.quote(script_path)} {shlex.quote(input_path)}'
    return {"command": cmd,
            "note": "use idat64 for 64-bit inputs; add -L<logfile> to capture output"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate IDAPython automation")
    sub = parser.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("script")
    ps.add_argument("--emit", default="functions,strings")
    ps.add_argument("--out", required=True)
    pb = sub.add_parser("batch")
    pb.add_argument("--script", required=True)
    pb.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "script":
        print(json.dumps(script(args.out, [e.strip() for e in args.emit.split(",")]), indent=2))
    else:
        print(json.dumps(batch(args.script, args.input), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
