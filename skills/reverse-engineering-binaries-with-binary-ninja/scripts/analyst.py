#!/usr/bin/env python3
"""Generate Binary Ninja Python API analysis scripts (and report API availability).

`check` reports whether the binaryninja API is importable. `skeleton` writes a Binary Ninja script
that opens a view, iterates functions, and exports functions/strings to JSON using the real API.
This tool only generates text — it does not run Binary Ninja or any sample.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import binaryninja  # type: ignore  # noqa: F401
    HAVE_BN = True
except ImportError:
    HAVE_BN = False

FUNCTIONS_SNIPPET = '''
    for func in bv.functions:
        result["functions"].append({
            "name": func.name,
            "start": hex(func.start),
            "basic_blocks": len(list(func.basic_blocks)),
        })
'''

STRINGS_SNIPPET = '''
    for s in bv.get_strings():
        result["strings"].append({"value": s.value, "start": hex(s.start)})
'''


def check() -> dict:
    return {"binaryninja_api_available": HAVE_BN}


def skeleton(out: str, emit: list[str]) -> dict:
    keys = []
    body = []
    if "functions" in emit:
        keys.append('"functions": []')
        body.append(FUNCTIONS_SNIPPET)
    if "strings" in emit:
        keys.append('"strings": []')
        body.append(STRINGS_SNIPPET)
    script = (
        "#!/usr/bin/env python3\n"
        "# Binary Ninja headless analysis script (generated skeleton).\n"
        "import json\n"
        "import sys\n"
        "import binaryninja\n\n"
        "def analyze(path):\n"
        "    bv = binaryninja.open_view(path)\n"
        "    result = {%s}\n%s"
        "    return result\n\n"
        "if __name__ == '__main__':\n"
        "    print(json.dumps(analyze(sys.argv[1]), indent=2))\n"
    ) % (", ".join(keys), "".join(body))
    Path(out).write_text(script, encoding="utf-8")
    return {"output": out, "emits": emit, "binaryninja_api_available": HAVE_BN}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Binary Ninja script generator")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    ps = sub.add_parser("skeleton")
    ps.add_argument("--emit", default="functions,strings")
    ps.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "check":
        print(json.dumps(check(), indent=2))
    else:
        print(json.dumps(skeleton(args.out, [e.strip() for e in args.emit.split(",")]),
                         indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
