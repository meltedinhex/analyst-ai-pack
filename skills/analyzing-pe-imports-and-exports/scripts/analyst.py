#!/usr/bin/env python3
"""Parse a PE file's imports/exports and bucket APIs into capability categories.

Uses ``pefile`` to enumerate imported DLLs/functions and exports, then maps imported API names to
behavior buckets (networking, injection, crypto, persistence, anti-analysis) and flags
dynamic-resolution indicators. It parses the PE statically and never executes it.
"""
from __future__ import annotations

import argparse
import json
import sys

BEHAVIOR = {
    "networking": ["wsastartup", "connect", "send", "recv", "internetopen", "httpopenrequest",
                   "winhttpopen", "urldownloadtofile"],
    "injection": ["virtualallocex", "writeprocessmemory", "createremotethread",
                  "ntunmapviewofsection", "queueuserapc", "setthreadcontext"],
    "crypto": ["cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "bcryptencrypt",
               "cryptgenkey"],
    "persistence": ["regsetvalue", "regcreatekey", "createservice", "openscmanager",
                    "schedule"],
    "anti_analysis": ["isdebuggerpresent", "checkremotedebuggerpresent",
                      "ntqueryinformationprocess", "outputdebugstring"],
    "dynamic_resolution": ["loadlibrary", "getprocaddress", "ldrloaddll"],
}


def _bucketize(funcs: list[str]) -> dict:
    lowered = [f.lower() for f in funcs]
    out = {}
    for bucket, needles in BEHAVIOR.items():
        hits = sorted({f for f in lowered if any(n in f for n in needles)})
        if hits:
            out[bucket] = hits
    return out


def analyze(path: str) -> dict:
    import pefile  # type: ignore
    pe = pefile.PE(path)
    imports = {}
    all_funcs = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin-1") if entry.dll else "?"
            funcs = []
            for imp in entry.imports:
                name = imp.name.decode("latin-1") if imp.name else f"ordinal_{imp.ordinal}"
                funcs.append(name)
            imports[dll] = funcs
            all_funcs.extend(funcs)

    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({"name": exp.name.decode("latin-1") if exp.name else None,
                            "ordinal": exp.ordinal})

    return {
        "imported_dlls": len(imports),
        "imported_functions": len(all_funcs),
        "imports": imports,
        "exports": exports,
        "capabilities": _bucketize(all_funcs),
        "thin_iat": len(all_funcs) < 10,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze PE imports/exports")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("imports")
    p.add_argument("file")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(analyze(args.file), indent=2))
    except ImportError:
        print("missing dependency: pefile (pip install pefile)", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
