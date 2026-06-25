#!/usr/bin/env python3
"""Classify a JSON API call trace and detect behavior signatures.

Accepts a flexible JSON trace: a list of call objects, or a dict with a "calls"/"apis" list, or a
CAPE-style apistats mapping. Categorizes API names and matches ordered sequences indicative of
process injection, dynamic API resolution, and self-deletion. Parses JSON only; executes nothing.
"""
from __future__ import annotations

import argparse
import json
import sys

CATEGORIES = {
    "process": ["createprocess", "openprocess", "createremotethread", "ntcreatethreadex",
                "resumethread", "terminateprocess"],
    "memory": ["virtualalloc", "virtualallocex", "virtualprotect", "writeprocessmemory",
               "readprocessmemory", "ntmapviewofsection", "ntunmapviewofsection"],
    "file": ["createfile", "writefile", "readfile", "deletefile", "copyfile", "movefile"],
    "registry": ["regopenkey", "regsetvalue", "regcreatekey", "regqueryvalue"],
    "network": ["internetopen", "internetconnect", "httpsendrequest", "wininet", "winhttp",
                "send", "recv", "connect", "getaddrinfo"],
    "crypto": ["cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "bcryptencrypt",
               "cryptstringtobinary"],
    "resolve": ["loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress"],
    "sync": ["createmutex", "openmutex", "createevent", "sleep", "waitforsingleobject"],
}

SIGNATURES = [
    ("remote_process_injection", ["virtualallocex", "writeprocessmemory", "createremotethread"],
     "T1055.002"),
    ("process_hollowing", ["createprocess", "ntunmapviewofsection", "writeprocessmemory"],
     "T1055.012"),
    ("dynamic_api_resolution", ["loadlibrary", "getprocaddress"], "T1027.007"),
    ("crypto_routine", ["cryptacquirecontext", "cryptdecrypt"], "T1027"),
]


def _extract_calls(obj) -> list[str]:
    if isinstance(obj, list):
        out = []
        for c in obj:
            if isinstance(c, str):
                out.append(c)
            elif isinstance(c, dict):
                out.append(c.get("api") or c.get("name") or c.get("function") or "")
        return [c for c in out if c]
    if isinstance(obj, dict):
        for key in ("calls", "apis", "apistats"):
            if key in obj:
                val = obj[key]
                if isinstance(val, dict):
                    return list(val.keys())
                return _extract_calls(val)
    return []


def _category(api: str) -> str:
    low = api.lower()
    for cat, names in CATEGORIES.items():
        if any(n in low for n in names):
            return cat
    return "other"


def classify(path: str) -> dict:
    data = json.loads(open(path, encoding="utf-8-sig").read())
    calls = _extract_calls(data)
    lowered = [c.lower() for c in calls]
    cats: dict[str, int] = {}
    unknown = set()
    for api in calls:
        cat = _category(api)
        cats[cat] = cats.get(cat, 0) + 1
        if cat == "other":
            unknown.add(api)
    detected = []
    for name, seq, tech in SIGNATURES:
        pos = 0
        for needle in seq:
            found = next((i for i in range(pos, len(lowered)) if needle in lowered[i]), -1)
            if found == -1:
                break
            pos = found + 1
        else:
            detected.append({"behavior": name, "attack": tech})
    return {
        "total_calls": len(calls),
        "categories": cats,
        "behaviors": detected,
        "unknown_apis": sorted(unknown)[:50],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify an API call trace")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("classify")
    p.add_argument("trace")
    args = parser.parse_args(argv)
    print(json.dumps(classify(args.trace), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
