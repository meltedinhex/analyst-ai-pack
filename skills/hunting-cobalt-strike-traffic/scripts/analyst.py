#!/usr/bin/env python3
"""Hunt default-configuration Cobalt Strike artifacts in HTTP and process telemetry.

Detects default stager URIs via the checksum8 algorithm (sum of the 4-char path mod 256 == 92 for
x86, 93 for x64), default Malleable C2 URIs/user-agents, and default named pipes. Parses telemetry
only; executes nothing. Default indicators catch default configs only — operators customize them.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

CS_X86 = 92
CS_X64 = 93
DEFAULT_URIS = ["/__utm.gif", "/submit.php", "/pixel", "/pixel.gif", "/ca", "/dpixel",
                "/fwlink", "/updates", "/load"]
DEFAULT_PIPES = ["\\.\\pipe\\msagent_", "\\.\\pipe\\status_", "\\.\\pipe\\mojo_",
                 "\\.\\pipe\\postex_", "\\.\\pipe\\msse-"]
DEFAULT_UA = ["mozilla/4.0 (compatible; msie 7.0; windows nt 6.0; trident/4.0",
              "mozilla/5.0 (windows nt 6.1; wow64; trident/7.0; rv:11.0) like gecko"]


def checksum8(path_segment: str) -> int | None:
    """Cobalt Strike default stager URI uses a 4-char path whose char-sum mod 256 is 92/93."""
    seg = path_segment.strip("/")
    if len(seg) != 4 or not seg.isalnum():
        return None
    return sum(ord(c) for c in seg) % 256


def _rows(path: str):
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if path.lower().endswith(".json") or text.lstrip()[:1] in "{[":
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    else:
        for row in csv.DictReader(text.splitlines()):
            yield row


def _get(row: dict, *keys: str) -> str:
    for k in keys:
        if row.get(k):
            return str(row[k])
    return ""


def hunt(path: str) -> dict:
    stager_hits, profile_hits, pipe_hits = [], [], []
    for row in _rows(path):
        uri = _get(row, "uri", "URI", "RequestPath", "url", "cs-uri-stem")
        ua = _get(row, "user_agent", "UserAgent", "cs(User-Agent)").lower()
        pipe = _get(row, "PipeName", "pipe_name", "TargetObject").lower()
        if uri:
            cs = checksum8(uri.split("?")[0])
            if cs in (CS_X86, CS_X64):
                stager_hits.append({"uri": uri, "checksum8": cs,
                                    "arch": "x86" if cs == CS_X86 else "x64"})
            if any(d == uri.split("?")[0] for d in DEFAULT_URIS):
                profile_hits.append({"uri": uri, "type": "default_uri"})
        if ua and any(d in ua for d in DEFAULT_UA):
            profile_hits.append({"user_agent": ua[:120], "type": "default_user_agent"})
        if pipe and any(d in pipe for d in DEFAULT_PIPES):
            pipe_hits.append({"pipe": pipe[:120]})
    return {
        "default_stager_uris": stager_hits,
        "default_profile_artifacts": profile_hits,
        "default_named_pipes": pipe_hits,
        "cobalt_strike_defaults_present": bool(stager_hits or profile_hits or pipe_hits),
        "note": "default indicators only; customized profiles will not match",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt Cobalt Strike default artifacts")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
