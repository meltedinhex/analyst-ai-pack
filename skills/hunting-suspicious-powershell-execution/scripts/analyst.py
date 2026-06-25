#!/usr/bin/env python3
"""Score and decode PowerShell script-block events for malicious indicators.

Reads a JSON list of events (each with a ``script_block`` text field), scores suspicious
construct combinations, and decodes any ``-EncodedCommand`` base64 (UTF-16LE) payloads. It
reads local JSON and decodes strings only; it never executes PowerShell.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

WEIGHTS = [
    (re.compile(r"-enc(odedcommand)?\b", re.I), 30, "encoded command"),
    (re.compile(r"frombase64string", re.I), 20, "base64 decode"),
    (re.compile(r"\b(iex|invoke-expression)\b", re.I), 15, "invoke-expression"),
    (re.compile(r"net\.webclient|invoke-webrequest|downloadstring|downloadfile", re.I), 25,
     "download cradle"),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.I), 15, "hidden window"),
    (re.compile(r"-nop|noprofile", re.I), 5, "no profile"),
    (re.compile(r"amsiinitfailed|amsiutils|\[ref\]\.assembly", re.I), 30, "AMSI/logging bypass"),
    (re.compile(r"reflection\.assembly|\[system\.reflection", re.I), 20, "reflective load"),
    (re.compile(r"-ep\s+bypass|executionpolicy\s+bypass", re.I), 10, "exec policy bypass"),
]

B64_ENC = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)


def decode_encoded(text: str) -> list[str]:
    out = []
    for m in B64_ENC.finditer(text):
        blob = m.group(1)
        try:
            raw = base64.b64decode(blob)
            out.append(raw.decode("utf-16-le", errors="replace"))
        except (binascii.Error, ValueError):
            continue
    return out


def score_event(text: str) -> dict:
    score = 0
    reasons = []
    for rx, weight, label in WEIGHTS:
        if rx.search(text):
            score += weight
            reasons.append(label)
    decoded = decode_encoded(text)
    if decoded:
        # re-score decoded content for layered obfuscation
        for d in decoded:
            for rx, weight, label in WEIGHTS:
                if rx.search(d):
                    score += weight // 2
                    reasons.append(f"decoded:{label}")
    return {"score": score, "reasons": sorted(set(reasons)), "decoded": decoded}


def run(events: list[dict]) -> dict:
    scored = []
    for ev in events:
        text = ev.get("script_block", "")
        res = score_event(text)
        if res["score"] >= 30:
            scored.append({"host": ev.get("host"), "user": ev.get("user"), **res})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return {"candidates": scored, "evaluated": len(events)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score PowerShell script-block events")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("score")
    p.add_argument("file", help="JSON list of script-block events")
    args = parser.parse_args(argv)
    events = json.loads(Path(args.file).read_text(encoding="utf-8"))
    print(json.dumps(run(events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
