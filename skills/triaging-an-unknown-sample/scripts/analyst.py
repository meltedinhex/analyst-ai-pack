#!/usr/bin/env python3
"""First-pass triage for an unknown file: type, hashes, entropy, and strings.

Pure static analysis on file bytes. Optionally checks a hash against VirusTotal if a key is
provided (hash lookup only; it never uploads the file). It never executes the sample.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

# magic-byte signatures -> label
_MAGIC = [
    (b"MZ", "PE/DOS executable"),
    (b"\x7fELF", "ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O (fat) / Java class"),
    (b"\xfe\xed\xfa", "Mach-O"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP/OOXML/JAR archive"),
    (b"\xd0\xcf\x11\xe0", "OLE2 (legacy Office)"),
    (b"Rar!", "RAR archive"),
    (b"\x1f\x8b", "gzip"),
]

_SUSPICIOUS = re.compile(
    rb"(https?://|cmd\.exe|powershell|VirtualAlloc|CreateRemoteThread|WScript|"
    rb"RegSetValue|URLDownloadToFile|\\\\\.\\pipe\\|-enc |FromBase64String)",
    re.I,
)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def identify(data: bytes) -> str:
    for magic, label in _MAGIC:
        if data.startswith(magic):
            return label
    return "unknown"


def extract_strings(data: bytes, minlen: int = 5) -> list[str]:
    found = re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)
    return [s.decode("ascii", "replace") for s in found]


def suspicious_strings(data: bytes) -> list[str]:
    return sorted({m.group(0).decode("ascii", "replace") for m in _SUSPICIOUS.finditer(data)})


def triage(filepath: str | Path) -> dict:
    data = Path(filepath).read_bytes()
    ent = shannon_entropy(data)
    sus = suspicious_strings(data)
    embedded_pe = data.count(b"MZ") > 1
    score = 0
    score += 2 if ent > 7.2 else 0
    score += 2 if sus else 0
    score += 2 if embedded_pe else 0
    verdict = "deep-analysis" if score >= 4 else "review" if score >= 2 else "low-signal"
    return {
        "file": str(filepath),
        "type": identify(data),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(ent, 3),
        "likely_packed": ent > 7.2,
        "embedded_pe": embedded_pe,
        "suspicious_strings": sus,
        "triage_score": score,
        "recommendation": verdict,
    }


def reputation(sha256: str, vt_key: str) -> dict:
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": vt_key},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            body = json.loads(resp.read())
        stats = body["data"]["attributes"]["last_analysis_stats"]
        return {"sha256": sha256, "found": True, "stats": stats}
    except Exception as exc:  # noqa: BLE001 - report, do not crash triage
        return {"sha256": sha256, "found": False, "error": str(exc)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage an unknown sample")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_tri = sub.add_parser("triage", help="static triage of a file")
    p_tri.add_argument("file")

    p_rep = sub.add_parser("reputation", help="VirusTotal hash lookup")
    p_rep.add_argument("--sha256", required=True)
    p_rep.add_argument("--vt-key", required=True)

    args = parser.parse_args(argv)
    if args.cmd == "triage":
        print(json.dumps(triage(args.file), indent=2))
    elif args.cmd == "reputation":
        print(json.dumps(reputation(args.sha256, args.vt_key), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
