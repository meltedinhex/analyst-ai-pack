#!/usr/bin/env python3
"""Hunt unusual outbound connections in network/flow telemetry.

Parses connection telemetry (CSV or JSON-lines) and scores connections by direct-to-IP (no
resolved domain), non-standard destination port, high sent:received byte ratio (possible exfil),
and egress from unexpected processes. Aggregates destination rarity. Parses telemetry only;
executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from collections import Counter
from pathlib import Path

COMMON_PORTS = {80, 443, 53, 123, 25, 587, 993, 995, 22, 389, 636, 3389, 88, 445}
UNEXPECTED_PROCS = {"notepad.exe", "calc.exe", "mspaint.exe", "winword.exe", "excel.exe",
                    "rundll32.exe", "regsvr32.exe", "mshta.exe"}


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


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _base(p: str) -> str:
    return p.replace("/", "\\").split("\\")[-1].lower()


def hunt(path: str, ratio_threshold: float = 5.0) -> dict:
    findings = []
    dest_counter: Counter = Counter()
    for row in _rows(path):
        dest = _get(row, "DestinationIp", "dest_ip", "id.resp_h", "destination")
        domain = _get(row, "DestinationHostname", "dest_host", "query", "domain")
        port = _get(row, "DestinationPort", "dest_port", "id.resp_p", "port")
        proc = _base(_get(row, "Image", "process", "proc"))
        sent = _get(row, "BytesSent", "orig_bytes", "sent")
        recv = _get(row, "BytesReceived", "resp_bytes", "received")
        if dest:
            dest_counter[dest] += 1
        reasons = []
        try:
            port_n = int(port) if port else None
        except ValueError:
            port_n = None
        if dest and _is_ip(dest) and not domain:
            reasons.append("direct_to_ip")
        if port_n is not None and port_n not in COMMON_PORTS:
            reasons.append(f"uncommon_port:{port_n}")
        try:
            s, r = float(sent or 0), float(recv or 0)
            if r > 0 and (s / r) >= ratio_threshold and s > 10000:
                reasons.append(f"high_egress_ratio:{round(s / r, 1)}")
        except ValueError:
            pass
        if proc in UNEXPECTED_PROCS:
            reasons.append(f"unexpected_process:{proc}")
        if reasons:
            findings.append({"dest": dest, "port": port, "process": proc,
                             "reasons": reasons, "score": len(reasons)})
    findings.sort(key=lambda d: d["score"], reverse=True)
    rare = [{"dest": d, "count": c} for d, c in dest_counter.items() if c <= 2]
    return {"findings": findings[:100], "rare_destinations": rare[:50],
            "ratio_threshold": ratio_threshold}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt unusual outbound connections")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    p.add_argument("--ratio", type=float, default=5.0)
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events, args.ratio), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
