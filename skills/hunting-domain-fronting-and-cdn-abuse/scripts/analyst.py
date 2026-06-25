#!/usr/bin/env python3
"""Hunt domain fronting via TLS SNI vs HTTP Host registered-domain mismatch.

Parses flow telemetry (CSV or JSON-lines) pairing TLS SNI with HTTP Host, computes the registered
domain (last two labels) for each, and flags mismatches, prioritizing known fronting-capable CDN
SNIs. Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

CDN_DOMAINS = {"cloudfront.net", "azureedge.net", "akamaihd.net", "fastly.net",
               "googleapis.com", "appspot.com", "cloudflare.net", "amazonaws.com",
               "windows.net", "akamaized.net"}


def _registered_domain(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


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
    findings = []
    for row in _rows(path):
        sni = _get(row, "sni", "SNI", "server_name", "tls_sni", "ssl_server_name")
        host = _get(row, "host", "Host", "http_host", "HostHeader")
        if not sni or not host:
            continue
        sni_dom = _registered_domain(sni)
        host_dom = _registered_domain(host)
        if sni_dom != host_dom:
            findings.append({
                "sni": sni, "host": host,
                "sni_domain": sni_dom, "host_domain": host_dom,
                "fronting_capable_cdn": sni_dom in CDN_DOMAINS,
            })
    findings.sort(key=lambda d: d["fronting_capable_cdn"], reverse=True)
    return {"mismatches": findings, "total": len(findings),
            "note": "mismatch is suggestive, not proof; corroborate with beacon/reputation"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt domain fronting / CDN abuse")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
