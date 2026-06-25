#!/usr/bin/env python3
"""Hunt Kerberoasting in Kerberos TGS request events (Event ID 4769).

Parses 4769 records (CSV or JSON-lines), flags RC4-HMAC (0x17) ticket requests, and computes
per-account distinct-SPN volume to surface bulk service-account targeting. Parses telemetry only;
executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

RC4_TYPE = "0x17"
AES_TYPES = {"0x11", "0x12"}
DEFAULT_SPN_THRESHOLD = 5


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


def hunt(path: str, threshold: int = DEFAULT_SPN_THRESHOLD) -> dict:
    spns_by_account: dict[str, set[str]] = defaultdict(set)
    rc4_requests = []
    for row in _rows(path):
        account = _get(row, "TargetUserName", "AccountName", "account").lower()
        spn = _get(row, "ServiceName", "service_name", "ServiceSid")
        etype = _get(row, "TicketEncryptionType", "encryption_type",
                     "TicketEncryptionTypeName").lower()
        client = _get(row, "IpAddress", "ClientAddress", "client_address")
        if account.endswith("$"):  # machine accounts: lower priority
            continue
        if spn:
            spns_by_account[account].add(spn)
        if etype == RC4_TYPE or "rc4" in etype:
            rc4_requests.append({"account": account, "spn": spn, "client": client})
    bulk = [{"account": a, "distinct_spns": len(s)}
            for a, s in spns_by_account.items() if len(s) >= threshold]
    bulk.sort(key=lambda d: d["distinct_spns"], reverse=True)
    return {
        "rc4_ticket_requests": rc4_requests[:100],
        "bulk_spn_accounts": bulk,
        "kerberoasting_suspected": bool(rc4_requests and bulk),
        "spn_threshold": threshold,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt Kerberoasting (4769)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    p.add_argument("--threshold", type=int, default=DEFAULT_SPN_THRESHOLD)
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events, args.threshold), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
