#!/usr/bin/env python3
"""Hunt Active Directory replication and forged-ticket attacks in Windows telemetry.

Parses Event IDs 4662 (directory service access), 4769 (TGS), and 4624 (logon) from CSV or
JSON-lines and flags DCSync replication-rights grants to non-DC accounts and Golden/Silver Ticket
anomalies. Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# Replication extended-rights GUIDs used by DCSync.
REPL_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}
RC4_TYPE = "0x17"


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
    dcsync, ticket = [], []
    for row in _rows(path):
        eid = _get(row, "EventID", "event_id")
        account = _get(row, "SubjectUserName", "AccountName", "TargetUserName", "account")
        low_all = " ".join(str(v).lower() for v in row.values())
        if eid == "4662" or "replication" in low_all:
            hit = [name for guid, name in REPL_GUIDS.items() if guid in low_all]
            if hit and not account.endswith("$"):  # non-machine/non-DC account
                dcsync.append({"account": account, "rights": hit})
        if eid == "4769":
            etype = _get(row, "TicketEncryptionType", "encryption_type").lower()
            tgt = _get(row, "TargetUserName", "ServiceName")
            if etype == RC4_TYPE or "rc4" in etype:
                ticket.append({"account": account or tgt, "encryption": "RC4 (0x17)",
                               "note": "RC4 TGS where AES expected — possible forged ticket"})
    return {
        "dcsync_replication_grants": dcsync,
        "forged_ticket_anomalies": ticket[:100],
        "ad_attack_suspected": bool(dcsync or ticket),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt Active Directory attacks")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
