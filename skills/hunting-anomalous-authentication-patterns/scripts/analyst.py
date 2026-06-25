#!/usr/bin/env python3
"""Hunt anomalous authentication patterns from Windows logon telemetry.

Aggregates logon success (4624) and failure (4625) events (CSV or JSON-lines) to detect password
spraying (one source vs many accounts), brute force (many failures per account), and
failure-then-success transitions. Parses telemetry only; executes nothing.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_SPRAY_ACCOUNTS = 5
DEFAULT_BRUTE_FAILURES = 10


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


def hunt(path: str, spray_accounts: int = DEFAULT_SPRAY_ACCOUNTS,
         brute_failures: int = DEFAULT_BRUTE_FAILURES) -> dict:
    fails_by_account: dict[str, int] = defaultdict(int)
    accounts_by_source: dict[str, set[str]] = defaultdict(set)
    seq_by_account: dict[str, list[str]] = defaultdict(list)
    for row in _rows(path):
        eid = _get(row, "EventID", "event_id")
        account = _get(row, "TargetUserName", "AccountName", "account").lower()
        source = _get(row, "IpAddress", "SourceNetworkAddress", "source", "Workstation")
        status = "fail" if eid == "4625" else ("success" if eid == "4624" else
                                               _get(row, "outcome").lower())
        if not account:
            continue
        if status in ("fail", "failure"):
            fails_by_account[account] += 1
            accounts_by_source[source].add(account)
            seq_by_account[account].append("F")
        elif status in ("success",):
            seq_by_account[account].append("S")
    spray = [{"source": s, "distinct_accounts": len(a)}
             for s, a in accounts_by_source.items() if len(a) >= spray_accounts]
    spray.sort(key=lambda d: d["distinct_accounts"], reverse=True)
    brute = [{"account": a, "failures": n}
             for a, n in fails_by_account.items() if n >= brute_failures]
    brute.sort(key=lambda d: d["failures"], reverse=True)
    breakthrough = [a for a, seq in seq_by_account.items()
                    if "F" in seq and seq[-1] == "S" and seq.count("F") >= 3]
    return {
        "password_spray_sources": spray,
        "brute_force_accounts": brute,
        "failure_then_success_accounts": sorted(breakthrough)[:50],
        "thresholds": {"spray_accounts": spray_accounts, "brute_failures": brute_failures},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hunt anomalous authentication")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hunt")
    p.add_argument("events")
    p.add_argument("--spray-accounts", type=int, default=DEFAULT_SPRAY_ACCOUNTS)
    p.add_argument("--brute-failures", type=int, default=DEFAULT_BRUTE_FAILURES)
    args = parser.parse_args(argv)
    print(json.dumps(hunt(args.events, args.spray_accounts, args.brute_failures), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
