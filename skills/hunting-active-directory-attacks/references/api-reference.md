# API Reference: Hunting Active Directory Attacks

## Overview

`scripts/analyst.py` parses Windows AD telemetry (Event IDs 4662 / 4769 / 4624) from CSV or
JSON-lines and flags DCSync replication-rights grants to non-DC accounts and Golden/Silver Ticket
anomalies (RC4 TGS where AES is expected). It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path)`
Returns DCSync replication grants, forged-ticket anomalies, and an AD-attack suspicion flag.

## Detection logic

- **DCSync**: 4662 granting `DS-Replication-Get-Changes` / `-All` GUIDs to a non-`$` account.
- **Forged tickets**: 4769 with RC4 (`0x17`) where the domain expects AES — a Golden/Silver
  Ticket indicator (corroborate with missing 4768).

## Replication GUIDs

`1131f6aa-…` (Get-Changes), `1131f6ad-…` (Get-Changes-All), `89e95b76-…` (filtered set).

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1003.006 DCSync; T1558.001 Golden Ticket — https://attack.mitre.org/
- Windows Security Event 4662 (directory service access) — https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4662
- DCSync replication extended-rights GUIDs from Microsoft AD schema documentation
