# API Reference: Hunting Kerberoasting and Ticket Attacks

## Overview

`scripts/analyst.py` parses Kerberos TGS request events (Event ID 4769) from CSV or JSON-lines,
flags RC4-HMAC (`0x17`) ticket requests, and computes per-account distinct-SPN volume to surface
bulk service-account targeting. Machine accounts are de-prioritized. It parses telemetry only and
executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path, threshold=5)`
Returns RC4 ticket requests, accounts requesting ≥ threshold distinct SPNs, and a suspicion flag.

## Encryption types

- `0x17` RC4-HMAC (crackable; Kerberoasting preference).
- `0x11`/`0x12` AES128/AES256 (stronger).

## Usage

```bash
python scripts/analyst.py hunt 4769_events.csv --threshold 5
```

## Sources

- MITRE ATT&CK T1558.003 Kerberoasting — https://attack.mitre.org/techniques/T1558/003/
- Windows Security Event 4769 (TicketEncryptionType) — https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769
- RC4 encryption-type Kerberoasting indicator from public AD detection research
