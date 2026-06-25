# API Reference: Hunting Anomalous Authentication Patterns

## Overview

`scripts/analyst.py` aggregates Windows logon success (4624) and failure (4625) telemetry (CSV or
JSON-lines) to detect password spraying (one source vs many accounts), brute force (many failures
per account), and failure-then-success transitions. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path, spray_accounts=5, brute_failures=10)`
Returns spray sources, brute-force accounts, breakthrough accounts, and the thresholds used.

## Detection logic

- **Spray**: distinct accounts failed per source ≥ `spray_accounts`.
- **Brute force**: failures per account ≥ `brute_failures`.
- **Breakthrough**: ≥3 failures then a trailing success for an account.

## Usage

```bash
python scripts/analyst.py hunt logons.csv --spray-accounts 5 --brute-failures 10
```

## Sources

- MITRE ATT&CK T1110.003 Password Spraying — https://attack.mitre.org/techniques/T1110/003/
- Windows Security Event 4625/4624 — https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625
- Spray vs brute-force aggregation approach from public detection-engineering practice
