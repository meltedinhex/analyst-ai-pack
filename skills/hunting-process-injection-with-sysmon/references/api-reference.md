# API Reference: Hunting Process Injection with Sysmon

## Overview

`scripts/analyst.py` triages normalized Sysmon events (Event ID 8 CreateRemoteThread, Event ID 10
ProcessAccess), correlating source→target pairs, weighting high-power access masks and
script/macro-spawned sources, and returning ranked injection candidates. It reads local JSON
only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## Input format

```json
[
  {"event_id": 10, "source_image": "C:/a.exe", "target_image": "C:/Windows/explorer.exe",
   "target_pid": 1234, "granted_access": "0x1F0FFF", "source_parent_image": "powershell.exe"},
  {"event_id": 8, "source_image": "C:/a.exe", "target_image": "C:/Windows/explorer.exe",
   "target_pid": 1234}
]
```

## Core functions

### `triage(events)`
Aggregates events by (source, target, pid), scores injection likelihood, and returns candidates
scoring >= 50.

## Usage

```bash
python scripts/analyst.py triage sysmon.json
```

## Sources

- Sysmon documentation (Event IDs 8 and 10) —
  https://learn.microsoft.com/sysinternals/downloads/sysmon
- MITRE ATT&CK T1055 Process Injection — https://attack.mitre.org/techniques/T1055/
- CAR-2019-04-001 (CreateRemoteThread detection analytic) — MITRE Cyber Analytics Repository
