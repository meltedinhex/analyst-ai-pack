# API Reference: Hunting Credential Dumping Activity

## Overview

`scripts/analyst.py` parses Sysmon ProcessAccess (EID 10) and process-creation telemetry (CSV or
JSON-lines), flagging LSASS access with high-risk GrantedAccess masks (excluding trusted security
agents) and command lines matching comsvcs MiniDump / procdump / known dumpers. It parses
telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path)`
Returns LSASS access events, dump-command events, and a suspicion flag.

## Heuristics

- Risky access masks: `0x1010`, `0x1410`, `0x143a`, `0x1438`, full-access variants.
- Dump patterns: `comsvcs.dll,MiniDump`, `procdump`, `sekurlsa`, `lsass.dmp`, etc.
- Trusted sources (Defender, MDE, CrowdStrike) are de-prioritized.

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1003.001 LSASS Memory — https://attack.mitre.org/techniques/T1003/001/
- Sysmon Event ID 10 ProcessAccess (GrantedAccess) — https://learn.microsoft.com/sysinternals/downloads/sysmon
- comsvcs.dll MiniDump LSASS technique from public detection-engineering write-ups
