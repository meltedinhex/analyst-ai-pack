# API Reference: Hunting Persistence Mechanisms on Windows

## Overview

`scripts/analyst.py` scores anomalous autostart entries against a fleet baseline, weighting
unsigned binaries, user-writable/temp paths, LOLBin usage, and encoded arguments. It reads
local JSON only and touches no live systems.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## Input format

```json
[
  {"type": "Run", "name": "Updater", "image": "C:/Users/Public/u.exe",
   "signed": false, "args": "-enc ...."},
  {"type": "Service", "name": "Svc1", "image": "C:/Windows/System32/svchost.exe", "signed": true}
]
```

## Core functions

### `hunt(entries, baseline)`
Scores each entry for anomaly indicators and returns candidates scoring >= 40.

## Usage

```bash
python scripts/analyst.py hunt autostart.json --baseline baseline.json
```

## Sources

- MITRE ATT&CK TA0003 Persistence (T1547.001, T1543.003, T1053.005, T1546.003) —
  https://attack.mitre.org/tactics/TA0003/
- Autoruns / Autostart Extensibility Points (Sysinternals) —
  https://learn.microsoft.com/sysinternals/downloads/autoruns
- Baseline-diff anomaly hunting (stack counting), established threat-hunting practice
