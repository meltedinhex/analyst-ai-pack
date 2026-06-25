# API Reference: Hunting Scheduled Task Abuse

## Overview

`scripts/analyst.py` parses task-registration (Event ID 4698) and `schtasks`/`at` process-creation
telemetry (CSV or JSON-lines) and flags task actions that invoke script hosts, encoded commands,
or binaries from suspicious paths. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path)`
Returns suspicious tasks with their name, matched indicators, and truncated action.

## Heuristics

- Suspicious actions: `powershell -enc`, `mshta`, `wscript`/`cscript`, `cmd /c`, `rundll32`,
  `certutil`, etc.
- Suspicious paths: `%TEMP%`, `%APPDATA%`, `Public`, `ProgramData`.

## Expected fields

`EventID`, `TaskName`, `TaskContent`/`Action`/`Command`/`CommandLine`.

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1053.005 Scheduled Task — https://attack.mitre.org/techniques/T1053/005/
- Windows Security Event 4698 (task registered) — https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4698
- schtasks abuse action patterns from public persistence-hunting research
