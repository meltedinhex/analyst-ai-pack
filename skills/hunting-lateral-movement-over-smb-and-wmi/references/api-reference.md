# API Reference: Hunting Lateral Movement Over SMB and WMI

## Overview

`scripts/analyst.py` parses Windows service-install (7045/4697) and process-creation telemetry (CSV
or JSON-lines) and flags PsExec-style service binaries, randomly named services launched from admin
shares, and `wmiprvse.exe`/`services.exe`-parented shells. It parses telemetry only and executes
nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, regex, file IO |

## Core functions

### `hunt(path)`
Returns remote service installs, remote WMI shells, and a lateral-movement suspicion flag.

## Heuristics

- PsExec-like service names/binaries (`PSEXESVC`, `paexec`, `remcom`).
- Random short service name + admin-share image path.
- `wmiprvse.exe` spawning `cmd`/`powershell` (remote WMI exec).

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1021.002 SMB/Windows Admin Shares; T1021.003 DCOM — https://attack.mitre.org/
- Windows Security Event 4624/4697 — https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
- PsExec service-creation and WMIexec parent patterns from public detection research
