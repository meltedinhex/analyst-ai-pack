# API Reference: Hunting WMI Event Subscription Persistence

## Overview

`scripts/analyst.py` parses Sysmon WMI telemetry (Event IDs 19 filter / 20 consumer / 21 binding)
from CSV or JSON-lines, correlates the subscription triad, and flags consumers whose payload runs
scripts or encoded commands. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path)`
Returns parsed filters/consumers/bindings, suspicious consumers (with indicators and payload), and
whether a complete subscription was observed.

## Expected fields

- EID 19: `Name`, `Query`.
- EID 20: `Name`, `Destination`/`CommandLineTemplate`/`ScriptText`.
- EID 21: `Consumer`, `Filter`.

## Usage

```bash
python scripts/analyst.py hunt wmi_events.csv
```

## Sources

- MITRE ATT&CK T1546.003 WMI Event Subscription — https://attack.mitre.org/techniques/T1546/003/
- Sysmon WMI events 19/20/21 — https://learn.microsoft.com/sysinternals/downloads/sysmon
- WMI persistence triad (__EventFilter/__EventConsumer/__FilterToConsumerBinding) from WMI docs
