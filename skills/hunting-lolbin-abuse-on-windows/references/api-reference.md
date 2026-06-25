# API Reference: Hunting LOLBin Abuse on Windows

## Overview

`scripts/analyst.py` parses Windows process-creation telemetry (CSV or JSON-lines) and flags known
LOLBins used with suspicious arguments, weighting by anomalous parent process. It parses telemetry
only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path)`
Returns scored findings (image, score, reasons, truncated command line), sorted by score.

### `_score_event(image, cmdline, parent)`
Matches LOLBin + suspicious argument, adds weight for suspicious parents.

## Expected fields

CSV: `Image`, `CommandLine`, `ParentImage` (Sysmon EID 1 field names). JSON-lines: same keys or
lowercase `image`/`command_line`/`parent_image`.

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1218 System Binary Proxy Execution — https://attack.mitre.org/techniques/T1218/
- LOLBAS project (binary/argument catalog) — https://lolbas-project.github.io/
- Sysmon Event ID 1 schema (Image/CommandLine/ParentImage) — Sysinternals documentation
