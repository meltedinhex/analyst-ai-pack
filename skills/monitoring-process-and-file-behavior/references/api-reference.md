# API Reference: Monitoring Process and File Behavior

## Overview

`scripts/analyst.py` parses a Process Monitor CSV export, categorizes operations
(process/thread, file, registry, network), reconstructs Process Create events, flags
persistence-relevant writes, and defangs URLs. It parses logs only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, regex, Counter, JSON |

## Core functions

### `summarize(path)`
Returns operation category counts, process creates, LOLBin children, persistence writes, and
defanged URLs.

## Expected CSV columns

`Process Name`, `Operation`, `Path`, `Detail` (Procmon "Save As → CSV" defaults). UTF-8 BOM is
handled via `utf-8-sig`.

## Usage

```bash
python scripts/analyst.py summarize procmon.csv
```

## Sources

- MITRE ATT&CK T1106 Native API — https://attack.mitre.org/techniques/T1106/
- Sysinternals Process Monitor — https://learn.microsoft.com/sysinternals/downloads/procmon
- Run/RunOnce/services persistence locations, Windows registry documentation
