# API Reference: Performing Dynamic Analysis in a Sandbox

## Overview

`scripts/analyst.py` summarizes a CAPE/Cuckoo-style behavioral JSON report into a process tree,
triggered signatures, network IOCs, and dropped files. It parses an existing report and never
detonates a sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON parsing |

## External tools

| Tool | Purpose |
|------|---------|
| CAPE / Cuckoo | Automated detonation and behavioral reporting |
| Process Monitor / Process Explorer | Manual behavioral instrumentation |
| Regshot | Pre/post system-state diffing for persistence |

## Core functions

### `summarize(report)`
Extracts the process tree, signatures, network IOCs (hosts/domains/URLs), and dropped files
from a behavioral report, tolerating partial schemas.

## Usage

```bash
python scripts/analyst.py summarize report.json
```

## Sources

- CAPE Sandbox — https://github.com/kevoreilly/CAPEv2
- Sysinternals Process Monitor — https://learn.microsoft.com/sysinternals/downloads/procmon
- Cuckoo/CAPE report JSON structure (project documentation)
