# API Reference: Hunting Data Staging and Archiving

## Overview

`scripts/analyst.py` parses process-creation telemetry (CSV or JSON-lines) and flags archive-tool
execution with compression/password flags and archives written to staging directories. It parses
telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, regex, file IO |

## Core functions

### `hunt(path)`
Returns staging events with the tool, matched indicators, archive filenames, and command line.

## Heuristics

- Archive tools: `rar`/`winrar`/`7z`/`zip`/`tar`/`makecab`, plus `Compress-Archive`/`tar -c`.
- Indicators: compression flags (`a -`, `-mx`), password flags (`-hp`, `-p`), staging paths
  (`%TEMP%`, `%APPDATA%`, `Public`), and archive file extensions (incl. split `.r00`/`.z01`).

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1074 Data Staged; T1560 Archive Collected Data — https://attack.mitre.org/
- Archive-tool flags from WinRAR/7-Zip command-line documentation
- Pre-exfil staging patterns from public intrusion-analysis reporting
