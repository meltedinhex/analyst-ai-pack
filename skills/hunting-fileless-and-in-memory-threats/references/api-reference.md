# API Reference: Hunting Fileless and In-Memory Threats

## Overview

`scripts/analyst.py` parses PowerShell script-block (4104), process, and registry telemetry (CSV or
JSON-lines) and flags in-memory loading patterns, large base64 blobs in script blocks, and
registry-resident encoded payloads. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, regex, file IO |

## Core functions

### `hunt(path)`
Returns scored in-memory script findings, registry-resident payloads, and a suspicion flag.

## Heuristics

- In-memory: `[Reflection.Assembly]::Load`, `VirtualAlloc`/`WriteProcessMemory`, `IEX`/
  `Invoke-Expression`, `DownloadString`, `FromBase64String`.
- Large base64 (≥200 chars) in script block or large encoded registry values under `Software`/`Run`.

## Expected fields

`ScriptBlockText`/`CommandLine`/`Message`; `TargetObject` + `Details` for registry writes.

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1620 Reflective Code Loading; T1059.001 PowerShell — https://attack.mitre.org/
- PowerShell Script Block Logging (Event 4104) — https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Registry-resident payload (fileless storage) patterns from public detection research
