# API Reference: Hunting Suspicious PowerShell Execution

## Overview

`scripts/analyst.py` scores PowerShell script-block events for suspicious construct combinations
and decodes `-EncodedCommand` base64 (UTF-16LE) payloads, re-scoring decoded content for
layered obfuscation. It reads local JSON and decodes strings only; it never executes PowerShell.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | base64, regex, JSON |

## Input format

```json
[
  {"host": "WS01", "user": "alice", "script_block": "powershell -enc SQBFAFgA..."}
]
```

## Core functions

### `score_event(text)`
Returns a score, matched reasons, and any decoded EncodedCommand payloads for one script block.

### `decode_encoded(text)`
Extracts and base64-decodes `-EncodedCommand` blobs as UTF-16LE.

### `run(events)`
Scores all events and returns candidates scoring >= 30.

## Usage

```bash
python scripts/analyst.py score events.json
```

## Sources

- PowerShell script block logging (Event ID 4104) —
  https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows
- MITRE ATT&CK T1059.001 PowerShell — https://attack.mitre.org/techniques/T1059/001/
- EncodedCommand is UTF-16LE base64 — PowerShell command-line reference
