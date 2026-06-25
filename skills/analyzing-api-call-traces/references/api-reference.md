# API Reference: Analyzing API Call Traces

## Overview

`scripts/analyst.py` classifies a JSON API trace into behavioral categories and detects ordered
API sequences indicative of process injection, hollowing, dynamic API resolution, and crypto
routines. It parses JSON only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | json, argparse |

## Accepted input shapes

- A list of strings (API names) or call objects with `api`/`name`/`function` keys.
- A dict containing `calls`, `apis`, or a CAPE-style `apistats` mapping.

## Core functions

### `classify(path)`
Returns total call count, per-category counts, detected behaviors (with ATT&CK IDs), and unknown
APIs.

## Sequence signatures

`VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` (T1055.002), hollowing (T1055.012),
`LoadLibrary → GetProcAddress` (T1027.007), `CryptAcquireContext → CryptDecrypt` (T1027). Matching
respects order via a sliding cursor.

## Usage

```bash
python scripts/analyst.py classify trace.json
```

## Sources

- MITRE ATT&CK T1106 Native API; T1055 Process Injection — https://attack.mitre.org/
- Windows API Index — https://learn.microsoft.com/windows/win32/apiindex/windows-api-list
- CAPE/Cuckoo report `behavior.apistats` structure (public sandbox schema)
