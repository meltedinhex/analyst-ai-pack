# API Reference: Hunting Cobalt Strike Traffic

## Overview

`scripts/analyst.py` detects default-configuration Cobalt Strike artifacts in HTTP and process
telemetry: default stager URIs via the checksum8 algorithm, default Malleable C2 URIs/user-agents,
and default named pipes. It parses telemetry only and executes nothing. Default indicators match
default configs only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `checksum8(path_segment)`
Returns the sum of a 4-character alphanumeric URI path mod 256; `92` (x86) or `93` (x64) indicates
a default Cobalt Strike stager URI.

### `hunt(path)`
Returns default stager URIs, default profile artifacts (URIs/user-agents), and default named pipes.

## Default artifacts

- Stager checksum8 == 92 (x86) / 93 (x64).
- URIs: `/__utm.gif`, `/submit.php`, `/pixel`, etc.
- Pipes: `\\.\pipe\msagent_*`, `\\.\pipe\status_*`, `\\.\pipe\postex_*`.

## Usage

```bash
python scripts/analyst.py hunt http.csv
```

## Sources

- MITRE ATT&CK Software S0154 Cobalt Strike — https://attack.mitre.org/software/S0154/
- Cobalt Strike default stager checksum8 (92/93) behavior from public C2 research
- Default Malleable C2 profile URIs/pipes from the publicly documented default profile
