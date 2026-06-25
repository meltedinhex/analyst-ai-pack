# API Reference: Detecting Process Injection in Memory

## Overview

`scripts/analyst.py` parses Volatility 3 `windows.malfind` text output and ranks processes by
injection indicators: RWX private regions, PE/MZ headers and DOS stubs in private memory, and
shellcode prologue bytes in the hexdump. It parses text only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |
| volatility3 | latest | produces the `windows.malfind` input (run separately) |

## Core functions

### `score(path)`
Returns ranked injection candidates with PID, cumulative score, and contributing reasons.

## Scoring weights

- RWX region: +3
- PE/MZ in private memory: +3
- DOS stub ("This program cannot be run"): +2
- Shellcode prologue bytes: +1

## Usage

```bash
vol -f memory.raw windows.malfind > malfind.txt
python scripts/analyst.py score malfind.txt
```

## Sources

- MITRE ATT&CK T1055 Process Injection — https://attack.mitre.org/techniques/T1055/
- Volatility 3 documentation (windows.malfind, windows.vadinfo) — https://volatility3.readthedocs.io/
- malfind RWX / private-memory PE heuristics from published memory-forensics practice
