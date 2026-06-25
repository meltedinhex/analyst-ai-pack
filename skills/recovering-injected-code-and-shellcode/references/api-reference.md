# API Reference: Recovering Injected Code and Shellcode

## Overview

`scripts/analyst.py` triages a carved memory region: it locates embedded MZ/PE headers (validating
`e_lfanew` → `PE\0\0` and reading the Machine field) and scans for position-independent code
markers. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, JSON, file IO |

## Core functions

### `identify(path)`
Returns embedded PE offsets/architecture, shellcode hint flags, and whether the region is likely
raw shellcode.

### `_pe_at(data, off)`
Validates an MZ/PE header at an offset and returns its architecture.

## PIC markers detected

- GetPC stubs (`call $+5`, `fnstenv`)
- PEB access (`fs:[30]` x86, `gs:[60]` x64)
- API-hashing loops (`lodsb` + `ror 13`)

## Usage

```bash
python scripts/analyst.py identify region.bin
```

## Sources

- MITRE ATT&CK T1620 Reflective Code Loading — https://attack.mitre.org/techniques/T1620/
- MITRE ATT&CK T1055 Process Injection — https://attack.mitre.org/techniques/T1055/
- PE/COFF specification (e_lfanew, Machine values); ror13 API-hash pattern from public shellcode research
