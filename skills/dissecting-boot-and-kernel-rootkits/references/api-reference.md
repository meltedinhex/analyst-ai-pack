# API Reference: Analyzing Bootkit and Rootkit Samples

## Overview

`scripts/analyst.py` classifies a sample as an MBR/VBR boot sector, UEFI module, or kernel driver
(via boot signature, PE subsystem, and kernel imports), then surfaces boot-tampering, kernel
hooking, and DKOM indicators from strings. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, regex, JSON, file IO |

## Core functions

### `classify(path)`
Returns the artifact type, boolean type flags, indicator lists, and the inferred persistence vector.

### `_is_mbr(data)` / `_is_pe(data)`
Boot-signature (`0x55AA` at 0x1FE) and PE/subsystem detection.

## Indicator classes

- Boot tampering: `Int 13h`, partition-table strings, `bootmgr`.
- Kernel hooking: SSDT/IRP, `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`.
- DKOM: `EPROCESS`, `ActiveProcessLinks`.

## Usage

```bash
python scripts/analyst.py classify sample.bin
```

## Sources

- MITRE ATT&CK T1542.003 Bootkit; T1014 Rootkit — https://attack.mitre.org/
- PE subsystem values (native=1, EFI=10–13) — https://learn.microsoft.com/windows/win32/debug/pe-format
- MBR `0x55AA` boot signature and kernel callback/hooking primitives from public OS/RE documentation
