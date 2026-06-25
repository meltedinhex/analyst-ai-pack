# API Reference: Dumping and Rebuilding a PE From Memory

## Overview

`scripts/analyst.py` inspects a memory-dumped PE's section alignment and entry point, and realigns
section raw pointers/sizes to the virtual layout used by files reconstructed from memory,
optionally setting a new OEP. It operates on file bytes only and executes nothing. Import table
reconstruction is delegated to a dedicated tool (Scylla/ImpRec).

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, JSON, file IO |

## Core functions

### `inspect(path)`
Reports entry point RVA, whether the dump is memory-aligned (raw==virtual), and the section table.

### `fix(path, oep, out)`
Rewrites PointerToRawData/SizeOfRawData to the virtual layout and sets AddressOfEntryPoint to `oep`.

## Usage

```bash
python scripts/analyst.py inspect dump.bin
python scripts/analyst.py fix dump.bin --oep 0x1234 -o rebuilt.bin
```

## Sources

- PE Format (AddressOfEntryPoint, section headers) — https://learn.microsoft.com/windows/win32/debug/pe-format
- MITRE ATT&CK T1620 Reflective Code Loading — https://attack.mitre.org/techniques/T1620/
- Memory-dump raw==virtual alignment convention from public unpacking tooling (Scylla)
