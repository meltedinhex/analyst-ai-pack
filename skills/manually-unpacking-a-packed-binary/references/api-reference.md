# API Reference: Manually Unpacking a Packed Binary

## Overview

`scripts/analyst.py` parses a PE's section table and reports per-section entropy, writable+executable
sections, known packer section names, and high-entropy sections to plan manual unpacking. It reads
bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, math, Counter, JSON |

## Core functions

### `inspect(path)`
Returns per-section details, write+execute sections, known packer names, high-entropy sections,
and a `likely_packed` flag.

### `_parse_sections(data)`
Minimal PE section-table parser (name, entropy, characteristics, sizes).

## Manual unpacking signals

- Write+execute section → in-place unpacking stub.
- Section entropy > 7.0 → compressed/encrypted payload.
- Tiny import table → imports resolved at runtime after unpacking.

## Usage

```bash
python scripts/analyst.py inspect packed.exe
```

## Sources

- MITRE ATT&CK T1027.002 Software Packing — https://attack.mitre.org/techniques/T1027/002/
- PE Format (section characteristics IMAGE_SCN_MEM_*) — https://learn.microsoft.com/windows/win32/debug/pe-format
- OEP / tail-jump methodology from public manual-unpacking practice
