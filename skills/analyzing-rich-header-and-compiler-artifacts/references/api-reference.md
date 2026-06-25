# API Reference: Analyzing Rich Header and Compiler Artifacts

## Overview

`scripts/analyst.py` parses the PE Rich header: it finds the `Rich` marker, recovers the XOR key,
locates the XOR-encoded `DanS` signature, decodes the comp.id entries into
`(product_id, build_id, use_count)` tuples, and emits a toolchain fingerprint hash. It reads bytes
statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, hashlib, JSON, file IO |

## Core functions

### `rich(path)`
Returns Rich-header presence, XOR key, decoded entries, and a clustering fingerprint.

### `_find_dans(data, rich_off, key)`
Scans backward for the XOR-encoded `DanS` (`0x536E6144`) signature.

## Rich header layout

`DanS` + 3 padding DWORDs, then 8-byte entries (`comp.id` = product_id<<16 | build_id, and
use_count), all XOR'd with the key, terminated by `Rich` + key.

## Usage

```bash
python scripts/analyst.py rich sample.exe
```

## Sources

- PE Format — https://learn.microsoft.com/windows/win32/debug/pe-format
- Rich header `DanS`/comp.id structure from public PE reverse-engineering research
- Toolchain-clustering use of the Rich header from public malware-clustering practice
