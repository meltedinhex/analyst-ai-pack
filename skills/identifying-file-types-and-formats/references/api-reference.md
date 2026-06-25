# API Reference: Identifying File Types and Formats

## Overview

`scripts/analyst.py` matches leading and offset-based magic signatures for common malware-relevant
formats and flags mismatches against the claimed extension (masquerading). It reads raw bytes
only and never opens the file in an application.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | byte matching, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| file / libmagic | Authoritative type identification with a large signature DB |

## Core functions

### `identify(path)`
Returns detected types (with offsets), the claimed extension, and an extension-mismatch flag.

### `SIGNATURES` / `EXT_EXPECT`
The signature table and the extension→expected-family map driving mismatch detection.

## Usage

```bash
python scripts/analyst.py identify sample.dat
```

## Sources

- libmagic / the `file` command — https://www.darwinsys.com/file/
- List of file signatures (magic numbers) —
  https://en.wikipedia.org/wiki/List_of_file_signatures
- ISO 9660 `CD001` at offset 0x8001, OLE compound `D0CF11E0` — format specifications
