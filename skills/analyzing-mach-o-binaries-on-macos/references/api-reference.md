# API Reference: Analyzing Mach-O Binaries on macOS

## Overview

`scripts/analyst.py` parses Mach-O headers with stdlib `struct`: it detects fat/universal vs. thin
binaries, enumerates slices, and reads load commands for linked dylibs, the entry point, and the
presence of a code signature. It parses statically and never executes the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct parsing, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| codesign | Verify signature and read entitlements on macOS |
| otool | Inspect load commands and linked libraries |

## Core functions

### `parse(path)`
Dispatches on magic to handle fat vs. thin binaries; returns format, slices, and per-slice data.

### `parse_thin(data, base)`
Parses one Mach-O image's load commands (dylibs, LC_MAIN, LC_CODE_SIGNATURE).

## Usage

```bash
python scripts/analyst.py header sample.macho
```

## Sources

- Apple Mach-O `loader.h` (header and load-command structures) —
  https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
- macOS code signing overview —
  https://developer.apple.com/documentation/security/code_signing_services
- Fat/universal binary layout (FAT_MAGIC + slice table), Mach-O format documentation
