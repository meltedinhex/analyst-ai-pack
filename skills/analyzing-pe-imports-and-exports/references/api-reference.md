# API Reference: Analyzing PE Imports and Exports

## Overview

`scripts/analyst.py` parses a PE's import and export tables with `pefile`, buckets imported APIs
into behavior categories (networking, injection, crypto, persistence, anti-analysis,
dynamic-resolution), and flags a thin IAT. It parses statically and never executes the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pefile | >= 2023.2.7 | PE import/export directory parsing |

## Core functions

### `analyze(path)`
Returns imported DLLs/functions, exports, capability buckets, and a `thin_iat` flag.

### `_bucketize(funcs)`
Maps API names to behavior categories via substring matching.

## Usage

```bash
pip install pefile
python scripts/analyst.py imports sample.exe
```

## Sources

- Microsoft PE/COFF specification (import/export directories) —
  https://learn.microsoft.com/windows/win32/debug/pe-format
- pefile library — https://github.com/erocarrera/pefile
- API-to-behavior mapping (e.g., VirtualAllocEx+WriteProcessMemory+CreateRemoteThread =
  injection), established static-analysis practice
