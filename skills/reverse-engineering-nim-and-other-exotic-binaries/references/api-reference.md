# API Reference: Reverse Engineering Nim and Other Exotic Binaries

## Overview

`scripts/analyst.py` detects the source language of an exotic compiled binary (Nim, Crystal, V, Zig,
D) by scanning printable strings for language-specific runtime signatures and scoring each language
by corroborating markers. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `detect(path)`
Returns the detected language (requires ≥2 markers), per-language scores, and the matched evidence.

## Signature markers

- Nim: `nimrtl`, `fatal.nim`, `system.nim`, `@m..nim`.
- Crystal: `__crystal_main`, `crystal::`.
- V: `_vinit`, `vlib/`, `tos3(`.
- Zig: `std.builtin`, `@panic`, `panic: `.
- D: `_Dmain`, `core.runtime`, `TypeInfo_`.

## Usage

```bash
python scripts/analyst.py detect sample.bin
```

## Sources

- Nim manual (runtime, name mangling) — https://nim-lang.org/docs/manual.html
- Crystal/V/Zig/D runtime symbol conventions from each language's official documentation
- Exotic-language malware landmarks from public RE write-ups (require corroborating markers)
