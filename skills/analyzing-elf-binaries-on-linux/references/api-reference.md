# API Reference: Analyzing ELF Binaries on Linux

## Overview

`scripts/analyst.py` reports ELF header facts, dynamic symbols and `NEEDED` libraries, a strip
check, and capability groupings (network/process/crypto). It uses `pyelftools` when present
and falls back to a minimal header/entropy parse otherwise.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pyelftools | >= 0.30 | Full ELF parsing (optional) |
| (stdlib) | — | Header/entropy fallback |

## External tools

| Tool | Purpose |
|------|---------|
| readelf / nm (binutils) | Authoritative ELF inspection |
| strings | Embedded string review |

## Core functions

### `analyze(path)`
Dispatches to the pyelftools or minimal parser; returns header, symbols, needed libs, and
capability groupings.

### `entropy(data)`
Byte-level Shannon entropy for packing assessment.

## Usage

```bash
pip install pyelftools     # optional
python scripts/analyst.py analyze sample.elf
```

## Sources

- ELF / System V ABI specification — https://refspecs.linuxfoundation.org/elf/elf.pdf
- pyelftools — https://github.com/eliben/pyelftools
- UPX section/marker conventions (vendor docs)
