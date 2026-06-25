# API Reference: Reverse Engineering ARM Binaries

## Overview

`scripts/analyst.py` parses ELF and Mach-O headers to identify ARM vs AArch64, endianness, entry
point, and (for 32-bit ARM ELF) Thumb entry state. It reads bytes statically and executes nothing.
Capstone can be used downstream for instruction decoding.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, JSON, file IO |

## Core functions

### `identify(path)`
Returns format, architecture, endianness, entry point, and Thumb-entry flag.

### `_parse_elf(data)` / `_parse_macho(data)`
Header parsers reading `e_machine`/`e_entry` (ELF) and CPU type (Mach-O).

## Machine types

- ELF: `0x28` ARM, `0xB7` AArch64.
- Mach-O: `0x0000000C` ARM, `0x0100000C` ARM64.

## Calling convention notes

Args in `r0-r3`/`x0-x7`, return `r0`/`x0`, syscall via `svc` with number in `r7`/`x8`.

## Usage

```bash
python scripts/analyst.py identify sample.bin
```

## Sources

- Arm Architecture Reference Manual — https://developer.arm.com/documentation/
- ELF for the Arm Architecture (AAELF), `$a`/`$t` mapping symbols — https://github.com/ARM-software/abi-aa
- ELF `e_machine` 0x28/0xB7 and Mach-O CPU types from the respective format specifications
