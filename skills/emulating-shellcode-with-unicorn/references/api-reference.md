# API Reference: Emulating Shellcode With Unicorn

## Overview

`scripts/analyst.py` emulates raw x86/x64 shellcode with the Unicorn engine: it maps the code and a
stack, hooks instruction and memory-write events, runs to an instruction budget, and reports
executed instruction count and self-modified regions (decoded stages). Unicorn is optional; without
it, `prep` still reports availability. Intended for isolated VMs.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| unicorn | latest | CPU emulation (optional; emulate requires it) |
| (stdlib) | — | JSON, file IO |

## Core functions

### `prep(path, arch)`
Reports size, architecture, and whether Unicorn is installed.

### `emulate(path, arch, max_insns)`
Maps and runs the shellcode under Unicorn; returns instruction count, self-modified addresses, and
the stop reason.

## Memory layout

- Code base `0x100000` (2 MiB region), stack at `0x300000` (64 KiB). Adjust for larger payloads.

## Usage

```bash
python scripts/analyst.py prep shellcode.bin --arch x64
python scripts/analyst.py emulate shellcode.bin --arch x64 --max-insns 200000
```

## Sources

- Unicorn CPU emulator framework — https://www.unicorn-engine.org/
- MITRE ATT&CK T1620 Reflective Code Loading — https://attack.mitre.org/techniques/T1620/
- Shellcode emulation methodology (mapping, stack setup, hooks) from public emulation tooling
