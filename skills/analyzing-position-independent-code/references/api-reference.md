# API Reference: Analyzing Position-Independent Code

## Overview

`scripts/analyst.py` identifies position-independent code techniques in a shellcode blob — GetPC
stubs, PEB access (x86/x64), API-hash loops, and stack-string construction — and infers the
architecture from the PEB-access form. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## Core functions

### `analyze(path)`
Returns detected techniques, inferred architecture, PEB-walk/API-hashing flags, and a PIC flag.

## Techniques detected

- GetPC: `call $+5` (`E8 00 00 00 00`), `fldz; fnstenv`.
- PEB: `fs:[30]` (x86), `gs:[60]` (x64).
- API hashing: `lodsb` + `ror 13`.
- Stack strings: `mov [esp+x], imm`.

## Usage

```bash
python scripts/analyst.py analyze shellcode.bin
```

## Sources

- PEB/LDR structures (winternl.h) — https://learn.microsoft.com/windows/win32/api/winternl/
- MITRE ATT&CK T1027.007 Dynamic API Resolution — https://attack.mitre.org/techniques/T1027/007/
- GetPC / PEB-walk / ror13 patterns from public shellcode research
