# API Reference: Defeating String and API Obfuscation

## Overview

`scripts/analyst.py` provides two deobfuscation utilities: brute-forcing single-byte XOR to
surface readable strings, and resolving API-name hashes (ROR13/ROR7/djb2) back to function
names. Both read input only and never execute the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, hashing arithmetic |

## External tools

| Tool | Purpose |
|------|---------|
| FLOSS | Automated stack-string and decoded-string recovery via emulation |
| Ghidra / IDA | Read the decode routine and reapply recovered names |

## Core functions

### `xor_strings(data, min_hits)`
Brute-forces single-byte XOR keys and returns keys that yield several interesting readable
strings (URLs, DLL/API names, paths).

### `resolve_hash(algo, target, names)`
Returns candidate API names whose hash (ROR13/ROR7/djb2) equals the target constant.

### `hash_ror13` / `hash_ror7` / `hash_djb2`
Implementations of the common API-hashing algorithms.

## Usage

```bash
python scripts/analyst.py xor-strings sample.bin
python scripts/analyst.py api-hash --algo ror13 --hash 0x726774C
```

## Sources

- FLOSS (FLARE Obfuscated String Solver) — https://github.com/mandiant/flare-floss
- ROR13 API-hashing technique (widely used in shellcode/loaders)
- djb2 string hash (Daniel J. Bernstein)
