# API Reference: Resolving Dynamic API Hashing

## Overview

`scripts/analyst.py` implements common malware API-hash algorithms (ROR13-add, djb2, FNV-1a, CRC32)
and matches observed 32-bit hash constants against a names wordlist. It is pure computation over
name strings and never loads or executes the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | binascii (CRC32), JSON, file IO |

## Core functions

### `ror13_add(name)`, `djb2(name)`, `fnv1a(name)`, `crc32(name)`
The supported 32-bit hashing algorithms.

### `identify(value)`
Tries each algorithm against a small seed API list to suggest which algorithm a constant came from.

### `resolve(hashes, algo, names)`
Builds a hash→name table for the wordlist and resolves the provided hashes; reports unresolved.

## Usage

```bash
python scripts/analyst.py id 0x6A4ABC5B
python scripts/analyst.py resolve hashes.txt --algo ror13 --wordlist names.txt
```

## Sources

- MITRE ATT&CK T1027.007 Dynamic API Resolution — https://attack.mitre.org/techniques/T1027/007/
- ROR13 PEB-walk shellcode hashing pattern (public shellcode/RE literature)
- djb2 (Daniel J. Bernstein), FNV-1a (Fowler/Noll/Vo), CRC-32 (ISO 3309) standard definitions
