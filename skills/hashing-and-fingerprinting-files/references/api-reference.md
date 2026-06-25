# API Reference: Hashing and Fingerprinting Files

## Overview

`scripts/analyst.py` computes MD5/SHA-1/SHA-256 with stdlib `hashlib`, adds PE imphash and
per-section SHA-256 when `pefile` is present, and includes ssdeep/TLSH fuzzy hashes when their
libraries are installed. It reads inert bytes and never executes the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | hashlib cryptographic hashes |
| pefile | >= 2023.2.7 | imphash and section hashing (optional) |
| ssdeep | >= 3.4 | Fuzzy/context-triggered piecewise hashing (optional) |
| python-tlsh | >= 4.5 | Locality-sensitive similarity hashing (optional) |

## Core functions

### `crypto_hashes(data)`
Returns MD5, SHA-1, SHA-256, and size.

### `pe_hashes(path)`
Returns imphash and per-section SHA-256 for PE files.

### `fuzzy_hashes(data)`
Returns ssdeep/TLSH digests when available.

## Usage

```bash
python scripts/analyst.py hash sample.bin
```

## Sources

- ssdeep fuzzy hashing — https://ssdeep-project.github.io/ssdeep/
- TLSH locality-sensitive hashing — https://github.com/trendmicro/tlsh
- imphash concept (import-table hash for toolchain clustering) — Mandiant/FireEye research
- SHA-256 as canonical sample identity, general malware-handling practice
