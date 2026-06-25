# API Reference: Identifying Cryptographic Routines in Binaries

## Overview

`scripts/analyst.py` scans a binary for well-known cryptographic constants — the AES S-box, SHA-256
init values (LE/BE), MD5 init constants, ChaCha/Salsa sigma strings, a CRC32 table prefix, and the
base64 alphabet — and reports their offsets. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, JSON, file IO |

## Core functions

### `scan(path)`
Returns the set of detected algorithms and per-constant offset hits.

### `_crc32_table_prefix()`
Computes the first entries of the standard `0xEDB88320` CRC32 table to anchor detection.

## Constants anchored

- AES S-box first 16 bytes (`0x63 0x7c 0x77 0x7b ...`).
- SHA-256 H0..H7; MD5 A/B/C/D init words.
- `expand 32-byte k` (ChaCha) / `expand 16-byte k` (Salsa20).
- Base64 standard alphabet.

## Usage

```bash
python scripts/analyst.py scan sample.bin
```

## Sources

- FIPS 197 (AES, S-box) — https://csrc.nist.gov/publications/detail/fips/197/final
- FIPS 180-4 (SHA-2 init/round constants) — https://csrc.nist.gov/publications/detail/fips/180/4/final
- RFC 8439 (ChaCha20 `expand 32-byte k` constant); CRC-32 polynomial 0xEDB88320 (ITU-T V.42)
