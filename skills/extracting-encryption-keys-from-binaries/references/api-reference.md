# API Reference: Extracting Encryption Keys From Binaries

## Overview

`scripts/analyst.py` surfaces candidate encryption keys: it finds key-sized (16/24/32-byte)
high-entropy, high-diversity regions and extracts printable hex (32–64 chars) and base64 (24–44
chars) strings matching common key lengths. It reads bytes statically and executes nothing.
Entropy is a heuristic — confirm by decryption.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | math, regex, Counter, JSON |

## Core functions

### `keys(path)`
Returns high-entropy key candidates (offset/size/entropy/hex), hex-string keys, and base64-string
keys.

### `_high_entropy_regions(data)`
Sliding-window search requiring near-maximal byte diversity to reduce false positives.

## Tuning

- `KEY_SIZES = (16, 24, 32)` for AES-128/192/256.
- `ENTROPY_THRESHOLD` over short windows; raise to reduce noise on packed binaries.

## Usage

```bash
python scripts/analyst.py keys sample.bin
```

## Sources

- FIPS 197 (AES key sizes 128/192/256) — https://csrc.nist.gov/publications/detail/fips/197/final
- MITRE ATT&CK T1573 Encrypted Channel — https://attack.mitre.org/techniques/T1573/
- High-entropy key-region heuristic from public key-recovery research; confirm by decryption
