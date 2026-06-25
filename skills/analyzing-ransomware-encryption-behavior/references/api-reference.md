# API Reference: Analyzing Ransomware Encryption Behavior

## Overview

`scripts/analyst.py` compares original test files against their encrypted counterparts to
extract the appended extension, measure entropy change, and recover a common trailing footer
(where families often store a wrapped key or IV). It runs on disposable test files only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | Entropy, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| Ghidra / radare2 | Identify crypto routines and key handling |
| Detect-It-Easy / capa | Crypto-constant detection |

## Core functions

### `compare(plain_dir, enc_dir)`
Returns added extensions, a common encrypted footer, per-file entropy, size deltas, and an
encryption-coverage estimate (full vs partial).

### `_common_suffix(blobs)`
Finds the longest shared trailing bytes across encrypted files (candidate footer/marker).

## Usage

```bash
python scripts/analyst.py compare ./plain ./encrypted
```

## Sources

- No More Ransom project — https://www.nomoreransom.org/
- NIST cryptographic standards (AES, RSA) — https://csrc.nist.gov/
- Hybrid-encryption ransomware design (per-file AES + RSA-wrapped key), widely documented
