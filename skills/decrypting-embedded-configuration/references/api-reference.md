# API Reference: Decrypting Embedded Configuration

## Overview

`scripts/analyst.py` brute-forces single-byte XOR, applies repeating-key XOR or RC4 with a supplied
key, and scores each candidate plaintext by printable ratio and config tokens, defanging recovered
endpoints. It reads the ciphertext blob statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `xor_brute(data)`
Tries all 256 single-byte keys; returns the top-scoring candidates with endpoints and a preview.

### `rc4(data, key)`
Standard RC4 keystream decryption.

### `xor_key(data, key)`
Repeating multi-byte XOR with a supplied key list.

## Scoring

Printable ratio (0–100) + 10 per config token + 5 per IP match. Higher = more config-like.

## Usage

```bash
python scripts/analyst.py xor blob.bin
python scripts/analyst.py rc4 blob.bin --key mysecret
python scripts/analyst.py xorkey blob.bin --key 0x11,0x22,0x33
```

## Sources

- MITRE ATT&CK T1140 Deobfuscate/Decode Information — https://attack.mitre.org/techniques/T1140/
- RC4 keystream algorithm (public description) — https://en.wikipedia.org/wiki/RC4
- XOR/base64/RC4 config patterns from public malware config-extractor write-ups
