# API Reference: Extracting Config From a Running Sample

## Overview

`scripts/analyst.py` scans a process memory dump for config indicators (URLs, IPv4:port pairs,
mutex tokens) and attempts base64 and single-byte XOR decoding of candidate blobs to surface
hidden endpoints. It reads bytes statically, defangs hosts, and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | base64, regex, JSON, file IO |

## Core functions

### `hunt(path)`
Returns defanged URLs, IP:port pairs, mutex tokens, and base64-decoded endpoints.

### `_xor_scan(blob)`
Brute-forces single-byte XOR keys and returns decoded URL/IP:port hits with the key used.

## Commands

- `hunt <dump>` — broad indicator sweep + base64 decode.
- `xor <dump>` — single-byte XOR brute force across the whole dump (noisier; corroborate hits).

## Usage

```bash
python scripts/analyst.py hunt process.dmp
```

## Sources

- MITRE ATT&CK T1140 Deobfuscate/Decode Information — https://attack.mitre.org/techniques/T1140/
- MITRE ATT&CK T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/
- Common malware config patterns (Global\\ mutexes, XOR/base64 blobs) from public family teardowns
