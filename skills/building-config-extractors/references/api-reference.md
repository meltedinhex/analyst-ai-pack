# API Reference: Building Config Extractors

## Overview

`scripts/analyst.py` is a declarative config-extraction engine: given a JSON spec describing the
config blob location, ordered decode layers, and field definitions, it extracts a structured,
defanged config from a sample. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | base64, struct, JSON, file IO |

## Spec format

```json
{
  "blob": {"marker": "CFG0", "length": 256},
  "decode": [{"type": "xor", "key": "0x5a"}, {"type": "base64"}],
  "fields": [
    {"name": "c2", "offset": 0, "length": 64, "type": "str"},
    {"name": "port", "offset": 64, "type": "u16"},
    {"name": "ip", "offset": 66, "type": "ipv4"}
  ]
}
```

- **blob**: `offset`+`length` or `marker`+`length` (searches for the marker).
- **decode**: ordered `xor` (single-byte `0x..` or multi-byte string key) and `base64` layers.
- **fields**: `str`, `u16`, `u32` (little-endian), `ipv4`. URL/IP fields are defanged.

## Core functions

### `extract(path, spec)`
Locates the blob, applies decode layers, parses fields, returns the config.

## Usage

```bash
python scripts/analyst.py extract sample.bin --spec family.json
```

## Sources

- MITRE ATT&CK T1140 Deobfuscate/Decode Information — https://attack.mitre.org/techniques/T1140/
- Declarative config-extractor design (DC3-MWCP, CAPE parsers) — https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP
- XOR/base64 layered config encoding from public family teardowns
