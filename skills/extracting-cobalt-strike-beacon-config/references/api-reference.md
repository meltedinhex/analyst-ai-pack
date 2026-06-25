# API Reference: Analyzing Cobalt Strike Beacon Config

## Overview

`scripts/analyst.py` brute-forces the single-byte XOR key protecting a Beacon configuration
block, locates the TLV settings table, and parses a well-known subset of settings (C2 server,
URIs, sleep/jitter, watermark, pipe name). It reads bytes only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, JSON |

## External tools

| Tool | Purpose |
|------|---------|
| CobaltStrikeParser (community) | Reference config parsing across versions |
| 1768.py (Didier Stevens) | Alternative beacon config extractor |

## Core functions

### `extract_config(data)`
Tries XOR keys 1–255, finds the decoded settings table (anchored on the BeaconType entry),
and returns the parsed config plus the recovered key.

### `_parse_table(buf)`
Walks TLV entries (index, type, length, value), mapping known indices to names. Returns
`None` on malformed data so the brute-force can reject wrong keys.

## Usage

```bash
python scripts/analyst.py parse beacon.bin
```

## Notes

The setting index catalog and XOR-encoded table layout are publicly documented. This parser
intentionally decodes a limited subset for triage; use a full community parser for complete,
version-specific extraction.

## Sources

- Cobalt Strike malleable C2 documentation — https://www.cobaltstrike.com/
- CobaltStrikeParser (community reference for config layout) —
  https://github.com/Sentinel-One/CobaltStrikeParser
- Publicly documented Beacon config TLV structure
