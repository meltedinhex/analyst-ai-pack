# API Reference: Extracting IOCs from Analysis Output

## Overview

`scripts/analyst.py` scans analysis text for URLs, domains, IPv4 addresses, emails, and hashes
using validated patterns, filters benign noise (RFC1918 IPs, well-known service domains), and
deduplicates. It reads a local text file only and performs no network activity.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `extract(text)`
Returns typed, deduplicated indicators and counts, with benign filtering applied.

### `_is_private(ip)` / `_benign_domain(d)`
Noise filters for private address space and common service domains.

## Usage

```bash
python scripts/analyst.py extract analysis.txt
```

## Sources

- MITRE ATT&CK — https://attack.mitre.org/
- Indicator-extraction patterns (validated IPv4 octets, hash lengths) —
  https://github.com/InQuest/python-iocextract
- RFC1918 private address ranges for noise filtering — IETF RFC 1918
