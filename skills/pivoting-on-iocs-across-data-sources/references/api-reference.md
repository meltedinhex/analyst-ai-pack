# API Reference: Pivoting on IOCs Across Data Sources

## Overview

`scripts/analyst.py` matches log records against a seed IOC set, then reports co-occurring hosts, the
activity time range, and new indicators ranked by co-occurrence with the seeds. It refangs input
for matching, defangs output, parses data only, and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, regex, Counter, file IO |

## Core functions

### `pivot(seeds_path, logs_path)`
Returns matched record count, affected hosts, time range, and ranked new indicators.

### `_indicators(text)`
Extracts IPs, domains, and hashes from a text blob.

## Inputs

- **seeds**: one IOC per line (plain or defanged; refanged internally).
- **logs**: CSV or JSON-lines records.

## Usage

```bash
python scripts/analyst.py pivot --seeds iocs.txt --logs events.csv
```

## Sources

- Pyramid of Pain (indicator pivoting value) — https://www.sans.org/
- MITRE ATT&CK techniques — https://attack.mitre.org/techniques/
- Seed-anchored co-occurrence pivoting from public investigation/IR practice
