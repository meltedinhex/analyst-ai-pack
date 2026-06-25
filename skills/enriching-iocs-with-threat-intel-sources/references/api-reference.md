# API Reference: Enriching IOCs with Threat Intel Sources

## Overview

`scripts/analyst.py` maps typed indicators to appropriate passive enrichment sources and emits
per-type operational-security cautions. It produces a lookup plan only and makes no network
requests, keeping enrichment opsec-safe by design.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## Input format

```json
{"indicators": {"domains": ["evil[.]com"], "hashes": ["<sha256>"], "ipv4": ["1[.]2[.]3[.]4"]}}
```

## Core functions

### `plan(indicators)`
Returns a per-type lookup plan (sources + opsec caution) for the supplied indicators.

### `SOURCE_MAP` / `OPSEC`
The type→source mapping and per-type operational-security guidance.

## Usage

```bash
python scripts/analyst.py plan iocs.json
```

## Sources

- MITRE ATT&CK — https://attack.mitre.org/
- Passive DNS / indicator enrichment concepts — https://www.first.org/
- Opsec caution against active resolution and public sample upload, established CTI practice
