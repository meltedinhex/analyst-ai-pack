# API Reference: Defanging and Sharing IOCs

## Overview

`scripts/analyst.py` classifies indicators (url, domain, ipv4, email, hash), defangs network
indicators so they cannot be clicked or resolved, deduplicates, and emits structured JSON. It
processes text only and performs no network lookups.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `classify(ind)`
Returns the indicator type via ordered regex checks (hash first to avoid domain mis-match).

### `defang(ind, kind)`
Defangs network indicators (`http`→`hxxp`, `.`→`[.]`, `@`→`[at]`); leaves hashes untouched.

### `process(lines)`
Deduplicates and produces typed, defanged records.

## Usage

```bash
python scripts/analyst.py defang iocs.txt
```

## Sources

- STIX 2.1 specification — https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- MISP indicator sharing — https://www.misp-project.org/
- Common defanging conventions (hxxp, [.], [at]) for safe IOC handling, CTI practice
