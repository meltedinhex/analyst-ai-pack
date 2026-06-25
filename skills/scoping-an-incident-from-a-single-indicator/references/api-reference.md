# API Reference: Scoping an Incident from a Single Indicator

## Overview

`scripts/analyst.py` performs breadth-first pivoting from a seed indicator across normalized event
records: events sharing a known entity pull in their other entities, expanding the affected set.
It returns involved hosts/accounts, all discovered entities, and a sorted timeline. It reads
local JSON only and touches no live systems.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## Input format

```json
[
  {"ts": 1700000000, "host": "WS01", "account": "alice", "sha256": "abc...", "dst_ip": "1.2.3.4"},
  {"ts": 1700000100, "host": "WS02", "dst_ip": "1.2.3.4"}
]
```

## Core functions

### `scope(events, seed)`
Iteratively expands the known-entity set, returns affected hosts/accounts and a sorted timeline.

### `_entities(ev)`
Collects entity values from an event across the recognized fields.

## Usage

```bash
python scripts/analyst.py scope events.json --seed 1.2.3.4
```

## Sources

- NIST SP 800-61 Computer Security Incident Handling Guide —
  https://csrc.nist.gov/pubs/sp/800/61/r2/final
- MITRE ATT&CK — https://attack.mitre.org/
- Scope-before-contain principle and indicator pivoting, established IR practice
