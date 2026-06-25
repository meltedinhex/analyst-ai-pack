# API Reference: Establishing Telemetry Baselines

## Overview

`scripts/analyst.py` builds frequency baselines from telemetry and scores new data against them.
`baseline` records per-value counts/frequencies for a field; `compare` flags first-seen and rare
values. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, Counter, file IO |

## Core functions

### `baseline(path, field, out)`
Writes a JSON baseline (`field`, `total`, `counts`) for the chosen field.

### `compare(path, field, baseline_file, rarity)`
Returns first-seen values (absent from baseline) and rare values (frequency < `rarity`).

## Usage

```bash
python scripts/analyst.py baseline history.csv --field Image --out baseline.json
python scripts/analyst.py compare new.csv --field Image --baseline baseline.json --rarity 0.01
```

## Sources

- The ThreatHunting Project (stacking / least-frequency-of-occurrence) — https://www.threathunting.net/
- MITRE ATT&CK threat-hunting resources — https://attack.mitre.org/resources/
- Frequency-stacking baseline method from established hunt methodology
