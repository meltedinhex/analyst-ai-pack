# API Reference: Hunting C2 Beaconing with Frequency Analysis

## Overview

`scripts/analyst.py` groups connection logs by source/destination pair, computes inter-arrival
intervals, and scores beacon regularity via the coefficient of variation (jitter tolerant),
optionally boosting on consistent payload sizes. It reads local JSON only and makes no network
connections.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | statistics, JSON, file IO |

## Input format

```json
[
  {"src": "10.0.0.5", "dst": "evil.example.com", "ts": 1700000000, "bytes": 512},
  {"src": "10.0.0.5", "dst": "evil.example.com", "ts": 1700000060, "bytes": 512}
]
```

## Core functions

### `hunt(conns, min_events)`
Groups by pair, requires `min_events`, scores each, returns candidates with score >= 60.

### `_score_pair(timestamps, sizes)`
Computes interval mean/CV and a jitter-tolerant regularity score, with a payload-size bonus.

## Usage

```bash
python scripts/analyst.py beacon conn.json --min-events 8
```

## Sources

- MITRE ATT&CK T1071 Application Layer Protocol — https://attack.mitre.org/techniques/T1071/
- Inter-arrival timing / coefficient-of-variation beacon detection — Active Countermeasures
  (RITA methodology), general network-hunting practice
- Jitter as a C2 evasion technique requiring tolerance-based scoring, established practice
