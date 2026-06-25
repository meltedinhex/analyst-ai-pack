# API Reference: Mapping Hunts to MITRE ATT&CK

## Overview

`scripts/analyst.py` reads a JSON hunt inventory (name, techniques, confidence) and produces a
per-technique coverage summary plus an ATT&CK Navigator layer with confidence-derived scores.
It reads and writes local JSON only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## Input format

```json
[
  {"name": "WMI lateral movement", "techniques": ["T1047"], "confidence": "high"},
  {"name": "Encoded PowerShell", "techniques": ["T1059.001"], "confidence": "medium"}
]
```

## Core functions

### `build(hunts)`
Aggregates hunts into a technique → {hunts, best_score} coverage map.

### `to_layer(coverage, name)`
Converts the coverage map into a minimal ATT&CK Navigator layer with a gradient.

## Usage

```bash
python scripts/analyst.py coverage hunts.json --out layer.json
```

## Sources

- MITRE ATT&CK Navigator (layer format) — https://github.com/mitre-attack/attack-navigator
- MITRE ATT&CK enterprise techniques — https://attack.mitre.org/techniques/enterprise/
- Coverage-with-confidence approach (presence is not quality), established detection practice
