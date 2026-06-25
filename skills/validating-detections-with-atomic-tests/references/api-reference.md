# API Reference: Validating Detections With Atomic Tests

## Overview

`scripts/analyst.py` computes detection coverage by joining Atomic Red Team-tested ATT&CK techniques
with your detection inventory's covered techniques, reporting covered/uncovered techniques and
ranking gaps by atomic-test count. It parses data only, executes nothing, and never runs an atomic.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | json, Counter, file IO |

## Inputs

- **atomics**: JSON list of `{"technique": "T1059.001", "test": "..."}` or a `technique→count`
  mapping.
- **detections**: JSON list of technique IDs or objects with a `technique` key.

## Core functions

### `coverage(atomics_path, detections_path)`
Returns tested count, covered/uncovered technique lists, coverage percent, and gap priority.

## Usage

```bash
python scripts/analyst.py coverage --atomics atomics.json --detections detections.json
```

## Sources

- Atomic Red Team (test→technique mapping) — https://github.com/redcanaryco/atomic-red-team
- MITRE ATT&CK techniques/sub-techniques — https://attack.mitre.org/techniques/
- Coverage-by-technique validation approach from detection-engineering practice
