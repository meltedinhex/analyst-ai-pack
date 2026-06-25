# API Reference: Tuning Detections to Reduce False Positives

## Overview

`scripts/analyst.py` analyzes labeled alert history to compute current precision and rank a field's
values by false-positive contribution, recommending allow-list filters for values with zero
true-positive loss and projecting the precision gain. It parses alert data only and executes
nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `analyze(path, label_field, field)`
Returns current tp/fp/precision, FP contributors, recommended safe filters, and projected precision.

## Label values

True positive: `tp`/`true_positive`/`malicious`/`1`. False positive: `fp`/`false_positive`/
`benign`/`0`.

## Safety

Only values with **zero** true positives are recommended as filters, so tuning never suppresses
known true positives.

## Usage

```bash
python scripts/analyst.py analyze alerts.csv --label verdict --field ParentImage
```

## Sources

- Sigma rule specification (filter/condition) — https://github.com/SigmaHQ/sigma-specification
- Precision/false-positive-rate detection-engineering concepts — https://attack.mitre.org/resources/
- FP-contribution ranking and safe-filter approach from detection-engineering practice
