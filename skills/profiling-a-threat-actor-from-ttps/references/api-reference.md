# API Reference: Profiling a Threat Actor From TTPs

## Overview

`scripts/analyst.py` compares an observed ATT&CK technique set against known-group technique sets,
computing Jaccard and overlap-coefficient similarity, ranking candidate groups, and listing shared
techniques. It parses data only and executes nothing. TTP overlap is suggestive, not confirmed
attribution.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | json, file IO |

## Inputs

- **observed**: one ATT&CK technique ID per line (e.g., `T1059.001`).
- **groups**: JSON mapping `group -> [techniques]` or a list of `{name, techniques}`.

## Core functions

### `compare(observed_path, groups_path)`
Returns observed count and ranked candidates (Jaccard, overlap coefficient, shared techniques).

## Similarity metrics

- Jaccard = |A∩B| / |A∪B|.
- Overlap coefficient = |A∩B| / min(|A|, |B|).

## Usage

```bash
python scripts/analyst.py compare --observed observed.txt --groups groups.json
```

## Sources

- MITRE ATT&CK Groups (group→technique mappings) — https://attack.mitre.org/groups/
- ATT&CK Navigator (technique-set comparison) — https://github.com/mitre-attack/attack-navigator
- Jaccard / overlap-coefficient set similarity (standard definitions)
