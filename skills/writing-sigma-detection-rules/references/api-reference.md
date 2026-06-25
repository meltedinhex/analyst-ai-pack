# API Reference: Writing Sigma Detection Rules

## Overview

`scripts/analyst.py` emits a Sigma YAML rule skeleton with a pinned logsource, selection/filter
pattern, ATT&CK tag, level, and falsepositives list. It emits text only; use sigma-cli to
validate and convert.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | text generation |

## External tools

| Tool | Purpose |
|------|---------|
| sigma-cli (pysigma) | Validate (`sigma check`) and convert (`sigma convert`) rules |

## Core functions

### `scaffold(title, category, technique, level, author)`
Returns a Sigma rule skeleton with selection, negated filter, tags, and falsepositives.

## Usage

```bash
python scripts/analyst.py scaffold --title "Encoded PowerShell" --category process_creation \
  --technique T1059.001 --level high
sigma convert -t splunk rules/encoded_powershell.yml
```

## Sources

- Sigma specification — https://github.com/SigmaHQ/sigma-specification
- Sigma rules repository (logsource taxonomy, rule structure) — https://github.com/SigmaHQ/sigma
- Selection + negated-filter pattern for low false positives, established detection-engineering
  practice
