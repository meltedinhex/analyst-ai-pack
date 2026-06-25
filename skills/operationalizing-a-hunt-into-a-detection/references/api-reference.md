# API Reference: Operationalizing a Hunt Into a Detection

## Overview

`scripts/analyst.py` generates a Sigma rule from a detection spec describing the logsource,
selection, optional filter, condition, level, and ATT&CK tags. It generates text only and executes
nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## Spec format

```json
{
  "title": "Suspicious certutil download",
  "logsource": {"category": "process_creation", "product": "windows"},
  "selection": {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["-urlcache", "http"]},
  "filter": {"CommandLine|contains": "internal-mirror"},
  "condition": "selection and not filter",
  "level": "high",
  "attack": ["T1218", "T1105"]
}
```

## Core functions

### `generate(spec, out)`
Writes a Sigma YAML rule with title/status/logsource/detection/condition/falsepositives/level/tags.

## Usage

```bash
python scripts/analyst.py generate --spec detection.json --out rule.yml
```

## Sources

- Sigma rule specification — https://github.com/SigmaHQ/sigma-specification
- MITRE ATT&CK threat-hunting resources (hunt→detect loop) — https://attack.mitre.org/resources/
- Sigma logsource/detection/condition structure from the official specification
