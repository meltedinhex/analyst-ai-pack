# API Reference: Building a Threat-Hunt Hypothesis

## Overview

`scripts/analyst.py` emits a structured hunt plan from an ATT&CK technique, data source, and
lookback window: a hypothesis statement, data requirements, baseline questions, scope, and the
three outcome branches. It is a planning aid and queries no systems.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | text/JSON generation |

## Core functions

### `plan(technique, datasource, window, behavior)`
Returns the hunt-plan dictionary (hypothesis, data requirements, baseline questions, scope,
outcomes).

## Usage

```bash
python scripts/analyst.py plan --technique T1047 --datasource "Sysmon EID1" --window 14d \
  --behavior "WMI lateral movement"
```

## Sources

- MITRE ATT&CK — https://attack.mitre.org/
- The PEAK Threat Hunting Framework (Prepare, Execute, Act with Knowledge) —
  https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html
- Hypothesis-driven hunting methodology (testable "if/then" framing), established practice
