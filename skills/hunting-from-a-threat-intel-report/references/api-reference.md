# API Reference: Hunting from a Threat Intel Report

## Overview

`scripts/analyst.py` extracts IOCs (IPs, domains, URLs, hashes) and ATT&CK technique IDs from
report text, refangs bracketed indicators for matching, re-defangs them for safe output, and
ranks indicator classes by the Pyramid of Pain. It reads a local text file only and performs no
lookups.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `extract(text)`
Returns techniques, defanged indicators grouped by type, and Pyramid-of-Pain priority guidance.

### `refang(text)` / `defang(ind)`
Normalize bracketed indicators for matching, then re-defang for safe display.

## Usage

```bash
python scripts/analyst.py extract report.txt
```

## Sources

- MITRE ATT&CK — https://attack.mitre.org/
- The Pyramid of Pain (David Bianco) —
  https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- Defanging conventions (hxxp, [.]) for safe IOC handling, common CTI practice
