# API Reference: Writing Suricata and Snort Rules

## Overview

`scripts/analyst.py` lints Suricata/Snort rule files for required metadata (`msg`, `sid`, `rev`,
`classtype`), balanced quotes/parentheses, duplicate SIDs, and short free-floating `content`
matches that cause false positives. It parses rule text only and does not load any IDS engine.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `lint(path)`
Returns rules checked, issue count, and per-line problems. Exit code is non-zero when issues exist
(useful in CI).

## Checks

- Presence of `msg`, `sid`, `rev`, `classtype`.
- Unique SIDs across the file.
- Balanced quotes and parentheses.
- `content` ≤ 3 chars must be anchored (`http.uri`, `flow:`, `offset`, `depth`, etc.).

## Usage

```bash
python scripts/analyst.py lint rules.rules
```

## Sources

- Suricata rules documentation — https://docs.suricata.io/en/latest/rules/intro.html
- Snort 3 rule writing guide — https://docs.snort.org/
- Rule anatomy and SID/anchoring best practices from official IDS documentation
