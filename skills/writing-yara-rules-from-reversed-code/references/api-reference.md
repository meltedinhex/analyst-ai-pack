# API Reference: Writing YARA Rules from Reversed Code

## Overview

`scripts/analyst.py` scaffolds a structured YARA rule with `meta`, placeholder byte-pattern
strings, an optional API-hash constant (emitted little-endian), and a multi-anchor condition
with a PE prefilter. It emits text only and scans nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | text generation |

## External tools

| Tool | Purpose |
|------|---------|
| yara | Compile and test rules against the corpus |
| yara-python | Programmatic testing/automation |

## Core functions

### `scaffold(name, api_hash, author)`
Returns a YARA rule skeleton; if `api_hash` is given, adds a little-endian byte-pattern string
and includes it in the condition.

## Usage

```bash
python scripts/analyst.py scaffold --name family_xyz --hash 0xABCDEF12
yara -r rules/family_xyz.yar ./corpus
```

## Sources

- YARA documentation — https://yara.readthedocs.io/
- YARA style guide (writing maintainable, low-FP rules) —
  https://github.com/Neo23x0/YARA-Style-Guide
- Preference for code/constant anchors over volatile strings, established RE detection practice
