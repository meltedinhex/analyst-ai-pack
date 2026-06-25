# API Reference: Generating Capability Reports with capa

## Overview

`scripts/analyst.py` summarizes a capa JSON report, aggregating matched rules by ATT&CK technique,
MBC behavior, and namespace. It parses an existing report; it does not run capa or the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| capa | Rule-based capability detection over disassembly (`capa -j sample.exe`) |

## Core functions

### `summarize(report)`
Aggregates capa rules into ATT&CK, MBC, and namespace groupings with rule lists/counts.

## Usage

```bash
capa -j sample.exe > capa.json
python scripts/analyst.py summarize capa.json
```

## Sources

- capa (Mandiant FLARE) — https://github.com/mandiant/capa
- Malware Behavior Catalog (MBC) — https://github.com/MBCProject/mbc-markdown
- capa detects potential capabilities from code patterns and requires unpacked input, per capa
  documentation
