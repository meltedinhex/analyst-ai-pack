# API Reference: Performing Static PE Analysis

## Overview

`scripts/analyst.py` parses a PE file and reports headers, sections with per-section entropy,
imports grouped into behavioral buckets, and TLS-callback presence. It prefers `pefile` and
falls back to a minimal built-in header walk when `pefile` is unavailable.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pefile | >= 2023.2 | Full PE parsing (optional but recommended) |
| (stdlib) | — | struct/entropy fallback parser |

## External tools

| Tool | Purpose |
|------|---------|
| capa | Capability identification from disassembly |
| PEStudio | Interactive static PE triage |

## Core functions

### `analyze(path)`
Dispatches to `analyze_with_pefile` or the `analyze_minimal` fallback. Returns headers,
sections, entropy, and classified imports.

### `_classify(imports)`
Groups imported API names into `injection`, `network`, `crypto`, `persistence`, `evasion`.

### `entropy(data)`
Byte-level Shannon entropy (0–8).

## Usage

```bash
pip install pefile        # optional, enables full analysis
python scripts/analyst.py analyze sample.bin
```

## Sources

- Microsoft PE Format specification — https://learn.microsoft.com/windows/win32/debug/pe-format
- pefile library — https://github.com/erocarrera/pefile
- Windows API behavioral groupings (standard malware-analysis import categories)
