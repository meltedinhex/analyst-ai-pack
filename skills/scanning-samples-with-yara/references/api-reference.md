# API Reference: Scanning Samples with YARA

## Overview

`scripts/analyst.py` compiles a YARA rule file or directory and scans a file or directory,
reporting matched rules, tags, and matched-string offsets. A `--summary` mode ranks files
with matches for triage.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| yara-python | >= 4.3 | Compile and match YARA rules |

## External tools

| Tool | Purpose |
|------|---------|
| yara (CLI) | Cross-check matches outside Python |

## Core functions

### `compile_rules(rules_path)`
Compiles a single rule file, or all `.yar`/`.yara` files under a directory (namespaced by
filename stem).

### `scan_file(rules, filepath)`
Returns matched rules with tags and per-string offsets for one file.

### `scan_path(rules_path, target, recursive)`
Scans a file or directory (optionally recursive) and returns per-file results.

## Usage

```bash
pip install yara-python
python scripts/analyst.py rules/ sample.bin
python scripts/analyst.py rules/ ./samples --recursive --summary
```

## Sources

- YARA documentation — https://yara.readthedocs.io/
- yara-python — https://github.com/VirusTotal/yara-python
