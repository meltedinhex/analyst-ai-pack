# API Reference: Extracting and Classifying Strings

## Overview

`scripts/analyst.py` extracts ASCII and UTF-16LE strings at a minimum length and classifies them
into investigative categories (urls, ips, paths, registry, commands, apis), flagging a sparse
dump as a possible obfuscation signal. It reads bytes only and never executes the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `ascii_strings(data, min_len)` / `unicode_strings(data, min_len)`
Extract printable ASCII and UTF-16LE runs respectively.

### `classify(strings)`
Buckets strings into categories via per-category regexes.

### `run(path, min_len)`
Returns counts, categorized strings, and an obfuscation hint.

## Usage

```bash
python scripts/analyst.py strings sample.bin --min-len 5
```

## Sources

- GNU binutils `strings` — https://www.gnu.org/software/binutils/
- FLOSS (FLARE Obfuscated String Solver) for stacked/encoded strings —
  https://github.com/mandiant/flare-floss
- UTF-16LE wide-string extraction (printable byte + 0x00), standard Windows-analysis practice
