# API Reference: Measuring Section Entropy to Detect Packing

## Overview

`scripts/analyst.py` computes whole-file Shannon entropy, sliding-window peak entropy, and (for PE
files, via `pefile`) per-section entropy with raw/virtual size comparison, flagging high-entropy
executable sections. It reads the inert file and never executes it.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | math (entropy), file IO |
| pefile | >= 2023.2.7 | per-section analysis (optional) |

## Core functions

### `shannon(data)`
Shannon entropy in bits/byte (0–8).

### `window_stats(data, window)`
Returns the peak entropy and the fraction of windows above the packing threshold; a sustained
high fraction (not a single window) indicates packing when section data is unavailable.

### `pe_sections(path)`
Per-section entropy, size, executable flag, and a suspicious flag.

## Usage

```bash
python scripts/analyst.py entropy sample.exe
```

## Sources

- Shannon, "A Mathematical Theory of Communication" (entropy) —
  https://doi.org/10.1002/j.1538-7305.1948.tb01338.x
- Microsoft PE/COFF specification (section characteristics) —
  https://learn.microsoft.com/windows/win32/debug/pe-format
- Entropy > ~7.0 in executable sections as a packing heuristic, established practice
