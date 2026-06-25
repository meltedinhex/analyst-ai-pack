# API Reference: Reverse Engineering Binaries With Binary Ninja

## Overview

`scripts/analyst.py` generates Binary Ninja Python API analysis scripts that open a view, iterate
functions, and export functions/strings to JSON. `check` reports whether the `binaryninja` API is
importable. It only generates text and does not run Binary Ninja or a sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| binaryninja | licensed | the analysis API (optional for generation) |
| (stdlib) | — | JSON, file IO |

## Core functions

### `check()`
Reports `binaryninja` API availability.

### `skeleton(out, emit)`
Writes a script using `binaryninja.open_view`, `bv.functions`, and `bv.get_strings`.

## IL levels

- LLIL: close to assembly.
- MLIL: variables/SSA reasoning.
- HLIL: readable pseudo-code.

## Usage

```bash
python scripts/analyst.py check
python scripts/analyst.py skeleton --emit functions,strings --out bn_extract.py
```

## Sources

- Binary Ninja Python API — https://api.binary.ninja/
- Binary Ninja IL (LLIL/MLIL/HLIL) — https://docs.binary.ninja/dev/bnil-llil.html
- `open_view`/`bv.functions`/`get_strings` usage from official API documentation
