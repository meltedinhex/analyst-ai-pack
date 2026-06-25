# API Reference: Automating Analysis With r2pipe

## Overview

`scripts/analyst.py` drives radare2/rizin static analysis through r2pipe: it runs `aaa` and collects
functions (`aflj`), imports (`iij`), and strings (`izj`) as JSON. r2pipe is optional; `check`
reports availability. It drives static analysis commands only and does not run the sample in a
debugger.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| r2pipe | latest | radare2/rizin automation (optional; summary requires it) |
| radare2/rizin | latest | the analysis engine |
| (stdlib) | — | shutil, JSON |

## Core functions

### `check()`
Reports r2pipe availability and which r2/rizin binary is on PATH.

### `summary(path)`
Returns function count/list, imports, and strings via JSON commands.

## Key r2 commands used

- `aaa` — analyze all.
- `aflj` — list functions (JSON).
- `iij` — imports (JSON).
- `izj` — strings in data sections (JSON).

## Usage

```bash
python scripts/analyst.py check
python scripts/analyst.py summary sample.bin
```

## Sources

- r2pipe documentation — https://github.com/radareorg/radare2-r2pipe
- radare2 command reference (The radare2 book) — https://book.rada.re/
- JSON command suffix (`*j`) convention from radare2 documentation
