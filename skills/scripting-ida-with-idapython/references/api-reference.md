# API Reference: Scripting IDA Pro With IDAPython

## Overview

`scripts/analyst.py` generates an IDAPython analysis script (enumerate functions/strings → JSON)
and the headless `idat` batch command to run it. It only generates text — it does not run IDA or
any sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | shlex, JSON, file IO |
| IDA Pro + IDAPython | 7.x/9.x | runs the generated script (separately) |

## Core functions

### `script(out, emit)`
Writes an IDAPython script using `idautils.Functions`, `idc.get_func_name`, `idautils.Strings`,
and `ida_auto.auto_wait()`, exiting via `ida_pro.qexit`.

### `batch(script_path, input_path)`
Builds `idat -A -S"<script>" <input>` (autonomous mode, run script).

## Key IDA batch flags

- `-A` — autonomous/auto mode (no dialogs).
- `-S<script>` — run the script after load.
- `-L<file>` — log output. Use `idat64` for 64-bit inputs.

## Usage

```bash
python scripts/analyst.py script --emit functions,strings --out ida_export.py
python scripts/analyst.py batch --script ida_export.py --input sample.exe
```

## Sources

- Hex-Rays IDAPython API docs — https://hex-rays.com/products/ida/support/idapython_docs/
- IDA batch/headless `idat -A -S` usage from Hex-Rays documentation
- `idautils.Functions`/`Strings` and `ida_auto.auto_wait` from the IDAPython API
