# API Reference: Scripting Ghidra Headless Analysis

## Overview

`scripts/analyst.py` generates a Ghidra `analyzeHeadless` command line and a Jython-compatible
post-analysis script that exports functions and/or strings to JSON. It only generates text — it
does not run Ghidra or any sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | shlex, JSON, file IO |

## Core functions

### `command(project, name, import_dir, script, recursive, overwrite)`
Builds the analyzeHeadless invocation with common flags.

### `postscript(out, emit)`
Writes a Jython post-script emitting `functions` and/or `strings` to a JSON file next to the
program.

## Generated script notes

- Targets Jython 2 (no f-strings); uses `currentProgram`, `getFunctionManager`, `getListing`.

## Usage

```bash
python scripts/analyst.py command --project /proj --name Batch --import ./samples --script export.py
python scripts/analyst.py postscript --out export.py --emit functions,strings
```

## Sources

- Ghidra analyzeHeadless documentation — https://ghidra-sre.org/
- Ghidra FlatProgramAPI / program model — https://ghidra.re/ghidra_docs/api/
- Headless batch-analysis workflow from official Ghidra `support/analyzeHeadlessREADME.html`
