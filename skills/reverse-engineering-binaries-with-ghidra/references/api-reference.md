# API Reference: Reverse Engineering Binaries with Ghidra

## Overview

`scripts/analyst.py` wraps Ghidra's `analyzeHeadless` to import a binary, run auto-analysis, and
optionally execute a post-script (such as a function/string exporter). It orchestrates Ghidra
and does not run the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | subprocess, JSON, tempfile |

## External tools

| Tool | Version | Purpose |
|------|---------|---------|
| Ghidra | 11.x | Disassembly, decompilation, headless scripting |
| JDK | 17+ | Required by Ghidra |

## Core functions

### `run_headless(ghidra_path, binary, post_script, script_path, project_dir, timeout)`
Builds and runs the `analyzeHeadless` command (import, overwrite, delete temp project) and
returns the command, return code, and trimmed stdout/stderr.

## Usage

```bash
python scripts/analyst.py headless --ghidra /opt/ghidra --bin sample.bin \
  --post-script ExportFunctions.py --script-path ./ghidra_scripts --out out.json
```

## Sources

- Ghidra documentation — https://ghidra-sre.org/
- Ghidra API / headless analyzer — https://ghidra.re/ghidra_docs/api/
- analyzeHeadless usage (Ghidra `support/analyzeHeadlessREADME.html`)
