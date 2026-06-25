# API Reference: Reverse Engineering Binaries With radare2/rizin

## Overview

`scripts/analyst.py` is a reference helper that prints curated radare2/rizin command cheatsheets
grouped by task. It emits text only and never runs r2 or a sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, argparse |

## Core functions

### `cheatsheet(topic)`
Returns commands for a topic, or all topics with `all`.

## Topics

`analyze`, `navigate`, `disassemble`, `xrefs`, `annotate`, `patch`, `strings`, `search`.

## Usage

```bash
python scripts/analyst.py cheatsheet analyze
python scripts/analyst.py cheatsheet all
```

## Sources

- The radare2 book (command reference) — https://book.rada.re/
- Rizin documentation — https://rizin.re/
- r2 visual/graph mode and patching commands from official documentation
