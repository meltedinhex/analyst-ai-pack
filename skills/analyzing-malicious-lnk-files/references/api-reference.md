# API Reference: Analyzing Malicious LNK Files

## Overview

`scripts/analyst.py` is a minimal [MS-SHLLINK] parser: it validates the LNK header and CLSID, reads
LinkFlags, skips the IDList/LinkInfo, and extracts the StringData fields (name, relative path,
working dir, arguments, icon), plus the count of any appended data. It parses statically and never
executes the shortcut.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct parsing, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| LECmd / lnkparse | Full-featured LNK parsing including extra data blocks |

## Core functions

### `parse(path)`
Returns LinkFlags and the recovered StringData fields, appended-data size, and a suspicious flag.

### `_read_stringdata(data, off, unicode_)`
Reads a CountedString (ANSI or UTF-16LE) per the IsUnicode flag.

## Usage

```bash
python scripts/analyst.py parse sample.lnk
```

## Sources

- Microsoft [MS-SHLLINK] Shell Link Binary File Format —
  https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink/
- liblnk LNK format documentation —
  https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc
- Malicious-argument hiding in COMMAND_LINE_ARGUMENTS, established document-analysis practice
