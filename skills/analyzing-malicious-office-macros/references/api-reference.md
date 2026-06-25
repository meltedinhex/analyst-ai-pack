# API Reference: Analyzing Malicious Office Macros

## Overview

`scripts/analyst.py` extracts VBA macros and flags auto-exec triggers, suspicious calls, and
URLs. It prefers `oletools`/olevba and falls back to locating `vbaProject.bin` in OOXML ZIP
containers (or scanning OLE2 bytes) when oletools is unavailable.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| oletools | >= 0.60 | VBA extraction (olevba), OLE inspection (optional but recommended) |
| (stdlib) | — | zipfile/regex fallback |

## External tools

| Tool | Purpose |
|------|---------|
| olevba / ol0id (oletools) | Macro extraction and document triage |
| oledump.py | Manual OLE stream inspection |

## Core functions

### `analyze(path)`
Dispatches to olevba or the minimal extractor; returns macro presence, auto-exec triggers,
suspicious calls, and URLs.

### `_scan_text(text)`
Flags auto-exec entry points, suspicious VBA calls, and extracts URLs from macro source.

## Usage

```bash
pip install oletools
python scripts/analyst.py extract maldoc.docm
```

## Sources

- oletools (olevba) — https://github.com/decalage2/oletools
- MS-OVBA VBA file format —
  https://learn.microsoft.com/openspecs/office_file_formats/ms-ovba/
- VBA auto-exec trigger names (Office VBA object model documentation)
