# API Reference: Analyzing Malicious PDFs

## Overview

`scripts/analyst.py` scans raw PDF bytes for weaponization keywords (/JavaScript, /OpenAction,
/Launch, /EmbeddedFile, /URI, /ObjStm, etc.), counts objects/streams, extracts and defangs URIs,
and flags likely weaponization. It parses statically and never opens the document.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| pdfid / pdf-parser (Didier Stevens) | Object inventory and stream extraction with filters |
| peepdf | Interactive PDF analysis and JS extraction |

## Core functions

### `triage(path)`
Returns object/stream counts, risk-keyword counts, auto-action list, defanged URIs, and a
weaponization flag.

## Usage

```bash
python scripts/analyst.py triage sample.pdf
```

## Sources

- PDF 32000-1:2008 (ISO PDF specification) — https://www.pdfa.org/resource/iso-32000-pdf/
- Didier Stevens PDF tools (pdfid, pdf-parser) —
  https://blog.didierstevens.com/programs/pdf-tools/
- /OpenAction, /AA, /Launch auto-execution and /ObjStm hiding, established PDF-analysis practice
