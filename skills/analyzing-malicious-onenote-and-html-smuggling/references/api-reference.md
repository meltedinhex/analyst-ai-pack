# API Reference: Analyzing Malicious OneNote and HTML Smuggling

## Overview

`scripts/analyst.py` carves embedded file signatures (PE, archives, scripts) from OneNote/binary
files by offset, and detects HTML smuggling by locating large base64 blobs that decode to
executables/archives alongside Blob-download hints. It reads statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | base64, regex, JSON, file IO |

## Core functions

### `carve(data)`
Returns offsets and types of embedded file signatures.

### `html_smuggle(data)`
Returns smuggling hints (Blob/Uint8Array/download) and any base64 blobs that decode to payloads.

## Usage

```bash
python scripts/analyst.py carve sample.one
```

## Sources

- MITRE ATT&CK T1027.006 HTML Smuggling — https://attack.mitre.org/techniques/T1027/006/
- OneNote file format (MS-ONESTORE, embedded FileDataStoreObject) —
  https://learn.microsoft.com/openspecs/office_file_formats/ms-onestore/
- Blob/createObjectURL/msSaveOrOpenBlob smuggling pattern, established delivery-analysis practice
