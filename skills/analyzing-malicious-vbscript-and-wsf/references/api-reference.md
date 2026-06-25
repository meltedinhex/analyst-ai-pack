# API Reference: Analyzing Malicious VBScript and WSF

## Overview

`scripts/analyst.py` extracts `<script>` bodies from WSF/HTA containers, detects and isolates
Microsoft Script Encoder (`#@~^`) blocks, and flags suspicious WScript/ActiveX dropper APIs. It
parses text only and never invokes Windows Script Host. Full Script Encoder decoding is delegated
to a dedicated decoder; the script isolates encoded blocks and confirms their presence.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `analyze(text)`
Returns script-block counts, encoded-block presence, suspicious API hits, and defanged URLs.

### `_isolate_script_encoder(encoded)`
Strips the `#@~^`/`^#~@` markers and framing to isolate the encoded body for follow-on decoding.

## Usage

```bash
python scripts/analyst.py analyze sample.wsf
```

## Sources

- Microsoft Windows Script Host documentation —
  https://learn.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/scripting-articles/
- VBScript.Encode / Script Encoder format (`#@~^` marker) analysis —
  https://gist.github.com/bcse/1834878
- WScript.Shell / ADODB.Stream / MSXML2.XMLHTTP dropper patterns, established script-analysis
  practice
