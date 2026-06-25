# API Reference: Analyzing Webshells

## Overview

`scripts/analyst.py` scans a server-side script (PHP/ASPX/JSP) for dynamic-execution sinks,
request-input-to-sink data flow, and encoder chains, and best-effort decodes base64/raw-deflate
layers that wrap webshell logic. It reads the file statically, executes nothing, and defangs URLs.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | base64, zlib, regex, JSON, file IO |

## Core functions

### `scan(path)`
Returns language, execution sinks, input sources, an input-to-sink flow flag, encoder chains,
decoded layers, defanged URLs, and a webshell likelihood flag.

### `_decode_layers(text)`
Decodes base64 (and raw-deflate) blobs and keeps those whose plaintext contains execution sinks.

## Detection logic

- **Sinks**: PHP `eval`/`system`/`passthru`/`preg_replace /e`; ASPX `eval`/`Process.Start`;
  JSP `Runtime.exec`/`ProcessBuilder`.
- **Input flow**: a sink plus `$_GET`/`$_POST`/`Request`/`getParameter` raises confidence.
- **Encoders**: `base64_decode`, `gzinflate`, `str_rot13`, `FromBase64String`, `\x` hex.

## Usage

```bash
python scripts/analyst.py scan shell.php
```

## Sources

- MITRE ATT&CK T1505.003 Web Shell — https://attack.mitre.org/techniques/T1505/003/
- Server-side execution sink and encoder-chain patterns from public webshell research
- PHP/ASP/JSP language execution APIs from their official documentation
