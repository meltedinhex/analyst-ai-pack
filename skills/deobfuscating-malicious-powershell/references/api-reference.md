# API Reference: Deobfuscating Malicious PowerShell

## Overview

`scripts/analyst.py` decodes `-EncodedCommand` (base64 UTF-16LE), peels nested base64 plus
gzip/deflate layers, neutralizes execution sinks (`IEX`, `Invoke-Expression`), and extracts
URLs. It never runs PowerShell.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | base64, gzip, zlib, regex |

## External tools

| Tool | Purpose |
|------|---------|
| PSDecode | Emulated unrolling of heavily layered scripts |
| CyberChef | Interactive multi-step decoding |

## Core functions

### `decode_encodedcommand(b64)`
Decodes a `-EncodedCommand`/`-enc` blob (base64 of UTF-16LE) to text.

### `peel_layers(text, max_depth)`
Iteratively decodes the largest base64 blob and attempts gzip/deflate/UTF-16 decompression,
returning each layer.

### `neutralize(text)`
Replaces `IEX`/`Invoke-Expression` with output statements so recovered scripts are not run.

### `extract_iocs(text)`
Collects URLs across all decoded layers.

## Usage

```bash
python scripts/analyst.py decode --encodedcommand "<base64>"
python scripts/analyst.py deobfuscate payload.ps1
```

## Sources

- PowerShell `-EncodedCommand` semantics (UTF-16LE base64) — https://learn.microsoft.com/powershell/
- PSDecode — https://github.com/R3MRUM/PSDecode
- Common PowerShell obfuscation transforms (format operator, char codes, reversal)
