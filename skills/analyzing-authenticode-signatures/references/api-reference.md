# API Reference: Analyzing Authenticode Signatures

## Overview

`scripts/analyst.py` parses the PE security data directory (index 4) to detect an embedded PKCS#7
Authenticode signature (WIN_CERTIFICATE), reporting presence, size, revision, and type. It is a
dependency-free presence check; cryptographic verification requires OS tooling. It parses bytes
statically and never executes the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct parsing, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| signtool / Get-AuthenticodeSignature | Cryptographically verify the signature and revocation |

## Core functions

### `check(path)`
Returns whether an embedded signature exists and the WIN_CERTIFICATE header fields.

## Usage

```bash
python scripts/analyst.py check sample.exe
```

## Sources

- Windows Authenticode PE signature format —
  https://learn.microsoft.com/windows-hardware/drivers/install/authenticode
- PE/COFF security data directory (index 4, file-offset semantics) —
  https://learn.microsoft.com/windows/win32/debug/pe-format
- Stolen/abused signing certificates (T1553.002), MITRE ATT&CK
