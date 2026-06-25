# API Reference: Analyzing Malicious ISO and Container Files

## Overview

`scripts/analyst.py` identifies a container's format (ISO 9660, VHD/VHDX, FAT/IMG) by signature and
carves embedded file signatures (PE, ZIP/Office, LNK, scripts) with offsets. With pycdlib it adds a
root directory listing. It reads bytes statically and never mounts the image.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pycdlib | latest | full ISO directory listing (optional) |
| (stdlib) | — | JSON, file IO |

## Core functions

### `inspect(path)`
Returns format, ISO directory (if pycdlib), embedded signatures, and a hidden-payload flag.

### `_format(data)`
Signature-based container format detection (`CD001`, `conectix`, `vhdxfile`, FAT markers).

## Carved signatures

PE (`MZ`), ZIP/Office (`PK`), LNK header, shebang/WSF/batch scripts.

## Usage

```bash
python scripts/analyst.py inspect sample.iso
```

## Sources

- MITRE ATT&CK T1553.005 Mark-of-the-Web Bypass — https://attack.mitre.org/techniques/T1553/005/
- ISO 9660 (`CD001` at sector 16) — https://wiki.osdev.org/ISO_9660
- VHD `conectix` / VHDX `vhdxfile` signatures from Microsoft VHD/VHDX specifications
