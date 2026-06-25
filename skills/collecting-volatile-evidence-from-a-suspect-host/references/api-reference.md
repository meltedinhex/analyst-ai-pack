# API Reference: Collecting Volatile Evidence from a Suspect Host

## Overview

`scripts/analyst.py` builds an integrity manifest over an already-collected evidence directory:
SHA-256, size, and modification time per artifact, plus the suggested order-of-volatility naming
scheme. It reads collected files only and never touches a live host.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | hashlib, JSON, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| Trusted memory acquisition tool | Capture full RAM image first |
| Trusted static binaries | Snapshot network/process/user state without host binaries |

## Core functions

### `manifest(collection, case, host)`
Hashes each artifact and writes `manifest.json` with case/host context and the volatility order.

## Usage

```bash
python scripts/analyst.py manifest ./collection --case IR-42 --host WS01
```

## Sources

- RFC 3227 Guidelines for Evidence Collection and Archiving (order of volatility) —
  https://www.rfc-editor.org/rfc/rfc3227
- NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response —
  https://csrc.nist.gov/pubs/sp/800/86/final
- Use of trusted external tooling during live response, general DFIR practice
