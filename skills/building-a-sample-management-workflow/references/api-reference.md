# API Reference: Building a Sample Management Workflow

## Overview

`scripts/analyst.py` performs idempotent content-addressed intake: it computes SHA-256, copies the
sample to a hash-derived path, writes a JSON metadata record, and appends a chain-of-custody log
entry. It reads inert bytes and never executes the sample.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | hashlib, shutil, JSON, file IO |

## Core functions

### `intake(path, store, source, case, analyst)`
Stores the sample at `<store>/<aa>/<bb>/<sha256>`, writes `<sha256>.meta.json`, and appends to
`custody.log`. Returns the metadata record (with a `duplicate` flag).

## Usage

```bash
python scripts/analyst.py intake sample.bin --source "phishing-case-42" --store ./samples
```

## Sources

- NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response —
  https://csrc.nist.gov/pubs/sp/800/86/final
- MalwareBazaar sample conventions (hash-named, password-protected) — https://bazaar.abuse.ch/
- Content-addressed storage and chain-of-custody, general DFIR practice
