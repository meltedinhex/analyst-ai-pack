# API Reference: Triaging an Unknown Sample

## Overview

`scripts/analyst.py` performs static first-pass triage: magic-byte type identification,
hashing, Shannon entropy (packing signal), categorized strings, and a simple suspicion
score with an escalation recommendation. An optional VirusTotal hash lookup adds reputation.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | Hashing, entropy, regex, optional `urllib` for VT |

## External tools

| Tool | Purpose |
|------|---------|
| file / libmagic | Authoritative type identification beyond the built-in magic set |
| VirusTotal API | Hash reputation (lookup only; no upload) |

## Core functions

### `triage(filepath)`
Returns type, size, sha256, entropy, `likely_packed`, `embedded_pe`, suspicious strings,
a `triage_score`, and a `recommendation` (`low-signal` / `review` / `deep-analysis`).

### `shannon_entropy(data)`
Byte-level Shannon entropy in bits (0–8). Values above ~7.2 suggest packing/encryption.

### `identify(data)`
Magic-byte file-type label.

### `reputation(sha256, vt_key)`
Looks up a hash on VirusTotal v3 and returns `last_analysis_stats`. Never uploads the file.

## Usage

```bash
python scripts/analyst.py triage sample.bin
python scripts/analyst.py reputation --sha256 <sha256> --vt-key "$VT_API_KEY"
```

## Sources

- file(1) / libmagic manual — https://man7.org/linux/man-pages/man1/file.1.html
- VirusTotal API v3 reference — https://docs.virustotal.com/reference/overview
- Shannon entropy as a packing indicator (information theory; standard practice)
