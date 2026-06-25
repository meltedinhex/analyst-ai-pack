# API Reference: Analyzing Banking Trojan Webinjects

## Overview

`scripts/analyst.py` parses Zeus/SpyEye-style webinject configs (`set_url` + `data_before`/
`data_inject`/`data_after` blocks), associates each target URL pattern with its injected snippet,
classifies the injection technique, and extracts/defangs exfil endpoints. It parses config text
only, executes nothing, and never renders injected code.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `parse(path)`
Returns webinject count, targeted URL patterns, and per-entry technique/exfil/preview details.

## Technique classes

- form_grabbing (onsubmit/form hooks)
- fake_fields (SSN/PIN/card/CVV/DOB additions)
- mfa_interception (OTP/2FA/token capture)
- balance_manipulation (innerHTML/balance rewriting)

## Webinject format

`set_url <pattern> <flags>` followed by `data_before … data_end`, `data_inject … data_end`,
`data_after … data_end`.

## Usage

```bash
python scripts/analyst.py parse webinjects.txt
```

## Sources

- MITRE ATT&CK T1185 Browser Session Hijacking — https://attack.mitre.org/techniques/T1185/
- Zeus/SpyEye webinject grammar (set_url/data_before/data_inject) from public malware research
- Web-fraud injection techniques (form-grab, fake fields, OTP capture) from banking-trojan analyses
