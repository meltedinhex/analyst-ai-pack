# API Reference: Hunting Domain Fronting and CDN Abuse

## Overview

`scripts/analyst.py` parses flow telemetry pairing TLS SNI with HTTP Host (CSV or JSON-lines),
computes each one's registered domain, and flags mismatches — prioritizing known fronting-capable
CDN SNIs. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, file IO |

## Core functions

### `hunt(path)`
Returns SNI/Host mismatches with registered domains and a fronting-capable-CDN flag.

### `_registered_domain(host)`
Returns the last two labels as a coarse registered-domain approximation.

## Expected fields

`sni`/`server_name`/`ssl_server_name` (Zeek ssl.log) and `host`/`http_host` (Zeek http.log) or
proxy-log equivalents.

## Usage

```bash
python scripts/analyst.py hunt flows.csv
```

## Sources

- MITRE ATT&CK T1090.004 Domain Fronting — https://attack.mitre.org/techniques/T1090/004/
- TLS SNI (RFC 6066) — https://datatracker.ietf.org/doc/html/rfc6066
- SNI-vs-Host fronting detection approach from public network-hunting research
