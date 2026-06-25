# API Reference: Tracking Adversary Infrastructure

## Overview

`scripts/analyst.py` clusters suspected adversary hosts that share pivot-attribute values (JARM,
cert CN, favicon hash, ASN, etc.) using union-find over shared `(attribute, value)` keys, ranks
clusters by the count of distinct shared attributes, and defangs host indicators. It parses data
only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | json, defaultdict, file IO |

## Core functions

### `cluster(path, attrs)`
Returns clusters (defanged hosts, shared attributes, strength) ranked by shared-attribute count.

## Input

A JSON list of host records, each with `host`/`ip` and the chosen attribute fields. Generic values
(empty, `cloudflare`, `n/a`) are ignored as pivots.

## Usage

```bash
python scripts/analyst.py cluster hosts.json --attrs jarm,cert_cn,favicon_hash,asn
```

## Sources

- MITRE ATT&CK T1583 Acquire Infrastructure — https://attack.mitre.org/techniques/T1583/
- JARM active TLS fingerprinting — https://github.com/salesforce/jarm
- Favicon-hash / certificate pivot clustering from public infrastructure-tracking research
