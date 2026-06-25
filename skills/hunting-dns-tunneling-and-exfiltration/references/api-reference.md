# API Reference: Hunting DNS Tunneling and Exfiltration

## Overview

`scripts/analyst.py` aggregates DNS queries by registered domain and scores tunneling signals:
unique-subdomain count, average label length, Shannon entropy of labels, and data-bearing record
types. It reads local JSON only and issues no DNS queries.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | math (entropy), JSON, file IO |

## Input format

```json
[
  {"query": "a8f3kd9.tunnel.example.com", "qtype": "TXT", "src": "10.0.0.5"}
]
```

## Core functions

### `entropy(s)`
Shannon entropy (bits/char) of a label, used to detect encoded data.

### `registered(domain)`
Heuristic registered-domain extraction (last two labels).

### `hunt(queries)`
Aggregates by registered domain and returns candidates scoring >= 50.

## Usage

```bash
python scripts/analyst.py hunt dns.json
```

## Sources

- MITRE ATT&CK T1071.004 DNS — https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol —
  https://attack.mitre.org/techniques/T1048/
- Subdomain entropy/length and TXT/NULL record abuse as DNS-tunnel indicators, established
  network-hunting practice
