# API Reference: Building Zeek Analytics for Hunting

## Overview

`scripts/analyst.py` parses Zeek logs (TSV `#fields` header or JSON-lines) and surfaces anomalies per
log kind: long/large connections (conn), JA3 rarity (ssl), executable/script downloads and rare
user-agents (http), and long/high-entropy queries (dns). It parses logs only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | math, json, Counter, file IO |

## Core functions

### `analyze(path, kind)`
Dispatches to per-kind anomaly logic and returns the findings.

### `_read_zeek(path)`
Parses Zeek TSV (via `#fields`) or JSON-lines into row dicts.

## Per-kind output

- **conn**: top long-duration/high-byte connections (`uid`, `id.resp_h`, `duration`).
- **ssl**: rare JA3 fingerprints.
- **http**: executable/script downloads and rare user-agents.
- **dns**: long or high-entropy queries.

## Usage

```bash
python scripts/analyst.py analyze conn.log --kind conn
python scripts/analyst.py analyze ssl.log --kind ssl
```

## Sources

- Zeek documentation (scripts, events) — https://docs.zeek.org/
- Zeek log formats (conn/dns/http/ssl fields, `uid` pivot) — https://docs.zeek.org/en/master/logs/index.html
- JA3 fingerprinting and long-connection hunting from public network-analytics practice
