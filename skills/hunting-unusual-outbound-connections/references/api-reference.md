# API Reference: Hunting Unusual Outbound Connections

## Overview

`scripts/analyst.py` parses outbound connection telemetry (CSV or JSON-lines) and scores connections
by direct-to-IP, non-standard port, high sent:received ratio, and egress from unexpected
processes, plus aggregates destination rarity. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, ipaddress, Counter |

## Core functions

### `hunt(path, ratio_threshold=5.0)`
Returns scored findings (dest, port, process, reasons) and rare destinations (≤2 connections).

## Signals

- `direct_to_ip`: IP destination with no resolved domain.
- `uncommon_port`: not in the common-port set (80/443/53/22/...).
- `high_egress_ratio`: sent/received ≥ threshold and >10 KB sent.
- `unexpected_process`: egress from `notepad.exe`, `rundll32.exe`, Office, etc.

## Expected fields

`DestinationIp`/`DestinationPort`/`DestinationHostname`, `Image`, `BytesSent`/`BytesReceived`
(Sysmon EID 3) or Zeek `id.resp_h`/`id.resp_p`/`orig_bytes`/`resp_bytes`.

## Usage

```bash
python scripts/analyst.py hunt conns.csv --ratio 5
```

## Sources

- MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol; T1571 Non-Standard Port — https://attack.mitre.org/
- Sysmon Event ID 3 and Zeek conn.log field names (official documentation)
- Egress-ratio / direct-IP hunting heuristics from public network-hunting practice
