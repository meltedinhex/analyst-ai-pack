# API Reference: Hunting Ransomware Precursor Behavior

## Overview

`scripts/analyst.py` parses process-creation telemetry (CSV or JSON-lines) and flags
recovery-inhibition commands and security/backup service tampering that precede encryption,
correlating co-occurrence per host to prioritize. It parses telemetry only and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | csv, json, defaultdict, file IO |

## Core functions

### `hunt(path)`
Returns recovery-inhibition events, service-tampering events, high-priority hosts (≥2 signal types),
and a precursor-suspected flag.

## Detection logic

- **Recovery inhibition**: `vssadmin delete shadows`, `wmic shadowcopy delete`, `Win32_ShadowCopy`,
  `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`, `wevtutil cl`.
- **Service tampering**: `net stop`/`sc stop`/`taskkill`/`Stop-Service` targeting backup/AV/DB
  services (Veeam, SQL, Defender, Sophos, …).
- **High priority**: a host showing both signal types in the dataset.

## Usage

```bash
python scripts/analyst.py hunt events.csv
```

## Sources

- MITRE ATT&CK T1490 Inhibit System Recovery; T1489 Service Stop; T1486 Data Encrypted for Impact
  — https://attack.mitre.org/
- Shadow-copy deletion and recovery-disabling command syntax from Windows admin documentation
- Pre-encryption sabotage sequences from public ransomware incident reporting
