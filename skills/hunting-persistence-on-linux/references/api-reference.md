# API Reference: Hunting Persistence on Linux

## Overview

`scripts/analyst.py` recursively scans collected Linux persistence artifacts and flags suspicious
lines (download-exec, reverse shells, suspicious paths) plus `authorized_keys` additions, grouped
by mechanism inferred from the file path. It reads files statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, pathlib |

## Core functions

### `scan(root)`
Returns findings (file, mechanism, line, match), a per-mechanism count, and the total.

## Mechanisms

cron, systemd (`.service`/`.timer`), rc/profile, ssh_keys (`authorized_keys`), autostart/init.d.

## Patterns

`curl|wget ... | sh`, `base64 -d | bash`, `nc -e`, `/dev/tcp/`, `bash -i`, python socket one-liners,
and `/tmp`/`/dev/shm` execution paths.

## Usage

```bash
python scripts/analyst.py scan /path/to/collected
```

## Sources

- MITRE ATT&CK T1543.002 Systemd Service; T1053.003 Cron; T1098.004 SSH Authorized Keys — https://attack.mitre.org/
- Reverse-shell / download-exec one-liner patterns from public Linux IR practice
- Linux persistence locations (cron, systemd, rc files, autostart) from distribution documentation
