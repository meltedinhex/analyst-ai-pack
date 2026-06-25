# API Reference: Detecting Sandbox Evasion Behavior

## Overview

`scripts/analyst.py` extracts ASCII and UTF-16LE strings from a sample and matches them against
curated evasion artifact lists (anti-VM, anti-sandbox, anti-debug, timing, fingerprinting),
returning hits grouped by category. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `scan(path)`
Returns categories found, per-category indicator hits, and an `evasion_suspected` boolean.

## Indicator categories

- **anti_vm**: VMware/VirtualBox/QEMU/Xen artifacts and guest tool names.
- **anti_sandbox**: Sandboxie, Cuckoo, analysis tools, telltale sample names/usernames.
- **anti_debug**: `IsDebuggerPresent`, `NtQueryInformationProcess`, etc.
- **timing**: `GetTickCount`, `rdtsc`, `Sleep` stalls.
- **fingerprint**: username/hostname/RAM/disk/CPUID environment checks.

## Usage

```bash
python scripts/analyst.py scan sample.bin
```

## Sources

- MITRE ATT&CK T1497 Virtualization/Sandbox Evasion — https://attack.mitre.org/techniques/T1497/
- MITRE ATT&CK T1622 Debugger Evasion — https://attack.mitre.org/techniques/T1622/
- Common VM/sandbox guest artifacts documented across public anti-analysis research
