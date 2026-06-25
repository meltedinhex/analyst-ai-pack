---
name: hunting-persistence-on-linux
description: 'Hunts for Linux persistence by inspecting cron, systemd units, shell rc files, SSH
  authorized_keys, and common autostart locations for attacker-added entries. Activates for
  requests to hunt Linux persistence, audit cron/systemd for backdoors, or find unauthorized
  autostart and authorized_keys entries.'
domain: cybersecurity
subdomain: threat-hunting
tags:
  - threat-hunting
  - linux
  - persistence
  - cron
  - systemd
version: 1.0.0
author: analyst-ai-pack
license: Apache-2.0
mitre_attack:
  - T1053.003
  - T1543.002
  - T1098.004
d3fend:
  - D3-FA
  - D3-PSA
references:
  - 'MITRE ATT&CK T1543.002 Systemd Service — https://attack.mitre.org/techniques/T1543/002/'
  - 'MITRE ATT&CK T1053.003 Cron — https://attack.mitre.org/techniques/T1053/003/'
---

# Hunting Persistence on Linux

## When to Use

- You have collected Linux persistence-relevant files (cron entries, systemd units, shell rc
  files, `authorized_keys`, autostart) and want to flag suspicious entries.
- You are triaging a suspected compromised Linux host's persistence surface.

**Do not use** this on a live root shell as a substitute for proper IR collection — feed it
collected copies. It reads files statically and executes nothing.

## Prerequisites

- Collected persistence artifacts (cron files, unit files, rc files, `authorized_keys`).

## Safety & Handling

- Read files statically; treat their contents as untrusted.

## Workflow

### Step 1: Scan persistence files

```bash
python scripts/analyst.py scan /path/to/collected
```

Recursively scans known persistence locations and flags entries containing download/exec patterns
(`curl|wget ... | sh`, `base64 -d | bash`, reverse-shell one-liners, `nc -e`), suspicious paths
(`/tmp`, `/dev/shm`), and unexpected `authorized_keys` additions.

### Step 2: Categorize by mechanism

Group findings by mechanism: cron, systemd, rc/profile, SSH keys, autostart.

### Step 3: Confirm

Compare against a known-good baseline of expected services/keys; investigate deviations.

### Step 4: Document

Record each persistence entry, its mechanism, and the suspicious indicator.

## Validation

- Findings are grouped by persistence mechanism.
- Reverse-shell/download-exec one-liners are flagged with the matched pattern.
- `authorized_keys` additions are surfaced for review.

## Pitfalls

- Legitimate admin cron/systemd entries — baseline before alerting.
- Persistence in less-common spots (udev, PAM, LD_PRELOAD) not covered by basic scans.
- Encoded/obfuscated payloads hiding the true command.

## References

- See [`references/api-reference.md`](references/api-reference.md) for the scanner.
- ATT&CK T1543.002 and T1053.003 (linked in frontmatter).
