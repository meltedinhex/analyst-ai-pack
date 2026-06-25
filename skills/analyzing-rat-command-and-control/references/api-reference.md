# API Reference: Analyzing RAT Command and Control

## Overview

`scripts/analyst.py` extracts strings from a RAT and maps them to capability classes (remote shell,
file ops, surveillance, persistence, proxy/relay, self-update, credential theft) and C2 transports
(HTTP, raw TCP, TLS, DNS, messaging), defanging C2 URLs. It reads bytes statically and executes
nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `profile(path)`
Returns grouped capabilities, C2 transports, defanged C2 URLs, and a RAT-likelihood flag
(≥3 capability classes).

## Capability classes

remote_shell, file_operations, surveillance (screenshot/keylog/webcam/audio), persistence,
proxy_relay, self_update, credential_theft.

## Usage

```bash
python scripts/analyst.py profile sample.bin
```

## Sources

- MITRE ATT&CK T1219 Remote Access Software — https://attack.mitre.org/techniques/T1219/
- MITRE ATT&CK T1071 Application Layer Protocol — https://attack.mitre.org/techniques/T1071/
- RAT capability/command-handler patterns from public family analyses
