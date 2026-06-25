# API Reference: Bypassing Anti-VM and Sandbox Checks

## Overview

`scripts/analyst.py` locates anti-VM/sandbox detection routines by scanning for artifact strings,
timing APIs, environment-fingerprint APIs, and CPUID/RDTSC opcodes, reporting offsets to guide
patching or hooking. It reads bytes statically and executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | regex, JSON, file IO |

## Core functions

### `locate(path)`
Returns artifact-string offsets, timing/fingerprint API offsets, CPUID/RDTSC opcode offsets, and an
evasion-present flag.

## Detection primitives located

- Artifact strings: VMware/VirtualBox/QEMU/Sandboxie/Cuckoo.
- Timing: `GetTickCount`, `QueryPerformanceCounter`, plus `rdtsc` (`0F 31`).
- CPUID (`0F A2`) for the hypervisor-present bit.
- Fingerprint APIs: adapters, computer/user name, memory/system info.

## Usage

```bash
python scripts/analyst.py locate sample.bin
```

## Sources

- MITRE ATT&CK T1497 Virtualization/Sandbox Evasion — https://attack.mitre.org/techniques/T1497/
- Intel SDM: CPUID leaf 1 ECX bit 31 hypervisor-present — https://www.intel.com/sdm
- RDTSC timing-evasion and VM artifact checks from public anti-analysis research
