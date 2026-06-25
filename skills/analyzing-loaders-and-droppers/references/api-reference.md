# API Reference: Analyzing Loaders and Droppers

## Overview

`scripts/analyst.py` analyzes a loader/dropper: it finds embedded PE/archive signatures (skipping
the loader's own header), counts high-entropy windows (packed/encrypted stages), and scans strings
for download, decode, and execution APIs plus URLs. It reads bytes statically, defangs URLs, and
executes nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | math, regex, Counter, JSON, file IO |

## Core functions

### `stage(path)`
Returns embedded signatures, high-entropy window count, download/decode/execution API hits,
defanged URLs, and a loader likelihood flag.

### `_entropy(chunk)`
Shannon entropy (bits/byte) over a window; >7.2 suggests compressed/encrypted data.

## API categories

- **download**: `URLDownloadToFile`, `InternetReadFile`, WinHTTP/WinINet.
- **decode**: `CryptDecrypt`, `CryptStringToBinary`, base64/RC4/XOR.
- **execution**: `CreateProcess`, `ShellExecute`, `WinExec`, `CreateRemoteThread`, `LoadLibrary`.

## Usage

```bash
python scripts/analyst.py stage sample.bin
```

## Sources

- MITRE ATT&CK T1105 Ingress Tool Transfer — https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1140 Deobfuscate/Decode Information — https://attack.mitre.org/techniques/T1140/
- Shannon entropy definition; overlay/staging patterns from public loader analyses
