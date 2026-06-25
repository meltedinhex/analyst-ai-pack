# API Reference: Unpacking UPX and Common Packers

## Overview

`scripts/analyst.py` detects common packers from PE section names and per-section entropy and
recommends an unpacking approach (automated UPX vs manual debugger unpacking). It parses the
PE section table directly and reads bytes only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct, entropy |

## External tools

| Tool | Purpose |
|------|---------|
| upx | Automated pack/unpack for standard UPX |
| Detect It Easy (DIE) | Broad packer/compiler signature detection |
| x64dbg + Scylla | Manual unpacking, dumping, IAT rebuild |

## Core functions

### `detect(path)`
Returns packer signatures, sections with entropy, high-entropy sections, whole-file entropy,
a `likely_packed` flag, and an unpacking recommendation.

### `parse_sections(data)`
Minimal PE section-table parser (name, raw size, entropy).

## Usage

```bash
python scripts/analyst.py detect sample.bin
upx -d -o sample_unpacked.bin sample.bin     # if standard UPX
```

## Sources

- UPX — https://upx.github.io/
- Detect It Easy — https://github.com/horsicq/Detect-It-Easy
- Common packer section-name conventions (DIE/PEiD signature knowledge)
