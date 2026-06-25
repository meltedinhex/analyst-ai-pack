# API Reference: Reverse Engineering Custom C2 Protocols

## Overview

`scripts/analyst.py` is a configurable reference decoder for a length-prefixed, XOR-obfuscated
framing (`[magic][len][opcode][flags][payload]`). Adapt the field sizes and crypto to the
protocol you reversed. It only parses a capture file and makes no network connections.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | struct parsing, file IO |

## Core functions

### `decode(stream, key, magic)`
Walks the byte stream, locates framed messages by magic, parses length/opcode/flags, and
XOR-decrypts each payload; returns parsed messages.

### `xor(data, key)`
Single-byte XOR helper used as the example payload transform.

## Usage

```bash
python scripts/analyst.py decode capture.bin --key 0x5a --magic 4d5a4331
```

## Sources

- MITRE ATT&CK T1071 Application Layer Protocol — https://attack.mitre.org/techniques/T1071/
- MITRE ATT&CK T1573 Encrypted Channel — https://attack.mitre.org/techniques/T1573/
- Common C2 framing patterns (magic + length prefix + opcode dispatch), general RE practice
