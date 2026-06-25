# API Reference: Deobfuscating Malicious JavaScript

## Overview

`scripts/analyst.py` statically decodes common JS obfuscation: `\xHH`/`\uHHHH` escapes,
`String.fromCharCode(...)` sequences, and standalone base64 string literals, then extracts and
defangs URLs. It executes nothing; dynamic `eval`/`Function` layers require a sandbox (box-js).

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | base64, regex, JSON, file IO |

## External tools

| Tool | Purpose |
|------|---------|
| box-js | Sandboxed execution of `eval`/`Function` layers without real browser/WScript |

## Core functions

### `decode(source)`
Applies escape, fromCharCode, and base64 decoding; returns a preview, decoded base64, and defanged
URLs.

### `_decode_escapes` / `_decode_fromcharcode` / `_decode_b64_literals`
The individual static-decoding passes.

## Usage

```bash
python scripts/analyst.py decode dropper.js
```

## Sources

- ECMAScript language specification — https://tc39.es/ecma262/
- box-js malicious JavaScript sandbox — https://github.com/CapacitorSet/box-js
- Common JS obfuscation families (string arrays, fromCharCode, eval-packers), established practice
