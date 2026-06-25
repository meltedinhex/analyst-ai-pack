# API Reference: Defeating Control-Flow Flattening

## Overview

`scripts/analyst.py` consumes a function CFG (basic blocks with successors, in-degree, state-compare
flag, and next-state constants) and reconstructs the original control flow by identifying the
dispatcher and mapping each case's next-state to its successor. It parses JSON only and executes
nothing.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| (stdlib) | — | JSON, argparse, pathlib |

## Input format

```json
{
  "state_var": "eax",
  "entry": "A",
  "blocks": [
    {"id": "D", "succ": ["B","C"], "in_degree": 5, "state_compare": true},
    {"id": "B", "succ": ["D"], "in_degree": 1, "next_state": "C"}
  ]
}
```

## Core functions

### `detect(path)`
Returns the dispatcher, case count, deflattened transitions, and unresolved blocks.

## Method

Dispatcher = highest in-degree block that compares the state variable; case blocks branch back to
it; each case's `next_state` constant gives the true successor.

## Usage

```bash
python scripts/analyst.py detect cfg.json
```

## Sources

- Obfuscator-LLVM control-flow flattening — https://github.com/obfuscator-llvm/obfuscator
- MITRE ATT&CK T1027 Obfuscated Files or Information — https://attack.mitre.org/techniques/T1027/
- Dispatcher/state-variable deflattening method from public deobfuscation research
