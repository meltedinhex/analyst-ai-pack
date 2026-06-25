# API Reference: Reverse Engineering Shellcode

## Overview

`scripts/analyst.py` disassembles raw shellcode with Capstone and emulates it with Unicorn under
a bounded instruction count, capturing executed addresses. Both operate inside the
disassembler/emulator; the shellcode never runs as a real process.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| capstone | >= 5.0 | Linear disassembly of x86/x64 bytes |
| unicorn | >= 2.0 | CPU emulation for self-decoding stubs |

## Core functions

### `disasm(data, arch, base, limit)`
Returns disassembled instructions (address, mnemonic, operands) at the chosen architecture.

### `emulate(data, arch, base, max_insns)`
Maps memory, writes the blob, hooks each instruction, and runs with a bounded count; returns
executed-instruction stats and the stop address.

## Usage

```bash
pip install capstone unicorn
python scripts/analyst.py disasm shellcode.bin --arch x64 --base 0x140000000
python scripts/analyst.py emulate shellcode.bin --arch x64
```

## Sources

- Capstone disassembly framework — https://www.capstone-engine.org/
- Unicorn CPU emulator — https://www.unicorn-engine.org/
- PEB-walk API resolution in Windows shellcode (kernel32 export hashing), standard technique
