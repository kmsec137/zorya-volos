<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Go Runtime Offsets

## Overview

Zorya extracts memory offsets of internal Go runtime structures to enable low-level analysis of Go binaries during concolic execution.

## Runtime G Offsets

The `runtime_g_offsets.json` file contains **byte offsets** (not values or counts) for fields in Go's internal `runtime.g` struct, which represents a goroutine.

### Format

```json
{
  "go_version": "go1.25.1",
  "runtime_g_offsets": {
    "goid": 152,      // goroutine ID is at byte offset 152
    "stack": 0,       // stack bounds at byte offset 0
    "m": 48,          // pointer to M (OS thread) at byte offset 48
    "racectx": 304,   // race detector context at byte offset 304
    ...
  }
}
```

### Usage

These offsets allow Zorya to:
- Read goroutine state directly from process memory
- Navigate Go runtime internals without runtime API calls
- Track goroutine scheduling and execution
- Access thread and stack information

### Important Notes

- **Offsets are version-specific**: Go runtime struct layouts change between versions
- **Values are byte positions**: Not actual runtime values or counts
- **Critical fields**: `goid`, `stack`, `stackguard0`, `m`, `atomicstatus` are most commonly used

## Function Signatures

The same extraction tool (`get-funct-arg-types`) also parses Go function signatures to map arguments to their physical locations (registers or stack).

### Output Format

```json
{
  "name": "main.ProcessData",
  "address": "0x4a2c00",
  "arguments": [
    {
      "name": "data",
      "type": "[]uint8",
      "registers": ["RDI", "RSI", "RDX"]  // ptr, len, cap
    },
    {
      "name": "flags",
      "type": "int64",
      "registers": ["RCX"]
    }
  ]
}
```

### How It Works

1. **DWARF-first approach**: Reads `DW_AT_location` attributes from DWARF to determine actual register/stack assignments
2. **Location expressions**: Parses DWARF opcodes (`DW_OP_reg*`, `DW_OP_breg*`, `DW_OP_fbreg`) to extract register numbers and stack offsets
3. **ABI fallback**: If DWARF lacks location info, infers registers from Go's register-based calling convention (RDI, RSI, RDX, RCX, R8, R9)
4. **Multi-register types**: Handles compound types (slices use 3 registers, strings use 2, interfaces use 2)

### Register Mapping

- **Slices** (`[]T`): 3 registers (pointer, length, capacity)
- **Strings**: 2 registers (pointer, length)
- **Interfaces**: 2 registers (data, type)
- **Scalars**: 1 register
- **Stack**: When registers exhausted, uses `STACK+0x<offset>` notation

### Important Notes

- **Result parameters** (like `~r0`, `~r1`) are filtered out - only input parameters are extracted
- **Register offsets are positions**, not values (e.g., `"registers": ["RDI"]` means argument is passed in RDI)
- Used by Zorya to initialize symbolic values for function arguments during concolic execution

## Extraction

Both runtime offsets and function signatures are automatically extracted by analyzing DWARF debug info in compiled Go binaries during Zorya's initialization phase using `scripts/get-funct-arg-types/main.go`.

