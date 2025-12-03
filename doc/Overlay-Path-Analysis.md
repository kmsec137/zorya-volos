# Overlay Path Analysis for Vulnerability Detection

## Overview

Zorya includes **overlay path analysis** to detect vulnerabilities (null pointer dereferences, division by zero, etc.) by exploring untaken paths using a copy-on-write overlay mechanism. This technique allows full concolic execution on unexplored paths without modifying the base execution state.

## How It Works

For every conditional branch involving symbolic variables, Zorya:

1. **Takes the concrete path** (normal execution continues)
2. **Creates an overlay state** for the untaken path
3. **Executes up to N instructions** in overlay mode (default: 15)
4. **Detects vulnerability patterns**:
   - `LOAD [address]` where address could be 0 → **NULL_DEREF_LOAD**
   - `STORE [address], value` where address could be 0 → **NULL_DEREF_STORE**
   - `DIV/REM` where divisor could be 0 → **DIV_BY_ZERO**
5. **Reports vulnerability** with SMT constraints to trigger it
6. **Discards overlay** and continues normal execution

## Overlay Mechanism

The overlay uses copy-on-write semantics for efficiency:

- **CPU registers**: Modified registers are stored in overlay, unmodified ones read from base state
- **Memory**: Modified regions are cloned on first write, unmodified regions read from base
- **No state pollution**: Base execution state remains unchanged

## Configuration

- **Max depth**: 15 instructions (configurable in `overlay_path_analysis.rs`)
- **Automatic**: Enabled for all conditional branches with symbolic variables
- **Overhead**: Minimal - overlay is discarded after analysis

## When to Use

Overlay path analysis is automatically enabled for:
- **Go GC binaries** - Detects implicit nil dereferences
- **C/C++ binaries** - Detects segfaults and undefined behavior
- **TinyGo binaries** - Works alongside explicit panic detection

## Technical Details

Implementation: `src/state/overlay_path_analysis.rs`

The overlay state provides:
- Copy-on-write CPU registers
- Copy-on-write memory regions
- Full concolic execution in isolated environment
- Zero impact on base execution state

