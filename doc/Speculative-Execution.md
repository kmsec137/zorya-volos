# Speculative Execution for Vulnerability Detection

## Overview

Zorya now includes **speculative execution** to detect vulnerabilities (null pointer dereferences, division by zero, etc.) that don't involve explicit panic function calls. This is crucial for analyzing binaries compiled with compilers that rely on CPU traps rather than explicit panic calls.

## Problem Statement

Different compilers handle errors differently:

### TinyGo Compiler
```
if ptr == nil {
    runtime.nilpanic()  ← Explicit call, detected by panic reach analysis
}
```

### Go GC Compiler (Standard Go)
```
*ptr = value  ← If ptr==0, CPU triggers SIGSEGV
              ← OS delivers signal → runtime.sigpanic → panic
              ← No direct panic call in binary!
```

### C/C++ Compilers
```
*ptr = value  ← If ptr==0, segfault via OS
              ← No panic infrastructure at all
```


## Solution for the Go GC and C/C++ compilers: Speculative Execution

For every conditional branch involving symbolic variables, Zorya now:

1. **Takes the concrete path** (normal execution)
2. **Speculatively explores the negated path** (up to N instructions)
3. **Checks for dangerous patterns**:
   - `LOAD [address]` where address could be 0 or symbolic → **NULL_DEREF_LOAD**
   - `STORE [address], value` where address could be 0 → **NULL_DEREF_STORE**
   - `DIV/REM` where divisor could be 0 → **DIV_BY_ZERO**
4. **Reports vulnerability** with constraint to trigger it
5. **Continues normal execution**

## Example: Detecting Null Pointer Dereference

### Source Code (Go)
```go
func crash(arg uint8) {
    if arg == 'K' {
        var x *int = nil
        *x = 0  // NULL DEREFERENCE!
    }
}
```

### Compiled Assembly
```asm
004b712c  CMP  AL, 0x4b        ; if arg == 'K'
004b712e  JZ   LAB_004b7132     ; jump to crash code

LAB_004b7132:
004b7132  MOV  qword ptr [RSP], 0x0   ; store nil pointer
004b713a  XOR  EAX, EAX                ; EAX = 0
004b713c  TEST byte ptr [RAX], AL      ; READ FROM [0x0] ← CRASH!
004b713e  MOV  qword ptr [RAX], 0x0    ; WRITE TO [0x0] ← CRASH!
```

### Zorya Execution Log (with input 'a')

```
Address: 4b712c → CMP AL, 0x4b
Branch at 0x4b712e: AL == 0x4b? (0x61 == 0x4b?)
  Concrete: false (input is 'a', not 'K')
  Symbolic: involves arg_RDI (tracked variable)

>>> Performing speculative execution on negated path at 0x4b7132...
>>> Starting speculative exploration at 0x4b7132 (max depth: 50)
>>> VULNERABILITY DETECTED: Potential null pointer write at 0x4b713e

╔═══════════════════════════════════════════════════════════════════
║ 🚨 VULNERABILITY DETECTED VIA SPECULATIVE EXECUTION
║ Type: NULL_DEREF_STORE
║ Location: 0x4b713e
║ Description: Potential null pointer write at 0x4b713e (instruction 3)
╚═══════════════════════════════════════════════════════════════════

Solving SMT constraints to find triggering input...
SAT! Found input: arg = 75 (0x4b = 'K')
```

## Detected Vulnerability Types

| Type | Description | Example |
|------|-------------|---------|
| `NULL_DEREF_LOAD` | Reading from null pointer | `x = *ptr` where `ptr == 0` |
| `NULL_DEREF_STORE` | Writing to null pointer | `*ptr = val` where `ptr == 0` |
| `DIV_BY_ZERO` | Division by zero | `x / y` where `y == 0` |
