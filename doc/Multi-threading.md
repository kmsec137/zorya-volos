<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Multi-Thread Support in Zorya

Zorya supports multi-threaded Go binaries by automatically dumping and restoring all OS thread states (registers + FS/GS bases) from GDB.

## Overview

When analyzing Go binaries compiled with the `gc` compiler (standard Go compiler), the runtime creates multiple OS threads. Starting execution at `main.main` or `runtime.main` requires all threads to be properly initialized with their TLS (Thread-Local Storage) bases.

## How It Works

### 1. Automatic Thread Dumping (GDB)

The `dump_memory.sh` script now automatically:
- Dumps all OS thread states to `results/initialization_data/threads/thread_<TID>.json`
- Captures general-purpose registers (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS)
- Captures TLS bases (FS_BASE and GS_BASE)
- **Captures full backtraces using `thread apply all bt`** for context
- Automatically identifies the main thread (the one at `main.main`)
- Classifies thread states (at_main, waiting, sysmon, background)
- Creates a thread index file (`threads_index.json`) with thread states
- Saves full backtrace output to `thread_backtraces.txt` for debugging

### 2. Automatic Thread Restoration (Zorya)

During initialization, Zorya:
- Scans `results/initialization_data/threads/` for thread dumps
- Creates an `OSThread` for each dump with full register state
- Sets FS base (offset 0x110) and GS base (offset 0x118) for each thread
- Marks the main thread as "Running" and others as "Ready"

### 3. ThreadManager Integration

The `ThreadManager`:
- Tracks `fs_base` and `gs_base` separately for each thread
- Supports creating threads from dumps via `create_thread_from_dump()`
- Maintains thread status (Running, Ready, Blocked, Exited)


## Files Created

After running Zorya, you'll find:

```
results/initialization_data/
├── threads/
│   ├── thread_<TID1>.json    # Thread 1 state
│   ├── thread_<TID2>.json    # Thread 2 state
│   └── threads_index.json    # Index with main_tid
├── dumps/                     # Memory region dumps
├── cpu_mapping.txt           # Primary CPU state
└── memory_mapping.txt        # Memory regions
```

## Thread Dump Format

Each `thread_<TID>.json` contains:

```json
{
  "tid": 164698,
  "regs": {
    "rax": 0,
    "rbx": 140737353945088,
    "rcx": 0,
    "rip": 4595152,
    ...
  },
  "fs_base": 140737353946880,
  "gs_base": 0,
  "backtrace": "#0  main.main () at main.go:16",
  "is_at_main": true
}
```

The `threads_index.json` contains:

```json
{
  "main_tid": 164698,
  "thread_count": 5,
  "threads": [164698, 164701, 164702, 164703, 164704],
  "thread_states": [
    {"tid": 164698, "state": "at_main"},
    {"tid": 164701, "state": "sysmon"},
    {"tid": 164702, "state": "waiting"},
    {"tid": 164703, "state": "waiting"},
    {"tid": 164704, "state": "waiting"}
  ]
}
```

This makes it trivial to identify:
- **Main thread**: The one with `"is_at_main": true` or at `main.main` in backtrace
- **System monitor**: Thread running `runtime.sysmon` (background GC/scheduling)
- **Waiting threads**: Blocked on futex/sleep (worker threads waiting for work)
- **Background threads**: Other runtime threads


## Future Work

- Support for thread scheduling/switching during execution
- Goroutine-level state tracking (currently OS threads only)
- Stack memory regions per thread
- Thread-specific breakpoints and watchpoints

## References

- Go Runtime: https://github.com/golang/go/tree/master/src/runtime
- x86-64 ABI: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
- GDB Python API: https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html

