<!--
// SPDX-FileCopyrightText: 2026 Keith Makan Security Consultancy Pty Ltd - WORLD CLASS CYBERSECURITY

SPDX-License-Identifier: Apache-2.0
-->

<div align="center">
  <img src="doc/zorya_logo.png" alt="Logo" width="250"/>
</div>

<br>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/version-0.0.5-green" alt="Version">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Made%20with-Rust-orange?logo=rust" alt="Made with Rust"/></a>
</p>

<<<<<<< HEAD
<pre>
:::::::::    ...    :::::::...-:.     ::-.:::.     
'`````;;; .;;;;;;;. ;;;;``;;;;';;.   ;;;;';;`;;    
    .n[[',[[     \[[,[[[,/[[['  '[[,[[[' ,[[ '[[,  
  ,$$P"  $$$,     $$$$$$$$$c      c$$"  c$$$cc$$$c 
,888bo,_ "888,_ _,88P888b "88bo,,8P"`    888   888,
 `""*UMM   "YMMMMMP" MMMM   "W"mM"       YMM   ""` 
:::      .::.  ...      :::         ...      .::::::. 
';;,   ,;;;'.;;;;;;;.   ;;;      .;;;;;;;.  ;;;`    ` 
 \[[  .[[/ ,[[     \[[, [[[     ,[[     \[[,'[==/[[[[,
  Y$c.$$"  $$$,     $$$ $$'     $$$,     $$$  '''    $
   Y88P    "888,_ _,88Po88oo,.__"888,_ _,88P 88b    dP
    MP       "YMMMMMP" """"YUMMM  "YMMMMMP"   "YMmMY" 

- KMSEC (PTY) LTD.

</pre>


ZORYA VOLOS IS A WIP FORK OF ZORYA OWNED AND MAINTAINED BY KEITH MAKAN SECURITY CONSULTANCY (PTY) LTD

What KMSEC has added:
- volos memory interaction tracking system

```
[VOLOS DETECTOR] DATA RACE FOUND AT 0x1f948
----------------------------------------------------------------
Access 1:
  Goroutine ID: 371053
  Op Type:      Write
  Locks Held:   [5843280]
--- VS ---
Access 2:
  Goroutine ID: 371056
  Op Type:      Write
  Locks Held:   NONE (UNPROTECTED)
----------------------------------------------------------------
REASON: One or more threads accessed this memory without a shared lock.
================================================================

[VOLOS] READ MEM @[0x572E50] <= [32, 59, 87, 0, 0, 0, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] READ MEM @[0x573C2F] <= [2] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] WRITE MEM @[0x573C2F] <= ['[1]'] Volos { thread_id: 371056, access_type: Write, locks_held: [] }
[VOLOS] READ MEM @[0x573C2F] <= [1] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] READ MEM @[0x7FFFFFFFD7E0] <= [24, 216, 255, 255, 255, 127, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] READ MEM @[0x7FFFFFFFD7E8] <= [120, 215, 67, 0, 0, 0, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] READ MEM @[0x572F00] <= [0, 0, 0, 0, 0, 0, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] READ MEM @[0x7FFFFFFFD828] <= [70, 234, 75, 0, 0, 0, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] READ MEM @[0x7FFFFFFFD830] <= [1, 0, 0, 0, 0, 0, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] WRITE MEM @[0x7FFFFFFFD7E8] <= ['[42, 216, 67, 0, 0, 0, 0, 0]'] Volos { thread_id: 371056, access_type: Write, locks_held: [] }
[VOLOS] READ MEM @[0x7FFFFFFFD7E8] <= [42, 216, 67, 0, 0, 0, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
arg_values.joinAddress: 44f1c0, Symbol: runtime.writeErrData -> data=0x4bea46 (reg=RAX @0x0), n=0x1 (reg=RBX @0x18)
[VOLOS] WRITE MEM @[0x7FFFFFFFD7E0] <= ['[24, 216, 255, 255, 255, 127, 0, 0]'] Volos { thread_id: 371056, access_type: Write, locks_held: [] }
[VOLOS] READ MEM @[0x7FFFFFFFD7E0] <= [24, 216, 255, 255, 255, 127, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] WRITE MEM @[0x7FFFFFFFD7F0] <= ['[70, 234, 75, 0, 0, 0, 0, 0]'] Volos { thread_id: 371056, access_type: Write, locks_held: [] }
[VOLOS] READ MEM @[0x7FFFFFFFD7F0] <= [70, 234, 75, 0, 0, 0, 0, 0] #Volos { thread_id: 371056, access_type: Read, locks_held: [] }
[VOLOS] WRITE MEM @[0x7FFFFFFFD7F8] <= ['[1, 0, 0, 0]'] Volos { thread_id: 371056, access_type: Write, locks_held: [] }

```

Zorya is a **concolic execution framework** designed to detect **logic-related bugs, language-specific vulnerabilities, and identify new patterns of security issues mainly in Go binaries**. The analysis begins by generating CPU register and memory dumps using ```gdb```. Zorya loads these dumps to initialize execution from a specified starting address, ensuring a realistic and accurate representation of the program state.

The engine is written in Rust and includes a state manager, AMD64 CPU model, memory model, and virtual file system.
It supports language/compiler-aware exploration strategies, including targeted advanced mode and fuzzer-driven campaigns.

> The owl sees what darkness keeps —
> Zorya comes, and nothing sleeps.

🚧 Zorya is under active development. Breaking changes may happen. 🚧

## :inbox_tray: Install
Make sure to have Rust, Golang and Python properly installed. FYI, the project is beeing developped and maintained under a Linux Ubuntu distrubution.

<<<<<<< HEAD
```
=======
### Option A: Docker Installation

```bash
git clone --recursive https://github.com/Ledger-Donjon/zorya
cd zorya
docker build -t zorya:latest .

docker run -it --rm \
  --security-opt seccomp=unconfined \
  --cap-add=SYS_PTRACE \
  -v $(pwd)/results:/opt/zorya/results \
  zorya:latest
```

### Option B: Native Installation

```bash
>>>>>>> upstream/main
git clone --recursive https://github.com/Ledger-Donjon/zorya
cd zorya
make ghidra-config
make all
```

## :wrench: Usage

### A. Interactive Usage (prefered)
Zorya provides a guided mode, so you don't need to remember the options or flags. It prompts you with questions to outline three typical scenarios:
=======

Run:

```bash
zorya <absolute-path-to-binary>
```

Interactive mode asks for:
- language and compiler
- execution mode (`start`, `main`, `function`, `advanced`)
- optional function/address details
- optional binary arguments
- optional negated-path exploration

Advanced mode allows explicit symbolic register and memory selection.

Detailed interactive and flag behavior: [doc/Usage.md](doc/Usage.md)

### B. Basic command-line usage

```bash
zorya <path> --lang <go|c|c++> [--compiler <tinygo|gc>] \
  --mode <start|main|function|advanced> <addr> \
  [--thread-scheduling <all-threads|main-only>] \
  [--arg "<arg1> <arg2>"] \
  [--negate-path-exploration|--no-negate-path-exploration] \
  [--force-pty] \
  [--symbolic-registers "REG1 REG2|all"] \
  [--symbolic-memory "0xADDR:SIZE ..."] \
  [--no-symbolic-registers] [--no-symbolic-memory]
```

Full flag reference and examples: [doc/Usage.md](doc/Usage.md)

### C. Fuzzer mode

For automated campaigns on multiple addresses/configurations:

Given the absolute path to the binary you want to analyze ```<path>```, simply run:
```
zorya <path>
```
The prompt will ask you for the:
1. Source code language: go, c, or c++
2. Go compiler: tinygo or gc (only when go is selected)
3. Thread scheduling strategy: all-threads or main-only (only for Go GC binaries)
4. Analysis mode: start, main, function, or advanced
5. Function address: If you chose function or advanced modes
6. (Advanced mode only) Registers and memory addresses to make symbolic
7. Binary arguments: If the binary expects arguments (optional)
8. Negating path execution: Whether to symbolically explore alternate branches (defaults to yes)

### B. Basic Command-Line Usage
To use Zorya in its basic form, you need the absolute path to the binary you wish to analyze (```<path>```) and the hexadecimal address where execution should begin (```<addr>```). You must then specify the execution mode (start, main, function, or advanced) based on your chosen analysis strategy. Additionally, you can provide any necessary arguments to be passed to the binary:
```
zorya <path> --lang <go|c|c++> [--compiler <tinygo|gc>] --mode <start|main|function|advanced> <addr> [--thread-scheduling <all-threads|main-only>] --arg "<arg1> <arg2>" [--negate-path-exploration|--no-negate-path-exploration] [--force-pty] [--symbolic-registers "REG1 REG2"] [--symbolic-memory "0xADDR1:SIZE1 0xADDR2:SIZE2"]

FLAG:
  --lang                        Specifies the language used in the source code (go/c/c++)
  --compiler                    When Go was chosen as 'lang', specifies the used compiler (tinygo or gc)
  --mode                        Specifies the strategy mode to determine the starting address for binary analysis. Options include:
                                      start → Use the binary's entry point
                                      main → Analyze the main function (main.main preferred in Go binaries)
                                      function → Specify a function address manually
                                      advanced → Define an arbitrary execution address with fine-grained
                                                 symbolic variable selection (registers, memory)
  --thread-scheduling           Thread scheduling strategy for Go GC binaries:
                                      all-threads → Load + schedule all dumped OS threads
                                      main-only   → Execute only the main thread (simpler/more deterministic)
  --negate-path-exploration    Enables symbolic exploration of negated paths (default behavior)
  --no-negate-path-exploration  Disables negated path exploration
  --force-pty                   Runs GDB inside a pseudo-terminal (PTY) so the target binary sees a real
                                terminal on its stdin/stdout. Required when the binary uses isatty() checks
                                that gate code paths you want to analyze (see notes below).

OPTION:
  --arg                         Specifies arguments to pass to the binary, if any (default is 'none').
  --symbolic-registers          (Advanced mode) Space-separated list of registers to make symbolic
                                (e.g., "RAX RDI RSI"). If omitted in advanced mode, Zorya prompts interactively.
  --symbolic-memory             (Advanced mode) Space-separated list of memory ranges to make symbolic,
                                formatted as "0xADDR:SIZE_IN_BYTES" (e.g., "0x7fff0010:8 0x404000:16").

ENVIRONMENT:
  LOG_MODE=trace_only           Disable creation of results/execution_log.txt (file logging). Zorya will still
                                write results/execution_trace.txt.
```

Notes:
- If any flag is missing, Zorya will prompt you interactively to ask for it.
- The address ()```<addr>```) is mandatory when using function or advanced modes.
- Arguments (--arg) are optional.
- The ```--negate-path-exploration``` flag enables alternate path exploration (symbolic branch negation) to increase code coverage. It is enabled by default unless explicitly disabled using ```--no-negate-path-exploration```, if the execution takes too much time for instance.
- The ```--force-pty``` flag is needed when the target binary checks whether its I/O streams are connected to a real terminal (via ```isatty()``` / Go's ```term.IsTerminal()```). By default, GDB runs the child process with pipes, so ```isatty()``` returns false and terminal-dependent code paths are skipped entirely during the GDB dump phase. When ```--force-pty``` is set, Zorya wraps every GDB session inside the Linux ```script``` command, which allocates a real pseudo-terminal (```/dev/pts/N```). The child process then sees a genuine TTY, and terminal-gated initialization runs normally. A concrete example is ```kubectl exec -it```, where terminal size monitoring is only initialized when stdout is a TTY — see [Go-Binary-Analysis.md](doc/Go-Binary-Analysis.md) for details.

## How to build your binary?
Zorya needs the binary to have the debug symbols to perform the complete analysis. Striped binaries could be also analyzed, but it required to disable many functionnalities of the tool.
=======
```bash
cargo build --release --bin zorya-fuzzer
./target/release/zorya-fuzzer --create-example fuzzer_config.json
./target/release/zorya-fuzzer fuzzer_config.json
```

Full documentation: [doc/Fuzzer.md](doc/Fuzzer.md)

### How to build your binary?

Zorya works best with debug symbols.

For Go:
- `tinygo build -gc=conservative -opt=0 .`
- `go build -gcflags=all="-N -l" .`

More details: [doc/Go-Binary-Analysis.md](doc/Go-Binary-Analysis.md)

## 3. Quick start with test binaries

You can validate your setup with the included test programs in `tests/programs`.

Minimal quick start:

```bash
zorya /absolute/path/to/zorya/tests/programs/crashme/crashme
```

Expected outputs and result files are documented in:
[doc/Quickstart.md](doc/Quickstart.md)

## 4. Documentation

<p align="center">
  <img src="doc/zorya_workflow.png" alt="Zorya workflow" width="500"/>
</p>


Technical details were moved under `doc/`:

- Usage and CLI details: [doc/Usage.md](doc/Usage.md)
- Quick start and expected outputs: [doc/Quickstart.md](doc/Quickstart.md)
- Vulnerability detection: [doc/Vulnerability-Detection.md](doc/Vulnerability-Detection.md)
- Compiler-aware strategies: [doc/Compiler-Aware-Strategies.md](doc/Compiler-Aware-Strategies.md)
- Overlay path analysis: [doc/Overlay-Path-Analysis.md](doc/Overlay-Path-Analysis.md)
- Strategy overview: [doc/Strategies.md](doc/Strategies.md)
- Multi-threading: [doc/Multi-threading.md](doc/Multi-threading.md)
- Go binary analysis details: [doc/Go-Binary-Analysis.md](doc/Go-Binary-Analysis.md)
- Fuzzer reference: [doc/Fuzzer.md](doc/Fuzzer.md)

## 5. Demo videos

Demo on TinyGo broken-calculator:
[Demo](https://youtu.be/8PeSZFvr6WA)

EthCC 2025 overview presentation:
[Presentation](https://www.youtube.com/live/QpcAtfN3B9M)

## 6. Academic work

Exposing Go's Hidden Bugs: A Novel Concolic Framework (IEEE SERA 2025):
[IEEE Xplore](https://ieeexplore.ieee.org/document/11449147)

```bibtex
@INPROCEEDINGS{11449147,
  author={Gorna, Karolina and Iooss, Nicolas and Seurin, Yannick and Khatoun, Rida},
  booktitle={2025 IEEE/ACIS 23rd International Conference on Software Engineering Research, Management and Applications (SERA)},
  title={Exposing Go’s Hidden Bugs: A Novel Concolic Framework},
  year={2025},
  pages={1-6},
  keywords={Couplings;Concurrent computing;Computer languages;Runtime;Static analysis;Fuzzing;Explosions;Security;Protection;Testing;Concolic execution;Go;Invariant testing;Vulnerabilities detection;P-Code},
  doi={10.1109/SERA65747.2025.11449147}
}
```

Zorya: Automated Concolic Execution of Single-Threaded Go Binaries:
[ArXiv](https://arxiv.org/abs/2512.10799)

```bibtex
@article{gorna2025zorya,
  title={Zorya: Automated Concolic Execution of Single-Threaded Go Binaries},
  author={Gorna, Karolina and Iooss, Nicolas and Seurin, Yannick and Khatoun, Rida},
  journal={arXiv preprint arXiv:2512.10799},
  year={2025},
  note={Accepted at the 41st ACM/SIGAPP Symposium On Applied Computing (SAC 2026)}
}
```

Evaluation repository:
[Zorya Evaluation](https://github.com/Ledger-Donjon/zorya-evaluation)

Evaluation Go dataset:
[Logic-Bombs-Go](https://github.com/Ledger-Donjon/logic_bombs_go)
