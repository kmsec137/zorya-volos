#!/usr/bin/env python3
import sys
import os
import pyhidra

try:
    from pyhidra import open_program
except ImportError:
    print("ERROR: Pyhidra not installed. Run: pip install pyhidra")
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print("Usage: precompute_panic_reach.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    xref_path = os.path.join("results", "xref_addresses.txt")
    out_path = os.path.join("results", "panic_reachable.txt")

    panic_hex = []
    if os.path.exists(xref_path):
        with open(xref_path, "r") as f:
            raw = [line.strip() for line in f if line.strip()]
            # Normalize to plain hex without 0x prefix for Ghidra
            panic_hex = [h[2:] if h.lower().startswith("0x") else h for h in raw]

    pyhidra.start()

    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import Function

    with open_program(binary_path, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        addr_factory = program.getAddressFactory()
        monitor = ConsoleTaskMonitor()
        model = BasicBlockModel(program)

        # Convert panic addresses (call sites) to blocks and seed reverse frontier (use containing blocks)
        panic_blocks = set()
        for h in panic_hex:
            try:
                a = addr_factory.getAddress(h)
                if a is None:
                    a = addr_factory.getAddress(f"ram:{h}")
                if a is None:
                    continue
                if not program.getMemory().contains(a):
                    continue
                blocks = model.getCodeBlocksContaining(a, monitor)
                for blk in blocks:
                    if blk is not None:
                        panic_blocks.add(blk)
            except Exception:
                continue

        # Also seed from panic functions discovered by name (case-insensitive contains "panic")
        fm = program.getFunctionManager()
        it = fm.getFunctions(True)
        while it.hasNext():
            fn = it.next()
            try:
                name = fn.getName()
            except Exception:
                continue
            if name is None:
                continue
            if "panic" in name.lower():
                entry = fn.getEntryPoint()
                if entry is None:
                    continue
                if not program.getMemory().contains(entry):
                    continue
                blk = model.getCodeBlockAt(entry, monitor)
                if blk is None:
                    blocks = model.getCodeBlocksContaining(entry, monitor)
                    for b in blocks:
                        if b is not None:
                            panic_blocks.add(b)
                else:
                    panic_blocks.add(blk)

        # Reverse BFS: predecessors via getSources; also include interprocedural step:
        # for each visited block, jump to all callers of its containing function
        reachable = set()
        work = list(panic_blocks)
        processed_funcs = set()  # function entry addresses we've already expanded callers for
        while work:
            blk = work.pop()
            if blk in reachable:
                continue
            reachable.add(blk)
            # 1) Intra-procedural predecessors
            src_iter = blk.getSources(monitor)
            while src_iter.hasNext():
                ref = src_iter.next()
                src_addr = ref.getSourceAddress()
                src_blk = model.getCodeBlockAt(src_addr, monitor)
                if src_blk is None:
                    # Fallback to containing block if exact start doesn't map
                    blocks = model.getCodeBlocksContaining(src_addr, monitor)
                    for b in blocks:
                        if b is not None and b not in reachable:
                            work.append(b)
                    continue
                if src_blk is not None and src_blk not in reachable:
                    work.append(src_blk)

            # 2) Inter-procedural step: add blocks of all call-sites of the containing function
            try:
                start_addr = blk.getFirstStartAddress()
                func = fm.getFunctionContaining(start_addr)
            except Exception:
                func = None

            if func is not None:
                entry = func.getEntryPoint()
                try:
                    entry_key = entry.toString()
                except Exception:
                    entry_key = None

                if entry is not None and entry_key is not None and entry_key not in processed_funcs:
                    processed_funcs.add(entry_key)
                    try:
                        refman = program.getReferenceManager()
                        refs = refman.getReferencesTo(entry)
                        for r in refs:
                            try:
                                if r.getReferenceType().isCall():
                                    from_addr = r.getFromAddress()
                                    cb = model.getCodeBlockAt(from_addr, monitor)
                                    if cb is None:
                                        cbs = model.getCodeBlocksContaining(from_addr, monitor)
                                        for b in cbs:
                                            if b is not None and b not in reachable:
                                                work.append(b)
                                    else:
                                        if cb not in reachable:
                                            work.append(cb)
                            except Exception:
                                continue
                    except Exception:
                        pass

        # Emit all start addresses of reachable blocks
        with open(out_path, "w") as out:
            for blk in reachable:
                try:
                    s = blk.getFirstStartAddress()
                    e = blk.getMaxAddress()
                    out.write(f"0x{str(s)} 0x{str(e)}\n")
                except Exception:
                    continue

if __name__ == "__main__":
    main()


