# find_panic_xrefs.py
# Used in main.rs by the get_cross_references function to find cross-references to panic functions.
import sys
import pyhidra
import os
import shutil

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_panic_xrefs.py /path/to/binary")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    project_name = os.path.basename(binary_path)  # Use binary name as project name
    project_dir = os.path.join(os.getcwd(), project_name + ".rep")  # Default Ghidra project directory

    # Delete the project if it already exists
    if os.path.exists(project_dir):
        print(f"[INFO] Deleting existing Ghidra project: {project_dir}")
        shutil.rmtree(project_dir, ignore_errors=True)

    print(f"[INFO] Starting Pyhidra for {binary_path}")

    # Start Pyhidra
    pyhidra.start()

    from ghidra.program.model.symbol import RefType
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    # Open the binary with Pyhidra
    with pyhidra.open_program(binary_path, analyze=True) as flat_api:
        # Get the Program object
        program = flat_api.getCurrentProgram()

        # Get the FunctionManager
        function_manager = program.getFunctionManager()

        # Addresses (as strings) to seed reverse search: include call sites and containing block starts
        xref_addresses = set()

        # Prepare basic block model to resolve containing block starts
        model = BasicBlockModel(program)
        monitor = ConsoleTaskMonitor()

        # Patterns for panic-like functions (case-insensitive)
        panic_substrings = [
            "panic",
            "nilpanic",
            "panicindex",
            "panicbounds",
            "panicmem",
            "panicdivide",
            "panicslice",
            "throw",
            "fatal",
            "abort",
            "trap",
            "tinygo_longjmp",
            "lookuppanic",
            "Panic",
        ]

        # Iterate over all functions in the program
        function_iterator = function_manager.getFunctions(True)
        while function_iterator.hasNext():
            function = function_iterator.next()
            function_name = function.getName()

            # Convert function name to lowercase for case-insensitive comparison
            function_name_lower = function_name.lower()

            # Match if any panic-like substring appears in the symbol name
            if any(pat in function_name_lower for pat in panic_substrings):
                # Always include the function entry point as a seed (even if no xrefs)
                entry = function.getEntryPoint()
                if entry is not None:
                    xref_addresses.add("0x{}".format(entry.toString()))

                # Get references to this function
                references = program.getReferenceManager().getReferencesTo(function.getEntryPoint())

                for ref in references:
                    # We are interested in code references that are calls
                    if ref.getReferenceType().isCall():
                        from_address = ref.getFromAddress()
                        # Add the raw call site
                        xref_addresses.add("0x{}".format(from_address.toString()))
                        # Also add the start of the containing basic block
                        blk = model.getCodeBlockAt(from_address, monitor)
                        if blk is None:
                            # Fallback: blocks containing the address
                            blocks = model.getCodeBlocksContaining(from_address, monitor)
                            for b in blocks:
                                if b is not None:
                                    xref_addresses.add("0x{}".format(b.getFirstStartAddress().toString()))
                        else:
                            xref_addresses.add("0x{}".format(blk.getFirstStartAddress().toString()))

        # Ensure results directory exists
        results_dir = "results"
        os.makedirs(results_dir, exist_ok=True)

        # Write the addresses to a file in the results directory
        output_file = os.path.join(results_dir, "xref_addresses.txt")
        with open(output_file, "w") as file:
            for addr in sorted(xref_addresses):
                file.write(f"{addr}\n")

        print(f"[INFO] Xref analysis completed. Results saved to {output_file}")

if __name__ == "__main__":
    main()
