import sys
import json
import pyhidra
import os
from pathlib import Path
import shutil
import subprocess


def is_code_address(program, addr):
    """
    Checks if the given address points to code by verifying if there is an instruction
    or a function starting at that address.
    """
    listing = program.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit and isinstance(code_unit, Instruction):
        return True

    fm = program.getFunctionManager()
    func = fm.getFunctionAt(addr)
    if func is not None:
        return True

    return False


def extract_jump_tables(program):
    """
    Extract jump tables by looking for likely switch data symbols and verifying 
    that they point to code.
    """
    symbol_table = program.getSymbolTable()
    listing = program.getListing()

    jump_tables = []
    visited = set()

    # Adjust these indicators based on Ghidra conventions
    switch_name_indicators = ["switchD_", "switchdata", "switch__"]

    for symbol in symbol_table.getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.LABEL:
            symbol_name = symbol.getName().lower()
            if any(indicator in symbol_name for indicator in switch_name_indicators):
                base_address = symbol.getAddress()
                
                if base_address in visited:
                    continue
                visited.add(base_address)

                print(f"Processing jump table at {base_address}")

                table_entries = []
                current_addr = base_address
                max_table_entries = 512  # Increased for larger tables
                invalid_entries = 0

                for _ in range(max_table_entries):
                    data = listing.getDataAt(current_addr)
                    if data is None:
                        break

                    if not data.isPointer():
                        # Non-pointer data indicates the end of the jump table
                        invalid_entries += 1
                        if invalid_entries > 3:  # Allow up to 3 invalid entries
                            break
                        current_addr = current_addr.add(8)  # Move to next potential entry
                        continue

                    destination = data.getValue()
                    if not destination or not isinstance(destination, Address):
                        break

                    if is_code_address(program, destination):
                        dest_symbol = symbol_table.getPrimarySymbol(destination)
                        label_name = dest_symbol.getName() if dest_symbol else "Unknown"

                        table_entries.append({
                            "label": label_name,
                            "destination": f"{destination.getOffset():08x}",
                            "input_address": f"{current_addr.getOffset():08x}"
                        })
                        invalid_entries = 0  # Reset invalid entries counter
                    else:
                        invalid_entries += 1
                        if invalid_entries > 3:
                            break

                    current_addr = current_addr.add(data.getLength())

                if len(table_entries) > 1:
                    jump_table = {
                        "switch_id": symbol.getName(),
                        "table_address": f"{base_address.getOffset():08x}",
                        "cases": table_entries
                    }
                    jump_tables.append(jump_table)

    return jump_tables


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_jump_tables.py /path/to/binary")
        sys.exit(1)

    binary_path = sys.argv[1]
    # Normalize paths and expected project layout
    bin_path = Path(os.path.abspath(binary_path))
    bin_parent = bin_path.parent
    bin_name = bin_path.name
    project_name = f"{bin_name}_ghidra"
    project_dir = bin_parent / project_name
    parent_gpr = bin_parent / f"{project_name}.gpr"
    parent_rep = bin_parent / f"{project_name}.rep"
    sub_gpr = project_dir / f"{project_name}.gpr"
    sub_rep = project_dir / f"{project_name}.rep"

    # Case 1: Headless created .gpr/.rep in parent; move into subdir expected by Pyhidra
    try:
        if parent_gpr.exists() and not sub_gpr.exists():
            project_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(parent_gpr), str(sub_gpr))
            if parent_rep.exists() and not sub_rep.exists():
                shutil.move(str(parent_rep), str(sub_rep))
    except Exception as move_err:
        print(f"Warning: could not relocate existing Ghidra project files: {move_err}")

    # Case 2: Avoid empty pre-created directory causing NotFoundException
    try:
        if project_dir.exists():
            try:
                contents = list(project_dir.iterdir())
            except Exception:
                contents = []
            if len(contents) == 0:
                project_dir.rmdir()
    except Exception:
        pass

    try:
        pyhidra.start()
    except Exception as init_error:
        print(f"Pyhidra initialization error: {init_error}")
        sys.exit(1)

    # Expose Ghidra classes at module/global scope for helper functions
    global SymbolType, Address, Instruction, PointerDataType
    from ghidra.program.model.symbol import SymbolType
    from ghidra.program.model.address import Address
    from ghidra.program.model.listing import Instruction
    from ghidra.program.model.data import PointerDataType

    try:
        # Prefer explicit project location/name to avoid ambiguous defaults
        with pyhidra.open_program(
            str(bin_path),
            project_location=str(bin_parent),
            project_name=project_name,
            analyze=True,
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            jump_tables = extract_jump_tables(program)

            # Ensure results directory exists
            output_dir = "results"
            os.makedirs(output_dir, exist_ok=True)

            # Set new output file path
            output_file = os.path.join(output_dir, "jump_tables.json")

            with open(output_file, "w") as f:
                json.dump(jump_tables, f, indent=4)

            print(f"Jump tables saved to {output_file}")
            print(f"Total jump tables found: {len(jump_tables)}")

    except Exception as e:
        # Fallback: attempt headless project creation, then retry once
        msg = str(e)
        print(f"Error processing binary: {msg}")
        need_headless = (
            "Project marker file not found" in msg
            or "NotFoundException" in msg
        )
        if need_headless:
            try:
                ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
                headless = os.path.join(ghidra_dir, "support", "analyzeHeadless")
                if not os.path.exists(headless):
                    raise RuntimeError(f"analyzeHeadless not found at {headless}")
                # Create parent-level project, then relocate into subdir if needed
                cmd = [
                    headless,
                    str(bin_parent),
                    project_name,
                    "-import",
                    str(bin_path),
                    "-overwrite",
                    "-noanalysis",
                ]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                # Move created artifacts into subdir for Pyhidra's expected layout
                if parent_gpr.exists():
                    project_dir.mkdir(parents=True, exist_ok=True)
                    if not sub_gpr.exists():
                        shutil.move(str(parent_gpr), str(sub_gpr))
                    if parent_rep.exists() and not sub_rep.exists():
                        shutil.move(str(parent_rep), str(sub_rep))
                # Retry once with explicit project
                with pyhidra.open_program(
                    str(bin_path),
                    project_location=str(bin_parent),
                    project_name=project_name,
                    analyze=True,
                ) as flat_api:
                    program = flat_api.getCurrentProgram()
                    jump_tables = extract_jump_tables(program)

                    output_dir = "results"
                    os.makedirs(output_dir, exist_ok=True)
                    output_file = os.path.join(output_dir, "jump_tables.json")
                    with open(output_file, "w") as f:
                        json.dump(jump_tables, f, indent=4)
                    print(f"Jump tables saved to {output_file}")
                    print(f"Total jump tables found: {len(jump_tables)}")
            except Exception as e2:
                print(f"Fallback headless creation failed: {e2}")
                import traceback
                traceback.print_exc()
        else:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()

# Example of expected output:
# [
#     {
#         "switch_id": "switchD_00468880::switchdataD_004df620",
#         "table_address": "004df620",
#         "cases": [
#             {
#                 "label": "switchD_00468880::caseD_14",
#                 "destination": "004688d7",
#                 "input_address": "004df658"
#             },
#             {
#                 "label": "switchD_00468880::caseD_12",
#                 "destination": "00468842",
#                 "input_address": "004df660"
#             },
#             {
#                 "label": "switchD_00468880::caseD_12",
#                 "destination": "00468842",
#                 "input_address": "004df668"
#             }
#         ]
#     }
# ]
