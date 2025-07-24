use core::panic;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use parser::parser::{Inst, Opcode};
use z3::{
    ast::{Int, BV},
    Config, Context,
};
use zorya::concolic::{ConcolicVar, Logger};
use zorya::executor::{ConcolicExecutor, SymbolicVar};
use zorya::state::evaluate_z3::{evaluate_args_z3, get_os_args_address};
use zorya::state::function_signatures::{
    load_function_args_map, load_go_function_args_map, precompute_function_signatures_via_ghidra,
    GoFunctionArg,
};
use zorya::state::memory_x86_64::MemoryValue;
use zorya::target_info::GLOBAL_TARGET_INFO;
use zorya::concolic::symbolic_initialization::{
    initialize_single_register_argument, initialize_single_register_slice,
    initialize_slice_argument, initialize_string_argument, initialize_slice_memory_contents
};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

/// Functions we want to completely ignore / skip execution in the TinyGo runtime.
const IGNORED_TINYGO_FUNCS: &[&str] = &[
    // "runtime.markRoots",
    // "runtime.alloc",
    // "runtime.markStack",
    // "runtime.runGC",
    // "runtime.markRoot",
    // "runtime.findGlobals",
];

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::new();
    let context = Context::new(&config);
    let logger = Logger::new("results/execution_log.txt", false).expect("Failed to create logger"); // get the instruction handling detailed log, log to the file only
    let trace_logger =
        Logger::new("results/execution_trace.txt", true).expect("Failed to create trace logger"); // get the trace of the executed symbols names, log to the file and stdout
    let mut executor: ConcolicExecutor<'_> =
        ConcolicExecutor::new(&context, logger.clone(), trace_logger.clone())
            .map_err(|e| e.to_string())?;

    log!(
        executor.state.logger,
        "Configuration and context have been initialized."
    );

    let (binary_path, pcode_file_path, main_program_addr) = {
        let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
        log!(executor.state.logger, "Acquired target information.");
        (
            target_info.binary_path.clone(),
            target_info.pcode_file_path.clone(),
            target_info.main_program_addr.clone(),
        )
    };
    log!(executor.state.logger, "Binary path: {}", binary_path);
    let pcode_file_path_str = pcode_file_path
        .to_str()
        .expect("The file path contains invalid Unicode characters.");

    // Adapt scenaris according to the chosen mode in the command
    let mode = env::var("MODE").expect("MODE environment variable is not set");
    let arguments = env::var("ARGS").expect("MODE environment variable is not set");
    let source_lang =
        std::env::var("SOURCE_LANG").expect("SOURCE_LANG environment variable is not set");

    // Populate the symbol table
    let elf_data = fs::read(binary_path.clone())?;
    executor.populate_symbol_table(&elf_data)?;
    log!(
        executor.state.logger,
        "The symbols table has been populated."
    );

    log!(
        executor.state.logger,
        "Path to the p-code file: {}",
        pcode_file_path_str
    );
    // Preprocess the p-code file to get a map of addresses to instructions
    let instructions_map = preprocess_pcode_file(pcode_file_path_str, &mut executor)
        .expect("Failed to preprocess the p-code file.");

    // Get the tables of cross references of potential panics in the programs (for bug detetcion)
    get_cross_references(&binary_path)?;

    let start_address = u64::from_str_radix(&main_program_addr.trim_start_matches("0x"), 16)
        .expect("The format of the main program address is invalid.");

    if mode == "function" {
        log!(
            executor.state.logger,
            "Mode is 'function'. Adapting the context..."
        );
        log!(
            executor.state.logger,
            "Start address is {:?}",
            format!("{:x}", start_address)
        );

        // Making the difference between Go and the rest because Ghidra's ABI has issues with Go
        // Both methods create a file called function_signature.json in the results directory
        let function_args_map = match source_lang.to_lowercase().as_str() {
            // --- C / C++ branch ---
            "c" | "c++" => {
                log!(
                    executor.state.logger,
                    "Precomputing function signatures using Ghidra headless…"
                );
                precompute_function_signatures_via_ghidra(&binary_path, &mut executor)?;

                log!(executor.state.logger, "Loading raw C signatures…");
                // now returns HashMap<u64, (String, Vec<(arg, Vec<reg>, typ)>)>
                let raw = load_function_args_map();
                log!(
                    executor.state.logger,
                    "Loaded {} raw C signatures.",
                    raw.len()
                );

                let mut unified = HashMap::new();
                let cpu = executor.state.cpu_state.lock().unwrap();

                for (addr, (fn_name, raw_args)) in raw {
                    let mut args: Vec<(String, String, String)> = Vec::new();

                    for (arg_name, regs, typ) in raw_args {
                        // we expect at least one register name
                        if regs.is_empty() {
                            continue;
                        }

                        // keep single-register as is, multi-register joined with “,” (like we do for Go)
                        let reg_repr = if regs.len() == 1 {
                            regs[0].clone()
                        } else {
                            regs.join(",")
                        };

                        // optional sanity-check against CPU register map
                        let reg_ok = regs
                            .iter()
                            .all(|r| cpu.resolve_offset_from_register_name(r).is_some());
                        if !reg_ok {
                            log!(
                                executor.state.logger,
                                "WARNING: unknown register(s) {:?} for arg '{}' @0x{:x}",
                                regs,
                                arg_name,
                                addr
                            );
                        }

                        args.push((arg_name, reg_repr, typ));
                    }
                    unified.insert(addr, (fn_name, args));
                }

                log!(
                    executor.state.logger,
                    "Unified {} C signatures.",
                    unified.len()
                );
                unified
            }
            // --- Go branch ---
            "go" => {
                log!(
                    executor.state.logger,
                    "Calling get-funct-arg-types to extract Go function info..."
                );
                let go_bin = format!(
                    "{}/scripts/get-funct-arg-types/main",
                    env::var("ZORYA_DIR")?
                );
                let func_signatures_path = "results/function_signatures_go.json";
                let out = std::process::Command::new(&go_bin)
                    .arg(&binary_path)
                    .arg(func_signatures_path)
                    .output()?;
                if !out.status.success() {
                    return Err(format!(
                        "go script failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )
                    .into());
                }

                log!(
                    executor.state.logger,
                    "Loading Go signatures from {}...",
                    func_signatures_path
                );

                // Read and parse the Go JSON file directly
                let file = std::fs::File::open(func_signatures_path)
                    .map_err(|e| format!("Failed to open {}: {}", func_signatures_path, e))?;
                let reader = std::io::BufReader::new(file);
                let functions: Vec<GoFunctionArg> =
                    serde_json::from_reader(reader).map_err(|e| {
                        format!("Failed to parse JSON from {}: {}", func_signatures_path, e)
                    })?;

                log!(
                    executor.state.logger,
                    "Loaded {} functions from JSON.",
                    functions.len()
                );

                // Build the final HashMap directly
                let mut go_signatures = HashMap::new();
                for func in functions {
                    // Parse hex address
                    if let Ok(addr) = u64::from_str_radix(func.address.trim_start_matches("0x"), 16)
                    {
                        let mut args = Vec::new();
                        for arg in func.arguments {
                            let reg_list = arg.registers.join(",");
                            args.push((arg.name, reg_list, arg.arg_type));
                        }
                        go_signatures.insert(addr, (func.name, args));
                    } else {
                        log!(
                            executor.state.logger,
                            "Warning: Failed to parse address {} for function {}",
                            func.address,
                            func.name
                        );
                    }
                }

                log!(
                    executor.state.logger,
                    "Processed {} Go signatures.",
                    go_signatures.len()
                );
                go_signatures
            }
            // --- unsupported ---
            other => {
                log!(executor.state.logger, "Unsupported language: {}", other);
                return Err("Unsupported source language".into());
            }
        };

        // In function mode: initialize symbolic arguments
        if let Some((_, args)) = function_args_map.get(&start_address) {
            log!(
                executor.state.logger,
                "Found {} arguments for function at 0x{:x}",
                args.len(),
                start_address
            );

            let mut concrete_values_of_args = Vec::new();

            // Phase 1: Initialize slice/string/argument structures
            log!(
                executor.state.logger,
                "=== PHASE 1: Initializing argument structures ==="
            );

            for (arg_name, reg_name, arg_type) in args {
                log!(
                    executor.state.logger,
                    "Assigning symbolic var '{}' to register '{}' of type {}",
                    arg_name,
                    reg_name,
                    arg_type
                );

                // Special handling for Go strings: two registers (ptr, len)
                if arg_type == "string" && reg_name.contains(',') {
                    let regs: Vec<&str> = reg_name.split(',').collect();
                    if regs.len() == 2 {
                        initialize_string_argument(
                            arg_name,
                            &regs,
                            &mut concrete_values_of_args,
                            &mut executor,
                        );
                    } else {
                        log!(
                            executor.state.logger,
                            "WARNING: unexpected registers '{}' for string '{}', skipping",
                            reg_name,
                            arg_name
                        );
                    }
                    continue;
                }

                // Handle slice types (including multi-dimensional slices like [][32]byte)
                if arg_type.starts_with("[]") {
                    if reg_name.contains(',') {
                        // Multi-register slice (ptr, len, cap)
                        let regs: Vec<&str> = reg_name.split(',').collect();
                        initialize_slice_argument(
                            arg_name,
                            arg_type,
                            &regs,
                            &mut concrete_values_of_args,
                            &mut executor,
                        );
                    } else {
                        // Single register slice (just pointer)
                        initialize_single_register_slice(
                            arg_name,
                            arg_type,
                            reg_name,
                            &mut concrete_values_of_args,
                            &mut executor,
                        );
                    }
                    continue;
                }

                // General case: single-register arguments
                initialize_single_register_argument(
                    arg_name,
                    reg_name,
                    arg_type,
                    &mut concrete_values_of_args,
                    &mut executor,
                );
            }

            // Phase 2: Initialize memory contents pointed to by slices
            log!(
                executor.state.logger,
                "=== PHASE 2: Initializing slice memory contents ==="
            );
            
            let slice_args: Vec<_> = args.iter()
                .filter(|(_, _, arg_type)| arg_type.starts_with("[]"))
                .collect();
            
            if !slice_args.is_empty() {
                log!(
                    executor.state.logger,
                    "Found {} slice arguments to initialize memory for",
                    slice_args.len()
                );
                
                // Convert to the format expected by initialize_slice_memory_contents
                let slice_args_owned: Vec<(String, String, String)> = slice_args
                    .into_iter()
                    .map(|(name, reg, typ)| (name.clone(), reg.clone(), typ.clone()))
                    .collect();
                    
                initialize_slice_memory_contents(&mut executor, &slice_args_owned);
            } else {
                log!(
                    executor.state.logger,
                    "No slice arguments found, skipping memory initialization"
                );
            }

            log!(
                executor.state.logger,
                "=== INITIALIZATION COMPLETE: {} total arguments processed ===",
                args.len()
            );

        } else {
            log!(
                executor.state.logger,
                "No signature at start_address 0x{:x}, skipping symbolic init",
                start_address
            );
        }
    } else if mode == "start" || mode == "main" {
        let os_args_addr = get_os_args_address(&binary_path)?;
        log!(
            executor.state.logger,
            "os.Args slice address: 0x{:x}",
            os_args_addr
        );
        initialize_symbolic_part_args(&mut executor, os_args_addr)?;
        log!(executor.state.logger, "Updating argc and argv on the stack");
        update_argc_argv(&mut executor, &arguments)?;
    } else {
        log!(executor.state.logger, "[WARNING] Custom mode used : Be aware that the arguments of the binary are not 'fresh symbolic' in that mode, the concolic exploration might not work correctly.");
    }

    // *****************************
    // CORE COMMAND
    println!("**************************************************************************");
    println!("THE CONCOLIC EXECUTION OF THE BINARY HAS STARTED!");
    println!("Find the logs in results/execution_log.txt and results/execution_trace.txt");
    println!("**************************************************************************");
    execute_instructions_from(
        &mut executor,
        start_address,
        &instructions_map,
        &binary_path,
    );
    // *****************************

    Ok(())
}

// Function to execute the instructions from the map of addresses to instructions
fn execute_instructions_from(
    executor: &mut ConcolicExecutor,
    start_address: u64,
    instructions_map: &BTreeMap<u64, Vec<Inst>>,
    binary_path: &str,
) {
    let mut current_rip = start_address;
    let mut local_line_number: i64 = 0; // Index of the current instruction within the block
    let end_address: u64 = 0x0; //no specific end address

    // For debugging
    //let address: u64 = 0x7fffffffe4b0;
    //let range = 0x8;

    log!(
        executor.state.logger,
        "Logging the addresses of the XREFs of Panic functions..."
    );
    // Read the panic addresses from the file once before the main loop
    let panic_addresses = read_panic_addresses(executor, "xref_addresses.txt")
        .expect("Failed to read panic addresses from results directory");

    // Convert panic addresses to Z3 Ints once
    let panic_address_ints: Vec<Int> = panic_addresses
        .iter()
        .map(|&addr| Int::from_u64(executor.context, addr))
        .collect();

    log!(
        executor.state.logger,
        "Beginning execution from address: 0x{:x}",
        start_address
    );

    // Set RIP to start_address once before entering the loop
    {
        let mut cpu_state_guard = executor.state.cpu_state.lock().unwrap();
        cpu_state_guard
            .set_register_value_by_offset(
                0x288,
                ConcolicVar::new_concrete_and_symbolic_int(
                    current_rip,
                    SymbolicVar::new_int(current_rip.try_into().unwrap(), executor.context, 64)
                        .to_bv(executor.context),
                    executor.context,
                ),
                64,
            )
            .map_err(|e| e.to_string())
            .unwrap();
    }

    // Load the function arguments map
    log!(executor.state.logger, "Loading function arguments map...");
    let lang = env::var("SOURCE_LANG").expect("SOURCE_LANG environment variable is not set");

    let function_args_map = if lang == "go" {
        log!(
            executor.state.logger,
            "Loading Go function arguments map..."
        );
        let function_args_map =
            load_go_function_args_map(binary_path, executor).unwrap_or_else(|e| {
                log!(
                    executor.state.logger,
                    "Error loading Go function arguments map: {}",
                    e
                );
                HashMap::new() // Return an empty map if loading fails
            });
        function_args_map
    } else {
        log!(executor.state.logger, "Loading C function arguments map...");
        let function_args_map = load_function_args_map();
        function_args_map
    };

    while let Some(instructions) = instructions_map.get(&current_rip) {
        if current_rip == end_address {
            log!(
                executor.state.logger,
                "END ADDRESS 0x{:x} REACHED, STOP THE EXECUTION",
                end_address
            );
            break; // Stop execution if end address is reached
        }

        log!(
            executor.state.logger,
            "*******************************************"
        );
        log!(
            executor.state.logger,
            "EXECUTING INSTRUCTIONS AT ADDRESS: 0x{:x}",
            current_rip
        );
        log!(
            executor.state.logger,
            "*******************************************"
        );

        let current_rip_hex = format!("{:x}", current_rip);

        // This block is only to get data about the execution in results/execution_trace.txt
        if let Some(symbol_name) = executor.symbol_table.get(&current_rip_hex) {
            if let Some((_, args)) = function_args_map.get(&current_rip) {
                let mut arg_values = Vec::new();
                let cpu = executor.state.cpu_state.lock().unwrap();
                for (arg_name, reg_names, _arg_type) in args {
                    for reg_name in reg_names {
                        if let Some(offset) = cpu.resolve_offset_from_register_name(reg_name) {
                            if let Some(value) = cpu.get_register_by_offset(offset, 64) {
                                arg_values.push(format!(
                                    "{}=0x{:x} (reg={} @0x{:x})",
                                    arg_name, value.concrete, reg_name, offset
                                ));
                            }
                        }
                    }
                }
                if !arg_values.is_empty() {
                    let log_string = format!(
                        "Address: {:x}, Symbol: {} -> {}",
                        current_rip,
                        symbol_name,
                        arg_values.join(", ")
                    );
                    log!(executor.trace_logger, "{}", log_string);
                }
            } else {
                log!(
                    executor.trace_logger,
                    "Address: {:x}, Symbol: {}",
                    current_rip,
                    symbol_name
                );
            }
        }

        // Inner loop: process each instruction in the current block.
        let mut end_of_block = false;

        while local_line_number < instructions.len().try_into().unwrap() && !end_of_block {
            // Calculate the potential next address taken by RIP, for the purpose of updating the symbolic part of CBRANCH and the speculative exploration
            let (next_addr_in_map, _) = instructions_map.range((current_rip + 1)..).next().unwrap();

            let inst = &instructions[local_line_number as usize];
            log!(
                executor.state.logger,
                "-------> Processing instruction at index: {}, {:?}",
                local_line_number,
                inst
            );

            // If this is a branch-type instruction, do symbolic checks.
            if inst.opcode == Opcode::CBranch {
                log!(
                    executor.state.logger,
                    " !!! Branch-type instruction detected: entrying symbolic checks..."
                );
                let branch_target_varnode = inst.inputs[0].clone();
                let branch_target_address = executor
                    .from_varnode_var_to_branch_address(&branch_target_varnode)
                    .map_err(|e| e.to_string())
                    .unwrap();
                let conditional_flag = inst.inputs[1].clone();
                let conditional_flag = executor
                    .varnode_to_concolic(&conditional_flag)
                    .map_err(|e| e.to_string())
                    .unwrap()
                    .to_concolic_var()
                    .unwrap();
                let conditional_flag_u64 = conditional_flag.concrete.to_u64();

                let address_of_negated_path_exploration = if conditional_flag_u64 == 0 {
                    // We want to explore the branch that is not taken
                    log!(executor.state.logger, ">>> Branch condition is false (0x{:x}), performing the speculative exploration on the other branch...", conditional_flag_u64);
                    let addr = branch_target_address;
                    addr
                } else {
                    // We want to explore the branch that is taken
                    log!(executor.state.logger, ">>> Branch condition is true (0x{:x}), performing the speculative exploration on the other branch...", conditional_flag_u64);
                    let addr = next_addr_in_map;
                    *addr
                };

                // This flag indicates whether we want to explore th negated (not taken) path to explor eit symbolically
                let negate_path_flag = std::env::var("NEGATE_PATH_FLAG")
                    .expect("NEGATE_PATH_FLAG environment variable is not set");

                // This block is for find fast a SAT state for the negated path exploration
                if negate_path_flag == "true" {
                    // broken-calculator 22f068 // omni-vuln4 0x2300b7 0x2300d7// crashme: 0x22b21a
                    if current_rip == 0x2300d7 {
                        log!(
                            executor.state.logger,
                            ">>> Evaluating arguments for the negated path exploration."
                        );
                        evaluate_args_z3(
                            executor,
                            inst,
                            address_of_negated_path_exploration,
                            Some(conditional_flag.clone()),
                        )
                        .unwrap_or_else(|e| {
                            log!(
                                executor.state.logger,
                                "Error evaluating arguments for branch at 0x{:x}: {}",
                                branch_target_address,
                                e
                            );
                        });
                    }
                } else {
                    log!(executor.state.logger, "NEGATE_PATH_FLAG is set to false, so the execution doesn't explore the negated path.");
                }

                // if panic_address_ints.contains(&z3::ast::Int::from_u64(
                //     executor.context,
                //     branch_target_address,
                // )) {
                //     log!(
                //         executor.state.logger,
                //         "Potential branching to a panic function at 0x{:x}",
                //         branch_target_address
                //     );
                //     evaluate_args_z3(
                //         executor,
                //         inst,
                //         binary_path,
                //         address_of_negated_path_exploration,
                //         conditional_flag,
                //     )
                //     .unwrap_or_else(|e| {
                //         log!(
                //             executor.state.logger,
                //             "Error evaluating arguments for branch at 0x{:x}: {}",
                //             branch_target_address,
                //             e
                //         );
                //     });
                // }
            }

            // Calculate the potential next address taken by RIP, for the purpose of updating the symbolic part of CBRANCH
            let (next_addr_in_map, _) = instructions_map.range((current_rip + 1)..).next().unwrap();

            // MAIN PART OF THE CODE
            // Execute the instruction and handle errors
            match executor.execute_instruction(
                inst.clone(),
                current_rip,
                *next_addr_in_map,
                instructions_map,
            ) {
                Ok(_) => {
                    // Check if the process has terminated
                    if executor.state.is_terminated {
                        log!(
                            executor.state.logger,
                            "Execution terminated with status: {:?}",
                            executor.state.exit_status
                        );
                        return; // Exit the function as execution has terminated
                    }
                }
                Err(e) => {
                    log!(executor.state.logger, "Execution error: {}", e);
                    if executor.state.is_terminated {
                        log!(
                            executor.state.logger,
                            "Process terminated via syscall with exit status: {:?}",
                            executor.state.exit_status
                        );
                        return; // Exit the function as execution has terminated
                    } else {
                        // Handle other errors as needed
                        log!(executor.state.logger, "Unhandled execution error: {}", e);
                        return; // Exit the function or handle the error appropriately
                    }
                }
            }

            // For debugging
            //log!(executor.state.logger, "Printing memory content around 0x{:x} with range 0x{:x}", address, range);
            //executor.state.print_memory_content(address, range);
            let register0x0 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x0, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x0 - RAX is {:x} and symbolic {:?}",
                register0x0.concrete,
                register0x0.symbolic.simplify()
            );
            let register0x8 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x8, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x8 - RCX is {:x} and symbolic {:?}",
                register0x8.concrete,
                register0x8.symbolic.simplify()
            );
            let register0x10 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x10, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x10 - RDX is {:x} and symbolic {:?}",
                register0x10.concrete,
                register0x10.symbolic.simplify()
            );
            let register0x18 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x18, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x18 - RBX is {:x} and symbolic {:?}",
                register0x18.concrete,
                register0x18.symbolic.simplify()
            );
            let register0x20 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x20, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x20 - RSP is {:x} and symbolic {:?}",
                register0x20.concrete,
                register0x20.symbolic.simplify()
            );
            let register0x28 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x28, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x28 - RBP is {:x} and symbolic {:?}",
                register0x28.concrete,
                register0x28.symbolic.simplify()
            );
            let register0x30 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x30, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x30 - RSI is {:x} and symbolic {:?}",
                register0x30.concrete,
                register0x30.symbolic.simplify()
            );
            let register0x38 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x38, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x38 - RDI is {:x} and symbolic {:?}",
                register0x38.concrete,
                register0x38.symbolic.simplify()
            );
            let register0x80 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x80, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x80 - R8 is {:x} and symbolic {:?}",
                register0x80.concrete,
                register0x80.symbolic.simplify()
            );
            let register0x88 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x88, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x88 - R9 is {:x} and symbolic {:?}",
                register0x88.concrete,
                register0x88.symbolic.simplify()
            );
            let register0x90 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x90, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x90 - R10 is {:x} and symbolic {:?}",
                register0x90.concrete,
                register0x90.symbolic.simplify()
            );
            let register0x98 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x98, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x98 - R11 is {:x} and symbolic {:?}",
                register0x98.concrete,
                register0x98.symbolic.simplify()
            );
            let register0xa0 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0xa0, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0xa0 - R12 is {:x} and symbolic {:?}",
                register0xa0.concrete,
                register0xa0.symbolic.simplify()
            );
            let register0xa8 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0xa8, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0xa8 - R13 is {:x} and symbolic {:?}",
                register0xa8.concrete,
                register0xa8.symbolic.simplify()
            );
            let register0xb0 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0xb0, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0xb0 - R14 is {:x} and symbolic {:?}",
                register0xb0.concrete,
                register0xb0.symbolic.simplify()
            );
            let register0xb8 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0xb8, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0xb8 - R15 is {:x} and symbolic {:?}",
                register0xb8.concrete,
                register0xb8.symbolic.simplify()
            );
            let register0x1200 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x1200, 256)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x1200 - YMM0 is {:x}, i.e. {:?}",
                register0x1200.concrete,
                register0x1200.concrete
            );
            let register0x1220 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x1220, 256)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x1220 - YMM1 is {:x}, i.e. {:?}",
                register0x1220.concrete,
                register0x1220.concrete
            );
            let register0x200 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x200, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x200 - CF is {:x} and symbolic {:?}",
                register0x200.concrete,
                register0x200.symbolic.simplify()
            );
            let register0x202 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x202, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x202 - PF is {:x} and symbolic {:?}",
                register0x202.concrete,
                register0x202.symbolic.simplify()
            );
            let register0x206 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x206, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x206 - ZF is {:x} and symbolic {:?}",
                register0x206.concrete,
                register0x206.symbolic.simplify()
            );
            let register0x207 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x207, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x207 - SF is {:x} and symbolic {:?}",
                register0x207.concrete,
                register0x207.symbolic.simplify()
            );
            let register0x20b = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x20b, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x20b - OF is {:x} and symbolic {:?}",
                register0x20b.concrete,
                register0x20b.symbolic.simplify()
            );
            let register0x110 = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x110, 64)
                .unwrap();
            log!(
                executor.state.logger,
                "The value of register at offset 0x110 - FS_OFFSET is {:x}",
                register0x110.concrete
            );

            // Check if there's a requested jump within the current block
            if executor.pcode_internal_lines_to_be_jumped != 0 {
                let proposed_jump_target =
                    local_line_number + executor.pcode_internal_lines_to_be_jumped;
                // Ensure the jump target does not exceed the bounds of the instruction list
                let jump_target = if proposed_jump_target < instructions.len().try_into().unwrap() {
                    proposed_jump_target
                } else {
                    (instructions.len() - 1).try_into().unwrap() // set to the last valid index if the calculated target is too high
                };

                log!(
                    executor.state.logger,
                    "Jumping from line {} to line {}",
                    local_line_number,
                    jump_target
                );
                executor.pcode_internal_lines_to_be_jumped = 0; // Reset after handling
                local_line_number = jump_target; // Perform the jump within the block
                continue; // Move directly to the jump target line
            }

            // Update RIP if the instruction modifies it
            let possible_new_rip = executor
                .state
                .cpu_state
                .lock()
                .unwrap()
                .get_register_by_offset(0x288, 64)
                .unwrap()
                .get_concrete_value()
                .unwrap();
            let possible_new_rip_hex = format!("{:x}", possible_new_rip);
            log!(
                executor.state.logger,
                "Possible new RIP: 0x{:x}",
                possible_new_rip
            );
            log!(executor.state.logger, "Current RIP: 0x{:x}", current_rip);
            log!(
                executor.state.logger,
                "local_line_number: {}, instructions.len()-1: {}",
                local_line_number,
                (instructions.len() - 1) as i64
            );

            // Check if there is a new RIP to set, beeing aware that all the instructions in the block have been executed, except for case with CBranch
            // FYI, the two blocks can not be put in a function because the varibales that are modified are not global, TODO: optimize this
            if inst.opcode == Opcode::CBranch {
                if possible_new_rip != current_rip {
                    log!(
                        executor.state.logger,
                        "Control flow change detected, new RIP: 0x{:x}",
                        possible_new_rip
                    );
                    if let Some(symbol_name_potential_new_rip) =
                        executor.symbol_table.get(&possible_new_rip_hex)
                    {
                        // Found a symbol, check if it's blacklisted, etc.
                        if IGNORED_TINYGO_FUNCS.contains(&symbol_name_potential_new_rip.as_str()) {
                            log!(
                                executor.state.logger,
                                "Skipping function '{:?}' at 0x{:x} because it is blacklisted.",
                                symbol_name_potential_new_rip,
                                current_rip
                            );

                            // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                            let rsp_value_concrete = executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .get_register_by_offset(0x20, 64)
                                .unwrap()
                                .concrete
                                .to_u64();
                            let rsp_value_symbolic = executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .get_register_by_offset(0x20, 64)
                                .unwrap()
                                .symbolic
                                .to_bv(executor.context)
                                .clone();
                            let next_rsp_value_concrete = rsp_value_concrete + 8;
                            let next_rsp_value_symbolic =
                                rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                            let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(
                                next_rsp_value_concrete,
                                next_rsp_value_symbolic,
                                executor.context,
                            );
                            executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .set_register_value_by_offset(0x20, next_rsp_value, 64)
                                .expect("Failed to set register value by offset");

                            let (next_addr_in_map, _) =
                                instructions_map.range((current_rip + 1)..).next().unwrap();
                            current_rip = *next_addr_in_map;
                            local_line_number = 0; // Reset instruction index
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                        } else {
                            // Manage the case where the RIP update points beyond the current block
                            current_rip = possible_new_rip;
                            local_line_number = 0; // Reset instruction index for new RIP
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                        }
                    } else {
                        // Manage the case where the RIP update points beyond the current block
                        current_rip = possible_new_rip;
                        local_line_number = 0; // Reset instruction index for new RIP
                        end_of_block = true; // Indicate end of current block execution
                        log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                    }
                } else {
                    // Regular progression to the next instruction
                    local_line_number += 1;
                }
            } else {
                if possible_new_rip != current_rip
                    && local_line_number >= (instructions.len() - 1).try_into().unwrap()
                {
                    log!(
                        executor.state.logger,
                        "local_line_number: {}, instructions.len()-1: {}",
                        local_line_number,
                        (instructions.len() - 1) as i64
                    );
                    log!(
                        executor.state.logger,
                        "Control flow change detected, new RIP: 0x{:x}",
                        possible_new_rip
                    );
                    if let Some(symbol_name_potential_new_rip) =
                        executor.symbol_table.get(&possible_new_rip_hex)
                    {
                        // Found a symbol, check if it's blacklisted, etc.
                        if IGNORED_TINYGO_FUNCS.contains(&symbol_name_potential_new_rip.as_str()) {
                            log!(
                                executor.state.logger,
                                "Skipping function '{:?}' at 0x{:x} because it is blacklisted.",
                                symbol_name_potential_new_rip,
                                current_rip
                            );

                            // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                            let rsp_value_concrete = executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .get_register_by_offset(0x20, 64)
                                .unwrap()
                                .concrete
                                .to_u64();
                            let rsp_value_symbolic = executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .get_register_by_offset(0x20, 64)
                                .unwrap()
                                .symbolic
                                .to_bv(executor.context)
                                .clone();
                            let next_rsp_value_concrete = rsp_value_concrete + 8;
                            let next_rsp_value_symbolic =
                                rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                            let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(
                                next_rsp_value_concrete,
                                next_rsp_value_symbolic,
                                executor.context,
                            );
                            executor
                                .state
                                .cpu_state
                                .lock()
                                .unwrap()
                                .set_register_value_by_offset(0x20, next_rsp_value, 64)
                                .expect("Failed to set register value by offset");

                            let (next_addr_in_map, _) =
                                instructions_map.range((current_rip + 1)..).next().unwrap();
                            current_rip = *next_addr_in_map;
                            local_line_number = 0; // Reset instruction index
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                        } else {
                            // Manage the case where the RIP update points beyond the current block
                            current_rip = possible_new_rip;
                            local_line_number = 0; // Reset instruction index for new RIP
                            end_of_block = true; // Indicate end of current block execution
                            log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                        }
                    } else {
                        // Manage the case where the RIP update points beyond the current block
                        current_rip = possible_new_rip;
                        local_line_number = 0; // Reset instruction index for new RIP
                        end_of_block = true; // Indicate end of current block execution
                        log!(executor.state.logger, "Control flow change detected, switching execution to new address: 0x{:x}", current_rip);
                    }
                } else {
                    // Regular progression to the next instruction
                    local_line_number += 1;
                }
            }
        }

        // Reset for new block or continue execution at new RIP if set within the block
        if !end_of_block {
            if let Some((&next_rip, _)) = instructions_map.range((current_rip + 1)..).next() {
                let next_rip_hex = format!("{:x}", next_rip);
                if let Some(symbol_name_new_rip) = executor.symbol_table.get(&next_rip_hex) {
                    // Found a symbol, check if it's blacklisted
                    if IGNORED_TINYGO_FUNCS.contains(&symbol_name_new_rip.as_str()) {
                        log!(
                            executor.state.logger,
                            "Skipping function '{:?}' at 0x{:x} because it is blacklisted.",
                            symbol_name_new_rip,
                            current_rip
                        );

                        // When skipping a function, we need to update the stack pointer i.e. add 8 to RSP
                        let rsp_value_concrete = executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .get_register_by_offset(0x20, 64)
                            .unwrap()
                            .concrete
                            .to_u64();
                        let rsp_value_symbolic = executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .get_register_by_offset(0x20, 64)
                            .unwrap()
                            .symbolic
                            .to_bv(executor.context)
                            .clone();
                        let next_rsp_value_concrete = rsp_value_concrete + 8;
                        let next_rsp_value_symbolic =
                            rsp_value_symbolic.bvadd(&BV::from_u64(executor.context, 8, 64));
                        let next_rsp_value = ConcolicVar::new_concrete_and_symbolic_int(
                            next_rsp_value_concrete,
                            next_rsp_value_symbolic,
                            executor.context,
                        );
                        executor
                            .state
                            .cpu_state
                            .lock()
                            .unwrap()
                            .set_register_value_by_offset(0x20, next_rsp_value, 64)
                            .expect("Failed to set register value by offset");

                        let (next_addr_in_map, _) =
                            instructions_map.range((current_rip + 1)..).next().unwrap();
                        current_rip = *next_addr_in_map;
                        local_line_number = 0; // Reset instruction index
                        log!(executor.state.logger, "Jumping to 0x{:x}", next_addr_in_map);
                    }
                } else {
                    current_rip = next_rip;
                    local_line_number = 0; // Reset for new block

                    let current_rip_symbolic = executor
                        .state
                        .cpu_state
                        .lock()
                        .unwrap()
                        .get_register_by_offset(0x288, 64)
                        .unwrap()
                        .symbolic
                        .to_bv(executor.context)
                        .clone();

                    let next_rip_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                        next_rip,
                        current_rip_symbolic,
                        executor.context,
                    );
                    executor
                        .state
                        .cpu_state
                        .lock()
                        .unwrap()
                        .set_register_value_by_offset(0x288, next_rip_concolic, 64)
                        .expect("Failed to set register value by offset");

                    log!(
                        executor.state.logger,
                        "Moving to next address block: 0x{:x}",
                        next_rip
                    );
                }
            } else {
                log!(
                    executor.state.logger,
                    "No further instructions. Execution completed."
                );
                break; // Exit the loop if there are no more instructions
            }
        }
    }
}

// Function to initialize the symbolic part of os.Args
pub fn initialize_symbolic_part_args(
    executor: &mut ConcolicExecutor,
    args_addr: u64,
) -> Result<(), Box<dyn Error>> {
    // Read os.Args slice header (Pointer, Len, Cap)
    let mem = &executor.state.memory;
    let slice_ptr = mem
        .read_u64(args_addr, &mut executor.state.logger.clone())?
        .concrete
        .to_u64(); // Pointer to backing array
    let slice_len = mem
        .read_u64(args_addr + 8, &mut executor.state.logger.clone())?
        .concrete
        .to_u64(); // Length (number of arguments)
    let _slice_cap = mem
        .read_u64(args_addr + 16, &mut executor.state.logger.clone())?
        .concrete
        .to_u64(); // Capacity (not used)

    log!(
        executor.state.logger,
        "os.Args -> ptr=0x{:?}, len={}, cap={}",
        slice_ptr,
        slice_len,
        _slice_cap
    );

    // Iterate through each argument
    for i in 0..slice_len {
        let string_struct_addr = slice_ptr + i * 16; // Each Go string struct is 16 bytes
        let str_data_ptr = mem
            .read_u64(string_struct_addr, &mut executor.state.logger.clone())?
            .concrete
            .to_u64(); // Pointer to actual string data
        let str_data_len = mem
            .read_u64(string_struct_addr + 8, &mut executor.state.logger.clone())?
            .concrete
            .to_u64(); // Length of the string

        log!(
            executor.state.logger,
            "os.Args[{}] -> string ptr=0x{:x}, len={}",
            i,
            str_data_ptr,
            str_data_len
        );

        if str_data_ptr == 0 || str_data_len == 0 {
            // Possibly an empty argument? Just skip or handle specially
            continue;
        }

        // Read the actual string bytes
        let concrete_str_bytes = mem.read_bytes(str_data_ptr, str_data_len as usize)?;

        // Create fresh symbolic variables for each byte of this argument
        let mut fresh_symbolic = Vec::with_capacity(str_data_len as usize);
        for (byte_index, _) in concrete_str_bytes.iter().enumerate() {
            let bv_name = format!("arg{}_byte_{}", i, byte_index);
            let fresh_bv = BV::fresh_const(&executor.context, &bv_name, 8);
            fresh_symbolic.push(Some(Arc::new(fresh_bv)));
        }

        // Write those symbolic values back into memory
        mem.write_memory(str_data_ptr, &concrete_str_bytes, &fresh_symbolic)?;

        log!(
            executor.state.logger,
            "Successfully replaced os.Args[{}] with {} symbolic bytes.",
            i,
            str_data_len
        );
    }

    Ok(())
}

// Function to execute the Python script to get the cross references of potential panics in the programs (for bug detetcion)
fn get_cross_references(binary_path: &str) -> Result<(), Box<dyn Error>> {
    let zorya_dir = {
        let info = GLOBAL_TARGET_INFO.lock().unwrap();
        info.zorya_path.clone()
    };
    let python_script_path = zorya_dir.join("scripts").join("find_panic_xrefs.py");

    if !python_script_path.exists() {
        panic!("Python script not found at {:?}", python_script_path);
    }

    let output = Command::new("python3")
        .arg(python_script_path)
        .arg(binary_path)
        .output()
        .expect("Failed to execute Python script");

    // Check if the script ran successfully
    if !output.status.success() {
        eprintln!(
            "Python script error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(Box::from("Python script failed"));
    } else {
        println!("The cross references of panic functions have been executed collected!");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    // Ensure the file was created
    if !Path::new("results/xref_addresses.txt").exists() {
        panic!("xref_addresses.txt not found after running the Python script");
    }

    Ok(())
}

// Function to preprocess the p-code file and return a map of addresses to instructions
fn preprocess_pcode_file(
    path: &str,
    executor: &mut ConcolicExecutor,
) -> io::Result<BTreeMap<u64, Vec<Inst>>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut instructions_map = BTreeMap::new();
    let mut current_address: Option<u64> = None;

    log!(executor.state.logger, "Preprocessing the p-code file...");

    for line in reader.lines().filter_map(Result::ok) {
        if line.trim_start().starts_with("0x") {
            current_address = Some(u64::from_str_radix(&line.trim()[2..], 16).unwrap());
            instructions_map
                .entry(current_address.unwrap())
                .or_insert_with(Vec::new);
        } else {
            match line.parse::<Inst>() {
                Ok(inst) => {
                    if let Some(addr) = current_address {
                        instructions_map.get_mut(&addr).unwrap().push(inst);
                    } else {
                        log!(
                            executor.state.logger,
                            "Instruction found without a preceding address: {}",
                            line
                        );
                    }
                }
                Err(e) => {
                    log!(
                        executor.state.logger,
                        "Error parsing line at address 0x{:x}: {}\nError: {}",
                        current_address.unwrap_or(0),
                        line,
                        e
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "Error parsing line at address 0x{:x}: {}\nError: {}",
                            current_address.unwrap_or(0),
                            line,
                            e
                        ),
                    ));
                }
            }
        }
    }

    log!(executor.state.logger, "Completed preprocessing.\n");

    Ok(instructions_map)
}

// Function to read the panic addresses from the file
fn read_panic_addresses(executor: &mut ConcolicExecutor, filename: &str) -> io::Result<Vec<u64>> {
    // Get the base path from the environment variable
    let zorya_path_buf =
        PathBuf::from(env::var("ZORYA_DIR").expect("ZORYA_DIR environment variable is not set"));
    let zorya_path = zorya_path_buf.to_str().unwrap();

    // Construct the full path to the results directory
    let results_dir = Path::new(zorya_path).join("results");
    let full_path = results_dir.join(filename);

    // Ensure the file exists before trying to read it
    if !full_path.exists() {
        log!(
            executor.state.logger,
            "Error: File {:?} does not exist.",
            full_path
        );
        return Err(io::Error::new(io::ErrorKind::NotFound, "File not found"));
    }

    let file = File::open(&full_path)?;
    let reader = BufReader::new(file);
    let mut addresses = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.starts_with("0x") {
            match u64::from_str_radix(&line[2..], 16) {
                Ok(addr) => {
                    // log!(executor.state.logger, "Read panic address: 0x{:x}", addr);
                    addresses.push(addr);
                }
                Err(e) => {
                    log!(
                        executor.state.logger,
                        "Failed to parse address {}: {}",
                        line,
                        e
                    );
                }
            }
        }
    }
    Ok(addresses)
}

// Function to add the arguments of the target binary from the user's command
fn update_argc_argv(
    executor: &mut ConcolicExecutor,
    arguments: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cpu_state_guard = executor.state.cpu_state.lock().unwrap();

    if arguments == "none" {
        return Ok(());
    }

    // Parse arguments
    let args: Vec<String> = shell_words::split(arguments)?;
    let argc = args.len() as u64;

    log!(executor.state.logger, "Symbolically setting argc: {}", argc);

    let rsp = cpu_state_guard
        .get_register_by_offset(0x20, 64)
        .unwrap()
        .concrete
        .to_u64();

    // Write argc (concrete)
    executor.state.memory.write_value(
        rsp,
        &MemoryValue::new(argc, BV::from_u64(&executor.context, argc, 64), 64),
    )?;

    let argv_ptr_base = rsp + 8;
    let mut current_string_address = argv_ptr_base + (argc + 1) * 8;

    for (i, arg) in args.iter().enumerate() {
        // Write argv[i] pointer
        executor.state.memory.write_value(
            argv_ptr_base + (i as u64 * 8),
            &MemoryValue::new(
                current_string_address,
                BV::from_u64(&executor.context, current_string_address, 64),
                64,
            ),
        )?;

        log!(
            executor.state.logger,
            "Set argv[{}] pointer at: 0x{:x}",
            i,
            current_string_address
        );

        let arg_bytes = arg.as_bytes();

        for offset in 0..arg_bytes.len() {
            let sym_byte =
                BV::fresh_const(&executor.context, &format!("arg{}_byte{}", i, offset), 8);

            executor.state.memory.write_value(
                current_string_address + offset as u64,
                &MemoryValue::new(0, sym_byte.clone(), 8),
            )?;
        }

        // NULL terminator
        executor.state.memory.write_value(
            current_string_address + arg_bytes.len() as u64,
            &MemoryValue::new(0, BV::from_u64(&executor.context, 0, 8), 8),
        )?;

        current_string_address += ((arg_bytes.len() + 8) as u64) & !7; // align to 8 bytes
    }

    // Write argv NULL terminator pointer
    executor.state.memory.write_value(
        argv_ptr_base + argc * 8,
        &MemoryValue::new(0, BV::from_u64(executor.context, 0, 64), 64),
    )?;

    Ok(())
}

