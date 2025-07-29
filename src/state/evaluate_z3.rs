use std::io::Write;
use std::{error::Error, process::Command};

use super::explore_ast::explore_ast_for_panic;
use crate::concolic::{ConcolicExecutor, ConcolicVar, Logger, SymbolicVar};
use crate::state::simplify_z3::add_constraints_from_vector;
use crate::target_info::GLOBAL_TARGET_INFO;
use chrono::{DateTime, Utc};
use parser::parser::Inst;
use std::fs::OpenOptions;
use std::path::Path;
use z3::ast::{Ast, BV};
use z3::SatResult;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

/// Write SAT state details to file and log to terminal
fn write_sat_state_to_file(
    evaluation_content: &str,
    mode: &str,
    panic_addr: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create results directory if it doesn't exist
    std::fs::create_dir_all("results")?;

    let file_path = "results/FOUND_SAT_STATE.txt";
    let file_exists = Path::new(file_path).exists();

    // Open file in append mode (creates if doesn't exist)
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)?;

    // Get current timestamp
    let timestamp: DateTime<Utc> = Utc::now();
    let timestamp_str = timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // Write header separator
    if file_exists {
        writeln!(file, "\n{}", "=".repeat(80))?;
    }

    // Write SAT state entry
    writeln!(file, "[*] SATISFIABLE STATE FOUND")?;
    writeln!(file, "Timestamp: {}", timestamp_str)?;
    writeln!(file, "Mode: {}", mode)?;

    if let Some(addr) = panic_addr {
        writeln!(file, "Panic Address: 0x{:x}", addr)?;
    }

    writeln!(file, "{}", "-".repeat(60))?;
    writeln!(file, "{}", evaluation_content)?;
    writeln!(file, "{}", "=".repeat(80))?;

    file.flush()?;

    println!("\n~~~~~~~~~~~");
    println!(
        "[*] SATISFIABLE STATE AND POTENTIAL BUG FOUND! You can find the details in: {}",
        file_path
    );
    println!("~~~~~~~~~~~\n");

    Ok(())
}

/// Capture the evaluation content as a string (similar to what goes to the logger)
fn capture_symbolic_arguments_evaluation(
    model: &z3::Model,
    function_symbolic_arguments: &std::collections::BTreeMap<String, SymbolicVar>,
) -> String {
    let mut output = String::new();

    output.push_str("=== EVALUATING TRACKED Z3 VARIABLES ===\n\n");

    for (arg_name, symbolic_var) in function_symbolic_arguments {
        match symbolic_var {
            SymbolicVar::Slice(slice) => {
                output.push_str(&format!("Argument '{}':\n", arg_name));
                output.push_str("  Slice components:\n");

                // Evaluate slice metadata
                if let Some(ptr_val) = model.eval(&slice.pointer, true) {
                    if let Some(ptr_u64) = ptr_val.as_u64() {
                        output.push_str(&format!(
                            "    pointer ({}) = #x{:016x}\n",
                            slice.pointer, ptr_u64
                        ));
                        output.push_str(&format!("      (hex: 0x{:x})\n", ptr_u64));
                    }
                }

                if let Some(len_val) = model.eval(&slice.length, true) {
                    if let Some(len_u64) = len_val.as_u64() {
                        output.push_str(&format!(
                            "    length ({}) = #x{:016x}\n",
                            slice.length, len_u64
                        ));
                        output.push_str(&format!("      (decimal: {})\n", len_u64));
                    }
                }

                if let Some(cap_val) = model.eval(&slice.capacity, true) {
                    if let Some(cap_u64) = cap_val.as_u64() {
                        output.push_str(&format!(
                            "    capacity ({}) = #x{:016x}\n",
                            slice.capacity, cap_u64
                        ));
                        output.push_str(&format!("      (decimal: {})\n", cap_u64));
                    }
                }

                output.push_str("\n");
            }
            SymbolicVar::Int(bv) => {
                if let Some(val) = model.eval(bv, true) {
                    output.push_str(&format!("Argument '{}':\n", arg_name));

                    if bv.get_size() <= 64 {
                        if let Some(val_u64) = val.as_u64() {
                            output.push_str(&format!("  {} = #x{:016x}\n", bv, val_u64));
                            output.push_str(&format!("    (decimal: {})\n", val_u64));
                        }
                    } else {
                        // For large bit vectors (like 256-bit arrays)
                        output.push_str(&format!("  {} = {}\n", bv, val));
                        output.push_str(&format!("    (decimal: 0)\n")); // Simplified for large values
                    }

                    output.push_str("\n");
                }
            }
            _ => {
                output.push_str(&format!(
                    "Argument '{}': (unsupported type for evaluation)\n\n",
                    arg_name
                ));
            }
        }
    }

    output.push_str("=== END TRACKED Z3 VARIABLES EVALUATION ===\n");
    output
}

/// Capture Go arguments evaluation as string
fn capture_go_arguments_evaluation(
    model: &z3::Model,
    executor: &ConcolicExecutor,
    binary_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::new();

    // Get address of os.Args
    let os_args_addr = get_os_args_address(binary_path)?;

    // Read slice pointer and length
    let slice_ptr_bv = executor
        .state
        .memory
        .read_u64(os_args_addr, &mut executor.state.logger.clone())?
        .symbolic
        .to_bv(executor.context);
    let slice_ptr_val = model.eval(&slice_ptr_bv, true).unwrap().as_u64().unwrap();

    let slice_len_bv = executor
        .state
        .memory
        .read_u64(os_args_addr + 8, &mut executor.state.logger.clone())?
        .symbolic
        .to_bv(executor.context);
    let slice_len_val = model.eval(&slice_len_bv, true).unwrap().as_u64().unwrap();

    output.push_str(&format!(
        "To take the panic-branch => os.Args ptr=0x{:x}, len={}\n",
        slice_ptr_val, slice_len_val
    ));

    // Process each argument
    for i in 1..slice_len_val {
        let string_struct_addr = slice_ptr_val + i * 16;

        let str_data_ptr_bv = executor
            .state
            .memory
            .read_u64(string_struct_addr, &mut executor.state.logger.clone())?
            .symbolic
            .to_bv(executor.context);
        let str_data_ptr_val = model
            .eval(&str_data_ptr_bv, true)
            .unwrap()
            .as_u64()
            .unwrap();

        let str_data_len_bv = executor
            .state
            .memory
            .read_u64(string_struct_addr + 8, &mut executor.state.logger.clone())?
            .symbolic
            .to_bv(executor.context);
        let str_data_len_val = model
            .eval(&str_data_len_bv, true)
            .unwrap()
            .as_u64()
            .unwrap();

        if str_data_ptr_val == 0 || str_data_len_val == 0 {
            output.push_str(&format!("Arg[{}] => (empty or null)\n", i));
            continue;
        }

        let mut arg_bytes = Vec::new();
        for j in 0..str_data_len_val {
            let byte_read = executor
                .state
                .memory
                .read_byte(str_data_ptr_val + j)
                .map_err(|e| format!("Could not read arg[{}][{}]: {}", i, j, e))?;
            let byte_bv = byte_read.symbolic.to_bv(executor.context);
            let byte_val = model.eval(&byte_bv, true).unwrap().as_u64().unwrap() as u8;
            arg_bytes.push(byte_val);
        }

        let arg_str = String::from_utf8_lossy(&arg_bytes);
        output.push_str(&format!(
            "The user input nr.{} must be => \"{}\", the raw value being {:?} (len={})\n",
            i, arg_str, arg_bytes, str_data_len_val
        ));
    }

    Ok(output)
}

pub fn evaluate_args_z3<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    inst: &Inst,
    address_of_negated_path_exploration: u64,
    conditional_flag: Option<ConcolicVar<'ctx>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    let mode = env::var("MODE").expect("MODE environment variable is not set");

    if mode == "function" {
        let binary_path = {
            let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
            target_info.binary_path.clone()
        };

        let ast_panic_result =
            explore_ast_for_panic(executor, address_of_negated_path_exploration, &binary_path);

        if ast_panic_result.starts_with("FOUND_PANIC_XREF_AT 0x") {
            let mut panic_addr: Option<u64> = None;

            if let Some(panic_addr_str) = ast_panic_result.trim().split_whitespace().last() {
                if let Some(stripped) = panic_addr_str.strip_prefix("0x") {
                    if let Ok(parsed_addr) = u64::from_str_radix(stripped, 16) {
                        panic_addr = Some(parsed_addr);
                        log!(executor.state.logger, ">>> The speculative AST exploration found a potential call to a panic address at 0x{:x}", parsed_addr);
                    } else {
                        log!(
                            executor.state.logger,
                            "Could not parse panic address from AST result: '{}'",
                            panic_addr_str
                        );
                    }
                }
            }

            executor.solver.push();

            // When evaluating arguments during a CBRANCH leading to a panic, we want to assert the condition that leads to the panic.
            if let Some(conditional_flag) = conditional_flag {
                let panic_causing_flag_u64 = conditional_flag.concrete.to_u64().clone();
                // Handle both Bool and BV types
                let condition = match &conditional_flag.symbolic {
                    SymbolicVar::Bool(bool_expr) => {
                        log!(
                            executor.state.logger,
                            "Conditional flag Bool simplified: {:?}",
                            bool_expr.simplify()
                        );
                        // Assert the condition that actually causes the panic
                        let condition = if panic_causing_flag_u64 == 0 {
                            // We want the condition to be false
                            bool_expr.clone()
                        } else {
                            // We want the condition to be true
                            bool_expr.not()
                        };
                        condition
                    }
                    SymbolicVar::Int(bv) => {
                        log!(
                            executor.state.logger,
                            "Conditional flag BV simplified: {:?}",
                            bv.simplify()
                        );
                        let bit_width = bv.get_size();
                        let expected_val =
                            BV::from_u64(executor.context, panic_causing_flag_u64, bit_width);
                        // We need to convert the BV in Bool form to assert the condition
                        let condition = if panic_causing_flag_u64 == 0 {
                            bv._eq(&expected_val) // Negate the condition
                        } else {
                            bv._eq(&expected_val).not() // Keep original
                        };
                        condition
                    }
                    _ => {
                        return Err("Unsupported symbolic variable type for conditional flag"
                            .to_string()
                            .into());
                    }
                };
                // Assert the new condition
                log!(
                    executor.state.logger,
                    "Asserting branch condition to the solver: {:?}",
                    condition.simplify()
                );
                executor.solver.assert(&condition);
            } else {
                log!(
                    executor.state.logger,
                    "No conditional flag provided, continuing."
                );
            }

            // List constraints and assert them to solver
            add_constraints_from_vector(&executor);

            // Minimize symbolic variables to prefer smaller values
            for symbolic_var in executor.function_symbolic_arguments.values() {
                match symbolic_var {
                    SymbolicVar::Int(bv_var) => {
                        executor.solver.minimize(bv_var); // minimizing so that z3 givess us the smallest values possible
                    }
                    SymbolicVar::Slice(slice) => {
                        for elem in &slice.elements {
                            match elem {
                                SymbolicVar::Int(bv_elem) => {
                                    executor.solver.minimize(bv_elem);
                                }
                                _ => {
                                    log!(
                                        executor.state.logger,
                                        "Skipping non-Int slice element during minimize"
                                    );
                                }
                            }
                        }
                        executor.solver.minimize(&slice.length);
                    }
                    _ => {
                        log!(
                            executor.state.logger,
                            "Skipping non-minimizable symbolic var"
                        );
                    }
                }
            }

            match executor.solver.check(&[]) {
                SatResult::Sat => {
                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(
                        executor.state.logger,
                        "SATISFIABLE: Symbolic execution can lead to a panic function."
                    );
                    log!(executor.state.logger, "~~~~~~~~~~~");

                    let model = executor.solver.get_model().unwrap();

                    log!(
                        executor.state.logger,
                        "To enter a panic function, the following conditions must be satisfied:"
                    );

                    // Log the symbolic arguments evaluation (to terminal)
                    log_symbolic_arguments_evaluation(
                        &mut executor.state.logger,
                        &model,
                        &executor.function_symbolic_arguments,
                    );

                    // Capture the evaluation content for file writing
                    let evaluation_content = capture_symbolic_arguments_evaluation(
                        &model,
                        &executor.function_symbolic_arguments,
                    );

                    // Write to file
                    if let Err(e) = write_sat_state_to_file(&evaluation_content, &mode, panic_addr)
                    {
                        log!(
                            executor.state.logger,
                            "WARNING: Failed to write SAT state to file: {}",
                            e
                        );
                    }

                    log!(executor.state.logger, "~~~~~~~~~~~");
                }
                SatResult::Unsat => {
                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(
                        executor.state.logger,
                        "Branch to panic is UNSAT => no input can make that branch lead to panic"
                    );
                    log!(executor.state.logger, "~~~~~~~~~~~");
                }
                SatResult::Unknown => {
                    log!(executor.state.logger, "Solver => Unknown feasibility");
                }
            }

            executor.solver.pop();
        } else {
            log!(executor.state.logger, ">>> No panic function found in the speculative exploration with the current max depth exploration");
        }
    } else if mode == "start" || mode == "main" {
        let cf_reg = executor
            .state
            .cpu_state
            .lock()
            .unwrap()
            .get_register_by_offset(0x200, 64)
            .unwrap();
        let cf_bv = cf_reg.symbolic.to_bv(executor.context).simplify();
        log!(executor.state.logger, "CF BV simplified: {:?}", cf_bv);

        // 1) Push the solver context.
        executor.solver.push();

        // 2) Process the branch condition.
        let cond_varnode = &inst.inputs[1];
        let cond_concolic = executor
            .varnode_to_concolic(cond_varnode)
            .map_err(|e| e.to_string())
            .unwrap()
            .to_concolic_var()
            .unwrap();
        let cond_bv = cond_concolic.symbolic.to_bv(executor.context);

        // List constraints and assert them to solver
        add_constraints_from_vector(&executor);

        // we want to assert that the condition is non zero.
        let zero_bv = z3::ast::BV::from_u64(executor.context, 0, cond_bv.get_size());
        let branch_condition = cond_bv._eq(&zero_bv).not();

        // 3) Assert the branch condition.
        executor.solver.assert(&branch_condition);

        // 4) check feasibility
        match executor.solver.check(&[]) {
            z3::SatResult::Sat => {
                log!(executor.state.logger, "~~~~~~~~~~~");
                log!(
                    executor.state.logger,
                    "SATISFIABLE: Symbolic execution can lead to a panic function."
                );
                log!(executor.state.logger, "~~~~~~~~~~~");

                let model = executor.solver.get_model().unwrap();
                let lang = std::env::var("SOURCE_LANG")
                    .unwrap_or_default()
                    .to_lowercase();
                let binary_path = {
                    let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
                    target_info.binary_path.clone()
                };

                let evaluation_content = if lang == "go" {
                    // Capture Go arguments evaluation
                    match capture_go_arguments_evaluation(&model, executor, &binary_path) {
                        Ok(go_eval) => {
                            // Also log to terminal (existing behavior)
                            let os_args_addr = get_os_args_address(&binary_path).unwrap();
                            let slice_ptr_bv = executor
                                .state
                                .memory
                                .read_u64(os_args_addr, &mut executor.state.logger.clone())
                                .unwrap()
                                .symbolic
                                .to_bv(executor.context);
                            let slice_ptr_val =
                                model.eval(&slice_ptr_bv, true).unwrap().as_u64().unwrap();

                            let slice_len_bv = executor
                                .state
                                .memory
                                .read_u64(os_args_addr + 8, &mut executor.state.logger.clone())
                                .unwrap()
                                .symbolic
                                .to_bv(executor.context);
                            let slice_len_val =
                                model.eval(&slice_len_bv, true).unwrap().as_u64().unwrap();

                            log!(
                                executor.state.logger,
                                "To take the panic-branch => os.Args ptr=0x{:x}, len={}",
                                slice_ptr_val,
                                slice_len_val
                            );

                            // Log arguments to terminal (existing behavior)
                            for i in 1..slice_len_val {
                                let string_struct_addr = slice_ptr_val + i * 16;

                                let str_data_ptr_bv = executor
                                    .state
                                    .memory
                                    .read_u64(
                                        string_struct_addr,
                                        &mut executor.state.logger.clone(),
                                    )
                                    .unwrap()
                                    .symbolic
                                    .to_bv(executor.context);
                                let str_data_ptr_val = model
                                    .eval(&str_data_ptr_bv, true)
                                    .unwrap()
                                    .as_u64()
                                    .unwrap();

                                let str_data_len_bv = executor
                                    .state
                                    .memory
                                    .read_u64(
                                        string_struct_addr + 8,
                                        &mut executor.state.logger.clone(),
                                    )
                                    .unwrap()
                                    .symbolic
                                    .to_bv(executor.context);
                                let str_data_len_val = model
                                    .eval(&str_data_len_bv, true)
                                    .unwrap()
                                    .as_u64()
                                    .unwrap();

                                if str_data_ptr_val == 0 || str_data_len_val == 0 {
                                    log!(executor.state.logger, "Arg[{}] => (empty or null)", i);
                                    continue;
                                }

                                let mut arg_bytes = Vec::new();
                                for j in 0..str_data_len_val {
                                    let byte_read = executor
                                        .state
                                        .memory
                                        .read_byte(str_data_ptr_val + j)
                                        .map_err(|e| {
                                            format!("Could not read arg[{}][{}]: {}", i, j, e)
                                        })
                                        .unwrap();
                                    let byte_bv = byte_read.symbolic.to_bv(executor.context);
                                    let byte_val =
                                        model.eval(&byte_bv, true).unwrap().as_u64().unwrap() as u8;
                                    arg_bytes.push(byte_val);
                                }

                                let arg_str = String::from_utf8_lossy(&arg_bytes);
                                log!(executor.state.logger, "The user input nr.{} must be => \"{}\", the raw value being {:?} (len={})", i, arg_str, arg_bytes, str_data_len_val);
                            }

                            go_eval // Return the captured evaluation
                        }
                        Err(e) => {
                            format!("Error capturing Go arguments: {}", e)
                        }
                    }
                } else {
                    let msg = format!(">>> SOURCE_LANG is '{}'. Argument inspection is not implemented for these binaries yet.", lang);
                    log!(executor.state.logger, "{}", msg);
                    msg
                };

                // Write to file
                if let Err(e) = write_sat_state_to_file(&evaluation_content, &mode, None) {
                    log!(
                        executor.state.logger,
                        "WARNING: Failed to write SAT state to file: {}",
                        e
                    );
                }

                log!(executor.state.logger, "~~~~~~~~~~~");
            }

            z3::SatResult::Unsat => {
                log!(executor.state.logger, "~~~~~~~~~~~");
                log!(
                    executor.state.logger,
                    "Branch to panic is UNSAT => no input can make that branch lead to panic"
                );
                log!(executor.state.logger, "~~~~~~~~~~~");
            }
            z3::SatResult::Unknown => {
                log!(executor.state.logger, "Solver => Unknown feasibility");
            }
        }
        // 6) pop the solver context
        executor.solver.pop();
    } else {
        log!(
            executor.state.logger,
            "Unsupported mode for evaluating arguments: {}",
            mode
        );
    }
    Ok(())
}

// Function to get the address of the os.Args slice in the target binary
pub fn get_os_args_address(binary_path: &str) -> Result<u64, Box<dyn Error>> {
    let output = Command::new("objdump")
        .arg("-t")
        .arg(binary_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("objdump failed: {}", stderr).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Example line we might see:
    // 0000000000236e68 l     O .bss   0000000000000018 os.Args
    for line in stdout.lines() {
        if line.contains("os.Args") {
            // The first token is the address in hex, like "0000000000236e68"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let addr_hex = parts[0];
                // Convert from hex string to u64
                let addr = u64::from_str_radix(addr_hex, 16)?;
                return Ok(addr);
            }
        }
    }
    Err("Could not find os.Args in objdump output".into())
}

/// Logs evaluation of symbolic arguments using the current model
fn log_symbolic_arguments_evaluation(
    logger: &mut Logger,
    model: &z3::Model,
    symbolic_arguments: &std::collections::BTreeMap<String, SymbolicVar>,
) {
    log!(logger, "=== EVALUATING TRACKED Z3 VARIABLES ===");

    for (arg_name, sym_var) in symbolic_arguments.iter() {
        log!(logger, "");
        log!(logger, "Argument '{}': ", arg_name);

        match sym_var {
            SymbolicVar::Int(bv_var) => {
                let var_name = bv_var.to_string();
                match model.eval(bv_var, true) {
                    Some(val) => {
                        log!(logger, "  {} = {}", var_name, val);
                        if let Some(u64_val) = val.as_u64() {
                            if var_name.contains("ptr") || var_name.contains("R8") {
                                log!(logger, "    (hex: 0x{:x})", u64_val);
                            } else {
                                log!(logger, "    (decimal: {})", u64_val);
                            }
                        }
                    }
                    None => {
                        log!(logger, "  {} = <could not evaluate>", var_name);
                    }
                }
            }
            SymbolicVar::Slice(slice) => {
                let ptr_name = slice.pointer.to_string();
                let len_name = slice.length.to_string();
                let cap_name = slice.capacity.to_string();

                log!(logger, "  Slice components:");

                // Evaluate pointer
                match model.eval(&slice.pointer, true) {
                    Some(val) => {
                        log!(logger, "    pointer ({}) = {}", ptr_name, val);
                        if let Some(u64_val) = val.as_u64() {
                            log!(logger, "      (hex: 0x{:x})", u64_val);
                        }
                    }
                    None => {
                        log!(logger, "    pointer ({}) = <could not evaluate>", ptr_name);
                    }
                }

                // Evaluate length
                match model.eval(&slice.length, true) {
                    Some(val) => {
                        log!(logger, "    length ({}) = {}", len_name, val);
                        if let Some(u64_val) = val.as_u64() {
                            log!(logger, "      (decimal: {})", u64_val);
                        }
                    }
                    None => {
                        log!(logger, "    length ({}) = <could not evaluate>", len_name);
                    }
                }

                // Evaluate capacity
                match model.eval(&slice.capacity, true) {
                    Some(val) => {
                        log!(logger, "    capacity ({}) = {}", cap_name, val);
                        if let Some(u64_val) = val.as_u64() {
                            log!(logger, "      (decimal: {})", u64_val);
                        }
                    }
                    None => {
                        log!(logger, "    capacity ({}) = <could not evaluate>", cap_name);
                    }
                }
            }
            SymbolicVar::Bool(bool_var) => {
                let var_name = bool_var.to_string();
                match model.eval(bool_var, true) {
                    Some(val) => {
                        log!(logger, "  {} = {}", var_name, val);
                    }
                    None => {
                        log!(logger, "  {} = <could not evaluate>", var_name);
                    }
                }
            }
            _ => {
                log!(logger, "  <unsupported symbolic type>");
            }
        }
    }
    log!(logger, "=== END TRACKED Z3 VARIABLES EVALUATION ===");
}
