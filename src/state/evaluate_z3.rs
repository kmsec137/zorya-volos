use std::{env, error::Error, process::Command};
use std::io::Write;

use z3::ast::{Ast, BV};
use parser::parser::Inst;
use crate::concolic::{ConcolicExecutor, ConcolicVar, SymbolicVar};
use super::explore_ast::explore_ast_for_panic;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

pub fn evaluate_args_z3(executor: &mut ConcolicExecutor, inst: &Inst, binary_path: &str, address_of_negated_path_exploration: u64, conditional_flag: ConcolicVar) -> Result<(), Box<dyn std::error::Error>> {
    let mode = env::var("MODE").expect("MODE environment variable is not set");

    if mode == "start" || mode == "main" {
        let cf_reg = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x200, 64).unwrap();
            let cf_bv = cf_reg.symbolic.to_bv(executor.context).simplify();
            log!(executor.state.logger, "CF BV simplified: {:?}", cf_bv);
            
            // 1) Push the solver context.
            executor.solver.push();

            // 2) Process the branch condition.
            let cond_varnode = &inst.inputs[1];
            let cond_concolic = executor.varnode_to_concolic(cond_varnode)
                .map_err(|e| e.to_string())
                .unwrap()
                .to_concolic_var()
                .unwrap();
            let cond_bv = cond_concolic.symbolic.to_bv(executor.context); 

            // we want to assert that the condition is non zero.
            let zero_bv = z3::ast::BV::from_u64(executor.context, 0, cond_bv.get_size());
            let branch_condition = cond_bv._eq(&zero_bv).not();

            // 3) Assert the branch condition.
            executor.solver.assert(&branch_condition);
    
            // 4) check feasibility
            match executor.solver.check() {
                z3::SatResult::Sat => {
                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(executor.state.logger, "SATISFIABLE: Symbolic execution can lead to a panic function.");
                    log!(executor.state.logger, "~~~~~~~~~~~");

                    let model = executor.solver.get_model().unwrap();
                    let lang = std::env::var("SOURCE_LANG").unwrap_or_default().to_lowercase();

                    if lang == "go" {
                        // 5.1) get address of os.Args
                        let os_args_addr = get_os_args_address(binary_path).unwrap();

                        // 5.2) read the slice's pointer and length from memory, then evaluate them in the model
                        let slice_ptr_bv = executor
                            .state
                            .memory
                            .read_u64(os_args_addr)
                            .unwrap()
                            .symbolic
                            .to_bv(executor.context);
                        let slice_ptr_val = model.eval(&slice_ptr_bv, true).unwrap().as_u64().unwrap();

                        let slice_len_bv = executor
                            .state
                            .memory
                            .read_u64(os_args_addr + 8)
                            .unwrap()
                            .symbolic
                            .to_bv(executor.context);
                        let slice_len_val = model.eval(&slice_len_bv, true).unwrap().as_u64().unwrap();

                        log!(executor.state.logger, "To take the panic-branch => os.Args ptr=0x{:x}, len={}", slice_ptr_val, slice_len_val);

                        // 5.3) For each argument in os.Args, read the string struct (ptr, len), then read each byte
                        for i in 1..slice_len_val {
                            let string_struct_addr = slice_ptr_val + i * 16;

                            let str_data_ptr_bv = executor
                                .state
                                .memory
                                .read_u64(string_struct_addr)
                                .unwrap()
                                .symbolic
                                .to_bv(executor.context);
                            let str_data_ptr_val = model.eval(&str_data_ptr_bv, true).unwrap().as_u64().unwrap();

                            let str_data_len_bv = executor
                                .state
                                .memory
                                .read_u64(string_struct_addr + 8)
                                .unwrap()
                                .symbolic
                                .to_bv(executor.context);
                            let str_data_len_val = model.eval(&str_data_len_bv, true).unwrap().as_u64().unwrap();

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
                                    .map_err(|e| format!("Could not read arg[{}][{}]: {}", i, j, e))
                                    .unwrap();
                                let byte_bv = byte_read.symbolic.to_bv(executor.context);
                                let byte_val = model.eval(&byte_bv, true).unwrap().as_u64().unwrap() as u8;
                                arg_bytes.push(byte_val);
                            }

                            let arg_str = String::from_utf8_lossy(&arg_bytes);
                            log!(executor.state.logger, "The user input nr.{} must be => \"{}\", the raw value being {:?} (len={})", i, arg_str, arg_bytes, str_data_len_val);
                        }
                    } else { // TODO: handle other languages
                        log!(executor.state.logger, ">>> SOURCE_LANG is '{}'. Argument inspection is not implemented for these binaries yet.", lang);
                    }

                    log!(executor.state.logger, "~~~~~~~~~~~");
                }

                z3::SatResult::Unsat => {
                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(executor.state.logger, "Branch to panic is UNSAT => no input can make that branch lead to panic");
                    log!(executor.state.logger, "~~~~~~~~~~~");
                }
                z3::SatResult::Unknown => {
                    log!(executor.state.logger, "Solver => Unknown feasibility");
                }
            }
            // 6) pop the solver context
            executor.solver.pop(1);
                   
    } else if mode == "function" {
        // CALL TO THE AST EXPLORATION FOR A PANIC FUNCTION
        let ast_panic_result = explore_ast_for_panic(executor, address_of_negated_path_exploration, binary_path);

        // If the AST exploration indicates a potential panic function...
        if ast_panic_result.starts_with("FOUND_PANIC_XREF_AT 0x") { 
            if let Some(panic_addr_str) = ast_panic_result.trim().split_whitespace().last() {
                if let Some(stripped) = panic_addr_str.strip_prefix("0x") {
                    if let Ok(parsed_addr) = u64::from_str_radix(stripped, 16) {
                        log!(executor.state.logger, ">>> The speculative AST exploration found a potential call to a panic address at 0x{:x}", parsed_addr);
                    } else {
                        log!(executor.state.logger, "Could not parse panic address from AST result: '{}'", panic_addr_str);
                    }
                }
            }
                                
            // 1) Push the solver context.
            executor.solver.push();

            // 2) Define the condition to explore the path not taken.
            let negative_conditional_flag_u64 = conditional_flag.concrete.to_u64() ^ 1;
            let conditional_flag_bv = conditional_flag.symbolic.to_bv(executor.context);
            log!(executor.state.logger, "Conditional flag BV simplified: {:?}", conditional_flag_bv.simplify());

            let bit_width = conditional_flag_bv.get_size();
            let expected_val = BV::from_u64(executor.context, negative_conditional_flag_u64, bit_width);
            let condition = conditional_flag_bv._eq(&expected_val);

            // 3) Assert the condition in the solver.
            executor.solver.assert(&condition);
    
            // 4) check feasibility
            match executor.solver.check() {
                z3::SatResult::Sat => {
                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(executor.state.logger, "SATISFIABLE: Symbolic execution can lead to a panic function.");
                    log!(executor.state.logger, "~~~~~~~~~~~");

                    let model = executor.solver.get_model().unwrap();

                    for (arg_name, sym) in executor.function_symbolic_arguments.iter() {
                        if let SymbolicVar::Slice(slice) = sym {
                            if let Some(len_val) = model.eval(&slice.length, true) {
                                log!(executor.state.logger, "Slice '{}' has symbolic length = {}", arg_name, len_val);
                            } else {
                                log!(executor.state.logger, "Slice '{}' length could not be evaluated in the model", arg_name);
                            }
                        }
                    }

                    log!(executor.state.logger, "To enter a panic function, the following conditions must be satisfied:");

                    // Stringify the simplified conditional flag to detect which arguments are constrained
                    let cond_str = format!("{:?}", conditional_flag_bv.simplify());

                    for (arg_name, sym_var) in executor.function_symbolic_arguments.iter() {
                        let is_constrained = cond_str.contains(arg_name);
                        match sym_var {
                            SymbolicVar::Int(bv_var) => {
                                let val = model.eval(bv_var, true)
                                    .map(|v| format!("{:?}", v))
                                    .unwrap_or_else(|| "<?>".to_string());
                                if is_constrained {
                                    log!(executor.state.logger, "  {}: {}", arg_name, val);
                                } else {
                                    log!(executor.state.logger, "  {}: {} (unconstrained)", arg_name, val);
                                }
                            }

                            SymbolicVar::Slice(slice) => {
                                let ptr_val = model.eval(&slice.pointer, true)
                                    .map(|v| format!("{:?}", v))
                                    .unwrap_or_else(|| "<?>".to_string());
                                let len_val = model.eval(&slice.length, true)
                                    .map(|v| format!("{:?}", v))
                                    .unwrap_or_else(|| "<?>".to_string());
                                if is_constrained {
                                    log!(executor.state.logger, "  {}__ptr: {}", arg_name, ptr_val);
                                    log!(executor.state.logger, "  {}__len: {}", arg_name, len_val);
                                } else {
                                    log!(executor.state.logger, "  {}__ptr: {} (unconstrained)", arg_name, ptr_val);
                                    log!(executor.state.logger, "  {}__len: {} (unconstrained)", arg_name, len_val);
                                }
                            }

                            _ => {
                                log!(executor.state.logger, "  {}: <unsupported symbolic type>", arg_name);
                            }
                        }
                    }

                    log!(executor.state.logger, "~~~~~~~~~~~");
                }

                z3::SatResult::Unsat => {
                    log!(executor.state.logger, "~~~~~~~~~~~");
                    log!(executor.state.logger, "Branch to panic is UNSAT => no input can make that branch lead to panic");
                    log!(executor.state.logger, "~~~~~~~~~~~");
                }
                z3::SatResult::Unknown => {
                    log!(executor.state.logger, "Solver => Unknown feasibility");
                }
            }
            // 6) pop the solver context
            executor.solver.pop(1);
        } else {
            log!(executor.state.logger, ">>> No panic function found in the speculative exploration with the current max depth exploration");
        }
    } else {
        log!(executor.state.logger, "Unsupported mode for evaluating arguments: {}", mode);
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
