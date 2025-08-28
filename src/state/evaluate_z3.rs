use std::io::Write;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::{error::Error, process::Command};

use super::explore_ast::explore_ast_for_panic;
use crate::concolic::{ConcolicExecutor, ConcolicVar, Logger, SymbolicVar};
use crate::state::simplify_z3::add_constraints_from_vector;
use crate::target_info::GLOBAL_TARGET_INFO;
use chrono::{DateTime, Utc};
use parser::parser::Inst;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::Path;
use z3::ast::{Ast, BV};
use z3::SatResult;

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

// Global timer to measure elapsed time until first SAT state is found
static START_INSTANT: OnceLock<Instant> = OnceLock::new();
static INVOCATION_CMDLINE: OnceLock<String> = OnceLock::new();

/// Initialize the global SAT timer start. Safe to call multiple times; only first wins.
pub fn init_sat_timer_start() {
    let _ = START_INSTANT.set(Instant::now());
}

/// Initialize the recorded command line invocation including key environment variables.
pub fn init_invocation_command_line() {
    // Try to reconstruct the full wrapper-style command
    let zorya_dir = std::env::var("ZORYA_DIR").ok();
    let bin_path = std::env::var("BIN_PATH").ok();
    let start_point = std::env::var("START_POINT").ok();
    let mode = std::env::var("MODE").ok();
    let source_lang = std::env::var("SOURCE_LANG").ok();
    let compiler = std::env::var("COMPILER").ok();
    let args_env = std::env::var("ARGS").ok();
    let negate_flag = std::env::var("NEGATE_PATH_FLAG").ok();

    let reconstructed = match (zorya_dir, bin_path, start_point, mode) {
        (Some(zdir), Some(bin), Some(start), Some(mode_val)) => {
            let mut s = format!("{}/zorya {} --mode {} {}", zdir, bin, mode_val, start);
            if let Some(lang) = source_lang {
                if !lang.is_empty() {
                    s.push_str(&format!(" --lang {}", lang));
                }
            }
            if let Some(comp) = compiler {
                if !comp.is_empty() {
                    s.push_str(&format!(" --compiler {}", comp));
                }
            }
            if let Some(a) = args_env {
                if !a.is_empty() && a != "none" {
                    s.push_str(&format!(" --arg \"{}\"", a));
                }
            }
            if let Some(neg) = negate_flag {
                if neg == "true" {
                    s.push_str(" --negate-path-exploration");
                } else if neg == "false" {
                    s.push_str(" --no-negate-path-exploration");
                }
            }
            s
        }
        _ => {
            // Fallback: argv join
            let mut parts: Vec<String> = Vec::new();
            for arg in std::env::args() {
                let needs_quotes = arg.contains(' ') || arg.contains('\t');
                let escaped = arg.replace('"', "\\\"");
                if needs_quotes {
                    parts.push(format!("\"{}\"", escaped));
                } else {
                    parts.push(escaped);
                }
            }
            parts.join(" ")
        }
    };

    let _ = INVOCATION_CMDLINE.set(reconstructed);
}

/// Add ASCII constraints for argument bytes to ensure readable output
fn add_ascii_constraints_for_args<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    binary_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ascii_profile = std::env::var("ARG_ASCII_PROFILE")
        .unwrap_or_else(|_| "auto".to_string())
        .to_lowercase();

    // Auto-detect numeric arguments by parsing the execution trace for calls
    // to strconv.Atoi / strconv.ParseInt and capture the first argument pointer.
    let mut numeric_arg_ptrs: HashSet<u64> = HashSet::new();
    if ascii_profile == "auto" {
        if let Ok(trace) = std::fs::read_to_string("results/execution_trace.txt") {
            for line in trace.lines() {
                if line.contains("Symbol: strconv.Atoi")
                    || line.contains("Symbol: strconv.ParseInt")
                {
                    // Heuristic: find the first "=0x..." after the arrow
                    if let Some(arrow_idx) = line.find("->") {
                        let after = &line[arrow_idx + 2..];
                        if let Some(s_idx) = after.find("=0x") {
                            let hex_start = s_idx + 3;
                            let mut hex_end = hex_start;
                            let bytes = after.as_bytes();
                            while hex_end < after.len() && bytes[hex_end].is_ascii_hexdigit() {
                                hex_end += 1;
                            }
                            if let Ok(val) = u64::from_str_radix(&after[hex_start..hex_end], 16) {
                                numeric_arg_ptrs.insert(val);
                            }
                        }
                    }
                }
            }
        }
    }
    if let Ok(os_args_addr) = get_os_args_address(binary_path) {
        if let Ok(slice_ptr_bv) = executor
            .state
            .memory
            .read_u64(os_args_addr, &mut executor.state.logger.clone())
        {
            if let Ok(slice_len_bv) = executor
                .state
                .memory
                .read_u64(os_args_addr + 8, &mut executor.state.logger.clone())
            {
                let slice_ptr_val = slice_ptr_bv.concrete.to_u64();
                let slice_len_val = slice_len_bv.concrete.to_u64();

                // Add ASCII constraints for each argument byte
                for i in 1..slice_len_val.min(10) {
                    // Limit to first 10 args for performance
                    let string_struct_addr = slice_ptr_val + i * 16;

                    if let Ok(str_data_ptr_cv) = executor
                        .state
                        .memory
                        .read_u64(string_struct_addr, &mut executor.state.logger.clone())
                    {
                        if let Ok(str_data_len_cv) = executor
                            .state
                            .memory
                            .read_u64(string_struct_addr + 8, &mut executor.state.logger.clone())
                        {
                            let str_data_ptr_val = str_data_ptr_cv.concrete.to_u64();
                            let str_data_len_val = str_data_len_cv.concrete.to_u64();
                            let str_data_len_bv_sym =
                                str_data_len_cv.symbolic.to_bv(executor.context);

                            if str_data_ptr_val != 0 && str_data_len_val > 0 {
                                // Decide constraint profile for this specific arg (auto/digits/printable)
                                let apply_digits_for_this_arg = match ascii_profile.as_str() {
                                    "digits" => true,
                                    "printable" => false,
                                    _ => numeric_arg_ptrs.contains(&str_data_ptr_val),
                                };
                                // Limit string length for performance
                                let max_len = str_data_len_val.min(256);
                                let mut first_byte_bv_opt: Option<z3::ast::BV> = None;
                                for j in 0..max_len {
                                    if let Ok(byte_read) =
                                        executor.state.memory.read_byte(str_data_ptr_val + j)
                                    {
                                        let byte_bv = byte_read.symbolic.to_bv(executor.context);
                                        if j == 0 {
                                            first_byte_bv_opt = Some(byte_bv.clone());
                                        }
                                        if apply_digits_for_this_arg {
                                            // Allow only digits '0'-'9'; allow optional leading '-' at position 0
                                            let zero = z3::ast::BV::from_u64(
                                                executor.context,
                                                b'0' as u64,
                                                8,
                                            );
                                            let nine = z3::ast::BV::from_u64(
                                                executor.context,
                                                b'9' as u64,
                                                8,
                                            );
                                            let is_digit =
                                                byte_bv.bvuge(&zero) & byte_bv.bvule(&nine);

                                            if j == 0 {
                                                let dash = z3::ast::BV::from_u64(
                                                    executor.context,
                                                    b'-' as u64,
                                                    8,
                                                );
                                                let is_dash = byte_bv._eq(&dash);
                                                let allowed = z3::ast::Bool::or(
                                                    executor.context,
                                                    &[&is_dash, &is_digit],
                                                );
                                                executor.solver.assert(&allowed);
                                            } else {
                                                executor.solver.assert(&is_digit);
                                            }
                                        } else {
                                            // Default: printable ASCII (32-126)
                                            let printable_min =
                                                z3::ast::BV::from_u64(executor.context, 32, 8);
                                            let printable_max =
                                                z3::ast::BV::from_u64(executor.context, 126, 8);
                                            let printable_constraint = byte_bv
                                                .bvuge(&printable_min)
                                                & byte_bv.bvule(&printable_max);
                                            executor.solver.assert(&printable_constraint);
                                        }
                                    }
                                }
                                // For digits profile, forbid a lone '-' when length == 1
                                if apply_digits_for_this_arg {
                                    if let Some(first_byte_bv) = first_byte_bv_opt {
                                        let one64 = z3::ast::BV::from_u64(executor.context, 1, 64);
                                        let len_eq_one = str_data_len_bv_sym._eq(&one64);
                                        let dash8 =
                                            z3::ast::BV::from_u64(executor.context, b'-' as u64, 8);
                                        let first_is_dash = first_byte_bv._eq(&dash8);
                                        let lone_dash = z3::ast::Bool::and(
                                            executor.context,
                                            &[&len_eq_one, &first_is_dash],
                                        );
                                        let not_lone_dash = lone_dash.not();
                                        executor.solver.assert(&not_lone_dash);
                                    }
                                }
                            }
                        }
                    }
                }

                match ascii_profile.as_str() {
                    "digits" => log!(executor.state.logger, "Added ASCII constraints for argument bytes (digits mode)"),
                    "printable" => log!(executor.state.logger, "Added ASCII constraints for argument bytes (printable mode)"),
                    _ => log!(executor.state.logger, "Added ASCII constraints for argument bytes (auto mode: digits applied to detected numeric args)"),
                }
            }
        }
    }
    Ok(())
}

/// Write SAT state details to file and log to terminal
fn write_sat_state_to_file(
    evaluation_content: &str,
    mode: &str,
    panic_addr: Option<u64>,
    elapsed_since_start: Option<Duration>,
    instruction_addr: Option<u64>,
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
    if let Some(inv) = INVOCATION_CMDLINE.get() {
        writeln!(file, "Running command: {}", inv)?;
    }
    writeln!(file, "[*] SATISFIABLE STATE FOUND")?;
    writeln!(file, "Timestamp: {}", timestamp_str)?;
    writeln!(file, "Mode: {}", mode)?;
    if let Some(dur) = elapsed_since_start {
        let secs = dur.as_secs();
        let millis = dur.subsec_millis();
        writeln!(file, "Elapsed since start: {}.{:03}s", secs, millis)?;
    }
    if let Some(addr) = instruction_addr {
        writeln!(file, "Instruction Address: 0x{:x}", addr)?;
    }
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
    if let Some(dur) = elapsed_since_start {
        let secs = dur.as_secs_f64();
        println!("[*] Elapsed since start: {:.3}s", secs);
    }
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

                            // Add ASCII interpretation for byte-sized values
                            if bv.get_size() == 8 && val_u64 <= 255 {
                                let byte_val = val_u64 as u8;
                                if byte_val >= 32 && byte_val <= 126 {
                                    // Printable ASCII
                                    output.push_str(&format!(
                                        "    (ASCII: '{}')\n",
                                        char::from(byte_val)
                                    ));
                                } else if byte_val == 0 {
                                    output.push_str(&format!("    (ASCII: '\\0' - null byte)\n"));
                                } else if byte_val == 9 {
                                    output.push_str(&format!("    (ASCII: '\\t' - tab)\n"));
                                } else if byte_val == 10 {
                                    output.push_str(&format!("    (ASCII: '\\n' - newline)\n"));
                                } else if byte_val == 13 {
                                    output.push_str(&format!(
                                        "    (ASCII: '\\r' - carriage return)\n"
                                    ));
                                } else {
                                    output.push_str(&format!(
                                        "    (ASCII: non-printable, code {})\n",
                                        byte_val
                                    ));
                                }
                            }
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
    let ascii_profile = std::env::var("ARG_ASCII_PROFILE")
        .unwrap_or_default()
        .to_lowercase();

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
        // If digits mode or value looks numeric, also print parsed integer form
        let looks_numeric = {
            let s = arg_str.trim();
            let bytes = s.as_bytes();
            !bytes.is_empty()
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(idx, b)| (*b >= b'0' && *b <= b'9') || (idx == 0 && *b == b'-'))
        };
        if ascii_profile == "digits" || looks_numeric {
            if let Ok(parsed) = arg_str.trim().parse::<i64>() {
                output.push_str(&format!("  as integer: {}\n", parsed));
            }
        }
    }

    Ok(output)
}

pub fn evaluate_args_z3<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    inst: &Inst,
    address_of_negated_path_exploration: u64,
    conditional_flag: Option<ConcolicVar<'ctx>>,
    instruction_addr: Option<u64>,
    branch_target_addr: Option<u64>,
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
                        // Flip the observed condition to explore the negated branch
                        let condition = if panic_causing_flag_u64 == 0 {
                            // Observed false; require true
                            bool_expr.not().not() // i.e., bool_expr == true
                        } else {
                            // Observed true; require false
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
                        let zero = BV::from_u64(executor.context, 0, bit_width);
                        // Flip the observed condition: if observed 0 (false), require non-zero (true);
                        // if observed non-zero (true), require zero (false).
                        let condition = if panic_causing_flag_u64 == 0 {
                            bv._eq(&zero).not()
                        } else {
                            bv._eq(&zero)
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

            // Add ASCII constraints for argument bytes
            let _ = add_ascii_constraints_for_args(executor, &binary_path);

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
                    let elapsed = START_INSTANT.get().map(|s| s.elapsed());
                    if let Err(e) = write_sat_state_to_file(
                        &evaluation_content,
                        &mode,
                        panic_addr,
                        elapsed,
                        instruction_addr,
                    ) {
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
        let binary_path = {
            let target_info = GLOBAL_TARGET_INFO.lock().unwrap();
            target_info.binary_path.clone()
        };

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

        // Add ASCII constraints for argument bytes
        let _ = add_ascii_constraints_for_args(executor, &binary_path);

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
                let elapsed = START_INSTANT.get().map(|s| s.elapsed());
                if let Err(e) = write_sat_state_to_file(
                    &evaluation_content,
                    &mode,
                    branch_target_addr,
                    elapsed,
                    instruction_addr,
                ) {
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

                                // Add ASCII interpretation for byte-sized values
                                if bv_var.get_size() == 8 && u64_val <= 255 {
                                    let byte_val = u64_val as u8;
                                    if byte_val >= 32 && byte_val <= 126 {
                                        // Printable ASCII
                                        log!(logger, "    (ASCII: '{}')", char::from(byte_val));
                                    } else if byte_val == 0 {
                                        log!(logger, "    (ASCII: '\\0' - null byte)");
                                    } else if byte_val == 9 {
                                        log!(logger, "    (ASCII: '\\t' - tab)");
                                    } else if byte_val == 10 {
                                        log!(logger, "    (ASCII: '\\n' - newline)");
                                    } else if byte_val == 13 {
                                        log!(logger, "    (ASCII: '\\r' - carriage return)");
                                    } else {
                                        log!(
                                            logger,
                                            "    (ASCII: non-printable, code {})",
                                            byte_val
                                        );
                                    }
                                }
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
