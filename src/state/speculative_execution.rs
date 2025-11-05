/// Speculative execution module for detecting vulnerabilities in unexplored paths
use crate::executor::ConcolicExecutor;
use parser::parser::{Inst, Opcode, Var};
use std::collections::BTreeMap;
use std::io::Write;

const MAX_SPECULATIVE_DEPTH: usize = 50; // Maximum instructions to execute speculatively

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

/// Result of speculative execution
#[derive(Debug, Clone)]
pub enum SpeculativeResult {
    /// Vulnerability found: (type, address, description)
    VulnerabilityFound(String, u64, String),
    /// No vulnerability found within depth limit
    Safe,
    /// Execution error (not a vulnerability)
    Error(String),
    /// Reached depth limit without finding anything
    DepthLimitReached,
}

/// Execute a path speculatively to detect vulnerabilities
/// This creates a lightweight execution context without full state cloning
pub fn speculative_explore_path<'ctx>(
    executor: &mut ConcolicExecutor<'ctx>,
    start_address: u64,
    instructions_map: &BTreeMap<u64, Vec<Inst>>,
    max_depth: usize,
) -> SpeculativeResult {
    log!(
        executor.state.logger,
        ">>> Starting speculative exploration at 0x{:x} (max depth: {})",
        start_address,
        max_depth
    );

    // Track visited addresses to avoid infinite loops
    let mut visited = std::collections::HashSet::new();
    let mut current_addr = start_address;
    let mut instruction_count = 0;

    // Track register values that we know are zero (for null pointer detection)
    // Initialize with registers that are currently zero in the executor state
    let mut zero_registers: std::collections::HashSet<u64> = std::collections::HashSet::new();
    if let Ok(cpu_state) = executor.state.cpu_state.lock() {
        for (offset, reg_var) in cpu_state.registers.iter() {
            if let Ok(concrete_val) = reg_var.get_concrete_value() {
                if concrete_val == 0 {
                    zero_registers.insert(*offset);
                    log!(
                        executor.state.logger,
                        ">>> Speculative: Register at offset 0x{:x} is zero at start",
                        offset
                    );
                }
            }
        }
    }

    // Simple execution without full state cloning
    // We'll just check for dangerous patterns
    while instruction_count < max_depth {
        // Check for loops
        if visited.contains(&current_addr) {
            log!(
                executor.state.logger,
                ">>> Speculative execution detected loop at 0x{:x}, stopping",
                current_addr
            );
            return SpeculativeResult::DepthLimitReached;
        }
        visited.insert(current_addr);

        // Get instructions at current address
        let instructions = match instructions_map.get(&current_addr) {
            Some(insts) => insts,
            None => {
                log!(
                    executor.state.logger,
                    ">>> Speculative execution: no instructions at 0x{:x}",
                    current_addr
                );
                return SpeculativeResult::DepthLimitReached;
            }
        };

        // Check each instruction for vulnerability patterns
        for (idx, inst) in instructions.iter().enumerate() {
            instruction_count += 1;

            log!(
                executor.state.logger,
                ">>> Speculative: Analyzing instruction {} at 0x{:x}: {:?}",
                idx,
                current_addr,
                inst
            );

            // Check for LOAD operations (potential null dereference)
            if inst.opcode == Opcode::Load {
                if let Some(pointer_varnode) = inst.inputs.get(1) {
                    // Check if this could be a null pointer (concrete zero or tracked zero register)
                    if is_potentially_null_pointer_with_tracking(
                        pointer_varnode,
                        executor,
                        &zero_registers,
                    ) {
                        let vuln_desc = format!(
                            "Potential null pointer dereference at 0x{:x} (instruction {})",
                            current_addr, idx
                        );
                        log!(
                            executor.state.logger,
                            ">>> VULNERABILITY DETECTED: {}",
                            vuln_desc
                        );
                        return SpeculativeResult::VulnerabilityFound(
                            "NULL_DEREF_LOAD".to_string(),
                            current_addr,
                            vuln_desc,
                        );
                    }

                    // Also check if the address has symbolic parts (depends on input)
                    if has_symbolic_address(pointer_varnode, executor) {
                        let vuln_desc = format!(
                            "Potential null pointer dereference (symbolic address) at 0x{:x} (instruction {})",
                            current_addr, idx
                        );
                        log!(
                            executor.state.logger,
                            ">>> VULNERABILITY DETECTED: {}",
                            vuln_desc
                        );
                        return SpeculativeResult::VulnerabilityFound(
                            "NULL_DEREF_LOAD_SYMBOLIC".to_string(),
                            current_addr,
                            vuln_desc,
                        );
                    }
                }
            }

            // Check for STORE operations (potential null dereference)
            if inst.opcode == Opcode::Store {
                if let Some(pointer_varnode) = inst.inputs.get(1) {
                    if is_potentially_null_pointer_with_tracking(
                        pointer_varnode,
                        executor,
                        &zero_registers,
                    ) {
                        let vuln_desc = format!(
                            "Potential null pointer write at 0x{:x} (instruction {})",
                            current_addr, idx
                        );
                        log!(
                            executor.state.logger,
                            ">>> VULNERABILITY DETECTED: {}",
                            vuln_desc
                        );
                        return SpeculativeResult::VulnerabilityFound(
                            "NULL_DEREF_STORE".to_string(),
                            current_addr,
                            vuln_desc,
                        );
                    }

                    // Also check if the address has symbolic parts (depends on input)
                    if has_symbolic_address(pointer_varnode, executor) {
                        let vuln_desc = format!(
                            "Potential null pointer write (symbolic address) at 0x{:x} (instruction {})",
                            current_addr, idx
                        );
                        log!(
                            executor.state.logger,
                            ">>> VULNERABILITY DETECTED: {}",
                            vuln_desc
                        );
                        return SpeculativeResult::VulnerabilityFound(
                            "NULL_DEREF_STORE_SYMBOLIC".to_string(),
                            current_addr,
                            vuln_desc,
                        );
                    }
                }
            }

            // Track operations that set registers to zero AFTER checking for vulnerabilities
            // This includes both explicit zero-setting and LOADs that might load zero
            track_zero_registers(inst, &mut zero_registers, executor);

            // Check for division operations (potential division by zero)
            if matches!(
                inst.opcode,
                Opcode::IntDiv | Opcode::IntRem | Opcode::IntSDiv | Opcode::IntSRem
            ) {
                if let Some(divisor_varnode) = inst.inputs.get(1) {
                    if is_potentially_zero(divisor_varnode, executor) {
                        let vuln_desc = format!(
                            "Potential division by zero at 0x{:x} (instruction {})",
                            current_addr, idx
                        );
                        log!(
                            executor.state.logger,
                            ">>> VULNERABILITY DETECTED: {}",
                            vuln_desc
                        );
                        return SpeculativeResult::VulnerabilityFound(
                            "DIV_BY_ZERO".to_string(),
                            current_addr,
                            vuln_desc,
                        );
                    }
                }
            }

            // Check for branches to find next address
            if inst.opcode == Opcode::Branch {
                if let Some(target_varnode) = inst.inputs.get(0) {
                    if let Var::Memory(target_addr) = target_varnode.var {
                        current_addr = target_addr;
                        break;
                    }
                }
                // Can't determine next address
                return SpeculativeResult::DepthLimitReached;
            }

            // Check for conditional branches (take both paths recursively?)
            if inst.opcode == Opcode::CBranch {
                // For simplicity, just take the branch target path
                if let Some(target_varnode) = inst.inputs.get(0) {
                    if let Var::Memory(target_addr) = target_varnode.var {
                        current_addr = target_addr;
                        break;
                    }
                }
                return SpeculativeResult::DepthLimitReached;
            }

            // Check for return (end of path)
            if inst.opcode == Opcode::Return {
                log!(
                    executor.state.logger,
                    ">>> Speculative execution reached return at 0x{:x}",
                    current_addr
                );
                return SpeculativeResult::Safe;
            }
        }

        // Move to next instruction block if no control flow change
        match instructions_map.range((current_addr + 1)..).next() {
            Some((next_addr, _)) => current_addr = *next_addr,
            None => {
                log!(
                    executor.state.logger,
                    ">>> Speculative execution reached end of code at 0x{:x}",
                    current_addr
                );
                return SpeculativeResult::Safe;
            }
        }

        if instruction_count >= max_depth {
            log!(
                executor.state.logger,
                ">>> Speculative execution reached depth limit at 0x{:x}",
                current_addr
            );
            return SpeculativeResult::DepthLimitReached;
        }
    }

    SpeculativeResult::DepthLimitReached
}

/// Track register modifications during speculative execution
/// Removes registers from zero-tracking when they're modified, and adds back if set to zero
fn track_zero_registers(
    inst: &Inst,
    zero_registers: &mut std::collections::HashSet<u64>,
    _executor: &mut ConcolicExecutor,
) {
    // Since speculative execution doesn't actually execute instructions,
    // we start with registers that ARE zero in the current state,
    // and remove them when they're modified (unless we can prove they stay zero)

    if let Some(output) = &inst.output {
        if let Var::Register(out_offset, _out_size) = &output.var {
            let out_offset_u64 = *out_offset as u64;

            // Check for patterns that definitely set a register to zero:
            // 1. XOR reg, reg
            // 2. SUB reg, reg
            // 3. MOV reg, 0
            // 4. IntZExt/IntSExt of a zero register
            // 5. AND with 0
            let definitely_zero =
                // XOR reg, reg
                (matches!(inst.opcode, Opcode::IntXor) &&
                 inst.inputs.len() >= 2 &&
                 matches!((&inst.inputs[0].var, &inst.inputs[1].var),
                         (Var::Register(o1, _), Var::Register(o2, _)) if o1 == o2))
                ||
                // SUB reg, reg
                (matches!(inst.opcode, Opcode::IntSub) &&
                 inst.inputs.len() >= 2 &&
                 matches!((&inst.inputs[0].var, &inst.inputs[1].var),
                         (Var::Register(o1, _), Var::Register(o2, _)) if o1 == o2))
                ||
                // COPY 0
                (matches!(inst.opcode, Opcode::Copy) &&
                 inst.inputs.get(0).map_or(false, |input| {
                     if let Var::Const(val_str) = &input.var {
                         val_str.trim_start_matches("0x").parse::<u64>().unwrap_or(1) == 0 ||
                         u64::from_str_radix(val_str.trim_start_matches("0x"), 16).unwrap_or(1) == 0
                     } else {
                         false
                     }
                 }))
                ||
                // IntZExt/IntSExt of a zero register preserves zero
                (matches!(inst.opcode, Opcode::IntZExt | Opcode::IntSExt) &&
                 inst.inputs.get(0).map_or(false, |input| {
                     if let Var::Register(reg_offset, _) = &input.var {
                         zero_registers.contains(&(*reg_offset as u64))
                     } else {
                         false
                     }
                 }))
                ||
                // AND with 0
                (matches!(inst.opcode, Opcode::IntAnd) &&
                 inst.inputs.iter().any(|input| {
                     if let Var::Const(val_str) = &input.var {
                         val_str.trim_start_matches("0x").parse::<u64>().unwrap_or(1) == 0 ||
                         u64::from_str_radix(val_str.trim_start_matches("0x"), 16).unwrap_or(1) == 0
                     } else {
                         false
                     }
                 }));

            if definitely_zero {
                // Keep or add to zero_registers
                zero_registers.insert(out_offset_u64);
                log!(
                    _executor.state.logger,
                    ">>> Speculative: Added register offset 0x{:x} to zero_registers (now has {} zero regs)",
                    out_offset_u64, zero_registers.len()
                );
            } else {
                // Register is being modified to an unknown value, stop tracking it as zero
                if zero_registers.remove(&out_offset_u64) {
                    log!(
                        _executor.state.logger,
                        ">>> Speculative: Removed register offset 0x{:x} from zero_registers (now has {} zero regs)",
                        out_offset_u64, zero_registers.len()
                    );
                }
            }
        }
    }
}

/// Check if a varnode could potentially be a null pointer (with tracking)
fn is_potentially_null_pointer_with_tracking(
    varnode: &parser::parser::Varnode,
    executor: &mut ConcolicExecutor,
    zero_registers: &std::collections::HashSet<u64>,
) -> bool {
    // First check if we tracked this register as being set to zero
    if let Var::Register(offset, _) = &varnode.var {
        let is_zero = zero_registers.contains(&(*offset as u64));
        log!(
            executor.state.logger,
            ">>> Speculative: Checking register offset 0x{:x} for null - is_zero={}, zero_registers has {} entries",
            offset, is_zero, zero_registers.len()
        );
        if is_zero {
            return true;
        }
    }

    // Fall back to checking current state
    is_potentially_null_pointer(varnode, executor)
}

/// Check if a varnode could potentially be a null pointer (checks current state)
fn is_potentially_null_pointer(
    varnode: &parser::parser::Varnode,
    executor: &mut ConcolicExecutor,
) -> bool {
    match &varnode.var {
        // Constant zero is definitely null
        Var::Const(val_str) => {
            if let Ok(val) = u64::from_str_radix(val_str.trim_start_matches("0x"), 16) {
                val == 0
            } else if let Ok(val) = val_str.parse::<u64>() {
                val == 0
            } else {
                false
            }
        }

        // Check register value
        Var::Register(offset, _size) => {
            // Try to get current register value
            if let Ok(cpu_guard) = executor.state.cpu_state.lock() {
                if let Some(concolic_val) = cpu_guard.get_register_by_offset(*offset as u64, 64) {
                    // Check concrete value
                    if concolic_val.concrete.to_u64() == 0 {
                        return true;
                    }

                    // TODO: Check symbolic value with SMT solver
                    // For now, conservatively assume registers could be null if they involve symbolic vars
                    let symbolic_str = format!("{:?}", concolic_val.symbolic);
                    for (arg_name, _) in executor.function_symbolic_arguments.iter() {
                        if symbolic_str.contains(arg_name) {
                            // Symbolic value involving arguments - could be null
                            return true;
                        }
                    }
                }
            }
            false
        }

        // Unique/temp variables - would need to track their origin
        Var::Unique(_) => false,

        _ => false,
    }
}

/// Check if a varnode could potentially be zero (for division)
fn is_potentially_zero(varnode: &parser::parser::Varnode, executor: &mut ConcolicExecutor) -> bool {
    // Similar logic to null pointer check
    is_potentially_null_pointer(varnode, executor)
}

/// Check if a varnode has a symbolic address that depends on user input
/// This detects cases where the address being accessed could be controlled by input
fn has_symbolic_address(
    varnode: &parser::parser::Varnode,
    executor: &mut ConcolicExecutor,
) -> bool {
    match &varnode.var {
        // Check if register has symbolic information
        Var::Register(offset, _size) => {
            if let Ok(cpu_guard) = executor.state.cpu_state.lock() {
                if let Some(reg) = cpu_guard.registers.get(offset) {
                    // Check if it has symbolic value that depends on input (arg_)
                    let symbolic_ast = reg.get_symbolic_value();
                    let symbolic_str = format!("{:?}", symbolic_ast);
                    // Check if it contains "arg_" which indicates it depends on function arguments
                    return symbolic_str.contains("arg_");
                }
            }
            false
        }

        _ => false,
    }
}
