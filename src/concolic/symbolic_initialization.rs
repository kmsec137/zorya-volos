
use std::{io::Write, sync::Arc};

use regex::Regex;
use z3::ast::{Ast, BV};
use crate::{concolic::{ConcolicExecutor, ConcolicVar, ConcreteVar, SymbolicVar}, state::{function_signatures::TypeDesc, memory_x86_64::MemoryValue}};

macro_rules! log {
    ($logger:expr, $($arg:tt)*) => {{
        writeln!($logger, $($arg)*).unwrap();
    }};
}

// Helper function to check if a register specification is a stack location
pub fn is_stack_location(reg_spec: &str) -> bool {
    reg_spec.starts_with("STACK+") || reg_spec.starts_with("STACK-")
}

// Helper function to parse stack offset from "STACK+0x8" format
pub fn parse_stack_offset(reg_spec: &str) -> Option<i64> {
    if let Some(offset_str) = reg_spec.strip_prefix("STACK+") {
        if let Ok(offset) = i64::from_str_radix(offset_str.strip_prefix("0x").unwrap_or(offset_str), 16) {
            return Some(offset);
        }
    } else if let Some(offset_str) = reg_spec.strip_prefix("STACK-") {
        if let Ok(offset) = i64::from_str_radix(offset_str.strip_prefix("0x").unwrap_or(offset_str), 16) {
            return Some(-offset);
        }
    }
    None
}

// ────────────────────────────────────────────────────────────
//  String   (two regs)
// ────────────────────────────────────────────────────────────
pub fn initialize_string_argument<'a>(
    arg_name: &str,
    regs: &[&str], // exactly 2 regs
    conc: &mut Vec<ConcreteVar>,
    exec: &mut ConcolicExecutor<'a>,
) {
    let ctx = exec.context;
    let cpu = &mut exec.state.cpu_state.lock().unwrap();
    let log = &mut exec.state.logger;
    let solver = &mut exec.solver;

    // Go swap: if first reg is RDX/R8/R10 → (len,ptr)
    let (ptr_reg, len_reg) = match regs {
        [r1, r2] if *r1 == "RDX" || *r1 == "R8" || *r1 == "R10" => (*r2, *r1),
        [r1, r2] => (*r1, *r2),
        _ => {
            log!(log, "BAD string reg list {:?}", regs);
            return;
        }
    };

    let bv_ptr = BV::fresh_const(ctx, &format!("{}__ptr", arg_name), 64);
    let bv_len = BV::fresh_const(ctx, &format!("{}__len", arg_name), 64);

    exec.function_symbolic_arguments.insert(
        format!("{}__ptr", arg_name),
        SymbolicVar::Int(bv_ptr.clone()),
    );
    exec.function_symbolic_arguments.insert(
        format!("{}__len", arg_name),
        SymbolicVar::Int(bv_len.clone()),
    );

    // ptr ≠ 0, 8-byte aligned  |  len ≥ 1
    solver.assert(
        &bv_ptr
            .bvand(&BV::from_u64(ctx, 7, 64))
            ._eq(&BV::from_u64(ctx, 0, 64)),
    );
    solver.assert(&bv_ptr._eq(&BV::from_u64(ctx, 0, 64)).not());
    solver.assert(&bv_len.bvuge(&BV::from_u64(ctx, 1, 64)));

    // helper: write symbolic BV into a register
    let mut write = |reg: &str, bv: &BV<'a>| {
        if let Some(off) = cpu.resolve_offset_from_register_name(reg) {
            let w = cpu.register_map.get(&off).map(|(_, w)| *w).unwrap_or(64);
            if let Some(orig) = cpu.get_register_by_offset(off, w) {
                conc.push(orig.concrete.clone());
                let cv = ConcolicVar {
                    concrete: orig.concrete.clone(),
                    symbolic: SymbolicVar::Int(bv.clone()),
                    ctx,
                };
                cpu.set_register_value_by_offset(off, cv, w).ok();
            }
        } else {
            log!(log, "WARN: unknown reg {}", reg);
        }
    };

    write(ptr_reg, &bv_ptr);
    write(len_reg, &bv_len);
    log!(
        log,
        "Init Go string '{}'  ptr:{} len:{}",
        arg_name,
        ptr_reg,
        len_reg
    );
}

// Enhanced helper function for single-register argument initialization that handles stack locations
pub fn initialize_single_register_argument<'a>(
    arg_name: &str,
    reg_spec: &str,
    arg_type: &str,
    concrete_values: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    if is_stack_location(reg_spec) {
        // Handle stack location
        initialize_stack_argument(arg_name, reg_spec, arg_type, concrete_values, executor);
    } else {
        // Handle regular register
        initialize_register_argument(arg_name, reg_spec, arg_type, concrete_values, executor);
    }
}

// Handle regular register initialization
pub fn initialize_register_argument<'a>(
    arg_name: &str,
    reg_name: &str,
    arg_type: &str,
    concrete_values: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    let cpu = &mut executor.state.cpu_state.lock().unwrap();
    if let Some(offset) = cpu.resolve_offset_from_register_name(reg_name) {
        let bit_width = cpu.register_map.get(&offset).map(|(_, w)| *w).unwrap_or(64);
        if let Some(original) = cpu.get_register_by_offset(offset, bit_width) {
            let orig_conc = original.concrete.clone();
            concrete_values.push(orig_conc.clone());

            let bv = BV::fresh_const(
                executor.context,
                &format!("{}_{}", arg_name, reg_name),
                bit_width,
            );
            executor
                .function_symbolic_arguments
                .insert(arg_name.to_string(), SymbolicVar::Int(bv.clone()));

            let sym = SymbolicVar::Int(bv.clone());
            let conc = ConcolicVar {
                concrete: orig_conc,
                symbolic: sym,
                ctx: executor.context,
            };

            match cpu.set_register_value_by_offset(offset, conc, bit_width) {
                Ok(()) => log!(
                    executor.state.logger,
                    "Initialized '{}' => {} (0x{:x}) as symbolic {}",
                    arg_name,
                    reg_name,
                    offset,
                    arg_type
                ),
                Err(e) => log!(executor.state.logger, "Failed to set {}: {}", reg_name, e),
            }
        }
    } else {
        log!(
            executor.state.logger,
            "WARNING: unknown register '{}' for arg {}",
            reg_name,
            arg_name
        );
    }
}

// Handle stack location initialization
pub fn initialize_stack_argument<'a>(
    arg_name: &str,
    stack_spec: &str,
    arg_type: &str,
    concrete_values: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    if let Some(stack_offset) = parse_stack_offset(stack_spec) {
        // Get current RSP value
        if let Some(rsp_reg) = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64) {
            let rsp_value = rsp_reg.concrete.to_u64();
            let stack_address = (rsp_value as i64 + stack_offset) as u64;
            
            log!(
                executor.state.logger,
                "Calculating stack address: RSP(0x{:x}) + offset({}) = 0x{:x}",
                rsp_value,
                stack_offset,
                stack_address
            );

            // Read current value from stack
            match executor.state.memory.read_u64(stack_address, &mut executor.state.logger) {
                Ok(current_stack_value) => {
                    concrete_values.push(current_stack_value.concrete.clone());

                    // Create symbolic variable for stack location
                    let bv = BV::fresh_const(
                        executor.context,
                        &format!("{}_{}", arg_name, stack_spec.replace("+", "plus").replace("-", "minus")),
                        64,
                    );
                    
                    executor
                        .function_symbolic_arguments
                        .insert(arg_name.to_string(), SymbolicVar::Int(bv.clone()));

                    // Create concolic variable with original concrete value but new symbolic value
                    let stack_concolic_mem = MemoryValue::new(
                        current_stack_value.concrete.to_u64(),
                        bv.clone(),
                        64,
                    );

                    // Write symbolic value back to stack
                    match executor.state.memory.write_u64(stack_address, &stack_concolic_mem) {
                        Ok(()) => log!(
                            executor.state.logger,
                            "Initialized '{}' => {} (0x{:x}) as symbolic {} on stack",
                            arg_name,
                            stack_spec,
                            stack_address,
                            arg_type
                        ),
                        Err(e) => log!(
                            executor.state.logger,
                            "Failed to write symbolic value to stack address 0x{:x}: {}",
                            stack_address,
                            e
                        ),
                    }
                },
                Err(e) => log!(
                    executor.state.logger,
                    "Failed to read from stack address 0x{:x}: {}",
                    stack_address,
                    e
                ),
            }
        } else {
            log!(
                executor.state.logger,
                "WARNING: Could not get RSP register value for stack calculation"
            );
        }
    } else {
        log!(
            executor.state.logger,
            "WARNING: Could not parse stack offset from '{}'",
            stack_spec
        );
    }
}

// ────────────────────────────────────────────────────────────
//  Multi-register slice ([]T)
// ────────────────────────────────────────────────────────────
// Enhanced slice initialization that handles mixed register/stack specifications
pub fn initialize_slice_argument<'a>(
    arg_name: &str,
    arg_type: &str,
    regs: &[&str],
    conc: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
) {
    if regs.len() < 2 {
        log!(
            executor.state.logger,
            "Slice '{}' has <2 locations: {:?}",
            arg_name,
            regs
        );
        return;
    }

    let ctx = executor.context;
    let ptr_spec = regs[0];
    let len_spec = regs[1];

    let inner_ty = &arg_type[2..];
    let elem_desc = if inner_ty.starts_with('[') {
        // Handle array type, e.g., "[3]byte" or "[4]int"
        if let Some(caps) = Regex::new(r"^\[(\d+)\](.+)$").unwrap().captures(inner_ty) {
            TypeDesc::Array {
                element: Box::new(TypeDesc::Primitive(caps[2].trim().into())),
                count: Some(caps[1].parse::<u64>().unwrap()),
            }
        } else {
            TypeDesc::Unknown(inner_ty.into())
        }
    } else {
        TypeDesc::Primitive(inner_ty.to_string())
    };

    let default_len = 3;
    let slice_sv = SymbolicVar::make_symbolic_slice(ctx, arg_name, &elem_desc, default_len);
    executor
        .function_symbolic_arguments
        .insert(arg_name.into(), slice_sv.clone());

    if let SymbolicVar::Slice(slice) = &slice_sv {
        // Handle solver assertions
        {
            let solver = &mut executor.solver;
            solver.assert(&slice.pointer._eq(&BV::from_u64(ctx, 0, 64)).not());
            solver.assert(
                &slice
                    .pointer
                    .bvand(&BV::from_u64(ctx, 7, 64))
                    ._eq(&BV::from_u64(ctx, 0, 64)),
            );
            solver.assert(&slice.length.bvuge(&BV::from_u64(ctx, 1, 64)));
        }

        // Write pointer (can be register or stack)
        write_symbolic_to_location(ptr_spec, &slice.pointer, conc, executor, "ptr");
        
        // Write length (can be register or stack)
        write_symbolic_to_location(len_spec, &slice.length, conc, executor, "len");

        // Handle capacity if present
        if regs.len() >= 3 {
            let cap_bv = BV::fresh_const(ctx, &format!("{}_cap", arg_name), 64);
            {
                let solver = &mut executor.solver;
                solver.assert(&cap_bv.bvuge(&slice.length));
            }
            write_symbolic_to_location(regs[2], &cap_bv, conc, executor, "cap");
        }

        log!(
            executor.state.logger,
            "Initialized slice '{}' ptr:{} len:{} with UNIFIED variables",
            arg_name,
            ptr_spec,
            len_spec
        );
    }
}

// Helper function to write a symbolic BV to either a register or stack location
fn write_symbolic_to_location<'a>(
    location_spec: &str,
    symbolic_bv: &BV<'a>,
    conc: &mut Vec<ConcreteVar>,
    executor: &mut ConcolicExecutor<'a>,
    field_name: &str,
) {
    if is_stack_location(location_spec) {
        // Handle stack location
        if let Some(stack_offset) = parse_stack_offset(location_spec) {
            if let Some(rsp_reg) = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64) {
                let rsp_value = rsp_reg.concrete.to_u64();
                let stack_address = (rsp_value as i64 + stack_offset) as u64;
                
                if let Ok(current_val) = executor.state.memory.read_u64(stack_address, &mut executor.state.logger) {
                    conc.push(current_val.concrete.clone());

                    let stack_concolic_mem = MemoryValue::new(
                        current_val.concrete.to_u64(),
                        symbolic_bv.clone(),
                        64,
                    );

                    executor.state.memory.write_u64(stack_address, &stack_concolic_mem).ok();
                    log!(
                        executor.state.logger,
                        "Wrote {} to stack location {} (0x{:x})",
                        field_name,
                        location_spec,
                        stack_address
                    );
                }
            }
        }
    } else {
        // Handle register location
        let cpu = &mut executor.state.cpu_state.lock().unwrap();
        if let Some(offset) = cpu.resolve_offset_from_register_name(location_spec) {
            let bit_width = cpu.register_map.get(&offset).map(|(_, w)| *w).unwrap_or(64);
            if let Some(original) = cpu.get_register_by_offset(offset, bit_width) {
                conc.push(original.concrete.clone());
                
                let reg_concolic = ConcolicVar {
                    concrete: original.concrete.clone(),
                    symbolic: SymbolicVar::Int(symbolic_bv.clone()),
                    ctx: executor.context,
                };
                
                cpu.set_register_value_by_offset(offset, reg_concolic, bit_width).ok();
                log!(
                    executor.state.logger,
                    "Wrote {} to register {} (0x{:x})",
                    field_name,
                    location_spec,
                    offset
                );
            }
        }
    }
}

// ────────────────────────────────────────────────────────────
//  Single-register slice (rare)
// ────────────────────────────────────────────────────────────
pub fn initialize_single_register_slice<'a>(
    arg_name: &str,
    arg_type: &str,
    reg: &str,
    conc: &mut Vec<ConcreteVar>,
    exec: &mut ConcolicExecutor<'a>,
) {
    let ctx = exec.context;

    let elem_td = TypeDesc::Primitive(arg_type[2..].to_string());
    let sv = SymbolicVar::make_symbolic_slice(ctx, arg_name, &elem_td, 2);
    exec.function_symbolic_arguments
        .insert(arg_name.into(), sv.clone());

    if let SymbolicVar::Slice(slice) = &sv {
        // Handle solver assertions
        {
            let solver = &mut exec.solver;
            solver.assert(
                &slice
                    .pointer
                    .bvand(&BV::from_u64(ctx, 7, 64))
                    ._eq(&BV::from_u64(ctx, 0, 64)),
            );
            solver.assert(&slice.pointer._eq(&BV::from_u64(ctx, 0, 64)).not());
            solver.assert(&slice.length.bvuge(&BV::from_u64(ctx, 1, 64)));
        }

        // Handle CPU state
        {
            let cpu = &mut exec.state.cpu_state.lock().unwrap();
            if let Some(off) = cpu.resolve_offset_from_register_name(reg) {
                let w = cpu.register_map.get(&off).map(|(_, w)| *w).unwrap_or(64);
                if let Some(orig) = cpu.get_register_by_offset(off, w) {
                    conc.push(orig.concrete.clone());
                    let cv = ConcolicVar {
                        concrete: orig.concrete.clone(),
                        symbolic: SymbolicVar::Int(slice.pointer.clone()),
                        ctx,
                    };
                    cpu.set_register_value_by_offset(off, cv, w).ok();
                }
            } else {
                log!(
                    exec.state.logger,
                    "WARN: unknown reg '{}' for '{}'",
                    reg,
                    arg_name
                );
            }
        }
    }
}

/// Initializes the memory contents pointed to by slices symbolically
/// This should be called after all slice arguments have been initialized
pub fn initialize_slice_memory_contents<'a>(
    executor: &mut ConcolicExecutor<'a>,
    function_args: &[(String, String, String)],
) {
    log!(
        executor.state.logger,
        "=== INITIALIZING SLICE MEMORY CONTENTS ==="
    );

    for (arg_name, reg_name, arg_type) in function_args {
        // Only process slice types
        if !arg_type.starts_with("[]") {
            continue;
        }

        log!(
            executor.state.logger,
            "Processing slice memory for '{}' of type '{}'",
            arg_name,
            arg_type
        );

        // Get the slice's symbolic variables
        if let Some(slice_sym_var) = executor.function_symbolic_arguments.get(arg_name) {
            if let SymbolicVar::Slice(_slice) = slice_sym_var {
                // Get concrete values from registers to determine memory layout
                let (ptr_concrete, len_concrete, _cap_concrete) = 
                    extract_slice_concrete_values(executor, reg_name);

                if let (Some(ptr_addr), Some(slice_len)) = (ptr_concrete, len_concrete) {
                    // Determine element size and type
                    let (element_size, element_type) = parse_slice_element_info(arg_type);
                    
                    log!(
                        executor.state.logger,
                        "Slice '{}': ptr=0x{:x}, len={}, element_size={}, element_type='{}'",
                        arg_name,
                        ptr_addr,
                        slice_len,
                        element_size,
                        element_type
                    );

                    // Initialize memory for each element in the slice
                    for i in 0..slice_len {
                        let element_addr = ptr_addr + (i * element_size);
                        
                        // Create symbolic variable for this element
                        let element_var_name = format!("{}[{}]", arg_name, i);
                        
                        initialize_slice_element_memory(
                            executor,
                            &element_var_name,
                            element_addr,
                            element_size,
                            &element_type,
                        );
                    }
                } else {
                    log!(
                        executor.state.logger,
                        "WARNING: Could not extract concrete values for slice '{}' (ptr={:?}, len={:?})",
                        arg_name,
                        ptr_concrete,
                        len_concrete
                    );
                }
            }
        }
    }

    log!(
        executor.state.logger,
        "=== FINISHED SLICE MEMORY INITIALIZATION ==="
    );
}

/// Extract concrete pointer, length, and capacity values from slice registers
fn extract_slice_concrete_values<'a>(
    executor: &ConcolicExecutor<'a>,
    reg_spec: &str,
) -> (Option<u64>, Option<u64>, Option<u64>) {
    if !reg_spec.contains(',') {
        // Single register case - only pointer available
        if let Some(ptr_val) = get_concrete_value_from_location(executor, reg_spec) {
            return (Some(ptr_val), None, None);
        }
        return (None, None, None);
    }

    let regs: Vec<&str> = reg_spec.split(',').collect();
    
    let ptr_concrete = if regs.len() >= 1 {
        get_concrete_value_from_location(executor, regs[0])
    } else {
        None
    };
    
    let len_concrete = if regs.len() >= 2 {
        get_concrete_value_from_location(executor, regs[1])
    } else {
        None
    };
    
    let cap_concrete = if regs.len() >= 3 {
        get_concrete_value_from_location(executor, regs[2])
    } else {
        None
    };

    (ptr_concrete, len_concrete, cap_concrete)
}

/// Get concrete value from either a register or stack location
fn get_concrete_value_from_location<'a>(
    executor: &ConcolicExecutor<'a>,
    location_spec: &str,
) -> Option<u64> {
    if is_stack_location(location_spec) {
        // Handle stack location
        if let Some(stack_offset) = parse_stack_offset(location_spec) {
            if let Some(rsp_reg) = executor.state.cpu_state.lock().unwrap().get_register_by_offset(0x20, 64) {
                let rsp_value = rsp_reg.concrete.to_u64();
                let stack_address = (rsp_value as i64 + stack_offset) as u64;
                
                if let Ok(stack_val) = executor.state.memory.read_u64(stack_address, &mut executor.state.logger.clone()) {
                    return Some(stack_val.concrete.to_u64());
                }
            }
        }
    } else {
        // Handle register location
        let cpu = executor.state.cpu_state.lock().unwrap();
        if let Some(offset) = cpu.resolve_offset_from_register_name(location_spec) {
            let bit_width = cpu.register_map.get(&offset).map(|(_, w)| *w).unwrap_or(64);
            if let Some(reg_val) = cpu.get_register_by_offset(offset, bit_width) {
                return Some(reg_val.concrete.to_u64());
            }
        }
    }
    None
}

/// Parse slice element information from type string
fn parse_slice_element_info(slice_type: &str) -> (u64, String) {
    let inner_type = &slice_type[2..]; // Remove "[]" prefix
    
    // Handle array types like "[32]byte"
    if inner_type.starts_with('[') {
        if let Some(caps) = Regex::new(r"^\[(\d+)\](.+)$").unwrap().captures(inner_type) {
            let array_size: u64 = caps[1].parse().unwrap_or(1);
            let element_type = caps[2].trim().to_string();
            let base_size = get_type_size(&element_type);
            
            // For [][32]byte, this is an array of 32 bytes, so total size is 32 * 1 = 32
            let total_size = array_size * base_size;
            
            return (total_size, inner_type.to_string());
        }
    }
    
    // Handle primitive types
    let size = get_type_size(inner_type);
    (size, inner_type.to_string())
}

/// Get the size in bytes for a Go type
fn get_type_size(type_name: &str) -> u64 {
    match type_name {
        "byte" | "uint8" | "int8" => 1,
        "uint16" | "int16" => 2,
        "uint32" | "int32" | "float32" => 4,
        "uint64" | "int64" | "float64" | "int" | "uint" | "uintptr" => 8,
        "string" => 16, // ptr (8) + len (8)
        "bool" => 1,
        _ => {
            // For unknown types, assume pointer size
            8
        }
    }
}

/// Initialize a single slice element in memory
fn initialize_slice_element_memory<'a>(
    executor: &mut ConcolicExecutor<'a>,
    element_name: &str,
    element_addr: u64,
    element_size: u64,
    element_type: &str,
) {
    log!(
        executor.state.logger,
        "Initializing slice element '{}' at 0x{:x} (size={}, type='{}')",
        element_name,
        element_addr,
        element_size,
        element_type
    );

    // Check if this memory address is valid
    if !executor.state.memory.is_valid_address(element_addr) {
        log!(
            executor.state.logger,
            "WARNING: Invalid memory address 0x{:x} for slice element '{}' - skipping",
            element_addr,
            element_name
        );
        return;
    }

    // Check if the entire element range is valid
    let end_addr = element_addr + element_size - 1;
    if !executor.state.memory.is_valid_address(end_addr) {
        log!(
            executor.state.logger,
            "WARNING: Memory range 0x{:x}-0x{:x} not fully valid for slice element '{}' - skipping",
            element_addr,
            end_addr,
            element_name
        );
        return;
    }

    // Ensure element_size is reasonable (not too large)
    if element_size > 1024 {
        log!(
            executor.state.logger,
            "WARNING: Element size {} too large for slice element '{}' - skipping",
            element_size,
            element_name
        );
        return;
    }

    // Handle different element sizes - read_value only supports up to 128 bits (16 bytes)
    let bit_size = (element_size * 8) as u32;
    
    if element_size <= 16 {
        // Use read_value for small elements (≤ 128 bits)
        match executor.state.memory.read_value(element_addr, bit_size, &mut executor.state.logger.clone()) {
            Ok(current_value) => {
                log!(
                    executor.state.logger,
                    "Successfully read current value from 0x{:x}: concrete=0x{:x}",
                    element_addr,
                    current_value.concrete.to_u64()
                );

                // Create fresh symbolic variable for this element
                let element_bv = BV::fresh_const(
                    executor.context,
                    &format!("slice_elem_{}", element_name.replace("[", "_").replace("]", "_")),
                    bit_size,
                );

                // Add to tracked symbolic arguments
                executor.function_symbolic_arguments.insert(
                    element_name.to_string(),
                    SymbolicVar::Int(element_bv.clone()),
                );

                // Create memory value with original concrete data but new symbolic variable
                let symbolic_memory_value = MemoryValue::new(
                    current_value.concrete.to_u64(),
                    element_bv.clone(),
                    bit_size,
                );

                // Write symbolic value back to memory
                match executor.state.memory.write_value(element_addr, &symbolic_memory_value) {
                    Ok(()) => {
                        log!(
                            executor.state.logger,
                            "✓ Successfully initialized slice element '{}' at 0x{:x} with fresh symbolic variable",
                            element_name,
                            element_addr
                        );
                    },
                    Err(e) => {
                        log!(
                            executor.state.logger,
                            "✗ Failed to write symbolic value for slice element '{}' at 0x{:x}: {}",
                            element_name,
                            element_addr,
                            e
                        );
                    }
                }
            },
            Err(e) => {
                log!(
                    executor.state.logger,
                    "✗ Failed to read current value for slice element '{}' at 0x{:x} (size={}): {}",
                    element_name,
                    element_addr,
                    element_size,
                    e
                );
            }
        }
    } else {
        // For large elements (>16 bytes), use read_bytes and create symbolic value manually
        log!(
            executor.state.logger,
            "Large element ({}bytes) - using byte-level initialization",
            element_size
        );

        match executor.state.memory.read_bytes(element_addr, element_size as usize) {
            Ok(concrete_bytes) => {
                log!(
                    executor.state.logger,
                    "Successfully read {} bytes from 0x{:x}: {:02x?}...",
                    concrete_bytes.len(),
                    element_addr,
                    &concrete_bytes[..std::cmp::min(8, concrete_bytes.len())] // Show first 8 bytes
                );

                // Create fresh symbolic variable for this element
                let element_bv = BV::fresh_const(
                    executor.context,
                    &format!("slice_elem_{}", element_name.replace("[", "_").replace("]", "_")),
                    bit_size,
                );

                // Add to tracked symbolic arguments
                executor.function_symbolic_arguments.insert(
                    element_name.to_string(),
                    SymbolicVar::Int(element_bv.clone()),
                );

                // Write symbolic bytes back to memory using write_bytes
                // Create symbolic bytes - each byte gets a portion of the symbolic variable
                let symbolic_bytes: Vec<Option<Arc<BV>>> = (0..element_size)
                    .map(|i| {
                        let byte_start = (i * 8) as u32;
                        let byte_end = std::cmp::min(byte_start + 7, bit_size - 1);
                        let byte_bv = element_bv.extract(byte_end, byte_start);
                        Some(Arc::new(byte_bv))
                    })
                    .collect();

                // Write back to memory using the low-level write_memory function
                match executor.state.memory.write_memory(element_addr, &concrete_bytes, &symbolic_bytes) {
                    Ok(()) => {
                        log!(
                            executor.state.logger,
                            "✓ Successfully initialized large slice element '{}' at 0x{:x} ({} bytes) with fresh symbolic variable",
                            element_name,
                            element_addr,
                            element_size
                        );
                    },
                    Err(e) => {
                        log!(
                            executor.state.logger,
                            "✗ Failed to write symbolic bytes for slice element '{}' at 0x{:x}: {}",
                            element_name,
                            element_addr,
                            e
                        );
                    }
                }
            },
            Err(e) => {
                log!(
                    executor.state.logger,
                    "✗ Failed to read bytes for large slice element '{}' at 0x{:x}: {}",
                    element_name,
                    element_addr,
                    e
                );
            }
        }
    }
}