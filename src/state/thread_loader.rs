/// Thread loader - loads multi-thread state from GDB dumps
use crate::concolic::ConcolicVar;
use crate::state::cpu_state::CpuState;
use crate::state::thread_manager::ThreadManager;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use z3::ast::BV;

#[derive(Debug, Serialize, Deserialize)]
struct ThreadDump {
    tid: u64,
    regs: HashMap<String, u64>,
    fs_base: u64,
    gs_base: u64,
    #[serde(default)]
    backtrace: String,
    #[serde(default)]
    is_at_main: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThreadState {
    tid: u64,
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThreadsIndex {
    main_tid: u64,
    thread_count: usize,
    threads: Vec<u64>,
    #[serde(default)]
    thread_states: Vec<ThreadState>,
}

/// Load all thread dumps from the initialization_data/threads directory
pub fn load_threads_from_dumps<'ctx>(
    threads_dir: &Path,
    template_cpu: &CpuState<'ctx>,
    thread_manager: &mut ThreadManager<'ctx>,
    logger: &mut dyn Write,
    ctx: &'ctx z3::Context,
) -> Result<()> {
    if !threads_dir.exists() || !threads_dir.is_dir() {
        writeln!(
            logger,
            "Thread dumps directory not found: {:?}. Skipping multi-thread loading.",
            threads_dir
        )
        .ok();
        return Ok(());
    }

    // Try to load the index file to determine main thread and valid thread list
    let index_path = threads_dir.join("threads_index.json");
    let (main_tid, valid_tids) = if index_path.exists() {
        let index_content =
            fs::read_to_string(&index_path).context("Failed to read threads_index.json")?;
        let index: ThreadsIndex =
            serde_json::from_str(&index_content).context("Failed to parse threads_index.json")?;

        writeln!(
            logger,
            "Found thread index: main_tid={}, {} thread(s)",
            index.main_tid, index.thread_count
        )
        .ok();

        // Log thread states if available
        if !index.thread_states.is_empty() {
            writeln!(logger, "Thread states:").ok();
            for ts in &index.thread_states {
                writeln!(logger, "  - TID {}: {}", ts.tid, ts.state).ok();
            }
        }

        // Use the thread list from the index to filter which dumps to load
        let valid_set: HashSet<u64> = index.threads.iter().copied().collect();
        (Some(index.main_tid), Some(valid_set))
    } else {
        writeln!(
            logger,
            "No threads_index.json found, will load all thread dumps"
        )
        .ok();
        (None, None)
    };

    // Find all thread dump files
    let mut thread_files: Vec<_> = fs::read_dir(threads_dir)
        .context("Failed to read threads directory")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.path().is_file()
                && entry
                    .path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("thread_") && n.ends_with(".json"))
                    .unwrap_or(false)
        })
        .collect();

    if thread_files.is_empty() {
        writeln!(
            logger,
            "No thread dump files found. Using single-threaded mode."
        )
        .ok();
        return Ok(());
    }

    thread_files.sort_by_key(|e| e.path());

    writeln!(
        logger,
        "Found {} total thread dump(s) on disk",
        thread_files.len()
    )
    .ok();

    let mut loaded_count = 0;

    // Load each thread dump
    for entry in thread_files {
        let path = entry.path();
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read thread dump: {:?}", path))?;

        let dump: ThreadDump = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse thread dump: {:?}", path))?;

        // If we have a valid TID set, skip dumps that aren't in it
        if let Some(ref valid_set) = valid_tids {
            if !valid_set.contains(&dump.tid) {
                // Skip this thread - it's from an old run
                continue;
            }
        }

        let thread_desc = if dump.is_at_main {
            format!(
                "  Loading TID {} (fs_base=0x{:x}, gs_base=0x{:x}) [AT MAIN]",
                dump.tid, dump.fs_base, dump.gs_base
            )
        } else {
            format!(
                "  Loading TID {} (fs_base=0x{:x}, gs_base=0x{:x})",
                dump.tid, dump.fs_base, dump.gs_base
            )
        };
        writeln!(logger, "{}", thread_desc).ok();

        // Create a new CPU state for this thread
        let mut cpu_state = template_cpu.clone();

        // Apply register values from dump
        apply_register_values(&mut cpu_state, &dump.regs, ctx, logger)?;

        // Set FS base (offset 0x110)
        if dump.fs_base != 0 {
            let fs_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                dump.fs_base,
                BV::from_u64(ctx, dump.fs_base, 64),
                ctx,
            );
            cpu_state
                .set_register_value_by_offset(0x110, fs_concolic, 64)
                .map_err(|e| anyhow::anyhow!("Failed to set FS base: {}", e))?;
        }

        // Set GS base (offset 0x118)
        if dump.gs_base != 0 {
            let gs_concolic = ConcolicVar::new_concrete_and_symbolic_int(
                dump.gs_base,
                BV::from_u64(ctx, dump.gs_base, 64),
                ctx,
            );
            cpu_state
                .set_register_value_by_offset(0x118, gs_concolic, 64)
                .map_err(|e| anyhow::anyhow!("Failed to set GS base: {}", e))?;
        }

        // Determine if this is the current/main thread
        let is_current = main_tid.map(|m| m == dump.tid).unwrap_or(false);

        // Add thread to the manager
        thread_manager
            .create_thread_from_dump(dump.tid, cpu_state, dump.fs_base, dump.gs_base, is_current)
            .with_context(|| format!("Failed to create thread {} from dump", dump.tid))?;

        loaded_count += 1;
    }

    writeln!(
        logger,
        "Successfully loaded {} thread(s) from dumps",
        loaded_count
    )
    .ok();

    Ok(())
}

/// Apply register values from the dump to the CPU state
fn apply_register_values<'ctx>(
    cpu_state: &mut CpuState<'ctx>,
    regs: &HashMap<String, u64>,
    ctx: &'ctx z3::Context,
    logger: &mut dyn Write,
) -> Result<()> {
    // Map register names to their offsets and sizes
    let reg_map: HashMap<&str, (u64, u32)> = [
        ("rax", (0x0, 64)),
        ("rbx", (0x28, 64)),
        ("rcx", (0x8, 64)),
        ("rdx", (0x10, 64)),
        ("rsi", (0x30, 64)),
        ("rdi", (0x38, 64)),
        ("rbp", (0x18, 64)),
        ("rsp", (0x20, 64)),
        ("r8", (0x80, 64)),
        ("r9", (0x88, 64)),
        ("r10", (0x90, 64)),
        ("r11", (0x98, 64)),
        ("r12", (0xa0, 64)),
        ("r13", (0xa8, 64)),
        ("r14", (0xb0, 64)),
        ("r15", (0xb8, 64)),
        ("rip", (0x288, 64)),
        ("eflags", (0x108, 64)),
    ]
    .iter()
    .cloned()
    .collect();

    for (reg_name, &value) in regs {
        if let Some(&(offset, size)) = reg_map.get(reg_name.as_str()) {
            let concolic_val = ConcolicVar::new_concrete_and_symbolic_int(
                value,
                BV::from_u64(ctx, value, size),
                ctx,
            );

            cpu_state
                .set_register_value_by_offset(offset, concolic_val, size)
                .map_err(|e| anyhow::anyhow!("Failed to set register {}: {}", reg_name, e))?;
        } else {
            writeln!(
                logger,
                "    Warning: Unknown register '{}' in dump",
                reg_name
            )
            .ok();
        }
    }

    Ok(())
}
