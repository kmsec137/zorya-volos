use crate::state::cpu_state::CpuState;
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use z3::Context;

/// Represents an OS thread in the Go runtime
/// This simulates a Go 'm' (machine/OS thread)
#[derive(Debug, Clone)]
pub struct OSThread<'ctx> {
    /// Thread ID (TID) - matches Linux TID
    pub tid: u64,

    /// Parent thread ID (the thread that created this one via clone)
    pub parent_tid: u64,

    /// CPU state for this thread (registers)
    pub cpu_state: CpuState<'ctx>,

    /// Stack pointer at thread creation
    pub stack_pointer: u64,

    /// Thread-local storage FS base
    pub fs_base: u64,

    /// Thread-local storage GS base
    pub gs_base: u64,

    /// Entry point (RIP) where this thread should start executing
    pub entry_point: u64,

    /// Thread status
    pub status: ThreadStatus,

    /// Clone flags used to create this thread
    pub clone_flags: u64,

    /// Child TID pointer (for CLONE_CHILD_SETTID)
    pub child_tid_ptr: Option<u64>,

    /// Child clear TID pointer (for CLONE_CHILD_CLEARTID)
    pub child_cleartid_ptr: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadStatus {
    /// Thread is ready to run
    Ready,

    /// Thread is currently running
    Running,

    /// Thread is blocked/sleeping
    Blocked,

    /// Thread has exited
    Exited(i32), // exit code
}

impl<'ctx> OSThread<'ctx> {
    /// Create a new OS thread from a parent thread via clone
    pub fn new_from_clone(
        tid: u64,
        parent_tid: u64,
        parent_cpu: &CpuState<'ctx>,
        stack_pointer: u64,
        entry_point: u64,
        tls_base: u64,
        clone_flags: u64,
        child_tid_ptr: Option<u64>,
        child_cleartid_ptr: Option<u64>,
        ctx: &'ctx Context,
    ) -> Result<Self> {
        // Clone the parent's CPU state
        let mut cpu_state = parent_cpu.clone();

        // Set up the new thread's stack pointer (RSP = 0x20)
        let (rsp_offset, rsp_size) = (0x20u64, 64u32);
        let rsp_symbolic = z3::ast::BV::from_u64(ctx, stack_pointer, rsp_size);
        let rsp_concolic = crate::concolic::ConcolicVar::new_concrete_and_symbolic_int(
            stack_pointer,
            rsp_symbolic,
            ctx,
        );
        cpu_state
            .set_register_value_by_offset(rsp_offset, rsp_concolic, rsp_size)
            .map_err(|e| anyhow!("Failed to set RSP: {}", e))?;

        // Set up the entry point (RIP = 0x118)
        let (rip_offset, rip_size) = (0x118u64, 64u32);
        let rip_symbolic = z3::ast::BV::from_u64(ctx, entry_point, rip_size);
        let rip_concolic = crate::concolic::ConcolicVar::new_concrete_and_symbolic_int(
            entry_point,
            rip_symbolic,
            ctx,
        );
        cpu_state
            .set_register_value_by_offset(rip_offset, rip_concolic, rip_size)
            .map_err(|e| anyhow!("Failed to set RIP: {}", e))?;

        // Set up TLS if provided (FS_OFFSET = 0x110)
        if tls_base != 0 {
            let (fs_offset, fs_size) = (0x110u64, 64u32);
            let fs_symbolic = z3::ast::BV::from_u64(ctx, tls_base, fs_size);
            let fs_concolic = crate::concolic::ConcolicVar::new_concrete_and_symbolic_int(
                tls_base,
                fs_symbolic,
                ctx,
            );
            cpu_state
                .set_register_value_by_offset(fs_offset, fs_concolic, fs_size)
                .map_err(|e| anyhow!("Failed to set FS_OFFSET: {}", e))?;
        }

        // Set return value (RAX = 0x0) to 0 for the child thread
        let (rax_offset, rax_size) = (0x0u64, 64u32);
        let rax_symbolic = z3::ast::BV::from_u64(ctx, 0, rax_size);
        let rax_concolic =
            crate::concolic::ConcolicVar::new_concrete_and_symbolic_int(0, rax_symbolic, ctx);
        cpu_state
            .set_register_value_by_offset(rax_offset, rax_concolic, rax_size)
            .map_err(|e| anyhow!("Failed to set RAX: {}", e))?;

        Ok(OSThread {
            tid,
            parent_tid,
            cpu_state,
            stack_pointer,
            fs_base: tls_base,
            gs_base: 0, // Not set during clone, only via arch_prctl
            entry_point,
            status: ThreadStatus::Ready,
            clone_flags,
            child_tid_ptr,
            child_cleartid_ptr,
        })
    }
}

/// Manages all OS threads in the execution
#[derive(Debug)]
pub struct ThreadManager<'ctx> {
    /// Map of TID to OSThread
    pub threads: BTreeMap<u64, OSThread<'ctx>>,

    /// Current active thread TID
    pub current_tid: u64,

    /// Next TID to assign (incremented for each new thread)
    next_tid: u64,

    /// Z3 context reference
    ctx: &'ctx Context,
}

impl<'ctx> ThreadManager<'ctx> {
    /// Create a new ThreadManager with an initial main thread
    pub fn new(initial_tid: u64, initial_cpu: CpuState<'ctx>, ctx: &'ctx Context) -> Self {
        let mut threads = BTreeMap::new();

        // Create the main thread
        let main_thread = OSThread {
            tid: initial_tid,
            parent_tid: 0, // Main thread has no parent
            cpu_state: initial_cpu,
            stack_pointer: 0, // Will be set from RSP
            fs_base: 0,
            gs_base: 0,
            entry_point: 0,
            status: ThreadStatus::Running,
            clone_flags: 0,
            child_tid_ptr: None,
            child_cleartid_ptr: None,
        };

        threads.insert(initial_tid, main_thread);

        ThreadManager {
            threads,
            current_tid: initial_tid,
            next_tid: initial_tid + 1,
            ctx,
        }
    }

    /// Get the current running thread
    pub fn current_thread(&self) -> Result<&OSThread<'ctx>> {
        self.threads
            .get(&self.current_tid)
            .ok_or_else(|| anyhow!("Current thread {} not found", self.current_tid))
    }

    /// Get the current running thread (mutable)
    pub fn current_thread_mut(&mut self) -> Result<&mut OSThread<'ctx>> {
        self.threads
            .get_mut(&self.current_tid)
            .ok_or_else(|| anyhow!("Current thread {} not found", self.current_tid))
    }

    /// Clone the current thread to create a new OS thread
    pub fn clone_thread(
        &mut self,
        stack_pointer: u64,
        entry_point: u64,
        tls_base: u64,
        clone_flags: u64,
        child_tid_ptr: Option<u64>,
        child_cleartid_ptr: Option<u64>,
    ) -> Result<u64> {
        let parent_tid = self.current_tid;
        let new_tid = self.next_tid;
        self.next_tid += 1;

        // Get parent thread's CPU state
        let parent_cpu = &self
            .threads
            .get(&parent_tid)
            .ok_or_else(|| anyhow!("Parent thread {} not found", parent_tid))?
            .cpu_state;

        // Create the new thread
        let new_thread = OSThread::new_from_clone(
            new_tid,
            parent_tid,
            parent_cpu,
            stack_pointer,
            entry_point,
            tls_base,
            clone_flags,
            child_tid_ptr,
            child_cleartid_ptr,
            self.ctx,
        )?;

        println!(
            "[THREAD] Created new OS thread TID={} from parent TID={}, entry=0x{:x}, stack=0x{:x}, tls=0x{:x}",
            new_tid, parent_tid, entry_point, stack_pointer, tls_base
        );

        self.threads.insert(new_tid, new_thread);

        Ok(new_tid)
    }

    /// Switch to a different thread
    pub fn switch_to_thread(&mut self, tid: u64) -> Result<()> {
        if !self.threads.contains_key(&tid) {
            return Err(anyhow!("Thread {} does not exist", tid));
        }

        // Mark current thread as ready (if not exited)
        if let Some(current) = self.threads.get_mut(&self.current_tid) {
            if current.status == ThreadStatus::Running {
                current.status = ThreadStatus::Ready;
            }
        }

        // Mark new thread as running
        if let Some(new_thread) = self.threads.get_mut(&tid) {
            new_thread.status = ThreadStatus::Running;
        }

        println!(
            "[THREAD] Switching from TID={} to TID={}",
            self.current_tid, tid
        );
        self.current_tid = tid;

        Ok(())
    }

    /// Mark a thread as exited
    pub fn exit_thread(&mut self, tid: u64, exit_code: i32) -> Result<()> {
        if let Some(thread) = self.threads.get_mut(&tid) {
            thread.status = ThreadStatus::Exited(exit_code);
            println!("[THREAD] Thread TID={} exited with code {}", tid, exit_code);
            Ok(())
        } else {
            Err(anyhow!("Thread {} not found", tid))
        }
    }

    /// Get all thread IDs
    pub fn all_tids(&self) -> Vec<u64> {
        self.threads.keys().copied().collect()
    }

    /// Get count of non-exited threads
    pub fn active_thread_count(&self) -> usize {
        self.threads
            .values()
            .filter(|t| !matches!(t.status, ThreadStatus::Exited(_)))
            .count()
    }

    /// Create a new thread from a dump (registers + TLS bases)
    /// Used when loading multi-thread state from GDB dumps
    pub fn create_thread_from_dump(
        &mut self,
        tid: u64,
        cpu_state: CpuState<'ctx>,
        fs_base: u64,
        gs_base: u64,
        is_current: bool,
    ) -> Result<()> {
        if self.threads.contains_key(&tid) {
            return Err(anyhow!("Thread {} already exists", tid));
        }

        // Get stack pointer and entry point from CPU state
        let stack_pointer = cpu_state
            .get_register_by_offset(0x20, 64) // RSP
            .map(|v| v.concrete.to_u64())
            .unwrap_or(0);

        let entry_point = cpu_state
            .get_register_by_offset(0x288, 64) // RIP
            .map(|v| v.concrete.to_u64())
            .unwrap_or(0);

        let thread = OSThread {
            tid,
            parent_tid: 0, // Unknown from dump
            cpu_state,
            stack_pointer,
            fs_base,
            gs_base,
            entry_point,
            status: if is_current {
                ThreadStatus::Running
            } else {
                ThreadStatus::Ready
            },
            clone_flags: 0,
            child_tid_ptr: None,
            child_cleartid_ptr: None,
        };

        self.threads.insert(tid, thread);

        if is_current {
            self.current_tid = tid;
        }

        println!(
            "[THREAD] Loaded TID={} from dump (fs_base=0x{:x}, gs_base=0x{:x})",
            tid, fs_base, gs_base
        );

        Ok(())
    }
}
