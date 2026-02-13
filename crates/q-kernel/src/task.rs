// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Task management for Qbitel EdgeOS Microkernel
//!
//! This module provides task structures and management for the preemptive
//! multitasking kernel. Tasks represent independent units of execution
//! with their own stack, context, and scheduling parameters.

#[cfg(feature = "cortex-m")]
use crate::arch::cortex_m::context::TaskContext;

#[cfg(feature = "riscv")]
use crate::arch::riscv::context::TaskContext;

#[cfg(not(any(feature = "cortex-m", feature = "riscv")))]
use crate::arch::stub::TaskContext;

// Architecture-specific address/pointer types
/// Stack pointer type (architecture-specific)
#[cfg(feature = "cortex-m")]
pub type StackAddr = u32;

#[cfg(feature = "riscv")]
pub type StackAddr = usize;

#[cfg(not(any(feature = "cortex-m", feature = "riscv")))]
pub type StackAddr = u32;

/// Maximum task name length
pub const MAX_TASK_NAME_LEN: usize = 16;

/// Task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskId(pub u8);

impl TaskId {
    /// Invalid task ID (used for "no task")
    pub const INVALID: TaskId = TaskId(0xFF);

    /// Create a new task ID
    #[must_use]
    pub const fn new(id: u8) -> Self {
        Self(id)
    }

    /// Check if this is a valid task ID
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.0 != 0xFF
    }
}

/// Task state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is ready to run and waiting for CPU
    Ready,
    /// Task is currently running on the CPU
    Running,
    /// Task is sleeping until the specified tick count
    Sleeping(u64),
    /// Task is blocked waiting for a resource (IPC, mutex, etc.)
    Blocked,
    /// Task is suspended (manually paused)
    Suspended,
    /// Task has terminated and is awaiting cleanup
    Terminated,
}

impl TaskState {
    /// Check if task can be scheduled
    #[must_use]
    pub const fn is_runnable(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Check if task is alive (not terminated)
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        !matches!(self, Self::Terminated)
    }
}

/// Task priority levels (lower number = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TaskPriority {
    /// Highest priority - real-time critical (interrupts, crypto)
    RealTime = 0,
    /// High priority - system services
    High = 1,
    /// Normal priority - application tasks
    Normal = 2,
    /// Low priority - background tasks
    Low = 3,
    /// Idle priority - only runs when nothing else can
    Idle = 4,
}

impl Default for TaskPriority {
    fn default() -> Self {
        Self::Normal
    }
}

impl From<u8> for TaskPriority {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::RealTime,
            1 => Self::High,
            2 => Self::Normal,
            3 => Self::Low,
            _ => Self::Idle,
        }
    }
}

/// Task statistics for monitoring
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskStats {
    /// Total CPU cycles consumed
    pub cpu_cycles: u64,
    /// Number of times this task was scheduled
    pub schedule_count: u64,
    /// Number of times this task yielded voluntarily
    pub yield_count: u64,
    /// Maximum stack usage (high water mark)
    pub max_stack_usage: u32,
    /// Current stack usage
    pub current_stack_usage: u32,
}

/// Task configuration for creation
#[derive(Debug, Clone, Copy)]
pub struct TaskConfig {
    /// Task priority
    pub priority: TaskPriority,
    /// Stack size in bytes
    pub stack_size: usize,
    /// Whether task runs in privileged mode
    pub privileged: bool,
    /// Time slice in ticks (0 = cooperative, no preemption within priority)
    pub time_slice: u32,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            priority: TaskPriority::Normal,
            stack_size: 2048,
            privileged: false,
            time_slice: 10, // 10 ticks default time slice
        }
    }
}

/// Task entry function type (C calling convention for ARM compatibility)
pub type TaskEntry = extern "C" fn();

/// Raw MPU region data for fast context-switch writes
///
/// Stores pre-computed RBAR and RASR values that can be written
/// directly to MPU registers during a context switch.
#[derive(Debug, Clone, Copy)]
pub struct MpuRegionRaw {
    /// MPU Region Base Address Register value
    pub rbar: u32,
    /// MPU Region Attribute and Size Register value
    pub rasr: u32,
}

/// Per-task MPU regions (2 slots: stack + data)
///
/// `[0]` = Region 3 (task stack), `[1]` = Region 4 (task data).
/// `None` means the corresponding region is disabled for this task.
pub type TaskMpuRegions = [Option<MpuRegionRaw>; 2];

/// Pre-computed PMP entry for fast context-switch writes (RISC-V)
///
/// Stores the pmpaddr value and pmpcfg byte that can be written
/// directly to PMP CSRs during a context switch.
#[derive(Debug, Clone, Copy)]
pub struct PmpEntryRaw {
    /// PMP address register value (pre-shifted)
    pub pmpaddr: usize,
    /// PMP configuration byte (permissions | address mode | lock)
    pub pmpcfg: u8,
}

/// Maximum per-task PMP entries (stack + data regions)
pub const MAX_TASK_PMP_ENTRIES: usize = 2;

/// Per-task PMP entries for RISC-V memory protection
///
/// `[0]` = task stack region, `[1]` = task data region.
/// `None` means the corresponding PMP entry is disabled for this task.
pub type TaskPmpEntries = [Option<PmpEntryRaw>; MAX_TASK_PMP_ENTRIES];

/// Task descriptor containing all task state
pub struct Task {
    /// Unique task identifier
    pub id: TaskId,
    /// Current task state
    pub state: TaskState,
    /// Task context (registers, stack pointer)
    pub context: TaskContext,
    /// Task entry point function
    pub entry: TaskEntry,
    /// Effective task priority level (may be boosted by priority inheritance)
    pub priority: TaskPriority,
    /// Original (base) priority — used to restore priority after inheritance ends
    pub base_priority: TaskPriority,
    /// Stack base address (lowest address)
    pub stack_base: StackAddr,
    /// Stack size in bytes
    pub stack_size: usize,
    /// Time slice remaining (for round-robin within priority)
    pub time_slice_remaining: u32,
    /// Time slice allocation
    pub time_slice: u32,
    /// Task statistics
    pub stats: TaskStats,
    /// Task name (for debugging)
    pub name: [u8; MAX_TASK_NAME_LEN],
    /// Name length
    pub name_len: usize,
    /// Per-task MPU regions (stack + data, ARM Cortex-M)
    pub mpu_regions: TaskMpuRegions,
    /// Per-task PMP entries (stack + data, RISC-V)
    pub pmp_entries: TaskPmpEntries,
}

impl Task {
    /// Create a new task (not yet initialized)
    #[must_use]
    pub const fn new(id: TaskId, entry: TaskEntry, priority: TaskPriority) -> Self {
        Self {
            id,
            state: TaskState::Ready,
            context: TaskContext::new(),
            entry,
            priority,
            base_priority: priority,
            stack_base: 0,
            stack_size: 0,
            time_slice_remaining: 10,
            time_slice: 10,
            stats: TaskStats {
                cpu_cycles: 0,
                schedule_count: 0,
                yield_count: 0,
                max_stack_usage: 0,
                current_stack_usage: 0,
            },
            name: [0u8; MAX_TASK_NAME_LEN],
            name_len: 0,
            mpu_regions: [None, None],
            pmp_entries: [None, None],
        }
    }

    /// Set per-task MPU regions (ARM Cortex-M)
    pub fn set_mpu_regions(&mut self, regions: TaskMpuRegions) {
        self.mpu_regions = regions;
    }

    /// Set per-task PMP entries (RISC-V)
    pub fn set_pmp_entries(&mut self, entries: TaskPmpEntries) {
        self.pmp_entries = entries;
    }

    /// Temporarily boost this task's effective priority (priority inheritance).
    ///
    /// If `new_priority` is higher (numerically lower) than the current effective
    /// priority, the task's `priority` is updated. The original priority is
    /// preserved in `base_priority` and can be restored via [`restore_priority`].
    pub fn boost_priority(&mut self, new_priority: TaskPriority) {
        if (new_priority as u8) < (self.priority as u8) {
            self.priority = new_priority;
        }
    }

    /// Restore the task's priority to its original (base) value.
    ///
    /// Called when the resource causing priority inheritance is released.
    pub fn restore_priority(&mut self) {
        self.priority = self.base_priority;
    }

    /// Check whether this task currently has an inherited (boosted) priority.
    pub fn is_priority_boosted(&self) -> bool {
        (self.priority as u8) < (self.base_priority as u8)
    }

    /// Initialize task with stack
    ///
    /// # Arguments
    /// * `stack_base` - Base address of allocated stack (lowest address)
    /// * `stack_size` - Size of stack in bytes
    /// * `privileged` - Whether task runs in privileged mode
    /// * `arg` - Argument to pass to task (in R0/A0)
    pub fn init_stack(&mut self, stack_base: StackAddr, stack_size: usize, privileged: bool, arg: StackAddr) {
        self.stack_base = stack_base;
        self.stack_size = stack_size;

        // Stack grows down, so top is base + size
        let stack_top = stack_base + stack_size as StackAddr;

        // Initialize the context with the stack
        self.context.init_stack(stack_top, self.entry, arg, privileged);
    }

    /// Set task name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(MAX_TASK_NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    /// Get task name as string slice
    #[must_use]
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("???")
    }

    /// Calculate current stack usage
    pub fn update_stack_usage(&mut self) {
        // Stack grows down, so usage = top - current_sp
        let stack_top = self.stack_base + self.stack_size as StackAddr;
        let usage = stack_top.saturating_sub(self.context.sp as StackAddr);
        self.stats.current_stack_usage = usage as u32;
        if usage as u32 > self.stats.max_stack_usage {
            self.stats.max_stack_usage = usage as u32;
        }
    }

    /// Check if stack is close to overflow
    #[must_use]
    pub fn is_stack_critical(&self) -> bool {
        // Critical if less than 128 bytes remaining
        let _stack_top = self.stack_base + self.stack_size as StackAddr;
        let remaining = (self.context.sp as StackAddr).saturating_sub(self.stack_base);
        remaining < 128
    }

    /// Reset time slice to full allocation
    pub fn reset_time_slice(&mut self) {
        self.time_slice_remaining = self.time_slice;
    }

    /// Decrement time slice, returns true if expired
    pub fn tick_time_slice(&mut self) -> bool {
        if self.time_slice == 0 {
            // Cooperative scheduling, never expires
            return false;
        }
        self.time_slice_remaining = self.time_slice_remaining.saturating_sub(1);
        self.time_slice_remaining == 0
    }

    /// Wake task from sleep if current tick >= wake_at
    pub fn try_wake(&mut self, current_tick: u64) -> bool {
        if let TaskState::Sleeping(wake_at) = self.state {
            if current_tick >= wake_at {
                self.state = TaskState::Ready;
                return true;
            }
        }
        false
    }
}

/// Idle task function - runs when no other tasks are ready
#[no_mangle]
pub extern "C" fn idle_task() {
    loop {
        // SAFETY: The WFI instruction is always safe to execute. It puts the processor
        // into a low-power state until an interrupt occurs. The nomem/nostack options are
        // correct as WFI does not access memory or the stack.
        #[cfg(target_arch = "arm")]
        unsafe {
            // Wait for interrupt (low power)
            core::arch::asm!("wfi", options(nomem, nostack));
        }

        #[cfg(not(target_arch = "arm"))]
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_id() {
        let id = TaskId::new(5);
        assert_eq!(id.0, 5);
        assert!(id.is_valid());
        assert!(!TaskId::INVALID.is_valid());
    }

    #[test]
    fn test_task_state() {
        assert!(TaskState::Ready.is_runnable());
        assert!(!TaskState::Running.is_runnable());
        assert!(!TaskState::Blocked.is_runnable());
        assert!(TaskState::Ready.is_alive());
        assert!(!TaskState::Terminated.is_alive());
    }

    #[test]
    fn test_task_priority() {
        assert!(TaskPriority::RealTime < TaskPriority::Normal);
        assert!(TaskPriority::Normal < TaskPriority::Low);
    }

    #[test]
    fn test_task_name() {
        extern "C" fn dummy_entry() {}
        let mut task = Task::new(TaskId::new(0), dummy_entry, TaskPriority::Normal);
        task.set_name("test_task");
        assert_eq!(task.name_str(), "test_task");
    }

    #[test]
    fn test_time_slice() {
        extern "C" fn dummy_entry() {}
        let mut task = Task::new(TaskId::new(0), dummy_entry, TaskPriority::Normal);
        task.time_slice = 3;
        task.time_slice_remaining = 3;

        assert!(!task.tick_time_slice()); // 2 remaining
        assert!(!task.tick_time_slice()); // 1 remaining
        assert!(task.tick_time_slice());  // 0 - expired
    }

    #[test]
    fn test_mpu_regions_default_none() {
        extern "C" fn dummy_entry() {}
        let task = Task::new(TaskId::new(0), dummy_entry, TaskPriority::Normal);
        assert!(task.mpu_regions[0].is_none());
        assert!(task.mpu_regions[1].is_none());
    }

    #[test]
    fn test_set_mpu_regions() {
        extern "C" fn dummy_entry() {}
        let mut task = Task::new(TaskId::new(0), dummy_entry, TaskPriority::Normal);

        let region = MpuRegionRaw {
            rbar: 0x2000_0000 | (3 << 0) | (1 << 4), // base + region 3 + VALID
            rasr: 0x0300_0027, // example RASR value
        };
        task.set_mpu_regions([Some(region), None]);

        assert!(task.mpu_regions[0].is_some());
        assert!(task.mpu_regions[1].is_none());
        assert_eq!(task.mpu_regions[0].unwrap().rbar & 0xFFFF_FFE0, 0x2000_0000);
    }
}
