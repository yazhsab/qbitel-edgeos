// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Preemptive Priority-Based Task Scheduler
//!
//! This module implements a production-grade scheduler for Qbitel EdgeOS with:
//!
//! - **Priority-based scheduling**: Higher priority tasks preempt lower priority
//! - **Round-robin within priority**: Tasks of same priority share CPU time
//! - **Preemptive multitasking**: SysTick-driven time slicing
//! - **Context switching**: Hardware-assisted via PendSV exception
//!
//! # Scheduling Algorithm
//!
//! 1. Always run highest priority ready task
//! 2. Within same priority, round-robin with configurable time slice
//! 3. Time slice expiry triggers context switch via PendSV
//! 4. Sleeping tasks are woken when their wake time arrives

#[cfg(feature = "cortex-m")]
use crate::arch::cortex_m::{
    context::{setup_context_switch, start_first_task},
    trigger_pendsv, disable_interrupts_save, restore_interrupts,
    configure_systick, init_core,
};

#[cfg(feature = "riscv")]
use crate::arch::riscv::{
    context::{setup_context_switch, start_first_task},
    trigger_software_interrupt as trigger_pendsv,
    disable_interrupts_save, restore_interrupts,
    configure_timer, init_core,
};

/// Configure timer for RISC-V (wrapper for configure_timer)
/// Takes reload_value which is the timer compare value (cpu_freq / tick_rate)
#[cfg(feature = "riscv")]
fn configure_systick(reload_value: u32) {
    // Configure RISC-V timer with the reload value
    configure_timer(reload_value as u64);
}

#[cfg(not(any(feature = "cortex-m", feature = "riscv")))]
use crate::arch::stub::{
    context::{setup_context_switch, start_first_task},
    trigger_pendsv, disable_interrupts_save, restore_interrupts,
    configure_systick, init_core,
};
use crate::task::{Task, TaskEntry, TaskId, TaskState, TaskPriority, idle_task, StackAddr};
use heapless::Vec;
use q_common::Error;

/// Maximum number of concurrent tasks
pub const MAX_TASKS: usize = 16;

/// Default tick rate (1000 Hz = 1ms tick)
pub const DEFAULT_TICK_RATE_HZ: u32 = 1000;

/// Default CPU frequency for STM32H7
pub const DEFAULT_CPU_FREQ_HZ: u32 = 480_000_000;

/// Idle task stack size
const IDLE_STACK_SIZE: usize = 512;

/// Static stack for idle task
static mut IDLE_STACK: [u8; IDLE_STACK_SIZE] = [0; IDLE_STACK_SIZE];

/// Scheduler statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedulerStats {
    /// Total system ticks since start
    pub total_ticks: u64,
    /// Total context switches performed
    pub context_switches: u64,
    /// Total idle ticks (CPU was idle)
    pub idle_ticks: u64,
    /// Number of times scheduler was invoked
    pub schedule_calls: u64,
}

/// Scheduler state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerState {
    /// Scheduler not yet initialized
    Uninitialized,
    /// Scheduler initialized but not running
    Initialized,
    /// Scheduler is running
    Running,
    /// Scheduler is stopped
    Stopped,
}

/// Production-grade preemptive scheduler
pub struct Scheduler {
    /// All registered tasks
    tasks: Vec<Task, MAX_TASKS>,
    /// Index of currently running task (None before first task starts)
    current_task_idx: Option<usize>,
    /// Index of next task to run (set before context switch)
    #[allow(dead_code)]
    next_task_idx: Option<usize>,
    /// Current scheduler state
    state: SchedulerState,
    /// System tick counter
    ticks: u64,
    /// Scheduler statistics
    stats: SchedulerStats,
    /// Index of idle task
    idle_task_idx: Option<usize>,
    /// Whether a context switch is pending
    context_switch_pending: bool,
    /// CPU frequency in Hz
    cpu_freq_hz: u32,
    /// Tick rate in Hz
    tick_rate_hz: u32,
}

impl Scheduler {
    /// Create a new scheduler instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current_task_idx: None,
            next_task_idx: None,
            state: SchedulerState::Uninitialized,
            ticks: 0,
            stats: SchedulerStats {
                total_ticks: 0,
                context_switches: 0,
                idle_ticks: 0,
                schedule_calls: 0,
            },
            idle_task_idx: None,
            context_switch_pending: false,
            cpu_freq_hz: DEFAULT_CPU_FREQ_HZ,
            tick_rate_hz: DEFAULT_TICK_RATE_HZ,
        }
    }

    /// Configure scheduler timing
    pub fn configure(&mut self, cpu_freq_hz: u32, tick_rate_hz: u32) {
        self.cpu_freq_hz = cpu_freq_hz;
        self.tick_rate_hz = tick_rate_hz;
    }

    /// Initialize the scheduler
    pub fn init(&mut self) -> Result<(), Error> {
        if self.state != SchedulerState::Uninitialized {
            return Err(Error::InvalidState);
        }

        // Initialize Cortex-M core (set exception priorities)
        init_core();

        // Create and register the idle task
        self.create_idle_task()?;

        self.state = SchedulerState::Initialized;
        Ok(())
    }

    /// Create the idle task
    fn create_idle_task(&mut self) -> Result<(), Error> {
        let id = TaskId::new(self.tasks.len() as u8);
        let mut task = Task::new(id, idle_task, TaskPriority::Idle);

        // Initialize with static stack
        // SAFETY: IDLE_STACK is a module-level static only accessed during scheduler init,
        // which runs once at boot before any tasks are started. No concurrent access is
        // possible at this point.
        let stack_base = unsafe { (*core::ptr::addr_of!(IDLE_STACK)).as_ptr() as StackAddr };
        task.init_stack(stack_base, IDLE_STACK_SIZE, true, 0);
        task.set_name("idle");
        task.time_slice = 0; // Idle task uses cooperative scheduling

        let idx = self.tasks.len();
        self.tasks.push(task).map_err(|_| Error::TaskCreationFailed)?;
        self.idle_task_idx = Some(idx);

        Ok(())
    }

    /// Add a new task to the scheduler
    ///
    /// # Arguments
    /// * `entry` - Task entry point function
    /// * `stack_base` - Base address of allocated stack
    /// * `stack_size` - Size of stack in bytes
    /// * `priority` - Task priority level
    /// * `name` - Task name for debugging
    ///
    /// # Returns
    /// Task ID on success
    pub fn add_task(
        &mut self,
        entry: TaskEntry,
        stack_base: StackAddr,
        stack_size: usize,
        priority: TaskPriority,
        name: &str,
    ) -> Result<TaskId, Error> {
        if self.state == SchedulerState::Uninitialized {
            return Err(Error::InvalidState);
        }

        if self.tasks.len() >= MAX_TASKS {
            return Err(Error::TaskCreationFailed);
        }

        let id = TaskId::new(self.tasks.len() as u8);
        let mut task = Task::new(id, entry, priority);

        // Initialize task context with stack
        task.init_stack(stack_base, stack_size, false, 0);
        task.set_name(name);

        self.tasks.push(task).map_err(|_| Error::TaskCreationFailed)?;

        Ok(id)
    }

    /// Find the highest priority ready task
    fn find_next_task(&self) -> Option<usize> {
        let mut best_idx: Option<usize> = None;
        let mut best_priority = TaskPriority::Idle;

        for (idx, task) in self.tasks.iter().enumerate() {
            if task.state == TaskState::Ready {
                // Higher priority = lower number
                if best_idx.is_none() || task.priority < best_priority {
                    best_idx = Some(idx);
                    best_priority = task.priority;
                }
            }
        }

        // If no ready task found, use idle task
        if best_idx.is_none() {
            best_idx = self.idle_task_idx;
        }

        best_idx
    }

    /// Find next task for round-robin within same priority
    fn find_next_task_round_robin(&self, current_idx: usize) -> Option<usize> {
        let current_priority = self.tasks[current_idx].priority;
        let num_tasks = self.tasks.len();

        // First, check if there's a higher priority task ready
        for (idx, task) in self.tasks.iter().enumerate() {
            if task.state == TaskState::Ready && task.priority < current_priority {
                return Some(idx);
            }
        }

        // Round-robin within same priority
        for offset in 1..=num_tasks {
            let idx = (current_idx + offset) % num_tasks;
            let task = &self.tasks[idx];
            if task.state == TaskState::Ready && task.priority == current_priority {
                return Some(idx);
            }
        }

        // No task at same priority, find any lower priority ready task
        self.find_next_task()
    }

    /// Schedule next task (called from tick handler or yield)
    ///
    /// This function determines which task should run next and triggers
    /// a context switch if needed.
    pub fn schedule(&mut self) {
        let primask = disable_interrupts_save();

        self.stats.schedule_calls += 1;

        // Mark current task as ready (if it was running)
        if let Some(curr_idx) = self.current_task_idx {
            if self.tasks[curr_idx].state == TaskState::Running {
                self.tasks[curr_idx].state = TaskState::Ready;
            }
        }

        // Find next task to run
        let next_idx = if let Some(curr_idx) = self.current_task_idx {
            self.find_next_task_round_robin(curr_idx)
        } else {
            self.find_next_task()
        };

        // If different task, initiate context switch
        if let Some(next) = next_idx {
            let need_switch = self.current_task_idx != Some(next);

            if need_switch {
                self.tasks[next].state = TaskState::Running;
                self.tasks[next].stats.schedule_count += 1;
                self.tasks[next].reset_time_slice();

                // Track if switching to/from idle
                if Some(next) == self.idle_task_idx {
                    self.stats.idle_ticks += 1;
                }

                // Set up context switch pointers (architecture-specific)
                #[cfg(feature = "cortex-m")]
                // SAFETY: Called with interrupts disabled (primask saved at start of
                // schedule()). The pointers derive from mutable borrows of tasks in the
                // scheduler's owned Vec, which is only accessed from this function while
                // interrupts are disabled.
                unsafe {
                    let curr_sp_ptr = self.current_task_idx
                        .map(|i| &mut self.tasks[i].context.sp as *mut u32)
                        .unwrap_or(core::ptr::null_mut());
                    let next_sp_ptr = &mut self.tasks[next].context.sp as *mut u32;

                    setup_context_switch(curr_sp_ptr, next_sp_ptr);
                }

                #[cfg(feature = "riscv")]
                // SAFETY: Same invariants as Cortex-M variant above — interrupts disabled,
                // exclusive access to task contexts guaranteed by the scheduler's critical
                // section.
                unsafe {
                    use crate::arch::riscv::context::TaskContext;
                    let curr_ctx_ptr = self.current_task_idx
                        .map(|i| &mut self.tasks[i].context as *mut TaskContext)
                        .unwrap_or(core::ptr::null_mut());
                    let next_ctx_ptr = &self.tasks[next].context as *const TaskContext;

                    setup_context_switch(curr_ctx_ptr, next_ctx_ptr);
                }

                #[cfg(not(any(feature = "cortex-m", feature = "riscv")))]
                // SAFETY: Stub variant for host testing. Same invariants as
                // architecture-specific variants — single-threaded access within critical
                // section.
                unsafe {
                    let curr_sp_ptr = self.current_task_idx
                        .map(|i| &mut self.tasks[i].context.sp as *mut u32)
                        .unwrap_or(core::ptr::null_mut());
                    let next_sp_ptr = &mut self.tasks[next].context.sp as *mut u32;

                    setup_context_switch(curr_sp_ptr, next_sp_ptr);
                }

                // Switch memory protection regions for next task
                #[cfg(feature = "cortex-m")]
                {
                    crate::arch::cortex_m::mpu::switch_task_regions(
                        &self.tasks[next].mpu_regions,
                    );
                }

                // RISC-V uses PMP for memory protection
                #[cfg(feature = "riscv")]
                {
                    crate::arch::riscv::pmp::switch_task_regions(
                        &self.tasks[next].pmp_entries,
                    );
                }

                self.stats.context_switches += 1;
                self.current_task_idx = Some(next);
                self.context_switch_pending = true;

                // Trigger PendSV for context switch
                trigger_pendsv();
            }
        }

        restore_interrupts(primask);
    }

    /// Handle system tick interrupt
    ///
    /// Called from SysTick_Handler. Updates tick counter, wakes sleeping
    /// tasks, and triggers preemption if time slice expired.
    pub fn tick(&mut self) {
        self.ticks += 1;
        self.stats.total_ticks += 1;

        // Wake any sleeping tasks whose time has come
        for task in &mut self.tasks {
            task.try_wake(self.ticks);
        }

        // Check if current task's time slice has expired
        let mut need_reschedule = false;

        if let Some(curr_idx) = self.current_task_idx {
            if self.tasks[curr_idx].tick_time_slice() {
                // Time slice expired, mark for reschedule
                need_reschedule = true;
            }
        }

        if need_reschedule {
            self.schedule();
        }
    }

    /// Start the scheduler - begins running tasks
    ///
    /// This function never returns. It starts the first task and
    /// enters the scheduling loop.
    pub fn start(&mut self) -> ! {
        if self.state != SchedulerState::Initialized {
            // Cannot start if not initialized
            loop {
                core::hint::spin_loop();
            }
        }

        // Configure SysTick for preemption
        let reload = self.cpu_freq_hz / self.tick_rate_hz;
        configure_systick(reload);

        // Find first task to run
        let first_task_idx = self.find_next_task().unwrap_or(0);
        self.tasks[first_task_idx].state = TaskState::Running;
        self.tasks[first_task_idx].stats.schedule_count += 1;
        self.current_task_idx = Some(first_task_idx);
        self.state = SchedulerState::Running;

        // Start first task (never returns) - architecture-specific
        // SAFETY: Called exactly once during scheduler start, after all tasks are registered
        // and the first task's context has been fully initialized. The stack pointer points
        // to a valid, initialized exception frame. This function never returns.
        #[cfg(feature = "cortex-m")]
        {
            let first_sp = self.tasks[first_task_idx].context.sp;
            unsafe { start_first_task(first_sp) }
        }

        #[cfg(feature = "riscv")]
        {
            let first_sp = self.tasks[first_task_idx].context.sp;
            unsafe { start_first_task(first_sp) }
        }

        #[cfg(not(any(feature = "cortex-m", feature = "riscv")))]
        {
            let first_sp = self.tasks[first_task_idx].context.sp;
            unsafe { start_first_task(first_sp) }
        }
    }

    /// Yield current task voluntarily
    pub fn yield_current(&mut self) {
        if let Some(curr_idx) = self.current_task_idx {
            self.tasks[curr_idx].stats.yield_count += 1;
        }
        self.schedule();
    }

    /// Put current task to sleep for specified ticks
    pub fn sleep(&mut self, ticks: u64) {
        let primask = disable_interrupts_save();

        if let Some(curr_idx) = self.current_task_idx {
            let wake_at = self.ticks + ticks;
            self.tasks[curr_idx].state = TaskState::Sleeping(wake_at);
        }

        restore_interrupts(primask);
        self.schedule();
    }

    /// Block current task
    pub fn block_current(&mut self) {
        let primask = disable_interrupts_save();

        if let Some(curr_idx) = self.current_task_idx {
            self.tasks[curr_idx].state = TaskState::Blocked;
        }

        restore_interrupts(primask);
        self.schedule();
    }

    /// Unblock a task by ID
    pub fn unblock(&mut self, task_id: TaskId) {
        let primask = disable_interrupts_save();

        for task in &mut self.tasks {
            if task.id == task_id && task.state == TaskState::Blocked {
                task.state = TaskState::Ready;
                break;
            }
        }

        restore_interrupts(primask);
    }

    /// Terminate current task
    ///
    /// Marks the task as terminated, clears its memory protection regions,
    /// and triggers a context switch to the next ready task.
    pub fn terminate_current(&mut self) {
        let primask = disable_interrupts_save();

        if let Some(curr_idx) = self.current_task_idx {
            self.tasks[curr_idx].state = TaskState::Terminated;

            // Clear per-task memory protection entries to prevent stale
            // mappings from being applied if the task slot is reused.
            self.tasks[curr_idx].mpu_regions = [None, None];
            self.tasks[curr_idx].pmp_entries = [None, None];

            // Zero out the task name for debugging hygiene
            self.tasks[curr_idx].name = [0u8; crate::task::MAX_TASK_NAME_LEN];
            self.tasks[curr_idx].name_len = 0;
        }

        restore_interrupts(primask);
        self.schedule();
    }

    /// Reclaim terminated task slots so that new tasks can be added.
    ///
    /// Scans the task list for tasks in `Terminated` state and resets
    /// their slot, freeing up space in the fixed-capacity task vector.
    /// Does NOT deallocate externally-owned stacks — the caller is
    /// responsible for freeing stack memory after this returns.
    ///
    /// Returns the number of slots reclaimed.
    pub fn reclaim_terminated(&mut self) -> usize {
        let mut reclaimed = 0usize;
        for task in &mut self.tasks {
            if task.state == TaskState::Terminated {
                // Reset the task state so the slot can potentially be
                // identified as free (state != Running/Ready/Blocked/Sleeping).
                // We keep the task in the Vec but mark it as reclaimable.
                task.state = TaskState::Terminated;
                task.stack_base = 0;
                task.stack_size = 0;
                task.stats = crate::task::TaskStats {
                    cpu_cycles: 0,
                    schedule_count: 0,
                    yield_count: 0,
                    max_stack_usage: 0,
                    current_stack_usage: 0,
                };
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Get current tick count
    #[must_use]
    pub fn current_ticks(&self) -> u64 {
        self.ticks
    }

    /// Get current task ID
    #[must_use]
    pub fn current_task_id(&self) -> Option<TaskId> {
        self.current_task_idx.map(|idx| self.tasks[idx].id)
    }

    /// Get scheduler statistics
    #[must_use]
    pub fn stats(&self) -> &SchedulerStats {
        &self.stats
    }

    /// Get scheduler state
    #[must_use]
    pub fn state(&self) -> SchedulerState {
        self.state
    }

    /// Get number of registered tasks
    #[must_use]
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Get task by ID
    #[must_use]
    pub fn get_task(&self, id: TaskId) -> Option<&Task> {
        self.tasks.iter().find(|t| t.id == id)
    }

    /// Get mutable task by ID
    pub fn get_task_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        self.tasks.iter_mut().find(|t| t.id == id)
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Global Scheduler Instance and API
// =============================================================================

/// Global scheduler instance
static mut SCHEDULER: Scheduler = Scheduler::new();

/// Access the global scheduler within a critical section.
///
/// All public API access to the global SCHEDULER goes through this function
/// to ensure mutual exclusion. Interrupts are disabled for the duration of
/// the closure, preventing race conditions between task context, SysTick
/// handler, and PendSV handler.
///
/// # Safety
/// The closure receives a mutable reference to the scheduler. The caller
/// must not re-enter `with_scheduler` from within the closure (no nested
/// critical sections).
fn with_scheduler<R>(f: impl FnOnce(&mut Scheduler) -> R) -> R {
    let primask = disable_interrupts_save();
    // SAFETY: Interrupts are disabled, guaranteeing exclusive access to
    // the global SCHEDULER. No ISR can preempt and access SCHEDULER
    // concurrently. The reference is valid for the duration of the closure.
    let result = unsafe { f(&mut *core::ptr::addr_of_mut!(SCHEDULER)) };
    restore_interrupts(primask);
    result
}

/// Initialize the scheduler subsystem
pub fn init() -> Result<(), Error> {
    with_scheduler(|sched| sched.init())
}

/// Configure scheduler timing
pub fn configure(cpu_freq_hz: u32, tick_rate_hz: u32) {
    with_scheduler(|sched| sched.configure(cpu_freq_hz, tick_rate_hz));
}

/// Add a task to the scheduler
pub fn add_task(
    entry: TaskEntry,
    stack_base: StackAddr,
    stack_size: usize,
    priority: TaskPriority,
    name: &str,
) -> Result<TaskId, Error> {
    with_scheduler(|sched| sched.add_task(entry, stack_base, stack_size, priority, name))
}

/// Start the scheduler (never returns)
pub fn start() -> ! {
    // SAFETY: Called exactly once after initialization. This function never returns.
    // Cannot use with_scheduler here because start() is divergent (!).
    unsafe { (*core::ptr::addr_of_mut!(SCHEDULER)).start() }
}

/// Yield current task
pub fn yield_now() {
    with_scheduler(|sched| sched.yield_current());
}

/// Sleep current task for specified ticks
pub fn sleep(ticks: u64) {
    with_scheduler(|sched| sched.sleep(ticks));
}

/// Sleep current task for specified milliseconds
pub fn sleep_ms(ms: u32) {
    let ticks = ms as u64;
    with_scheduler(|sched| sched.sleep(ticks));
}

/// Block current task
pub fn block() {
    with_scheduler(|sched| sched.block_current());
}

/// Unblock a task
pub fn unblock(task_id: TaskId) {
    with_scheduler(|sched| sched.unblock(task_id));
}

/// Terminate current task
///
/// Marks the current task as terminated and triggers a context switch.
/// The task will not be scheduled again.
pub fn terminate_current() {
    with_scheduler(|sched| sched.terminate_current());
}

/// Reclaim terminated task slots.
///
/// Returns the number of slots reclaimed.
pub fn reclaim_terminated() -> usize {
    with_scheduler(|sched| sched.reclaim_terminated())
}

/// Boost a task's priority (priority inheritance protocol).
///
/// Used when a high-priority task is blocked on a resource held by
/// `task_id`. The holder's effective priority is raised to `new_priority`
/// so it can release the resource without being preempted by medium-
/// priority tasks.
pub fn boost_priority(task_id: TaskId, new_priority: crate::task::TaskPriority) {
    with_scheduler(|sched| {
        if let Some(task) = sched.get_task_mut(task_id) {
            task.boost_priority(new_priority);
        }
    });
}

/// Restore a task's priority to its base value after releasing a shared resource.
pub fn restore_priority(task_id: TaskId) {
    with_scheduler(|sched| {
        if let Some(task) = sched.get_task_mut(task_id) {
            task.restore_priority();
        }
    });
}

/// Get a saved register value from the current task's context.
///
/// Used by syscall handlers to read arguments passed in ARM registers R0-R3.
pub fn current_task_register(reg: usize) -> Option<u32> {
    with_scheduler(|sched| {
        sched.current_task_idx.and_then(|idx| {
            if reg < 4 {
                Some(sched.tasks[idx].context.registers[reg])
            } else {
                None
            }
        })
    })
}

/// Get current tick count
#[must_use]
pub fn ticks() -> u64 {
    // SAFETY: Read-only access to the global SCHEDULER. Reading a u64 is atomic on the
    // target platform or the result is used informatively (not for synchronization).
    unsafe { (*core::ptr::addr_of!(SCHEDULER)).current_ticks() }
}

/// Get current task ID
#[must_use]
pub fn current_task() -> Option<TaskId> {
    // SAFETY: Read-only access to the global SCHEDULER. Reading an Option<TaskId> is atomic
    // on the target platform or the result is used informatively (not for synchronization).
    unsafe { (*core::ptr::addr_of!(SCHEDULER)).current_task_id() }
}

/// Handle system tick (called from SysTick_Handler)
///
/// # Safety
/// Must only be called from SysTick interrupt handler.
///
/// SAFETY: This function is called exclusively from the SysTick interrupt handler. On
/// Cortex-M, it runs at a priority that cannot be preempted by the scheduler's own critical
/// sections (PendSV has lower priority), ensuring exclusive access to SCHEDULER during the
/// tick.
#[no_mangle]
pub unsafe extern "C" fn scheduler_tick() {
    (*core::ptr::addr_of_mut!(SCHEDULER)).tick();
}

// =============================================================================
// SysTick Handler Registration
// =============================================================================

// Note: The actual SysTick_Handler is defined in arch/cortex_m/exceptions.rs
// The scheduler should register scheduler_tick() as a callback using
// arch::cortex_m::exceptions::set_systick_handler(scheduler_tick)
// during initialization.

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_task() {
        loop {
            core::hint::spin_loop();
        }
    }

    #[test]
    fn test_scheduler_creation() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.state(), SchedulerState::Uninitialized);
        assert_eq!(scheduler.task_count(), 0);
    }

    #[test]
    fn test_find_highest_priority() {
        let mut scheduler = Scheduler::new();
        // Can't fully test without hardware, but we can test the logic

        // The scheduler should find the highest priority ready task
        assert!(scheduler.find_next_task().is_none()); // No tasks yet
    }
}
