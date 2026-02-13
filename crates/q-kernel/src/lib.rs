// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Microkernel
//!
//! A minimal, secure microkernel for embedded devices with:
//!
//! - **Scheduler**: Priority-based preemptive task scheduling
//! - **Memory**: Static memory management with MPU protection
//! - **IPC**: Inter-process communication channels
//! - **Syscall**: System call interface
//! - **Arch**: Architecture-specific code (Cortex-M context switching, MPU)
//!
//! # Usage
//!
//! ```rust,ignore
//! use q_kernel::{init, start, scheduler, task::TaskPriority};
//!
//! // Initialize kernel
//! init().expect("Kernel init failed");
//!
//! // Add tasks
//! static mut TASK_STACK: [u8; 2048] = [0; 2048];
//! scheduler::add_task(
//!     my_task,
//!     unsafe { TASK_STACK.as_ptr() as u32 },
//!     2048,
//!     TaskPriority::Normal,
//!     "my_task"
//! ).expect("Failed to add task");
//!
//! // Start scheduler (never returns)
//! start();
//! ```

#![no_std]
#![warn(missing_docs)]
// Note: naked_functions feature removed - using global_asm! instead for stable Rust

pub mod scheduler;
pub mod memory;
pub mod ipc;
pub mod syscall;
pub mod task;
pub mod panic;
pub mod arch;

// Re-export commonly used types
pub use scheduler::{add_task, yield_now, sleep, sleep_ms, ticks, current_task};
pub use task::{TaskId, TaskState, TaskPriority, Task, TaskEntry};

use q_common::Error;

/// Configure kernel with custom CPU frequency and tick rate
///
/// # Arguments
/// * `cpu_freq_hz` - CPU frequency in Hz
/// * `tick_rate_hz` - Scheduler tick rate in Hz (typically 1000 for 1ms tick)
pub fn configure(cpu_freq_hz: u32, tick_rate_hz: u32) {
    scheduler::configure(cpu_freq_hz, tick_rate_hz);
}

/// Kernel initialization
///
/// Initializes all kernel subsystems:
/// - Memory manager
/// - Scheduler (with idle task)
/// - IPC channels
///
/// # Errors
/// Returns error if any subsystem initialization fails.
pub fn init() -> Result<(), Error> {
    // Initialize memory manager
    memory::init()?;

    // Initialize scheduler
    scheduler::init()?;

    // Initialize IPC
    ipc::init()?;

    Ok(())
}

/// Start the kernel (never returns)
///
/// Begins executing tasks. This function:
/// 1. Configures SysTick for preemption
/// 2. Finds the highest priority ready task
/// 3. Starts the first task
///
/// # Panics
/// Will loop forever if no tasks are registered.
pub fn start() -> ! {
    scheduler::start()
}

/// Kernel version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Kernel build info
pub const BUILD_INFO: &str = concat!(
    env!("CARGO_PKG_NAME"),
    " v",
    env!("CARGO_PKG_VERSION"),
    " - Qbitel EdgeOS Microkernel"
);
