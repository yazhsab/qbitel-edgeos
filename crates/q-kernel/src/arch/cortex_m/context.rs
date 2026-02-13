// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! ARM Cortex-M Context Switching
//!
//! This module implements hardware context switching for ARM Cortex-M processors
//! using the PendSV exception handler.
//!
//! # Context Layout
//!
//! When an exception occurs, the hardware automatically stacks:
//! - xPSR (Program Status Register)
//! - PC (Program Counter / Return Address)
//! - LR (Link Register)
//! - R12
//! - R3, R2, R1, R0
//!
//! The software must manually save:
//! - R4-R11 (callee-saved registers)
//! - LR (EXC_RETURN value, for FPU context detection)
//!
//! For FPU-enabled cores (Cortex-M4F, M7, M33), additional registers:
//! - S0-S15 (caller-saved FPU registers) - auto-stacked
//! - S16-S31 (callee-saved FPU registers) - manual save
//! - FPSCR (FPU Status and Control Register)
//!
//! # Memory Layout
//!
//! Stack grows downward. After exception entry with software context save:
//!
//! ```text
//! High Address
//! ┌───────────────┐ <- Original PSP
//! │     xPSR      │ (auto-stacked by hardware)
//! │      PC       │
//! │      LR       │
//! │      R12      │
//! │      R3       │
//! │      R2       │
//! │      R1       │
//! │      R0       │
//! ├───────────────┤ <- PSP after exception
//! │   [S0-S15]    │ (auto-stacked if FPU active)
//! │   [FPSCR]     │
//! ├───────────────┤
//! │  EXC_RETURN   │ (software saved)
//! │      R4       │
//! │      R5       │
//! │      R6       │
//! │      R7       │
//! │      R8       │
//! │      R9       │
//! │      R10      │
//! │      R11      │
//! │   [S16-S31]   │ (software saved if FPU)
//! └───────────────┘ <- Saved PSP (stored in TCB)
//! Low Address
//! ```

use core::arch::{asm, global_asm};
use core::ptr;

// ============================================================================
// Task Context Structure
// ============================================================================

/// Hardware-stacked exception frame (pushed by CPU on exception entry)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    /// R0
    pub r0: u32,
    /// R1
    pub r1: u32,
    /// R2
    pub r2: u32,
    /// R3
    pub r3: u32,
    /// R12
    pub r12: u32,
    /// Link Register (return address before exception)
    pub lr: u32,
    /// Program Counter (return address)
    pub pc: u32,
    /// Program Status Register
    pub xpsr: u32,
}

/// Extended exception frame with FPU context (Cortex-M4F/M7/M33)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExtendedExceptionFrame {
    /// Basic exception frame
    pub basic: ExceptionFrame,
    /// S0-S15 (caller-saved FPU registers)
    pub s0_s15: [u32; 16],
    /// FPSCR
    pub fpscr: u32,
    /// Reserved (for 8-byte alignment)
    pub reserved: u32,
}

/// Software-saved context (callee-saved registers)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SoftwareContext {
    /// EXC_RETURN value (determines stack and FPU context)
    pub exc_return: u32,
    /// R4
    pub r4: u32,
    /// R5
    pub r5: u32,
    /// R6
    pub r6: u32,
    /// R7
    pub r7: u32,
    /// R8
    pub r8: u32,
    /// R9
    pub r9: u32,
    /// R10
    pub r10: u32,
    /// R11
    pub r11: u32,
}

/// Extended software context with FPU callee-saved registers
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExtendedSoftwareContext {
    /// Basic software context
    pub basic: SoftwareContext,
    /// S16-S31 (callee-saved FPU registers)
    pub s16_s31: [u32; 16],
}

/// Complete task context
#[repr(C)]
#[derive(Debug)]
pub struct TaskContext {
    /// Stack pointer (PSP value)
    pub sp: u32,
    /// MPU region configuration index
    pub mpu_region: u8,
    /// Task privilege level (0 = privileged, 1 = unprivileged)
    pub privilege: u8,
    /// FPU context active
    pub fpu_active: bool,
    /// Reserved for alignment
    _reserved: u8,
}

impl TaskContext {
    /// Create a new task context with initial values
    pub const fn new() -> Self {
        Self {
            sp: 0,
            mpu_region: 0,
            privilege: 0,
            fpu_active: false,
            _reserved: 0,
        }
    }

    /// Initialize task context for first execution
    ///
    /// # Arguments
    /// * `stack_top` - Top of the task's stack (highest address)
    /// * `entry` - Task entry point function
    /// * `arg` - Argument to pass to task (in R0)
    /// * `privileged` - Whether task runs in privileged mode
    ///
    /// # Returns
    /// Initialized stack pointer value
    pub fn init_stack(
        &mut self,
        stack_top: u32,
        entry: extern "C" fn(),
        arg: u32,
        privileged: bool,
    ) -> u32 {
        // Align stack to 8 bytes (required by ARM ABI)
        let aligned_top = stack_top & !0x7;

        // Reserve space for exception frame
        let frame_ptr = (aligned_top - core::mem::size_of::<ExceptionFrame>() as u32) as *mut ExceptionFrame;

        // Initialize exception frame
        // SAFETY: frame_ptr is derived from stack_top (which the caller guarantees is a valid,
        // aligned stack allocation) minus the size of ExceptionFrame. The resulting pointer is
        // within the task's stack and properly aligned to 4 bytes (guaranteed by the 8-byte
        // alignment of stack_top). We have exclusive access because this is called during task
        // creation before the task is started.
        unsafe {
            let frame = &mut *frame_ptr;
            frame.r0 = arg;                           // Argument in R0
            frame.r1 = 0;
            frame.r2 = 0;
            frame.r3 = 0;
            frame.r12 = 0;
            frame.lr = task_exit_handler as u32;      // Return address if task exits
            frame.pc = entry as u32;                  // Entry point
            frame.xpsr = 0x0100_0000;                 // Thumb bit set
        }

        // Reserve space for software context
        let sw_context_ptr = (frame_ptr as u32 - core::mem::size_of::<SoftwareContext>() as u32) as *mut SoftwareContext;

        // Initialize software context
        // SAFETY: sw_context_ptr is derived by subtracting SoftwareContext size from frame_ptr,
        // keeping the pointer within the task's stack. Alignment is maintained by the struct
        // sizes. Exclusive access is guaranteed as the task has not been started.
        unsafe {
            let sw = &mut *sw_context_ptr;
            // EXC_RETURN: Return to Thread mode, use PSP, no FPU
            // 0xFFFFFFFD = Thread mode, PSP, no floating-point
            sw.exc_return = 0xFFFF_FFFD;
            sw.r4 = 0;
            sw.r5 = 0;
            sw.r6 = 0;
            sw.r7 = 0;
            sw.r8 = 0;
            sw.r9 = 0;
            sw.r10 = 0;
            sw.r11 = 0;
        }

        let final_sp = sw_context_ptr as u32;

        self.sp = final_sp;
        self.privilege = if privileged { 0 } else { 1 };
        self.fpu_active = false;

        final_sp
    }

    /// Initialize task context with FPU support
    #[cfg(any(target_feature = "vfp2", target_feature = "vfp3", target_feature = "vfp4"))]
    pub fn init_stack_fpu(
        &mut self,
        stack_top: u32,
        entry: extern "C" fn(),
        arg: u32,
        privileged: bool,
    ) -> u32 {
        // Align stack to 8 bytes
        let aligned_top = stack_top & !0x7;

        // Reserve space for extended exception frame (with FPU)
        let frame_ptr = (aligned_top - core::mem::size_of::<ExtendedExceptionFrame>() as u32)
            as *mut ExtendedExceptionFrame;

        // Initialize exception frame
        // SAFETY: Same invariants as the non-FPU init_stack -- frame_ptr is within the task's
        // allocated stack, properly aligned, and we have exclusive access during task creation.
        // The extended frame includes FPU register space.
        unsafe {
            let frame = &mut *frame_ptr;
            frame.basic.r0 = arg;
            frame.basic.r1 = 0;
            frame.basic.r2 = 0;
            frame.basic.r3 = 0;
            frame.basic.r12 = 0;
            frame.basic.lr = task_exit_handler as u32;
            frame.basic.pc = entry as u32;
            frame.basic.xpsr = 0x0100_0000;

            // Initialize FPU registers to zero
            for s in &mut frame.s0_s15 {
                *s = 0;
            }
            frame.fpscr = 0;
            frame.reserved = 0;
        }

        // Reserve space for extended software context
        let sw_context_ptr = (frame_ptr as u32 - core::mem::size_of::<ExtendedSoftwareContext>() as u32)
            as *mut ExtendedSoftwareContext;

        // Initialize software context
        // SAFETY: sw_context_ptr is within the task's stack allocation, derived from frame_ptr
        // minus ExtendedSoftwareContext size. Alignment maintained. Exclusive access guaranteed
        // during task creation.
        unsafe {
            let sw = &mut *sw_context_ptr;
            // EXC_RETURN with FPU: 0xFFFFFFED = Thread mode, PSP, extended frame (FPU)
            sw.basic.exc_return = 0xFFFF_FFED;
            sw.basic.r4 = 0;
            sw.basic.r5 = 0;
            sw.basic.r6 = 0;
            sw.basic.r7 = 0;
            sw.basic.r8 = 0;
            sw.basic.r9 = 0;
            sw.basic.r10 = 0;
            sw.basic.r11 = 0;

            for s in &mut sw.s16_s31 {
                *s = 0;
            }
        }

        let final_sp = sw_context_ptr as u32;

        self.sp = final_sp;
        self.privilege = if privileged { 0 } else { 1 };
        self.fpu_active = true;

        final_sp
    }
}

impl Default for TaskContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Context Switch Implementation
// ============================================================================

/// Context switch manager
pub struct ContextSwitch {
    /// Pointer to current task's stack pointer storage
    current_sp_ptr: *mut u32,
    /// Pointer to next task's stack pointer storage
    next_sp_ptr: *mut u32,
}

impl ContextSwitch {
    /// Create a new context switch manager (uninitialized)
    pub const fn new() -> Self {
        Self {
            current_sp_ptr: ptr::null_mut(),
            next_sp_ptr: ptr::null_mut(),
        }
    }

    /// Prepare for context switch
    ///
    /// # Arguments
    /// * `current_sp_ptr` - Pointer to store current task's SP
    /// * `next_sp_ptr` - Pointer to next task's SP
    pub fn prepare(&mut self, current_sp_ptr: *mut u32, next_sp_ptr: *mut u32) {
        self.current_sp_ptr = current_sp_ptr;
        self.next_sp_ptr = next_sp_ptr;
    }

    /// Get current task SP pointer
    pub fn current_sp_ptr(&self) -> *mut u32 {
        self.current_sp_ptr
    }

    /// Get next task SP pointer
    pub fn next_sp_ptr(&self) -> *mut u32 {
        self.next_sp_ptr
    }
}

impl Default for ContextSwitch {
    fn default() -> Self {
        Self::new()
    }
}

/// Global context switch state
static mut CONTEXT_SWITCH: ContextSwitch = ContextSwitch::new();

/// Set up pending context switch
///
/// # Safety
/// Must be called with interrupts disabled or from exception handler
pub unsafe fn setup_context_switch(current_sp_ptr: *mut u32, next_sp_ptr: *mut u32) {
    (*core::ptr::addr_of_mut!(CONTEXT_SWITCH)).prepare(current_sp_ptr, next_sp_ptr);
}

/// Get context switch state
///
/// # Safety
/// Must be called from PendSV handler
pub unsafe fn get_context_switch() -> *mut ContextSwitch {
    core::ptr::addr_of_mut!(CONTEXT_SWITCH)
}

// ============================================================================
// Task Exit Handler
// ============================================================================

/// Handler for when a task returns from its entry function
///
/// This function is set as the LR value in the initial stack frame.
/// If a task's main function returns, execution jumps here.
#[no_mangle]
extern "C" fn task_exit_handler() {
    // Task has exited - signal to scheduler
    // In a real implementation, this would:
    // 1. Mark the task as terminated
    // 2. Trigger a context switch to another task
    // 3. Optionally clean up task resources

    // For now, just loop forever
    // The scheduler should never schedule this task again
    loop {
        // SAFETY: WFI (Wait For Interrupt) is always safe to execute. It halts the processor
        // in a low-power state until an interrupt occurs. This is used as an infinite loop for
        // a terminated task to avoid busy-spinning.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

// ============================================================================
// PendSV Handler (Context Switch)
// ============================================================================

// ============================================================================
// PendSV Handler using global_asm! (works on stable Rust)
// ============================================================================

// PendSV exception handler for context switching
// This handler performs the actual context switch between tasks.
// It is triggered by setting the PENDSVSET bit in the SCB ICSR register.
//
// Register Usage:
// - R0: Used for loading/storing stack pointers
// - R1-R3: Scratch registers
// - R4-R11: Saved as part of context
// - LR: Contains EXC_RETURN value
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".fpu fpv5-d16",
    ".section .text.PendSV_Handler",
    ".global PendSV_Handler",
    ".type PendSV_Handler, %function",
    ".thumb_func",
    "PendSV_Handler:",
    // Disable interrupts during context switch
    "    cpsid i",

    // Get current PSP
    "    mrs r0, psp",

    // Check if FPU context needs saving (EXC_RETURN bit 4)
    // If bit 4 is 0, extended frame with FPU was used
    "    tst lr, #0x10",
    "    it eq",
    "    vstmdbeq r0!, {{s16-s31}}",

    // Save software context: EXC_RETURN and R4-R11
    "    stmdb r0!, {{r4-r11, lr}}",

    // Get context switch pointers
    "    ldr r1, =CONTEXT_SWITCH",
    "    ldr r2, [r1, #0]",
    "    ldr r3, [r1, #4]",

    // Save current PSP if we have a current task
    "    cbz r2, 1f",
    "    str r0, [r2]",

    "1:",
    // Load next task's SP
    "    ldr r0, [r3]",

    // Restore software context: R4-R11 and EXC_RETURN
    "    ldmia r0!, {{r4-r11, lr}}",

    // Check if FPU context needs restoring
    "    tst lr, #0x10",
    "    it eq",
    "    vldmiaeq r0!, {{s16-s31}}",

    // Update PSP
    "    msr psp, r0",

    // Memory barrier
    "    isb",

    // Re-enable interrupts
    "    cpsie i",

    // Return from exception (LR contains EXC_RETURN)
    "    bx lr",
    ".size PendSV_Handler, . - PendSV_Handler",
);

// ============================================================================
// First Context Switch (Start First Task)
// ============================================================================

// Start first task using global_asm! (stable Rust)
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.start_first_task",
    ".global start_first_task",
    ".type start_first_task, %function",
    ".thumb_func",
    // Start the first task
    // R0 = first_task_sp
    "start_first_task:",
    // Set PSP to first task's stack
    "    msr psp, r0",

    // Switch to using PSP in Thread mode
    "    mrs r0, control",
    "    orr r0, r0, #2",
    "    msr control, r0",
    "    isb",

    // Get the SP value and pop software context
    "    mrs r0, psp",
    "    ldmia r0!, {{r4-r11, lr}}",
    "    msr psp, r0",

    // Enable interrupts
    "    cpsie i",
    "    cpsie f",

    // Branch to task using EXC_RETURN mechanism
    "    bx lr",
    ".size start_first_task, . - start_first_task",
);

// Alternative first task start that pops exception frame manually
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.start_first_task_manual",
    ".global start_first_task_manual",
    ".type start_first_task_manual, %function",
    ".thumb_func",
    // R0 = first_task_sp
    "start_first_task_manual:",
    // Load first task's SP
    "    mov sp, r0",

    // Skip software context (9 words: exc_return + r4-r11)
    "    add sp, sp, #36",

    // Pop exception frame
    "    pop {{r0-r3, r12}}",
    "    pop {{lr}}",
    "    pop {{r4}}",
    "    pop {{r5}}",

    // Set PSP (need to use a temp register since msr can't take sp directly)
    "    mov r6, sp",
    "    msr psp, r6",

    // Switch to PSP
    "    mrs r6, control",
    "    orr r6, r6, #2",
    "    msr control, r6",
    "    isb",

    // Enable interrupts
    "    cpsie i",

    // Jump to task entry (PC was in R4)
    "    bx r4",
    ".size start_first_task_manual, . - start_first_task_manual",
);

// Extern declarations for the assembly functions
extern "C" {
    /// Start the first task
    ///
    /// # Safety
    /// Must be called exactly once during kernel initialization.
    pub fn start_first_task(first_task_sp: u32) -> !;

    /// Alternative first task start
    ///
    /// # Safety
    /// Must be called exactly once during kernel initialization.
    pub fn start_first_task_manual(first_task_sp: u32) -> !;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Trigger a context switch by pending PendSV
#[inline]
pub fn request_context_switch() {
    super::trigger_pendsv();
}

/// Check if a context switch is pending
#[inline]
pub fn is_context_switch_pending() -> bool {
    // SAFETY: The ICSR register at 0xE000_ED04 is an architecturally-defined Cortex-M register
    // that is always valid to read. The volatile read is necessary because the hardware may set
    // PENDSVSET asynchronously. Reading ICSR has no side effects.
    unsafe {
        let icsr = super::scb::ICSR as *const u32;
        (ptr::read_volatile(icsr) & super::scb::ICSR_PENDSVSET) != 0
    }
}

/// Calculate required stack size for a task
///
/// # Arguments
/// * `user_stack_size` - Stack space needed for task code
/// * `with_fpu` - Whether FPU context will be used
///
/// # Returns
/// Total stack size in bytes (including context frames)
pub const fn calculate_stack_size(user_stack_size: usize, with_fpu: bool) -> usize {
    let exception_frame = if with_fpu {
        core::mem::size_of::<ExtendedExceptionFrame>()
    } else {
        core::mem::size_of::<ExceptionFrame>()
    };

    let software_context = if with_fpu {
        core::mem::size_of::<ExtendedSoftwareContext>()
    } else {
        core::mem::size_of::<SoftwareContext>()
    };

    // Add 8 bytes for alignment and some safety margin
    user_stack_size + exception_frame + software_context + 16
}

/// Initialize a stack with a sentinel pattern for debugging
///
/// # Arguments
/// * `stack_base` - Base address of stack (lowest address)
/// * `stack_size` - Size of stack in bytes
pub fn init_stack_pattern(stack_base: u32, stack_size: usize) {
    const STACK_FILL_PATTERN: u32 = 0xDEAD_BEEF;

    let words = stack_size / 4;
    let base_ptr = stack_base as *mut u32;

    for i in 0..words {
        // SAFETY: The caller provides stack_base and stack_size for a validly-allocated stack
        // region. We iterate within bounds (0..words where words = stack_size/4). The pointer
        // arithmetic via add(i) stays within the allocated stack. volatile write is used to
        // prevent the compiler from optimizing away the sentinel pattern.
        unsafe {
            ptr::write_volatile(base_ptr.add(i), STACK_FILL_PATTERN);
        }
    }
}

/// Calculate used stack space by scanning for sentinel pattern
///
/// # Arguments
/// * `stack_base` - Base address of stack (lowest address)
/// * `stack_size` - Size of stack in bytes
///
/// # Returns
/// Number of bytes used (approximate high-water mark)
pub fn calculate_stack_usage(stack_base: u32, stack_size: usize) -> usize {
    const STACK_FILL_PATTERN: u32 = 0xDEAD_BEEF;

    let words = stack_size / 4;
    let base_ptr = stack_base as *const u32;

    let mut untouched = 0;
    for i in 0..words {
        // SAFETY: The caller provides stack_base and stack_size for a valid stack. We iterate
        // within bounds. The volatile read prevents the compiler from assuming the stack memory
        // hasn't been modified by task execution.
        unsafe {
            if ptr::read_volatile(base_ptr.add(i)) == STACK_FILL_PATTERN {
                untouched += 1;
            } else {
                break;
            }
        }
    }

    stack_size - (untouched * 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exception_frame_size() {
        assert_eq!(core::mem::size_of::<ExceptionFrame>(), 32);
    }

    #[test]
    fn test_software_context_size() {
        assert_eq!(core::mem::size_of::<SoftwareContext>(), 36);
    }

    #[test]
    fn test_calculate_stack_size() {
        let size = calculate_stack_size(1024, false);
        assert!(size >= 1024 + 32 + 36);
    }
}
