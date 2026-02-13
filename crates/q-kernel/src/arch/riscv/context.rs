// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! RISC-V Context Switching
//!
//! This module provides context switching primitives for RISC-V processors.
//! Context switches are triggered via software interrupt (MSIP) or timer interrupt.

use core::arch::{asm, global_asm};

/// Number of general-purpose registers to save (x1-x31, excluding x0)
pub const NUM_GP_REGS: usize = 31;

/// Task context structure
///
/// Contains all registers that must be saved during a context switch.
/// The layout matches the stack frame created by the trap handler.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaskContext {
    /// Return address (x1/ra)
    pub ra: usize,
    /// Stack pointer (x2/sp)
    pub sp: usize,
    /// Global pointer (x3/gp)
    pub gp: usize,
    /// Thread pointer (x4/tp)
    pub tp: usize,
    /// Temporary registers (x5-x7, t0-t2)
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    /// Saved register / frame pointer (x8/s0/fp)
    pub s0: usize,
    /// Saved register (x9/s1)
    pub s1: usize,
    /// Function arguments / return values (x10-x17, a0-a7)
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    /// Saved registers (x18-x27, s2-s11)
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    /// Temporary registers (x28-x31, t3-t6)
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    /// Machine Exception Program Counter (where to return)
    pub mepc: usize,
    /// Machine Status (for interrupt enable state)
    pub mstatus: usize,
}

impl TaskContext {
    /// Size of context in bytes
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Create a new empty context
    pub const fn new() -> Self {
        Self {
            ra: 0,
            sp: 0,
            gp: 0,
            tp: 0,
            t0: 0,
            t1: 0,
            t2: 0,
            s0: 0,
            s1: 0,
            a0: 0,
            a1: 0,
            a2: 0,
            a3: 0,
            a4: 0,
            a5: 0,
            a6: 0,
            a7: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
            t3: 0,
            t4: 0,
            t5: 0,
            t6: 0,
            mepc: 0,
            mstatus: 0,
        }
    }

    /// Initialize context for a new task
    ///
    /// # Arguments
    /// * `entry_point` - Task entry function address
    /// * `stack_top` - Top of the task's stack (highest address)
    /// * `arg` - Argument to pass to the task (in a0)
    pub fn init(&mut self, entry_point: usize, stack_top: usize, arg: usize) {
        // Clear all registers
        *self = Self::new();

        // Set up initial state
        self.sp = stack_top;
        self.mepc = entry_point;
        self.a0 = arg;

        // Set mstatus for returning to machine mode with interrupts enabled
        // MPIE = 1 (interrupts will be enabled on mret)
        // MPP = 11 (machine mode)
        self.mstatus = (1 << 7) | (0b11 << 11);
    }

    /// Initialize stack for a new task (compatible interface with Cortex-M)
    ///
    /// # Arguments
    /// * `stack_top` - Top of the task's stack (highest address, will be cast from u32)
    /// * `entry` - Task entry function
    /// * `arg` - Argument to pass to the task
    /// * `_privileged` - Privilege mode (ignored on RISC-V M-mode, always machine mode)
    ///
    /// # Returns
    /// The initial stack pointer value
    pub fn init_stack(
        &mut self,
        stack_top: usize,
        entry: extern "C" fn(),
        arg: usize,
        _privileged: bool,
    ) -> usize {
        // Align stack to 16 bytes (RISC-V ABI requires 16-byte alignment)
        let aligned_top = stack_top & !0xF;

        // Initialize context
        self.init(entry as usize, aligned_top, arg);

        // Return the stack pointer
        self.sp
    }
}

impl Default for TaskContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Context switch state
pub struct ContextSwitch {
    /// Current task context pointer
    current_ctx: *mut TaskContext,
    /// Next task context pointer
    next_ctx: *const TaskContext,
}

impl ContextSwitch {
    /// Create a new context switch handler
    pub const fn new() -> Self {
        Self {
            current_ctx: core::ptr::null_mut(),
            next_ctx: core::ptr::null(),
        }
    }

    /// Set up for a context switch
    pub fn prepare(&mut self, current: *mut TaskContext, next: *const TaskContext) {
        self.current_ctx = current;
        self.next_ctx = next;
    }

    /// Get current context pointer
    pub fn current(&self) -> *mut TaskContext {
        self.current_ctx
    }

    /// Get next context pointer
    pub fn next(&self) -> *const TaskContext {
        self.next_ctx
    }
}

/// Global context switch state (used by trap handler)
static mut CONTEXT_SWITCH: ContextSwitch = ContextSwitch::new();

/// Set up context switch (called by scheduler)
pub fn setup_context_switch(current: *mut TaskContext, next: *const TaskContext) {
    // SAFETY: Accesses the global CONTEXT_SWITCH state. Called from the scheduler
    // with interrupts disabled (within a critical section), ensuring no concurrent
    // access from the trap handler.
    unsafe {
        (*core::ptr::addr_of_mut!(CONTEXT_SWITCH)).prepare(current, next);
    }
}

/// Get context switch pointers (called by trap handler)
pub fn get_context_switch() -> (*mut TaskContext, *const TaskContext) {
    // SAFETY: Reads the global CONTEXT_SWITCH state. Called from the trap handler,
    // which runs with interrupts disabled. The scheduler only writes to
    // CONTEXT_SWITCH from a critical section, so there are no data races.
    unsafe {
        ((*core::ptr::addr_of!(CONTEXT_SWITCH)).current_ctx, (*core::ptr::addr_of!(CONTEXT_SWITCH)).next_ctx)
    }
}

// ============================================================================
// Assembly Trap Handler for RV32
// ============================================================================

#[cfg(all(target_arch = "riscv32", feature = "riscv"))]
global_asm!(
    ".section .text.trap_handler",
    ".global trap_handler",
    ".type trap_handler, @function",
    ".align 4",
    "trap_handler:",
    // Save context to stack
    "    addi sp, sp, -128",      // Allocate stack frame
    "    sw ra, 0(sp)",
    "    sw gp, 8(sp)",
    "    sw tp, 12(sp)",
    "    sw t0, 16(sp)",
    "    sw t1, 20(sp)",
    "    sw t2, 24(sp)",
    "    sw s0, 28(sp)",
    "    sw s1, 32(sp)",
    "    sw a0, 36(sp)",
    "    sw a1, 40(sp)",
    "    sw a2, 44(sp)",
    "    sw a3, 48(sp)",
    "    sw a4, 52(sp)",
    "    sw a5, 56(sp)",
    "    sw a6, 60(sp)",
    "    sw a7, 64(sp)",
    "    sw s2, 68(sp)",
    "    sw s3, 72(sp)",
    "    sw s4, 76(sp)",
    "    sw s5, 80(sp)",
    "    sw s6, 84(sp)",
    "    sw s7, 88(sp)",
    "    sw s8, 92(sp)",
    "    sw s9, 96(sp)",
    "    sw s10, 100(sp)",
    "    sw s11, 104(sp)",
    "    sw t3, 108(sp)",
    "    sw t4, 112(sp)",
    "    sw t5, 116(sp)",
    "    sw t6, 120(sp)",
    // Save mepc and mstatus
    "    csrr t0, mepc",
    "    sw t0, 124(sp)",
    "    csrr t0, mstatus",
    "    sw t0, 128(sp)",
    // Save sp to mscratch for later
    "    csrw mscratch, sp",
    // Call Rust trap handler with mcause as argument
    "    csrr a0, mcause",
    "    csrr a1, mtval",
    "    mv a2, sp",
    "    call handle_trap",
    // Restore context (handler may have switched stack pointers)
    "    csrr sp, mscratch",
    // Restore mepc and mstatus
    "    lw t0, 124(sp)",
    "    csrw mepc, t0",
    "    lw t0, 128(sp)",
    "    csrw mstatus, t0",
    // Restore registers
    "    lw ra, 0(sp)",
    "    lw gp, 8(sp)",
    "    lw tp, 12(sp)",
    "    lw t0, 16(sp)",
    "    lw t1, 20(sp)",
    "    lw t2, 24(sp)",
    "    lw s0, 28(sp)",
    "    lw s1, 32(sp)",
    "    lw a0, 36(sp)",
    "    lw a1, 40(sp)",
    "    lw a2, 44(sp)",
    "    lw a3, 48(sp)",
    "    lw a4, 52(sp)",
    "    lw a5, 56(sp)",
    "    lw a6, 60(sp)",
    "    lw a7, 64(sp)",
    "    lw s2, 68(sp)",
    "    lw s3, 72(sp)",
    "    lw s4, 76(sp)",
    "    lw s5, 80(sp)",
    "    lw s6, 84(sp)",
    "    lw s7, 88(sp)",
    "    lw s8, 92(sp)",
    "    lw s9, 96(sp)",
    "    lw s10, 100(sp)",
    "    lw s11, 104(sp)",
    "    lw t3, 108(sp)",
    "    lw t4, 112(sp)",
    "    lw t5, 116(sp)",
    "    lw t6, 120(sp)",
    "    addi sp, sp, 128",
    "    mret",
    ".size trap_handler, . - trap_handler",
);

// ============================================================================
// Assembly Trap Handler for RV64
// ============================================================================

#[cfg(all(target_arch = "riscv64", feature = "riscv"))]
global_asm!(
    ".section .text.trap_handler",
    ".global trap_handler",
    ".type trap_handler, @function",
    ".align 4",
    "trap_handler:",
    // Save context to stack (double-word aligned for RV64)
    "    addi sp, sp, -256",
    "    sd ra, 0(sp)",
    "    sd gp, 16(sp)",
    "    sd tp, 24(sp)",
    "    sd t0, 32(sp)",
    "    sd t1, 40(sp)",
    "    sd t2, 48(sp)",
    "    sd s0, 56(sp)",
    "    sd s1, 64(sp)",
    "    sd a0, 72(sp)",
    "    sd a1, 80(sp)",
    "    sd a2, 88(sp)",
    "    sd a3, 96(sp)",
    "    sd a4, 104(sp)",
    "    sd a5, 112(sp)",
    "    sd a6, 120(sp)",
    "    sd a7, 128(sp)",
    "    sd s2, 136(sp)",
    "    sd s3, 144(sp)",
    "    sd s4, 152(sp)",
    "    sd s5, 160(sp)",
    "    sd s6, 168(sp)",
    "    sd s7, 176(sp)",
    "    sd s8, 184(sp)",
    "    sd s9, 192(sp)",
    "    sd s10, 200(sp)",
    "    sd s11, 208(sp)",
    "    sd t3, 216(sp)",
    "    sd t4, 224(sp)",
    "    sd t5, 232(sp)",
    "    sd t6, 240(sp)",
    // Save mepc and mstatus
    "    csrr t0, mepc",
    "    sd t0, 248(sp)",
    "    csrr t0, mstatus",
    "    sd t0, 256(sp)",
    // Save sp to mscratch
    "    csrw mscratch, sp",
    // Call Rust trap handler
    "    csrr a0, mcause",
    "    csrr a1, mtval",
    "    mv a2, sp",
    "    call handle_trap",
    // Restore context
    "    csrr sp, mscratch",
    "    ld t0, 248(sp)",
    "    csrw mepc, t0",
    "    ld t0, 256(sp)",
    "    csrw mstatus, t0",
    "    ld ra, 0(sp)",
    "    ld gp, 16(sp)",
    "    ld tp, 24(sp)",
    "    ld t0, 32(sp)",
    "    ld t1, 40(sp)",
    "    ld t2, 48(sp)",
    "    ld s0, 56(sp)",
    "    ld s1, 64(sp)",
    "    ld a0, 72(sp)",
    "    ld a1, 80(sp)",
    "    ld a2, 88(sp)",
    "    ld a3, 96(sp)",
    "    ld a4, 104(sp)",
    "    ld a5, 112(sp)",
    "    ld a6, 120(sp)",
    "    ld a7, 128(sp)",
    "    ld s2, 136(sp)",
    "    ld s3, 144(sp)",
    "    ld s4, 152(sp)",
    "    ld s5, 160(sp)",
    "    ld s6, 168(sp)",
    "    ld s7, 176(sp)",
    "    ld s8, 184(sp)",
    "    ld s9, 192(sp)",
    "    ld s10, 200(sp)",
    "    ld s11, 208(sp)",
    "    ld t3, 216(sp)",
    "    ld t4, 224(sp)",
    "    ld t5, 232(sp)",
    "    ld t6, 240(sp)",
    "    addi sp, sp, 256",
    "    mret",
    ".size trap_handler, . - trap_handler",
);

// Provide stub implementation when not building for actual RISC-V
#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
extern "C" {
    /// Trap handler (defined in assembly for actual RISC-V targets)
    pub fn trap_handler();
}

// ============================================================================
// Start First Task (RV32)
// ============================================================================

#[cfg(all(target_arch = "riscv32", feature = "riscv"))]
global_asm!(
    ".section .text.start_first_task",
    ".global start_first_task",
    ".type start_first_task, @function",
    ".align 4",
    "start_first_task:",
    // a0 contains pointer to first task's context
    "    mv sp, a0",
    // Load mepc (return address)
    "    lw t0, 124(sp)",
    "    csrw mepc, t0",
    // Load mstatus
    "    lw t0, 128(sp)",
    "    csrw mstatus, t0",
    // Restore registers
    "    lw ra, 0(sp)",
    "    lw gp, 8(sp)",
    "    lw tp, 12(sp)",
    "    lw t0, 16(sp)",
    "    lw t1, 20(sp)",
    "    lw t2, 24(sp)",
    "    lw s0, 28(sp)",
    "    lw s1, 32(sp)",
    "    lw a0, 36(sp)",
    "    lw a1, 40(sp)",
    "    lw a2, 44(sp)",
    "    lw a3, 48(sp)",
    "    lw a4, 52(sp)",
    "    lw a5, 56(sp)",
    "    lw a6, 60(sp)",
    "    lw a7, 64(sp)",
    "    lw s2, 68(sp)",
    "    lw s3, 72(sp)",
    "    lw s4, 76(sp)",
    "    lw s5, 80(sp)",
    "    lw s6, 84(sp)",
    "    lw s7, 88(sp)",
    "    lw s8, 92(sp)",
    "    lw s9, 96(sp)",
    "    lw s10, 100(sp)",
    "    lw s11, 104(sp)",
    "    lw t3, 108(sp)",
    "    lw t4, 112(sp)",
    "    lw t5, 116(sp)",
    "    lw t6, 120(sp)",
    "    addi sp, sp, 128",
    // Return to task
    "    mret",
    ".size start_first_task, . - start_first_task",
);

#[cfg(all(target_arch = "riscv64", feature = "riscv"))]
global_asm!(
    ".section .text.start_first_task",
    ".global start_first_task",
    ".type start_first_task, @function",
    ".align 4",
    "start_first_task:",
    // a0 contains pointer to first task's context
    "    mv sp, a0",
    // Load mepc
    "    ld t0, 248(sp)",
    "    csrw mepc, t0",
    // Load mstatus
    "    ld t0, 256(sp)",
    "    csrw mstatus, t0",
    // Restore registers
    "    ld ra, 0(sp)",
    "    ld gp, 16(sp)",
    "    ld tp, 24(sp)",
    "    ld t0, 32(sp)",
    "    ld t1, 40(sp)",
    "    ld t2, 48(sp)",
    "    ld s0, 56(sp)",
    "    ld s1, 64(sp)",
    "    ld a0, 72(sp)",
    "    ld a1, 80(sp)",
    "    ld a2, 88(sp)",
    "    ld a3, 96(sp)",
    "    ld a4, 104(sp)",
    "    ld a5, 112(sp)",
    "    ld a6, 120(sp)",
    "    ld a7, 128(sp)",
    "    ld s2, 136(sp)",
    "    ld s3, 144(sp)",
    "    ld s4, 152(sp)",
    "    ld s5, 160(sp)",
    "    ld s6, 168(sp)",
    "    ld s7, 176(sp)",
    "    ld s8, 184(sp)",
    "    ld s9, 192(sp)",
    "    ld s10, 200(sp)",
    "    ld s11, 208(sp)",
    "    ld t3, 216(sp)",
    "    ld t4, 224(sp)",
    "    ld t5, 232(sp)",
    "    ld t6, 240(sp)",
    "    addi sp, sp, 256",
    "    mret",
    ".size start_first_task, . - start_first_task",
);

// Extern declaration for RISC-V builds (defined in global_asm above)
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
extern "C" {
    /// Start the first task (defined in assembly for actual RISC-V targets)
    pub fn start_first_task(context_ptr: usize) -> !;
}

// Stub for non-RISC-V builds (for testing/compilation)
#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
pub fn start_first_task(_context_ptr: usize) -> ! {
    panic!("start_first_task called on non-RISC-V platform")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_size() {
        // Context should be properly sized
        assert!(TaskContext::SIZE >= 128);
    }

    #[test]
    fn test_context_new() {
        let ctx = TaskContext::new();
        assert_eq!(ctx.ra, 0);
        assert_eq!(ctx.sp, 0);
        assert_eq!(ctx.mepc, 0);
    }

    #[test]
    fn test_context_init() {
        let mut ctx = TaskContext::new();
        ctx.init(0x1000, 0x8000, 42);

        assert_eq!(ctx.mepc, 0x1000);
        assert_eq!(ctx.sp, 0x8000);
        assert_eq!(ctx.a0, 42);
        // Check mstatus has MPIE and MPP=M-mode set
        assert!(ctx.mstatus & (1 << 7) != 0); // MPIE
        assert!(ctx.mstatus & (0b11 << 11) != 0); // MPP
    }

    #[test]
    fn test_context_switch_new() {
        let cs = ContextSwitch::new();
        assert!(cs.current().is_null());
        assert!(cs.next().is_null());
    }
}
