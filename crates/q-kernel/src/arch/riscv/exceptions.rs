// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! RISC-V Exception and Interrupt Handling
//!
//! This module provides exception and interrupt handling for RISC-V processors.
//! It includes the trap handler dispatcher and exception-specific handlers.

use super::{cause, mip, get_mcause, get_mtval, get_mepc, set_mepc};
use super::context::TaskContext;

/// Exception frame passed to handlers
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    /// Exception cause (mcause)
    pub cause: usize,
    /// Trap value (mtval) - faulting address or instruction
    pub tval: usize,
    /// Exception program counter (mepc) - where exception occurred
    pub epc: usize,
    /// Pointer to saved context
    pub context: *mut TaskContext,
}

impl ExceptionFrame {
    /// Create a new exception frame
    pub fn new(cause: usize, tval: usize, epc: usize, context: *mut TaskContext) -> Self {
        Self {
            cause,
            tval,
            epc,
            context,
        }
    }

    /// Check if this is an interrupt (not an exception)
    pub fn is_interrupt(&self) -> bool {
        // On RISC-V, the high bit of mcause indicates interrupt
        #[cfg(target_pointer_width = "32")]
        { self.cause & (1 << 31) != 0 }
        #[cfg(target_pointer_width = "64")]
        { self.cause & (1 << 63) != 0 }
        #[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
        { self.cause & (1 << 31) != 0 }
    }

    /// Get the exception/interrupt code
    pub fn code(&self) -> usize {
        #[cfg(target_pointer_width = "32")]
        { self.cause & 0x7FFF_FFFF }
        #[cfg(target_pointer_width = "64")]
        { self.cause & 0x7FFF_FFFF_FFFF_FFFF }
        #[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
        { self.cause & 0x7FFF_FFFF }
    }
}

/// Exception handler type
pub type ExceptionHandler = fn(&mut ExceptionFrame);

/// Interrupt handler type
pub type InterruptHandler = fn(&mut ExceptionFrame);

/// Exception handlers table
static mut EXCEPTION_HANDLERS: [Option<ExceptionHandler>; 16] = [None; 16];

/// Interrupt handlers table
static mut INTERRUPT_HANDLERS: [Option<InterruptHandler>; 16] = [None; 16];

/// Register an exception handler
///
/// # Safety
/// This modifies global state and should only be called during initialization.
pub unsafe fn register_exception_handler(code: usize, handler: ExceptionHandler) {
    if code < EXCEPTION_HANDLERS.len() {
        EXCEPTION_HANDLERS[code] = Some(handler);
    }
}

/// Register an interrupt handler
///
/// # Safety
/// This modifies global state and should only be called during initialization.
pub unsafe fn register_interrupt_handler(code: usize, handler: InterruptHandler) {
    if code < INTERRUPT_HANDLERS.len() {
        INTERRUPT_HANDLERS[code] = Some(handler);
    }
}

/// Main trap handler called from assembly
///
/// This function is called by the assembly trap handler with the saved context.
#[no_mangle]
pub extern "C" fn handle_trap(mcause: usize, mtval: usize, context: *mut TaskContext) {
    let mepc = get_mepc();
    let mut frame = ExceptionFrame::new(mcause, mtval, mepc, context);

    if frame.is_interrupt() {
        handle_interrupt(&mut frame);
    } else {
        handle_exception(&mut frame);
    }

    // Update mepc if it was modified (e.g., to skip faulting instruction)
    set_mepc(frame.epc);
}

/// Handle an interrupt
fn handle_interrupt(frame: &mut ExceptionFrame) {
    let code = frame.code();

    match code {
        // Machine software interrupt (used for context switching)
        3 => {
            handle_software_interrupt(frame);
        }
        // Machine timer interrupt
        7 => {
            handle_timer_interrupt(frame);
        }
        // Machine external interrupt
        11 => {
            handle_external_interrupt(frame);
        }
        // Try registered handler
        _ => {
            // SAFETY: Reads from the global INTERRUPT_HANDLERS array. This is called
            // from the trap handler which runs with interrupts disabled. The array is
            // only modified during initialization (via register_interrupt_handler which
            // requires unsafe). Bounds check is performed.
            unsafe {
                if code < INTERRUPT_HANDLERS.len() {
                    if let Some(handler) = INTERRUPT_HANDLERS[code] {
                        handler(frame);
                        return;
                    }
                }
            }
            // Unhandled interrupt
            unhandled_interrupt(frame);
        }
    }
}

/// Handle an exception
fn handle_exception(frame: &mut ExceptionFrame) {
    let code = frame.code();

    match code {
        cause::INSTRUCTION_MISALIGNED => {
            handle_instruction_misaligned(frame);
        }
        cause::INSTRUCTION_ACCESS_FAULT => {
            handle_instruction_fault(frame);
        }
        cause::ILLEGAL_INSTRUCTION => {
            handle_illegal_instruction(frame);
        }
        cause::BREAKPOINT => {
            handle_breakpoint(frame);
        }
        cause::LOAD_MISALIGNED => {
            handle_load_misaligned(frame);
        }
        cause::LOAD_ACCESS_FAULT => {
            handle_load_fault(frame);
        }
        cause::STORE_MISALIGNED => {
            handle_store_misaligned(frame);
        }
        cause::STORE_ACCESS_FAULT => {
            handle_store_fault(frame);
        }
        cause::ECALL_FROM_U | cause::ECALL_FROM_S | cause::ECALL_FROM_M => {
            handle_ecall(frame);
        }
        cause::INSTRUCTION_PAGE_FAULT => {
            handle_instruction_page_fault(frame);
        }
        cause::LOAD_PAGE_FAULT => {
            handle_load_page_fault(frame);
        }
        cause::STORE_PAGE_FAULT => {
            handle_store_page_fault(frame);
        }
        // Try registered handler
        _ => {
            // SAFETY: Same as INTERRUPT_HANDLERS -- reads from global array in
            // trap context with interrupts disabled. Modified only during
            // initialization. Bounds-checked.
            unsafe {
                if code < EXCEPTION_HANDLERS.len() {
                    if let Some(handler) = EXCEPTION_HANDLERS[code] {
                        handler(frame);
                        return;
                    }
                }
            }
            // Unhandled exception
            unhandled_exception(frame);
        }
    }
}

// ============================================================================
// Interrupt Handlers
// ============================================================================

/// Handle machine software interrupt (context switch)
fn handle_software_interrupt(frame: &mut ExceptionFrame) {
    // Clear the software interrupt pending bit
    super::clear_software_interrupt();

    // Perform context switch if one is pending
    let (current, next) = super::context::get_context_switch();

    if !current.is_null() && !next.is_null() {
        // SAFETY: The current and next pointers are set by the scheduler via
        // setup_context_switch, which is called within a critical section. The
        // frame.context pointer comes from the assembly trap handler and points
        // to the saved register context on the current stack. The scheduler
        // guarantees both task contexts are valid and non-overlapping.
        // copy_nonoverlapping is safe because source and destination are
        // different task context structures.
        unsafe {
            // Save current context
            let current_ctx = &mut *current;
            let saved_ctx = &*(frame.context);

            // Copy saved registers to current task's context
            *current_ctx = *saved_ctx;

            // Load next task's context
            let next_ctx = &*next;

            // Update the context pointer for trap return
            core::ptr::copy_nonoverlapping(
                next_ctx as *const TaskContext,
                frame.context,
                1,
            );

            // Update mscratch to point to new context
            super::set_mscratch(frame.context as usize);
        }
    }
}

/// Handle machine timer interrupt
fn handle_timer_interrupt(frame: &mut ExceptionFrame) {
    // Acknowledge timer by setting next compare value
    let current = super::get_timer();
    let interval = 10_000_000; // Example: 10ms at 1GHz
    super::configure_timer(current + interval);

    // Trigger context switch (scheduler tick)
    super::trigger_software_interrupt();
}

/// Handle machine external interrupt
fn handle_external_interrupt(frame: &mut ExceptionFrame) {
    // Platform-Level Interrupt Controller (PLIC) claim/dispatch/complete cycle
    // Using SiFive PLIC memory map layout
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    {
        use core::ptr;

        // PLIC base addresses (SiFive layout, hart 0 M-mode context)
        const PLIC_BASE: usize = 0x0C00_0000;
        const PLIC_CLAIM: usize = PLIC_BASE + 0x20_0004; // Hart 0 M-mode claim/complete

        // 1. Claim the interrupt (read interrupt ID)
        // SAFETY: The PLIC claim register at 0x0C20_0004 is a memory-mapped MMIO
        // register. Reading it atomically claims the highest-priority pending
        // interrupt and returns its ID (0 = no interrupt). This is the standard
        // PLIC claim mechanism per the RISC-V PLIC specification.
        let irq_id = unsafe { ptr::read_volatile(PLIC_CLAIM as *const u32) };

        if irq_id != 0 {
            // 2. Dispatch to registered handler
            // SAFETY: Reads from the global INTERRUPT_HANDLERS array. Called from
            // the trap handler which runs with interrupts disabled. The array is
            // only modified during initialization. Bounds check is performed.
            unsafe {
                let id = irq_id as usize;
                if id < INTERRUPT_HANDLERS.len() {
                    if let Some(handler) = INTERRUPT_HANDLERS[id] {
                        handler(frame);
                    }
                }
            }

            // 3. Complete the interrupt (write back the claimed ID)
            // SAFETY: Writing the claimed interrupt ID back to the PLIC claim register
            // signals interrupt completion. This must be done after handling to allow
            // the interrupt source to re-trigger. Standard PLIC complete mechanism.
            unsafe {
                ptr::write_volatile(PLIC_CLAIM as *mut u32, irq_id);
            }
        }
    }
}

/// Unhandled interrupt
fn unhandled_interrupt(frame: &ExceptionFrame) {
    // In production, this might log and halt or reset
    // For now, we just ignore unknown interrupts
}

// ============================================================================
// Exception Handlers
// ============================================================================

/// Handle instruction address misaligned
fn handle_instruction_misaligned(frame: &mut ExceptionFrame) {
    // This is typically a fatal error
    panic_exception("Instruction address misaligned", frame);
}

/// Handle instruction access fault
fn handle_instruction_fault(frame: &mut ExceptionFrame) {
    panic_exception("Instruction access fault", frame);
}

/// Handle illegal instruction
fn handle_illegal_instruction(frame: &mut ExceptionFrame) {
    // Could implement instruction emulation here
    panic_exception("Illegal instruction", frame);
}

/// Handle breakpoint (EBREAK)
fn handle_breakpoint(frame: &mut ExceptionFrame) {
    // For debugging - could notify debugger
    // Skip the EBREAK instruction (2 or 4 bytes depending on compression)
    frame.epc += 2; // Assume compressed instruction
}

/// Handle load address misaligned
fn handle_load_misaligned(frame: &mut ExceptionFrame) {
    // Could implement misaligned load emulation
    panic_exception("Load address misaligned", frame);
}

/// Handle load access fault
fn handle_load_fault(frame: &mut ExceptionFrame) {
    panic_exception("Load access fault", frame);
}

/// Handle store address misaligned
fn handle_store_misaligned(frame: &mut ExceptionFrame) {
    // Could implement misaligned store emulation
    panic_exception("Store address misaligned", frame);
}

/// Handle store access fault
fn handle_store_fault(frame: &mut ExceptionFrame) {
    panic_exception("Store access fault", frame);
}

/// Handle ECALL (system call)
fn handle_ecall(frame: &mut ExceptionFrame) {
    // Get syscall arguments from saved context
    // SAFETY: frame.context is set by the assembly trap handler and points to
    // the saved register context on the current task's stack. The pointer is
    // valid for the duration of the trap handler. We read syscall arguments from
    // the saved a0-a7 registers and write the result back to a0/a1. No other
    // code accesses this context concurrently as we are in the trap handler with
    // interrupts disabled.
    unsafe {
        let ctx = &*frame.context;

        // Syscall number in a7, args in a0-a6
        let result = super::syscall::handle_ecall(
            ctx.a7,
            ctx.a0,
            ctx.a1,
            ctx.a2,
            ctx.a3,
            ctx.a4,
            ctx.a5,
            ctx.a6,
        );

        // Store result in a0/a1 of saved context
        let ctx_mut = &mut *frame.context;
        ctx_mut.a0 = result.value;
        ctx_mut.a1 = result.error;
    }

    // Skip ECALL instruction (always 4 bytes)
    frame.epc += 4;
}

/// Handle instruction page fault
fn handle_instruction_page_fault(frame: &mut ExceptionFrame) {
    // Page fault handling - could implement demand paging
    panic_exception("Instruction page fault", frame);
}

/// Handle load page fault
fn handle_load_page_fault(frame: &mut ExceptionFrame) {
    panic_exception("Load page fault", frame);
}

/// Handle store page fault
fn handle_store_page_fault(frame: &mut ExceptionFrame) {
    panic_exception("Store page fault", frame);
}

/// Unhandled exception
fn unhandled_exception(frame: &ExceptionFrame) {
    panic_exception("Unhandled exception", frame);
}

/// Panic on exception (for fatal errors)
fn panic_exception(msg: &str, frame: &ExceptionFrame) -> ! {
    // In a real system, this would log detailed info and halt/reset
    // For now, just loop forever
    loop {
        super::wfi();
    }
}

// ============================================================================
// Exception Information
// ============================================================================

/// Get human-readable exception name
pub fn exception_name(code: usize) -> &'static str {
    match code {
        cause::INSTRUCTION_MISALIGNED => "Instruction address misaligned",
        cause::INSTRUCTION_ACCESS_FAULT => "Instruction access fault",
        cause::ILLEGAL_INSTRUCTION => "Illegal instruction",
        cause::BREAKPOINT => "Breakpoint",
        cause::LOAD_MISALIGNED => "Load address misaligned",
        cause::LOAD_ACCESS_FAULT => "Load access fault",
        cause::STORE_MISALIGNED => "Store address misaligned",
        cause::STORE_ACCESS_FAULT => "Store access fault",
        cause::ECALL_FROM_U => "Environment call from U-mode",
        cause::ECALL_FROM_S => "Environment call from S-mode",
        cause::ECALL_FROM_M => "Environment call from M-mode",
        cause::INSTRUCTION_PAGE_FAULT => "Instruction page fault",
        cause::LOAD_PAGE_FAULT => "Load page fault",
        cause::STORE_PAGE_FAULT => "Store page fault",
        _ => "Unknown exception",
    }
}

/// Get human-readable interrupt name
pub fn interrupt_name(code: usize) -> &'static str {
    match code {
        1 => "Supervisor software interrupt",
        3 => "Machine software interrupt",
        5 => "Supervisor timer interrupt",
        7 => "Machine timer interrupt",
        9 => "Supervisor external interrupt",
        11 => "Machine external interrupt",
        _ => "Unknown interrupt",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exception_frame_is_interrupt() {
        // Exception (high bit clear)
        let frame = ExceptionFrame::new(0x0000_0002, 0, 0x1000, core::ptr::null_mut());
        assert!(!frame.is_interrupt());

        // Interrupt (high bit set) - using u32 for test
        let frame = ExceptionFrame::new(0x8000_0007, 0, 0x1000, core::ptr::null_mut());
        assert!(frame.is_interrupt());
    }

    #[test]
    fn test_exception_frame_code() {
        let frame = ExceptionFrame::new(0x8000_0007, 0, 0x1000, core::ptr::null_mut());
        assert_eq!(frame.code(), 7);

        let frame = ExceptionFrame::new(0x0000_0002, 0, 0x1000, core::ptr::null_mut());
        assert_eq!(frame.code(), 2);
    }

    #[test]
    fn test_exception_names() {
        assert_eq!(exception_name(cause::ILLEGAL_INSTRUCTION), "Illegal instruction");
        assert_eq!(exception_name(cause::BREAKPOINT), "Breakpoint");
        assert_eq!(exception_name(cause::ECALL_FROM_M), "Environment call from M-mode");
        assert_eq!(exception_name(999), "Unknown exception");
    }

    #[test]
    fn test_interrupt_names() {
        assert_eq!(interrupt_name(3), "Machine software interrupt");
        assert_eq!(interrupt_name(7), "Machine timer interrupt");
        assert_eq!(interrupt_name(11), "Machine external interrupt");
        assert_eq!(interrupt_name(999), "Unknown interrupt");
    }
}
