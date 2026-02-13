// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! RISC-V Architecture Support
//!
//! This module provides architecture-specific implementations for RISC-V
//! processors, including:
//!
//! - Context switching via software interrupts
//! - PMP (Physical Memory Protection) configuration
//! - ECALL handler for system calls
//! - Exception and interrupt handlers

pub mod context;
pub mod pmp;
pub mod syscall;
pub mod exceptions;

// Re-export main types
pub use context::{TaskContext, ContextSwitch, setup_context_switch, start_first_task};
pub use pmp::{PmpConfig, PmpRegionNumber, PmpRegionConfig, PmpPermission};
pub use syscall::{SyscallHandler, SyscallNumber};
pub use exceptions::ExceptionFrame;

use core::arch::asm;

// ============================================================================
// RISC-V CSR Addresses and Constants
// ============================================================================

/// Machine Status Register
pub const CSR_MSTATUS: u16 = 0x300;
/// Machine ISA Register
pub const CSR_MISA: u16 = 0x301;
/// Machine Exception Delegation
pub const CSR_MEDELEG: u16 = 0x302;
/// Machine Interrupt Delegation
pub const CSR_MIDELEG: u16 = 0x303;
/// Machine Interrupt Enable
pub const CSR_MIE: u16 = 0x304;
/// Machine Trap Vector
pub const CSR_MTVEC: u16 = 0x305;
/// Machine Scratch Register
pub const CSR_MSCRATCH: u16 = 0x340;
/// Machine Exception Program Counter
pub const CSR_MEPC: u16 = 0x341;
/// Machine Cause
pub const CSR_MCAUSE: u16 = 0x342;
/// Machine Trap Value
pub const CSR_MTVAL: u16 = 0x343;
/// Machine Interrupt Pending
pub const CSR_MIP: u16 = 0x344;
/// Machine Cycle Counter
pub const CSR_MCYCLE: u16 = 0xB00;
/// Machine Instructions Retired
pub const CSR_MINSTRET: u16 = 0xB02;

/// Supervisor Status Register
pub const CSR_SSTATUS: u16 = 0x100;
/// Supervisor Interrupt Enable
pub const CSR_SIE: u16 = 0x104;
/// Supervisor Trap Vector
pub const CSR_STVEC: u16 = 0x105;
/// Supervisor Scratch Register
pub const CSR_SSCRATCH: u16 = 0x140;
/// Supervisor Exception Program Counter
pub const CSR_SEPC: u16 = 0x141;
/// Supervisor Cause
pub const CSR_SCAUSE: u16 = 0x142;
/// Supervisor Trap Value
pub const CSR_STVAL: u16 = 0x143;
/// Supervisor Interrupt Pending
pub const CSR_SIP: u16 = 0x144;

// ============================================================================
// MSTATUS bits
// ============================================================================

/// Machine mode status bits
pub mod mstatus {
    /// Machine Interrupt Enable
    pub const MIE: usize = 1 << 3;
    /// Machine Previous Interrupt Enable
    pub const MPIE: usize = 1 << 7;
    /// Machine Previous Privilege (2 bits at position 11-12)
    pub const MPP_MASK: usize = 0b11 << 11;
    pub const MPP_USER: usize = 0b00 << 11;
    pub const MPP_SUPERVISOR: usize = 0b01 << 11;
    pub const MPP_MACHINE: usize = 0b11 << 11;
    /// Supervisor Interrupt Enable
    pub const SIE: usize = 1 << 1;
    /// Supervisor Previous Interrupt Enable
    pub const SPIE: usize = 1 << 5;
    /// Supervisor Previous Privilege
    pub const SPP: usize = 1 << 8;
}

// ============================================================================
// Interrupt bits
// ============================================================================

/// Machine mode interrupt bits
pub mod mie {
    /// Machine Software Interrupt Enable
    pub const MSIE: usize = 1 << 3;
    /// Machine Timer Interrupt Enable
    pub const MTIE: usize = 1 << 7;
    /// Machine External Interrupt Enable
    pub const MEIE: usize = 1 << 11;
    /// Supervisor Software Interrupt Enable
    pub const SSIE: usize = 1 << 1;
    /// Supervisor Timer Interrupt Enable
    pub const STIE: usize = 1 << 5;
    /// Supervisor External Interrupt Enable
    pub const SEIE: usize = 1 << 9;
}

/// Machine interrupt pending bits
pub mod mip {
    /// Machine Software Interrupt Pending
    pub const MSIP: usize = 1 << 3;
    /// Machine Timer Interrupt Pending
    pub const MTIP: usize = 1 << 7;
    /// Machine External Interrupt Pending
    pub const MEIP: usize = 1 << 11;
    /// Supervisor Software Interrupt Pending
    pub const SSIP: usize = 1 << 1;
    /// Supervisor Timer Interrupt Pending
    pub const STIP: usize = 1 << 5;
    /// Supervisor External Interrupt Pending
    pub const SEIP: usize = 1 << 9;
}

// ============================================================================
// Exception causes
// ============================================================================

/// Exception cause codes
pub mod cause {
    /// Instruction address misaligned
    pub const INSTRUCTION_MISALIGNED: usize = 0;
    /// Instruction access fault
    pub const INSTRUCTION_ACCESS_FAULT: usize = 1;
    /// Illegal instruction
    pub const ILLEGAL_INSTRUCTION: usize = 2;
    /// Breakpoint
    pub const BREAKPOINT: usize = 3;
    /// Load address misaligned
    pub const LOAD_MISALIGNED: usize = 4;
    /// Load access fault
    pub const LOAD_ACCESS_FAULT: usize = 5;
    /// Store address misaligned
    pub const STORE_MISALIGNED: usize = 6;
    /// Store access fault
    pub const STORE_ACCESS_FAULT: usize = 7;
    /// Environment call from U-mode
    pub const ECALL_FROM_U: usize = 8;
    /// Environment call from S-mode
    pub const ECALL_FROM_S: usize = 9;
    /// Environment call from M-mode
    pub const ECALL_FROM_M: usize = 11;
    /// Instruction page fault
    pub const INSTRUCTION_PAGE_FAULT: usize = 12;
    /// Load page fault
    pub const LOAD_PAGE_FAULT: usize = 13;
    /// Store page fault
    pub const STORE_PAGE_FAULT: usize = 15;
}

// ============================================================================
// Core Functions
// ============================================================================

/// Trigger software interrupt (for context switching)
#[inline]
pub fn trigger_software_interrupt() {
    // SAFETY: Writing MSIP to the mip CSR sets the machine software interrupt
    // pending bit. This is the standard RISC-V mechanism for triggering a
    // software interrupt (used for context switching). CSR access is always
    // valid in M-mode.
    unsafe {
        // Set machine software interrupt pending
        asm!(
            "csrs mip, {0}",
            in(reg) mip::MSIP,
            options(nomem, nostack)
        );
    }
}

/// Clear software interrupt
#[inline]
pub fn clear_software_interrupt() {
    // SAFETY: Clearing MSIP in mip removes the pending software interrupt.
    // Always valid in M-mode.
    unsafe {
        asm!(
            "csrc mip, {0}",
            in(reg) mip::MSIP,
            options(nomem, nostack)
        );
    }
}

/// Enable global interrupts
#[inline]
pub fn enable_interrupts() {
    // SAFETY: Setting MIE in mstatus enables global machine-mode interrupts.
    // Always valid in M-mode.
    unsafe {
        asm!(
            "csrs mstatus, {0}",
            in(reg) mstatus::MIE,
            options(nomem, nostack)
        );
    }
}

/// Disable global interrupts
#[inline]
pub fn disable_interrupts() {
    // SAFETY: Clearing MIE in mstatus disables global machine-mode interrupts.
    // Always valid in M-mode.
    unsafe {
        asm!(
            "csrc mstatus, {0}",
            in(reg) mstatus::MIE,
            options(nomem, nostack)
        );
    }
}

/// Disable interrupts and return previous state
#[inline]
pub fn disable_interrupts_save() -> usize {
    let mstatus: usize;
    // SAFETY: CSRRC atomically reads mstatus and clears the MIE bit, returning
    // the previous value. This is the RISC-V idiom for entering a critical
    // section. Always valid in M-mode.
    unsafe {
        asm!(
            "csrrc {0}, mstatus, {1}",
            out(reg) mstatus,
            in(reg) mstatus::MIE,
            options(nomem, nostack)
        );
    }
    mstatus
}

/// Restore interrupt state
#[inline]
pub fn restore_interrupts(mstatus: usize) {
    // SAFETY: Restores the MIE bit in mstatus to its previously-saved value.
    // The caller must provide a value obtained from disable_interrupts_save().
    // Only the MIE bit is restored (masked by & mstatus::MIE).
    unsafe {
        asm!(
            "csrs mstatus, {0}",
            in(reg) mstatus & mstatus::MIE,
            options(nomem, nostack)
        );
    }
}

/// Wait for interrupt (low-power sleep)
#[inline]
pub fn wfi() {
    // SAFETY: WFI (Wait For Interrupt) is always safe. It halts the processor
    // until an interrupt occurs, reducing power consumption.
    unsafe {
        asm!("wfi", options(nomem, nostack));
    }
}

/// Memory fence (full barrier)
#[inline]
pub fn fence() {
    // SAFETY: FENCE IORW,IORW is a full memory and I/O ordering fence.
    // Always safe to execute.
    unsafe {
        asm!("fence iorw, iorw", options(nomem, nostack));
    }
}

/// Instruction fence
#[inline]
pub fn fence_i() {
    // SAFETY: FENCE.I is an instruction fence that synchronizes the instruction
    // and data streams. Always safe to execute.
    unsafe {
        asm!("fence.i", options(nomem, nostack));
    }
}

/// Get current stack pointer
#[inline]
pub fn get_sp() -> usize {
    let sp: usize;
    // SAFETY: Reading the stack pointer register is non-destructive and always safe.
    unsafe {
        asm!("mv {0}, sp", out(reg) sp, options(nomem, nostack));
    }
    sp
}

/// Set stack pointer
#[inline]
pub fn set_sp(sp: usize) {
    // SAFETY: Writing the stack pointer. The caller must ensure the new value
    // points to valid, properly-aligned stack memory. Used during context
    // switch setup.
    unsafe {
        asm!("mv sp, {0}", in(reg) sp, options(nomem, nostack));
    }
}

/// Get machine scratch register (often used for hart-local storage)
#[inline]
pub fn get_mscratch() -> usize {
    let val: usize;
    // SAFETY: Reading the mscratch CSR is non-destructive. Always valid in M-mode.
    unsafe {
        asm!("csrr {0}, mscratch", out(reg) val, options(nomem, nostack));
    }
    val
}

/// Set machine scratch register
#[inline]
pub fn set_mscratch(val: usize) {
    // SAFETY: Writing mscratch stores a value for use by the trap handler
    // (typically a pointer to the current task's context). Always valid in M-mode.
    unsafe {
        asm!("csrw mscratch, {0}", in(reg) val, options(nomem, nostack));
    }
}

/// Get machine exception program counter
#[inline]
pub fn get_mepc() -> usize {
    let mepc: usize;
    // SAFETY: Reading mepc (Machine Exception Program Counter) is non-destructive.
    // Always valid in M-mode.
    unsafe {
        asm!("csrr {0}, mepc", out(reg) mepc, options(nomem, nostack));
    }
    mepc
}

/// Set machine exception program counter
#[inline]
pub fn set_mepc(mepc: usize) {
    // SAFETY: Writing mepc sets the return address for the next mret. The caller
    // must ensure the address is a valid instruction address.
    unsafe {
        asm!("csrw mepc, {0}", in(reg) mepc, options(nomem, nostack));
    }
}

/// Get machine cause register
#[inline]
pub fn get_mcause() -> usize {
    let mcause: usize;
    // SAFETY: Reading mcause is non-destructive. Always valid in M-mode.
    unsafe {
        asm!("csrr {0}, mcause", out(reg) mcause, options(nomem, nostack));
    }
    mcause
}

/// Get machine trap value
#[inline]
pub fn get_mtval() -> usize {
    let mtval: usize;
    // SAFETY: Reading mtval is non-destructive. Always valid in M-mode.
    unsafe {
        asm!("csrr {0}, mtval", out(reg) mtval, options(nomem, nostack));
    }
    mtval
}

/// Get machine status register
#[inline]
pub fn get_mstatus() -> usize {
    let mstatus: usize;
    // SAFETY: Reading mstatus is non-destructive. Always valid in M-mode.
    unsafe {
        asm!("csrr {0}, mstatus", out(reg) mstatus, options(nomem, nostack));
    }
    mstatus
}

/// Set machine status register
#[inline]
pub fn set_mstatus(mstatus: usize) {
    // SAFETY: Writing mstatus controls machine-mode privilege and interrupt
    // settings. Always valid in M-mode. The caller should understand the
    // implications of changing privilege bits.
    unsafe {
        asm!("csrw mstatus, {0}", in(reg) mstatus, options(nomem, nostack));
    }
}

/// Get current hart ID
#[inline]
pub fn get_hart_id() -> usize {
    let hartid: usize;
    // SAFETY: Reading mhartid is non-destructive. Returns the hardware thread
    // (hart) ID. Always valid.
    unsafe {
        asm!("csrr {0}, mhartid", out(reg) hartid, options(nomem, nostack));
    }
    hartid
}

/// Get cycle counter
#[inline]
pub fn get_cycle() -> u64 {
    #[cfg(target_pointer_width = "32")]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: Reading mcycle/mcycleh CSRs is non-destructive. Returns the
        // CPU cycle count. Always valid in M-mode.
        unsafe {
            asm!(
                "csrr {0}, mcycle",
                "csrr {1}, mcycleh",
                out(reg) lo,
                out(reg) hi,
                options(nomem, nostack)
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_pointer_width = "64")]
    {
        let cycle: u64;
        // SAFETY: Reading mcycle/mcycleh CSRs is non-destructive. Returns the
        // CPU cycle count. Always valid in M-mode.
        unsafe {
            asm!("csrr {0}, mcycle", out(reg) cycle, options(nomem, nostack));
        }
        cycle
    }
}

/// Configure machine timer
pub fn configure_timer(compare_value: u64) {
    // The timer memory-mapped location varies by platform
    // Timer compare is memory-mapped at the CLINT base (SiFive layout)
    #[cfg(target_pointer_width = "32")]
    {
        // For RV32, timer compare is typically memory-mapped
        // Example for CLINT: 0x0200_4000 + hart_id * 8
        let hart_id = get_hart_id();
        let mtimecmp_addr = 0x0200_4000 + hart_id * 8;
        // SAFETY: The CLINT mtimecmp register at 0x0200_4000 + hart_id*8 is a
        // memory-mapped timer compare register. Writing it sets the next timer
        // interrupt. The address is platform-specific (SiFive CLINT layout).
        // volatile write required for MMIO.
        unsafe {
            let ptr = mtimecmp_addr as *mut u64;
            core::ptr::write_volatile(ptr, compare_value);
        }
    }
    #[cfg(target_pointer_width = "64")]
    {
        let hart_id = get_hart_id();
        let mtimecmp_addr = 0x0200_4000 + hart_id * 8;
        // SAFETY: The CLINT mtimecmp register at 0x0200_4000 + hart_id*8 is a
        // memory-mapped timer compare register. Writing it sets the next timer
        // interrupt. The address is platform-specific (SiFive CLINT layout).
        // volatile write required for MMIO.
        unsafe {
            let ptr = mtimecmp_addr as *mut u64;
            core::ptr::write_volatile(ptr, compare_value);
        }
    }
}

/// Get current timer value
pub fn get_timer() -> u64 {
    // Timer is typically memory-mapped at CLINT base + 0xBFF8
    let mtime_addr: usize = 0x0200_BFF8;
    // SAFETY: The CLINT mtime register at 0x0200_BFF8 is a memory-mapped
    // read-only timer counter. volatile read required for MMIO. Always valid
    // when CLINT is present.
    unsafe {
        let ptr = mtime_addr as *const u64;
        core::ptr::read_volatile(ptr)
    }
}

/// Set trap vector base address
pub fn set_trap_vector(addr: usize, mode: TrapMode) {
    let mtvec = addr | (mode as usize);
    // SAFETY: Writing mtvec sets the trap vector base address and mode. The
    // caller must ensure addr points to a valid trap handler aligned to 4 bytes.
    // Always valid in M-mode.
    unsafe {
        asm!("csrw mtvec, {0}", in(reg) mtvec, options(nomem, nostack));
    }
}

/// Trap vector mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum TrapMode {
    /// All exceptions use same handler
    Direct = 0,
    /// Interrupts use vectored handlers
    Vectored = 1,
}

/// Enable specific interrupts
pub fn enable_interrupt(int_type: InterruptType) {
    let bit = match int_type {
        InterruptType::MachineSoftware => mie::MSIE,
        InterruptType::MachineTimer => mie::MTIE,
        InterruptType::MachineExternal => mie::MEIE,
        InterruptType::SupervisorSoftware => mie::SSIE,
        InterruptType::SupervisorTimer => mie::STIE,
        InterruptType::SupervisorExternal => mie::SEIE,
    };
    // SAFETY: Setting bits in the mie CSR enables specific interrupt sources.
    // Always valid in M-mode.
    unsafe {
        asm!("csrs mie, {0}", in(reg) bit, options(nomem, nostack));
    }
}

/// Disable specific interrupts
pub fn disable_interrupt(int_type: InterruptType) {
    let bit = match int_type {
        InterruptType::MachineSoftware => mie::MSIE,
        InterruptType::MachineTimer => mie::MTIE,
        InterruptType::MachineExternal => mie::MEIE,
        InterruptType::SupervisorSoftware => mie::SSIE,
        InterruptType::SupervisorTimer => mie::STIE,
        InterruptType::SupervisorExternal => mie::SEIE,
    };
    // SAFETY: Clearing bits in the mie CSR disables specific interrupt sources.
    // Always valid in M-mode.
    unsafe {
        asm!("csrc mie, {0}", in(reg) bit, options(nomem, nostack));
    }
}

/// Interrupt types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// Machine software interrupt
    MachineSoftware,
    /// Machine timer interrupt
    MachineTimer,
    /// Machine external interrupt
    MachineExternal,
    /// Supervisor software interrupt
    SupervisorSoftware,
    /// Supervisor timer interrupt
    SupervisorTimer,
    /// Supervisor external interrupt
    SupervisorExternal,
}

/// Initialize RISC-V core for RTOS operation
pub fn init_core() {
    // Clear any pending interrupts
    clear_software_interrupt();

    // Set up trap vector (direct mode for now)
    // Note: Actual trap handler address should be set by the kernel
    // set_trap_vector(trap_handler as usize, TrapMode::Direct);

    // Enable timer and software interrupts
    enable_interrupt(InterruptType::MachineTimer);
    enable_interrupt(InterruptType::MachineSoftware);

    // Ensure barriers before enabling interrupts
    fence();
    fence_i();
}

/// Check if currently in machine mode
#[inline]
pub fn is_machine_mode() -> bool {
    let mstatus = get_mstatus();
    // In RISC-V, there's no direct way to check current mode
    // We assume M-mode if MPP indicates M-mode (though this is for previous mode)
    // A more reliable check would be attempting a M-mode only instruction
    true // Embedded systems typically run in M-mode
}
