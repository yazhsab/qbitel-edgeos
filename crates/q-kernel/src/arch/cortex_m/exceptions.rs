// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! ARM Cortex-M Exception Handlers
//!
//! This module provides exception handlers for ARM Cortex-M processors:
//!
//! - HardFault: Catches unrecoverable faults
//! - MemManage: Memory protection unit faults
//! - BusFault: Bus errors
//! - UsageFault: Undefined instructions, alignment, etc.
//! - SysTick: System timer interrupt
//!
//! # Fault Analysis
//!
//! The fault handlers analyze the Configurable Fault Status Register (CFSR)
//! to determine the cause of faults and provide diagnostic information.

use core::arch::{asm, global_asm};
use core::ptr;

// ============================================================================
// Fault Status Register Definitions
// ============================================================================

/// System Control Block addresses for fault analysis
#[allow(dead_code)]
mod scb {
    /// Configurable Fault Status Register
    pub const CFSR: u32 = 0xE000_ED28;
    /// Hard Fault Status Register
    pub const HFSR: u32 = 0xE000_ED2C;
    /// Debug Fault Status Register
    pub const DFSR: u32 = 0xE000_ED30;
    /// MemManage Fault Address Register
    pub const MMFAR: u32 = 0xE000_ED34;
    /// Bus Fault Address Register
    pub const BFAR: u32 = 0xE000_ED38;
    /// Auxiliary Fault Status Register
    pub const AFSR: u32 = 0xE000_ED3C;
}

/// CFSR bit definitions - MemManage Fault Status (bits 7:0)
#[allow(dead_code)]
mod mmfsr {
    /// Instruction access violation
    pub const IACCVIOL: u32 = 1 << 0;
    /// Data access violation
    pub const DACCVIOL: u32 = 1 << 1;
    /// MemManage fault on exception return
    pub const MUNSTKERR: u32 = 1 << 3;
    /// MemManage fault on exception entry
    pub const MSTKERR: u32 = 1 << 4;
    /// MemManage fault during lazy FP state preservation
    pub const MLSPERR: u32 = 1 << 5;
    /// MMFAR has valid address
    pub const MMARVALID: u32 = 1 << 7;
}

/// CFSR bit definitions - Bus Fault Status (bits 15:8)
#[allow(dead_code)]
mod bfsr {
    /// Instruction bus error
    pub const IBUSERR: u32 = 1 << 8;
    /// Precise data bus error
    pub const PRECISERR: u32 = 1 << 9;
    /// Imprecise data bus error
    pub const IMPRECISERR: u32 = 1 << 10;
    /// Bus fault on exception return
    pub const UNSTKERR: u32 = 1 << 11;
    /// Bus fault on exception entry
    pub const STKERR: u32 = 1 << 12;
    /// Bus fault during lazy FP state preservation
    pub const LSPERR: u32 = 1 << 13;
    /// BFAR has valid address
    pub const BFARVALID: u32 = 1 << 15;
}

/// CFSR bit definitions - Usage Fault Status (bits 31:16)
#[allow(dead_code)]
mod ufsr {
    /// Undefined instruction
    pub const UNDEFINSTR: u32 = 1 << 16;
    /// Invalid state (EPSR.T = 0)
    pub const INVSTATE: u32 = 1 << 17;
    /// Invalid exception return
    pub const INVPC: u32 = 1 << 18;
    /// Coprocessor disabled or not present
    pub const NOCP: u32 = 1 << 19;
    /// Stack limit violation (ARMv8-M)
    pub const STKOF: u32 = 1 << 20;
    /// Unaligned access
    pub const UNALIGNED: u32 = 1 << 24;
    /// Divide by zero
    pub const DIVBYZERO: u32 = 1 << 25;
}

/// HFSR bit definitions
#[allow(dead_code)]
mod hfsr {
    /// Debug event caused hard fault
    pub const DEBUGEVT: u32 = 1 << 31;
    /// Forced hard fault (escalated fault)
    pub const FORCED: u32 = 1 << 30;
    /// Vector table read error
    pub const VECTTBL: u32 = 1 << 1;
}

// ============================================================================
// Exception Frame
// ============================================================================

/// Exception frame pushed by hardware during exception entry
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
    /// Link Register
    pub lr: u32,
    /// Program Counter (faulting instruction)
    pub pc: u32,
    /// Program Status Register
    pub xpsr: u32,
}

impl ExceptionFrame {
    /// Get the address of the faulting instruction
    pub fn fault_address(&self) -> u32 {
        self.pc
    }
}

// ============================================================================
// Fault Information
// ============================================================================

/// Detailed fault information
#[derive(Debug, Clone, Copy)]
pub struct FaultInfo {
    /// Fault type
    pub fault_type: FaultType,
    /// Faulting address (if applicable)
    pub address: Option<u32>,
    /// Faulting instruction PC
    pub pc: u32,
    /// Additional flags
    pub flags: FaultFlags,
}

/// Type of fault
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    /// Hard fault
    HardFault,
    /// Memory management fault
    MemManageFault,
    /// Bus fault
    BusFault,
    /// Usage fault
    UsageFault,
    /// Unknown fault
    Unknown,
}

/// Fault detail flags
#[derive(Debug, Clone, Copy, Default)]
pub struct FaultFlags {
    /// Instruction access violation
    pub instruction_access: bool,
    /// Data access violation
    pub data_access: bool,
    /// Stacking error
    pub stacking_error: bool,
    /// Unstacking error
    pub unstacking_error: bool,
    /// Undefined instruction
    pub undefined_instruction: bool,
    /// Invalid state (Thumb bit)
    pub invalid_state: bool,
    /// Invalid exception return
    pub invalid_pc: bool,
    /// Divide by zero
    pub divide_by_zero: bool,
    /// Unaligned access
    pub unaligned_access: bool,
    /// Bus error (precise)
    pub bus_error_precise: bool,
    /// Bus error (imprecise)
    pub bus_error_imprecise: bool,
    /// Escalated from lower priority fault
    pub escalated: bool,
}

impl FaultInfo {
    /// Analyze fault registers and build fault info
    pub fn from_registers(frame: &ExceptionFrame) -> Self {
        // SAFETY: CFSR (0xE000_ED28) and HFSR (0xE000_ED2C) are Cortex-M SCB registers at
        // architecturally-defined addresses. Reading them is always valid and has no side
        // effects. volatile reads are necessary as hardware updates these registers
        // asynchronously during faults.
        let cfsr = unsafe { ptr::read_volatile(scb::CFSR as *const u32) };
        let hfsr = unsafe { ptr::read_volatile(scb::HFSR as *const u32) };

        let mut flags = FaultFlags::default();
        let mut address = None;
        let fault_type;

        // Check for hard fault
        if hfsr & hfsr::FORCED != 0 {
            flags.escalated = true;
        }

        // Check MemManage faults (CFSR bits 7:0)
        if cfsr & 0xFF != 0 {
            fault_type = FaultType::MemManageFault;
            flags.instruction_access = cfsr & mmfsr::IACCVIOL != 0;
            flags.data_access = cfsr & mmfsr::DACCVIOL != 0;
            flags.stacking_error = cfsr & mmfsr::MSTKERR != 0;
            flags.unstacking_error = cfsr & mmfsr::MUNSTKERR != 0;

            if cfsr & mmfsr::MMARVALID != 0 {
                // SAFETY: MMFAR (0xE000_ED34) is valid to read when MMARVALID bit is set
                // in CFSR, which we checked above.
                address = Some(unsafe { ptr::read_volatile(scb::MMFAR as *const u32) });
            }
        }
        // Check Bus faults (CFSR bits 15:8)
        else if cfsr & 0xFF00 != 0 {
            fault_type = FaultType::BusFault;
            flags.bus_error_precise = cfsr & bfsr::PRECISERR != 0;
            flags.bus_error_imprecise = cfsr & bfsr::IMPRECISERR != 0;
            flags.stacking_error = cfsr & bfsr::STKERR != 0;
            flags.unstacking_error = cfsr & bfsr::UNSTKERR != 0;

            if cfsr & bfsr::BFARVALID != 0 {
                // SAFETY: BFAR (0xE000_ED38) is valid to read when BFARVALID bit is set
                // in CFSR, which we checked above.
                address = Some(unsafe { ptr::read_volatile(scb::BFAR as *const u32) });
            }
        }
        // Check Usage faults (CFSR bits 31:16)
        else if cfsr & 0xFFFF0000 != 0 {
            fault_type = FaultType::UsageFault;
            flags.undefined_instruction = cfsr & ufsr::UNDEFINSTR != 0;
            flags.invalid_state = cfsr & ufsr::INVSTATE != 0;
            flags.invalid_pc = cfsr & ufsr::INVPC != 0;
            flags.divide_by_zero = cfsr & ufsr::DIVBYZERO != 0;
            flags.unaligned_access = cfsr & ufsr::UNALIGNED != 0;
        }
        // Unknown fault
        else {
            fault_type = FaultType::HardFault;
        }

        Self {
            fault_type,
            address,
            pc: frame.pc,
            flags,
        }
    }
}

// ============================================================================
// Fault Handler Callback
// ============================================================================

/// Type for fault handler callback
pub type FaultHandlerFn = fn(&ExceptionFrame, &FaultInfo);

/// Global fault handler callback
static mut FAULT_HANDLER: Option<FaultHandlerFn> = None;

/// Set custom fault handler
///
/// # Safety
/// Must be called before enabling interrupts
pub unsafe fn set_fault_handler(handler: FaultHandlerFn) {
    FAULT_HANDLER = Some(handler);
}

/// Default fault handler that loops forever
fn default_fault_handler(_frame: &ExceptionFrame, _info: &FaultInfo) {
    // In debug builds, we could log fault information
    // In production, we might trigger a watchdog reset

    loop {
        // SAFETY: WFI is always safe to execute. Used here to avoid busy-spinning in the
        // fault handler's infinite loop.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

// ============================================================================
// Exception Handlers
// ============================================================================

// Hard Fault handler (using global_asm! for stable Rust)
//
// This handler is called for unrecoverable faults or when a configurable
// fault handler is disabled.
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.HardFault_Handler",
    ".global HardFault_Handler",
    ".type HardFault_Handler, %function",
    ".thumb_func",
    "HardFault_Handler:",
    // Determine which stack was used
    "    tst lr, #4",
    "    ite eq",
    "    mrseq r0, msp",
    "    mrsne r0, psp",
    // Call C handler
    "    bl hard_fault_handler_c",
    // If handler returns, loop forever
    "1:  b 1b",
    ".size HardFault_Handler, . - HardFault_Handler",
);

/// C-callable hard fault handler
#[no_mangle]
extern "C" fn hard_fault_handler_c(frame: *const ExceptionFrame) {
    // SAFETY: The frame pointer is provided by the HardFault assembly trampoline, which
    // extracts it from MSP or PSP (the stack that was active when the fault occurred). The
    // pointer is valid because the hardware automatically stacks the exception frame.
    // FAULT_HANDLER is read-only here and was set during initialization before interrupts
    // were enabled.
    unsafe {
        let frame = &*frame;
        let info = FaultInfo::from_registers(frame);

        if let Some(handler) = FAULT_HANDLER {
            handler(frame, &info);
        } else {
            default_fault_handler(frame, &info);
        }
    }
}

// MemManage Fault handler (using global_asm! for stable Rust)
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.MemManage_Handler",
    ".global MemManage_Handler",
    ".type MemManage_Handler, %function",
    ".thumb_func",
    "MemManage_Handler:",
    "    tst lr, #4",
    "    ite eq",
    "    mrseq r0, msp",
    "    mrsne r0, psp",
    "    bl memmanage_handler_c",
    "1:  b 1b",
    ".size MemManage_Handler, . - MemManage_Handler",
);

#[no_mangle]
extern "C" fn memmanage_handler_c(frame: *const ExceptionFrame) {
    // SAFETY: Same invariants as hard_fault_handler_c -- the frame pointer comes from the
    // assembly trampoline and points to hardware-stacked registers. FAULT_HANDLER is a global
    // set once during init.
    unsafe {
        let frame = &*frame;
        let info = FaultInfo::from_registers(frame);

        if let Some(handler) = FAULT_HANDLER {
            handler(frame, &info);
        } else {
            default_fault_handler(frame, &info);
        }
    }
}

// Bus Fault handler (using global_asm! for stable Rust)
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.BusFault_Handler",
    ".global BusFault_Handler",
    ".type BusFault_Handler, %function",
    ".thumb_func",
    "BusFault_Handler:",
    "    tst lr, #4",
    "    ite eq",
    "    mrseq r0, msp",
    "    mrsne r0, psp",
    "    bl busfault_handler_c",
    "1:  b 1b",
    ".size BusFault_Handler, . - BusFault_Handler",
);

#[no_mangle]
extern "C" fn busfault_handler_c(frame: *const ExceptionFrame) {
    // SAFETY: Same invariants as hard_fault_handler_c -- the frame pointer comes from the
    // assembly trampoline and points to hardware-stacked registers. FAULT_HANDLER is a global
    // set once during init.
    unsafe {
        let frame = &*frame;
        let info = FaultInfo::from_registers(frame);

        if let Some(handler) = FAULT_HANDLER {
            handler(frame, &info);
        } else {
            default_fault_handler(frame, &info);
        }
    }
}

// Usage Fault handler (using global_asm! for stable Rust)
#[cfg(target_arch = "arm")]
global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.UsageFault_Handler",
    ".global UsageFault_Handler",
    ".type UsageFault_Handler, %function",
    ".thumb_func",
    "UsageFault_Handler:",
    "    tst lr, #4",
    "    ite eq",
    "    mrseq r0, msp",
    "    mrsne r0, psp",
    "    bl usagefault_handler_c",
    "1:  b 1b",
    ".size UsageFault_Handler, . - UsageFault_Handler",
);

#[no_mangle]
extern "C" fn usagefault_handler_c(frame: *const ExceptionFrame) {
    // SAFETY: Same invariants as hard_fault_handler_c -- the frame pointer comes from the
    // assembly trampoline and points to hardware-stacked registers. FAULT_HANDLER is a global
    // set once during init.
    unsafe {
        let frame = &*frame;
        let info = FaultInfo::from_registers(frame);

        if let Some(handler) = FAULT_HANDLER {
            handler(frame, &info);
        } else {
            default_fault_handler(frame, &info);
        }
    }
}

// ============================================================================
// SysTick Handler
// ============================================================================

/// Type for SysTick callback
pub type SysTickHandlerFn = fn();

/// Global SysTick handler callback
static mut SYSTICK_HANDLER: Option<SysTickHandlerFn> = None;

/// Set SysTick handler callback
///
/// # Safety
/// Must be called before enabling SysTick
pub unsafe fn set_systick_handler(handler: SysTickHandlerFn) {
    SYSTICK_HANDLER = Some(handler);
}

/// SysTick handler
///
/// This handler is called on each SysTick interrupt.
/// It typically triggers a context switch if preemptive scheduling is enabled.
#[no_mangle]
pub extern "C" fn SysTick_Handler() {
    // SAFETY: SYSTICK_HANDLER is a global function pointer set once during init (via
    // set_systick_handler) before SysTick is enabled. Once set, it is only read from this
    // interrupt context. trigger_pendsv writes to the ICSR register which is always safe
    // from handler mode.
    unsafe {
        if let Some(handler) = SYSTICK_HANDLER {
            handler();
        }

        // For preemptive scheduling, trigger PendSV
        // This allows any higher-priority interrupts to be handled first
        super::trigger_pendsv();
    }
}

// ============================================================================
// NMI Handler
// ============================================================================

/// Non-Maskable Interrupt handler
#[no_mangle]
pub extern "C" fn NMI_Handler() {
    // NMI could be triggered by:
    // - Clock security system
    // - Voltage detector
    // - SRAM parity error (STM32)

    // For now, just loop - a real implementation would
    // log the event and potentially reset
    loop {
        // SAFETY: WFI is always safe to execute. Used to avoid busy-spinning in the NMI
        // handler's infinite loop.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

// ============================================================================
// Default Handler for Unused Interrupts
// ============================================================================

/// Default handler for unused interrupts
///
/// Device interrupts (exception number >= 16) are dispatched to the
/// software handler table via `nvic_dispatch`. System exceptions that
/// reach this handler are treated as unexpected and loop forever.
#[no_mangle]
pub extern "C" fn DefaultHandler() {
    // Get the exception number
    let ipsr: u32;
    // SAFETY: Reading the IPSR (Interrupt Program Status Register) is a non-destructive
    // operation. It returns the exception number of the currently executing handler. The
    // register is always readable from handler mode.
    unsafe {
        asm!("mrs {}, IPSR", out(reg) ipsr, options(nomem, nostack));
    }

    let exception_number = (ipsr & 0xFF) as u16;

    // Device interrupts have exception numbers >= 16
    // IRQ number = exception_number - 16
    if exception_number >= 16 {
        let irq = exception_number - 16;
        super::nvic_dispatch(irq);
        return;
    }

    // Unexpected system exception — loop forever
    loop {
        // SAFETY: WFI is always safe. Used to avoid busy-spinning for unexpected system
        // exceptions.
        unsafe {
            asm!("wfi", options(nomem, nostack));
        }
    }
}

// ============================================================================
// Enable Fault Handlers
// ============================================================================

/// Enable all configurable fault handlers
///
/// By default, MemManage, BusFault, and UsageFault are escalated to HardFault.
/// This function enables them as separate handlers for better diagnostics.
pub fn enable_fault_handlers() {
    const SCB_SHCSR: u32 = 0xE000_ED24;
    const SHCSR_MEMFAULTENA: u32 = 1 << 16;
    const SHCSR_BUSFAULTENA: u32 = 1 << 17;
    const SHCSR_USGFAULTENA: u32 = 1 << 18;

    // SAFETY: SCB_SHCSR (0xE000_ED24) is an architecturally-defined Cortex-M register.
    // Read-modify-write to enable fault handlers is a standard operation. volatile accesses
    // are required for MMIO registers.
    unsafe {
        let shcsr = ptr::read_volatile(SCB_SHCSR as *const u32);
        ptr::write_volatile(
            SCB_SHCSR as *mut u32,
            shcsr | SHCSR_MEMFAULTENA | SHCSR_BUSFAULTENA | SHCSR_USGFAULTENA,
        );
    }

    super::dsb();
    super::isb();
}

/// Enable divide-by-zero and unaligned access traps
pub fn enable_usage_traps() {
    const SCB_CCR: u32 = 0xE000_ED14;
    const CCR_DIV_0_TRP: u32 = 1 << 4;
    const CCR_UNALIGN_TRP: u32 = 1 << 3;

    // SAFETY: SCB_CCR (0xE000_ED14) is an architecturally-defined Cortex-M register.
    // Read-modify-write to enable traps is a standard operation. volatile accesses required
    // for MMIO.
    unsafe {
        let ccr = ptr::read_volatile(SCB_CCR as *const u32);
        ptr::write_volatile(
            SCB_CCR as *mut u32,
            ccr | CCR_DIV_0_TRP | CCR_UNALIGN_TRP,
        );
    }

    super::dsb();
    super::isb();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_flags_default() {
        let flags = FaultFlags::default();
        assert!(!flags.instruction_access);
        assert!(!flags.undefined_instruction);
        assert!(!flags.divide_by_zero);
    }
}
