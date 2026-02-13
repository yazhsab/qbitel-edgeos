// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! ARM Cortex-M architecture support
//!
//! This module provides architecture-specific implementations for ARM Cortex-M
//! processors, including:
//!
//! - Context switching via PendSV
//! - MPU (Memory Protection Unit) configuration
//! - SVC handler for system calls
//! - Exception handlers

pub mod context;
pub mod mpu;
pub mod syscall;
pub mod exceptions;

// Re-export main types
pub use context::{TaskContext, ContextSwitch, setup_context_switch, start_first_task};
pub use mpu::{MpuConfig, MpuRegionNumber, MpuRegionConfig, MpuRegionSize};
pub use syscall::{SyscallHandler, SyscallNumber};
pub use exceptions::ExceptionFrame;

use core::arch::asm;

// ============================================================================
// Cortex-M Core Register Addresses
// ============================================================================

/// System Control Block (SCB) base address
pub const SCB_BASE: u32 = 0xE000_ED00;

/// SCB registers
pub mod scb {
    /// Interrupt Control and State Register
    pub const ICSR: u32 = super::SCB_BASE + 0x04;
    /// Vector Table Offset Register
    pub const VTOR: u32 = super::SCB_BASE + 0x08;
    /// Application Interrupt and Reset Control Register
    pub const AIRCR: u32 = super::SCB_BASE + 0x0C;
    /// System Control Register
    pub const SCR: u32 = super::SCB_BASE + 0x10;
    /// Configuration and Control Register
    pub const CCR: u32 = super::SCB_BASE + 0x14;
    /// System Handler Priority Registers
    pub const SHPR1: u32 = super::SCB_BASE + 0x18;
    /// System Handler Priority Register 2 (SVCall priority)
    pub const SHPR2: u32 = super::SCB_BASE + 0x1C;
    /// System Handler Priority Register 3 (PendSV/SysTick priority)
    pub const SHPR3: u32 = super::SCB_BASE + 0x20;
    /// System Handler Control and State Register
    pub const SHCSR: u32 = super::SCB_BASE + 0x24;

    /// ICSR bits
    pub const ICSR_PENDSVSET: u32 = 1 << 28;
    /// ICSR bit: Clear PendSV pending status
    pub const ICSR_PENDSVCLR: u32 = 1 << 27;
    /// ICSR bit: Set SysTick pending status
    pub const ICSR_PENDSTSET: u32 = 1 << 26;
    /// ICSR bit: Clear SysTick pending status
    pub const ICSR_PENDSTCLR: u32 = 1 << 25;
}

/// SysTick base address
pub const SYSTICK_BASE: u32 = 0xE000_E010;

/// SysTick registers
pub mod systick {
    /// SysTick Control and Status Register
    pub const CTRL: u32 = super::SYSTICK_BASE + 0x00;
    /// SysTick Reload Value Register
    pub const LOAD: u32 = super::SYSTICK_BASE + 0x04;
    /// SysTick Current Value Register
    pub const VAL: u32 = super::SYSTICK_BASE + 0x08;
    /// SysTick Calibration Value Register
    pub const CALIB: u32 = super::SYSTICK_BASE + 0x0C;

    /// CTRL bits
    pub const CTRL_ENABLE: u32 = 1 << 0;
    /// SysTick CTRL bit: Enable SysTick exception request
    pub const CTRL_TICKINT: u32 = 1 << 1;
    /// SysTick CTRL bit: Use processor clock
    pub const CTRL_CLKSOURCE: u32 = 1 << 2;
    /// SysTick CTRL bit: Counter has counted to 0
    pub const CTRL_COUNTFLAG: u32 = 1 << 16;
}

/// NVIC base address
pub const NVIC_BASE: u32 = 0xE000_E100;

/// FPU registers
pub mod fpu {
    /// Coprocessor Access Control Register
    pub const CPACR: u32 = 0xE000_ED88;
    /// Floating Point Context Control Register
    pub const FPCCR: u32 = 0xE000_EF34;

    /// CP10 full access (bits 21:20 = 0b11)
    pub const CPACR_CP10_FULL: u32 = 0b11 << 20;
    /// CP11 full access (bits 23:22 = 0b11)
    pub const CPACR_CP11_FULL: u32 = 0b11 << 22;
    /// FPCCR: Automatic state preservation enable
    pub const FPCCR_ASPEN: u32 = 1 << 31;
    /// FPCCR: Lazy state preservation enable
    pub const FPCCR_LSPEN: u32 = 1 << 30;
}

// ============================================================================
// Core Functions
// ============================================================================

/// Trigger PendSV exception (for context switching)
#[inline]
pub fn trigger_pendsv() {
    // SAFETY: Writing PENDSVSET to ICSR (0xE000_ED04) is the standard mechanism to trigger
    // PendSV on Cortex-M. The register address is architecturally defined and always valid.
    // This is safe to call from any privilege level.
    unsafe {
        let icsr = scb::ICSR as *mut u32;
        core::ptr::write_volatile(icsr, scb::ICSR_PENDSVSET);
    }
}

/// Clear pending PendSV exception
#[inline]
pub fn clear_pendsv() {
    // SAFETY: Writing PENDSVCLR to ICSR clears a pending PendSV exception. The ICSR register
    // address is architecturally defined and always valid.
    unsafe {
        let icsr = scb::ICSR as *mut u32;
        core::ptr::write_volatile(icsr, scb::ICSR_PENDSVCLR);
    }
}

/// Enable interrupts
#[inline]
pub fn enable_interrupts() {
    // SAFETY: CPSIE I clears PRIMASK, enabling all maskable interrupts. This is a standard
    // ARM instruction, always safe in privileged mode.
    unsafe {
        asm!("cpsie i", options(nomem, nostack));
    }
}

/// Disable interrupts
#[inline]
pub fn disable_interrupts() {
    // SAFETY: CPSID I sets PRIMASK, disabling all maskable interrupts. Always safe in
    // privileged mode.
    unsafe {
        asm!("cpsid i", options(nomem, nostack));
    }
}

/// Disable interrupts and return previous state
#[inline]
pub fn disable_interrupts_save() -> u32 {
    let primask: u32;
    // SAFETY: MRS reads the current PRIMASK value (saving interrupt state), then CPSID I
    // disables interrupts. Both operations are standard ARM instructions, safe in privileged
    // mode. The saved value can later be restored with restore_interrupts().
    unsafe {
        asm!(
            "mrs {}, PRIMASK",
            "cpsid i",
            out(reg) primask,
            options(nomem, nostack)
        );
    }
    primask
}

/// Restore interrupt state
#[inline]
pub fn restore_interrupts(primask: u32) {
    // SAFETY: MSR restores the PRIMASK register to a previously-saved value, re-enabling
    // interrupts if they were previously enabled. The caller must provide a value obtained
    // from disable_interrupts_save().
    unsafe {
        asm!(
            "msr PRIMASK, {}",
            in(reg) primask,
            options(nomem, nostack)
        );
    }
}

/// Wait for interrupt (sleep until interrupt occurs)
#[inline]
pub fn wfi() {
    // SAFETY: WFI (Wait For Interrupt) is always safe. It halts the processor until an
    // interrupt occurs, reducing power consumption.
    unsafe {
        asm!("wfi", options(nomem, nostack));
    }
}

/// Wait for event
#[inline]
pub fn wfe() {
    // SAFETY: WFE (Wait For Event) is always safe. It halts the processor until an event or
    // interrupt occurs.
    unsafe {
        asm!("wfe", options(nomem, nostack));
    }
}

/// Send event (wakes up cores waiting with WFE)
#[inline]
pub fn sev() {
    // SAFETY: SEV (Send Event) is always safe. It sends an event signal to all processors in
    // a multiprocessor system.
    unsafe {
        asm!("sev", options(nomem, nostack));
    }
}

/// Data Synchronization Barrier
#[inline]
pub fn dsb() {
    // SAFETY: DSB SY (Data Synchronization Barrier) is always safe. It ensures all
    // outstanding memory transactions complete before the next instruction.
    unsafe {
        asm!("dsb sy", options(nomem, nostack));
    }
}

/// Instruction Synchronization Barrier
#[inline]
pub fn isb() {
    // SAFETY: ISB SY (Instruction Synchronization Barrier) is always safe. It flushes the
    // processor pipeline and ensures subsequent instructions are fetched fresh.
    unsafe {
        asm!("isb sy", options(nomem, nostack));
    }
}

/// Data Memory Barrier
#[inline]
pub fn dmb() {
    // SAFETY: DMB SY (Data Memory Barrier) is always safe. It ensures that all memory
    // accesses before the barrier are visible to all bus masters before any accesses after
    // the barrier.
    unsafe {
        asm!("dmb sy", options(nomem, nostack));
    }
}

/// Get current stack pointer (PSP or MSP depending on mode)
#[inline]
pub fn get_sp() -> u32 {
    let sp: u32;
    // SAFETY: Reading the stack pointer register is a non-destructive operation, always safe.
    unsafe {
        asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
    }
    sp
}

/// Get Process Stack Pointer (PSP)
#[inline]
pub fn get_psp() -> u32 {
    let psp: u32;
    // SAFETY: Reading PSP (Process Stack Pointer) is a non-destructive operation. Requires
    // privileged mode, which kernel code always has.
    unsafe {
        asm!("mrs {}, PSP", out(reg) psp, options(nomem, nostack));
    }
    psp
}

/// Set Process Stack Pointer (PSP)
#[inline]
pub fn set_psp(psp: u32) {
    // SAFETY: Writing PSP changes the process stack pointer. The caller must ensure the new
    // value points to a valid, properly aligned stack. Only called during context setup.
    unsafe {
        asm!("msr PSP, {}", in(reg) psp, options(nomem, nostack));
    }
}

/// Get Main Stack Pointer (MSP)
#[inline]
pub fn get_msp() -> u32 {
    let msp: u32;
    // SAFETY: Reading MSP (Main Stack Pointer) is non-destructive, always safe in privileged
    // mode.
    unsafe {
        asm!("mrs {}, MSP", out(reg) msp, options(nomem, nostack));
    }
    msp
}

/// Set Main Stack Pointer (MSP)
#[inline]
pub fn set_msp(msp: u32) {
    // SAFETY: Writing MSP changes the main stack pointer. The caller must ensure the new
    // value points to valid stack memory. Only used during early initialization.
    unsafe {
        asm!("msr MSP, {}", in(reg) msp, options(nomem, nostack));
    }
}

/// Get CONTROL register
#[inline]
pub fn get_control() -> u32 {
    let control: u32;
    // SAFETY: Reading the CONTROL register is non-destructive, always safe in privileged
    // mode.
    unsafe {
        asm!("mrs {}, CONTROL", out(reg) control, options(nomem, nostack));
    }
    control
}

/// Set CONTROL register
#[inline]
pub fn set_control(control: u32) {
    // SAFETY: Writing CONTROL changes privilege level and stack pointer selection. The ISB
    // ensures the pipeline is flushed after the change. Must be called from privileged mode.
    unsafe {
        asm!("msr CONTROL, {}", in(reg) control, options(nomem, nostack));
        asm!("isb", options(nomem, nostack));
    }
}

/// CONTROL register bits
pub mod control {
    /// Thread mode uses MSP (0) or PSP (1)
    pub const SPSEL: u32 = 1 << 1;
    /// Thread mode is privileged (0) or unprivileged (1)
    pub const NPRIV: u32 = 1 << 0;
    /// FPU context is active (Cortex-M4F/M7/M33)
    pub const FPCA: u32 = 1 << 2;
}

/// Switch to using PSP in Thread mode
#[inline]
pub fn use_psp() {
    let control = get_control();
    set_control(control | control::SPSEL);
}

/// Switch to using MSP in Thread mode
#[inline]
pub fn use_msp() {
    let control = get_control();
    set_control(control & !control::SPSEL);
}

/// Check if currently in handler mode
#[inline]
pub fn is_handler_mode() -> bool {
    let ipsr: u32;
    // SAFETY: Reading IPSR is non-destructive and always safe. Returns the exception number
    // (0 = Thread mode).
    unsafe {
        asm!("mrs {}, IPSR", out(reg) ipsr, options(nomem, nostack));
    }
    ipsr != 0
}

/// Get current exception number (0 = Thread mode)
#[inline]
pub fn get_exception_number() -> u8 {
    let ipsr: u32;
    // SAFETY: Reading IPSR is non-destructive, always safe.
    unsafe {
        asm!("mrs {}, IPSR", out(reg) ipsr, options(nomem, nostack));
    }
    (ipsr & 0xFF) as u8
}

/// Configure SysTick timer
pub fn configure_systick(reload_value: u32) {
    // SAFETY: SysTick registers (CTRL, LOAD, VAL) at 0xE000_E010-0xE000_E018 are
    // architecturally-defined Cortex-M registers. Writing them configures the system timer.
    // volatile accesses are required for MMIO registers. The sequence (disable -> set reload
    // -> clear -> enable) is the standard SysTick configuration procedure.
    unsafe {
        let ctrl = systick::CTRL as *mut u32;
        let load = systick::LOAD as *mut u32;
        let val = systick::VAL as *mut u32;

        // Disable SysTick
        core::ptr::write_volatile(ctrl, 0);

        // Set reload value
        core::ptr::write_volatile(load, reload_value - 1);

        // Clear current value
        core::ptr::write_volatile(val, 0);

        // Enable SysTick with interrupt, using processor clock
        core::ptr::write_volatile(
            ctrl,
            systick::CTRL_ENABLE | systick::CTRL_TICKINT | systick::CTRL_CLKSOURCE
        );
    }
}

/// Set exception priority
pub fn set_exception_priority(exception: u8, priority: u8) {
    // Exception numbers 4-6 (MemManage, BusFault, UsageFault) are in SHPR1
    // Exception numbers 11 (SVCall) is in SHPR2
    // Exception numbers 14-15 (PendSV, SysTick) are in SHPR3

    // SAFETY: SHPR1-SHPR3 are architecturally-defined SCB registers for setting exception
    // priorities. Read-modify-write is used to change only the target exception's priority
    // byte. volatile accesses are required for MMIO.
    unsafe {
        match exception {
            4..=6 => {
                let shpr1 = scb::SHPR1 as *mut u32;
                let shift = (exception - 4) * 8;
                let mask = !(0xFF << shift);
                let val = core::ptr::read_volatile(shpr1);
                core::ptr::write_volatile(shpr1, (val & mask) | ((priority as u32) << shift));
            }
            11 => {
                let shpr2 = scb::SHPR2 as *mut u32;
                let val = core::ptr::read_volatile(shpr2);
                core::ptr::write_volatile(shpr2, (val & 0x00FF_FFFF) | ((priority as u32) << 24));
            }
            14 => {
                // PendSV
                let shpr3 = scb::SHPR3 as *mut u32;
                let val = core::ptr::read_volatile(shpr3);
                core::ptr::write_volatile(shpr3, (val & 0xFF00_FFFF) | ((priority as u32) << 16));
            }
            15 => {
                // SysTick
                let shpr3 = scb::SHPR3 as *mut u32;
                let val = core::ptr::read_volatile(shpr3);
                core::ptr::write_volatile(shpr3, (val & 0x00FF_FFFF) | ((priority as u32) << 24));
            }
            _ => {}
        }
    }
}

/// Initialize Cortex-M core for RTOS operation
pub fn init_core() {
    // Set PendSV to lowest priority (for context switching)
    set_exception_priority(14, 0xFF);

    // Set SysTick to second-lowest priority
    set_exception_priority(15, 0xFE);

    // Set SVCall to higher priority than PendSV
    set_exception_priority(11, 0x80);

    // Enable FPU: grant full access to CP10 and CP11
    // SAFETY: CPACR (0xE000_ED88) and FPCCR (0xE000_EF34) are architecturally-defined FPU
    // configuration registers. Enabling CP10/CP11 full access and lazy stacking is the
    // standard FPU initialization sequence on Cortex-M4F/M7/M33. volatile accesses required
    // for MMIO.
    unsafe {
        let cpacr = fpu::CPACR as *mut u32;
        let val = core::ptr::read_volatile(cpacr);
        core::ptr::write_volatile(cpacr, val | fpu::CPACR_CP10_FULL | fpu::CPACR_CP11_FULL);

        // Configure FPCCR for lazy stacking (reduces context switch overhead)
        let fpccr = fpu::FPCCR as *mut u32;
        let val = core::ptr::read_volatile(fpccr);
        core::ptr::write_volatile(fpccr, val | fpu::FPCCR_ASPEN | fpu::FPCCR_LSPEN);
    }

    // Ensure barriers before enabling interrupts
    dsb();
    isb();
}

// ============================================================================
// NVIC (Nested Vectored Interrupt Controller)
// ============================================================================

/// NVIC register offsets from NVIC_BASE (0xE000_E100)
pub mod nvic {
    use super::NVIC_BASE;

    /// Interrupt Set-Enable Registers (8 x 32-bit)
    pub const ISER_BASE: u32 = NVIC_BASE;
    /// Interrupt Clear-Enable Registers
    pub const ICER_BASE: u32 = NVIC_BASE + 0x080;
    /// Interrupt Set-Pending Registers
    pub const ISPR_BASE: u32 = NVIC_BASE + 0x100;
    /// Interrupt Clear-Pending Registers
    pub const ICPR_BASE: u32 = NVIC_BASE + 0x180;
    /// Interrupt Active Bit Registers
    pub const IABR_BASE: u32 = NVIC_BASE + 0x200;
    /// Interrupt Priority Registers (byte-addressable)
    pub const IPR_BASE: u32 = NVIC_BASE + 0x300;

    /// Maximum number of external interrupts supported
    pub const MAX_IRQS: u16 = 240;
}

/// Maximum number of IRQ handlers in the software dispatch table
const NVIC_HANDLER_TABLE_SIZE: usize = 150;

/// Software interrupt handler table
///
/// Stores function pointers for runtime-registered interrupt handlers.
/// Indexed by IRQ number (0-based, i.e., exception_number - 16).
static mut INTERRUPT_HANDLERS: [Option<fn()>; NVIC_HANDLER_TABLE_SIZE] =
    [None; NVIC_HANDLER_TABLE_SIZE];

/// Enable an external interrupt in the NVIC
///
/// # Arguments
/// * `irq` - IRQ number (0-based device interrupt number)
pub fn nvic_enable_irq(irq: u16) {
    if irq >= nvic::MAX_IRQS {
        return;
    }
    let reg_index = (irq / 32) as u32;
    let bit_pos = irq % 32;
    // SAFETY: ISER registers at NVIC_BASE (0xE000_E100) are architecturally-defined. Writing
    // a 1-bit to the corresponding position enables the IRQ. The bounds check on irq is done
    // above. volatile access required for MMIO.
    unsafe {
        let iser = (nvic::ISER_BASE + reg_index * 4) as *mut u32;
        core::ptr::write_volatile(iser, 1 << bit_pos);
    }
}

/// Disable an external interrupt in the NVIC
///
/// # Arguments
/// * `irq` - IRQ number (0-based device interrupt number)
pub fn nvic_disable_irq(irq: u16) {
    if irq >= nvic::MAX_IRQS {
        return;
    }
    let reg_index = (irq / 32) as u32;
    let bit_pos = irq % 32;
    // SAFETY: ICER registers disable interrupts. Same safety invariants as nvic_enable_irq.
    // Followed by DSB+ISB to ensure the disable takes effect before returning.
    unsafe {
        let icer = (nvic::ICER_BASE + reg_index * 4) as *mut u32;
        core::ptr::write_volatile(icer, 1 << bit_pos);
    }
    dsb();
    isb();
}

/// Set an interrupt as pending
pub fn nvic_set_pending(irq: u16) {
    if irq >= nvic::MAX_IRQS {
        return;
    }
    let reg_index = (irq / 32) as u32;
    let bit_pos = irq % 32;
    // SAFETY: ISPR register writes to set a pending interrupt. Bounds-checked above. volatile
    // required for MMIO.
    unsafe {
        let ispr = (nvic::ISPR_BASE + reg_index * 4) as *mut u32;
        core::ptr::write_volatile(ispr, 1 << bit_pos);
    }
}

/// Clear a pending interrupt
pub fn nvic_clear_pending(irq: u16) {
    if irq >= nvic::MAX_IRQS {
        return;
    }
    let reg_index = (irq / 32) as u32;
    let bit_pos = irq % 32;
    // SAFETY: ICPR register writes to clear a pending interrupt. Bounds-checked above.
    // volatile required for MMIO.
    unsafe {
        let icpr = (nvic::ICPR_BASE + reg_index * 4) as *mut u32;
        core::ptr::write_volatile(icpr, 1 << bit_pos);
    }
}

/// Check if an interrupt is active (currently being serviced)
pub fn nvic_is_active(irq: u16) -> bool {
    if irq >= nvic::MAX_IRQS {
        return false;
    }
    let reg_index = (irq / 32) as u32;
    let bit_pos = irq % 32;
    // SAFETY: IABR register reads to check if an interrupt is active. Bounds-checked above.
    // volatile required for MMIO.
    unsafe {
        let iabr = (nvic::IABR_BASE + reg_index * 4) as *const u32;
        (core::ptr::read_volatile(iabr) & (1 << bit_pos)) != 0
    }
}

/// Set interrupt priority (0 = highest, 255 = lowest)
///
/// On Cortex-M7, typically only the upper 4 bits are implemented,
/// giving 16 priority levels. Writing 0x10 and 0x1F both result in
/// priority level 1.
pub fn nvic_set_priority(irq: u16, priority: u8) {
    if irq >= nvic::MAX_IRQS {
        return;
    }
    // SAFETY: IPR registers set interrupt priority. Byte-addressable at NVIC_BASE + 0x300.
    // Bounds-checked above. volatile required for MMIO.
    unsafe {
        let ipr = (nvic::IPR_BASE + irq as u32) as *mut u8;
        core::ptr::write_volatile(ipr, priority);
    }
}

/// Get interrupt priority
pub fn nvic_get_priority(irq: u16) -> u8 {
    if irq >= nvic::MAX_IRQS {
        return 0;
    }
    // SAFETY: IPR register reads to get interrupt priority. Bounds-checked above. volatile
    // required for MMIO.
    unsafe {
        let ipr = (nvic::IPR_BASE + irq as u32) as *const u8;
        core::ptr::read_volatile(ipr)
    }
}

/// Register a software interrupt handler
///
/// The handler will be called from `DefaultHandler` when the corresponding
/// IRQ fires. Returns `Err(())` if the IRQ number is out of range.
///
/// # Arguments
/// * `irq` - IRQ number (0-based)
/// * `handler` - Function pointer to the handler
pub fn nvic_register_handler(irq: u16, handler: fn()) -> Result<(), ()> {
    if (irq as usize) >= NVIC_HANDLER_TABLE_SIZE {
        return Err(());
    }
    let primask = disable_interrupts_save();
    // SAFETY: Accesses the global INTERRUPT_HANDLERS array. Protected by a critical section
    // (disable_interrupts_save/restore_interrupts), ensuring no concurrent modification from
    // interrupt handlers. The bounds check is done above.
    unsafe {
        INTERRUPT_HANDLERS[irq as usize] = Some(handler);
    }
    restore_interrupts(primask);
    Ok(())
}

/// Unregister a software interrupt handler
pub fn nvic_unregister_handler(irq: u16) {
    if (irq as usize) >= NVIC_HANDLER_TABLE_SIZE {
        return;
    }
    let primask = disable_interrupts_save();
    // SAFETY: Same as nvic_register_handler -- protected by critical section and
    // bounds-checked.
    unsafe {
        INTERRUPT_HANDLERS[irq as usize] = None;
    }
    restore_interrupts(primask);
}

/// Dispatch an IRQ to its registered handler
///
/// Called from `DefaultHandler` when a device interrupt fires.
/// If no handler is registered, the interrupt is silently ignored.
pub fn nvic_dispatch(irq: u16) {
    if (irq as usize) >= NVIC_HANDLER_TABLE_SIZE {
        return;
    }
    // SAFETY: Reads from the global INTERRUPT_HANDLERS array. This is called from
    // DefaultHandler (interrupt context). The array is only modified during handler
    // registration which uses a critical section. The bounds check is done above.
    let handler = unsafe { INTERRUPT_HANDLERS[irq as usize] };
    if let Some(handler_fn) = handler {
        handler_fn();
    }
}
