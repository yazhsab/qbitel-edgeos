// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Panic handling for Qbitel EdgeOS Microkernel
//!
//! Provides panic handler with:
//! - Fault register capture (CFSR, HFSR, MMFAR, BFAR on Cortex-M)
//! - Panic state persistence to backup SRAM (survives reset)
//! - Automatic system reset for recovery
//! - Previous-panic detection on boot

use core::panic::PanicInfo;

// =============================================================================
// Panic State (persisted to backup SRAM)
// =============================================================================

/// Magic value indicating valid panic state in backup SRAM
const PANIC_MAGIC: u32 = 0xDEAD_BEEF;

/// Backup SRAM base address (STM32H7)
#[cfg(target_arch = "arm")]
const BKPSRAM_BASE: u32 = 0x3800_0000;

/// SCB register addresses (ARM Cortex-M)
#[cfg(target_arch = "arm")]
mod scb {
    /// Configurable Fault Status Register
    pub const CFSR: u32 = 0xE000_ED28;
    /// Hard Fault Status Register
    pub const HFSR: u32 = 0xE000_ED2C;
    /// MemManage Fault Address Register
    pub const MMFAR: u32 = 0xE000_ED34;
    /// BusFault Address Register
    pub const BFAR: u32 = 0xE000_ED38;
    /// Application Interrupt and Reset Control Register
    pub const AIRCR: u32 = 0xE000_ED0C;
}

/// Captured panic state for post-mortem debugging
///
/// This structure is written to backup SRAM on panic and can be
/// read after reset to diagnose the failure.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PanicState {
    /// Magic value (PANIC_MAGIC if valid)
    pub magic: u32,
    /// Stack pointer at time of panic
    pub sp: u32,
    /// Link register (return address)
    pub lr: u32,
    /// Configurable Fault Status Register (Cortex-M)
    pub cfsr: u32,
    /// Hard Fault Status Register
    pub hfsr: u32,
    /// MemManage Fault Address Register
    pub mmfar: u32,
    /// BusFault Address Register
    pub bfar: u32,
    /// Current task ID (0xFF if unknown)
    pub task_id: u8,
    /// Padding for alignment
    _pad: [u8; 3],
    /// System tick count at panic time
    pub ticks: u64,
}

impl PanicState {
    /// Create an empty (invalid) panic state
    #[allow(dead_code)]
    const fn empty() -> Self {
        Self {
            magic: 0,
            sp: 0,
            lr: 0,
            cfsr: 0,
            hfsr: 0,
            mmfar: 0,
            bfar: 0,
            task_id: 0xFF,
            _pad: [0; 3],
            ticks: 0,
        }
    }
}

// =============================================================================
// Panic State Capture (ARM-specific)
// =============================================================================

/// Capture fault registers and CPU state
#[cfg(target_arch = "arm")]
fn capture_panic_state() -> PanicState {
    let sp: u32;
    let lr: u32;
    // SAFETY: Reading the SP and LR registers is a non-destructive operation that does not
    // affect program state. The nomem/nostack options are correct as these are pure register reads.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
        core::arch::asm!("mov {}, lr", out(reg) lr, options(nomem, nostack));
    }

    // SAFETY: These are reads from ARM Cortex-M System Control Block registers at their
    // architecturally-defined addresses (0xE000_EDxx). These addresses are always valid on any
    // Cortex-M processor and reading them has no side effects. volatile reads are used because
    // the hardware may update these registers asynchronously (e.g., during a fault).
    let cfsr = unsafe { core::ptr::read_volatile(scb::CFSR as *const u32) };
    let hfsr = unsafe { core::ptr::read_volatile(scb::HFSR as *const u32) };
    let mmfar = unsafe { core::ptr::read_volatile(scb::MMFAR as *const u32) };
    let bfar = unsafe { core::ptr::read_volatile(scb::BFAR as *const u32) };

    let task_id = crate::scheduler::current_task()
        .map(|id| id.0)
        .unwrap_or(0xFF);

    let ticks = crate::scheduler::ticks();

    PanicState {
        magic: PANIC_MAGIC,
        sp,
        lr,
        cfsr,
        hfsr,
        mmfar,
        bfar,
        task_id,
        _pad: [0; 3],
        ticks,
    }
}

/// Capture panic state on non-ARM (host) — returns minimal info
#[cfg(not(target_arch = "arm"))]
fn capture_panic_state() -> PanicState {
    let task_id = crate::scheduler::current_task()
        .map(|id| id.0)
        .unwrap_or(0xFF);

    let ticks = crate::scheduler::ticks();

    PanicState {
        magic: PANIC_MAGIC,
        sp: 0,
        lr: 0,
        cfsr: 0,
        hfsr: 0,
        mmfar: 0,
        bfar: 0,
        task_id,
        _pad: [0; 3],
        ticks,
    }
}

// =============================================================================
// Backup SRAM Persistence
// =============================================================================

/// Save panic state to backup SRAM (survives system reset)
#[cfg(target_arch = "arm")]
fn save_panic_state(state: &PanicState) {
    let dst = BKPSRAM_BASE as *mut PanicState;
    // SAFETY: BKPSRAM_BASE (0x3800_0000) is the architecturally-defined backup SRAM address
    // on STM32H7. This region is always mapped and writable when backup SRAM power is enabled
    // (which is done during early boot). The PanicState struct is repr(C) and Copy, so the
    // write is well-defined.
    unsafe {
        core::ptr::write_volatile(dst, *state);
    }
}

/// Save panic state — no-op on host
#[cfg(not(target_arch = "arm"))]
fn save_panic_state(_state: &PanicState) {
    // Nothing to persist on host/test targets
}

/// Check for a previous panic by reading backup SRAM
///
/// Call this early in boot (after enabling backup SRAM power).
/// Returns the panic state if the magic value is present, then
/// clears it so the next boot starts clean.
#[cfg(target_arch = "arm")]
pub fn check_previous_panic() -> Option<PanicState> {
    let src = BKPSRAM_BASE as *const PanicState;
    // SAFETY: Reading from BKPSRAM_BASE is safe when backup SRAM power is enabled. The memory
    // is always mapped at this fixed hardware address on STM32H7. The read_volatile is necessary
    // because the contents may have been written by a previous boot cycle.
    let state = unsafe { core::ptr::read_volatile(src) };

    if state.magic == PANIC_MAGIC {
        // Clear magic so we don't re-read stale data
        let magic_ptr = BKPSRAM_BASE as *mut u32;
        // SAFETY: Writing zero to the magic field clears the panic marker, preventing stale
        // reads on subsequent boots. The address is valid backup SRAM.
        unsafe { core::ptr::write_volatile(magic_ptr, 0) };
        Some(state)
    } else {
        None
    }
}

/// Check for previous panic — always None on host
#[cfg(not(target_arch = "arm"))]
pub fn check_previous_panic() -> Option<PanicState> {
    None
}

// =============================================================================
// System Reset
// =============================================================================

/// Trigger a system reset via SCB AIRCR
#[cfg(target_arch = "arm")]
fn trigger_system_reset() -> ! {
    // AIRCR key (0x05FA) + SYSRESETREQ (bit 2)
    const AIRCR_RESET: u32 = 0x05FA_0004;
    // SAFETY: The DSB instructions ensure all pending memory transactions complete before/after
    // the reset request. Writing the AIRCR register at its architecturally-defined address
    // (0xE000_ED0C) with the VECTKEY (0x05FA) and SYSRESETREQ bit triggers a system reset.
    // This is a well-defined operation on all Cortex-M processors.
    unsafe {
        core::arch::asm!("dsb sy", options(nomem, nostack));
        core::ptr::write_volatile(scb::AIRCR as *mut u32, AIRCR_RESET);
        core::arch::asm!("dsb sy", options(nomem, nostack));
    }
    // Should never reach here, but loop just in case
    loop {
        core::hint::spin_loop();
    }
}

/// System reset — loops forever on host (no hardware reset available)
#[cfg(not(target_arch = "arm"))]
fn trigger_system_reset() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Kernel panic handler
///
/// Captures fault state, persists to backup SRAM, and triggers system reset.
///
/// # Arguments
/// * `_message` - Panic message (not currently stored due to space constraints)
pub fn kernel_panic(_message: &str) -> ! {
    // 1. Disable interrupts
    // SAFETY: CPSID I disables all maskable interrupts by setting PRIMASK. This is required
    // to prevent further interrupt handling during the panic sequence. The instruction is
    // always safe to execute in privileged mode.
    #[cfg(target_arch = "arm")]
    unsafe {
        core::arch::asm!("cpsid i", options(nomem, nostack));
    }

    // SAFETY: Clears the MIE (Machine Interrupt Enable) bit in mstatus, disabling all
    // machine-mode interrupts. This is the RISC-V equivalent of CPSID on ARM. Required to
    // prevent further interrupts during panic handling.
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        core::arch::asm!("csrci mstatus, 0x8", options(nomem, nostack));
    }

    // 2. Capture state
    let state = capture_panic_state();

    // 3. Save to backup SRAM
    save_panic_state(&state);

    // 4. Reset (on ARM) or loop (on host)
    trigger_system_reset()
}

/// Panic handler for no_std environment
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    kernel_panic("panic handler invoked")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_state_size() {
        // Ensure PanicState fits in a reasonable backup SRAM footprint
        assert!(core::mem::size_of::<PanicState>() <= 64);
    }

    #[test]
    fn test_panic_state_alignment() {
        assert_eq!(core::mem::align_of::<PanicState>(), 8);
    }

    #[test]
    fn test_panic_state_empty() {
        let state = PanicState::empty();
        assert_ne!(state.magic, PANIC_MAGIC);
        assert_eq!(state.task_id, 0xFF);
    }

    #[test]
    fn test_capture_panic_state() {
        let state = capture_panic_state();
        assert_eq!(state.magic, PANIC_MAGIC);
        // On host, sp/lr/fault regs should be 0
        assert_eq!(state.sp, 0);
        assert_eq!(state.cfsr, 0);
    }

    #[test]
    fn test_check_previous_panic() {
        // On host, always returns None
        assert!(check_previous_panic().is_none());
    }
}
