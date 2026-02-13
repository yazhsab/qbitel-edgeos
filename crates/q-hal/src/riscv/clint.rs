// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Core Local Interruptor (CLINT) Driver for RISC-V
//!
//! CLINT provides:
//! - Machine Timer (mtime, mtimecmp)
//! - Machine Software Interrupt (MSIP)
//!
//! This is essential for preemptive scheduling on RISC-V.

use crate::error::{HalError, HalResult};

/// Default CLINT base address (implementation defined)
pub const CLINT_BASE: usize = 0x0200_0000;

/// MSIP register offset (per hart)
const MSIP_OFFSET: usize = 0x0000;
/// MTIMECMP register offset (per hart)
const MTIMECMP_OFFSET: usize = 0x4000;
/// MTIME register offset
const MTIME_OFFSET: usize = 0xBFF8;

/// CLINT driver
pub struct Clint {
    /// Base address
    base: usize,
    /// Timer frequency in Hz
    frequency: u64,
    /// Current hart ID
    hart_id: usize,
}

impl Clint {
    /// Create a new CLINT driver
    #[must_use]
    pub const fn new(base: usize, frequency: u64) -> Self {
        Self {
            base,
            frequency,
            hart_id: 0,
        }
    }

    /// Create with default base address
    #[must_use]
    pub const fn with_default_base(frequency: u64) -> Self {
        Self::new(CLINT_BASE, frequency)
    }

    /// Set hart ID
    pub fn set_hart(&mut self, hart_id: usize) {
        self.hart_id = hart_id;
    }

    /// Read current timer value
    #[must_use]
    pub fn read_mtime(&self) -> u64 {
        let addr = (self.base + MTIME_OFFSET) as *const u64;
        // SAFETY: The mtime register is at a fixed offset (0xBFF8) from the CLINT
        // base address. The base address is set at construction time to a valid CLINT
        // MMIO region. Volatile read is required for correct MMIO semantics.
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write timer compare value for current hart
    pub fn write_mtimecmp(&self, value: u64) {
        let addr = (self.base + MTIMECMP_OFFSET + self.hart_id * 8) as *mut u64;
        // SAFETY: The mtimecmp register is at offset 0x4000 + (hart_id * 8) from the
        // CLINT base. The base is set at construction to a valid CLINT region.
        // Writing u64::MAX first prevents spurious timer interrupts during the update.
        unsafe {
            // Write max value first to prevent spurious interrupts
            core::ptr::write_volatile(addr, u64::MAX);
            core::ptr::write_volatile(addr, value);
        }
    }

    /// Read timer compare value for current hart
    #[must_use]
    pub fn read_mtimecmp(&self) -> u64 {
        let addr = (self.base + MTIMECMP_OFFSET + self.hart_id * 8) as *const u64;
        // SAFETY: The mtimecmp register is at offset 0x4000 + (hart_id * 8) from the
        // CLINT base. The base is set at construction to a valid CLINT MMIO region.
        // Volatile read is required for correct MMIO semantics.
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Set timer interrupt to trigger after specified ticks
    pub fn set_timer(&self, ticks: u64) {
        let current = self.read_mtime();
        self.write_mtimecmp(current.wrapping_add(ticks));
    }

    /// Set timer interrupt to trigger after specified microseconds
    pub fn set_timer_us(&self, us: u64) {
        let ticks = (us * self.frequency) / 1_000_000;
        self.set_timer(ticks);
    }

    /// Set timer interrupt to trigger after specified milliseconds
    pub fn set_timer_ms(&self, ms: u64) {
        let ticks = (ms * self.frequency) / 1_000;
        self.set_timer(ticks);
    }

    /// Clear timer interrupt (set mtimecmp to max)
    pub fn clear_timer(&self) {
        self.write_mtimecmp(u64::MAX);
    }

    /// Trigger software interrupt on specified hart
    pub fn send_ipi(&self, target_hart: usize) {
        let addr = (self.base + MSIP_OFFSET + target_hart * 4) as *mut u32;
        // SAFETY: The MSIP register is at offset 0x0000 + (target_hart * 4) from the
        // CLINT base. Writing 1 triggers a software interrupt on the target hart.
        // The caller must ensure target_hart is a valid hart ID for this platform.
        unsafe {
            core::ptr::write_volatile(addr, 1);
        }
    }

    /// Clear software interrupt on current hart
    pub fn clear_ipi(&self) {
        let addr = (self.base + MSIP_OFFSET + self.hart_id * 4) as *mut u32;
        // SAFETY: The MSIP register is at offset 0x0000 + (hart_id * 4) from the
        // CLINT base. Writing 0 clears the pending software interrupt for this hart.
        // hart_id is set at construction or via set_hart() by the caller.
        unsafe {
            core::ptr::write_volatile(addr, 0);
        }
    }

    /// Check if software interrupt is pending for current hart
    #[must_use]
    pub fn is_ipi_pending(&self) -> bool {
        let addr = (self.base + MSIP_OFFSET + self.hart_id * 4) as *const u32;
        // SAFETY: The MSIP register is at offset 0x0000 + (hart_id * 4) from the
        // CLINT base. Reading it returns the pending software interrupt status.
        // Volatile read is required for correct MMIO semantics.
        unsafe { core::ptr::read_volatile(addr) != 0 }
    }

    /// Get timer frequency
    #[must_use]
    pub const fn frequency(&self) -> u64 {
        self.frequency
    }

    /// Convert ticks to microseconds
    #[must_use]
    pub fn ticks_to_us(&self, ticks: u64) -> u64 {
        (ticks * 1_000_000) / self.frequency
    }

    /// Convert ticks to milliseconds
    #[must_use]
    pub fn ticks_to_ms(&self, ticks: u64) -> u64 {
        (ticks * 1_000) / self.frequency
    }

    /// Get elapsed time since boot in microseconds
    #[must_use]
    pub fn elapsed_us(&self) -> u64 {
        self.ticks_to_us(self.read_mtime())
    }

    /// Get elapsed time since boot in milliseconds
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.ticks_to_ms(self.read_mtime())
    }

    /// Delay for specified microseconds (busy wait)
    pub fn delay_us(&self, us: u64) {
        let start = self.read_mtime();
        let ticks = (us * self.frequency) / 1_000_000;
        while self.read_mtime().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }

    /// Delay for specified milliseconds (busy wait)
    pub fn delay_ms(&self, ms: u64) {
        self.delay_us(ms * 1000);
    }
}

impl Default for Clint {
    fn default() -> Self {
        Self::with_default_base(10_000_000) // 10 MHz default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_conversion() {
        let clint = Clint::with_default_base(10_000_000); // 10 MHz

        // 10 million ticks = 1 second = 1,000,000 us
        assert_eq!(clint.ticks_to_us(10_000_000), 1_000_000);

        // 10 million ticks = 1 second = 1,000 ms
        assert_eq!(clint.ticks_to_ms(10_000_000), 1_000);
    }
}
