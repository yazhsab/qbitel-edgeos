// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! RISC-V Hardware Abstraction Layer
//!
//! This module provides hardware drivers for RISC-V processors with
//! Physical Memory Protection (PMP).
//!
//! # Supported Platforms
//!
//! - SiFive HiFive series
//! - Generic RISC-V with PMP extension
//!
//! # Features
//!
//! - **PMP**: Physical Memory Protection for memory isolation
//! - **CLINT**: Core Local Interruptor for timer and IPI
//! - **PLIC**: Platform-Level Interrupt Controller
//!
//! # Memory Protection
//!
//! RISC-V PMP provides up to 16 memory protection regions with
//! configurable access permissions (R/W/X) for M-mode and U-mode.

pub mod pmp;
pub mod clint;

// Re-export main types
pub use pmp::{Pmp, PmpConfig, PmpRegion, PmpPermissions};

use crate::error::{HalError, HalResult};

/// RISC-V HAL instance
pub struct RiscvHal {
    /// PMP configuration
    pub pmp: Pmp,
    /// Initialization state
    initialized: bool,
}

impl RiscvHal {
    /// Create a new uninitialized HAL instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pmp: Pmp::new(),
            initialized: false,
        }
    }

    /// Initialize the HAL
    pub fn init(&mut self) -> HalResult<()> {
        // Initialize PMP for memory protection
        self.pmp.init()?;

        self.initialized = true;
        Ok(())
    }

    /// Check if HAL is initialized
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get current hart (hardware thread) ID
    #[must_use]
    pub fn hart_id() -> usize {
        let id: usize;
        // SAFETY: Reading mhartid CSR is a read-only operation that is always valid
        // in M-mode. It returns the hardware thread ID and has no side effects.
        unsafe {
            core::arch::asm!("csrr {}, mhartid", out(reg) id, options(nomem, nostack));
        }
        id
    }

    /// Enable global interrupts
    pub fn enable_interrupts() {
        // SAFETY: Setting the MIE bit (bit 3) in the mstatus CSR enables global
        // machine-mode interrupts. This is valid in M-mode and is the standard
        // mechanism to enable interrupt handling on RISC-V.
        unsafe {
            core::arch::asm!("csrsi mstatus, 0x8", options(nomem, nostack)); // Set MIE bit
        }
    }

    /// Disable global interrupts
    pub fn disable_interrupts() {
        // SAFETY: Clearing the MIE bit (bit 3) in the mstatus CSR disables global
        // machine-mode interrupts. This is valid in M-mode and is the standard
        // mechanism to disable interrupt handling on RISC-V.
        unsafe {
            core::arch::asm!("csrci mstatus, 0x8", options(nomem, nostack)); // Clear MIE bit
        }
    }

    /// Wait for interrupt (low power mode)
    pub fn wfi() {
        // SAFETY: The WFI (Wait For Interrupt) instruction is a hint that puts the
        // hart into a low-power idle state until an interrupt occurs. It is always
        // valid in M-mode and has no side effects beyond power management.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}

impl Default for RiscvHal {
    fn default() -> Self {
        Self::new()
    }
}

/// CSR (Control and Status Register) utilities
pub mod csr {
    /// Read a CSR
    #[macro_export]
    macro_rules! read_csr {
        ($csr:literal) => {{
            let value: usize;
            // SAFETY: Reading a CSR via CSRR is valid when executing in a privilege
            // mode that has access to the specified CSR. The caller is responsible
            // for ensuring the CSR name is valid and accessible.
            unsafe {
                core::arch::asm!(concat!("csrr {}, ", $csr), out(reg) value, options(nomem, nostack));
            }
            value
        }};
    }

    /// Write a CSR
    #[macro_export]
    macro_rules! write_csr {
        ($csr:literal, $value:expr) => {{
            let val: usize = $value;
            // SAFETY: Writing a CSR via CSRW is valid when executing in a privilege
            // mode that has access to the specified CSR. The caller is responsible
            // for ensuring the CSR name is valid, accessible, and the value is sound.
            unsafe {
                core::arch::asm!(concat!("csrw ", $csr, ", {}"), in(reg) val, options(nomem, nostack));
            }
        }};
    }

    /// Set bits in a CSR
    #[macro_export]
    macro_rules! set_csr {
        ($csr:literal, $value:expr) => {{
            let val: usize = $value;
            // SAFETY: Setting bits in a CSR via CSRS is valid when executing in a
            // privilege mode that has access to the specified CSR. The caller is
            // responsible for ensuring the CSR name and bit mask are valid.
            unsafe {
                core::arch::asm!(concat!("csrs ", $csr, ", {}"), in(reg) val, options(nomem, nostack));
            }
        }};
    }

    /// Clear bits in a CSR
    #[macro_export]
    macro_rules! clear_csr {
        ($csr:literal, $value:expr) => {{
            let val: usize = $value;
            // SAFETY: Clearing bits in a CSR via CSRC is valid when executing in a
            // privilege mode that has access to the specified CSR. The caller is
            // responsible for ensuring the CSR name and bit mask are valid.
            unsafe {
                core::arch::asm!(concat!("csrc ", $csr, ", {}"), in(reg) val, options(nomem, nostack));
            }
        }};
    }
}
