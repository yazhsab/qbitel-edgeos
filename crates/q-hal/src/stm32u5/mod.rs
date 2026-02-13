// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32U5 Hardware Abstraction Layer
//!
//! This module provides hardware drivers for the STM32U5 series
//! microcontrollers (ARM Cortex-M33 with TrustZone-M).
//!
//! # Features
//!
//! - **TrustZone-M**: Full SAU/IDAU configuration
//! - **GTZC**: Global TrustZone Controller for peripheral security
//! - **Secure Flash**: Secure/Non-secure flash partitioning
//! - **TRNG**: True Random Number Generator
//! - **AES**: Hardware AES accelerator
//! - **PKA**: Public Key Accelerator (RSA, ECC, ECDSA)
//!
//! # Memory Map (STM32U575/585)
//!
//! - Flash: 0x0800_0000 - 0x081F_FFFF (2MB)
//! - SRAM1: 0x2000_0000 - 0x2003_FFFF (256KB)
//! - SRAM2: 0x2004_0000 - 0x2004_FFFF (64KB)
//! - SRAM3: 0x2005_0000 - 0x2005_FFFF (64KB)
//! - SRAM4: 0x2800_0000 - 0x2800_3FFF (16KB, backup domain)

pub mod sau;
pub mod gtzc;
pub mod flash;
pub mod rng;

// Re-export main types
pub use sau::{Sau, SauRegion, SauConfig};
pub use gtzc::{Gtzc, GtzcConfig, SecurePeripheral};

use crate::error::{HalError, HalResult};

/// STM32U5 system clock configuration
#[derive(Debug, Clone, Copy)]
pub struct ClockConfig {
    /// System clock frequency in Hz
    pub sysclk_hz: u32,
    /// AHB clock frequency in Hz
    pub hclk_hz: u32,
    /// APB1 clock frequency in Hz
    pub pclk1_hz: u32,
    /// APB2 clock frequency in Hz
    pub pclk2_hz: u32,
    /// APB3 clock frequency in Hz
    pub pclk3_hz: u32,
}

impl Default for ClockConfig {
    fn default() -> Self {
        Self {
            sysclk_hz: 160_000_000, // 160 MHz max
            hclk_hz: 160_000_000,
            pclk1_hz: 160_000_000,
            pclk2_hz: 160_000_000,
            pclk3_hz: 160_000_000,
        }
    }
}

/// STM32U5 HAL instance
pub struct Stm32u5Hal {
    /// Clock configuration
    pub clock: ClockConfig,
    /// SAU (Security Attribution Unit)
    pub sau: Sau,
    /// GTZC (Global TrustZone Controller)
    pub gtzc: Gtzc,
    /// Initialization state
    initialized: bool,
    /// TrustZone enabled
    trustzone_enabled: bool,
}

impl Stm32u5Hal {
    /// Create a new uninitialized HAL instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clock: ClockConfig {
                sysclk_hz: 160_000_000,
                hclk_hz: 160_000_000,
                pclk1_hz: 160_000_000,
                pclk2_hz: 160_000_000,
                pclk3_hz: 160_000_000,
            },
            sau: Sau::new(),
            gtzc: Gtzc::new(),
            initialized: false,
            trustzone_enabled: false,
        }
    }

    /// Initialize HAL with TrustZone enabled
    pub fn init_secure(&mut self) -> HalResult<()> {
        // Initialize SAU for secure/non-secure memory partitioning
        self.sau.init()?;

        // Initialize GTZC for peripheral security
        self.gtzc.init()?;

        // Apply default secure configuration
        self.apply_default_security_config()?;

        self.trustzone_enabled = true;
        self.initialized = true;
        Ok(())
    }

    /// Initialize HAL without TrustZone (for non-secure development)
    pub fn init(&mut self) -> HalResult<()> {
        self.initialized = true;
        self.trustzone_enabled = false;
        Ok(())
    }

    /// Apply default security configuration
    fn apply_default_security_config(&mut self) -> HalResult<()> {
        // Configure secure bootloader region
        self.sau.configure_region(SauRegion {
            number: 0,
            base: 0x0800_0000,     // Flash start
            limit: 0x0803_FFFF,    // First 256KB secure (bootloader + kernel)
            secure: true,
            enabled: true,
        })?;

        // Configure non-secure application region
        self.sau.configure_region(SauRegion {
            number: 1,
            base: 0x0804_0000,
            limit: 0x081F_FFFF,    // Remaining flash for app
            secure: false,
            enabled: true,
        })?;

        // Configure secure SRAM region
        self.sau.configure_region(SauRegion {
            number: 2,
            base: 0x2000_0000,
            limit: 0x2001_FFFF,    // First 128KB SRAM secure
            secure: true,
            enabled: true,
        })?;

        // Configure non-secure SRAM region
        self.sau.configure_region(SauRegion {
            number: 3,
            base: 0x2002_0000,
            limit: 0x2005_FFFF,    // Remaining SRAM non-secure
            secure: false,
            enabled: true,
        })?;

        // Configure NSC (Non-Secure Callable) region for secure function calls
        self.sau.configure_nsc_region(4, 0x0C03_E000, 0x0C03_FFFF)?;

        // Enable SAU
        self.sau.enable()?;

        // Configure critical peripherals as secure
        self.gtzc.set_peripheral_secure(SecurePeripheral::Rng)?;
        self.gtzc.set_peripheral_secure(SecurePeripheral::Aes)?;
        self.gtzc.set_peripheral_secure(SecurePeripheral::Pka)?;
        self.gtzc.set_peripheral_secure(SecurePeripheral::Hash)?;
        self.gtzc.set_peripheral_secure(SecurePeripheral::Saes)?;
        self.gtzc.set_peripheral_secure(SecurePeripheral::Flash)?;

        // Configure secure SRAM blocks via MPCBB (first 128KB = 512 blocks of 256 bytes)
        self.gtzc.configure_sram_range(1, 0, 511, true)?;

        Ok(())
    }

    /// Configure TrustZone with custom security boundaries
    ///
    /// # Arguments
    /// * `secure_flash_end` - End address of secure flash (e.g., 0x0803_FFFF for 256KB)
    /// * `secure_sram_end` - End address of secure SRAM (e.g., 0x2001_FFFF for 128KB)
    /// * `nsc_base` - Base address of Non-Secure Callable veneer table
    /// * `nsc_size` - Size of NSC region (must be 32-byte aligned)
    pub fn configure_trustzone(
        &mut self,
        secure_flash_end: u32,
        secure_sram_end: u32,
        nsc_base: u32,
        nsc_size: u32,
    ) -> HalResult<()> {
        // Validate parameters
        if (nsc_base & 0x1F) != 0 || (nsc_size & 0x1F) != 0 {
            return Err(HalError::InvalidParameter);
        }

        // Disable SAU during reconfiguration
        self.sau.disable()?;

        // Region 0: Secure flash (bootloader + kernel)
        self.sau.configure_region(SauRegion {
            number: 0,
            base: 0x0800_0000,
            limit: secure_flash_end | 0x1F, // Align to 32 bytes
            secure: true,
            enabled: true,
        })?;

        // Region 1: Non-secure flash (application)
        let ns_flash_base = (secure_flash_end + 1) & !0x1F;
        self.sau.configure_region(SauRegion {
            number: 1,
            base: ns_flash_base,
            limit: 0x081F_FFFF,
            secure: false,
            enabled: true,
        })?;

        // Region 2: Secure SRAM
        self.sau.configure_region(SauRegion {
            number: 2,
            base: 0x2000_0000,
            limit: secure_sram_end | 0x1F,
            secure: true,
            enabled: true,
        })?;

        // Region 3: Non-secure SRAM
        let ns_sram_base = (secure_sram_end + 1) & !0x1F;
        self.sau.configure_region(SauRegion {
            number: 3,
            base: ns_sram_base,
            limit: 0x2005_FFFF,
            secure: false,
            enabled: true,
        })?;

        // Region 4: NSC veneer table
        let nsc_limit = nsc_base + nsc_size - 1;
        self.sau.configure_nsc_region(4, nsc_base, nsc_limit)?;

        // Region 5: Secure peripherals (APB)
        self.sau.configure_region(SauRegion {
            number: 5,
            base: 0x4000_0000,
            limit: 0x4FFF_FFFF,
            secure: true,
            enabled: true,
        })?;

        // Region 6: Non-secure peripherals (APB alias)
        self.sau.configure_region(SauRegion {
            number: 6,
            base: 0x5000_0000,
            limit: 0x5FFF_FFFF,
            secure: false,
            enabled: true,
        })?;

        // Enable SAU
        self.sau.enable()?;

        // Configure MPCBB for SRAM based on secure boundary
        let secure_sram_size = (secure_sram_end - 0x2000_0000 + 1) as usize;
        let secure_blocks = (secure_sram_size + 255) / 256; // 256-byte blocks
        self.gtzc.configure_sram_range(1, 0, (secure_blocks - 1) as u16, true)?;

        self.trustzone_enabled = true;
        Ok(())
    }

    /// Lock TrustZone configuration to prevent modification
    ///
    /// After calling this, the security configuration cannot be changed
    /// until the next reset.
    pub fn lock_trustzone(&mut self) -> HalResult<()> {
        if !self.trustzone_enabled {
            return Err(HalError::InvalidState);
        }

        // Lock SAU configuration
        self.sau.lock()?;

        // Lock GTZC configuration
        self.gtzc.lock_all()?;

        // Lock secure SRAM blocks (first 512 blocks = 128KB)
        self.gtzc.lock_sram_blocks(1, 0, 511)?;

        Ok(())
    }

    /// Transition to non-secure state and execute non-secure code
    ///
    /// # Safety
    /// The entry point must be a valid non-secure function pointer.
    /// The non-secure stack must be properly set up.
    pub unsafe fn jump_to_nonsecure(&self, entry: u32, ns_sp: u32) -> ! {
        // Set non-secure stack pointer
        core::arch::asm!(
            "msr msp_ns, {sp}",
            sp = in(reg) ns_sp,
            options(nomem, nostack)
        );

        // Clear LSB to indicate non-secure target (TrustZone convention)
        let ns_entry = entry & !1;

        // Branch to non-secure code using BLXNS
        core::arch::asm!(
            "bic r0, {entry}, #1",  // Clear LSB for NS state
            "blxns r0",             // Branch with link to non-secure
            entry = in(reg) ns_entry,
            options(noreturn)
        );
    }

    /// Check if HAL is initialized
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Check if TrustZone is enabled
    #[must_use]
    pub const fn is_trustzone_enabled(&self) -> bool {
        self.trustzone_enabled
    }

    /// Get system clock frequency
    #[must_use]
    pub const fn sysclk(&self) -> u32 {
        self.clock.sysclk_hz
    }

    /// Check if currently in secure state
    #[must_use]
    pub fn is_secure(&self) -> bool {
        // Read CONTROL register SFPA bit
        let control: u32;
        // SAFETY: Reading the ARM CONTROL register via MRS is a read-only operation
        // that is always valid in secure privileged mode. It does not modify processor state.
        unsafe {
            core::arch::asm!("mrs {}, control", out(reg) control, options(nomem, nostack));
        }
        // If running in Thread mode Secure, bit 3 (SFPA) indicates floating point secure
        // More reliable: read SCB->AIRCR.BFHFNMINS
        (control & 0x08) == 0
    }
}

impl Default for Stm32u5Hal {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory-mapped register access utilities
pub(crate) mod registers {
    use core::ptr::{read_volatile, write_volatile};

    /// Read a 32-bit register
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    pub unsafe fn read_reg(addr: u32) -> u32 {
        read_volatile(addr as *const u32)
    }

    /// Write a 32-bit register
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    pub unsafe fn write_reg(addr: u32, value: u32) {
        write_volatile(addr as *mut u32, value);
    }

    /// Modify a 32-bit register (read-modify-write)
    ///
    /// # Safety
    /// The address must be a valid memory-mapped register.
    #[inline]
    pub unsafe fn modify_reg<F>(addr: u32, f: F)
    where
        F: FnOnce(u32) -> u32,
    {
        let value = read_reg(addr);
        write_reg(addr, f(value));
    }
}

/// STM32U5 peripheral base addresses
pub mod addresses {
    /// Flash memory base (secure alias)
    pub const FLASH_BASE_S: u32 = 0x0C00_0000;
    /// Flash memory base (non-secure alias)
    pub const FLASH_BASE_NS: u32 = 0x0800_0000;

    /// SRAM1 base (secure alias)
    pub const SRAM1_BASE_S: u32 = 0x3000_0000;
    /// SRAM1 base (non-secure alias)
    pub const SRAM1_BASE_NS: u32 = 0x2000_0000;

    /// Flash controller registers
    pub const FLASH_R_BASE: u32 = 0x4002_2000;

    /// RNG registers
    pub const RNG_BASE: u32 = 0x420C_0800;

    /// RCC registers
    pub const RCC_BASE: u32 = 0x4602_0C00;

    /// SAU registers
    pub const SAU_BASE: u32 = 0xE000_EDD0;

    /// GTZC_TZSC registers (TrustZone Security Controller)
    pub const GTZC_TZSC_BASE: u32 = 0x4002_2400;

    /// GTZC_MPCBB1 registers (Memory Protection Controller Block-Based 1)
    pub const GTZC_MPCBB1_BASE: u32 = 0x4002_2C00;

    /// GTZC_MPCBB2 registers
    pub const GTZC_MPCBB2_BASE: u32 = 0x4002_3000;

    /// PWR registers
    pub const PWR_BASE: u32 = 0x4602_0800;
}
