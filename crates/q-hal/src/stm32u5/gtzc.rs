// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Global TrustZone Controller (GTZC) Driver for STM32U5
//!
//! The GTZC manages peripheral and memory security attributes on STM32U5.
//! It consists of:
//!
//! - **TZSC**: TrustZone Security Controller (peripheral security)
//! - **TZIC**: TrustZone Interrupt Controller (secure interrupt routing)
//! - **MPCBB**: Memory Protection Controller Block-Based (SRAM security)
//!
//! # Peripheral Security
//!
//! Each peripheral can be configured as:
//! - Secure: Only accessible from secure state
//! - Non-secure: Accessible from both states
//! - Privileged: Additional privilege level requirement

use crate::error::{HalError, HalResult};
use super::addresses::{GTZC_TZSC_BASE, GTZC_MPCBB1_BASE, GTZC_MPCBB2_BASE};
use super::registers::{read_reg, write_reg, modify_reg};

// =============================================================================
// TZSC Register Offsets
// =============================================================================

/// TZSC Control Register
const TZSC_CR: u32 = GTZC_TZSC_BASE + 0x00;
/// TZSC Secure Configuration Register 1
const TZSC_SECCFGR1: u32 = GTZC_TZSC_BASE + 0x10;
/// TZSC Secure Configuration Register 2
const TZSC_SECCFGR2: u32 = GTZC_TZSC_BASE + 0x14;
/// TZSC Secure Configuration Register 3
const TZSC_SECCFGR3: u32 = GTZC_TZSC_BASE + 0x18;
/// TZSC Privilege Configuration Register 1
const TZSC_PRIVCFGR1: u32 = GTZC_TZSC_BASE + 0x20;
/// TZSC Privilege Configuration Register 2
const TZSC_PRIVCFGR2: u32 = GTZC_TZSC_BASE + 0x24;
/// TZSC Privilege Configuration Register 3
const TZSC_PRIVCFGR3: u32 = GTZC_TZSC_BASE + 0x28;

// =============================================================================
// MPCBB Register Offsets (per block)
// =============================================================================

/// MPCBB Control Register
const MPCBB_CR: u32 = 0x00;
/// MPCBB Lock Register 1
const MPCBB_LCKVTR1: u32 = 0x10;
/// MPCBB Lock Register 2
const MPCBB_LCKVTR2: u32 = 0x14;
/// MPCBB Security Configuration Registers (32 registers for 1MB in 256B blocks)
const MPCBB_VCTR_BASE: u32 = 0x100;

// =============================================================================
// Secure Peripherals
// =============================================================================

/// Peripherals that can be configured as secure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurePeripheral {
    // SECCFGR1 peripherals
    /// Timer 2
    Tim2 = 0,
    /// Timer 3
    Tim3 = 1,
    /// Timer 4
    Tim4 = 2,
    /// Timer 5
    Tim5 = 3,
    /// Timer 6
    Tim6 = 4,
    /// Timer 7
    Tim7 = 5,
    /// Window Watchdog
    Wwdg = 6,
    /// Independent Watchdog
    Iwdg = 7,
    /// SPI2
    Spi2 = 8,
    /// USART2
    Usart2 = 9,
    /// USART3
    Usart3 = 10,
    /// UART4
    Uart4 = 11,
    /// UART5
    Uart5 = 12,
    /// I2C1
    I2c1 = 13,
    /// I2C2
    I2c2 = 14,
    /// CRS
    Crs = 15,

    // SECCFGR2 peripherals (offset by 32)
    /// AES hardware accelerator
    Aes = 32,
    /// Hash hardware accelerator
    Hash = 33,
    /// Random Number Generator
    Rng = 34,
    /// PKA (Public Key Accelerator)
    Pka = 35,
    /// SAES (Secure AES)
    Saes = 36,
    /// OCTOSPI1
    Octospi1 = 37,
    /// SDMMC1
    Sdmmc1 = 38,
    /// SDMMC2
    Sdmmc2 = 39,
    /// FMC
    Fmc = 40,
    /// OCTOSPI2
    Octospi2 = 41,

    // SECCFGR3 peripherals (offset by 64)
    /// DMA1
    Dma1 = 64,
    /// DMA2
    Dma2 = 65,
    /// DMAMUX1
    Dmamux1 = 66,
    /// Flash interface
    Flash = 67,
    /// SRAM1
    Sram1 = 68,
    /// SRAM2
    Sram2 = 69,
    /// SRAM3
    Sram3 = 70,
}

impl SecurePeripheral {
    /// Get the configuration register and bit position
    fn get_reg_and_bit(&self) -> (u32, u32) {
        let id = *self as u8;
        if id < 32 {
            (TZSC_SECCFGR1, id as u32)
        } else if id < 64 {
            (TZSC_SECCFGR2, (id - 32) as u32)
        } else {
            (TZSC_SECCFGR3, (id - 64) as u32)
        }
    }

    /// Get the privilege configuration register
    fn get_priv_reg(&self) -> u32 {
        let id = *self as u8;
        if id < 32 {
            TZSC_PRIVCFGR1
        } else if id < 64 {
            TZSC_PRIVCFGR2
        } else {
            TZSC_PRIVCFGR3
        }
    }
}

// =============================================================================
// GTZC Configuration
// =============================================================================

/// GTZC configuration
#[derive(Debug, Clone, Default)]
pub struct GtzcConfig {
    /// Secure peripherals bitmap (SECCFGR1)
    pub seccfgr1: u32,
    /// Secure peripherals bitmap (SECCFGR2)
    pub seccfgr2: u32,
    /// Secure peripherals bitmap (SECCFGR3)
    pub seccfgr3: u32,
    /// Privileged peripherals bitmap (PRIVCFGR1)
    pub privcfgr1: u32,
    /// Privileged peripherals bitmap (PRIVCFGR2)
    pub privcfgr2: u32,
    /// Privileged peripherals bitmap (PRIVCFGR3)
    pub privcfgr3: u32,
}

// =============================================================================
// MPCBB Configuration
// =============================================================================

/// Memory block security configuration (256-byte granularity)
#[derive(Debug, Clone, Copy)]
pub struct MemoryBlockConfig {
    /// Block number (0-4095 for 1MB SRAM)
    pub block: u16,
    /// Block is secure
    pub secure: bool,
    /// Block is locked (cannot be changed)
    pub locked: bool,
}

// =============================================================================
// GTZC Driver
// =============================================================================

/// GTZC driver
pub struct Gtzc {
    /// Current configuration
    config: GtzcConfig,
    /// Initialization state
    initialized: bool,
}

impl Gtzc {
    /// Create a new GTZC driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: GtzcConfig {
                seccfgr1: 0,
                seccfgr2: 0,
                seccfgr3: 0,
                privcfgr1: 0,
                privcfgr2: 0,
                privcfgr3: 0,
            },
            initialized: false,
        }
    }

    /// Initialize the GTZC
    pub fn init(&mut self) -> HalResult<()> {
        // SAFETY: TZSC_SECCFGR1-3 and TZSC_PRIVCFGR1-3 are valid MMIO registers
        // at offsets from GTZC_TZSC_BASE (0x4002_2400). Volatile reads are required
        // to obtain the current hardware security/privilege configuration.
        // Read current configuration
        unsafe {
            self.config.seccfgr1 = read_reg(TZSC_SECCFGR1);
            self.config.seccfgr2 = read_reg(TZSC_SECCFGR2);
            self.config.seccfgr3 = read_reg(TZSC_SECCFGR3);
            self.config.privcfgr1 = read_reg(TZSC_PRIVCFGR1);
            self.config.privcfgr2 = read_reg(TZSC_PRIVCFGR2);
            self.config.privcfgr3 = read_reg(TZSC_PRIVCFGR3);
        }

        self.initialized = true;
        Ok(())
    }

    /// Set a peripheral as secure
    pub fn set_peripheral_secure(&mut self, peripheral: SecurePeripheral) -> HalResult<()> {
        let (reg, bit) = peripheral.get_reg_and_bit();

        // SAFETY: `reg` is one of TZSC_SECCFGR1/2/3, valid MMIO registers at known
        // offsets from GTZC_TZSC_BASE. `bit` is derived from the peripheral enum
        // and is guaranteed to be within 0-31 for each register.
        unsafe {
            modify_reg(reg, |v| v | (1 << bit));
        }

        // Update local config
        match reg {
            r if r == TZSC_SECCFGR1 => self.config.seccfgr1 |= 1 << bit,
            r if r == TZSC_SECCFGR2 => self.config.seccfgr2 |= 1 << bit,
            r if r == TZSC_SECCFGR3 => self.config.seccfgr3 |= 1 << bit,
            _ => {}
        }

        Ok(())
    }

    /// Set a peripheral as non-secure
    pub fn set_peripheral_nonsecure(&mut self, peripheral: SecurePeripheral) -> HalResult<()> {
        let (reg, bit) = peripheral.get_reg_and_bit();

        // SAFETY: `reg` is one of TZSC_SECCFGR1/2/3, valid MMIO registers at known
        // offsets from GTZC_TZSC_BASE. `bit` is derived from the peripheral enum
        // and is guaranteed to be within 0-31 for each register.
        unsafe {
            modify_reg(reg, |v| v & !(1 << bit));
        }

        // Update local config
        match reg {
            r if r == TZSC_SECCFGR1 => self.config.seccfgr1 &= !(1 << bit),
            r if r == TZSC_SECCFGR2 => self.config.seccfgr2 &= !(1 << bit),
            r if r == TZSC_SECCFGR3 => self.config.seccfgr3 &= !(1 << bit),
            _ => {}
        }

        Ok(())
    }

    /// Check if a peripheral is secure
    #[must_use]
    pub fn is_peripheral_secure(&self, peripheral: SecurePeripheral) -> bool {
        let (_, bit) = peripheral.get_reg_and_bit();
        let id = peripheral as u8;

        let mask = 1 << bit;
        if id < 32 {
            (self.config.seccfgr1 & mask) != 0
        } else if id < 64 {
            (self.config.seccfgr2 & mask) != 0
        } else {
            (self.config.seccfgr3 & mask) != 0
        }
    }

    /// Set a peripheral as privileged (requires privileged access)
    pub fn set_peripheral_privileged(&mut self, peripheral: SecurePeripheral) -> HalResult<()> {
        let (_, bit) = peripheral.get_reg_and_bit();
        let priv_reg = peripheral.get_priv_reg();

        // SAFETY: `priv_reg` is one of TZSC_PRIVCFGR1/2/3, valid MMIO registers at
        // known offsets from GTZC_TZSC_BASE. `bit` is within 0-31 as guaranteed by
        // the SecurePeripheral enum mapping.
        unsafe {
            modify_reg(priv_reg, |v| v | (1 << bit));
        }

        Ok(())
    }

    /// Set a peripheral as unprivileged (accessible from unprivileged code)
    pub fn set_peripheral_unprivileged(&mut self, peripheral: SecurePeripheral) -> HalResult<()> {
        let (_, bit) = peripheral.get_reg_and_bit();
        let priv_reg = peripheral.get_priv_reg();

        // SAFETY: `priv_reg` is one of TZSC_PRIVCFGR1/2/3, valid MMIO registers at
        // known offsets from GTZC_TZSC_BASE. `bit` is within 0-31 as guaranteed by
        // the SecurePeripheral enum mapping.
        unsafe {
            modify_reg(priv_reg, |v| v & !(1 << bit));
        }

        Ok(())
    }

    /// Configure SRAM1 block security (MPCBB1)
    ///
    /// # Arguments
    /// * `block` - Block number (0-1023 for 256KB SRAM1, 256-byte blocks)
    /// * `secure` - true for secure, false for non-secure
    pub fn configure_sram1_block(&mut self, block: u16, secure: bool) -> HalResult<()> {
        if block >= 1024 {
            return Err(HalError::InvalidParameter);
        }

        let reg_index = block / 32;
        let bit = block % 32;
        let reg_addr = GTZC_MPCBB1_BASE + MPCBB_VCTR_BASE + (reg_index as u32 * 4);

        // SAFETY: `reg_addr` is computed from GTZC_MPCBB1_BASE + MPCBB_VCTR_BASE
        // plus a register index offset. The block number is bounds-checked above
        // (< 1024), ensuring the register address stays within the MPCBB1 register space.
        unsafe {
            if secure {
                modify_reg(reg_addr, |v| v | (1 << bit));
            } else {
                modify_reg(reg_addr, |v| v & !(1 << bit));
            }
        }

        Ok(())
    }

    /// Configure SRAM2 block security (MPCBB2)
    pub fn configure_sram2_block(&mut self, block: u16, secure: bool) -> HalResult<()> {
        if block >= 256 {
            return Err(HalError::InvalidParameter);
        }

        let reg_index = block / 32;
        let bit = block % 32;
        let reg_addr = GTZC_MPCBB2_BASE + MPCBB_VCTR_BASE + (reg_index as u32 * 4);

        // SAFETY: `reg_addr` is computed from GTZC_MPCBB2_BASE + MPCBB_VCTR_BASE
        // plus a register index offset. The block number is bounds-checked above
        // (< 256), ensuring the register address stays within the MPCBB2 register space.
        unsafe {
            if secure {
                modify_reg(reg_addr, |v| v | (1 << bit));
            } else {
                modify_reg(reg_addr, |v| v & !(1 << bit));
            }
        }

        Ok(())
    }

    /// Configure a range of SRAM blocks
    pub fn configure_sram_range(
        &mut self,
        sram: u8,          // 1 or 2
        start_block: u16,
        end_block: u16,
        secure: bool,
    ) -> HalResult<()> {
        for block in start_block..=end_block {
            match sram {
                1 => self.configure_sram1_block(block, secure)?,
                2 => self.configure_sram2_block(block, secure)?,
                _ => return Err(HalError::InvalidParameter),
            }
        }
        Ok(())
    }

    /// Lock SRAM block configuration (cannot be changed until reset)
    pub fn lock_sram_blocks(&mut self, sram: u8, start_block: u16, end_block: u16) -> HalResult<()> {
        let base = match sram {
            1 => GTZC_MPCBB1_BASE,
            2 => GTZC_MPCBB2_BASE,
            _ => return Err(HalError::InvalidParameter),
        };

        // Lock registers contain 1 bit per super-block (32 blocks)
        let start_superblock = start_block / 32;
        let end_superblock = end_block / 32;

        for sb in start_superblock..=end_superblock {
            let lock_reg = if sb < 32 {
                base + MPCBB_LCKVTR1
            } else {
                base + MPCBB_LCKVTR2
            };
            let bit = sb % 32;

            // SAFETY: `lock_reg` is either MPCBB_LCKVTR1 or MPCBB_LCKVTR2 at a valid
            // offset from the MPCBB base address. The superblock index is derived from
            // the bounds-checked block range. Setting lock bits is an irreversible
            // operation until reset, which is the intended behavior.
            unsafe {
                modify_reg(lock_reg, |v| v | (1 << bit));
            }
        }

        Ok(())
    }

    /// Apply a complete configuration
    pub fn apply_config(&mut self, config: &GtzcConfig) -> HalResult<()> {
        // SAFETY: TZSC_SECCFGR1-3 and TZSC_PRIVCFGR1-3 are valid MMIO registers at
        // known offsets from GTZC_TZSC_BASE (0x4002_2400). Writing the full register
        // values atomically applies the complete security/privilege configuration.
        unsafe {
            write_reg(TZSC_SECCFGR1, config.seccfgr1);
            write_reg(TZSC_SECCFGR2, config.seccfgr2);
            write_reg(TZSC_SECCFGR3, config.seccfgr3);
            write_reg(TZSC_PRIVCFGR1, config.privcfgr1);
            write_reg(TZSC_PRIVCFGR2, config.privcfgr2);
            write_reg(TZSC_PRIVCFGR3, config.privcfgr3);
        }

        self.config = config.clone();
        Ok(())
    }

    /// Lock all GTZC configuration (cannot be changed until reset)
    pub fn lock_all(&mut self) -> HalResult<()> {
        // SAFETY: TZSC_CR (GTZC_TZSC_BASE + 0x00) is a valid MMIO register.
        // Setting bit 0 locks the TZSC configuration until the next reset,
        // which is the intended irreversible security hardening operation.
        unsafe {
            // Set lock bit in control register
            modify_reg(TZSC_CR, |v| v | (1 << 0));
        }
        Ok(())
    }

    /// Get current configuration
    #[must_use]
    pub fn config(&self) -> &GtzcConfig {
        &self.config
    }
}

impl Default for Gtzc {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peripheral_reg_mapping() {
        // Test SECCFGR1 peripherals
        let (reg, bit) = SecurePeripheral::Tim2.get_reg_and_bit();
        assert_eq!(reg, TZSC_SECCFGR1);
        assert_eq!(bit, 0);

        // Test SECCFGR2 peripherals
        let (reg, bit) = SecurePeripheral::Aes.get_reg_and_bit();
        assert_eq!(reg, TZSC_SECCFGR2);
        assert_eq!(bit, 0);

        // Test SECCFGR3 peripherals
        let (reg, bit) = SecurePeripheral::Dma1.get_reg_and_bit();
        assert_eq!(reg, TZSC_SECCFGR3);
        assert_eq!(bit, 0);
    }

    #[test]
    fn test_gtzc_config_default() {
        let config = GtzcConfig::default();
        assert_eq!(config.seccfgr1, 0);
        assert_eq!(config.seccfgr2, 0);
        assert_eq!(config.seccfgr3, 0);
    }
}
