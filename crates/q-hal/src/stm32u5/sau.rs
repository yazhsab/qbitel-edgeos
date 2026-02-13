// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Security Attribution Unit (SAU) Driver for STM32U5
//!
//! The SAU is part of the ARMv8-M TrustZone architecture. It defines which
//! memory regions are Secure, Non-Secure, or Non-Secure Callable (NSC).
//!
//! # Architecture
//!
//! The STM32U5 implements TrustZone-M with:
//! - SAU: Software-configurable security attribution (8 regions)
//! - IDAU: Implementation-defined security attribution (hardwired)
//!
//! The final security attribute is: SAU AND IDAU (most restrictive wins)
//!
//! # Region Types
//!
//! - **Secure**: Only accessible from secure state
//! - **Non-Secure**: Accessible from both states
//! - **Non-Secure Callable (NSC)**: Secure memory with SG instruction entry points

use crate::error::{HalError, HalResult};
use super::addresses::SAU_BASE;
use super::registers::{read_reg, write_reg};

// =============================================================================
// SAU Register Offsets
// =============================================================================

/// SAU Control Register
const SAU_CTRL: u32 = SAU_BASE + 0x00;
/// SAU Type Register
const SAU_TYPE: u32 = SAU_BASE + 0x04;
/// SAU Region Number Register
const SAU_RNR: u32 = SAU_BASE + 0x08;
/// SAU Region Base Address Register
const SAU_RBAR: u32 = SAU_BASE + 0x0C;
/// SAU Region Limit Address Register
const SAU_RLAR: u32 = SAU_BASE + 0x10;
/// SAU Secure Fault Status Register
const SAU_SFSR: u32 = SAU_BASE + 0x14;
/// SAU Secure Fault Address Register
const SAU_SFAR: u32 = SAU_BASE + 0x18;

// =============================================================================
// SAU Control Register Bits
// =============================================================================

/// SAU Enable bit
const SAU_CTRL_ENABLE: u32 = 1 << 0;
/// All memory is Non-Secure when SAU is disabled
const SAU_CTRL_ALLNS: u32 = 1 << 1;

// =============================================================================
// SAU RLAR Bits
// =============================================================================

/// Region Enable bit
const SAU_RLAR_ENABLE: u32 = 1 << 0;
/// Non-Secure Callable bit
const SAU_RLAR_NSC: u32 = 1 << 1;

// =============================================================================
// Maximum Regions
// =============================================================================

/// Maximum number of SAU regions (implementation defined, STM32U5 has 8)
pub const MAX_SAU_REGIONS: usize = 8;

// =============================================================================
// SAU Region Configuration
// =============================================================================

/// SAU region configuration
#[derive(Debug, Clone, Copy)]
pub struct SauRegion {
    /// Region number (0-7)
    pub number: u8,
    /// Base address (must be 32-byte aligned)
    pub base: u32,
    /// Limit address (must be 32-byte aligned, inclusive)
    pub limit: u32,
    /// Region is secure (false = non-secure)
    pub secure: bool,
    /// Region is enabled
    pub enabled: bool,
}

impl SauRegion {
    /// Create a new SAU region configuration
    #[must_use]
    pub const fn new(number: u8, base: u32, limit: u32, secure: bool) -> Self {
        Self {
            number,
            base,
            limit,
            secure,
            enabled: true,
        }
    }

    /// Validate region configuration
    fn validate(&self) -> HalResult<()> {
        // Check region number
        if self.number >= MAX_SAU_REGIONS as u8 {
            return Err(HalError::InvalidParameter);
        }

        // Check 32-byte alignment
        if (self.base & 0x1F) != 0 {
            return Err(HalError::InvalidParameter);
        }

        // Limit must be aligned to 32 bytes - 1 (last valid byte)
        if (self.limit & 0x1F) != 0x1F {
            return Err(HalError::InvalidParameter);
        }

        // Base must be less than limit
        if self.base > self.limit {
            return Err(HalError::InvalidParameter);
        }

        Ok(())
    }
}

// =============================================================================
// SAU Configuration
// =============================================================================

/// SAU configuration
#[derive(Debug, Clone)]
pub struct SauConfig {
    /// All configured regions
    pub regions: [Option<SauRegion>; MAX_SAU_REGIONS],
    /// When SAU is disabled, treat all memory as non-secure
    pub all_ns_when_disabled: bool,
}

impl Default for SauConfig {
    fn default() -> Self {
        Self {
            regions: [None; MAX_SAU_REGIONS],
            all_ns_when_disabled: true,
        }
    }
}

// =============================================================================
// SAU Fault Information
// =============================================================================

/// SAU secure fault type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureFault {
    /// No fault
    None,
    /// Invalid entry point (SG instruction missing)
    InvalidEntryPoint,
    /// Invalid secure state transition
    InvalidTransition,
    /// Attribution unit violation
    AttributionViolation,
    /// Invalid exception return
    InvalidExceptionReturn,
    /// Lazy state error
    LazyStateError,
}

/// SAU fault information
#[derive(Debug, Clone, Copy)]
pub struct SauFaultInfo {
    /// Fault type
    pub fault: SecureFault,
    /// Faulting address (if valid)
    pub address: Option<u32>,
    /// Fault address valid
    pub address_valid: bool,
}

// =============================================================================
// SAU Driver
// =============================================================================

/// SAU driver
pub struct Sau {
    /// Current configuration
    config: SauConfig,
    /// Whether SAU is enabled
    enabled: bool,
    /// Initialization state
    initialized: bool,
}

impl Sau {
    /// Create a new SAU driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: SauConfig {
                regions: [None; MAX_SAU_REGIONS],
                all_ns_when_disabled: true,
            },
            enabled: false,
            initialized: false,
        }
    }

    /// Initialize the SAU
    pub fn init(&mut self) -> HalResult<()> {
        // Disable SAU during configuration
        self.disable()?;

        // Clear all regions
        for i in 0..MAX_SAU_REGIONS {
            self.disable_region(i as u8)?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Get the number of supported SAU regions
    #[must_use]
    pub fn num_regions(&self) -> u8 {
        // SAFETY: SAU_TYPE (0xE000_EDD4) is a valid read-only MMIO register in the
        // ARMv8-M system control space. Volatile read is required for MMIO access.
        unsafe {
            let sau_type = read_reg(SAU_TYPE);
            (sau_type & 0xFF) as u8
        }
    }

    /// Configure a SAU region
    pub fn configure_region(&mut self, region: SauRegion) -> HalResult<()> {
        region.validate()?;

        // SAFETY: SAU_RNR, SAU_RBAR, and SAU_RLAR are valid MMIO registers in the
        // ARMv8-M system control space (base 0xE000_EDD0). The region number is
        // validated above via region.validate(), ensuring in-bounds access.
        unsafe {
            // Select region
            write_reg(SAU_RNR, region.number as u32);

            // Write base address (bits 31:5, lower bits reserved)
            write_reg(SAU_RBAR, region.base & 0xFFFF_FFE0);

            // Write limit address with attributes
            let mut rlar = region.limit & 0xFFFF_FFE0;

            if region.enabled {
                rlar |= SAU_RLAR_ENABLE;
            }

            if !region.secure {
                // NSC bit: 0 = Secure, 1 = Non-Secure Callable
                // For pure non-secure, we don't set NSC (handled by IDAU)
            }

            write_reg(SAU_RLAR, rlar);
        }

        // Store configuration
        self.config.regions[region.number as usize] = Some(region);

        Ok(())
    }

    /// Configure a Non-Secure Callable (NSC) region
    ///
    /// NSC regions are secure memory that can be called from non-secure
    /// code via the SG (Secure Gateway) instruction.
    pub fn configure_nsc_region(&mut self, region_num: u8, base: u32, limit: u32) -> HalResult<()> {
        if region_num >= MAX_SAU_REGIONS as u8 {
            return Err(HalError::InvalidParameter);
        }

        // SAFETY: SAU_RNR, SAU_RBAR, and SAU_RLAR are valid MMIO registers in the
        // ARMv8-M system control space. The region number is bounds-checked above
        // against MAX_SAU_REGIONS. Volatile writes are required for MMIO.
        unsafe {
            // Select region
            write_reg(SAU_RNR, region_num as u32);

            // Write base address
            write_reg(SAU_RBAR, base & 0xFFFF_FFE0);

            // Write limit with NSC and Enable bits
            let rlar = (limit & 0xFFFF_FFE0) | SAU_RLAR_NSC | SAU_RLAR_ENABLE;
            write_reg(SAU_RLAR, rlar);
        }

        let region = SauRegion {
            number: region_num,
            base,
            limit,
            secure: true, // NSC is technically secure
            enabled: true,
        };
        self.config.regions[region_num as usize] = Some(region);

        Ok(())
    }

    /// Disable a SAU region
    pub fn disable_region(&mut self, region_num: u8) -> HalResult<()> {
        if region_num >= MAX_SAU_REGIONS as u8 {
            return Err(HalError::InvalidParameter);
        }

        // SAFETY: SAU_RNR, SAU_RBAR, and SAU_RLAR are valid MMIO registers in the
        // ARMv8-M system control space. The region number is bounds-checked above.
        // Writing zeros disables the region without affecting other regions.
        unsafe {
            // Select region
            write_reg(SAU_RNR, region_num as u32);

            // Clear region (disable)
            write_reg(SAU_RBAR, 0);
            write_reg(SAU_RLAR, 0);
        }

        self.config.regions[region_num as usize] = None;
        Ok(())
    }

    /// Enable the SAU
    pub fn enable(&mut self) -> HalResult<()> {
        // SAFETY: SAU_CTRL (0xE000_EDD0) is a valid MMIO register for SAU control.
        // Read-modify-write is required to preserve other control bits. DSB/ISB
        // barriers ensure the SAU configuration takes effect before subsequent accesses.
        unsafe {
            let mut ctrl = read_reg(SAU_CTRL);
            ctrl |= SAU_CTRL_ENABLE;

            if self.config.all_ns_when_disabled {
                ctrl |= SAU_CTRL_ALLNS;
            } else {
                ctrl &= !SAU_CTRL_ALLNS;
            }

            write_reg(SAU_CTRL, ctrl);

            // Data and instruction synchronization barriers
            core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
        }

        self.enabled = true;
        Ok(())
    }

    /// Disable the SAU
    pub fn disable(&mut self) -> HalResult<()> {
        // SAFETY: SAU_CTRL (0xE000_EDD0) is a valid MMIO register. Read-modify-write
        // preserves other control bits. DSB/ISB barriers ensure the disable takes
        // effect before any subsequent memory accesses.
        unsafe {
            let mut ctrl = read_reg(SAU_CTRL);
            ctrl &= !SAU_CTRL_ENABLE;
            write_reg(SAU_CTRL, ctrl);

            core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
        }

        self.enabled = false;
        Ok(())
    }

    /// Check if SAU is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        // SAFETY: SAU_CTRL (0xE000_EDD0) is a valid read-only access to the SAU
        // control register. Volatile read is required for correct MMIO behavior.
        unsafe {
            let ctrl = read_reg(SAU_CTRL);
            (ctrl & SAU_CTRL_ENABLE) != 0
        }
    }

    /// Get secure fault information
    #[must_use]
    pub fn get_fault_info(&self) -> SauFaultInfo {
        // SAFETY: SAU_SFSR (0xE000_EDE4) and SAU_SFAR (0xE000_EDE8) are valid
        // read-only MMIO registers for secure fault status and address. Volatile
        // reads are required to get the current hardware fault state.
        unsafe {
            let sfsr = read_reg(SAU_SFSR);
            let sfar = read_reg(SAU_SFAR);

            let fault = if (sfsr & (1 << 0)) != 0 {
                SecureFault::InvalidEntryPoint
            } else if (sfsr & (1 << 1)) != 0 {
                SecureFault::InvalidTransition
            } else if (sfsr & (1 << 2)) != 0 {
                SecureFault::AttributionViolation
            } else if (sfsr & (1 << 3)) != 0 {
                SecureFault::InvalidExceptionReturn
            } else if (sfsr & (1 << 5)) != 0 {
                SecureFault::LazyStateError
            } else {
                SecureFault::None
            };

            let address_valid = (sfsr & (1 << 6)) != 0;

            SauFaultInfo {
                fault,
                address: if address_valid { Some(sfar) } else { None },
                address_valid,
            }
        }
    }

    /// Clear secure fault status
    pub fn clear_fault(&mut self) {
        // SAFETY: SAU_SFSR (0xE000_EDE4) is a valid MMIO register. Writing 1 to
        // fault flag bits clears them (W1C semantics), which is the correct
        // procedure to acknowledge and clear secure fault status.
        unsafe {
            // Write 1 to clear fault flags
            write_reg(SAU_SFSR, 0xFF);
        }
    }

    /// Check if an address is in secure memory
    #[must_use]
    pub fn is_address_secure(&self, address: u32) -> bool {
        for region in &self.config.regions {
            if let Some(r) = region {
                if r.enabled && address >= r.base && address <= r.limit {
                    return r.secure;
                }
            }
        }
        // Default to secure if not in any region (depends on IDAU)
        true
    }

    /// Apply a complete configuration
    pub fn apply_config(&mut self, config: &SauConfig) -> HalResult<()> {
        // Disable SAU during reconfiguration
        self.disable()?;

        // Configure all regions
        for (i, region) in config.regions.iter().enumerate() {
            if let Some(r) = region {
                let mut r = *r;
                r.number = i as u8;
                self.configure_region(r)?;
            } else {
                self.disable_region(i as u8)?;
            }
        }

        self.config = config.clone();

        // Re-enable SAU
        self.enable()?;

        Ok(())
    }

    /// Lock SAU configuration (cannot be changed until reset)
    pub fn lock(&mut self) -> HalResult<()> {
        #[cfg(target_arch = "arm")]
        {
            use core::ptr;

            // STM32U5 GTZC TZSC control register
            const GTZC_TZSC_BASE: u32 = 0x4003_2400;
            const GTZC_TZSC_CR: u32 = GTZC_TZSC_BASE + 0x00;
            const GTZC_TZSC_CR_LCK: u32 = 1 << 0;

            // SAFETY: GTZC TZSC control register is an architecturally-defined STM32U5
            // security peripheral register. Writing the lock bit prevents further SAU/GTZC
            // configuration changes until the next system reset.
            unsafe {
                let cr = ptr::read_volatile(GTZC_TZSC_CR as *const u32);
                ptr::write_volatile(GTZC_TZSC_CR as *mut u32, cr | GTZC_TZSC_CR_LCK);
            }
        }

        Ok(())
    }
}

impl Default for Sau {
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
    fn test_sau_region_validation() {
        // Valid region
        let region = SauRegion::new(0, 0x0800_0000, 0x0803_FFFF, true);
        assert!(region.validate().is_ok());

        // Invalid region number
        let invalid = SauRegion::new(10, 0x0800_0000, 0x0803_FFFF, true);
        assert!(invalid.validate().is_err());

        // Invalid alignment
        let unaligned = SauRegion::new(0, 0x0800_0001, 0x0803_FFFF, true);
        assert!(unaligned.validate().is_err());
    }

    #[test]
    fn test_sau_config_default() {
        let config = SauConfig::default();
        assert!(config.all_ns_when_disabled);
        for region in &config.regions {
            assert!(region.is_none());
        }
    }
}
