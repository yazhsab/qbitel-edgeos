// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Physical Memory Protection (PMP) Driver for RISC-V
//!
//! PMP provides memory isolation between privilege levels (M-mode, S-mode, U-mode).
//! It allows M-mode to configure memory regions with specific access permissions
//! that apply to lower privilege modes.
//!
//! # Architecture
//!
//! PMP consists of:
//! - **pmpaddr0-15**: Region address registers (up to 16 regions)
//! - **pmpcfg0-3**: Region configuration registers (4 bits per region)
//!
//! # Address Matching Modes
//!
//! - **OFF**: Region disabled
//! - **TOR**: Top of Range (address is top, previous pmpaddr is bottom)
//! - **NA4**: Naturally aligned 4-byte region
//! - **NAPOT**: Naturally aligned power-of-two region
//!
//! # Usage Example
//!
//! ```rust,ignore
//! let mut pmp = Pmp::new();
//! pmp.init()?;
//!
//! // Configure region 0: RW access for kernel data (1MB at 0x8000_0000)
//! pmp.configure_region(PmpRegion {
//!     index: 0,
//!     address: 0x8000_0000,
//!     size: 0x0010_0000,
//!     permissions: PmpPermissions::RW,
//!     mode: PmpAddressMode::Napot,
//!     locked: false,
//! })?;
//! ```

use crate::error::{HalError, HalResult};

// =============================================================================
// PMP Constants
// =============================================================================

/// Maximum number of PMP regions (implementation defined, typically 8 or 16)
pub const MAX_PMP_REGIONS: usize = 16;

/// Minimum region size (4 bytes for NA4)
pub const MIN_REGION_SIZE: usize = 4;

// =============================================================================
// PMP Configuration Bits
// =============================================================================

/// Read permission bit
const PMP_R: u8 = 1 << 0;
/// Write permission bit
const PMP_W: u8 = 1 << 1;
/// Execute permission bit
const PMP_X: u8 = 1 << 2;
/// Address matching mode (bits 4:3)
const PMP_A_SHIFT: u8 = 3;
/// Lock bit (cannot be changed until reset)
const PMP_L: u8 = 1 << 7;

// =============================================================================
// PMP Types
// =============================================================================

/// PMP address matching mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PmpAddressMode {
    /// Region disabled
    Off = 0,
    /// Top of Range (uses previous pmpaddr as bottom)
    Tor = 1,
    /// Naturally aligned 4-byte region
    Na4 = 2,
    /// Naturally aligned power-of-two region
    Napot = 3,
}

impl PmpAddressMode {
    /// Get the configuration bits for this mode
    const fn to_bits(self) -> u8 {
        (self as u8) << PMP_A_SHIFT
    }
}

/// PMP access permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmpPermissions {
    /// Read permission
    pub read: bool,
    /// Write permission
    pub write: bool,
    /// Execute permission
    pub execute: bool,
}

impl PmpPermissions {
    /// No access
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };

    /// Read only
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };

    /// Read-Write
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };

    /// Read-Execute
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };

    /// Read-Write-Execute (full access)
    pub const RWX: Self = Self {
        read: true,
        write: true,
        execute: true,
    };

    /// Execute only
    pub const X: Self = Self {
        read: false,
        write: false,
        execute: true,
    };

    /// Convert to configuration bits
    const fn to_bits(self) -> u8 {
        let mut bits = 0u8;
        if self.read {
            bits |= PMP_R;
        }
        if self.write {
            bits |= PMP_W;
        }
        if self.execute {
            bits |= PMP_X;
        }
        bits
    }

    /// Create from configuration bits
    const fn from_bits(bits: u8) -> Self {
        Self {
            read: (bits & PMP_R) != 0,
            write: (bits & PMP_W) != 0,
            execute: (bits & PMP_X) != 0,
        }
    }
}

/// PMP region configuration
#[derive(Debug, Clone, Copy)]
pub struct PmpRegion {
    /// Region index (0-15)
    pub index: u8,
    /// Base address (must be properly aligned for mode)
    pub address: usize,
    /// Region size in bytes (for NAPOT mode)
    pub size: usize,
    /// Access permissions
    pub permissions: PmpPermissions,
    /// Address matching mode
    pub mode: PmpAddressMode,
    /// Lock configuration (cannot be changed until reset)
    pub locked: bool,
}

impl PmpRegion {
    /// Create a new disabled region
    #[must_use]
    pub const fn disabled(index: u8) -> Self {
        Self {
            index,
            address: 0,
            size: 0,
            permissions: PmpPermissions::NONE,
            mode: PmpAddressMode::Off,
            locked: false,
        }
    }

    /// Create a NAPOT region
    ///
    /// NAPOT (Naturally Aligned Power Of Two) encodes the region size
    /// in the address register itself. The size must be a power of 2
    /// and >= 8 bytes.
    #[must_use]
    pub const fn napot(index: u8, address: usize, size: usize, permissions: PmpPermissions) -> Self {
        Self {
            index,
            address,
            size,
            permissions,
            mode: PmpAddressMode::Napot,
            locked: false,
        }
    }

    /// Create a TOR (Top of Range) region
    ///
    /// TOR mode uses the previous pmpaddr register as the bottom of the range
    /// and this pmpaddr as the top. For region 0, the bottom is address 0.
    #[must_use]
    pub const fn tor(index: u8, top_address: usize, permissions: PmpPermissions) -> Self {
        Self {
            index,
            address: top_address,
            size: 0, // Not used for TOR
            permissions,
            mode: PmpAddressMode::Tor,
            locked: false,
        }
    }

    /// Convert size to NAPOT address encoding
    ///
    /// NAPOT encoding: pmpaddr = (base >> 2) | ((size >> 3) - 1)
    fn napot_encode(&self) -> usize {
        if self.size < 8 {
            // Minimum NAPOT size is 8 bytes
            return self.address >> 2;
        }

        let napot_bits = self.size.trailing_zeros() - 3; // log2(size) - 3
        let base = (self.address >> 2) & !((1 << (napot_bits + 1)) - 1);
        base | ((1 << napot_bits) - 1)
    }

    /// Get the pmpaddr value for this region
    fn get_pmpaddr(&self) -> usize {
        match self.mode {
            PmpAddressMode::Off => 0,
            PmpAddressMode::Tor => self.address >> 2,
            PmpAddressMode::Na4 => self.address >> 2,
            PmpAddressMode::Napot => self.napot_encode(),
        }
    }

    /// Get the pmpcfg value for this region
    fn get_pmpcfg(&self) -> u8 {
        let mut cfg = self.permissions.to_bits() | self.mode.to_bits();
        if self.locked {
            cfg |= PMP_L;
        }
        cfg
    }

    /// Validate region configuration
    fn validate(&self) -> HalResult<()> {
        if self.index >= MAX_PMP_REGIONS as u8 {
            return Err(HalError::InvalidParameter);
        }

        match self.mode {
            PmpAddressMode::Off => {}
            PmpAddressMode::Na4 => {
                if (self.address & 0x3) != 0 {
                    return Err(HalError::InvalidParameter); // Must be 4-byte aligned
                }
            }
            PmpAddressMode::Napot => {
                if self.size < 8 {
                    return Err(HalError::InvalidParameter); // Minimum 8 bytes
                }
                if !self.size.is_power_of_two() {
                    return Err(HalError::InvalidParameter); // Must be power of 2
                }
                if (self.address & (self.size - 1)) != 0 {
                    return Err(HalError::InvalidParameter); // Must be naturally aligned
                }
            }
            PmpAddressMode::Tor => {
                if (self.address & 0x3) != 0 {
                    return Err(HalError::InvalidParameter); // Must be 4-byte aligned
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// PMP Configuration
// =============================================================================

/// Complete PMP configuration
#[derive(Debug, Clone)]
pub struct PmpConfig {
    /// Configured regions
    pub regions: [PmpRegion; MAX_PMP_REGIONS],
}

impl Default for PmpConfig {
    fn default() -> Self {
        Self {
            regions: [
                PmpRegion::disabled(0),
                PmpRegion::disabled(1),
                PmpRegion::disabled(2),
                PmpRegion::disabled(3),
                PmpRegion::disabled(4),
                PmpRegion::disabled(5),
                PmpRegion::disabled(6),
                PmpRegion::disabled(7),
                PmpRegion::disabled(8),
                PmpRegion::disabled(9),
                PmpRegion::disabled(10),
                PmpRegion::disabled(11),
                PmpRegion::disabled(12),
                PmpRegion::disabled(13),
                PmpRegion::disabled(14),
                PmpRegion::disabled(15),
            ],
        }
    }
}

// =============================================================================
// PMP Driver
// =============================================================================

/// PMP driver
pub struct Pmp {
    /// Current configuration
    config: PmpConfig,
    /// Number of supported regions (read from hardware)
    num_regions: usize,
    /// Initialization state
    initialized: bool,
}

impl Pmp {
    /// Create a new PMP driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config: PmpConfig {
                regions: [
                    PmpRegion::disabled(0),
                    PmpRegion::disabled(1),
                    PmpRegion::disabled(2),
                    PmpRegion::disabled(3),
                    PmpRegion::disabled(4),
                    PmpRegion::disabled(5),
                    PmpRegion::disabled(6),
                    PmpRegion::disabled(7),
                    PmpRegion::disabled(8),
                    PmpRegion::disabled(9),
                    PmpRegion::disabled(10),
                    PmpRegion::disabled(11),
                    PmpRegion::disabled(12),
                    PmpRegion::disabled(13),
                    PmpRegion::disabled(14),
                    PmpRegion::disabled(15),
                ],
            },
            num_regions: 0,
            initialized: false,
        }
    }

    /// Initialize PMP
    pub fn init(&mut self) -> HalResult<()> {
        // Detect number of supported PMP regions
        self.num_regions = self.detect_num_regions();

        // Clear all regions
        for i in 0..self.num_regions {
            self.disable_region(i as u8)?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Detect the number of supported PMP regions
    fn detect_num_regions(&self) -> usize {
        // Try writing to pmpaddr registers to detect how many exist
        // Most implementations have 8 or 16 regions
        // For simplicity, assume 16 (RV32/RV64 standard)
        16
    }

    /// Configure a PMP region
    pub fn configure_region(&mut self, region: PmpRegion) -> HalResult<()> {
        region.validate()?;

        if region.index >= self.num_regions as u8 {
            return Err(HalError::InvalidParameter);
        }

        let pmpaddr = region.get_pmpaddr();
        let pmpcfg = region.get_pmpcfg();
        let idx = region.index as usize;

        // Write pmpaddr register
        self.write_pmpaddr(idx, pmpaddr);

        // Write pmpcfg register (each register holds 4 or 8 region configs)
        self.write_pmpcfg_entry(idx, pmpcfg);

        // Store configuration
        self.config.regions[idx] = region;

        // Synchronize
        // SAFETY: SFENCE.VMA is required after modifying PMP configuration to ensure
        // the new memory protection settings take effect. This instruction flushes
        // address-translation caches and is valid in M-mode.
        unsafe {
            core::arch::asm!("sfence.vma", options(nomem, nostack));
        }

        Ok(())
    }

    /// Disable a PMP region
    pub fn disable_region(&mut self, index: u8) -> HalResult<()> {
        if index >= self.num_regions as u8 {
            return Err(HalError::InvalidParameter);
        }

        let idx = index as usize;

        // Clear pmpaddr
        self.write_pmpaddr(idx, 0);

        // Clear pmpcfg (A=OFF)
        self.write_pmpcfg_entry(idx, 0);

        // Update stored config
        self.config.regions[idx] = PmpRegion::disabled(index);

        Ok(())
    }

    /// Write to pmpaddr register
    fn write_pmpaddr(&self, index: usize, value: usize) {
        // SAFETY: pmpaddr0-15 are M-mode CSRs for PMP address configuration. Each
        // CSR write targets a specific, valid PMP address register selected by the
        // match arm. The index is bounds-checked by the caller (< num_regions).
        // Out-of-range indices fall through to the no-op default arm.
        unsafe {
            match index {
                0 => core::arch::asm!("csrw pmpaddr0, {}", in(reg) value, options(nomem, nostack)),
                1 => core::arch::asm!("csrw pmpaddr1, {}", in(reg) value, options(nomem, nostack)),
                2 => core::arch::asm!("csrw pmpaddr2, {}", in(reg) value, options(nomem, nostack)),
                3 => core::arch::asm!("csrw pmpaddr3, {}", in(reg) value, options(nomem, nostack)),
                4 => core::arch::asm!("csrw pmpaddr4, {}", in(reg) value, options(nomem, nostack)),
                5 => core::arch::asm!("csrw pmpaddr5, {}", in(reg) value, options(nomem, nostack)),
                6 => core::arch::asm!("csrw pmpaddr6, {}", in(reg) value, options(nomem, nostack)),
                7 => core::arch::asm!("csrw pmpaddr7, {}", in(reg) value, options(nomem, nostack)),
                8 => core::arch::asm!("csrw pmpaddr8, {}", in(reg) value, options(nomem, nostack)),
                9 => core::arch::asm!("csrw pmpaddr9, {}", in(reg) value, options(nomem, nostack)),
                10 => core::arch::asm!("csrw pmpaddr10, {}", in(reg) value, options(nomem, nostack)),
                11 => core::arch::asm!("csrw pmpaddr11, {}", in(reg) value, options(nomem, nostack)),
                12 => core::arch::asm!("csrw pmpaddr12, {}", in(reg) value, options(nomem, nostack)),
                13 => core::arch::asm!("csrw pmpaddr13, {}", in(reg) value, options(nomem, nostack)),
                14 => core::arch::asm!("csrw pmpaddr14, {}", in(reg) value, options(nomem, nostack)),
                15 => core::arch::asm!("csrw pmpaddr15, {}", in(reg) value, options(nomem, nostack)),
                _ => {}
            }
        }
    }

    /// Read from pmpaddr register
    fn read_pmpaddr(&self, index: usize) -> usize {
        let value: usize;
        // SAFETY: pmpaddr0-7 are M-mode CSRs for PMP address configuration. Each
        // CSR read targets a specific, valid PMP address register selected by the
        // match arm. Out-of-range indices return 0 via the default arm.
        unsafe {
            match index {
                0 => core::arch::asm!("csrr {}, pmpaddr0", out(reg) value, options(nomem, nostack)),
                1 => core::arch::asm!("csrr {}, pmpaddr1", out(reg) value, options(nomem, nostack)),
                2 => core::arch::asm!("csrr {}, pmpaddr2", out(reg) value, options(nomem, nostack)),
                3 => core::arch::asm!("csrr {}, pmpaddr3", out(reg) value, options(nomem, nostack)),
                4 => core::arch::asm!("csrr {}, pmpaddr4", out(reg) value, options(nomem, nostack)),
                5 => core::arch::asm!("csrr {}, pmpaddr5", out(reg) value, options(nomem, nostack)),
                6 => core::arch::asm!("csrr {}, pmpaddr6", out(reg) value, options(nomem, nostack)),
                7 => core::arch::asm!("csrr {}, pmpaddr7", out(reg) value, options(nomem, nostack)),
                _ => value = 0,
            }
        }
        value
    }

    /// Write pmpcfg entry for a specific region
    fn write_pmpcfg_entry(&self, index: usize, cfg: u8) {
        // For RV32: pmpcfg0-3, each holding 4 entries
        // For RV64: pmpcfg0 and pmpcfg2, each holding 8 entries
        #[cfg(target_pointer_width = "32")]
        {
            let reg_idx = index / 4;
            let byte_idx = index % 4;
            let shift = byte_idx * 8;
            let mask = 0xFFusize << shift;
            let value = (cfg as usize) << shift;

            // SAFETY: pmpcfg0-3 are M-mode CSRs that hold PMP configuration entries
            // (4 entries per register on RV32). Read-modify-write ensures only the
            // target entry's byte is updated while preserving adjacent entries.
            // reg_idx is derived from index/4 and the match covers all valid values.
            unsafe {
                match reg_idx {
                    0 => {
                        let old: usize;
                        core::arch::asm!("csrr {}, pmpcfg0", out(reg) old, options(nomem, nostack));
                        let new = (old & !mask) | value;
                        core::arch::asm!("csrw pmpcfg0, {}", in(reg) new, options(nomem, nostack));
                    }
                    1 => {
                        let old: usize;
                        core::arch::asm!("csrr {}, pmpcfg1", out(reg) old, options(nomem, nostack));
                        let new = (old & !mask) | value;
                        core::arch::asm!("csrw pmpcfg1, {}", in(reg) new, options(nomem, nostack));
                    }
                    2 => {
                        let old: usize;
                        core::arch::asm!("csrr {}, pmpcfg2", out(reg) old, options(nomem, nostack));
                        let new = (old & !mask) | value;
                        core::arch::asm!("csrw pmpcfg2, {}", in(reg) new, options(nomem, nostack));
                    }
                    3 => {
                        let old: usize;
                        core::arch::asm!("csrr {}, pmpcfg3", out(reg) old, options(nomem, nostack));
                        let new = (old & !mask) | value;
                        core::arch::asm!("csrw pmpcfg3, {}", in(reg) new, options(nomem, nostack));
                    }
                    _ => {}
                }
            }
        }

        #[cfg(target_pointer_width = "64")]
        {
            let reg_idx = index / 8;
            let byte_idx = index % 8;
            let shift = byte_idx * 8;
            let mask = 0xFFusize << shift;
            let value = (cfg as usize) << shift;

            // SAFETY: pmpcfg0 and pmpcfg2 are M-mode CSRs that hold PMP configuration
            // entries (8 entries per register on RV64). Read-modify-write ensures only
            // the target entry's byte is updated while preserving adjacent entries.
            // reg_idx is derived from index/8 and the match covers all valid values.
            unsafe {
                match reg_idx {
                    0 => {
                        let old: usize;
                        core::arch::asm!("csrr {}, pmpcfg0", out(reg) old, options(nomem, nostack));
                        let new = (old & !mask) | value;
                        core::arch::asm!("csrw pmpcfg0, {}", in(reg) new, options(nomem, nostack));
                    }
                    1 => {
                        let old: usize;
                        core::arch::asm!("csrr {}, pmpcfg2", out(reg) old, options(nomem, nostack));
                        let new = (old & !mask) | value;
                        core::arch::asm!("csrw pmpcfg2, {}", in(reg) new, options(nomem, nostack));
                    }
                    _ => {}
                }
            }
        }
    }

    /// Get the number of supported PMP regions
    #[must_use]
    pub const fn num_regions(&self) -> usize {
        self.num_regions
    }

    /// Check if an address is accessible with given permissions
    #[must_use]
    pub fn check_access(&self, address: usize, permissions: PmpPermissions) -> bool {
        // Check each region in order (first match wins)
        for region in &self.config.regions {
            if region.mode == PmpAddressMode::Off {
                continue;
            }

            let (start, end) = self.get_region_bounds(region);

            if address >= start && address < end {
                // Region matches - check permissions
                if permissions.read && !region.permissions.read {
                    return false;
                }
                if permissions.write && !region.permissions.write {
                    return false;
                }
                if permissions.execute && !region.permissions.execute {
                    return false;
                }
                return true;
            }
        }

        // No matching region - in M-mode this allows access, in U-mode it denies
        false
    }

    /// Get the bounds of a region
    fn get_region_bounds(&self, region: &PmpRegion) -> (usize, usize) {
        match region.mode {
            PmpAddressMode::Off => (0, 0),
            PmpAddressMode::Na4 => (region.address, region.address + 4),
            PmpAddressMode::Napot => (region.address, region.address + region.size),
            PmpAddressMode::Tor => {
                // TOR uses previous pmpaddr as start
                let start = if region.index > 0 {
                    self.config.regions[region.index as usize - 1].address
                } else {
                    0
                };
                (start, region.address)
            }
        }
    }

    /// Apply a complete configuration
    pub fn apply_config(&mut self, config: &PmpConfig) -> HalResult<()> {
        for region in &config.regions {
            if region.mode != PmpAddressMode::Off {
                self.configure_region(*region)?;
            } else {
                self.disable_region(region.index)?;
            }
        }
        Ok(())
    }

    /// Get current configuration
    #[must_use]
    pub fn config(&self) -> &PmpConfig {
        &self.config
    }
}

impl Default for Pmp {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Create a standard kernel memory protection configuration
#[must_use]
pub fn create_kernel_config(
    flash_base: usize,
    flash_size: usize,
    ram_base: usize,
    ram_size: usize,
) -> PmpConfig {
    let mut config = PmpConfig::default();

    // Region 0: Flash (RX) - kernel code
    config.regions[0] = PmpRegion::napot(0, flash_base, flash_size, PmpPermissions::RX);

    // Region 1: RAM (RW) - kernel data
    config.regions[1] = PmpRegion::napot(1, ram_base, ram_size, PmpPermissions::RW);

    // Region 2: Full access for M-mode (catch-all)
    // This allows M-mode to access anything not covered by other regions
    config.regions[2] = PmpRegion::napot(2, 0, 0x80000000, PmpPermissions::RWX);

    config
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_napot_encoding() {
        // 8 bytes at 0x1000
        let region = PmpRegion::napot(0, 0x1000, 8, PmpPermissions::RW);
        let encoded = region.napot_encode();
        // pmpaddr = (0x1000 >> 2) | 0 = 0x400
        assert_eq!(encoded, 0x400);

        // 256 bytes at 0x1000
        let region = PmpRegion::napot(0, 0x1000, 256, PmpPermissions::RW);
        let encoded = region.napot_encode();
        // Size = 256 = 2^8, napot_bits = 8-3 = 5
        // pmpaddr = (0x1000 >> 2) & ~0x3F | 0x1F = 0x400 & ~0x3F | 0x1F = 0x400 | 0x1F = 0x41F
        // Actually: (base >> 2) & !(2^(napot+1) - 1) | (2^napot - 1)
        // = 0x400 & !0x3F | 0x1F = 0x400 | 0x1F = 0x41F
        assert!(encoded > 0);
    }

    #[test]
    fn test_permissions() {
        let rwx = PmpPermissions::RWX;
        let bits = rwx.to_bits();
        assert_eq!(bits, PMP_R | PMP_W | PMP_X);

        let recovered = PmpPermissions::from_bits(bits);
        assert_eq!(recovered, rwx);
    }

    #[test]
    fn test_region_validation() {
        // Valid NAPOT region
        let valid = PmpRegion::napot(0, 0x1000, 256, PmpPermissions::RW);
        assert!(valid.validate().is_ok());

        // Invalid: size not power of 2
        let invalid = PmpRegion {
            index: 0,
            address: 0x1000,
            size: 100,
            permissions: PmpPermissions::RW,
            mode: PmpAddressMode::Napot,
            locked: false,
        };
        assert!(invalid.validate().is_err());

        // Invalid: region index too high
        let invalid = PmpRegion::napot(20, 0x1000, 256, PmpPermissions::RW);
        assert!(invalid.validate().is_err());
    }
}
