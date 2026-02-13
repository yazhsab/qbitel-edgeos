// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! RISC-V Physical Memory Protection (PMP)
//!
//! This module provides configuration for the RISC-V Physical Memory Protection
//! unit, which controls access permissions for memory regions in M-mode and
//! lower privilege levels.
//!
//! # PMP Overview
//!
//! The PMP provides:
//! - Up to 16 memory regions (PMP0-PMP15)
//! - Per-region read, write, execute permissions
//! - Address matching modes: OFF, TOR, NA4, NAPOT
//! - Lock bit to prevent modification

use core::arch::asm;

/// Maximum number of PMP regions (typically 16)
pub const MAX_PMP_REGIONS: usize = 16;

/// PMP configuration bits
pub mod pmpcfg {
    /// Read permission
    pub const R: u8 = 1 << 0;
    /// Write permission
    pub const W: u8 = 1 << 1;
    /// Execute permission
    pub const X: u8 = 1 << 2;
    /// Address matching mode (2 bits at position 3-4)
    pub const A_MASK: u8 = 0b11 << 3;
    /// Address matching: OFF (disabled)
    pub const A_OFF: u8 = 0b00 << 3;
    /// Address matching: TOR (top of range)
    pub const A_TOR: u8 = 0b01 << 3;
    /// Address matching: NA4 (naturally aligned 4-byte)
    pub const A_NA4: u8 = 0b10 << 3;
    /// Address matching: NAPOT (naturally aligned power-of-two)
    pub const A_NAPOT: u8 = 0b11 << 3;
    /// Lock bit (prevents further modification)
    pub const L: u8 = 1 << 7;
}

/// PMP region number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PmpRegionNumber {
    /// Region 0
    Region0 = 0,
    /// Region 1
    Region1 = 1,
    /// Region 2
    Region2 = 2,
    /// Region 3
    Region3 = 3,
    /// Region 4
    Region4 = 4,
    /// Region 5
    Region5 = 5,
    /// Region 6
    Region6 = 6,
    /// Region 7
    Region7 = 7,
    /// Region 8
    Region8 = 8,
    /// Region 9
    Region9 = 9,
    /// Region 10
    Region10 = 10,
    /// Region 11
    Region11 = 11,
    /// Region 12
    Region12 = 12,
    /// Region 13
    Region13 = 13,
    /// Region 14
    Region14 = 14,
    /// Region 15
    Region15 = 15,
}

impl From<u8> for PmpRegionNumber {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Region0,
            1 => Self::Region1,
            2 => Self::Region2,
            3 => Self::Region3,
            4 => Self::Region4,
            5 => Self::Region5,
            6 => Self::Region6,
            7 => Self::Region7,
            8 => Self::Region8,
            9 => Self::Region9,
            10 => Self::Region10,
            11 => Self::Region11,
            12 => Self::Region12,
            13 => Self::Region13,
            14 => Self::Region14,
            _ => Self::Region15,
        }
    }
}

/// PMP permission flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmpPermission(u8);

impl PmpPermission {
    /// No access
    pub const NONE: Self = Self(0);
    /// Read only
    pub const READ: Self = Self(pmpcfg::R);
    /// Write only (unusual)
    pub const WRITE: Self = Self(pmpcfg::W);
    /// Execute only
    pub const EXECUTE: Self = Self(pmpcfg::X);
    /// Read + Write
    pub const READ_WRITE: Self = Self(pmpcfg::R | pmpcfg::W);
    /// Read + Execute
    pub const READ_EXECUTE: Self = Self(pmpcfg::R | pmpcfg::X);
    /// Read + Write + Execute
    pub const READ_WRITE_EXECUTE: Self = Self(pmpcfg::R | pmpcfg::W | pmpcfg::X);

    /// Create permission from raw bits
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & (pmpcfg::R | pmpcfg::W | pmpcfg::X))
    }

    /// Get raw permission bits
    pub const fn bits(&self) -> u8 {
        self.0
    }

    /// Check if readable
    pub const fn is_readable(&self) -> bool {
        self.0 & pmpcfg::R != 0
    }

    /// Check if writable
    pub const fn is_writable(&self) -> bool {
        self.0 & pmpcfg::W != 0
    }

    /// Check if executable
    pub const fn is_executable(&self) -> bool {
        self.0 & pmpcfg::X != 0
    }
}

/// PMP address matching mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PmpAddressMode {
    /// Region disabled
    Off = 0,
    /// Top of Range (address is upper bound, previous region is lower bound)
    Tor = 1,
    /// Naturally Aligned 4-byte region
    Na4 = 2,
    /// Naturally Aligned Power-of-Two region
    Napot = 3,
}

impl PmpAddressMode {
    /// Convert to configuration bits
    pub const fn to_cfg_bits(&self) -> u8 {
        match self {
            Self::Off => pmpcfg::A_OFF,
            Self::Tor => pmpcfg::A_TOR,
            Self::Na4 => pmpcfg::A_NA4,
            Self::Napot => pmpcfg::A_NAPOT,
        }
    }
}

/// PMP region configuration
#[derive(Debug, Clone, Copy)]
pub struct PmpRegionConfig {
    /// Region number
    pub region: PmpRegionNumber,
    /// Base address
    pub base_addr: usize,
    /// Region size (must be power of 2 for NAPOT, ignored for TOR)
    pub size: usize,
    /// Access permissions
    pub permission: PmpPermission,
    /// Address matching mode
    pub mode: PmpAddressMode,
    /// Lock the region (prevents further modification)
    pub locked: bool,
}

impl PmpRegionConfig {
    /// Create a new NAPOT region configuration
    ///
    /// # Arguments
    /// * `region` - Region number
    /// * `base_addr` - Base address (must be aligned to size)
    /// * `size` - Region size (must be power of 2, minimum 8 bytes)
    /// * `permission` - Access permissions
    pub fn napot(
        region: PmpRegionNumber,
        base_addr: usize,
        size: usize,
        permission: PmpPermission,
    ) -> Self {
        Self {
            region,
            base_addr,
            size,
            permission,
            mode: PmpAddressMode::Napot,
            locked: false,
        }
    }

    /// Create a TOR (Top of Range) region configuration
    ///
    /// Note: TOR uses the previous region's address as the lower bound.
    /// For region 0, the lower bound is 0.
    pub fn tor(
        region: PmpRegionNumber,
        top_addr: usize,
        permission: PmpPermission,
    ) -> Self {
        Self {
            region,
            base_addr: top_addr,
            size: 0,
            permission,
            mode: PmpAddressMode::Tor,
            locked: false,
        }
    }

    /// Lock this region (prevents further modification until reset)
    pub fn lock(mut self) -> Self {
        self.locked = true;
        self
    }

    /// Calculate NAPOT address encoding
    ///
    /// For NAPOT, the pmpaddr encodes both base and size:
    /// - For size = 2^(n+3), set lowest (n-1) bits of (base >> 2) to 1
    fn napot_addr(&self) -> usize {
        if self.size < 8 {
            return self.base_addr >> 2;
        }

        // Find the number of trailing ones needed
        // size = 2^(n+3), so we need (n) trailing ones in pmpaddr
        let trailing_ones = (self.size.trailing_zeros() as usize).saturating_sub(2);
        let mask = (1 << trailing_ones) - 1;

        ((self.base_addr >> 2) & !mask) | mask
    }

    /// Get pmpaddr value for this region
    pub fn pmpaddr(&self) -> usize {
        match self.mode {
            PmpAddressMode::Off => 0,
            PmpAddressMode::Tor => self.base_addr >> 2,
            PmpAddressMode::Na4 => self.base_addr >> 2,
            PmpAddressMode::Napot => self.napot_addr(),
        }
    }

    /// Get pmpcfg value for this region
    pub fn pmpcfg(&self) -> u8 {
        let mut cfg = self.permission.bits() | self.mode.to_cfg_bits();
        if self.locked {
            cfg |= pmpcfg::L;
        }
        cfg
    }
}

/// PMP configuration manager
pub struct PmpConfig {
    /// Region configurations (indexed by region number)
    regions: [Option<PmpRegionConfig>; MAX_PMP_REGIONS],
    /// Number of configured regions
    count: usize,
}

impl PmpConfig {
    /// Create a new PMP configuration
    pub const fn new() -> Self {
        Self {
            regions: [None; MAX_PMP_REGIONS],
            count: 0,
        }
    }

    /// Add a region configuration
    pub fn add_region(&mut self, config: PmpRegionConfig) -> Result<(), PmpError> {
        let idx = config.region as usize;

        if idx >= MAX_PMP_REGIONS {
            return Err(PmpError::InvalidRegion);
        }

        // Check alignment for NAPOT
        if config.mode == PmpAddressMode::Napot {
            if !config.size.is_power_of_two() {
                return Err(PmpError::InvalidSize);
            }
            if config.base_addr & (config.size - 1) != 0 {
                return Err(PmpError::MisalignedAddress);
            }
        }

        self.regions[idx] = Some(config);
        if idx >= self.count {
            self.count = idx + 1;
        }

        Ok(())
    }

    /// Remove a region configuration
    pub fn remove_region(&mut self, region: PmpRegionNumber) -> bool {
        let idx = region as usize;
        if self.regions[idx].is_some() {
            self.regions[idx] = None;
            true
        } else {
            false
        }
    }

    /// Apply the configuration to hardware
    pub fn apply(&self) {
        // Apply each region's configuration
        for (i, region) in self.regions.iter().enumerate() {
            if let Some(config) = region {
                let addr = config.pmpaddr();
                let cfg = config.pmpcfg();

                // Write pmpaddr
                write_pmpaddr(i, addr);

                // Write pmpcfg (packed into 32-bit or 64-bit registers)
                write_pmpcfg(i, cfg);
            } else {
                // Disable unused regions
                write_pmpcfg(i, 0);
            }
        }

        // Fence to ensure PMP changes take effect
        // SAFETY: SFENCE.VMA synchronizes PMP configuration changes by flushing
        // the TLB. Required after modifying PMP registers to ensure the new
        // permissions take effect. Always safe to execute in M-mode.
        unsafe {
            asm!("sfence.vma", options(nomem, nostack));
        }
    }

    /// Get a region configuration
    pub fn get_region(&self, region: PmpRegionNumber) -> Option<&PmpRegionConfig> {
        self.regions[region as usize].as_ref()
    }
}

impl Default for PmpConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// PMP configuration errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmpError {
    /// Invalid region number
    InvalidRegion,
    /// Invalid region size (must be power of 2 for NAPOT)
    InvalidSize,
    /// Address not aligned to size
    MisalignedAddress,
    /// Region is locked
    RegionLocked,
}

// ============================================================================
// Low-level PMP register access
// ============================================================================

/// Write to pmpaddr register
fn write_pmpaddr(index: usize, value: usize) {
    // RISC-V has pmpaddr0-pmpaddr15
    // We use a match statement since CSR addresses are immediate values
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    // SAFETY: Writing pmpaddr CSRs configures PMP region addresses. The index
    // is used to select the correct CSR via a match statement (CSR addresses are
    // immediate values and cannot be computed at runtime). Values out of range
    // 0-15 are ignored. Always valid in M-mode.
    unsafe {
        match index {
            0 => asm!("csrw pmpaddr0, {0}", in(reg) value, options(nomem, nostack)),
            1 => asm!("csrw pmpaddr1, {0}", in(reg) value, options(nomem, nostack)),
            2 => asm!("csrw pmpaddr2, {0}", in(reg) value, options(nomem, nostack)),
            3 => asm!("csrw pmpaddr3, {0}", in(reg) value, options(nomem, nostack)),
            4 => asm!("csrw pmpaddr4, {0}", in(reg) value, options(nomem, nostack)),
            5 => asm!("csrw pmpaddr5, {0}", in(reg) value, options(nomem, nostack)),
            6 => asm!("csrw pmpaddr6, {0}", in(reg) value, options(nomem, nostack)),
            7 => asm!("csrw pmpaddr7, {0}", in(reg) value, options(nomem, nostack)),
            8 => asm!("csrw pmpaddr8, {0}", in(reg) value, options(nomem, nostack)),
            9 => asm!("csrw pmpaddr9, {0}", in(reg) value, options(nomem, nostack)),
            10 => asm!("csrw pmpaddr10, {0}", in(reg) value, options(nomem, nostack)),
            11 => asm!("csrw pmpaddr11, {0}", in(reg) value, options(nomem, nostack)),
            12 => asm!("csrw pmpaddr12, {0}", in(reg) value, options(nomem, nostack)),
            13 => asm!("csrw pmpaddr13, {0}", in(reg) value, options(nomem, nostack)),
            14 => asm!("csrw pmpaddr14, {0}", in(reg) value, options(nomem, nostack)),
            15 => asm!("csrw pmpaddr15, {0}", in(reg) value, options(nomem, nostack)),
            _ => {}
        }
    }

    // For non-RISC-V targets, this is a no-op
    #[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
    let _ = (index, value);
}

/// Read from pmpaddr register
#[allow(dead_code)]
fn read_pmpaddr(index: usize) -> usize {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    // SAFETY: Reading pmpaddr CSRs is non-destructive. Index selects the CSR
    // via match. Out-of-range indices return 0. Always valid in M-mode.
    unsafe {
        let value: usize;
        match index {
            0 => asm!("csrr {0}, pmpaddr0", out(reg) value, options(nomem, nostack)),
            1 => asm!("csrr {0}, pmpaddr1", out(reg) value, options(nomem, nostack)),
            2 => asm!("csrr {0}, pmpaddr2", out(reg) value, options(nomem, nostack)),
            3 => asm!("csrr {0}, pmpaddr3", out(reg) value, options(nomem, nostack)),
            4 => asm!("csrr {0}, pmpaddr4", out(reg) value, options(nomem, nostack)),
            5 => asm!("csrr {0}, pmpaddr5", out(reg) value, options(nomem, nostack)),
            6 => asm!("csrr {0}, pmpaddr6", out(reg) value, options(nomem, nostack)),
            7 => asm!("csrr {0}, pmpaddr7", out(reg) value, options(nomem, nostack)),
            8 => asm!("csrr {0}, pmpaddr8", out(reg) value, options(nomem, nostack)),
            9 => asm!("csrr {0}, pmpaddr9", out(reg) value, options(nomem, nostack)),
            10 => asm!("csrr {0}, pmpaddr10", out(reg) value, options(nomem, nostack)),
            11 => asm!("csrr {0}, pmpaddr11", out(reg) value, options(nomem, nostack)),
            12 => asm!("csrr {0}, pmpaddr12", out(reg) value, options(nomem, nostack)),
            13 => asm!("csrr {0}, pmpaddr13", out(reg) value, options(nomem, nostack)),
            14 => asm!("csrr {0}, pmpaddr14", out(reg) value, options(nomem, nostack)),
            15 => asm!("csrr {0}, pmpaddr15", out(reg) value, options(nomem, nostack)),
            _ => return 0,
        }
        value
    }

    #[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
    {
        let _ = index;
        0
    }
}

/// Write to pmpcfg register
///
/// pmpcfg registers pack 4 (RV32) or 8 (RV64) region configs per register.
fn write_pmpcfg(region: usize, value: u8) {
    #[cfg(target_arch = "riscv32")]
    // SAFETY: Read-modify-write of pmpcfg CSRs to set a single region's
    // configuration byte. The region index determines which pmpcfg register and
    // byte offset to use. CSR access is always valid in M-mode. The
    // read-modify-write pattern preserves other regions' configurations.
    unsafe {
        // RV32: 4 configs per register (pmpcfg0-pmpcfg3)
        let reg_idx = region / 4;
        let byte_idx = region % 4;
        let shift = byte_idx * 8;

        // Read-modify-write
        let current: u32;
        match reg_idx {
            0 => asm!("csrr {0}, pmpcfg0", out(reg) current, options(nomem, nostack)),
            1 => asm!("csrr {0}, pmpcfg1", out(reg) current, options(nomem, nostack)),
            2 => asm!("csrr {0}, pmpcfg2", out(reg) current, options(nomem, nostack)),
            3 => asm!("csrr {0}, pmpcfg3", out(reg) current, options(nomem, nostack)),
            _ => return,
        }

        let mask = !(0xFFu32 << shift);
        let new_val = (current & mask) | ((value as u32) << shift);

        match reg_idx {
            0 => asm!("csrw pmpcfg0, {0}", in(reg) new_val, options(nomem, nostack)),
            1 => asm!("csrw pmpcfg1, {0}", in(reg) new_val, options(nomem, nostack)),
            2 => asm!("csrw pmpcfg2, {0}", in(reg) new_val, options(nomem, nostack)),
            3 => asm!("csrw pmpcfg3, {0}", in(reg) new_val, options(nomem, nostack)),
            _ => {}
        }
    }

    #[cfg(target_arch = "riscv64")]
    // SAFETY: Read-modify-write of pmpcfg CSRs to set a single region's
    // configuration byte. The region index determines which pmpcfg register and
    // byte offset to use. CSR access is always valid in M-mode. The
    // read-modify-write pattern preserves other regions' configurations.
    unsafe {
        // RV64: 8 configs per register (pmpcfg0, pmpcfg2)
        let reg_idx = region / 8;
        let byte_idx = region % 8;
        let shift = byte_idx * 8;

        let current: u64;
        match reg_idx {
            0 => asm!("csrr {0}, pmpcfg0", out(reg) current, options(nomem, nostack)),
            1 => asm!("csrr {0}, pmpcfg2", out(reg) current, options(nomem, nostack)),
            _ => return,
        }

        let mask = !(0xFFu64 << shift);
        let new_val = (current & mask) | ((value as u64) << shift);

        match reg_idx {
            0 => asm!("csrw pmpcfg0, {0}", in(reg) new_val, options(nomem, nostack)),
            1 => asm!("csrw pmpcfg2, {0}", in(reg) new_val, options(nomem, nostack)),
            _ => {}
        }
    }

    #[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
    let _ = (region, value);
}

// ============================================================================
// Task PMP region switching (context switch)
// ============================================================================

/// PMP region indices reserved for per-task memory protection.
///
/// Regions 0-1 are reserved for kernel/global use (e.g., kernel code/data).
/// Regions 2-3 are switched on every context switch for the active task.
const TASK_PMP_REGION_BASE: usize = 2;

/// Switch PMP regions for the next task during a context switch.
///
/// Writes the task's pre-computed PMP entries to hardware regions 2 and 3.
/// Entries set to `None` disable the corresponding region.
///
/// # Arguments
/// * `entries` - Per-task PMP entries (stack + data regions).
///
/// # Safety contract
/// The caller (scheduler) must ensure this is called with interrupts disabled.
pub fn switch_task_regions(entries: &crate::task::TaskPmpEntries) {
    for (i, entry) in entries.iter().enumerate() {
        let region = TASK_PMP_REGION_BASE + i;
        if let Some(raw) = entry {
            write_pmpaddr(region, raw.pmpaddr);
            write_pmpcfg(region, raw.pmpcfg);
        } else {
            // Disable the region (A=OFF clears all permissions)
            write_pmpcfg(region, 0);
        }
    }

    // Fence to ensure PMP changes take effect before returning to user task
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    // SAFETY: SFENCE.VMA flushes the TLB to synchronize PMP configuration
    // changes. Required after modifying PMP registers. Always safe in M-mode.
    unsafe {
        asm!("sfence.vma", options(nomem, nostack));
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_flags() {
        assert_eq!(PmpPermission::NONE.bits(), 0);
        assert_eq!(PmpPermission::READ.bits(), 1);
        assert_eq!(PmpPermission::WRITE.bits(), 2);
        assert_eq!(PmpPermission::EXECUTE.bits(), 4);
        assert_eq!(PmpPermission::READ_WRITE.bits(), 3);
        assert_eq!(PmpPermission::READ_EXECUTE.bits(), 5);
        assert_eq!(PmpPermission::READ_WRITE_EXECUTE.bits(), 7);
    }

    #[test]
    fn test_permission_checks() {
        assert!(PmpPermission::READ.is_readable());
        assert!(!PmpPermission::READ.is_writable());
        assert!(!PmpPermission::READ.is_executable());

        assert!(PmpPermission::READ_WRITE_EXECUTE.is_readable());
        assert!(PmpPermission::READ_WRITE_EXECUTE.is_writable());
        assert!(PmpPermission::READ_WRITE_EXECUTE.is_executable());
    }

    #[test]
    fn test_napot_addr_calculation() {
        // 4KB region at 0x80000000
        let config = PmpRegionConfig::napot(
            PmpRegionNumber::Region0,
            0x8000_0000,
            4096, // 4KB = 2^12
            PmpPermission::READ_EXECUTE,
        );

        // For 4KB (2^12), we need 10 trailing ones in pmpaddr
        // pmpaddr = (base >> 2) with lowest 10 bits set to 1
        let expected_addr = (0x8000_0000 >> 2) | 0x1FF; // 9 trailing ones for 4KB
        assert_eq!(config.pmpaddr(), expected_addr);
    }

    #[test]
    fn test_pmp_config_add_region() {
        let mut pmp = PmpConfig::new();

        let config = PmpRegionConfig::napot(
            PmpRegionNumber::Region0,
            0x8000_0000,
            4096,
            PmpPermission::READ_EXECUTE,
        );

        assert!(pmp.add_region(config).is_ok());
        assert!(pmp.get_region(PmpRegionNumber::Region0).is_some());
    }

    #[test]
    fn test_pmp_config_invalid_alignment() {
        let mut pmp = PmpConfig::new();

        // Misaligned base address for 4KB region
        let config = PmpRegionConfig::napot(
            PmpRegionNumber::Region0,
            0x8000_0100, // Not aligned to 4KB
            4096,
            PmpPermission::READ,
        );

        assert_eq!(pmp.add_region(config), Err(PmpError::MisalignedAddress));
    }

    #[test]
    fn test_pmp_config_invalid_size() {
        let mut pmp = PmpConfig::new();

        // Non-power-of-2 size
        let config = PmpRegionConfig::napot(
            PmpRegionNumber::Region0,
            0x8000_0000,
            5000, // Not a power of 2
            PmpPermission::READ,
        );

        assert_eq!(pmp.add_region(config), Err(PmpError::InvalidSize));
    }

    #[test]
    fn test_region_lock() {
        let config = PmpRegionConfig::napot(
            PmpRegionNumber::Region0,
            0x8000_0000,
            4096,
            PmpPermission::READ,
        ).lock();

        assert!(config.locked);
        assert!(config.pmpcfg() & pmpcfg::L != 0);
    }

    #[test]
    fn test_tor_region() {
        let config = PmpRegionConfig::tor(
            PmpRegionNumber::Region1,
            0x8000_1000,
            PmpPermission::READ_WRITE,
        );

        assert_eq!(config.mode, PmpAddressMode::Tor);
        assert_eq!(config.pmpaddr(), 0x8000_1000 >> 2);
    }

    #[test]
    fn test_switch_task_regions_with_entries() {
        use crate::task::PmpEntryRaw;

        // Build entries from a NAPOT region config
        let config = PmpRegionConfig::napot(
            PmpRegionNumber::Region2,
            0x2000_0000,
            4096,
            PmpPermission::READ_WRITE,
        );

        let entries: crate::task::TaskPmpEntries = [
            Some(PmpEntryRaw {
                pmpaddr: config.pmpaddr(),
                pmpcfg: config.pmpcfg(),
            }),
            None,
        ];

        // On non-RISC-V hosts, this is a no-op but should not panic
        switch_task_regions(&entries);
    }

    #[test]
    fn test_switch_task_regions_all_none() {
        let entries: crate::task::TaskPmpEntries = [None, None];
        // Should not panic even with all regions disabled
        switch_task_regions(&entries);
    }
}
