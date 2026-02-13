// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! ARM Cortex-M Memory Protection Unit (MPU) Configuration
//!
//! This module provides MPU configuration for task isolation on ARM Cortex-M
//! processors with ARMv7-M or ARMv8-M architecture.
//!
//! # MPU Overview
//!
//! The MPU provides:
//! - Memory region protection (read, write, execute permissions)
//! - Privilege-level separation (privileged vs unprivileged)
//! - Task isolation (each task gets its own memory regions)
//!
//! # Region Configuration
//!
//! ARMv7-M MPU supports 8 regions (0-7), each with:
//! - Base address (must be aligned to region size)
//! - Size (32 bytes to 4 GB, power of 2)
//! - Access permissions (privileged/unprivileged R/W/X)
//! - Memory attributes (cacheable, bufferable, shareable)
//!
//! ARMv8-M MPU (Cortex-M33) uses different register layout but similar concepts.
//!
//! # Region Layout for Qbitel EdgeOS
//!
//! | Region | Purpose              | Access        |
//! |--------|---------------------|---------------|
//! | 0      | Flash (code)        | RO, exec      |
//! | 1      | RAM (data)          | RW, no exec   |
//! | 2      | Peripherals         | RW, no exec   |
//! | 3      | Task stack          | RW, no exec   |
//! | 4      | Task data           | RW, no exec   |
//! | 5      | Shared memory       | RW, no exec   |
//! | 6      | Secure storage      | Privileged RW |
//! | 7      | Reserved            | -             |

use core::ptr;

// ============================================================================
// MPU Register Definitions (ARMv7-M)
// ============================================================================

/// MPU base address
const MPU_BASE: u32 = 0xE000_ED90;

/// MPU Type Register - indicates MPU presence and number of regions
const MPU_TYPE: u32 = MPU_BASE + 0x00;

/// MPU Control Register
const MPU_CTRL: u32 = MPU_BASE + 0x04;

/// MPU Region Number Register
const MPU_RNR: u32 = MPU_BASE + 0x08;

/// MPU Region Base Address Register
const MPU_RBAR: u32 = MPU_BASE + 0x0C;

/// MPU Region Attribute and Size Register
const MPU_RASR: u32 = MPU_BASE + 0x10;

/// MPU Region Base Address Register Alias 1
#[allow(dead_code)]
const MPU_RBAR_A1: u32 = MPU_BASE + 0x14;
/// MPU Region Attribute and Size Register Alias 1
#[allow(dead_code)]
const MPU_RASR_A1: u32 = MPU_BASE + 0x18;
/// MPU Region Base Address Register Alias 2
#[allow(dead_code)]
const MPU_RBAR_A2: u32 = MPU_BASE + 0x1C;
/// MPU Region Attribute and Size Register Alias 2
#[allow(dead_code)]
const MPU_RASR_A2: u32 = MPU_BASE + 0x20;
/// MPU Region Base Address Register Alias 3
#[allow(dead_code)]
const MPU_RBAR_A3: u32 = MPU_BASE + 0x24;
/// MPU Region Attribute and Size Register Alias 3
#[allow(dead_code)]
const MPU_RASR_A3: u32 = MPU_BASE + 0x28;

// MPU_CTRL bits
const MPU_CTRL_ENABLE: u32 = 1 << 0;     // Enable MPU
const MPU_CTRL_HFNMIENA: u32 = 1 << 1;   // Enable MPU during hard fault, NMI, FAULTMASK
const MPU_CTRL_PRIVDEFENA: u32 = 1 << 2; // Enable default memory map for privileged access

// MPU_RBAR bits
const MPU_RBAR_VALID: u32 = 1 << 4;      // Use REGION field to select region
#[allow(dead_code)]
const MPU_RBAR_REGION_MASK: u32 = 0xF;   // Region number field

// MPU_RASR bits
const MPU_RASR_ENABLE: u32 = 1 << 0;     // Enable region
const MPU_RASR_SIZE_SHIFT: u32 = 1;      // Size field shift (bits 5:1)
const MPU_RASR_SIZE_MASK: u32 = 0x1F << 1;
const MPU_RASR_SRD_SHIFT: u32 = 8;       // Sub-region disable shift
const MPU_RASR_SRD_MASK: u32 = 0xFF << 8;
const MPU_RASR_B: u32 = 1 << 16;         // Bufferable
const MPU_RASR_C: u32 = 1 << 17;         // Cacheable
const MPU_RASR_S: u32 = 1 << 18;         // Shareable
const MPU_RASR_TEX_SHIFT: u32 = 19;      // TEX field shift
const MPU_RASR_TEX_MASK: u32 = 0x7 << 19;
const MPU_RASR_AP_SHIFT: u32 = 24;       // Access permission shift
const MPU_RASR_AP_MASK: u32 = 0x7 << 24;
const MPU_RASR_XN: u32 = 1 << 28;        // Execute never

// ============================================================================
// Type Definitions
// ============================================================================

/// MPU region number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MpuRegionNumber {
    /// Region 0 - typically Flash (code)
    Region0 = 0,
    /// Region 1 - typically RAM (data)
    Region1 = 1,
    /// Region 2 - typically Peripherals
    Region2 = 2,
    /// Region 3 - Task stack
    Region3 = 3,
    /// Region 4 - Task data
    Region4 = 4,
    /// Region 5 - Shared memory
    Region5 = 5,
    /// Region 6 - Secure storage
    Region6 = 6,
    /// Region 7 - Reserved
    Region7 = 7,
}

/// MPU region size (must be power of 2, minimum 32 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MpuRegionSize {
    /// 32 bytes
    Size32B = 4,
    /// 64 bytes
    Size64B = 5,
    /// 128 bytes
    Size128B = 6,
    /// 256 bytes
    Size256B = 7,
    /// 512 bytes
    Size512B = 8,
    /// 1 KB
    Size1KB = 9,
    /// 2 KB
    Size2KB = 10,
    /// 4 KB
    Size4KB = 11,
    /// 8 KB
    Size8KB = 12,
    /// 16 KB
    Size16KB = 13,
    /// 32 KB
    Size32KB = 14,
    /// 64 KB
    Size64KB = 15,
    /// 128 KB
    Size128KB = 16,
    /// 256 KB
    Size256KB = 17,
    /// 512 KB
    Size512KB = 18,
    /// 1 MB
    Size1MB = 19,
    /// 2 MB
    Size2MB = 20,
    /// 4 MB
    Size4MB = 21,
    /// 8 MB
    Size8MB = 22,
    /// 16 MB
    Size16MB = 23,
    /// 32 MB
    Size32MB = 24,
    /// 64 MB
    Size64MB = 25,
    /// 128 MB
    Size128MB = 26,
    /// 256 MB
    Size256MB = 27,
    /// 512 MB
    Size512MB = 28,
    /// 1 GB
    Size1GB = 29,
    /// 2 GB
    Size2GB = 30,
    /// 4 GB
    Size4GB = 31,
}

impl MpuRegionSize {
    /// Get the size in bytes
    #[must_use]
    pub const fn bytes(&self) -> u32 {
        1 << ((*self as u32) + 1)
    }

    /// Convert a raw code (4–31) to the corresponding region size enum variant.
    ///
    /// Returns `None` if the code is out of the valid range.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            4  => Some(Self::Size32B),
            5  => Some(Self::Size64B),
            6  => Some(Self::Size128B),
            7  => Some(Self::Size256B),
            8  => Some(Self::Size512B),
            9  => Some(Self::Size1KB),
            10 => Some(Self::Size2KB),
            11 => Some(Self::Size4KB),
            12 => Some(Self::Size8KB),
            13 => Some(Self::Size16KB),
            14 => Some(Self::Size32KB),
            15 => Some(Self::Size64KB),
            16 => Some(Self::Size128KB),
            17 => Some(Self::Size256KB),
            18 => Some(Self::Size512KB),
            19 => Some(Self::Size1MB),
            20 => Some(Self::Size2MB),
            21 => Some(Self::Size4MB),
            22 => Some(Self::Size8MB),
            23 => Some(Self::Size16MB),
            24 => Some(Self::Size32MB),
            25 => Some(Self::Size64MB),
            26 => Some(Self::Size128MB),
            27 => Some(Self::Size256MB),
            28 => Some(Self::Size512MB),
            29 => Some(Self::Size1GB),
            30 => Some(Self::Size2GB),
            31 => Some(Self::Size4GB),
            _  => None,
        }
    }

    /// Find the smallest region size that can contain the given number of bytes
    pub fn from_bytes(bytes: u32) -> Option<Self> {
        if bytes == 0 {
            return None;
        }

        // Find the position of the highest set bit
        let msb = 31 - bytes.leading_zeros();

        // Round up if not a power of 2
        let size_bits = if bytes.is_power_of_two() {
            msb
        } else {
            msb + 1
        };

        // Convert to region size code (size_bits = code + 1)
        if size_bits < 5 {
            Some(Self::Size32B) // Minimum size
        } else if size_bits > 32 {
            None // Too large
        } else {
            Self::from_code((size_bits - 1) as u8)
        }
    }
}

/// Access permissions for MPU regions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MpuAccessPermission {
    /// No access
    NoAccess = 0b000,
    /// Privileged RW only
    PrivRw = 0b001,
    /// Privileged RW, Unprivileged RO
    PrivRwUnprivRo = 0b010,
    /// Full access (Priv RW, Unpriv RW)
    FullAccess = 0b011,
    /// Privileged RO only
    PrivRo = 0b101,
    /// Read-only (Priv RO, Unpriv RO)
    ReadOnly = 0b110,
}

/// Memory attributes for MPU regions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MpuMemoryAttributes {
    /// TEX field (type extension)
    pub tex: u8,
    /// Cacheable
    pub cacheable: bool,
    /// Bufferable
    pub bufferable: bool,
    /// Shareable
    pub shareable: bool,
}

impl MpuMemoryAttributes {
    /// Strongly-ordered (no caching, no buffering, synchronous)
    pub const STRONGLY_ORDERED: Self = Self {
        tex: 0,
        cacheable: false,
        bufferable: false,
        shareable: true,
    };

    /// Device memory (no caching, buffered, for peripherals)
    pub const DEVICE: Self = Self {
        tex: 0,
        cacheable: false,
        bufferable: true,
        shareable: true,
    };

    /// Normal memory, write-through, no write allocate
    pub const NORMAL_WT: Self = Self {
        tex: 0,
        cacheable: true,
        bufferable: false,
        shareable: false,
    };

    /// Normal memory, write-back, no write allocate
    pub const NORMAL_WB: Self = Self {
        tex: 0,
        cacheable: true,
        bufferable: true,
        shareable: false,
    };

    /// Normal memory, non-cacheable
    pub const NORMAL_NC: Self = Self {
        tex: 1,
        cacheable: false,
        bufferable: false,
        shareable: false,
    };

    /// Normal memory, write-back, write and read allocate
    pub const NORMAL_WBWA: Self = Self {
        tex: 1,
        cacheable: true,
        bufferable: true,
        shareable: false,
    };
}

/// MPU region configuration
#[derive(Debug, Clone, Copy)]
pub struct MpuRegionConfig {
    /// Region number
    pub region: MpuRegionNumber,
    /// Base address (must be aligned to region size)
    pub base_address: u32,
    /// Region size
    pub size: MpuRegionSize,
    /// Access permissions
    pub access: MpuAccessPermission,
    /// Memory attributes
    pub attributes: MpuMemoryAttributes,
    /// Execute never (disable instruction fetch)
    pub execute_never: bool,
    /// Sub-region disable mask (8 bits, each bit disables 1/8 of region)
    pub subregion_disable: u8,
    /// Enable this region
    pub enabled: bool,
}

impl MpuRegionConfig {
    /// Create a new region configuration
    pub const fn new(
        region: MpuRegionNumber,
        base_address: u32,
        size: MpuRegionSize,
        access: MpuAccessPermission,
    ) -> Self {
        Self {
            region,
            base_address,
            size,
            access,
            attributes: MpuMemoryAttributes::NORMAL_WB,
            execute_never: true,
            subregion_disable: 0,
            enabled: true,
        }
    }

    /// Set memory attributes
    pub const fn with_attributes(mut self, attributes: MpuMemoryAttributes) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set execute never flag
    pub const fn with_execute_never(mut self, xn: bool) -> Self {
        self.execute_never = xn;
        self
    }

    /// Set subregion disable mask
    pub const fn with_subregion_disable(mut self, mask: u8) -> Self {
        self.subregion_disable = mask;
        self
    }

    /// Enable/disable the region
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Build the RASR (Region Attribute and Size Register) value
    fn to_rasr(&self) -> u32 {
        let mut rasr = 0u32;

        if self.enabled {
            rasr |= MPU_RASR_ENABLE;
        }

        // Size field
        rasr |= ((self.size as u32) << MPU_RASR_SIZE_SHIFT) & MPU_RASR_SIZE_MASK;

        // Sub-region disable
        rasr |= ((self.subregion_disable as u32) << MPU_RASR_SRD_SHIFT) & MPU_RASR_SRD_MASK;

        // Memory attributes
        if self.attributes.bufferable {
            rasr |= MPU_RASR_B;
        }
        if self.attributes.cacheable {
            rasr |= MPU_RASR_C;
        }
        if self.attributes.shareable {
            rasr |= MPU_RASR_S;
        }
        rasr |= ((self.attributes.tex as u32) << MPU_RASR_TEX_SHIFT) & MPU_RASR_TEX_MASK;

        // Access permissions
        rasr |= ((self.access as u32) << MPU_RASR_AP_SHIFT) & MPU_RASR_AP_MASK;

        // Execute never
        if self.execute_never {
            rasr |= MPU_RASR_XN;
        }

        rasr
    }

    /// Build the RBAR (Region Base Address Register) value
    fn to_rbar(&self) -> u32 {
        // Base address must be aligned to region size
        let mask = self.size.bytes() - 1;
        let aligned_base = self.base_address & !mask;

        aligned_base | MPU_RBAR_VALID | (self.region as u32)
    }
}

// ============================================================================
// MPU Configuration Manager
// ============================================================================

/// MPU configuration state
pub struct MpuConfig {
    /// Whether MPU is enabled
    enabled: bool,
    /// Number of available regions
    num_regions: u8,
    /// Region configurations
    regions: [Option<MpuRegionConfig>; 8],
}

impl MpuConfig {
    /// Create a new MPU configuration manager
    pub const fn new() -> Self {
        Self {
            enabled: false,
            num_regions: 0,
            regions: [None; 8],
        }
    }

    /// Initialize MPU and detect capabilities
    pub fn init(&mut self) -> Result<(), MpuError> {
        // Read MPU_TYPE to check if MPU is present
        // SAFETY: MPU_TYPE (0xE000_ED90) is an architecturally-defined read-only Cortex-M
        // register. Reading it detects MPU presence. Always valid, no side effects.
        let mpu_type = unsafe { ptr::read_volatile(MPU_TYPE as *const u32) };

        // Bits 15:8 contain DREGION (number of data regions)
        let dregion = ((mpu_type >> 8) & 0xFF) as u8;

        if dregion == 0 {
            return Err(MpuError::NotPresent);
        }

        self.num_regions = dregion;

        // Disable MPU during configuration
        self.disable();

        Ok(())
    }

    /// Get number of available MPU regions
    #[must_use]
    pub fn num_regions(&self) -> u8 {
        self.num_regions
    }

    /// Check if MPU is present
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.num_regions > 0
    }

    /// Check if MPU is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Configure a single MPU region
    pub fn configure_region(&mut self, config: MpuRegionConfig) -> Result<(), MpuError> {
        if (config.region as u8) >= self.num_regions {
            return Err(MpuError::InvalidRegion);
        }

        // Verify alignment
        let size_bytes = config.size.bytes();
        if config.base_address & (size_bytes - 1) != 0 {
            return Err(MpuError::InvalidAlignment);
        }

        // Store configuration
        self.regions[config.region as usize] = Some(config);

        // Apply to hardware
        // SAFETY: MPU_RNR, MPU_RBAR, and MPU_RASR are architecturally-defined MPU
        // configuration registers. Writing them configures a memory protection region. The
        // region number and alignment have been validated above. volatile accesses required
        // for MMIO.
        unsafe {
            ptr::write_volatile(MPU_RNR as *mut u32, config.region as u32);
            ptr::write_volatile(MPU_RBAR as *mut u32, config.to_rbar());
            ptr::write_volatile(MPU_RASR as *mut u32, config.to_rasr());
        }

        // Memory barrier
        super::dsb();
        super::isb();

        Ok(())
    }

    /// Configure multiple regions at once (more efficient)
    pub fn configure_regions(&mut self, configs: &[MpuRegionConfig]) -> Result<(), MpuError> {
        for config in configs {
            self.configure_region(*config)?;
        }
        Ok(())
    }

    /// Disable a specific region
    pub fn disable_region(&mut self, region: MpuRegionNumber) -> Result<(), MpuError> {
        if (region as u8) >= self.num_regions {
            return Err(MpuError::InvalidRegion);
        }

        self.regions[region as usize] = None;

        // SAFETY: Writing 0 to MPU_RASR disables the selected MPU region. The region number
        // is bounds-checked above. volatile accesses required for MMIO.
        unsafe {
            ptr::write_volatile(MPU_RNR as *mut u32, region as u32);
            ptr::write_volatile(MPU_RASR as *mut u32, 0); // Disable region
        }

        super::dsb();
        super::isb();

        Ok(())
    }

    /// Enable the MPU
    pub fn enable(&mut self, enable_default_map: bool, enable_hfnmi: bool) {
        let mut ctrl = MPU_CTRL_ENABLE;

        if enable_default_map {
            ctrl |= MPU_CTRL_PRIVDEFENA;
        }

        if enable_hfnmi {
            ctrl |= MPU_CTRL_HFNMIENA;
        }

        // SAFETY: MPU_CTRL (0xE000_ED94) is the MPU control register. Writing the ENABLE bit
        // activates the MPU. volatile access required for MMIO.
        unsafe {
            ptr::write_volatile(MPU_CTRL as *mut u32, ctrl);
        }

        super::dsb();
        super::isb();

        self.enabled = true;
    }

    /// Disable the MPU
    pub fn disable(&mut self) {
        // SAFETY: Writing 0 to MPU_CTRL disables the MPU entirely. volatile access required
        // for MMIO.
        unsafe {
            ptr::write_volatile(MPU_CTRL as *mut u32, 0);
        }

        super::dsb();
        super::isb();

        self.enabled = false;
    }

    /// Switch MPU configuration for a task context switch
    ///
    /// This function rapidly reconfigures task-specific regions (3-5)
    /// without touching system regions (0-2, 6-7).
    pub fn switch_task_regions(&mut self, task_regions: &[MpuRegionConfig]) -> Result<(), MpuError> {
        // Disable MPU during reconfiguration for atomicity
        let was_enabled = self.enabled;
        if was_enabled {
            self.disable();
        }

        // Configure task regions
        for config in task_regions {
            match config.region {
                MpuRegionNumber::Region3
                | MpuRegionNumber::Region4
                | MpuRegionNumber::Region5 => {
                    self.configure_region(*config)?;
                }
                _ => return Err(MpuError::InvalidRegion),
            }
        }

        // Re-enable MPU
        if was_enabled {
            self.enable(true, false);
        }

        Ok(())
    }
}

impl Default for MpuConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Error Type
// ============================================================================

/// MPU configuration error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpuError {
    /// MPU not present on this device
    NotPresent,
    /// Invalid region number
    InvalidRegion,
    /// Base address not aligned to region size
    InvalidAlignment,
    /// Region size invalid
    InvalidSize,
}

// ============================================================================
// Default Configurations
// ============================================================================

/// Create default MPU configuration for Qbitel EdgeOS
///
/// This sets up:
/// - Region 0: Flash (code) - Read-only, executable
/// - Region 1: SRAM - Read-write, no execute
/// - Region 2: Peripherals - Device memory
/// - Region 6: Backup SRAM (secure) - Privileged RW only
pub fn create_default_config(
    flash_base: u32,
    flash_size: MpuRegionSize,
    ram_base: u32,
    ram_size: MpuRegionSize,
    periph_base: u32,
    periph_size: MpuRegionSize,
) -> [MpuRegionConfig; 4] {
    [
        // Flash - RO, executable
        MpuRegionConfig::new(
            MpuRegionNumber::Region0,
            flash_base,
            flash_size,
            MpuAccessPermission::ReadOnly,
        )
        .with_execute_never(false)
        .with_attributes(MpuMemoryAttributes::NORMAL_WT),

        // SRAM - RW, no execute
        MpuRegionConfig::new(
            MpuRegionNumber::Region1,
            ram_base,
            ram_size,
            MpuAccessPermission::FullAccess,
        )
        .with_execute_never(true)
        .with_attributes(MpuMemoryAttributes::NORMAL_WBWA),

        // Peripherals - Device memory
        MpuRegionConfig::new(
            MpuRegionNumber::Region2,
            periph_base,
            periph_size,
            MpuAccessPermission::FullAccess,
        )
        .with_execute_never(true)
        .with_attributes(MpuMemoryAttributes::DEVICE),

        // Backup SRAM - Privileged only
        MpuRegionConfig::new(
            MpuRegionNumber::Region6,
            0x3800_0000, // STM32 backup SRAM
            MpuRegionSize::Size4KB,
            MpuAccessPermission::PrivRw,
        )
        .with_execute_never(true)
        .with_attributes(MpuMemoryAttributes::NORMAL_NC),
    ]
}

/// Create task-specific MPU regions
pub fn create_task_regions(
    stack_base: u32,
    stack_size: MpuRegionSize,
    data_base: u32,
    data_size: MpuRegionSize,
) -> [MpuRegionConfig; 2] {
    [
        // Task stack
        MpuRegionConfig::new(
            MpuRegionNumber::Region3,
            stack_base,
            stack_size,
            MpuAccessPermission::FullAccess,
        )
        .with_execute_never(true)
        .with_attributes(MpuMemoryAttributes::NORMAL_WBWA),

        // Task data
        MpuRegionConfig::new(
            MpuRegionNumber::Region4,
            data_base,
            data_size,
            MpuAccessPermission::FullAccess,
        )
        .with_execute_never(true)
        .with_attributes(MpuMemoryAttributes::NORMAL_WBWA),
    ]
}

// ============================================================================
// Fast Task Region Switch
// ============================================================================

/// Switch task-specific MPU regions during a context switch
///
/// This updates regions 3 and 4 (task stack and task data) directly
/// without going through the `MpuConfig` manager, for minimal latency
/// during context switches.
///
/// Accepts pre-computed raw RBAR/RASR values from `TaskMpuRegions`.
///
/// # Arguments
/// * `regions` - Two optional raw region entries for the next task.
///   `[0]` maps to Region3 (task stack), `[1]` maps to Region4 (task data).
///   `None` entries disable the corresponding region.
pub fn switch_task_regions(regions: &crate::task::TaskMpuRegions) {
    // SAFETY: MPU register writes to reconfigure task-specific regions (3 and 4) during a
    // context switch. The caller (scheduler) ensures this is called with interrupts disabled
    // or from PendSV handler. The raw RBAR/RASR values were pre-computed during task creation
    // with validated alignment and size. volatile accesses required for MMIO.
    unsafe {
        // Region 3: task stack
        ptr::write_volatile(MPU_RNR as *mut u32, MpuRegionNumber::Region3 as u32);
        if let Some(ref raw) = regions[0] {
            ptr::write_volatile(MPU_RBAR as *mut u32, raw.rbar);
            ptr::write_volatile(MPU_RASR as *mut u32, raw.rasr);
        } else {
            ptr::write_volatile(MPU_RASR as *mut u32, 0); // Disable region
        }

        // Region 4: task data
        ptr::write_volatile(MPU_RNR as *mut u32, MpuRegionNumber::Region4 as u32);
        if let Some(ref raw) = regions[1] {
            ptr::write_volatile(MPU_RBAR as *mut u32, raw.rbar);
            ptr::write_volatile(MPU_RASR as *mut u32, raw.rasr);
        } else {
            ptr::write_volatile(MPU_RASR as *mut u32, 0); // Disable region
        }
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
    fn test_region_size_bytes() {
        assert_eq!(MpuRegionSize::Size32B.bytes(), 32);
        assert_eq!(MpuRegionSize::Size1KB.bytes(), 1024);
        assert_eq!(MpuRegionSize::Size1MB.bytes(), 1024 * 1024);
    }

    #[test]
    fn test_region_size_from_bytes() {
        assert_eq!(MpuRegionSize::from_bytes(32), Some(MpuRegionSize::Size32B));
        assert_eq!(MpuRegionSize::from_bytes(100), Some(MpuRegionSize::Size128B));
        assert_eq!(MpuRegionSize::from_bytes(1024), Some(MpuRegionSize::Size1KB));
    }

    #[test]
    fn test_rasr_encoding() {
        let config = MpuRegionConfig::new(
            MpuRegionNumber::Region0,
            0x0800_0000,
            MpuRegionSize::Size1MB,
            MpuAccessPermission::ReadOnly,
        )
        .with_execute_never(false);

        let rasr = config.to_rasr();

        // Check enable bit
        assert_ne!(rasr & MPU_RASR_ENABLE, 0);

        // Check size (19 = 1MB)
        assert_eq!((rasr & MPU_RASR_SIZE_MASK) >> MPU_RASR_SIZE_SHIFT, 19);

        // Check XN is not set
        assert_eq!(rasr & MPU_RASR_XN, 0);
    }
}
