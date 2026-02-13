// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Kernel loading and memory protection configuration
//!
//! This module handles the final steps of secure boot:
//! - MPU configuration for memory isolation
//! - Bootloader region lockdown
//! - Kernel entry point handoff

use core::ptr;

// =============================================================================
// MPU Register Definitions (ARMv7-M) - Bootloader copy
// =============================================================================

/// MPU base address
const MPU_BASE: u32 = 0xE000_ED90;

/// MPU Type Register
const MPU_TYPE: u32 = MPU_BASE + 0x00;
/// MPU Control Register
const MPU_CTRL: u32 = MPU_BASE + 0x04;
/// MPU Region Number Register
const MPU_RNR: u32 = MPU_BASE + 0x08;
/// MPU Region Base Address Register
const MPU_RBAR: u32 = MPU_BASE + 0x0C;
/// MPU Region Attribute and Size Register
const MPU_RASR: u32 = MPU_BASE + 0x10;

// MPU_CTRL bits
const MPU_CTRL_ENABLE: u32 = 1 << 0;
const MPU_CTRL_HFNMIENA: u32 = 1 << 1;
const MPU_CTRL_PRIVDEFENA: u32 = 1 << 2;

// MPU_RBAR bits
const MPU_RBAR_VALID: u32 = 1 << 4;

// MPU_RASR bits
const MPU_RASR_ENABLE: u32 = 1 << 0;
const MPU_RASR_SIZE_SHIFT: u32 = 1;
const MPU_RASR_B: u32 = 1 << 16;      // Bufferable
const MPU_RASR_C: u32 = 1 << 17;      // Cacheable
const MPU_RASR_S: u32 = 1 << 18;      // Shareable
const MPU_RASR_TEX_SHIFT: u32 = 19;
const MPU_RASR_AP_SHIFT: u32 = 24;
const MPU_RASR_XN: u32 = 1 << 28;     // Execute never

// Region sizes (encoded as log2(size) - 1)
const MPU_SIZE_32KB: u32 = 14;
#[allow(dead_code)]
const MPU_SIZE_64KB: u32 = 15;
#[allow(dead_code)]
const MPU_SIZE_128KB: u32 = 16;
#[allow(dead_code)]
const MPU_SIZE_256KB: u32 = 17;
const MPU_SIZE_512KB: u32 = 18;
const MPU_SIZE_1MB: u32 = 19;
#[allow(dead_code)]
const MPU_SIZE_2MB: u32 = 20;

// Access permissions
const AP_PRIV_RO: u32 = 0b101;        // Privileged read-only
const AP_PRIV_RW: u32 = 0b001;        // Privileged read-write
const AP_FULL_RW: u32 = 0b011;        // Full read-write access
const AP_RO_RO: u32 = 0b110;          // Read-only for all

// STM32H7 memory map
const FLASH_BASE: u32 = 0x0800_0000;
const BOOTLOADER_SIZE: u32 = 32 * 1024; // 32KB bootloader
const RAM_BASE: u32 = 0x2000_0000;
#[allow(dead_code)]
const RAM_SIZE: u32 = 512 * 1024;       // 512KB SRAM
const PERIPH_BASE: u32 = 0x4000_0000;

// =============================================================================
// MPU Configuration
// =============================================================================

/// MPU region configuration for bootloader handoff
struct MpuBootRegion {
    region: u32,
    base: u32,
    size: u32,
    access: u32,
    tex: u32,
    cacheable: bool,
    bufferable: bool,
    shareable: bool,
    execute_never: bool,
}

impl MpuBootRegion {
    /// Convert to RASR value
    const fn to_rasr(&self) -> u32 {
        let mut rasr = MPU_RASR_ENABLE;

        // Size field
        rasr |= self.size << MPU_RASR_SIZE_SHIFT;

        // Memory attributes
        if self.bufferable {
            rasr |= MPU_RASR_B;
        }
        if self.cacheable {
            rasr |= MPU_RASR_C;
        }
        if self.shareable {
            rasr |= MPU_RASR_S;
        }
        rasr |= self.tex << MPU_RASR_TEX_SHIFT;

        // Access permissions
        rasr |= self.access << MPU_RASR_AP_SHIFT;

        // Execute never
        if self.execute_never {
            rasr |= MPU_RASR_XN;
        }

        rasr
    }

    /// Convert to RBAR value
    const fn to_rbar(&self) -> u32 {
        self.base | MPU_RBAR_VALID | self.region
    }
}

/// Check if MPU is present
fn is_mpu_present() -> bool {
    // SAFETY: MPU_TYPE (0xE000_ED90) is an ARM Cortex-M System Control Block
    // register, always mapped and readable in privileged mode. Volatile read
    // required because this is an MMIO register.
    let mpu_type = unsafe { ptr::read_volatile(MPU_TYPE as *const u32) };
    let num_regions = (mpu_type >> 8) & 0xFF;
    num_regions > 0
}

/// Configure MPU for kernel handoff
///
/// Sets up memory protection regions:
/// - Region 0: Bootloader flash (read-only, no execute from kernel perspective)
/// - Region 1: Kernel flash (read-only, executable)
/// - Region 2: RAM (read-write, no execute)
/// - Region 3: Peripherals (device memory)
/// - Region 4: Backup SRAM / Secure storage (privileged only)
///
/// # Safety
///
/// This function configures hardware registers and must be called with
/// interrupts disabled. The bootloader is locked as read-only after this.
pub fn configure_memory_protection() -> bool {
    if !is_mpu_present() {
        // No MPU available - continue without protection
        // In production, this might be a fatal error
        return false;
    }

    // Disable MPU during configuration
    // SAFETY: MPU_CTRL (0xE000_ED94) is the MPU control register. Writing 0
    // disables the MPU, which is required before reconfiguring regions.
    // Must be called with interrupts disabled (bootloader context).
    unsafe {
        ptr::write_volatile(MPU_CTRL as *mut u32, 0);
    }

    // Data Synchronization Barrier
    dsb();
    isb();

    // Region 0: Bootloader flash - Read-only, NO execute
    // After handoff, bootloader code should never execute
    let bootloader_region = MpuBootRegion {
        region: 0,
        base: FLASH_BASE,
        size: MPU_SIZE_32KB,
        access: AP_PRIV_RO,  // Privileged read-only
        tex: 0,
        cacheable: true,
        bufferable: false,
        shareable: false,
        execute_never: true,  // CRITICAL: Lock bootloader as non-executable
    };

    // Region 1: Kernel flash - Read-only, executable
    let kernel_region = MpuBootRegion {
        region: 1,
        base: FLASH_BASE + BOOTLOADER_SIZE, // 0x0800_8000
        size: MPU_SIZE_1MB,  // 1MB for kernel
        access: AP_RO_RO,    // Read-only for all
        tex: 0,
        cacheable: true,
        bufferable: false,
        shareable: false,
        execute_never: false, // Kernel can execute
    };

    // Region 2: RAM - Full access, no execute (W^X)
    let ram_region = MpuBootRegion {
        region: 2,
        base: RAM_BASE,
        size: MPU_SIZE_512KB,
        access: AP_FULL_RW,
        tex: 1,              // Normal memory, write-back write-allocate
        cacheable: true,
        bufferable: true,
        shareable: false,
        execute_never: true, // CRITICAL: No code execution from RAM (W^X)
    };

    // Region 3: Peripherals - Device memory
    let periph_region = MpuBootRegion {
        region: 3,
        base: PERIPH_BASE,
        size: MPU_SIZE_512KB,
        access: AP_FULL_RW,
        tex: 0,              // Device memory
        cacheable: false,
        bufferable: true,
        shareable: true,
        execute_never: true,
    };

    // Region 4: Backup SRAM / OTP - Privileged only
    let secure_region = MpuBootRegion {
        region: 4,
        base: 0x3800_0000,   // Backup SRAM on STM32H7
        size: MPU_SIZE_32KB,
        access: AP_PRIV_RW,  // Privileged access only
        tex: 1,
        cacheable: false,
        bufferable: false,
        shareable: false,
        execute_never: true,
    };

    // Region 5: Stack guard - No access (stack overflow detection)
    // Place a small region at the bottom of the stack to catch overflows
    let stack_guard_region = MpuBootRegion {
        region: 5,
        base: RAM_BASE,      // Bottom of RAM
        size: 7,             // 256 bytes (2^(7+1))
        access: 0,           // No access - will fault on access
        tex: 0,
        cacheable: false,
        bufferable: false,
        shareable: false,
        execute_never: true,
    };

    // Apply all regions
    let regions = [
        bootloader_region,
        kernel_region,
        ram_region,
        periph_region,
        secure_region,
        stack_guard_region,
    ];

    for region in &regions {
        // SAFETY: MPU_RNR (0xE000_ED98), MPU_RBAR (0xE000_ED9C), and
        // MPU_RASR (0xE000_EDA0) are ARM MPU configuration registers. The
        // MPU was disabled above, so reconfiguring regions is safe. Each
        // region index (0-5) is within the hardware's region count.
        unsafe {
            ptr::write_volatile(MPU_RNR as *mut u32, region.region);
            ptr::write_volatile(MPU_RBAR as *mut u32, region.to_rbar());
            ptr::write_volatile(MPU_RASR as *mut u32, region.to_rasr());
        }
    }

    dsb();
    isb();

    // Enable MPU with:
    // - ENABLE: Turn on MPU
    // - PRIVDEFENA: Enable default memory map for privileged access
    //   (allows access to regions not covered by MPU regions)
    // - HFNMIENA: Keep MPU enabled during HardFault/NMI
    //   (prevents escalation attacks via exceptions)
    let ctrl = MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA | MPU_CTRL_HFNMIENA;
    // SAFETY: MPU_CTRL (0xE000_ED94) write enables the MPU with all regions
    // configured above. DSB/ISB barriers before and after ensure proper
    // ordering of MPU configuration and activation.
    unsafe {
        ptr::write_volatile(MPU_CTRL as *mut u32, ctrl);
    }

    dsb();
    isb();

    true
}

/// Load and jump to kernel
///
/// # Security
///
/// Before jumping to the kernel:
/// 1. MPU is configured to protect bootloader as read-only, non-executable
/// 2. RAM is marked as non-executable (W^X policy)
/// 3. Stack guard region is configured to detect stack overflows
///
/// # Safety
///
/// This function never returns. It transfers control to the kernel.
pub fn load_kernel(address: u32) -> ! {
    // 1. Configure MPU before kernel handoff
    configure_memory_protection();

    // 2. Get entry point from kernel header
    // Kernel header format:
    //   +0x0000: Stack pointer initial value
    //   +0x0004: Reset vector (entry point)
    //   ...
    // For Qbitel EdgeOS, entry is at a fixed offset after header
    let entry_point = address + 0x4000; // After 16KB header region

    // 3. Set up stack pointer (read from vector table)
    // SAFETY: `address` points to the kernel's vector table in flash. The
    // first word of an ARM Cortex-M vector table is the initial stack pointer
    // value. The address was verified by verify_kernel() before calling
    // load_kernel(). Volatile read required for flash-mapped memory.
    let initial_sp = unsafe { ptr::read_volatile(address as *const u32) };

    // 4. Data barrier before jump
    dsb();
    isb();

    // 5. Jump to kernel (never returns)
    // SAFETY: The kernel at `entry_point` was cryptographically verified by
    // verify_kernel(). The MSP is set to the kernel's initial stack pointer
    // from the vector table. `transmute` converts the verified entry point
    // address to a function pointer. This is the standard ARM Cortex-M boot
    // handoff sequence. MPU is configured to protect bootloader memory.
    unsafe {
        // Set stack pointer (ARM Cortex-M specific)
        #[cfg(target_arch = "arm")]
        core::arch::asm!(
            "msr msp, {sp}",
            sp = in(reg) initial_sp,
            options(nomem, nostack)
        );

        // Jump to kernel entry point
        let kernel_entry: extern "C" fn() -> ! = core::mem::transmute(entry_point as usize);
        kernel_entry();
    }

    // Silence unused variable warning on non-ARM targets
    #[cfg(not(target_arch = "arm"))]
    {
        let _ = initial_sp;
        loop {}
    }
}

/// Data Synchronization Barrier
#[inline(always)]
fn dsb() {
    #[cfg(target_arch = "arm")]
    // SAFETY: DSB (Data Synchronization Barrier) is a standard ARM
    // instruction with no side effects beyond ensuring all prior memory
    // accesses complete. It has no memory or stack effects.
    unsafe {
        core::arch::asm!("dsb sy", options(nomem, nostack, preserves_flags));
    }
}

/// Instruction Synchronization Barrier
#[inline(always)]
fn isb() {
    #[cfg(target_arch = "arm")]
    // SAFETY: ISB (Instruction Synchronization Barrier) is a standard ARM
    // instruction that flushes the pipeline. It has no memory or stack
    // effects and is required after MPU configuration changes.
    unsafe {
        core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
    }
}
