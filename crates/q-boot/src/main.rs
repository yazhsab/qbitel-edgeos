// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Secure Bootloader Entry Point
//!
//! This is the first code that runs on device power-on.
//! It establishes device identity and verifies the kernel before execution.
//!
//! # Boot Flow
//!
//! 1. Early hardware initialization (watchdog, clocks, caches)
//! 2. Initialize HAL
//! 3. Verify device identity against stored commitment
//! 4. Select active kernel slot (A/B partitioning)
//! 5. Verify kernel signature and integrity
//! 6. Configure MPU for kernel handoff
//! 7. Jump to kernel entry point
//!
//! # A/B Slot Selection
//!
//! The bootloader maintains boot state in backup SRAM:
//! - Active slot (A or B)
//! - Boot attempt counter
//! - Last successful boot slot
//!
//! On boot failure, the bootloader will:
//! 1. Increment boot attempt counter
//! 2. If attempts exceed threshold, try alternate slot
//! 3. Mark current slot as failed if verification fails

#![no_std]
#![no_main]

use core::ptr;
use q_boot::{verify_kernel, load_kernel};
use q_common::config::MemoryLayout;

// =============================================================================
// Boot State Management
// =============================================================================

/// Boot state stored in backup SRAM
/// This survives soft resets but not power cycles
#[repr(C)]
#[derive(Clone, Copy)]
struct BootState {
    /// Magic value to detect valid state
    magic: u32,
    /// Currently active slot (0 = A, 1 = B)
    active_slot: u8,
    /// Boot attempt counter for current slot
    boot_attempts: u8,
    /// Last known good slot
    last_good_slot: u8,
    /// Slot A status (0 = unknown, 1 = verified, 2 = failed)
    slot_a_status: u8,
    /// Slot B status
    slot_b_status: u8,
    /// Reserved for future use
    _reserved: [u8; 3],
    /// CRC32 of the above fields
    crc: u32,
}

const BOOT_STATE_MAGIC: u32 = 0x514F_4F54; // "QOOT"
const BOOT_STATE_ADDR: u32 = 0x3800_0000;  // Backup SRAM on STM32H7
const MAX_BOOT_ATTEMPTS: u8 = 3;

/// Slot status values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SlotStatus {
    Unknown = 0,
    Verified = 1,
    Failed = 2,
    Staged = 3,  // New firmware staged, not yet verified
}

impl From<u8> for SlotStatus {
    fn from(val: u8) -> Self {
        match val {
            1 => SlotStatus::Verified,
            2 => SlotStatus::Failed,
            3 => SlotStatus::Staged,
            _ => SlotStatus::Unknown,
        }
    }
}

/// Read boot state from backup SRAM
fn read_boot_state() -> Option<BootState> {
    // SAFETY: BOOT_STATE_ADDR (0x3800_0000) is the start of backup SRAM on
    // STM32H7, enabled by early_init(). The BootState struct is repr(C) and
    // fits within the SRAM region. Volatile read required because the data
    // persists across reboots and may change between power cycles.
    let state = unsafe {
        ptr::read_volatile(BOOT_STATE_ADDR as *const BootState)
    };

    // Verify magic
    if state.magic != BOOT_STATE_MAGIC {
        return None;
    }

    // Verify CRC
    let computed_crc = compute_boot_state_crc(&state);
    if state.crc != computed_crc {
        return None;
    }

    Some(state)
}

/// Write boot state to backup SRAM
fn write_boot_state(state: &mut BootState) {
    state.magic = BOOT_STATE_MAGIC;
    state.crc = compute_boot_state_crc(state);

    // SAFETY: BOOT_STATE_ADDR (0x3800_0000) is within backup SRAM, writable
    // after early_init() enables the backup domain. `state` is a valid
    // BootState with magic and CRC set. Volatile write ensures persistence.
    unsafe {
        ptr::write_volatile(BOOT_STATE_ADDR as *mut BootState, *state);
    }
}

/// Compute CRC32 of boot state (excluding CRC field)
fn compute_boot_state_crc(state: &BootState) -> u32 {
    // Simple CRC32 implementation
    // In production, use hardware CRC or proper polynomial
    // SAFETY: `state` is a valid BootState reference. The slice covers
    // size_of::<BootState>() - 4 bytes to exclude the trailing CRC field.
    // BootState is repr(C) so the layout is deterministic and the CRC field
    // is the last 4-byte member.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            state as *const BootState as *const u8,
            core::mem::size_of::<BootState>() - 4, // Exclude CRC field
        )
    };

    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Initialize boot state with defaults
fn init_boot_state() -> BootState {
    BootState {
        magic: BOOT_STATE_MAGIC,
        active_slot: 0,  // Start with slot A
        boot_attempts: 0,
        last_good_slot: 0,
        slot_a_status: SlotStatus::Unknown as u8,
        slot_b_status: SlotStatus::Unknown as u8,
        _reserved: [0; 3],
        crc: 0,
    }
}

/// Select the kernel slot to boot from
///
/// Returns (slot_address, slot_index) where slot_index is 0 for A, 1 for B
fn select_boot_slot(layout: &MemoryLayout, state: &mut BootState) -> (u32, u8) {
    // Increment boot attempts
    state.boot_attempts = state.boot_attempts.saturating_add(1);

    // Check if we've exceeded max attempts on current slot
    if state.boot_attempts > MAX_BOOT_ATTEMPTS {
        // Try the alternate slot
        let alternate = if state.active_slot == 0 { 1 } else { 0 };

        // Only switch if alternate slot is not marked as failed
        let alternate_status = if alternate == 0 {
            SlotStatus::from(state.slot_a_status)
        } else {
            SlotStatus::from(state.slot_b_status)
        };

        if alternate_status != SlotStatus::Failed {
            state.active_slot = alternate;
            state.boot_attempts = 1;
        }
        // If both slots are exhausted, continue with current slot
        // (will likely fail, but allows for recovery)
    }

    // Return address based on active slot
    let address = if state.active_slot == 0 {
        layout.kernel_a_start()
    } else {
        layout.kernel_b_start()
    };

    (address, state.active_slot)
}

/// Mark current boot as successful
/// Called by kernel after successful initialization
#[no_mangle]
pub extern "C" fn boot_success() {
    if let Some(mut state) = read_boot_state() {
        state.boot_attempts = 0;
        state.last_good_slot = state.active_slot;

        // Mark current slot as verified
        if state.active_slot == 0 {
            state.slot_a_status = SlotStatus::Verified as u8;
        } else {
            state.slot_b_status = SlotStatus::Verified as u8;
        }

        write_boot_state(&mut state);
    }
}

/// Mark a slot as failed
fn mark_slot_failed(state: &mut BootState, slot: u8) {
    if slot == 0 {
        state.slot_a_status = SlotStatus::Failed as u8;
    } else {
        state.slot_b_status = SlotStatus::Failed as u8;
    }
}

// =============================================================================
// Bootloader Entry Point
// =============================================================================

/// Bootloader entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Early hardware initialization
    early_init();

    // 2. Initialize HAL
    let mut hal = init_hal();

    // 3. Establish/verify identity
    if !verify_identity(&mut hal) {
        boot_failure(BootError::IdentityFailed);
    }

    // 4. Load or initialize boot state
    let mut boot_state = read_boot_state().unwrap_or_else(init_boot_state);

    // 5. Select kernel slot using A/B logic
    let layout = MemoryLayout::STM32H7;
    let (kernel_addr, slot_index) = select_boot_slot(&layout, &mut boot_state);

    // 6. Save updated boot state before verification
    write_boot_state(&mut boot_state);

    // 7. Verify kernel signature
    if !verify_kernel(kernel_addr) {
        // Mark slot as failed
        mark_slot_failed(&mut boot_state, slot_index);
        write_boot_state(&mut boot_state);

        // Try alternate slot if available
        let alternate_slot = if slot_index == 0 { 1 } else { 0 };
        let alternate_status = if alternate_slot == 0 {
            SlotStatus::from(boot_state.slot_a_status)
        } else {
            SlotStatus::from(boot_state.slot_b_status)
        };

        if alternate_status != SlotStatus::Failed {
            // Switch to alternate slot and retry
            boot_state.active_slot = alternate_slot;
            boot_state.boot_attempts = 1;
            write_boot_state(&mut boot_state);

            let alt_addr = if alternate_slot == 0 {
                layout.kernel_a_start()
            } else {
                layout.kernel_b_start()
            };

            if verify_kernel(alt_addr) {
                load_kernel(alt_addr);
            }
        }

        // Both slots failed - enter recovery mode
        boot_failure(BootError::KernelVerifyFailed);
    }

    // 8. Load and jump to kernel (MPU is configured inside load_kernel)
    load_kernel(kernel_addr);
}

/// Early hardware initialization (before HAL)
fn early_init() {
    // Feed watchdog if enabled
    #[cfg(target_arch = "arm")]
    {
        // Enable backup SRAM clock for boot state persistence
        // RCC->AHB4ENR |= RCC_AHB4ENR_BKPRAMEN
        const RCC_AHB4ENR: u32 = 0x5802_44E0;
        const RCC_AHB4ENR_BKPRAMEN: u32 = 1 << 28;
        // SAFETY: RCC_AHB4ENR (0x5802_44E0) is the AHB4 clock enable register
        // on STM32H7, always accessible in privileged mode at reset. We
        // read-modify-write to set BKPRAMEN without disturbing other enables.
        // Volatile MMIO access required for hardware registers.
        unsafe {
            let val = ptr::read_volatile(RCC_AHB4ENR as *const u32);
            ptr::write_volatile(RCC_AHB4ENR as *mut u32, val | RCC_AHB4ENR_BKPRAMEN);
        }

        // Small delay for backup SRAM to be accessible
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }

    // Set up basic clocks (use internal oscillator for safety)
    // Enable instruction and data caches
    // Configure flash wait states
}

/// Initialize HAL
///
/// Performs platform-specific hardware initialization:
/// - Clock tree configuration (HSE → PLL → SYSCLK)
/// - Flash wait states for target frequency
/// - Peripheral clock enables
/// - TRNG initialization
fn init_hal() -> HalInstance {
    #[cfg(all(target_arch = "arm", feature = "stm32h7"))]
    {
        // Initialize the STM32H7 HAL with default 480MHz clock config
        use q_hal::stm32h7::Stm32h7Hal;
        let mut hal = Stm32h7Hal::new();
        match hal.init() {
            Ok(()) => return HalInstance { inner: Some(hal) },
            Err(_) => {
                // HAL init failed — continue with internal oscillator
                // The watchdog will eventually reset us if kernel boot fails
            }
        }
    }

    // Fallback: no real HAL (host builds, unsupported platforms)
    HalInstance {
        #[cfg(all(target_arch = "arm", feature = "stm32h7"))]
        inner: None,
    }
}

/// Verify device identity
///
/// This function verifies that the device's hardware fingerprint matches
/// the stored identity commitment hash in OTP. This ensures:
/// 1. The device is provisioned with a valid identity
/// 2. The hardware has not been tampered with or replaced
/// 3. The firmware is running on the intended device
fn verify_identity(_hal: &mut HalInstance) -> bool {
    use q_boot::verify::EfuseFingerprintProvider;
    use q_boot::verify::PufProvider;
    use q_crypto::hash::Sha3_256;
    use q_crypto::traits::Hash;

    // 1. Get hardware fingerprint from eFUSE/device unique ID
    let efuse_provider = EfuseFingerprintProvider::from_device();
    let fingerprint = match efuse_provider.get_fingerprint() {
        Ok(fp) => fp,
        Err(_) => return false,
    };

    // 2. Read stored identity commitment hash from OTP/secure storage
    // OTP layout: identity commitment hash stored at OTP block 16-17
    const IDENTITY_OTP_BASE: u32 = 0x1FF0_F000 + (16 * 32); // Block 16

    let mut stored_commitment_hash = [0u8; 32];
    for (i, byte) in stored_commitment_hash.iter_mut().enumerate() {
        // SAFETY: IDENTITY_OTP_BASE (0x1FF0_F200, OTP block 16) is within
        // the STM32H7 OTP region. `i` ranges 0..31, reading 32 bytes total.
        // OTP is read-only memory-mapped flash, always accessible.
        *byte = unsafe { ptr::read_volatile((IDENTITY_OTP_BASE + i as u32) as *const u8) };
    }

    // 3. Check if identity is provisioned (not all zeros or all ones)
    let is_provisioned = !stored_commitment_hash.iter().all(|&b| b == 0x00)
        && !stored_commitment_hash.iter().all(|&b| b == 0xFF);

    if !is_provisioned {
        // Device not provisioned - allow boot in development mode
        #[cfg(feature = "development")]
        return true;

        // In production, fail if not provisioned
        #[cfg(not(feature = "development"))]
        return false;
    }

    // 4. Compute expected commitment hash from current hardware
    // commitment_hash = SHA3-256(domain_sep || fingerprint || device_class)
    const DOMAIN_SEP: &[u8] = b"Qbitel EdgeOS-IDENTITY-v1";
    const DEVICE_CLASS_EDGE: u8 = 0x01;

    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_SEP);
    hasher.update(&fingerprint);
    hasher.update(&[DEVICE_CLASS_EDGE]);
    let computed_hash = hasher.finalize();

    // 5. Constant-time comparison to prevent timing attacks
    let mut diff = 0u8;
    for (a, b) in stored_commitment_hash.iter().zip(computed_hash.as_ref().iter()) {
        diff |= a ^ b;
    }

    diff == 0
}

/// Boot failure handler
fn boot_failure(error: BootError) -> ! {
    // Log error code via GPIO LED pattern or UART
    let _code = match error {
        BootError::IdentityFailed => 1,
        BootError::KernelVerifyFailed => 2,
        BootError::HardwareInitFailed => 3,
        BootError::NoValidSlot => 4,
    };

    // In production:
    // - Blink LED with error pattern
    // - Log to persistent storage
    // - Reset after timeout (watchdog will handle this)
    // - Or enter recovery mode if available

    // For now, just halt
    loop {
        core::hint::spin_loop();
    }
}

/// HAL instance wrapping platform-specific driver
#[allow(dead_code)]
struct HalInstance {
    #[cfg(all(target_arch = "arm", feature = "stm32h7"))]
    inner: Option<q_hal::stm32h7::Stm32h7Hal>,
}

/// Boot error types
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
enum BootError {
    /// Identity verification failed
    IdentityFailed,
    /// Kernel verification failed
    KernelVerifyFailed,
    /// Hardware init failed
    HardwareInitFailed,
    /// No valid boot slot available
    NoValidSlot,
}

/// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // In debug mode, could log panic info
    // In release mode, just reset

    loop {
        core::hint::spin_loop();
    }
}

/// Trivial allocator for `no_std` binary
///
/// Some transitive dependencies (e.g., crypto crates) pull in `alloc` even
/// though the bootloader never calls `alloc::*` at runtime. Providing a
/// minimal `GlobalAlloc` that aborts satisfies the linker while guaranteeing
/// no heap allocation occurs.
mod alloc_shim {
    use core::alloc::{GlobalAlloc, Layout};

    struct Abort;

    unsafe impl GlobalAlloc for Abort {
        unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
            // No heap in the bootloader — abort immediately
            core::ptr::null_mut()
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: Abort = Abort;
}
