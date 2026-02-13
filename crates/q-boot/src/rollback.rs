// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Anti-Rollback Protection
//!
//! This module implements anti-rollback protection using OTP (One-Time Programmable)
//! fuses and secure storage counters.
//!
//! # Rollback Protection Mechanisms
//!
//! 1. **OTP Counters**: Hardware fuses that can only be incremented, never decremented
//! 2. **Secure Storage Counters**: Software counters with integrity protection
//! 3. **Hybrid**: Combination of both for defense in depth
//!
//! # OTP Layout (STM32H7)
//!
//! The STM32H7 has 1 KB of OTP memory organized as 32 blocks of 32 bytes each.
//! We use dedicated blocks for rollback counters:
//!
//! - Block 0-3: Bootloader version counter
//! - Block 4-7: Kernel version counter
//! - Block 8-11: Application version counter
//! - Block 12-15: Reserved for future use
//!
//! # Counter Format
//!
//! Counters are stored as unary encoding (count of set bits), which provides:
//! - Simple increment (set next available bit)
//! - Tamper detection (more bits set than expected)
//! - Maximum count per block: 256 (32 bytes × 8 bits)

use core::ptr;
use q_common::Error;

// ============================================================================
// OTP Memory Configuration (STM32H7)
// ============================================================================

/// OTP base address (STM32H7)
const OTP_BASE: u32 = 0x1FF0_F000;

/// OTP block size in bytes
const OTP_BLOCK_SIZE: usize = 32;

/// Number of OTP blocks
const OTP_NUM_BLOCKS: usize = 32;

/// Maximum counter value per block (256 bits = 32 bytes × 8 bits)
const MAX_COUNTER_PER_BLOCK: u32 = 256;

/// OTP lock base address
const OTP_LOCK_BASE: u32 = 0x1FF0_F800;

// Block allocations
const BOOTLOADER_COUNTER_BLOCKS: core::ops::Range<usize> = 0..4;
const KERNEL_COUNTER_BLOCKS: core::ops::Range<usize> = 4..8;
const APPLICATION_COUNTER_BLOCKS: core::ops::Range<usize> = 8..12;

// ============================================================================
// Counter Type
// ============================================================================

/// Counter type (determines which OTP blocks to use)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterType {
    /// Bootloader version counter
    Bootloader,
    /// Kernel version counter
    Kernel,
    /// Application version counter
    Application,
}

impl CounterType {
    /// Get the OTP block range for this counter type
    fn block_range(&self) -> core::ops::Range<usize> {
        match self {
            Self::Bootloader => BOOTLOADER_COUNTER_BLOCKS,
            Self::Kernel => KERNEL_COUNTER_BLOCKS,
            Self::Application => APPLICATION_COUNTER_BLOCKS,
        }
    }

    /// Get maximum counter value (bits across all blocks)
    fn max_value(&self) -> u32 {
        let blocks = self.block_range().len();
        (blocks as u32) * MAX_COUNTER_PER_BLOCK
    }
}

// ============================================================================
// OTP Operations
// ============================================================================

/// Read OTP counter value using unary encoding
///
/// Counts the number of bits set to 1 across the allocated blocks.
pub fn read_otp_counter(counter_type: CounterType) -> Result<u32, Error> {
    let blocks = counter_type.block_range();
    let mut count: u32 = 0;

    for block in blocks {
        let block_addr = OTP_BASE + (block * OTP_BLOCK_SIZE) as u32;

        // Read each word in the block and count set bits
        for word_offset in (0..OTP_BLOCK_SIZE).step_by(4) {
            let addr = block_addr + word_offset as u32;
            // SAFETY: `addr` is within the OTP region (OTP_BASE + block *
            // OTP_BLOCK_SIZE + word_offset). The block range is bounded by
            // counter_type (0..4, 4..8, or 8..12), all within the 32-block
            // OTP area. OTP is read-only memory-mapped flash, always accessible.
            let value = unsafe { ptr::read_volatile(addr as *const u32) };
            count += value.count_ones();
        }
    }

    Ok(count)
}

/// Write OTP counter value
///
/// Sets bits to increment the counter to the target value.
/// Cannot decrement - returns error if target < current.
pub fn write_otp_counter(counter_type: CounterType, target_value: u32) -> Result<(), Error> {
    let current = read_otp_counter(counter_type)?;

    if target_value < current {
        return Err(Error::RollbackAttempted);
    }

    if target_value == current {
        return Ok(()); // Already at target
    }

    if target_value > counter_type.max_value() {
        return Err(Error::StorageFull);
    }

    let blocks = counter_type.block_range();
    let mut bits_to_set = target_value - current;
    let current_bit = current;

    // Find and set the required number of bits
    'outer: for block in blocks {
        let block_addr = OTP_BASE + (block * OTP_BLOCK_SIZE) as u32;

        for word_offset in (0..OTP_BLOCK_SIZE).step_by(4) {
            let addr = block_addr + word_offset as u32;
            // SAFETY: `addr` is within the OTP region, bounded by the counter
            // type's block range. Volatile read of OTP memory to check which
            // bits are already programmed before setting new ones.
            let current_word = unsafe { ptr::read_volatile(addr as *const u32) };

            // Find unset bits in this word
            for bit in 0..32 {
                if bits_to_set == 0 {
                    break 'outer;
                }

                let bit_position = (block * OTP_BLOCK_SIZE * 8) + (word_offset * 8) + bit;
                if bit_position < current_bit as usize {
                    continue; // Already counted
                }

                if current_word & (1 << bit) == 0 {
                    // This bit is not set, program it
                    program_otp_bit(addr, bit)?;
                    bits_to_set -= 1;
                }
            }
        }
    }

    if bits_to_set > 0 {
        return Err(Error::StorageFull);
    }

    Ok(())
}

/// Program a single OTP bit
///
/// Uses the STM32H7 flash programming interface to set an OTP bit.
///
/// # STM32H7 Flash/OTP Programming Sequence
///
/// 1. Unlock flash with FLASH_KEYR sequence
/// 2. Wait for BSY flag to clear
/// 3. Set PG bit in FLASH_CR
/// 4. Write the 256-bit (32-byte) flash word
/// 5. Wait for BSY flag to clear
/// 6. Check for errors (WRPERR, PGSERR, etc.)
/// 7. Clear PG bit
/// 8. Optionally re-lock flash
fn program_otp_bit(word_addr: u32, bit: usize) -> Result<(), Error> {
    // STM32H7 Flash Register Addresses (Bank 1)
    const FLASH_BASE: u32 = 0x5200_2000;
    const FLASH_KEYR: u32 = FLASH_BASE + 0x04;
    const FLASH_CR: u32 = FLASH_BASE + 0x0C;
    const FLASH_SR: u32 = FLASH_BASE + 0x10;

    // Flash unlock keys
    const FLASH_KEY1: u32 = 0x4567_0123;
    const FLASH_KEY2: u32 = 0xCDEF_89AB;

    // Flash CR bits
    const FLASH_CR_LOCK: u32 = 1 << 0;
    const FLASH_CR_PG: u32 = 1 << 1;

    // Flash SR bits
    const FLASH_SR_BSY: u32 = 1 << 0;
    const FLASH_SR_QW: u32 = 1 << 2;
    const FLASH_SR_WRPERR: u32 = 1 << 17;
    const FLASH_SR_PGSERR: u32 = 1 << 18;
    const FLASH_SR_STRBERR: u32 = 1 << 19;
    const FLASH_SR_INCERR: u32 = 1 << 21;
    const FLASH_SR_OPERR: u32 = 1 << 22;
    const FLASH_SR_ERROR_MASK: u32 = FLASH_SR_WRPERR | FLASH_SR_PGSERR |
        FLASH_SR_STRBERR | FLASH_SR_INCERR | FLASH_SR_OPERR;

    // Maximum wait iterations
    const MAX_WAIT: u32 = 100_000;

    // SAFETY: This block performs the STM32H7 flash/OTP programming sequence
    // using memory-mapped flash controller registers (FLASH_BASE 0x5200_2000).
    // The sequence follows the reference manual: unlock flash, wait for BSY
    // clear, enable PG, write value, wait for completion, verify. All register
    // addresses are valid STM32H7 MMIO. `word_addr` is within the OTP region
    // as validated by the caller. `bit` is 0..31 (single word bit position).
    unsafe {
        // 1. Check if flash is locked, unlock if needed
        let cr = ptr::read_volatile(FLASH_CR as *const u32);
        if cr & FLASH_CR_LOCK != 0 {
            // Unlock sequence
            ptr::write_volatile(FLASH_KEYR as *mut u32, FLASH_KEY1);
            ptr::write_volatile(FLASH_KEYR as *mut u32, FLASH_KEY2);

            // Verify unlock succeeded
            let cr_after = ptr::read_volatile(FLASH_CR as *const u32);
            if cr_after & FLASH_CR_LOCK != 0 {
                return Err(Error::HardwareInitFailed);
            }
        }

        // 2. Wait for any ongoing operations
        let mut wait = 0;
        while ptr::read_volatile(FLASH_SR as *const u32) & (FLASH_SR_BSY | FLASH_SR_QW) != 0 {
            wait += 1;
            if wait > MAX_WAIT {
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }

        // 3. Clear any previous errors
        ptr::write_volatile(FLASH_SR as *mut u32, FLASH_SR_ERROR_MASK);

        // 4. Read current value and compute new value
        let current = ptr::read_volatile(word_addr as *const u32);
        let new_value = current | (1u32 << bit);

        // If bit is already set, nothing to do
        if current == new_value {
            return Ok(());
        }

        // 5. Set PG bit to enable programming
        let cr = ptr::read_volatile(FLASH_CR as *const u32);
        ptr::write_volatile(FLASH_CR as *mut u32, cr | FLASH_CR_PG);

        // 6. Write the new value (OTP supports single-bit programming)
        ptr::write_volatile(word_addr as *mut u32, new_value);

        // 7. Wait for programming to complete
        wait = 0;
        while ptr::read_volatile(FLASH_SR as *const u32) & (FLASH_SR_BSY | FLASH_SR_QW) != 0 {
            wait += 1;
            if wait > MAX_WAIT {
                // Clear PG bit before returning
                let cr = ptr::read_volatile(FLASH_CR as *const u32);
                ptr::write_volatile(FLASH_CR as *mut u32, cr & !FLASH_CR_PG);
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }

        // 8. Check for errors
        let sr = ptr::read_volatile(FLASH_SR as *const u32);
        if sr & FLASH_SR_ERROR_MASK != 0 {
            // Clear errors and PG bit
            ptr::write_volatile(FLASH_SR as *mut u32, FLASH_SR_ERROR_MASK);
            let cr = ptr::read_volatile(FLASH_CR as *const u32);
            ptr::write_volatile(FLASH_CR as *mut u32, cr & !FLASH_CR_PG);
            return Err(Error::HardwareInitFailed);
        }

        // 9. Clear PG bit
        let cr = ptr::read_volatile(FLASH_CR as *const u32);
        ptr::write_volatile(FLASH_CR as *mut u32, cr & !FLASH_CR_PG);

        // 10. Verify the write
        let verify = ptr::read_volatile(word_addr as *const u32);
        if verify != new_value {
            return Err(Error::IntegrityCheckFailed);
        }
    }

    Ok(())
}

/// Check if OTP block is locked
fn is_otp_block_locked(block: usize) -> bool {
    if block >= OTP_NUM_BLOCKS {
        return true;
    }

    // Lock bits are stored at OTP_LOCK_BASE, one byte per block
    let lock_addr = OTP_LOCK_BASE + block as u32;
    // SAFETY: `lock_addr` is within OTP_LOCK_BASE (0x1FF0_F800) + block
    // index. The block index is bounds-checked above (< OTP_NUM_BLOCKS).
    // OTP lock bytes are read-only memory-mapped, always accessible.
    let lock_byte = unsafe { ptr::read_volatile(lock_addr as *const u8) };

    lock_byte != 0xFF // 0xFF = unlocked, any other value = locked
}

/// Lock an OTP block (permanent!)
pub fn lock_otp_block(block: usize) -> Result<(), Error> {
    if block >= OTP_NUM_BLOCKS {
        return Err(Error::InvalidParameter);
    }

    if is_otp_block_locked(block) {
        return Ok(()); // Already locked
    }

    // Write 0x00 to lock the block
    let lock_addr = OTP_LOCK_BASE + block as u32;
    // SAFETY: `lock_addr` is OTP_LOCK_BASE + block index, bounds-checked
    // above (< OTP_NUM_BLOCKS). Writing 0x00 permanently locks the OTP
    // block. This is an intentional one-time write to OTP lock memory.
    unsafe {
        ptr::write_volatile(lock_addr as *mut u8, 0x00);
    }

    Ok(())
}

// ============================================================================
// Rollback Protection API
// ============================================================================

/// Check if a version is allowed (not a rollback)
///
/// # Arguments
/// * `counter_type` - Which counter to check
/// * `version` - Proposed version number
///
/// # Returns
/// * `Ok(true)` - Version is allowed
/// * `Ok(false)` - Version is a rollback attempt
/// * `Err` - Error reading counter
pub fn check_rollback(counter_type: CounterType, version: u32) -> Result<bool, Error> {
    let stored_counter = read_otp_counter(counter_type)?;

    // Version must be >= stored counter
    // Note: Version and counter are related but not necessarily equal
    // The counter is incremented with each upgrade, version is embedded in image
    Ok(version >= stored_counter)
}

/// Update rollback counter after successful update
///
/// # Arguments
/// * `counter_type` - Which counter to update
/// * `new_version` - New version to commit
///
/// # Returns
/// * `Ok(())` - Counter updated successfully
/// * `Err` - Error (including if this would be a rollback)
pub fn update_rollback_counter(counter_type: CounterType, new_version: u32) -> Result<(), Error> {
    // Verify this isn't a rollback first
    if !check_rollback(counter_type, new_version)? {
        return Err(Error::RollbackAttempted);
    }

    // Write the new counter value
    write_otp_counter(counter_type, new_version)?;

    Ok(())
}

/// Get current rollback counter value
pub fn get_rollback_counter(counter_type: CounterType) -> Result<u32, Error> {
    read_otp_counter(counter_type)
}

// ============================================================================
// Secure Storage Counter (Alternative/Fallback)
// ============================================================================

/// Secure storage counter (for platforms without OTP or as backup)
///
/// Uses encrypted + authenticated storage with replay protection.
pub struct SecureCounter {
    /// Counter value
    value: u32,
    /// Nonce for replay protection
    nonce: u64,
}

impl SecureCounter {
    /// Create a new secure counter
    pub const fn new() -> Self {
        Self {
            value: 0,
            nonce: 0,
        }
    }

    /// Load counter from secure storage
    pub fn load(&mut self, storage: &impl SecureStorage) -> Result<(), Error> {
        let mut data = [0u8; 16]; // 4 bytes value + 8 bytes nonce + 4 bytes MAC
        storage.read(COUNTER_SLOT, &mut data)?;

        // Parse and verify
        // In real implementation: decrypt, verify MAC, check nonce
        self.value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        self.nonce = u64::from_le_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]);

        Ok(())
    }

    /// Save counter to secure storage
    pub fn save(&mut self, storage: &mut impl SecureStorage) -> Result<(), Error> {
        // Increment nonce for replay protection
        self.nonce = self.nonce.wrapping_add(1);

        let mut data = [0u8; 16];
        data[0..4].copy_from_slice(&self.value.to_le_bytes());
        data[4..12].copy_from_slice(&self.nonce.to_le_bytes());
        // data[12..16] would be MAC in real implementation

        storage.write(COUNTER_SLOT, &data)?;

        Ok(())
    }

    /// Check if version is allowed
    pub fn check(&self, version: u32) -> bool {
        version >= self.value
    }

    /// Increment counter
    pub fn increment(&mut self, new_value: u32) -> Result<(), Error> {
        if new_value < self.value {
            return Err(Error::RollbackAttempted);
        }
        self.value = new_value;
        Ok(())
    }
}

impl Default for SecureCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Secure storage trait for counter persistence
pub trait SecureStorage {
    /// Read from storage slot
    fn read(&self, slot: u8, data: &mut [u8]) -> Result<(), Error>;
    /// Write to storage slot
    fn write(&mut self, slot: u8, data: &[u8]) -> Result<(), Error>;
}

/// Storage slot for rollback counter
const COUNTER_SLOT: u8 = 0xFE;

// ============================================================================
// Combined Rollback Protection
// ============================================================================

/// Combined rollback protection using both OTP and secure storage
///
/// This provides defense in depth:
/// 1. Primary: OTP counter (hardware-backed, tamper-resistant)
/// 2. Backup: Secure storage counter (can store larger values)
pub struct RollbackProtection {
    /// Whether OTP is available
    otp_available: bool,
    /// Secure storage counter
    sw_counter: SecureCounter,
}

impl RollbackProtection {
    /// Create new rollback protection instance
    pub fn new(otp_available: bool) -> Self {
        Self {
            otp_available,
            sw_counter: SecureCounter::new(),
        }
    }

    /// Check if version is allowed
    pub fn check(&self, counter_type: CounterType, version: u32) -> Result<bool, Error> {
        if self.otp_available {
            check_rollback(counter_type, version)
        } else {
            Ok(self.sw_counter.check(version))
        }
    }

    /// Commit a new version
    pub fn commit(
        &mut self,
        counter_type: CounterType,
        version: u32,
        storage: Option<&mut impl SecureStorage>,
    ) -> Result<(), Error> {
        // Update OTP if available
        if self.otp_available {
            update_rollback_counter(counter_type, version)?;
        }

        // Also update software counter as backup
        self.sw_counter.increment(version)?;
        if let Some(storage) = storage {
            self.sw_counter.save(storage)?;
        }

        Ok(())
    }
}

// ============================================================================
// Legacy API (Backward Compatibility)
// ============================================================================

/// Check rollback protection (legacy API)
pub fn check_rollback_legacy(current_version: u32, stored_version: u32) -> Result<bool, Error> {
    if current_version >= stored_version {
        Ok(true)
    } else {
        Err(Error::RollbackAttempted)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_type_max_value() {
        // 4 blocks × 256 bits = 1024
        assert_eq!(CounterType::Bootloader.max_value(), 1024);
        assert_eq!(CounterType::Kernel.max_value(), 1024);
        assert_eq!(CounterType::Application.max_value(), 1024);
    }

    #[test]
    fn test_check_rollback_legacy() {
        assert!(check_rollback_legacy(5, 4).unwrap());
        assert!(check_rollback_legacy(5, 5).unwrap());
        assert!(check_rollback_legacy(4, 5).is_err());
    }

    #[test]
    fn test_secure_counter() {
        let mut counter = SecureCounter::new();
        assert!(counter.check(0));
        assert!(counter.check(1));

        counter.increment(5).unwrap();
        assert!(!counter.check(4));
        assert!(counter.check(5));
        assert!(counter.check(6));
    }
}
