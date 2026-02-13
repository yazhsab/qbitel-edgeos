// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 Secure Storage driver
//!
//! Provides access to OTP (One-Time Programmable) memory and
//! secure flash storage for key material.
//!
//! # OTP Memory Layout (STM32H7)
//!
//! The STM32H7 series has 1024 bytes (256 words) of OTP memory.
//! This memory can only be programmed once - bits can only change from 1 to 0.
//!
//! # Safety
//!
//! OTP writes are **permanent and irreversible**. Ensure data is correct before writing.

use crate::error::{HalError, HalResult};
use crate::traits::SecureStorageInterface;

/// OTP area size (1024 bytes on STM32H7)
pub const OTP_SIZE: usize = 1024;

/// Number of OTP words (256 x 32-bit)
pub const OTP_WORDS: usize = 256;

/// OTP base address (mapped in system memory)
pub const OTP_BASE: u32 = 0x1FF0_F000;

/// Maximum slot size (256 bytes per slot)
pub const MAX_SLOT_SIZE: usize = 256;

/// Number of storage slots
pub const NUM_SLOTS: usize = 4;

// =============================================================================
// STM32H7 Flash Register Definitions
// =============================================================================

/// Flash register base address (Bank 1)
#[cfg(target_arch = "arm")]
const FLASH_BASE: u32 = 0x5200_2000;

/// Flash Key Register offset
#[cfg(target_arch = "arm")]
const FLASH_KEYR_OFFSET: u32 = 0x04;

/// Flash Option Key Register offset
#[allow(dead_code)]
#[cfg(target_arch = "arm")]
const FLASH_OPTKEYR_OFFSET: u32 = 0x08;

/// Flash Control Register offset
#[cfg(target_arch = "arm")]
const FLASH_CR_OFFSET: u32 = 0x0C;

/// Flash Status Register offset
#[cfg(target_arch = "arm")]
const FLASH_SR_OFFSET: u32 = 0x10;

/// Flash unlock key 1
#[cfg(target_arch = "arm")]
const FLASH_KEY1: u32 = 0x4567_0123;

/// Flash unlock key 2
#[cfg(target_arch = "arm")]
const FLASH_KEY2: u32 = 0xCDEF_89AB;

/// Flash option unlock key 1
#[allow(dead_code)]
#[cfg(target_arch = "arm")]
const FLASH_OPT_KEY1: u32 = 0x0819_2A3B;

/// Flash option unlock key 2
#[allow(dead_code)]
#[cfg(target_arch = "arm")]
const FLASH_OPT_KEY2: u32 = 0x4C5D_6E7F;

// Flash CR register bits
#[cfg(target_arch = "arm")]
const FLASH_CR_LOCK: u32 = 1 << 0;
#[cfg(target_arch = "arm")]
const FLASH_CR_PG: u32 = 1 << 1;      // Programming enable
#[allow(dead_code)]
#[cfg(target_arch = "arm")]
const FLASH_CR_OPTLOCK: u32 = 1 << 30;

// Flash SR register bits
#[cfg(target_arch = "arm")]
const FLASH_SR_BSY: u32 = 1 << 0;     // Busy
#[cfg(target_arch = "arm")]
const FLASH_SR_QW: u32 = 1 << 2;      // Wait queue flag
#[cfg(target_arch = "arm")]
const FLASH_SR_WRPERR: u32 = 1 << 17; // Write protection error
#[cfg(target_arch = "arm")]
const FLASH_SR_PGSERR: u32 = 1 << 18; // Programming sequence error
#[cfg(target_arch = "arm")]
const FLASH_SR_EOP: u32 = 1 << 16;    // End of operation

/// Maximum wait iterations for flash operations
#[cfg(target_arch = "arm")]
const FLASH_TIMEOUT_ITERATIONS: u32 = 100_000;

/// Slot layout in OTP
#[derive(Debug, Clone, Copy)]
pub struct SlotLayout {
    /// Start offset in OTP
    pub offset: usize,
    /// Size in bytes
    pub size: usize,
}

/// Predefined slot layouts
pub const SLOT_LAYOUTS: [SlotLayout; NUM_SLOTS] = [
    SlotLayout { offset: 0, size: 256 },     // Slot 0: Identity commitment
    SlotLayout { offset: 256, size: 256 },   // Slot 1: Encrypted secrets
    SlotLayout { offset: 512, size: 128 },   // Slot 2: PUF helper data
    SlotLayout { offset: 640, size: 128 },   // Slot 3: Boot config
];

/// STM32H7 secure storage driver
pub struct Stm32h7SecureStorage {
    /// Initialized state
    initialized: bool,
    /// Simulated OTP memory (for development)
    #[cfg(not(target_arch = "arm"))]
    sim_otp: [u8; OTP_SIZE],
    /// Slot lock status
    slot_locks: [bool; NUM_SLOTS],
}

impl Stm32h7SecureStorage {
    /// Create a new secure storage driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: false,
            #[cfg(not(target_arch = "arm"))]
            sim_otp: [0xFF; OTP_SIZE], // OTP reads as 0xFF when not programmed
            slot_locks: [false; NUM_SLOTS],
        }
    }

    /// Get slot layout
    fn get_slot_layout(slot: u8) -> Option<SlotLayout> {
        if (slot as usize) < NUM_SLOTS {
            Some(SLOT_LAYOUTS[slot as usize])
        } else {
            None
        }
    }

    /// Read raw OTP data
    fn read_otp(&self, offset: usize, buffer: &mut [u8]) -> HalResult<()> {
        if offset + buffer.len() > OTP_SIZE {
            return Err(HalError::FlashOutOfBounds);
        }

        #[cfg(target_arch = "arm")]
        {
            // Read from actual OTP memory
            for (i, byte) in buffer.iter_mut().enumerate() {
                let addr = OTP_BASE + (offset + i) as u32;
                // SAFETY: OTP memory is mapped at OTP_BASE (0x1FF0_F000). The address is
                // within bounds (checked above). Volatile read required for memory-mapped OTP.
                *byte = unsafe { core::ptr::read_volatile(addr as *const u8) };
            }
        }

        #[cfg(not(target_arch = "arm"))]
        {
            // Simulated OTP for development
            buffer.copy_from_slice(&self.sim_otp[offset..offset + buffer.len()]);
        }

        Ok(())
    }

    /// Write raw OTP data (one-time operation!)
    ///
    /// # Safety
    ///
    /// This operation is **permanent and irreversible**. OTP bits can only
    /// transition from 1 to 0, never back. Verify data before calling.
    ///
    /// # STM32H7 OTP Programming Sequence
    ///
    /// 1. Wait for flash to be ready (BSY=0, QW=0)
    /// 2. Unlock flash with KEYR sequence
    /// 3. Enable programming (PG=1)
    /// 4. Write data as 256-bit (32-byte) aligned blocks
    /// 5. Wait for programming to complete
    /// 6. Verify written data
    /// 7. Lock flash
    fn write_otp(&mut self, offset: usize, data: &[u8]) -> HalResult<()> {
        if offset + data.len() > OTP_SIZE {
            return Err(HalError::FlashOutOfBounds);
        }

        // Verify OTP bits can only go from 1 to 0
        let mut verify_buf = [0u8; MAX_SLOT_SIZE];
        self.read_otp(offset, &mut verify_buf[..data.len()])?;
        for (i, &byte) in data.iter().enumerate() {
            let current = verify_buf[i];
            // Check if any bit would need to go from 0 to 1 (impossible in OTP)
            if (byte & !current) != 0 {
                return Err(HalError::FlashWriteFailed);
            }
        }

        #[cfg(target_arch = "arm")]
        {
            self.write_otp_hardware(offset, data)?;
        }

        #[cfg(not(target_arch = "arm"))]
        {
            // Simulated OTP - apply bit-level OTP semantics
            for (i, &byte) in data.iter().enumerate() {
                // OTP semantics: bits can only go 1->0, never 0->1
                self.sim_otp[offset + i] &= byte;
            }
        }

        // Verify write by reading back
        let mut read_back = [0u8; MAX_SLOT_SIZE];
        self.read_otp(offset, &mut read_back[..data.len()])?;
        if &read_back[..data.len()] != data {
            return Err(HalError::FlashWriteFailed);
        }

        Ok(())
    }

    /// Hardware OTP write implementation for STM32H7
    #[cfg(target_arch = "arm")]
    fn write_otp_hardware(&mut self, offset: usize, data: &[u8]) -> HalResult<()> {
        // Step 1: Wait for flash to be ready
        self.wait_flash_ready()?;

        // Step 2: Unlock flash
        self.unlock_flash()?;

        // Step 3: Enable programming
        let cr = (FLASH_BASE + FLASH_CR_OFFSET) as *mut u32;
        // SAFETY: Flash CR register is at an architecturally-defined address.
        // Volatile read-modify-write enables flash programming mode (PG bit).
        // Flash was unlocked in the previous step.
        unsafe {
            let val = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, val | FLASH_CR_PG);
        }

        // Step 4: Write data in 32-byte aligned blocks (STM32H7 flash word = 256 bits)
        // OTP can be written byte-by-byte but we align for efficiency
        let result = self.program_otp_bytes(offset, data);

        // Step 5: Disable programming and lock flash (always, even on error)
        // SAFETY: Flash CR register is at an architecturally-defined address.
        // Volatile read-modify-write disables flash programming mode for safety.
        unsafe {
            let val = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, val & !FLASH_CR_PG);
        }
        self.lock_flash();

        result
    }

    /// Wait for flash to be ready
    #[cfg(target_arch = "arm")]
    fn wait_flash_ready(&self) -> HalResult<()> {
        let sr = (FLASH_BASE + FLASH_SR_OFFSET) as *const u32;

        for _ in 0..FLASH_TIMEOUT_ITERATIONS {
            // SAFETY: Flash SR is an architecturally-defined read-only status register.
            // Volatile read required to poll flash busy and queue wait flags.
            let status = unsafe { core::ptr::read_volatile(sr) };
            if (status & (FLASH_SR_BSY | FLASH_SR_QW)) == 0 {
                return Ok(());
            }
            // Small delay - could use a proper delay mechanism
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        Err(HalError::FlashTimeout)
    }

    /// Unlock flash for programming
    #[cfg(target_arch = "arm")]
    fn unlock_flash(&self) -> HalResult<()> {
        let cr = (FLASH_BASE + FLASH_CR_OFFSET) as *const u32;
        let keyr = (FLASH_BASE + FLASH_KEYR_OFFSET) as *mut u32;

        // Check if already unlocked
        // SAFETY: Flash CR is an architecturally-defined register. Volatile read checks the lock bit.
        let cr_val = unsafe { core::ptr::read_volatile(cr) };
        if (cr_val & FLASH_CR_LOCK) == 0 {
            return Ok(());
        }

        // Unlock sequence: write KEY1 then KEY2
        // SAFETY: Flash KEYR is an architecturally-defined key register.
        // Volatile writes of the unlock sequence (KEY1 then KEY2) unlock flash for programming.
        unsafe {
            core::ptr::write_volatile(keyr, FLASH_KEY1);
            core::ptr::write_volatile(keyr, FLASH_KEY2);
        }

        // Verify unlock
        // SAFETY: Flash CR is an architecturally-defined register. Volatile read verifies
        // the lock bit was cleared by the unlock sequence.
        let cr_val = unsafe { core::ptr::read_volatile(cr) };
        if (cr_val & FLASH_CR_LOCK) != 0 {
            return Err(HalError::FlashLocked);
        }

        Ok(())
    }

    /// Lock flash after programming
    #[cfg(target_arch = "arm")]
    fn lock_flash(&self) {
        let cr = (FLASH_BASE + FLASH_CR_OFFSET) as *mut u32;
        // SAFETY: Flash CR is an architecturally-defined register. Volatile read-modify-write
        // sets the lock bit to re-lock flash after programming, preventing accidental writes.
        unsafe {
            let val = core::ptr::read_volatile(cr);
            core::ptr::write_volatile(cr, val | FLASH_CR_LOCK);
        }
    }

    /// Program bytes to OTP area
    #[cfg(target_arch = "arm")]
    fn program_otp_bytes(&self, offset: usize, data: &[u8]) -> HalResult<()> {
        let sr = (FLASH_BASE + FLASH_SR_OFFSET) as *mut u32;

        // Clear any pending errors
        // SAFETY: Flash SR is an architecturally-defined status register. Volatile write
        // clears error flags by writing 1 to the respective bits (rc_w1 semantics).
        unsafe {
            core::ptr::write_volatile(sr, FLASH_SR_WRPERR | FLASH_SR_PGSERR | FLASH_SR_EOP);
        }

        // STM32H7 flash must be programmed in 256-bit (32-byte) chunks
        // For OTP, we pad with 0xFF (no change) if data is not aligned
        let chunk_size = 32;
        let mut pos = 0;

        while pos < data.len() {
            // Calculate chunk boundaries
            let chunk_offset = offset + pos;
            let aligned_offset = (chunk_offset / chunk_size) * chunk_size;
            let offset_in_chunk = chunk_offset - aligned_offset;

            // Prepare 32-byte chunk (0xFF = no change for OTP)
            let mut chunk = [0xFFu8; 32];

            // Fill in the data bytes for this chunk
            let bytes_in_chunk = core::cmp::min(
                data.len() - pos,
                chunk_size - offset_in_chunk
            );
            chunk[offset_in_chunk..offset_in_chunk + bytes_in_chunk]
                .copy_from_slice(&data[pos..pos + bytes_in_chunk]);

            // Write the 32-byte chunk as 8 x 32-bit words
            let target_addr = OTP_BASE + aligned_offset as u32;
            for (i, word_bytes) in chunk.chunks(4).enumerate() {
                let word = u32::from_le_bytes([
                    word_bytes[0],
                    word_bytes[1],
                    word_bytes[2],
                    word_bytes[3],
                ]);
                let addr = (target_addr + (i * 4) as u32) as *mut u32;
                // SAFETY: OTP memory address is computed from OTP_BASE with validated bounds.
                // Volatile write programs one 32-bit word into the OTP flash region.
                // Flash programming mode was enabled in the calling function.
                unsafe {
                    core::ptr::write_volatile(addr, word);
                }
            }

            // Wait for this chunk to complete
            self.wait_flash_ready()?;

            // Check for errors
            // SAFETY: Flash SR is an architecturally-defined status register.
            // Volatile read checks for write protection or programming sequence errors.
            let status = unsafe { core::ptr::read_volatile(sr as *const u32) };
            if (status & (FLASH_SR_WRPERR | FLASH_SR_PGSERR)) != 0 {
                // Clear error flags
                // SAFETY: Flash SR is an architecturally-defined status register.
                // Volatile write clears error flags before returning the error.
                unsafe {
                    core::ptr::write_volatile(sr, FLASH_SR_WRPERR | FLASH_SR_PGSERR);
                }
                return Err(HalError::FlashWriteFailed);
            }

            pos += bytes_in_chunk;
        }

        Ok(())
    }
}

impl Default for Stm32h7SecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorageInterface for Stm32h7SecureStorage {
    const MAX_SLOT_SIZE: usize = MAX_SLOT_SIZE;
    const NUM_SLOTS: usize = NUM_SLOTS;

    fn init(&mut self) -> HalResult<()> {
        if self.initialized {
            return Ok(());
        }

        // In a real implementation:
        // 1. Enable flash peripheral
        // 2. Configure OTP access
        // 3. Read lock bits to determine slot status

        self.initialized = true;
        Ok(())
    }

    fn read(&self, slot: u8, buffer: &mut [u8]) -> HalResult<usize> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let layout = Self::get_slot_layout(slot).ok_or(HalError::InvalidParameter)?;

        if buffer.len() < layout.size {
            return Err(HalError::InvalidParameter);
        }

        self.read_otp(layout.offset, &mut buffer[..layout.size])?;

        Ok(layout.size)
    }

    fn write(&mut self, slot: u8, data: &[u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let layout = Self::get_slot_layout(slot).ok_or(HalError::InvalidParameter)?;

        if data.len() > layout.size {
            return Err(HalError::InvalidParameter);
        }

        if self.slot_locks[slot as usize] {
            return Err(HalError::SecureStorageLocked);
        }

        // Check if already written
        if self.is_slot_written(slot)? {
            return Err(HalError::SecureStorageError);
        }

        self.write_otp(layout.offset, data)?;

        Ok(())
    }

    fn is_slot_written(&self, slot: u8) -> HalResult<bool> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let layout = Self::get_slot_layout(slot).ok_or(HalError::InvalidParameter)?;

        let mut buffer = [0u8; 32];
        let check_len = layout.size.min(32);
        self.read_otp(layout.offset, &mut buffer[..check_len])?;

        // Check if any bytes are programmed (not 0xFF)
        Ok(buffer[..check_len].iter().any(|&b| b != 0xFF))
    }

    fn lock_slot(&mut self, slot: u8) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if (slot as usize) >= NUM_SLOTS {
            return Err(HalError::InvalidParameter);
        }

        // In a real implementation, this would program lock bits in OTP
        self.slot_locks[slot as usize] = true;
        Ok(())
    }

    fn is_slot_locked(&self, slot: u8) -> HalResult<bool> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if (slot as usize) >= NUM_SLOTS {
            return Err(HalError::InvalidParameter);
        }

        Ok(self.slot_locks[slot as usize])
    }

    fn read_uid(&self) -> HalResult<[u8; 16]> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        // STM32H7 has 96-bit unique ID at a specific address
        // UID base: 0x1FF1_E800 (12 bytes)
        #[cfg(target_arch = "arm")]
        let uid = {
            let mut buf = [0u8; 16];
            const UID_BASE: u32 = 0x1FF1_E800;
            for (i, byte) in buf[..12].iter_mut().enumerate() {
                // SAFETY: UID_BASE (0x1FF1_E800) is the architecturally-defined STM32H7 unique
                // device ID address. Volatile read retrieves the 96-bit factory-programmed UID.
                // Index i is bounded by the 12-byte slice iterator.
                *byte = unsafe { core::ptr::read_volatile((UID_BASE + i as u32) as *const u8) };
            }
            buf
        };

        #[cfg(not(target_arch = "arm"))]
        let uid: [u8; 16] = [
            // Simulated UID for development
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00,
        ];

        Ok(uid)
    }
}
