// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 Flash Driver
//!
//! Production-quality flash driver for STM32H7 series microcontrollers.
//!
//! # Features
//!
//! - Dual-bank flash support (2 x 1MB)
//! - 128KB sector erase
//! - 256-bit (32-byte) write granularity
//! - ECC protection
//! - Option bytes management
//! - Proper error handling
//!
//! # STM32H7 Flash Characteristics
//!
//! - Total: 2MB (dual-bank, 1MB per bank)
//! - Sector size: 128KB (8 sectors per bank)
//! - Write: 256-bit (flash word)
//! - Read: ECC protected
//!
//! # Safety
//!
//! Flash operations modify volatile memory-mapped registers.
//! All operations are atomic where possible.

use crate::error::{HalError, HalResult};
use crate::traits::FlashInterface;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

// =============================================================================
// Flash Memory Map
// =============================================================================

/// Flash base address (Bank 1)
pub const FLASH_BASE_BANK1: u32 = 0x0800_0000;

/// Flash base address (Bank 2)
pub const FLASH_BASE_BANK2: u32 = 0x0810_0000;

/// Total flash base address
pub const FLASH_BASE: u32 = FLASH_BASE_BANK1;

/// Flash page/sector size (128KB)
pub const FLASH_PAGE_SIZE: usize = 128 * 1024;

/// Flash bank size (1MB)
pub const FLASH_BANK_SIZE: usize = 1024 * 1024;

/// Total flash size (2MB)
pub const FLASH_TOTAL_SIZE: usize = 2 * FLASH_BANK_SIZE;

/// Number of sectors per bank
pub const SECTORS_PER_BANK: usize = 8;

/// Write granularity (256 bits = 32 bytes)
pub const FLASH_WRITE_SIZE: usize = 32;

// =============================================================================
// Flash Register Definitions (STM32H7 RM0433)
// =============================================================================

/// Flash interface register base (Bank 1)
const FLASH_R_BASE_BANK1: u32 = 0x5200_2000;

/// Flash interface register base (Bank 2)
const FLASH_R_BASE_BANK2: u32 = 0x5200_2100;

// Register offsets — kept for completeness even if not all are currently used
#[allow(dead_code)]
const FLASH_ACR_OFFSET: u32 = 0x00;      // Access control register
const FLASH_KEYR_OFFSET: u32 = 0x04;     // Key register
#[allow(dead_code)]
const FLASH_OPTKEYR_OFFSET: u32 = 0x08;  // Option key register
const FLASH_CR_OFFSET: u32 = 0x0C;       // Control register
const FLASH_SR_OFFSET: u32 = 0x10;       // Status register
const FLASH_CCR_OFFSET: u32 = 0x14;      // Clear control register

// Flash unlock keys
const FLASH_KEY1: u32 = 0x4567_0123;
const FLASH_KEY2: u32 = 0xCDEF_89AB;

// Option bytes unlock keys
#[allow(dead_code)]
const FLASH_OPT_KEY1: u32 = 0x0819_2A3B;
#[allow(dead_code)]
const FLASH_OPT_KEY2: u32 = 0x4C5D_6E7F;

// Control register bits
const FLASH_CR_LOCK: u32 = 1 << 0;       // Lock
const FLASH_CR_PG: u32 = 1 << 1;         // Programming
const FLASH_CR_SER: u32 = 1 << 2;        // Sector erase
const FLASH_CR_BER: u32 = 1 << 3;        // Bank erase
const FLASH_CR_PSIZE_MASK: u32 = 0x3 << 4;  // Program size
const FLASH_CR_PSIZE_X64: u32 = 0x3 << 4;   // 64-bit parallelism
#[allow(dead_code)]
const FLASH_CR_FW: u32 = 1 << 6;         // Force write
const FLASH_CR_START: u32 = 1 << 7;      // Start
const FLASH_CR_SNB_MASK: u32 = 0x7 << 8; // Sector number
const FLASH_CR_SNB_SHIFT: u32 = 8;

// Status register bits
const FLASH_SR_BSY: u32 = 1 << 0;        // Busy
#[allow(dead_code)]
const FLASH_SR_WBNE: u32 = 1 << 1;       // Write buffer not empty
const FLASH_SR_QW: u32 = 1 << 2;         // Wait queue flag
#[allow(dead_code)]
const FLASH_SR_CRC_BUSY: u32 = 1 << 3;   // CRC busy
const FLASH_SR_EOP: u32 = 1 << 16;       // End of operation
const FLASH_SR_WRPERR: u32 = 1 << 17;    // Write protection error
const FLASH_SR_PGSERR: u32 = 1 << 18;    // Programming sequence error
const FLASH_SR_STRBERR: u32 = 1 << 19;   // Strobe error
const FLASH_SR_INCERR: u32 = 1 << 21;    // Inconsistency error
const FLASH_SR_OPERR: u32 = 1 << 22;     // Operation error
const FLASH_SR_RDPERR: u32 = 1 << 23;    // Read protection error
const FLASH_SR_RDSERR: u32 = 1 << 24;    // Read secure error
#[allow(dead_code)]
const FLASH_SR_SNECCERR: u32 = 1 << 25;  // Single ECC error
const FLASH_SR_DBECCERR: u32 = 1 << 26;  // Double ECC error

/// All error flags mask
const FLASH_SR_ERRORS: u32 = FLASH_SR_WRPERR | FLASH_SR_PGSERR | FLASH_SR_STRBERR
    | FLASH_SR_INCERR | FLASH_SR_OPERR | FLASH_SR_RDPERR | FLASH_SR_RDSERR
    | FLASH_SR_DBECCERR;

// Access control register bits
const FLASH_ACR_LATENCY_MASK: u32 = 0xF;
const FLASH_ACR_WRHIGHFREQ_MASK: u32 = 0x3 << 4;

// =============================================================================
// Flash Bank Register Access
// =============================================================================

/// Flash bank identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashBank {
    /// Bank 1 (0x0800_0000 - 0x080F_FFFF)
    Bank1,
    /// Bank 2 (0x0810_0000 - 0x081F_FFFF)
    Bank2,
}

impl FlashBank {
    /// Get register base for this bank
    #[must_use]
    const fn reg_base(self) -> u32 {
        match self {
            FlashBank::Bank1 => FLASH_R_BASE_BANK1,
            FlashBank::Bank2 => FLASH_R_BASE_BANK2,
        }
    }

    /// Get flash base address for this bank
    #[must_use]
    pub const fn flash_base(self) -> u32 {
        match self {
            FlashBank::Bank1 => FLASH_BASE_BANK1,
            FlashBank::Bank2 => FLASH_BASE_BANK2,
        }
    }

    /// Determine bank from address
    #[must_use]
    pub const fn from_address(address: u32) -> Option<Self> {
        if address >= FLASH_BASE_BANK1 && address < FLASH_BASE_BANK2 {
            Some(FlashBank::Bank1)
        } else if address >= FLASH_BASE_BANK2 && address < FLASH_BASE_BANK2 + FLASH_BANK_SIZE as u32 {
            Some(FlashBank::Bank2)
        } else {
            None
        }
    }
}

/// Flash bank register accessors
struct FlashRegs {
    base: u32,
}

impl FlashRegs {
    const fn new(bank: FlashBank) -> Self {
        Self { base: bank.reg_base() }
    }

    #[inline]
    unsafe fn read(&self, offset: u32) -> u32 {
        read_volatile((self.base + offset) as *const u32)
    }

    #[inline]
    unsafe fn write(&self, offset: u32, value: u32) {
        write_volatile((self.base + offset) as *mut u32, value);
    }

    #[inline]
    unsafe fn modify<F: FnOnce(u32) -> u32>(&self, offset: u32, f: F) {
        let val = self.read(offset);
        self.write(offset, f(val));
    }

    // Register accessors
    unsafe fn cr(&self) -> u32 { self.read(FLASH_CR_OFFSET) }
    unsafe fn set_cr(&self, val: u32) { self.write(FLASH_CR_OFFSET, val); }
    unsafe fn sr(&self) -> u32 { self.read(FLASH_SR_OFFSET) }
    unsafe fn set_ccr(&self, val: u32) { self.write(FLASH_CCR_OFFSET, val); }
    unsafe fn set_keyr(&self, val: u32) { self.write(FLASH_KEYR_OFFSET, val); }
}

// =============================================================================
// STM32H7 Flash Driver
// =============================================================================

/// STM32H7 Flash driver
///
/// Provides production-quality flash operations with proper error handling,
/// timeout protection, and dual-bank support.
pub struct Stm32h7Flash {
    /// Bank 1 locked state
    bank1_locked: bool,
    /// Bank 2 locked state
    bank2_locked: bool,
    /// Initialized state
    initialized: bool,
    /// Timeout in cycles (0 = no timeout)
    timeout_cycles: u32,
}

impl Stm32h7Flash {
    /// Default timeout (approximately 1 second at 480MHz)
    pub const DEFAULT_TIMEOUT: u32 = 480_000_000;

    /// Create a new flash driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bank1_locked: true,
            bank2_locked: true,
            initialized: false,
            timeout_cycles: Self::DEFAULT_TIMEOUT,
        }
    }

    /// Set operation timeout in CPU cycles
    pub fn set_timeout(&mut self, cycles: u32) {
        self.timeout_cycles = cycles;
    }

    /// Check if an address is within flash bounds
    #[must_use]
    pub const fn is_valid_address(address: u32) -> bool {
        address >= FLASH_BASE && address < FLASH_BASE + FLASH_TOTAL_SIZE as u32
    }

    /// Get the sector number for an address (0-7 within bank)
    #[must_use]
    pub const fn get_sector(address: u32) -> Option<u8> {
        if !Self::is_valid_address(address) {
            return None;
        }
        match FlashBank::from_address(address) {
            Some(bank) => {
                let offset = address - bank.flash_base();
                Some((offset / FLASH_PAGE_SIZE as u32) as u8)
            }
            None => None,
        }
    }

    /// Get the bank for an address
    #[must_use]
    pub const fn get_bank(address: u32) -> Option<FlashBank> {
        FlashBank::from_address(address)
    }

    /// Check if bank is locked
    fn is_bank_locked(&self, bank: FlashBank) -> bool {
        match bank {
            FlashBank::Bank1 => self.bank1_locked,
            FlashBank::Bank2 => self.bank2_locked,
        }
    }

    /// Set bank lock state
    fn set_bank_locked(&mut self, bank: FlashBank, locked: bool) {
        match bank {
            FlashBank::Bank1 => self.bank1_locked = locked,
            FlashBank::Bank2 => self.bank2_locked = locked,
        }
    }

    /// Wait for flash operation to complete
    fn wait_for_operation(&self, regs: &FlashRegs) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        loop {
            // SAFETY: Reading status register
            let sr = unsafe { regs.sr() };

            // Check for errors
            if sr & FLASH_SR_ERRORS != 0 {
                // SAFETY: Writing to CCR register to clear error flags
                unsafe { regs.set_ccr(FLASH_SR_ERRORS); }

                if sr & FLASH_SR_WRPERR != 0 {
                    return Err(HalError::FlashLocked);
                } else if sr & FLASH_SR_PGSERR != 0 {
                    return Err(HalError::FlashWriteFailed);
                } else if sr & FLASH_SR_DBECCERR != 0 {
                    // Double ECC error - data corrupted
                    return Err(HalError::FlashVerifyFailed);
                } else {
                    return Err(HalError::FlashError);
                }
            }

            // Check if operation complete
            if sr & (FLASH_SR_BSY | FLASH_SR_QW) == 0 {
                // Clear end of operation flag if set
                if sr & FLASH_SR_EOP != 0 {
                    // SAFETY: Writing to CCR register to clear end-of-operation flag
                    unsafe { regs.set_ccr(FLASH_SR_EOP); }
                }
                return Ok(());
            }

            // Timeout check
            if timeout > 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(HalError::Timeout);
                }
            }

            // Small delay to reduce bus contention
            core::hint::spin_loop();
        }
    }

    /// Clear all flash error flags
    fn clear_errors(&self, regs: &FlashRegs) {
        // SAFETY: Writing to CCR register to clear flags
        unsafe {
            regs.set_ccr(FLASH_SR_ERRORS | FLASH_SR_EOP);
        }
    }

    /// Unlock a flash bank
    fn unlock_bank(&mut self, bank: FlashBank) -> HalResult<()> {
        let regs = FlashRegs::new(bank);

        // SAFETY: Checking lock bit and writing unlock sequence
        unsafe {
            // Check if already unlocked
            if (regs.cr() & FLASH_CR_LOCK) == 0 {
                self.set_bank_locked(bank, false);
                return Ok(());
            }

            // Write unlock sequence
            regs.set_keyr(FLASH_KEY1);
            regs.set_keyr(FLASH_KEY2);

            // Memory barrier
            compiler_fence(Ordering::SeqCst);

            // Verify unlock succeeded
            if (regs.cr() & FLASH_CR_LOCK) != 0 {
                return Err(HalError::FlashLocked);
            }
        }

        self.set_bank_locked(bank, false);
        Ok(())
    }

    /// Lock a flash bank
    fn lock_bank(&mut self, bank: FlashBank) -> HalResult<()> {
        let regs = FlashRegs::new(bank);

        // SAFETY: Setting lock bit
        unsafe {
            regs.modify(FLASH_CR_OFFSET, |cr| cr | FLASH_CR_LOCK);
        }

        self.set_bank_locked(bank, true);
        Ok(())
    }

    /// Write a flash word (256 bits = 32 bytes)
    fn write_flash_word(&mut self, address: u32, data: &[u8; 32]) -> HalResult<()> {
        let bank = Self::get_bank(address).ok_or(HalError::FlashOutOfBounds)?;
        let regs = FlashRegs::new(bank);

        if self.is_bank_locked(bank) {
            return Err(HalError::FlashLocked);
        }

        // Check alignment
        if address % 32 != 0 {
            return Err(HalError::InvalidParameter);
        }

        // Wait for any pending operation
        self.wait_for_operation(&regs)?;

        // Clear errors and set programming mode
        self.clear_errors(&regs);

        // SAFETY: Programming flash
        unsafe {
            // Set PSIZE and enable programming
            let cr = (regs.cr() & !FLASH_CR_PSIZE_MASK) | FLASH_CR_PSIZE_X64 | FLASH_CR_PG;
            regs.set_cr(cr);

            // Memory barrier before writing
            compiler_fence(Ordering::SeqCst);

            // Write 32 bytes as 8 x 32-bit words
            // STM32H7 requires writing all 256 bits before operation completes
            let ptr = address as *mut u32;
            for i in 0..8 {
                let word = u32::from_le_bytes([
                    data[i * 4],
                    data[i * 4 + 1],
                    data[i * 4 + 2],
                    data[i * 4 + 3],
                ]);
                write_volatile(ptr.add(i), word);
            }

            // Memory barrier after writing
            compiler_fence(Ordering::SeqCst);
        }

        // Wait for operation to complete
        self.wait_for_operation(&regs)?;

        // SAFETY: Disable programming mode
        unsafe {
            regs.modify(FLASH_CR_OFFSET, |cr| cr & !FLASH_CR_PG);
        }

        Ok(())
    }

    /// Erase a sector
    fn erase_sector_internal(&mut self, bank: FlashBank, sector: u8) -> HalResult<()> {
        if sector >= SECTORS_PER_BANK as u8 {
            return Err(HalError::InvalidParameter);
        }

        let regs = FlashRegs::new(bank);

        if self.is_bank_locked(bank) {
            return Err(HalError::FlashLocked);
        }

        // Wait for any pending operation
        self.wait_for_operation(&regs)?;

        // Clear errors
        self.clear_errors(&regs);

        // SAFETY: Erasing sector
        unsafe {
            // Set up erase: select sector, enable sector erase
            let cr = (regs.cr() & !(FLASH_CR_PSIZE_MASK | FLASH_CR_SNB_MASK))
                | FLASH_CR_PSIZE_X64
                | FLASH_CR_SER
                | ((sector as u32) << FLASH_CR_SNB_SHIFT);
            regs.set_cr(cr);

            // Start erase
            regs.modify(FLASH_CR_OFFSET, |cr| cr | FLASH_CR_START);
        }

        // Wait for erase to complete (this can take several seconds)
        self.wait_for_operation(&regs)?;

        // SAFETY: Clear erase bits
        unsafe {
            regs.modify(FLASH_CR_OFFSET, |cr| cr & !(FLASH_CR_SER | FLASH_CR_SNB_MASK));
        }

        Ok(())
    }

    /// Verify erased (all 0xFF)
    fn verify_erased(&self, address: u32, size: usize) -> HalResult<bool> {
        // SAFETY: Reading from flash memory
        unsafe {
            let ptr = address as *const u8;
            for i in 0..size {
                if read_volatile(ptr.add(i)) != 0xFF {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Configure flash wait states for given CPU frequency
    pub fn configure_latency(&mut self, cpu_freq_hz: u32) -> HalResult<()> {
        // Wait states based on CPU frequency and VOS settings
        // Assuming VOS1 (1.15-1.26V, highest performance)
        let latency = match cpu_freq_hz {
            0..=70_000_000 => 0,
            70_000_001..=140_000_000 => 1,
            140_000_001..=185_000_000 => 2,
            185_000_001..=210_000_000 => 3,
            210_000_001..=225_000_000 => 4,
            225_000_001..=240_000_000 => 5,
            _ => 7, // Maximum latency
        };

        // WRHIGHFREQ setting based on frequency
        let wrhighfreq = match cpu_freq_hz {
            0..=185_000_000 => 0,
            185_000_001..=285_000_000 => 1,
            285_000_001..=400_000_000 => 2,
            _ => 3,
        };

        // SAFETY: Modifying flash ACR
        unsafe {
            let acr = read_volatile(FLASH_R_BASE_BANK1 as *const u32);
            let new_acr = (acr & !(FLASH_ACR_LATENCY_MASK | FLASH_ACR_WRHIGHFREQ_MASK))
                | latency
                | (wrhighfreq << 4);
            write_volatile(FLASH_R_BASE_BANK1 as *mut u32, new_acr);

            // Verify latency was set correctly
            let verify = read_volatile(FLASH_R_BASE_BANK1 as *const u32);
            if (verify & FLASH_ACR_LATENCY_MASK) != latency {
                return Err(HalError::FlashError);
            }
        }

        Ok(())
    }
}

impl Default for Stm32h7Flash {
    fn default() -> Self {
        Self::new()
    }
}

impl FlashInterface for Stm32h7Flash {
    const PAGE_SIZE: usize = FLASH_PAGE_SIZE;
    const TOTAL_SIZE: usize = FLASH_TOTAL_SIZE;
    const BASE_ADDRESS: u32 = FLASH_BASE;

    fn init(&mut self) -> HalResult<()> {
        if self.initialized {
            return Ok(());
        }

        // Clear any pending errors on both banks
        let regs1 = FlashRegs::new(FlashBank::Bank1);
        let regs2 = FlashRegs::new(FlashBank::Bank2);

        self.clear_errors(&regs1);
        self.clear_errors(&regs2);

        // Configure default latency for 480MHz operation
        // In a real system, this would be coordinated with clock configuration
        self.configure_latency(480_000_000)?;

        self.initialized = true;
        Ok(())
    }

    fn read(&self, address: u32, buffer: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if !Self::is_valid_address(address) {
            return Err(HalError::FlashOutOfBounds);
        }

        let end_address = address.saturating_add(buffer.len() as u32);
        if end_address > FLASH_BASE + FLASH_TOTAL_SIZE as u32 {
            return Err(HalError::FlashOutOfBounds);
        }

        // SAFETY: Reading from flash memory-mapped region
        unsafe {
            let src = address as *const u8;
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = read_volatile(src.add(i));
            }
        }

        Ok(())
    }

    fn write(&mut self, address: u32, data: &[u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if !Self::is_valid_address(address) {
            return Err(HalError::FlashOutOfBounds);
        }

        // Check alignment - must be 32-byte aligned
        if address % FLASH_WRITE_SIZE as u32 != 0 {
            return Err(HalError::InvalidParameter);
        }

        let end_address = address.saturating_add(data.len() as u32);
        if end_address > FLASH_BASE + FLASH_TOTAL_SIZE as u32 {
            return Err(HalError::FlashOutOfBounds);
        }

        // Write 32-byte flash words
        let mut offset = 0;
        while offset < data.len() {
            let mut word = [0xFFu8; 32];
            let chunk_size = (data.len() - offset).min(32);
            word[..chunk_size].copy_from_slice(&data[offset..offset + chunk_size]);

            self.write_flash_word(address + offset as u32, &word)?;
            offset += 32;
        }

        Ok(())
    }

    fn erase_page(&mut self, address: u32) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let bank = Self::get_bank(address).ok_or(HalError::FlashOutOfBounds)?;
        let sector = Self::get_sector(address).ok_or(HalError::FlashOutOfBounds)?;

        self.erase_sector_internal(bank, sector)?;

        // Verify sector is erased (optional, but recommended for security)
        let sector_start = bank.flash_base() + (sector as u32 * FLASH_PAGE_SIZE as u32);
        if !self.verify_erased(sector_start, FLASH_PAGE_SIZE)? {
            return Err(HalError::FlashEraseFailed);
        }

        Ok(())
    }

    fn lock(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        self.lock_bank(FlashBank::Bank1)?;
        self.lock_bank(FlashBank::Bank2)?;
        Ok(())
    }

    fn unlock(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        self.unlock_bank(FlashBank::Bank1)?;
        self.unlock_bank(FlashBank::Bank2)?;
        Ok(())
    }

    fn is_locked(&self) -> bool {
        self.bank1_locked && self.bank2_locked
    }
}

// =============================================================================
// Additional Flash Operations
// =============================================================================

impl Stm32h7Flash {
    /// Unlock only Bank 1
    pub fn unlock_bank1(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }
        self.unlock_bank(FlashBank::Bank1)
    }

    /// Unlock only Bank 2
    pub fn unlock_bank2(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }
        self.unlock_bank(FlashBank::Bank2)
    }

    /// Lock only Bank 1
    pub fn lock_bank1(&mut self) -> HalResult<()> {
        self.lock_bank(FlashBank::Bank1)
    }

    /// Lock only Bank 2
    pub fn lock_bank2(&mut self) -> HalResult<()> {
        self.lock_bank(FlashBank::Bank2)
    }

    /// Erase entire Bank 1 (mass erase)
    pub fn mass_erase_bank1(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if self.bank1_locked {
            return Err(HalError::FlashLocked);
        }

        let regs = FlashRegs::new(FlashBank::Bank1);

        self.wait_for_operation(&regs)?;
        self.clear_errors(&regs);

        // SAFETY: Mass erase Bank 1
        unsafe {
            let cr = (regs.cr() & !FLASH_CR_PSIZE_MASK) | FLASH_CR_PSIZE_X64 | FLASH_CR_BER;
            regs.set_cr(cr);
            regs.modify(FLASH_CR_OFFSET, |cr| cr | FLASH_CR_START);
        }

        self.wait_for_operation(&regs)?;

        // SAFETY: Clear bank erase bit
        unsafe {
            regs.modify(FLASH_CR_OFFSET, |cr| cr & !FLASH_CR_BER);
        }

        Ok(())
    }

    /// Erase entire Bank 2 (mass erase)
    pub fn mass_erase_bank2(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if self.bank2_locked {
            return Err(HalError::FlashLocked);
        }

        let regs = FlashRegs::new(FlashBank::Bank2);

        self.wait_for_operation(&regs)?;
        self.clear_errors(&regs);

        // SAFETY: Mass erase Bank 2
        unsafe {
            let cr = (regs.cr() & !FLASH_CR_PSIZE_MASK) | FLASH_CR_PSIZE_X64 | FLASH_CR_BER;
            regs.set_cr(cr);
            regs.modify(FLASH_CR_OFFSET, |cr| cr | FLASH_CR_START);
        }

        self.wait_for_operation(&regs)?;

        // SAFETY: Clear bank erase bit
        unsafe {
            regs.modify(FLASH_CR_OFFSET, |cr| cr & !FLASH_CR_BER);
        }

        Ok(())
    }

    /// Get sector address
    #[must_use]
    pub const fn get_sector_address(bank: FlashBank, sector: u8) -> u32 {
        bank.flash_base() + (sector as u32 * FLASH_PAGE_SIZE as u32)
    }

    /// Check if address is erased (reads as 0xFF)
    pub fn is_erased(&self, address: u32, size: usize) -> HalResult<bool> {
        self.verify_erased(address, size)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bank_from_address() {
        assert_eq!(FlashBank::from_address(0x0800_0000), Some(FlashBank::Bank1));
        assert_eq!(FlashBank::from_address(0x0808_0000), Some(FlashBank::Bank1));
        assert_eq!(FlashBank::from_address(0x080F_FFFF), Some(FlashBank::Bank1));
        assert_eq!(FlashBank::from_address(0x0810_0000), Some(FlashBank::Bank2));
        assert_eq!(FlashBank::from_address(0x081F_FFFF), Some(FlashBank::Bank2));
        assert_eq!(FlashBank::from_address(0x0820_0000), None);
        assert_eq!(FlashBank::from_address(0x0700_0000), None);
    }

    #[test]
    fn test_sector_from_address() {
        assert_eq!(Stm32h7Flash::get_sector(0x0800_0000), Some(0));
        assert_eq!(Stm32h7Flash::get_sector(0x0802_0000), Some(1));
        assert_eq!(Stm32h7Flash::get_sector(0x080E_0000), Some(7));
        assert_eq!(Stm32h7Flash::get_sector(0x0810_0000), Some(0)); // Bank 2, sector 0
        assert_eq!(Stm32h7Flash::get_sector(0x0700_0000), None);
    }

    #[test]
    fn test_is_valid_address() {
        assert!(Stm32h7Flash::is_valid_address(0x0800_0000));
        assert!(Stm32h7Flash::is_valid_address(0x081F_FFFF));
        assert!(!Stm32h7Flash::is_valid_address(0x0820_0000));
        assert!(!Stm32h7Flash::is_valid_address(0x0700_0000));
    }

    #[test]
    fn test_sector_address() {
        assert_eq!(Stm32h7Flash::get_sector_address(FlashBank::Bank1, 0), 0x0800_0000);
        assert_eq!(Stm32h7Flash::get_sector_address(FlashBank::Bank1, 1), 0x0802_0000);
        assert_eq!(Stm32h7Flash::get_sector_address(FlashBank::Bank2, 0), 0x0810_0000);
    }
}
