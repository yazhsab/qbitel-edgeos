// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32U5 Flash Driver with TrustZone Support
//!
//! Provides secure and non-secure flash access for STM32U5 series.

use crate::error::{HalError, HalResult};
use crate::traits::FlashInterface;

/// Flash page size (8KB for STM32U5)
pub const PAGE_SIZE: usize = 8192;

/// Total flash size (2MB)
pub const TOTAL_SIZE: usize = 2 * 1024 * 1024;

/// Flash base address (non-secure alias)
pub const FLASH_BASE_NS: u32 = 0x0800_0000;

/// Flash base address (secure alias)
pub const FLASH_BASE_S: u32 = 0x0C00_0000;

/// STM32U5 Flash driver
pub struct Stm32u5Flash {
    /// Use secure alias
    secure: bool,
    /// Initialization state
    initialized: bool,
}

impl Stm32u5Flash {
    /// Create a new flash driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            secure: false,
            initialized: false,
        }
    }

    /// Create a new flash driver using secure alias
    #[must_use]
    pub const fn new_secure() -> Self {
        Self {
            secure: true,
            initialized: false,
        }
    }

    /// Get base address based on security mode
    fn base_address(&self) -> u32 {
        if self.secure {
            FLASH_BASE_S
        } else {
            FLASH_BASE_NS
        }
    }
}

impl FlashInterface for Stm32u5Flash {
    const PAGE_SIZE: usize = PAGE_SIZE;
    const TOTAL_SIZE: usize = TOTAL_SIZE;
    const BASE_ADDRESS: u32 = FLASH_BASE_NS;

    fn init(&mut self) -> HalResult<()> {
        self.initialized = true;
        Ok(())
    }

    fn read(&self, address: u32, buffer: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let base = self.base_address();
        if address < base || address + buffer.len() as u32 > base + TOTAL_SIZE as u32 {
            return Err(HalError::FlashOutOfBounds);
        }

        // SAFETY: The address is validated above to be within the flash memory region
        // (base to base + TOTAL_SIZE). The source pointer is derived from a valid
        // flash-mapped address, and the buffer length is checked to not exceed the
        // flash boundary. Flash memory is always readable via its memory-mapped alias.
        unsafe {
            let src = address as *const u8;
            core::ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), buffer.len());
        }

        Ok(())
    }

    fn write(&mut self, address: u32, data: &[u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        // STM32U5 flash write is done in 128-bit (16-byte) quad-words
        #[cfg(target_arch = "arm")]
        {
            use core::ptr;

            const FLASH_BASE: u32 = 0x4002_2000;
            const FLASH_NSCR: u32 = FLASH_BASE + 0x20;  // Non-secure control register
            const FLASH_NSSR: u32 = FLASH_BASE + 0x24;   // Non-secure status register
            const FLASH_CR_PG: u32 = 1 << 0;             // Programming enable
            const FLASH_SR_BSY: u32 = 1 << 16;           // Busy flag
            const FLASH_SR_EOP: u32 = 1 << 0;            // End of operation

            // SAFETY: Flash controller MMIO registers are architecturally defined for STM32U5.
            // Volatile accesses required. The programming sequence follows the reference manual.
            unsafe {
                // Wait for flash not busy
                while ptr::read_volatile(FLASH_NSSR as *const u32) & FLASH_SR_BSY != 0 {
                    core::hint::spin_loop();
                }

                // Set PG bit to enable programming
                let cr = ptr::read_volatile(FLASH_NSCR as *const u32);
                ptr::write_volatile(FLASH_NSCR as *mut u32, cr | FLASH_CR_PG);

                // Write data in 16-byte aligned chunks (quad-word programming)
                let mut offset = 0u32;
                while (offset as usize) < data.len() {
                    let dest = (address + offset) as *mut u32;
                    let remaining = data.len() - offset as usize;
                    let chunk_size = remaining.min(16);

                    // Pad to 16 bytes with 0xFF (erased state)
                    let mut quad_word = [0xFFu8; 16];
                    quad_word[..chunk_size].copy_from_slice(&data[offset as usize..offset as usize + chunk_size]);

                    // Write 4 words (128 bits)
                    for i in 0..4 {
                        let word = u32::from_le_bytes([
                            quad_word[i * 4],
                            quad_word[i * 4 + 1],
                            quad_word[i * 4 + 2],
                            quad_word[i * 4 + 3],
                        ]);
                        ptr::write_volatile(dest.add(i), word);
                    }

                    // Wait for completion
                    while ptr::read_volatile(FLASH_NSSR as *const u32) & FLASH_SR_BSY != 0 {
                        core::hint::spin_loop();
                    }

                    // Clear EOP flag
                    ptr::write_volatile(FLASH_NSSR as *mut u32, FLASH_SR_EOP);

                    offset += 16;
                }

                // Clear PG bit
                let cr = ptr::read_volatile(FLASH_NSCR as *const u32);
                ptr::write_volatile(FLASH_NSCR as *mut u32, cr & !FLASH_CR_PG);
            }
        }

        Ok(())
    }

    fn erase_page(&mut self, address: u32) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        #[cfg(target_arch = "arm")]
        {
            use core::ptr;

            const FLASH_BASE: u32 = 0x4002_2000;
            const FLASH_NSCR: u32 = FLASH_BASE + 0x20;
            const FLASH_NSSR: u32 = FLASH_BASE + 0x24;
            const FLASH_CR_PER: u32 = 1 << 1;            // Page erase
            const FLASH_CR_STRT: u32 = 1 << 16;          // Start erase
            const FLASH_SR_BSY: u32 = 1 << 16;
            const FLASH_SR_EOP: u32 = 1 << 0;
            const PAGE_SIZE: u32 = 8 * 1024;             // STM32U5 page = 8KB

            let page_number = (address - 0x0800_0000) / PAGE_SIZE;

            // SAFETY: Flash controller MMIO registers for STM32U5 page erase sequence.
            // The page number is derived from the address and shifted into the PNB field.
            unsafe {
                // Wait for not busy
                while ptr::read_volatile(FLASH_NSSR as *const u32) & FLASH_SR_BSY != 0 {
                    core::hint::spin_loop();
                }

                // Set PER bit and page number (PNB in bits 3..10)
                let cr = ptr::read_volatile(FLASH_NSCR as *const u32);
                let cr = (cr & !(0xFF << 3)) | FLASH_CR_PER | ((page_number & 0xFF) << 3);
                ptr::write_volatile(FLASH_NSCR as *mut u32, cr);

                // Start erase
                ptr::write_volatile(FLASH_NSCR as *mut u32, cr | FLASH_CR_STRT);

                // Wait for completion
                while ptr::read_volatile(FLASH_NSSR as *const u32) & FLASH_SR_BSY != 0 {
                    core::hint::spin_loop();
                }

                // Clear EOP and PER
                ptr::write_volatile(FLASH_NSSR as *mut u32, FLASH_SR_EOP);
                let cr = ptr::read_volatile(FLASH_NSCR as *const u32);
                ptr::write_volatile(FLASH_NSCR as *mut u32, cr & !FLASH_CR_PER);
            }
        }

        Ok(())
    }

    fn lock(&mut self) -> HalResult<()> {
        Ok(())
    }

    fn unlock(&mut self) -> HalResult<()> {
        Ok(())
    }

    fn is_locked(&self) -> bool {
        false
    }
}

impl Default for Stm32u5Flash {
    fn default() -> Self {
        Self::new()
    }
}
