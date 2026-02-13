// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32U5 True Random Number Generator Driver
//!
//! Provides hardware random number generation for STM32U5 series.

use crate::error::{HalError, HalResult};
use crate::traits::RngInterface;

/// STM32U5 RNG driver
pub struct Stm32u5Rng {
    initialized: bool,
}

impl Stm32u5Rng {
    /// Create a new RNG driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: false,
        }
    }
}

impl RngInterface for Stm32u5Rng {
    fn init(&mut self) -> HalResult<()> {
        #[cfg(target_arch = "arm")]
        {
            use core::ptr;

            const RCC_AHB2ENR: u32 = 0x4002_1090;
            const RCC_AHB2ENR_RNGEN: u32 = 1 << 18;
            const RNG_BASE: u32 = 0x420C_0800;
            const RNG_CR: u32 = RNG_BASE + 0x00;
            const RNG_SR: u32 = RNG_BASE + 0x04;
            const RNG_CR_RNGEN: u32 = 1 << 2;
            const RNG_SR_DRDY: u32 = 1 << 0;

            // SAFETY: RCC and RNG peripheral MMIO registers for STM32U5.
            // Enables RNG clock, then enables RNG peripheral.
            unsafe {
                // Enable RNG clock
                let enr = ptr::read_volatile(RCC_AHB2ENR as *const u32);
                ptr::write_volatile(RCC_AHB2ENR as *mut u32, enr | RCC_AHB2ENR_RNGEN);

                // Enable RNG
                ptr::write_volatile(RNG_CR as *mut u32, RNG_CR_RNGEN);

                // Wait for first random number to be ready
                let mut timeout = 100_000u32;
                while ptr::read_volatile(RNG_SR as *const u32) & RNG_SR_DRDY == 0 {
                    timeout = timeout.saturating_sub(1);
                    if timeout == 0 {
                        return Err(HalError::InitFailed);
                    }
                    core::hint::spin_loop();
                }
            }
        }

        self.initialized = true;
        Ok(())
    }

    fn fill_bytes(&mut self, buffer: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        #[cfg(target_arch = "arm")]
        {
            use core::ptr;

            const RNG_BASE: u32 = 0x420C_0800;
            const RNG_SR: u32 = RNG_BASE + 0x04;
            const RNG_DR: u32 = RNG_BASE + 0x08;
            const RNG_SR_DRDY: u32 = 1 << 0;
            const RNG_SR_SECS: u32 = 1 << 2;
            const RNG_SR_CECS: u32 = 1 << 1;

            let mut offset = 0;
            while offset < buffer.len() {
                // SAFETY: RNG status and data registers. Wait for DRDY, check for errors,
                // then read the 32-bit random value.
                unsafe {
                    // Wait for data ready
                    let mut timeout = 100_000u32;
                    loop {
                        let sr = ptr::read_volatile(RNG_SR as *const u32);

                        // Check for errors
                        if sr & (RNG_SR_SECS | RNG_SR_CECS) != 0 {
                            return Err(HalError::RngError);
                        }

                        if sr & RNG_SR_DRDY != 0 {
                            break;
                        }

                        timeout = timeout.saturating_sub(1);
                        if timeout == 0 {
                            return Err(HalError::Timeout);
                        }
                        core::hint::spin_loop();
                    }

                    // Read random word
                    let random_word = ptr::read_volatile(RNG_DR as *const u32);
                    let bytes = random_word.to_le_bytes();

                    let remaining = buffer.len() - offset;
                    let to_copy = remaining.min(4);
                    buffer[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
                    offset += to_copy;
                }
            }
        }

        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.initialized
    }
}

impl Default for Stm32u5Rng {
    fn default() -> Self {
        Self::new()
    }
}
