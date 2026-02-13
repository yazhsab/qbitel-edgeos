// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 I2C Driver
//!
//! Provides blocking I2C master communication for the STM32H7 series MCUs.
//! Supports I2C1-4 with configurable speed (standard 100 kHz, fast 400 kHz,
//! fast-mode plus 1 MHz).
//!
//! # STM32H7 I2C Features
//!
//! - Up to 1 Mbit/s (fast-mode plus)
//! - 7-bit and 10-bit addressing
//! - Hardware address matching
//! - DMA support (not implemented here — blocking only)
//! - Programmable timing (TIMINGR register)

use crate::error::{HalError, HalResult};
use core::ptr;

// ============================================================================
// I2C Register Offsets (STM32H7)
// ============================================================================

/// Control Register 1
const I2C_CR1_OFFSET: u32 = 0x00;
/// Control Register 2
const I2C_CR2_OFFSET: u32 = 0x04;
/// Timing Register
const I2C_TIMINGR_OFFSET: u32 = 0x10;
/// Interrupt and Status Register
const I2C_ISR_OFFSET: u32 = 0x18;
/// Interrupt Clear Register
const I2C_ICR_OFFSET: u32 = 0x1C;
/// Receive Data Register
const I2C_RXDR_OFFSET: u32 = 0x24;
/// Transmit Data Register
const I2C_TXDR_OFFSET: u32 = 0x28;

// ============================================================================
// CR1 bits
// ============================================================================

/// Peripheral enable
const CR1_PE: u32 = 1 << 0;

// ============================================================================
// CR2 bits
// ============================================================================

/// Start generation
const CR2_START: u32 = 1 << 13;
/// Stop generation
const CR2_STOP: u32 = 1 << 14;
/// Transfer direction (0=write, 1=read)
const CR2_RD_WRN: u32 = 1 << 10;
/// Auto-end mode
const CR2_AUTOEND: u32 = 1 << 25;
/// Slave address mask (bits 9:0)
const CR2_SADD_MASK: u32 = 0x3FF;
/// NBYTES mask (bits 23:16)
const CR2_NBYTES_SHIFT: u32 = 16;

// ============================================================================
// ISR bits
// ============================================================================

/// TX data register empty
const ISR_TXE: u32 = 1 << 0;
/// TX interrupt status
const ISR_TXIS: u32 = 1 << 1;
/// RX data register not empty
const ISR_RXNE: u32 = 1 << 2;
/// Transfer complete
const ISR_TC: u32 = 1 << 6;
/// Transfer complete reload
const ISR_TCR: u32 = 1 << 7;
/// Not acknowledge received
const ISR_NACKF: u32 = 1 << 4;
/// Bus error
const ISR_BERR: u32 = 1 << 8;
/// Arbitration lost
const ISR_ARLO: u32 = 1 << 9;
/// Bus busy
const ISR_BUSY: u32 = 1 << 15;

// ============================================================================
// ICR bits
// ============================================================================

/// Clear NACK flag
const ICR_NACKCF: u32 = 1 << 4;
/// Clear bus error
const ICR_BERRCF: u32 = 1 << 8;
/// Clear arbitration lost
const ICR_ARLOCF: u32 = 1 << 9;
/// Clear stop flag
const ICR_STOPCF: u32 = 1 << 5;

// ============================================================================
// RCC Clock Enable
// ============================================================================

/// RCC APB1LENR (I2C1, I2C2, I2C3)
const RCC_APB1LENR: u32 = 0x5802_4400 + 0xE8;
/// RCC APB4ENR (I2C4)
const RCC_APB4ENR: u32 = 0x5802_4400 + 0xF4;

/// Timeout for blocking operations
const I2C_TIMEOUT: u32 = 500_000;

// ============================================================================
// I2C Instance Definitions
// ============================================================================

/// I2C peripheral instance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cInstance {
    /// I2C1 (APB1)
    I2c1,
    /// I2C2 (APB1)
    I2c2,
    /// I2C3 (APB1)
    I2c3,
    /// I2C4 (APB4)
    I2c4,
}

impl I2cInstance {
    /// Get the base address
    const fn base_addr(&self) -> u32 {
        match self {
            Self::I2c1 => 0x4000_5400,
            Self::I2c2 => 0x4000_5800,
            Self::I2c3 => 0x4000_5C00,
            Self::I2c4 => 0x5800_1C00,
        }
    }

    /// Get the RCC enable register and bit
    const fn rcc_enable(&self) -> (u32, u32) {
        match self {
            Self::I2c1 => (RCC_APB1LENR, 1 << 21),
            Self::I2c2 => (RCC_APB1LENR, 1 << 22),
            Self::I2c3 => (RCC_APB1LENR, 1 << 23),
            Self::I2c4 => (RCC_APB4ENR, 1 << 7),
        }
    }
}

// ============================================================================
// I2C Speed Configuration
// ============================================================================

/// I2C speed mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    /// Standard mode (100 kHz)
    Standard,
    /// Fast mode (400 kHz)
    Fast,
    /// Fast-mode plus (1 MHz)
    FastPlus,
}

impl I2cSpeed {
    /// Get the TIMINGR value for this speed at 120 MHz APB clock.
    ///
    /// Pre-computed values from STM32CubeMX for the STM32H7 running
    /// APB1 at 120 MHz.
    const fn timingr(&self) -> u32 {
        match self {
            // PRESC=5, SCLDEL=4, SDADEL=2, SCLH=0xF3, SCLL=0xF7
            Self::Standard => 0x5042_F4F7,
            // PRESC=1, SCLDEL=3, SDADEL=2, SCLH=0x2B, SCLL=0x55
            Self::Fast => 0x1032_2B55,
            // PRESC=0, SCLDEL=2, SDADEL=0, SCLH=0x12, SCLL=0x26
            Self::FastPlus => 0x0020_1226,
        }
    }
}

/// I2C configuration
#[derive(Debug, Clone, Copy)]
pub struct I2cConfig {
    /// Bus speed
    pub speed: I2cSpeed,
}

impl Default for I2cConfig {
    fn default() -> Self {
        Self {
            speed: I2cSpeed::Standard,
        }
    }
}

// ============================================================================
// I2C Driver
// ============================================================================

/// STM32H7 I2C driver (master mode)
pub struct Stm32h7I2c {
    /// I2C instance
    instance: I2cInstance,
    /// Configuration
    config: I2cConfig,
    /// Whether the I2C is initialized
    initialized: bool,
}

impl Stm32h7I2c {
    /// Create a new I2C driver instance
    #[must_use]
    pub const fn new(instance: I2cInstance, config: I2cConfig) -> Self {
        Self {
            instance,
            config,
            initialized: false,
        }
    }

    /// Enable the I2C peripheral clock
    fn enable_clock(&self) {
        let (reg_addr, bit) = self.instance.rcc_enable();
        // SAFETY: RCC APBxENR register — volatile RMW.
        unsafe {
            let val = ptr::read_volatile(reg_addr as *const u32);
            ptr::write_volatile(reg_addr as *mut u32, val | bit);
            let _ = ptr::read_volatile(reg_addr as *const u32);
        }
    }

    /// Initialize the I2C peripheral
    pub fn init(&mut self) -> HalResult<()> {
        self.enable_clock();
        let base = self.instance.base_addr();

        // SAFETY: All writes target valid STM32H7 I2C MMIO registers.
        // I2C is disabled during configuration.
        unsafe {
            // Disable I2C during configuration
            ptr::write_volatile((base + I2C_CR1_OFFSET) as *mut u32, 0);

            // Set timing register
            ptr::write_volatile(
                (base + I2C_TIMINGR_OFFSET) as *mut u32,
                self.config.speed.timingr(),
            );

            // Enable I2C
            ptr::write_volatile((base + I2C_CR1_OFFSET) as *mut u32, CR1_PE);
        }

        self.initialized = true;
        Ok(())
    }

    /// Clear error flags
    fn clear_errors(&self) {
        let base = self.instance.base_addr();
        // SAFETY: Writing ICR clears sticky error flags.
        unsafe {
            ptr::write_volatile(
                (base + I2C_ICR_OFFSET) as *mut u32,
                ICR_NACKCF | ICR_BERRCF | ICR_ARLOCF | ICR_STOPCF,
            );
        }
    }

    /// Read the ISR register
    fn read_isr(&self) -> u32 {
        let base = self.instance.base_addr();
        // SAFETY: Read-only status register.
        unsafe { ptr::read_volatile((base + I2C_ISR_OFFSET) as *const u32) }
    }

    /// Check for and report I2C errors from ISR
    fn check_errors(&self) -> HalResult<()> {
        let isr = self.read_isr();
        if isr & ISR_NACKF != 0 {
            self.clear_errors();
            return Err(HalError::I2cError);
        }
        if isr & ISR_BERR != 0 {
            self.clear_errors();
            return Err(HalError::I2cError);
        }
        if isr & ISR_ARLO != 0 {
            self.clear_errors();
            return Err(HalError::I2cError);
        }
        Ok(())
    }

    /// Write data to a 7-bit address device (blocking)
    pub fn write(&mut self, addr: u8, data: &[u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }
        if data.is_empty() || data.len() > 255 {
            return Err(HalError::InvalidParameter);
        }

        let base = self.instance.base_addr();
        self.clear_errors();

        // SAFETY: Valid I2C MMIO register accesses for master write transfer.
        unsafe {
            // Configure transfer: 7-bit addr, write, NBYTES, AUTOEND, START
            let cr2 = ((addr as u32) << 1)
                | ((data.len() as u32) << CR2_NBYTES_SHIFT)
                | CR2_AUTOEND
                | CR2_START;
            ptr::write_volatile((base + I2C_CR2_OFFSET) as *mut u32, cr2);

            for &byte in data {
                // Wait for TXIS
                let mut timeout = I2C_TIMEOUT;
                loop {
                    self.check_errors()?;
                    if self.read_isr() & ISR_TXIS != 0 {
                        break;
                    }
                    timeout = timeout.saturating_sub(1);
                    if timeout == 0 {
                        return Err(HalError::Timeout);
                    }
                    core::hint::spin_loop();
                }

                // Write data byte
                ptr::write_volatile((base + I2C_TXDR_OFFSET) as *mut u32, byte as u32);
            }

            // Wait for STOP (AUTOEND generates it automatically)
            let mut timeout = I2C_TIMEOUT;
            while self.read_isr() & ISR_BUSY != 0 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::Timeout);
                }
                core::hint::spin_loop();
            }
        }

        self.clear_errors();
        Ok(())
    }

    /// Read data from a 7-bit address device (blocking)
    pub fn read(&mut self, addr: u8, buffer: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }
        if buffer.is_empty() || buffer.len() > 255 {
            return Err(HalError::InvalidParameter);
        }

        let base = self.instance.base_addr();
        self.clear_errors();

        // SAFETY: Valid I2C MMIO register accesses for master read transfer.
        unsafe {
            // Configure transfer: 7-bit addr, read, NBYTES, AUTOEND, START
            let cr2 = ((addr as u32) << 1)
                | CR2_RD_WRN
                | ((buffer.len() as u32) << CR2_NBYTES_SHIFT)
                | CR2_AUTOEND
                | CR2_START;
            ptr::write_volatile((base + I2C_CR2_OFFSET) as *mut u32, cr2);

            for slot in buffer.iter_mut() {
                // Wait for RXNE
                let mut timeout = I2C_TIMEOUT;
                loop {
                    self.check_errors()?;
                    if self.read_isr() & ISR_RXNE != 0 {
                        break;
                    }
                    timeout = timeout.saturating_sub(1);
                    if timeout == 0 {
                        return Err(HalError::Timeout);
                    }
                    core::hint::spin_loop();
                }

                // Read data byte
                *slot = ptr::read_volatile((base + I2C_RXDR_OFFSET) as *const u32) as u8;
            }

            // Wait for bus free
            let mut timeout = I2C_TIMEOUT;
            while self.read_isr() & ISR_BUSY != 0 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::Timeout);
                }
                core::hint::spin_loop();
            }
        }

        self.clear_errors();
        Ok(())
    }

    /// Write then read (write-restart-read) for register-based devices
    pub fn write_read(&mut self, addr: u8, write_data: &[u8], read_buffer: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }
        if write_data.is_empty() || write_data.len() > 255 {
            return Err(HalError::InvalidParameter);
        }
        if read_buffer.is_empty() || read_buffer.len() > 255 {
            return Err(HalError::InvalidParameter);
        }

        let base = self.instance.base_addr();
        self.clear_errors();

        // SAFETY: Valid I2C MMIO register accesses for master write-read transfer.
        unsafe {
            // Phase 1: Write (without AUTOEND, so we can restart)
            let cr2_write = ((addr as u32) << 1)
                | ((write_data.len() as u32) << CR2_NBYTES_SHIFT)
                | CR2_START;
            ptr::write_volatile((base + I2C_CR2_OFFSET) as *mut u32, cr2_write);

            for &byte in write_data {
                let mut timeout = I2C_TIMEOUT;
                loop {
                    self.check_errors()?;
                    if self.read_isr() & ISR_TXIS != 0 {
                        break;
                    }
                    timeout = timeout.saturating_sub(1);
                    if timeout == 0 {
                        return Err(HalError::Timeout);
                    }
                    core::hint::spin_loop();
                }
                ptr::write_volatile((base + I2C_TXDR_OFFSET) as *mut u32, byte as u32);
            }

            // Wait for transfer complete (TC)
            let mut timeout = I2C_TIMEOUT;
            while self.read_isr() & ISR_TC == 0 {
                self.check_errors()?;
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::Timeout);
                }
                core::hint::spin_loop();
            }

            // Phase 2: Repeated start + read (with AUTOEND)
            let cr2_read = ((addr as u32) << 1)
                | CR2_RD_WRN
                | ((read_buffer.len() as u32) << CR2_NBYTES_SHIFT)
                | CR2_AUTOEND
                | CR2_START;
            ptr::write_volatile((base + I2C_CR2_OFFSET) as *mut u32, cr2_read);

            for slot in read_buffer.iter_mut() {
                let mut timeout = I2C_TIMEOUT;
                loop {
                    self.check_errors()?;
                    if self.read_isr() & ISR_RXNE != 0 {
                        break;
                    }
                    timeout = timeout.saturating_sub(1);
                    if timeout == 0 {
                        return Err(HalError::Timeout);
                    }
                    core::hint::spin_loop();
                }
                *slot = ptr::read_volatile((base + I2C_RXDR_OFFSET) as *const u32) as u8;
            }

            // Wait for bus free
            let mut timeout = I2C_TIMEOUT;
            while self.read_isr() & ISR_BUSY != 0 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::Timeout);
                }
                core::hint::spin_loop();
            }
        }

        self.clear_errors();
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i2c_instance_addresses() {
        assert_eq!(I2cInstance::I2c1.base_addr(), 0x4000_5400);
        assert_eq!(I2cInstance::I2c2.base_addr(), 0x4000_5800);
        assert_eq!(I2cInstance::I2c3.base_addr(), 0x4000_5C00);
        assert_eq!(I2cInstance::I2c4.base_addr(), 0x5800_1C00);
    }

    #[test]
    fn test_i2c_default_config() {
        let config = I2cConfig::default();
        assert_eq!(config.speed, I2cSpeed::Standard);
    }

    #[test]
    fn test_i2c_timing_values() {
        // Ensure timing values are non-zero
        assert_ne!(I2cSpeed::Standard.timingr(), 0);
        assert_ne!(I2cSpeed::Fast.timingr(), 0);
        assert_ne!(I2cSpeed::FastPlus.timingr(), 0);
    }

    #[test]
    fn test_i2c_not_initialized_write() {
        let mut i2c = Stm32h7I2c::new(I2cInstance::I2c1, I2cConfig::default());
        assert_eq!(i2c.write(0x50, &[0x00]), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_i2c_not_initialized_read() {
        let mut i2c = Stm32h7I2c::new(I2cInstance::I2c2, I2cConfig::default());
        let mut buf = [0u8; 4];
        assert_eq!(i2c.read(0x50, &mut buf), Err(HalError::NotInitialized));
    }

    #[test]
    fn test_i2c_empty_data_rejected() {
        let mut i2c = Stm32h7I2c::new(I2cInstance::I2c1, I2cConfig::default());
        // Even if init'd, empty data should fail at validation
        // (but since not init'd, we get NotInitialized first)
        assert_eq!(i2c.write(0x50, &[]), Err(HalError::NotInitialized));
    }
}
