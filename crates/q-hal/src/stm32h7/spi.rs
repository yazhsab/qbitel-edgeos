// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 SPI Driver
//!
//! Provides blocking SPI master communication for the STM32H7 series MCUs.
//! Supports SPI1-6 with configurable clock polarity, phase, and baud rate.
//!
//! # STM32H7 SPI Features
//!
//! - Up to 150 Mbit/s (SPI1/2/3) or 100 Mbit/s (SPI4/5/6)
//! - Full-duplex, half-duplex, simplex modes
//! - 4-32 bit data frame size
//! - Hardware CRC
//! - DMA support (not implemented here — blocking only)

use crate::error::{HalError, HalResult};
use core::ptr;

// ============================================================================
// SPI Register Offsets (STM32H7)
// ============================================================================

/// Control Register 1
const SPI_CR1_OFFSET: u32 = 0x00;
/// Control Register 2
const SPI_CR2_OFFSET: u32 = 0x04;
/// Configuration Register 1
const SPI_CFG1_OFFSET: u32 = 0x08;
/// Configuration Register 2
const SPI_CFG2_OFFSET: u32 = 0x0C;
/// Status Register
const SPI_SR_OFFSET: u32 = 0x14;
/// Interrupt Flag Clear Register
const SPI_IFCR_OFFSET: u32 = 0x18;
/// Transmit Data Register
const SPI_TXDR_OFFSET: u32 = 0x20;
/// Receive Data Register
const SPI_RXDR_OFFSET: u32 = 0x30;

// ============================================================================
// CR1 bits
// ============================================================================

/// SPI enable
const CR1_SPE: u32 = 1 << 0;
/// Master transfer start
const CR1_CSTART: u32 = 1 << 9;

// ============================================================================
// CFG1 bits
// ============================================================================

/// Baud rate prescaler mask (bits 30:28)
const CFG1_MBR_MASK: u32 = 0b111 << 28;

// ============================================================================
// CFG2 bits
// ============================================================================

/// Master mode
const CFG2_MASTER: u32 = 1 << 22;
/// Software slave management
const CFG2_SSM: u32 = 1 << 26;
/// Clock polarity
const CFG2_CPOL: u32 = 1 << 25;
/// Clock phase
const CFG2_CPHA: u32 = 1 << 24;
/// SS output enable (managed by software)
const CFG2_SSOE: u32 = 1 << 29;

// ============================================================================
// SR bits
// ============================================================================

/// TX FIFO not full / space available
const SR_TXP: u32 = 1 << 1;
/// RX FIFO not empty / data available
const SR_RXP: u32 = 1 << 0;
/// End of transfer
const SR_EOT: u32 = 1 << 3;
/// Transfer complete filled
const SR_TXTF: u32 = 1 << 4;

// ============================================================================
// RCC Clock Enable
// ============================================================================

/// RCC APB2ENR (SPI1, SPI4, SPI5)
const RCC_APB2ENR: u32 = 0x5802_4400 + 0xF0;
/// RCC APB1LENR (SPI2, SPI3)
const RCC_APB1LENR: u32 = 0x5802_4400 + 0xE8;
/// RCC APB4ENR (SPI6)
const RCC_APB4ENR: u32 = 0x5802_4400 + 0xF4;

/// Timeout for blocking operations
const SPI_TIMEOUT: u32 = 500_000;

// ============================================================================
// SPI Instance Definitions
// ============================================================================

/// SPI peripheral instance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiInstance {
    /// SPI1 (APB2, up to 150 Mbit/s)
    Spi1,
    /// SPI2 (APB1, up to 150 Mbit/s)
    Spi2,
    /// SPI3 (APB1, up to 150 Mbit/s)
    Spi3,
    /// SPI4 (APB2, up to 100 Mbit/s)
    Spi4,
    /// SPI5 (APB2, up to 100 Mbit/s)
    Spi5,
    /// SPI6 (APB4, up to 100 Mbit/s)
    Spi6,
}

impl SpiInstance {
    /// Get the base address for this SPI instance
    const fn base_addr(&self) -> u32 {
        match self {
            Self::Spi1 => 0x4001_3000,
            Self::Spi2 => 0x4000_3800,
            Self::Spi3 => 0x4000_3C00,
            Self::Spi4 => 0x4001_3400,
            Self::Spi5 => 0x4001_5000,
            Self::Spi6 => 0x5800_1400,
        }
    }

    /// Get the RCC enable register address and bit
    const fn rcc_enable(&self) -> (u32, u32) {
        match self {
            Self::Spi1 => (RCC_APB2ENR, 1 << 12),
            Self::Spi2 => (RCC_APB1LENR, 1 << 14),
            Self::Spi3 => (RCC_APB1LENR, 1 << 15),
            Self::Spi4 => (RCC_APB2ENR, 1 << 13),
            Self::Spi5 => (RCC_APB2ENR, 1 << 20),
            Self::Spi6 => (RCC_APB4ENR, 1 << 5),
        }
    }
}

// ============================================================================
// SPI Configuration
// ============================================================================

/// Clock polarity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockPolarity {
    /// Clock idle low
    IdleLow,
    /// Clock idle high
    IdleHigh,
}

/// Clock phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockPhase {
    /// Data captured on first clock edge
    FirstEdge,
    /// Data captured on second clock edge
    SecondEdge,
}

/// SPI baud rate prescaler
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BaudRatePrescaler {
    /// Divide by 2
    Div2 = 0,
    /// Divide by 4
    Div4 = 1,
    /// Divide by 8
    Div8 = 2,
    /// Divide by 16
    Div16 = 3,
    /// Divide by 32
    Div32 = 4,
    /// Divide by 64
    Div64 = 5,
    /// Divide by 128
    Div128 = 6,
    /// Divide by 256
    Div256 = 7,
}

/// SPI configuration
#[derive(Debug, Clone, Copy)]
pub struct SpiConfig {
    /// Clock polarity
    pub polarity: ClockPolarity,
    /// Clock phase
    pub phase: ClockPhase,
    /// Baud rate prescaler
    pub prescaler: BaudRatePrescaler,
}

impl Default for SpiConfig {
    fn default() -> Self {
        Self {
            polarity: ClockPolarity::IdleLow,
            phase: ClockPhase::FirstEdge,
            prescaler: BaudRatePrescaler::Div8,
        }
    }
}

// ============================================================================
// SPI Driver
// ============================================================================

/// STM32H7 SPI driver (master mode, 8-bit data)
pub struct Stm32h7Spi {
    /// SPI instance
    instance: SpiInstance,
    /// Configuration
    config: SpiConfig,
    /// Whether the SPI is initialized
    initialized: bool,
}

impl Stm32h7Spi {
    /// Create a new SPI driver instance
    #[must_use]
    pub const fn new(instance: SpiInstance, config: SpiConfig) -> Self {
        Self {
            instance,
            config,
            initialized: false,
        }
    }

    /// Enable the SPI peripheral clock
    fn enable_clock(&self) {
        let (reg_addr, bit) = self.instance.rcc_enable();
        // SAFETY: RCC APBxENR register — volatile RMW to enable peripheral clock.
        unsafe {
            let val = ptr::read_volatile(reg_addr as *const u32);
            ptr::write_volatile(reg_addr as *mut u32, val | bit);
            let _ = ptr::read_volatile(reg_addr as *const u32);
        }
    }

    /// Initialize the SPI peripheral in master mode
    pub fn init(&mut self) -> HalResult<()> {
        self.enable_clock();
        let base = self.instance.base_addr();

        // SAFETY: All writes target valid STM32H7 SPI MMIO registers.
        // SPI is disabled during configuration.
        unsafe {
            // Disable SPI
            ptr::write_volatile((base + SPI_CR1_OFFSET) as *mut u32, 0);

            // CFG1: 8-bit data frame, baud rate prescaler
            // DSIZE[4:0] = 0b00111 (8-bit) at bits 4:0
            let cfg1 = 0b00111 | ((self.config.prescaler as u32) << 28);
            ptr::write_volatile((base + SPI_CFG1_OFFSET) as *mut u32, cfg1);

            // CFG2: master mode, software SS management, CPOL, CPHA
            let mut cfg2 = CFG2_MASTER | CFG2_SSM | CFG2_SSOE;
            if self.config.polarity == ClockPolarity::IdleHigh {
                cfg2 |= CFG2_CPOL;
            }
            if self.config.phase == ClockPhase::SecondEdge {
                cfg2 |= CFG2_CPHA;
            }
            ptr::write_volatile((base + SPI_CFG2_OFFSET) as *mut u32, cfg2);

            // CR2: TSIZE = 0 (unlimited transfer)
            ptr::write_volatile((base + SPI_CR2_OFFSET) as *mut u32, 0);

            // Enable SPI
            ptr::write_volatile((base + SPI_CR1_OFFSET) as *mut u32, CR1_SPE);
        }

        self.initialized = true;
        Ok(())
    }

    /// Transfer a single byte (full duplex: send + receive)
    pub fn transfer_byte(&mut self, tx: u8) -> HalResult<u8> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }
        let base = self.instance.base_addr();

        // SAFETY: Valid STM32H7 SPI MMIO register accesses.
        unsafe {
            // Start transfer
            let cr1 = ptr::read_volatile((base + SPI_CR1_OFFSET) as *const u32);
            ptr::write_volatile((base + SPI_CR1_OFFSET) as *mut u32, cr1 | CR1_CSTART);

            // Wait for TXP (TX FIFO space available)
            let mut timeout = SPI_TIMEOUT;
            while ptr::read_volatile((base + SPI_SR_OFFSET) as *const u32) & SR_TXP == 0 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::Timeout);
                }
                core::hint::spin_loop();
            }

            // Write data
            ptr::write_volatile((base + SPI_TXDR_OFFSET) as *mut u8, tx);

            // Wait for RXP (RX data available)
            timeout = SPI_TIMEOUT;
            while ptr::read_volatile((base + SPI_SR_OFFSET) as *const u32) & SR_RXP == 0 {
                timeout = timeout.saturating_sub(1);
                if timeout == 0 {
                    return Err(HalError::Timeout);
                }
                core::hint::spin_loop();
            }

            // Read data
            let rx = ptr::read_volatile((base + SPI_RXDR_OFFSET) as *const u8);
            Ok(rx)
        }
    }

    /// Write a buffer of bytes (ignore received data)
    pub fn write(&mut self, data: &[u8]) -> HalResult<()> {
        for &byte in data {
            let _ = self.transfer_byte(byte)?;
        }
        Ok(())
    }

    /// Read a buffer of bytes (sends 0x00 while reading)
    pub fn read(&mut self, buffer: &mut [u8]) -> HalResult<()> {
        for slot in buffer.iter_mut() {
            *slot = self.transfer_byte(0x00)?;
        }
        Ok(())
    }

    /// Full-duplex transfer (simultaneous write + read)
    pub fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> HalResult<()> {
        let len = tx.len().min(rx.len());
        for i in 0..len {
            rx[i] = self.transfer_byte(tx[i])?;
        }
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
    fn test_spi_instance_addresses() {
        assert_eq!(SpiInstance::Spi1.base_addr(), 0x4001_3000);
        assert_eq!(SpiInstance::Spi2.base_addr(), 0x4000_3800);
        assert_eq!(SpiInstance::Spi3.base_addr(), 0x4000_3C00);
        assert_eq!(SpiInstance::Spi4.base_addr(), 0x4001_3400);
        assert_eq!(SpiInstance::Spi5.base_addr(), 0x4001_5000);
        assert_eq!(SpiInstance::Spi6.base_addr(), 0x5800_1400);
    }

    #[test]
    fn test_spi_default_config() {
        let config = SpiConfig::default();
        assert_eq!(config.polarity, ClockPolarity::IdleLow);
        assert_eq!(config.phase, ClockPhase::FirstEdge);
        assert_eq!(config.prescaler as u8, BaudRatePrescaler::Div8 as u8);
    }

    #[test]
    fn test_spi_not_initialized() {
        let mut spi = Stm32h7Spi::new(SpiInstance::Spi1, SpiConfig::default());
        assert_eq!(spi.transfer_byte(0x42), Err(HalError::NotInitialized));
    }
}
