// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! HAL trait definitions
//!
//! This module defines the platform-agnostic hardware abstraction traits
//! that must be implemented for each target platform.

use crate::error::HalResult;

/// Flash memory interface
pub trait FlashInterface {
    /// Flash page/sector size in bytes
    const PAGE_SIZE: usize;

    /// Total flash size in bytes
    const TOTAL_SIZE: usize;

    /// Base address of flash
    const BASE_ADDRESS: u32;

    /// Initialize flash controller
    fn init(&mut self) -> HalResult<()>;

    /// Read data from flash
    ///
    /// # Arguments
    /// * `address` - Absolute flash address
    /// * `buffer` - Buffer to read into
    fn read(&self, address: u32, buffer: &mut [u8]) -> HalResult<()>;

    /// Write data to flash
    ///
    /// # Arguments
    /// * `address` - Absolute flash address (must be aligned to write granularity)
    /// * `data` - Data to write
    ///
    /// # Notes
    /// Flash must be erased before writing.
    fn write(&mut self, address: u32, data: &[u8]) -> HalResult<()>;

    /// Erase a flash page/sector
    ///
    /// # Arguments
    /// * `address` - Address within the page to erase
    fn erase_page(&mut self, address: u32) -> HalResult<()>;

    /// Erase a range of flash
    ///
    /// # Arguments
    /// * `start` - Start address
    /// * `end` - End address (exclusive)
    fn erase_range(&mut self, start: u32, end: u32) -> HalResult<()> {
        let mut addr = start;
        while addr < end {
            self.erase_page(addr)?;
            addr += Self::PAGE_SIZE as u32;
        }
        Ok(())
    }

    /// Verify flash contents match expected data
    fn verify(&self, address: u32, expected: &[u8]) -> HalResult<bool> {
        let mut buffer = [0u8; 256];
        let mut offset = 0;

        while offset < expected.len() {
            let chunk_size = (expected.len() - offset).min(buffer.len());
            self.read(address + offset as u32, &mut buffer[..chunk_size])?;

            if buffer[..chunk_size] != expected[offset..offset + chunk_size] {
                return Ok(false);
            }
            offset += chunk_size;
        }

        Ok(true)
    }

    /// Lock flash region (prevent writes)
    fn lock(&mut self) -> HalResult<()>;

    /// Unlock flash region (allow writes)
    fn unlock(&mut self) -> HalResult<()>;

    /// Check if flash is locked
    fn is_locked(&self) -> bool;
}

/// Random number generator interface
pub trait RngInterface {
    /// Initialize the RNG
    fn init(&mut self) -> HalResult<()>;

    /// Fill buffer with random bytes
    fn fill_bytes(&mut self, buffer: &mut [u8]) -> HalResult<()>;

    /// Generate a random u32
    fn next_u32(&mut self) -> HalResult<u32> {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Generate a random u64
    fn next_u64(&mut self) -> HalResult<u64> {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Check if RNG is ready
    fn is_ready(&self) -> bool;
}

/// Timer interface
pub trait TimerInterface {
    /// Timer resolution in Hz
    const FREQUENCY_HZ: u32;

    /// Initialize the timer
    fn init(&mut self) -> HalResult<()>;

    /// Get current tick count
    fn get_ticks(&self) -> u64;

    /// Get elapsed microseconds since boot
    fn get_micros(&self) -> u64 {
        (self.get_ticks() * 1_000_000) / Self::FREQUENCY_HZ as u64
    }

    /// Get elapsed milliseconds since boot
    fn get_millis(&self) -> u32 {
        ((self.get_ticks() * 1_000) / Self::FREQUENCY_HZ as u64) as u32
    }

    /// Delay for specified microseconds
    fn delay_us(&self, us: u32);

    /// Delay for specified milliseconds
    fn delay_ms(&self, ms: u32) {
        self.delay_us(ms * 1000);
    }
}

/// Secure storage interface (OTP, eFUSE, or encrypted storage)
pub trait SecureStorageInterface {
    /// Maximum data size per slot
    const MAX_SLOT_SIZE: usize;

    /// Number of available slots
    const NUM_SLOTS: usize;

    /// Initialize secure storage
    fn init(&mut self) -> HalResult<()>;

    /// Read data from a slot
    ///
    /// # Arguments
    /// * `slot` - Slot number
    /// * `buffer` - Buffer to read into
    fn read(&self, slot: u8, buffer: &mut [u8]) -> HalResult<usize>;

    /// Write data to a slot
    ///
    /// # Arguments
    /// * `slot` - Slot number
    /// * `data` - Data to write
    ///
    /// # Notes
    /// For OTP, this is a one-time operation.
    fn write(&mut self, slot: u8, data: &[u8]) -> HalResult<()>;

    /// Check if a slot has been written
    fn is_slot_written(&self, slot: u8) -> HalResult<bool>;

    /// Lock a slot (prevent further writes)
    fn lock_slot(&mut self, slot: u8) -> HalResult<()>;

    /// Check if a slot is locked
    fn is_slot_locked(&self, slot: u8) -> HalResult<bool>;

    /// Read the device unique ID (eFUSE UID)
    fn read_uid(&self) -> HalResult<[u8; 16]>;
}

/// PUF (Physically Unclonable Function) interface
pub trait PufInterface {
    /// Response size in bytes
    const RESPONSE_SIZE: usize;

    /// Initialize PUF
    fn init(&mut self) -> HalResult<()>;

    /// Check if PUF is available
    fn is_available(&self) -> bool;

    /// Generate PUF response for a challenge
    ///
    /// # Arguments
    /// * `challenge` - Challenge input (typically 32 bytes)
    ///
    /// # Returns
    /// PUF response (typically 256 bytes)
    fn challenge(&mut self, challenge: &[u8; 32]) -> HalResult<[u8; 256]>;

    /// Enroll PUF (generate helper data for stable reconstruction)
    ///
    /// # Returns
    /// Tuple of (fingerprint, helper_data)
    fn enroll(&mut self) -> HalResult<([u8; 32], [u8; 128])>;

    /// Reconstruct fingerprint using helper data
    fn reconstruct(&mut self, helper_data: &[u8; 128]) -> HalResult<[u8; 32]>;
}

/// TrustZone configuration interface (for Cortex-M33/M7)
#[cfg(any(feature = "stm32h7", feature = "stm32u5"))]
pub trait TrustZoneInterface {
    /// Configure a memory region as secure
    fn configure_secure_region(&mut self, start: u32, size: u32) -> HalResult<()>;

    /// Configure a memory region as non-secure
    fn configure_nonsecure_region(&mut self, start: u32, size: u32) -> HalResult<()>;

    /// Configure a peripheral as secure
    fn configure_secure_peripheral(&mut self, peripheral_id: u32) -> HalResult<()>;

    /// Lock TrustZone configuration (cannot be changed until reset)
    fn lock_configuration(&mut self) -> HalResult<()>;

    /// Check if running in secure mode
    fn is_secure(&self) -> bool;
}

/// GPIO interface
pub trait GpioPin {
    /// Set pin high
    fn set_high(&mut self) -> HalResult<()>;

    /// Set pin low
    fn set_low(&mut self) -> HalResult<()>;

    /// Read pin state
    fn is_high(&self) -> HalResult<bool>;

    /// Toggle pin
    fn toggle(&mut self) -> HalResult<()>;
}

/// UART serial interface
pub trait UartInterface {
    /// Initialize the UART with the given baud rate
    fn init(&mut self, baud_rate: u32) -> HalResult<()>;

    /// Write a byte (blocking)
    fn write_byte(&mut self, byte: u8) -> HalResult<()>;

    /// Read a byte (blocking, with timeout)
    fn read_byte(&mut self) -> HalResult<u8>;

    /// Write a buffer of bytes (blocking)
    fn write(&mut self, data: &[u8]) -> HalResult<()> {
        for &byte in data {
            self.write_byte(byte)?;
        }
        Ok(())
    }

    /// Read into a buffer, returning the number of bytes read
    fn read(&mut self, buffer: &mut [u8]) -> HalResult<usize>;

    /// Check if data is available to read
    fn is_rx_available(&self) -> bool;

    /// Check if transmitter is ready
    fn is_tx_ready(&self) -> bool;

    /// Flush the transmit buffer
    fn flush(&mut self) -> HalResult<()>;
}

/// Watchdog interface
pub trait WatchdogInterface {
    /// Initialize and start watchdog
    fn init(&mut self, timeout_ms: u32) -> HalResult<()>;

    /// Feed/refresh the watchdog
    fn feed(&mut self) -> HalResult<()>;

    /// Check if reset was caused by watchdog
    fn was_watchdog_reset(&self) -> bool;
}

/// Reset interface
pub trait ResetInterface {
    /// Perform a soft reset
    fn soft_reset(&mut self) -> !;

    /// Get reset reason
    fn get_reset_reason(&self) -> ResetReason;

    /// Clear reset flags
    fn clear_reset_flags(&mut self);
}

/// Reset reason enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    /// Power-on reset
    PowerOn,
    /// Software reset
    Software,
    /// Watchdog reset
    Watchdog,
    /// External reset (NRST pin)
    External,
    /// Brown-out reset
    BrownOut,
    /// Unknown reason
    Unknown,
}

/// Debug interface control
pub trait DebugInterface {
    /// Check if debug interface is enabled
    fn is_enabled(&self) -> bool;

    /// Disable debug interface (security feature)
    fn disable(&mut self) -> HalResult<()>;

    /// Lock debug interface (permanent until reset)
    fn lock(&mut self) -> HalResult<()>;
}
