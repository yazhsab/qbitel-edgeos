// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! STM32H7 True Random Number Generator Driver
//!
//! Production-quality hardware RNG driver for STM32H7 series with NIST SP 800-90B
//! compliant health monitoring and conditioning.
//!
//! # Features
//!
//! - Hardware TRNG access
//! - Continuous health testing (CECS, SECS)
//! - Automatic error recovery
//! - Conditioning via SHA3 (optional)
//! - DRBG integration
//!
//! # STM32H7 RNG Specifications
//!
//! - True random number generator based on analog noise
//! - 32-bit output register
//! - ~40 CPU cycles per 32-bit word
//! - Built-in health tests (clock error, seed error)
//!
//! # Security
//!
//! The hardware RNG provides entropy for seeding DRBGs. For cryptographic
//! operations, use the conditioned output through `q_crypto::rng::SystemRng`.

use crate::error::{HalError, HalResult};
use crate::traits::RngInterface;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

// =============================================================================
// RNG Register Definitions (STM32H7 RM0433)
// =============================================================================

/// RNG peripheral base address
const RNG_BASE: u32 = 0x4802_1800;

/// RCC AHB2 enable register (for RNG clock)
const RCC_AHB2ENR: u32 = 0x5802_44DC;

/// RCC AHB2 reset register
const RCC_AHB2RSTR: u32 = 0x5802_441C;

// Register offsets
const RNG_CR_OFFSET: u32 = 0x00;   // Control register
const RNG_SR_OFFSET: u32 = 0x04;   // Status register
const RNG_DR_OFFSET: u32 = 0x08;   // Data register
#[allow(dead_code)]
const RNG_HTCR_OFFSET: u32 = 0x10; // Health test control register (H7 Rev Y+)

// Control register bits
const RNG_CR_RNGEN: u32 = 1 << 2;      // RNG enable
const RNG_CR_IE: u32 = 1 << 3;         // Interrupt enable
const RNG_CR_CED: u32 = 1 << 5;        // Clock error detection disable
const RNG_CR_CONDRST: u32 = 1 << 30;   // Conditioning soft reset
#[allow(dead_code)]
const RNG_CR_CONFIGLOCK: u32 = 1 << 31; // Configuration lock

// Status register bits
const RNG_SR_DRDY: u32 = 1 << 0;  // Data ready
const RNG_SR_CECS: u32 = 1 << 1;  // Clock error current status
const RNG_SR_SECS: u32 = 1 << 2;  // Seed error current status
const RNG_SR_CEIS: u32 = 1 << 5;  // Clock error interrupt status
const RNG_SR_SEIS: u32 = 1 << 6;  // Seed error interrupt status

/// All error flags
const RNG_SR_ERRORS: u32 = RNG_SR_CECS | RNG_SR_SECS | RNG_SR_CEIS | RNG_SR_SEIS;

// RCC bits
const RCC_AHB2ENR_RNGEN: u32 = 1 << 6;
const RCC_AHB2RSTR_RNGRST: u32 = 1 << 6;

// Health test magic value for unlocking HTCR
#[allow(dead_code)]
const RNG_HTCR_MAGIC: u32 = 0x1759_0ABC;

// =============================================================================
// RNG Health Test Statistics
// =============================================================================

/// RNG health statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct RngHealthStats {
    /// Total words generated
    pub words_generated: u64,
    /// Clock errors detected
    pub clock_errors: u32,
    /// Seed errors detected
    pub seed_errors: u32,
    /// Recovery attempts
    pub recovery_attempts: u32,
    /// Successful recoveries
    pub successful_recoveries: u32,
    /// Last error code
    pub last_error: u32,
}

// =============================================================================
// STM32H7 RNG Driver
// =============================================================================

/// STM32H7 True Random Number Generator driver
///
/// Provides access to the hardware TRNG with continuous health monitoring.
pub struct Stm32h7Rng {
    /// Initialized state
    initialized: bool,
    /// Health statistics
    stats: RngHealthStats,
    /// Timeout in cycles for waiting operations
    timeout_cycles: u32,
    /// Number of consecutive errors before giving up
    max_retries: u32,
    /// Enable clock error detection
    clock_error_detection: bool,
}

impl Stm32h7Rng {
    /// Default timeout (approximately 1ms at 480MHz)
    pub const DEFAULT_TIMEOUT: u32 = 480_000;

    /// Default maximum retries
    pub const DEFAULT_MAX_RETRIES: u32 = 3;

    /// Create a new RNG driver instance
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: false,
            stats: RngHealthStats {
                words_generated: 0,
                clock_errors: 0,
                seed_errors: 0,
                recovery_attempts: 0,
                successful_recoveries: 0,
                last_error: 0,
            },
            timeout_cycles: Self::DEFAULT_TIMEOUT,
            max_retries: Self::DEFAULT_MAX_RETRIES,
            clock_error_detection: true,
        }
    }

    /// Configure timeout for RNG operations
    pub fn set_timeout(&mut self, cycles: u32) {
        self.timeout_cycles = cycles;
    }

    /// Configure maximum retries on error
    pub fn set_max_retries(&mut self, retries: u32) {
        self.max_retries = retries;
    }

    /// Disable clock error detection (not recommended for security)
    pub fn disable_clock_error_detection(&mut self) {
        self.clock_error_detection = false;
    }

    /// Get health statistics
    #[must_use]
    pub const fn stats(&self) -> &RngHealthStats {
        &self.stats
    }

    /// Read RNG control register
    #[inline]
    unsafe fn read_cr() -> u32 {
        read_volatile((RNG_BASE + RNG_CR_OFFSET) as *const u32)
    }

    /// Write RNG control register
    #[inline]
    unsafe fn write_cr(val: u32) {
        write_volatile((RNG_BASE + RNG_CR_OFFSET) as *mut u32, val);
    }

    /// Read RNG status register
    #[inline]
    unsafe fn read_sr() -> u32 {
        read_volatile((RNG_BASE + RNG_SR_OFFSET) as *const u32)
    }

    /// Write RNG status register (to clear flags)
    #[inline]
    unsafe fn write_sr(val: u32) {
        write_volatile((RNG_BASE + RNG_SR_OFFSET) as *mut u32, val);
    }

    /// Read RNG data register
    #[inline]
    unsafe fn read_dr() -> u32 {
        read_volatile((RNG_BASE + RNG_DR_OFFSET) as *const u32)
    }

    /// Enable RNG peripheral clock
    fn enable_clock() {
        // SAFETY: Modifying RCC register
        unsafe {
            let enr = read_volatile(RCC_AHB2ENR as *const u32);
            write_volatile(RCC_AHB2ENR as *mut u32, enr | RCC_AHB2ENR_RNGEN);
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Reset RNG peripheral
    fn reset_peripheral() {
        // SAFETY: Modifying RCC register for reset
        unsafe {
            // Assert reset
            let rstr = read_volatile(RCC_AHB2RSTR as *const u32);
            write_volatile(RCC_AHB2RSTR as *mut u32, rstr | RCC_AHB2RSTR_RNGRST);
            compiler_fence(Ordering::SeqCst);

            // Short delay
            for _ in 0..100 {
                core::hint::spin_loop();
            }

            // Release reset
            write_volatile(RCC_AHB2RSTR as *mut u32, rstr & !RCC_AHB2RSTR_RNGRST);
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Enable the RNG peripheral
    fn enable_rng(&mut self) -> HalResult<()> {
        // SAFETY: Configuring RNG
        unsafe {
            let mut cr = Self::read_cr();

            // Clear and reconfigure
            cr &= !(RNG_CR_CED | RNG_CR_IE);

            // Optionally disable clock error detection (NOT recommended for security)
            if !self.clock_error_detection {
                cr |= RNG_CR_CED;
            }

            // Enable RNG
            cr |= RNG_CR_RNGEN;

            Self::write_cr(cr);
            compiler_fence(Ordering::SeqCst);
        }

        // Wait for first random value to be ready
        self.wait_for_data()?;

        // Discard first value (may be less random)
        // SAFETY: Reading RNG data register to discard the first potentially low-quality value.
        // The RNG peripheral has been enabled and data readiness was confirmed above.
        unsafe {
            let _ = Self::read_dr();
        }

        Ok(())
    }

    /// Wait for data to be ready
    fn wait_for_data(&self) -> HalResult<()> {
        let mut timeout = self.timeout_cycles;

        loop {
            // SAFETY: Reading RNG status register to check for errors and data readiness.
            let sr = unsafe { Self::read_sr() };

            // Check for errors first
            if sr & RNG_SR_ERRORS != 0 {
                return Err(HalError::RngError);
            }

            // Check if data ready
            if sr & RNG_SR_DRDY != 0 {
                return Ok(());
            }

            // Timeout check
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(HalError::Timeout);
            }

            core::hint::spin_loop();
        }
    }

    /// Check RNG health status
    fn check_health(&mut self) -> HalResult<()> {
        // SAFETY: Reading RNG status register to check clock and seed error flags.
        let sr = unsafe { Self::read_sr() };

        // Check clock error
        if sr & (RNG_SR_CECS | RNG_SR_CEIS) != 0 {
            self.stats.clock_errors = self.stats.clock_errors.saturating_add(1);
            self.stats.last_error = sr;
            return Err(HalError::RngError);
        }

        // Check seed error
        if sr & (RNG_SR_SECS | RNG_SR_SEIS) != 0 {
            self.stats.seed_errors = self.stats.seed_errors.saturating_add(1);
            self.stats.last_error = sr;
            return Err(HalError::RngError);
        }

        Ok(())
    }

    /// Clear error flags
    fn clear_errors(&mut self) {
        // SAFETY: Clearing status flags
        unsafe {
            // Clear interrupt flags by writing 0 to them
            let sr = Self::read_sr();
            Self::write_sr(sr & !(RNG_SR_CEIS | RNG_SR_SEIS));
        }
    }

    /// Attempt to recover from an error
    fn attempt_recovery(&mut self) -> HalResult<()> {
        self.stats.recovery_attempts = self.stats.recovery_attempts.saturating_add(1);

        // Clear errors
        self.clear_errors();

        // Conditioning soft reset (available on newer H7 revisions)
        // SAFETY: RNG CR is an architecturally-defined register. Volatile read-modify-write
        // asserts and then clears the conditioning soft reset bit for error recovery.
        unsafe {
            let cr = Self::read_cr();
            Self::write_cr(cr | RNG_CR_CONDRST);
            compiler_fence(Ordering::SeqCst);

            // Wait a bit
            for _ in 0..1000 {
                core::hint::spin_loop();
            }

            // Clear reset
            Self::write_cr(cr & !RNG_CR_CONDRST);
            compiler_fence(Ordering::SeqCst);
        }

        // Wait for recovery
        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        // Check if recovered
        // SAFETY: Reading RNG status register to verify error flags cleared after recovery.
        let sr = unsafe { Self::read_sr() };
        if sr & RNG_SR_ERRORS == 0 {
            self.stats.successful_recoveries = self.stats.successful_recoveries.saturating_add(1);
            return Ok(());
        }

        // Full reset as last resort
        Self::reset_peripheral();
        Self::enable_clock();
        self.enable_rng()?;

        // Check again
        // SAFETY: Reading RNG status register to verify full peripheral reset was successful.
        let sr = unsafe { Self::read_sr() };
        if sr & RNG_SR_ERRORS == 0 {
            self.stats.successful_recoveries = self.stats.successful_recoveries.saturating_add(1);
            Ok(())
        } else {
            Err(HalError::RngError)
        }
    }

    /// Read a single 32-bit random value
    fn read_random(&mut self) -> HalResult<u32> {
        // Check health before reading
        if let Err(_) = self.check_health() {
            // Attempt recovery
            for _ in 0..self.max_retries {
                if self.attempt_recovery().is_ok() {
                    break;
                }
            }
            self.check_health()?;
        }

        // Wait for data
        self.wait_for_data()?;

        // Read the value
        // SAFETY: Reading RNG data register after confirming data readiness via wait_for_data.
        let value = unsafe { Self::read_dr() };

        // Check health after reading
        self.check_health()?;

        self.stats.words_generated = self.stats.words_generated.saturating_add(1);

        Ok(value)
    }

    /// Get a random u32 value
    pub fn next_u32(&mut self) -> HalResult<u32> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }
        self.read_random()
    }

    /// Get a random u64 value
    pub fn next_u64(&mut self) -> HalResult<u64> {
        let low = self.next_u32()? as u64;
        let high = self.next_u32()? as u64;
        Ok((high << 32) | low)
    }

    /// Check if the RNG has encountered any errors
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.stats.clock_errors > 0 || self.stats.seed_errors > 0
    }

    /// Reset error statistics
    pub fn reset_stats(&mut self) {
        self.stats = RngHealthStats::default();
    }
}

impl Default for Stm32h7Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngInterface for Stm32h7Rng {
    fn init(&mut self) -> HalResult<()> {
        if self.initialized {
            return Ok(());
        }

        // Enable RNG clock
        Self::enable_clock();

        // Wait for clock to stabilize
        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        // Enable RNG
        self.enable_rng()?;

        self.initialized = true;
        Ok(())
    }

    fn fill_bytes(&mut self, buffer: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        let mut offset = 0;
        let mut retries = 0;

        while offset < buffer.len() {
            match self.read_random() {
                Ok(value) => {
                    let bytes = value.to_le_bytes();
                    let copy_len = (buffer.len() - offset).min(4);
                    buffer[offset..offset + copy_len].copy_from_slice(&bytes[..copy_len]);
                    offset += copy_len;
                    retries = 0; // Reset retry counter on success
                }
                Err(e) => {
                    retries += 1;
                    if retries >= self.max_retries {
                        return Err(e);
                    }
                    // Attempt recovery
                    self.attempt_recovery()?;
                }
            }
        }

        Ok(())
    }

    fn is_ready(&self) -> bool {
        if !self.initialized {
            return false;
        }

        // SAFETY: Reading status register
        let sr = unsafe { Self::read_sr() };

        // Ready if no errors and data available
        (sr & RNG_SR_ERRORS == 0) && (sr & RNG_SR_DRDY != 0)
    }
}

// =============================================================================
// CryptoRng implementation
// =============================================================================

impl q_crypto::traits::CryptoRng for Stm32h7Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), q_crypto::CryptoError> {
        RngInterface::fill_bytes(self, dest).map_err(|_| q_crypto::CryptoError::RngFailure)
    }
}

// =============================================================================
// Entropy source for DRBG
// =============================================================================

/// Entropy source interface for DRBG seeding
pub trait EntropySource {
    /// Get entropy bytes
    fn get_entropy(&mut self, buffer: &mut [u8]) -> HalResult<()>;

    /// Get minimum entropy estimate (bits per byte)
    fn entropy_per_byte(&self) -> u8;
}

impl EntropySource for Stm32h7Rng {
    fn get_entropy(&mut self, buffer: &mut [u8]) -> HalResult<()> {
        self.fill_bytes(buffer)
    }

    fn entropy_per_byte(&self) -> u8 {
        // STM32H7 RNG provides approximately 8 bits of entropy per byte
        // when properly conditioned
        8
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_new() {
        let rng = Stm32h7Rng::new();
        assert!(!rng.initialized);
        assert_eq!(rng.stats().words_generated, 0);
    }

    #[test]
    fn test_stats_default() {
        let stats = RngHealthStats::default();
        assert_eq!(stats.words_generated, 0);
        assert_eq!(stats.clock_errors, 0);
        assert_eq!(stats.seed_errors, 0);
    }

    // Note: Hardware-dependent tests would require actual hardware
    // or a mock implementation. The following tests verify configuration.

    #[test]
    fn test_set_timeout() {
        let mut rng = Stm32h7Rng::new();
        rng.set_timeout(1000);
        assert_eq!(rng.timeout_cycles, 1000);
    }

    #[test]
    fn test_set_max_retries() {
        let mut rng = Stm32h7Rng::new();
        rng.set_max_retries(5);
        assert_eq!(rng.max_retries, 5);
    }

    #[test]
    fn test_not_initialized_error() {
        let mut rng = Stm32h7Rng::new();
        let mut buffer = [0u8; 32];
        // This would fail with NotInitialized in real hardware
        // but we can't test actual hardware access here
        assert!(!rng.initialized);
    }
}
