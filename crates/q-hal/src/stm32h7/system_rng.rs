// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Hardware-Seeded Cryptographic RNG
//!
//! This module provides a production-grade random number generator that combines:
//!
//! - **Hardware TRNG**: STM32H7 True Random Number Generator for entropy
//! - **Hash-DRBG**: NIST SP 800-90A compliant deterministic generator
//! - **Automatic reseeding**: Periodic reseed from hardware entropy
//! - **Health monitoring**: Continuous entropy source health tests
//!
//! # Security Features
//!
//! - Hardware entropy with NIST SP 800-90B health tests
//! - DRBG output stretching for efficient random generation
//! - Automatic reseeding after configurable output limit
//! - Secure state zeroization on drop
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut rng = HardwareSeededRng::new()?;
//! let mut bytes = [0u8; 32];
//! rng.fill_bytes(&mut bytes)?;
//! ```

use crate::error::{HalError, HalResult};
use crate::stm32h7::rng::{Stm32h7Rng, RngHealthStats};
use crate::traits::RngInterface;
use q_crypto::rng::HashDrbg;
use q_crypto::traits::CryptoRng;
use q_crypto::error::CryptoError;
use q_crypto::zeroize_utils::secure_zero;

/// Reseed interval in bytes (1 MB)
pub const RESEED_INTERVAL_BYTES: u64 = 1024 * 1024;

/// Minimum entropy bytes for seeding
pub const MIN_ENTROPY_BYTES: usize = 48;

/// Nonce size for DRBG instantiation
pub const NONCE_SIZE: usize = 16;

/// Hardware-seeded cryptographic RNG state
#[derive(Debug, Clone, Copy, Default)]
pub struct HwRngStats {
    /// Total bytes generated
    pub bytes_generated: u64,
    /// Number of reseeds performed
    pub reseed_count: u64,
    /// Number of failed entropy requests
    pub entropy_failures: u64,
    /// Last reseed tick
    pub last_reseed_tick: u64,
    /// Hardware RNG health stats
    pub hw_stats: RngHealthStats,
}

/// Production-grade hardware-seeded RNG
///
/// Combines hardware TRNG with Hash-DRBG for efficient, secure random
/// number generation. The hardware RNG provides entropy, while the DRBG
/// stretches it into unlimited random bytes with proper security properties.
pub struct HardwareSeededRng {
    /// Hardware TRNG driver
    hw_rng: Stm32h7Rng,
    /// Hash-DRBG for output generation
    drbg: Option<HashDrbg>,
    /// Bytes generated since last reseed
    bytes_since_reseed: u64,
    /// Reseed interval in bytes
    reseed_interval: u64,
    /// Statistics
    stats: HwRngStats,
    /// Initialization complete
    initialized: bool,
}

impl HardwareSeededRng {
    /// Create a new hardware-seeded RNG instance (uninitialized)
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hw_rng: Stm32h7Rng::new(),
            drbg: None,
            bytes_since_reseed: 0,
            reseed_interval: RESEED_INTERVAL_BYTES,
            stats: HwRngStats {
                bytes_generated: 0,
                reseed_count: 0,
                entropy_failures: 0,
                last_reseed_tick: 0,
                hw_stats: RngHealthStats {
                    words_generated: 0,
                    clock_errors: 0,
                    seed_errors: 0,
                    recovery_attempts: 0,
                    successful_recoveries: 0,
                    last_error: 0,
                },
            },
            initialized: false,
        }
    }

    /// Initialize the RNG subsystem
    ///
    /// This performs:
    /// 1. Hardware RNG initialization
    /// 2. Initial entropy collection with health tests
    /// 3. DRBG instantiation
    pub fn init(&mut self) -> HalResult<()> {
        if self.initialized {
            return Ok(());
        }

        // Initialize hardware RNG
        self.hw_rng.init()?;

        // Wait for RNG to be ready
        let mut attempts = 0;
        while !self.hw_rng.is_ready() && attempts < 1000 {
            attempts += 1;
            core::hint::spin_loop();
        }

        if !self.hw_rng.is_ready() {
            return Err(HalError::RngError);
        }

        // Collect initial entropy
        let mut entropy = [0u8; MIN_ENTROPY_BYTES];
        self.collect_entropy(&mut entropy)?;

        // Collect nonce
        let mut nonce = [0u8; NONCE_SIZE];
        self.collect_entropy(&mut nonce)?;

        // Instantiate DRBG
        let drbg = HashDrbg::instantiate(
            &entropy,
            &nonce,
            b"Qbitel EdgeOS-OS-HW-RNG-v1",
            false, // No prediction resistance (we handle reseeding)
        ).map_err(|_| HalError::RngError)?;

        // Securely clear entropy from stack
        secure_zero(&mut entropy);
        secure_zero(&mut nonce);

        self.drbg = Some(drbg);
        self.stats.reseed_count = 1;
        self.initialized = true;

        Ok(())
    }

    /// Collect entropy from hardware RNG with retries
    fn collect_entropy(&mut self, buffer: &mut [u8]) -> HalResult<()> {
        const MAX_RETRIES: usize = 3;

        for attempt in 0..MAX_RETRIES {
            match RngInterface::fill_bytes(&mut self.hw_rng, buffer) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.stats.entropy_failures += 1;
                    if attempt == MAX_RETRIES - 1 {
                        return Err(e);
                    }
                    // Brief delay before retry
                    for _ in 0..1000 {
                        core::hint::spin_loop();
                    }
                }
            }
        }

        Err(HalError::RngError)
    }

    /// Reseed the DRBG with fresh hardware entropy
    pub fn reseed(&mut self) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        // Collect fresh entropy
        let mut entropy = [0u8; 32];
        self.collect_entropy(&mut entropy)?;

        // Reseed the DRBG
        if let Some(ref mut drbg) = self.drbg {
            drbg.reseed(&entropy, &[]).map_err(|_| HalError::RngError)?;
        }

        // Secure cleanup
        secure_zero(&mut entropy);

        self.bytes_since_reseed = 0;
        self.stats.reseed_count += 1;

        Ok(())
    }

    /// Check if reseed is needed
    fn check_reseed(&mut self) -> HalResult<()> {
        if self.bytes_since_reseed >= self.reseed_interval {
            self.reseed()?;
        }

        // Also check DRBG's internal reseed counter
        if let Some(ref drbg) = self.drbg {
            if drbg.needs_reseed() {
                self.reseed()?;
            }
        }

        Ok(())
    }

    /// Generate random bytes
    pub fn generate(&mut self, buffer: &mut [u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        // Check if reseed is needed
        self.check_reseed()?;

        // Generate from DRBG
        if let Some(ref mut drbg) = self.drbg {
            drbg.fill_bytes(buffer).map_err(|_| HalError::RngError)?;
        } else {
            return Err(HalError::NotInitialized);
        }

        // Update statistics
        self.bytes_since_reseed += buffer.len() as u64;
        self.stats.bytes_generated += buffer.len() as u64;

        Ok(())
    }

    /// Get a random u32 value
    pub fn next_u32(&mut self) -> HalResult<u32> {
        let mut bytes = [0u8; 4];
        self.generate(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Get a random u64 value
    pub fn next_u64(&mut self) -> HalResult<u64> {
        let mut bytes = [0u8; 8];
        self.generate(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Generate a random value in range [0, max)
    pub fn random_range(&mut self, max: u32) -> HalResult<u32> {
        if max == 0 {
            return Ok(0);
        }
        if max == 1 {
            return Ok(0);
        }

        // Use rejection sampling to avoid modulo bias
        let threshold = u32::MAX - (u32::MAX % max);

        loop {
            let value = self.next_u32()?;
            if value < threshold {
                return Ok(value % max);
            }
        }
    }

    /// Set custom reseed interval
    pub fn set_reseed_interval(&mut self, bytes: u64) {
        self.reseed_interval = bytes;
    }

    /// Get statistics
    #[must_use]
    pub fn stats(&self) -> &HwRngStats {
        &self.stats
    }

    /// Update hardware stats from RNG driver
    pub fn refresh_hw_stats(&mut self) {
        self.stats.hw_stats = *self.hw_rng.stats();
    }

    /// Check if RNG is healthy
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        if !self.initialized {
            return false;
        }

        // Check hardware RNG health
        if self.hw_rng.has_errors() {
            return false;
        }

        // Check DRBG health
        if let Some(ref drbg) = self.drbg {
            if !drbg.is_healthy() {
                return false;
            }
        }

        true
    }

    /// Check if initialized
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get bytes generated since last reseed
    #[must_use]
    pub const fn bytes_since_reseed(&self) -> u64 {
        self.bytes_since_reseed
    }

    /// Force immediate reseed (for security-critical operations)
    pub fn force_reseed(&mut self) -> HalResult<()> {
        self.reseed()
    }

    /// Add additional entropy (from external sources like PUF, ADC noise, etc.)
    pub fn add_entropy(&mut self, entropy: &[u8]) -> HalResult<()> {
        if !self.initialized {
            return Err(HalError::NotInitialized);
        }

        if let Some(ref mut drbg) = self.drbg {
            drbg.add_entropy(entropy).map_err(|_| HalError::RngError)?;
        }

        Ok(())
    }
}

impl Default for HardwareSeededRng {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HardwareSeededRng {
    fn drop(&mut self) {
        // DRBG will zeroize itself when dropped
        self.drbg = None;
        self.bytes_since_reseed = 0;
        self.stats.bytes_generated = 0;
    }
}

// Implement HAL RNG interface
impl RngInterface for HardwareSeededRng {
    fn init(&mut self) -> HalResult<()> {
        HardwareSeededRng::init(self)
    }

    fn fill_bytes(&mut self, buffer: &mut [u8]) -> HalResult<()> {
        self.generate(buffer)
    }

    fn is_ready(&self) -> bool {
        self.initialized && self.is_healthy()
    }
}

// Implement q-crypto CryptoRng trait for direct use with crypto primitives
impl CryptoRng for HardwareSeededRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.generate(dest).map_err(|_| CryptoError::RngFailure)
    }
}

// =============================================================================
// Global RNG Instance
// =============================================================================

use core::cell::UnsafeCell;

/// Wrapper to allow a static `UnsafeCell<HardwareSeededRng>`.
///
/// # Safety
/// Access is only safe in single-threaded (interrupt-masked) embedded contexts
/// or when external synchronization is provided.
struct SyncRng(UnsafeCell<HardwareSeededRng>);
// SAFETY: SyncRng is only accessed in single-threaded embedded contexts or with
// interrupts masked. No concurrent access occurs on bare-metal STM32H7.
unsafe impl Sync for SyncRng {}

/// Global hardware-seeded RNG instance
static SYSTEM_RNG: SyncRng = SyncRng(UnsafeCell::new(HardwareSeededRng::new()));

/// Initialize the system RNG
///
/// Must be called during system startup before any cryptographic operations.
pub fn init_system_rng() -> HalResult<()> {
    // SAFETY: Dereference of UnsafeCell pointer to access the global RNG.
    // This is safe in single-threaded embedded contexts (no concurrent access).
    unsafe { (*SYSTEM_RNG.0.get()).init() }
}

/// Get random bytes from system RNG
pub fn system_random_bytes(buffer: &mut [u8]) -> HalResult<()> {
    // SAFETY: Dereference of UnsafeCell pointer to access the global RNG.
    // Safe in single-threaded embedded contexts; caller ensures no concurrent access.
    unsafe { (*SYSTEM_RNG.0.get()).generate(buffer) }
}

/// Get a random u32 from system RNG
pub fn system_random_u32() -> HalResult<u32> {
    // SAFETY: Dereference of UnsafeCell pointer to access the global RNG.
    // Safe in single-threaded embedded contexts; caller ensures no concurrent access.
    unsafe { (*SYSTEM_RNG.0.get()).next_u32() }
}

/// Get a random u64 from system RNG
pub fn system_random_u64() -> HalResult<u64> {
    // SAFETY: Dereference of UnsafeCell pointer to access the global RNG.
    // Safe in single-threaded embedded contexts; caller ensures no concurrent access.
    unsafe { (*SYSTEM_RNG.0.get()).next_u64() }
}

/// Force reseed of system RNG
pub fn system_rng_reseed() -> HalResult<()> {
    // SAFETY: Dereference of UnsafeCell pointer to access the global RNG.
    // Safe in single-threaded embedded contexts; caller ensures no concurrent access.
    unsafe { (*SYSTEM_RNG.0.get()).force_reseed() }
}

/// Check if system RNG is healthy
pub fn system_rng_healthy() -> bool {
    // SAFETY: Dereference of UnsafeCell pointer to access the global RNG.
    // Safe in single-threaded embedded contexts; caller ensures no concurrent access.
    unsafe { (*SYSTEM_RNG.0.get()).is_healthy() }
}

/// Add entropy to system RNG from external source
pub fn system_rng_add_entropy(entropy: &[u8]) -> HalResult<()> {
    // SAFETY: Dereference of UnsafeCell pointer to access the global RNG.
    // Safe in single-threaded embedded contexts; caller ensures no concurrent access.
    unsafe { (*SYSTEM_RNG.0.get()).add_entropy(entropy) }
}

/// Get reference to system RNG for use with crypto APIs
///
/// # Safety
/// The returned reference is valid as long as no other code is accessing
/// the system RNG. This is typically safe in single-threaded embedded contexts.
pub unsafe fn get_system_rng() -> &'static mut HardwareSeededRng {
    // SAFETY: Caller guarantees no other references to the global RNG exist,
    // as documented in the function's safety contract above.
    &mut *SYSTEM_RNG.0.get()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_creation() {
        let rng = HardwareSeededRng::new();
        assert!(!rng.is_initialized());
        assert!(!rng.is_healthy());
    }

    #[test]
    fn test_stats_default() {
        let stats = HwRngStats::default();
        assert_eq!(stats.bytes_generated, 0);
        assert_eq!(stats.reseed_count, 0);
    }

    // Note: Full tests require hardware and would be run as integration tests
}
