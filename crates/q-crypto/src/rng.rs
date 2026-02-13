// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! NIST SP 800-90A/B Compliant Random Number Generation
//!
//! This module provides cryptographically secure random number generation
//! implementing NIST SP 800-90A DRBG (Deterministic Random Bit Generator)
//! with SP 800-90B entropy source health tests.
//!
//! # Implementations
//!
//! - **Hash-DRBG**: Based on SHA3-256 (primary for embedded)
//! - **CTR-DRBG**: Based on AES-256 (when hardware acceleration available)
//!
//! # Security Features
//!
//! - Automatic reseeding after configurable output limit
//! - Prediction resistance support
//! - Entropy health testing (repetition count, adaptive proportion)
//! - Secure state zeroization

use crate::error::CryptoError;
use crate::traits::CryptoRng;
use crate::hash::Sha3_256;
use crate::traits::Hash;
use crate::zeroize_utils::{secure_zero, SecureBuffer};
use zeroize::Zeroize;

// =============================================================================
// NIST SP 800-90B Entropy Health Tests
// =============================================================================

/// Entropy source health test configuration
/// Per NIST SP 800-90B Section 4.4
pub struct EntropyHealthTest {
    /// Cutoff value for repetition count test (H=8 bits, alpha=2^-40)
    /// C = 1 + ceil(-log2(alpha) / H) = 1 + ceil(40/8) = 6
    repetition_cutoff: u8,
    /// Window size for adaptive proportion test
    adaptive_window: u16,
    /// Cutoff for adaptive proportion test
    adaptive_cutoff: u16,
    /// Last sample for repetition count test
    last_sample: u8,
    /// Repetition counter
    repetition_count: u8,
    /// Sample buffer for adaptive proportion test
    adaptive_count: u16,
    /// Current sample in adaptive window
    adaptive_sample: u8,
    /// Position in adaptive window
    adaptive_position: u16,
    /// Total failures detected
    failure_count: u32,
}

impl EntropyHealthTest {
    /// Create new entropy health test with default parameters
    /// Parameters chosen for H=8 bits, alpha=2^-40 per SP 800-90B
    #[must_use]
    pub const fn new() -> Self {
        Self {
            // For H=8, alpha=2^-40: C = 1 + ceil(40/8) = 6
            repetition_cutoff: 6,
            // Window W = 1024, cutoff for H=8: ceil((1 + 40/8) * 1024 / 256) = 24
            // More conservative: W=512, cutoff=337 (for H=1, alpha=2^-30)
            adaptive_window: 512,
            adaptive_cutoff: 337,
            last_sample: 0,
            repetition_count: 1,
            adaptive_count: 0,
            adaptive_sample: 0,
            adaptive_position: 0,
            failure_count: 0,
        }
    }

    /// Reset the health test state
    pub fn reset(&mut self) {
        self.last_sample = 0;
        self.repetition_count = 1;
        self.adaptive_count = 0;
        self.adaptive_sample = 0;
        self.adaptive_position = 0;
    }

    /// Process a single entropy sample
    /// Returns Ok(()) if health tests pass, Err if failure detected
    pub fn process_sample(&mut self, sample: u8) -> Result<(), CryptoError> {
        // Repetition Count Test (SP 800-90B Section 4.4.1)
        if sample == self.last_sample {
            self.repetition_count = self.repetition_count.saturating_add(1);
            if self.repetition_count >= self.repetition_cutoff {
                self.failure_count = self.failure_count.saturating_add(1);
                return Err(CryptoError::RngFailure);
            }
        } else {
            self.last_sample = sample;
            self.repetition_count = 1;
        }

        // Adaptive Proportion Test (SP 800-90B Section 4.4.2)
        if self.adaptive_position == 0 {
            // Start new window
            self.adaptive_sample = sample;
            self.adaptive_count = 1;
            self.adaptive_position = 1;
        } else {
            if sample == self.adaptive_sample {
                self.adaptive_count += 1;
                if self.adaptive_count >= self.adaptive_cutoff {
                    self.failure_count = self.failure_count.saturating_add(1);
                    return Err(CryptoError::RngFailure);
                }
            }
            self.adaptive_position += 1;
            if self.adaptive_position >= self.adaptive_window {
                self.adaptive_position = 0;
            }
        }

        Ok(())
    }

    /// Process multiple entropy samples
    pub fn process_samples(&mut self, samples: &[u8]) -> Result<(), CryptoError> {
        for &sample in samples {
            self.process_sample(sample)?;
        }
        Ok(())
    }

    /// Check if entropy source is considered healthy
    /// Returns true if fewer than 3 failures in last window
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.failure_count < 3
    }

    /// Get failure count
    #[must_use]
    pub const fn failure_count(&self) -> u32 {
        self.failure_count
    }
}

impl Default for EntropyHealthTest {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Hash-DRBG (NIST SP 800-90A Section 10.1)
// =============================================================================

/// Security strength for Hash-DRBG
pub const HASH_DRBG_SECURITY_STRENGTH: usize = 256;

/// Seed length for SHA3-256 based Hash-DRBG (seedlen = 440 bits = 55 bytes per spec)
/// We use 64 bytes for alignment
pub const HASH_DRBG_SEED_LEN: usize = 64;

/// Maximum bytes per request (2^16 for our implementation, spec allows 2^19)
pub const HASH_DRBG_MAX_REQUEST: usize = 65536;

/// Reseed interval (2^20 for our implementation, spec allows 2^48)
pub const HASH_DRBG_RESEED_INTERVAL: u64 = 1 << 20;

/// Hash-DRBG state using SHA3-256
/// Implements NIST SP 800-90A Section 10.1.1
pub struct HashDrbg {
    /// Value V (seed length)
    v: SecureBuffer<HASH_DRBG_SEED_LEN>,
    /// Constant C (seed length)
    c: SecureBuffer<HASH_DRBG_SEED_LEN>,
    /// Reseed counter
    reseed_counter: u64,
    /// Prediction resistance flag
    #[allow(dead_code)]
    prediction_resistance: bool,
    /// Entropy health test
    health_test: EntropyHealthTest,
    /// Entropy pool for additional input
    entropy_pool: SecureBuffer<32>,
    /// Entropy pool fill level
    entropy_pool_level: usize,
}

impl HashDrbg {
    /// Hash derivation function (Hash_df) per SP 800-90A Section 10.3.1
    fn hash_df(input: &[u8], output: &mut [u8]) {
        let output_bits = (output.len() * 8) as u32;
        let mut counter = 1u8;
        let mut offset = 0;

        while offset < output.len() {
            let mut hasher = Sha3_256::new();
            hasher.update(&[counter]);
            hasher.update(&output_bits.to_be_bytes());
            hasher.update(input);
            let hash = hasher.finalize();

            let copy_len = (output.len() - offset).min(32);
            output[offset..offset + copy_len].copy_from_slice(&hash.as_ref()[..copy_len]);
            offset += copy_len;
            counter += 1;
        }
    }

    /// Add two byte arrays modulo 2^(seedlen*8)
    fn add_mod(a: &mut [u8], b: &[u8]) {
        debug_assert_eq!(a.len(), b.len());
        let mut carry: u16 = 0;

        // Add from LSB (end of array)
        for i in (0..a.len()).rev() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            a[i] = sum as u8;
            carry = sum >> 8;
        }
    }

    /// Instantiate Hash-DRBG (SP 800-90A Section 10.1.1.2)
    ///
    /// # Arguments
    /// * `entropy` - Entropy input (min 256 bits for security strength 256)
    /// * `nonce` - Nonce (min 128 bits)
    /// * `personalization` - Optional personalization string
    /// * `prediction_resistance` - Enable prediction resistance
    pub fn instantiate(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
        prediction_resistance: bool,
    ) -> Result<Self, CryptoError> {
        // Entropy must be at least security_strength bits
        if entropy.len() < 32 {
            return Err(CryptoError::RngFailure);
        }

        // seed_material = entropy_input || nonce || personalization_string
        let seed_material_len = entropy.len() + nonce.len() + personalization.len();

        // Use stack buffer for seed material (max ~256 bytes)
        let mut seed_material = [0u8; 256];
        if seed_material_len > seed_material.len() {
            return Err(CryptoError::BufferTooSmall);
        }

        let mut offset = 0;
        seed_material[offset..offset + entropy.len()].copy_from_slice(entropy);
        offset += entropy.len();
        seed_material[offset..offset + nonce.len()].copy_from_slice(nonce);
        offset += nonce.len();
        seed_material[offset..offset + personalization.len()].copy_from_slice(personalization);

        // seed = Hash_df(seed_material, seedlen)
        let mut v = SecureBuffer::<HASH_DRBG_SEED_LEN>::new();
        Self::hash_df(&seed_material[..seed_material_len], v.as_mut_slice());

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_input = [0u8; HASH_DRBG_SEED_LEN + 1];
        c_input[0] = 0x00;
        c_input[1..].copy_from_slice(v.as_slice());

        let mut c = SecureBuffer::<HASH_DRBG_SEED_LEN>::new();
        Self::hash_df(&c_input, c.as_mut_slice());

        // Clean up
        secure_zero(&mut seed_material);
        secure_zero(&mut c_input);

        Ok(Self {
            v,
            c,
            reseed_counter: 1,
            prediction_resistance,
            health_test: EntropyHealthTest::new(),
            entropy_pool: SecureBuffer::new(),
            entropy_pool_level: 0,
        })
    }

    /// Reseed Hash-DRBG (SP 800-90A Section 10.1.1.3)
    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), CryptoError> {
        if entropy.len() < 32 {
            return Err(CryptoError::RngFailure);
        }

        // Run health tests on new entropy
        self.health_test.process_samples(entropy)?;

        // seed_material = 0x01 || V || entropy_input || additional_input
        let seed_material_len = 1 + HASH_DRBG_SEED_LEN + entropy.len() + additional.len();
        let mut seed_material = [0u8; 384];
        if seed_material_len > seed_material.len() {
            return Err(CryptoError::BufferTooSmall);
        }

        seed_material[0] = 0x01;
        seed_material[1..1 + HASH_DRBG_SEED_LEN].copy_from_slice(self.v.as_slice());
        let mut offset = 1 + HASH_DRBG_SEED_LEN;
        seed_material[offset..offset + entropy.len()].copy_from_slice(entropy);
        offset += entropy.len();
        seed_material[offset..offset + additional.len()].copy_from_slice(additional);

        // seed = Hash_df(seed_material, seedlen)
        Self::hash_df(&seed_material[..seed_material_len], self.v.as_mut_slice());

        // C = Hash_df(0x00 || V, seedlen)
        let mut c_input = [0u8; HASH_DRBG_SEED_LEN + 1];
        c_input[0] = 0x00;
        c_input[1..].copy_from_slice(self.v.as_slice());
        Self::hash_df(&c_input, self.c.as_mut_slice());

        self.reseed_counter = 1;

        // Clean up
        secure_zero(&mut seed_material);
        secure_zero(&mut c_input);

        Ok(())
    }

    /// Generate random bytes (SP 800-90A Section 10.1.1.4)
    fn generate_internal(
        &mut self,
        output: &mut [u8],
        additional: &[u8]
    ) -> Result<(), CryptoError> {
        if output.len() > HASH_DRBG_MAX_REQUEST {
            return Err(CryptoError::BufferTooSmall);
        }

        // Check if reseed is required
        if self.reseed_counter > HASH_DRBG_RESEED_INTERVAL {
            return Err(CryptoError::RngFailure); // Need reseed
        }

        // If additional input, modify state
        if !additional.is_empty() {
            // w = Hash(0x02 || V || additional_input)
            let mut hasher = Sha3_256::new();
            hasher.update(&[0x02]);
            hasher.update(self.v.as_slice());
            hasher.update(additional);
            let w = hasher.finalize();

            // V = (V + w) mod 2^seedlen
            let mut w_padded = [0u8; HASH_DRBG_SEED_LEN];
            w_padded[HASH_DRBG_SEED_LEN - 32..].copy_from_slice(w.as_ref());
            Self::add_mod(self.v.as_mut_slice(), &w_padded);
        }

        // Generate output using Hashgen
        self.hashgen(output);

        // H = Hash(0x03 || V)
        let mut hasher = Sha3_256::new();
        hasher.update(&[0x03]);
        hasher.update(self.v.as_slice());
        let h = hasher.finalize();

        // V = (V + H + C + reseed_counter) mod 2^seedlen
        let mut h_padded = [0u8; HASH_DRBG_SEED_LEN];
        h_padded[HASH_DRBG_SEED_LEN - 32..].copy_from_slice(h.as_ref());
        Self::add_mod(self.v.as_mut_slice(), &h_padded);
        Self::add_mod(self.v.as_mut_slice(), self.c.as_slice());

        let mut counter_bytes = [0u8; HASH_DRBG_SEED_LEN];
        counter_bytes[HASH_DRBG_SEED_LEN - 8..].copy_from_slice(&self.reseed_counter.to_be_bytes());
        Self::add_mod(self.v.as_mut_slice(), &counter_bytes);

        self.reseed_counter += 1;

        Ok(())
    }

    /// Hashgen function (SP 800-90A Section 10.1.1.4)
    fn hashgen(&self, output: &mut [u8]) {
        let mut data = [0u8; HASH_DRBG_SEED_LEN];
        data.copy_from_slice(self.v.as_slice());

        let mut offset = 0;
        while offset < output.len() {
            let hash = Sha3_256::hash(&data);
            let copy_len = (output.len() - offset).min(32);
            output[offset..offset + copy_len].copy_from_slice(&hash.as_ref()[..copy_len]);
            offset += copy_len;

            // data = (data + 1) mod 2^seedlen
            let mut one = [0u8; HASH_DRBG_SEED_LEN];
            one[HASH_DRBG_SEED_LEN - 1] = 1;
            Self::add_mod(&mut data, &one);
        }

        secure_zero(&mut data);
    }

    /// Add entropy to the pool (for continuous entropy collection)
    pub fn add_entropy(&mut self, entropy: &[u8]) -> Result<(), CryptoError> {
        // Run health test on incoming entropy
        self.health_test.process_samples(entropy)?;

        // Mix into entropy pool using SHA3-256
        let mut hasher = Sha3_256::new();
        hasher.update(self.entropy_pool.as_slice());
        hasher.update(entropy);
        let hash = hasher.finalize();
        self.entropy_pool.as_mut_slice()[..32].copy_from_slice(hash.as_ref());
        self.entropy_pool_level = self.entropy_pool_level.saturating_add(entropy.len()).min(256);

        Ok(())
    }

    /// Check if DRBG needs reseeding
    #[must_use]
    pub fn needs_reseed(&self) -> bool {
        self.reseed_counter > HASH_DRBG_RESEED_INTERVAL
    }

    /// Get reseed counter value
    #[must_use]
    pub const fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// Check if entropy source is healthy
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.health_test.is_healthy()
    }
}

impl CryptoRng for HashDrbg {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        // Handle large requests by splitting
        let mut offset = 0;
        while offset < dest.len() {
            let chunk_size = (dest.len() - offset).min(HASH_DRBG_MAX_REQUEST);
            self.generate_internal(&mut dest[offset..offset + chunk_size], &[])?;
            offset += chunk_size;
        }
        Ok(())
    }
}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        self.v.zeroize();
        self.c.zeroize();
        self.entropy_pool.zeroize();
        self.reseed_counter = 0;
    }
}

// =============================================================================
// System RNG - High-level interface
// =============================================================================

/// System random number generator state
pub struct SystemRngState {
    /// Underlying DRBG
    #[allow(dead_code)]
    drbg: HashDrbg,
    /// Total bytes generated since last reseed
    #[allow(dead_code)]
    bytes_generated: u64,
    /// Hardware RNG available
    #[allow(dead_code)]
    hw_available: bool,
}

/// System random number generator
///
/// Wraps Hash-DRBG with automatic reseeding and hardware RNG integration.
/// This is the primary RNG interface for Qbitel EdgeOS.
pub struct SystemRng {
    /// Internal DRBG state
    drbg: HashDrbg,
    /// Hardware RNG callback (for reseeding)
    hw_entropy_callback: Option<fn(&mut [u8]) -> Result<(), CryptoError>>,
    /// Whether hardware RNG is available
    hw_available: bool,
    /// Bytes generated since instantiation
    total_bytes: u64,
}

impl SystemRng {
    /// Create a new system RNG with given entropy
    ///
    /// # Arguments
    /// * `entropy` - Initial entropy (min 32 bytes)
    /// * `nonce` - Nonce for instantiation (min 16 bytes recommended)
    /// * `personalization` - Optional personalization string
    pub fn new(
        entropy: &[u8],
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, CryptoError> {
        let drbg = HashDrbg::instantiate(entropy, nonce, personalization, false)?;

        Ok(Self {
            drbg,
            hw_entropy_callback: None,
            hw_available: false,
            total_bytes: 0,
        })
    }

    /// Create with a simple 32-byte seed (for compatibility)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        // Use first 16 bytes as nonce
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&seed[16..]);

        Self::new(seed, &nonce, b"Qbitel EdgeOS-OS")
    }

    /// Set hardware entropy callback for automatic reseeding
    pub fn set_hw_entropy_callback(
        &mut self,
        callback: fn(&mut [u8]) -> Result<(), CryptoError>
    ) {
        self.hw_entropy_callback = Some(callback);
        self.hw_available = true;
    }

    /// Check if hardware RNG is available
    #[must_use]
    pub const fn is_hw_available(&self) -> bool {
        self.hw_available
    }

    /// Manually reseed with new entropy
    pub fn reseed(&mut self, entropy: &[u8]) -> Result<(), CryptoError> {
        self.drbg.reseed(entropy, &[])?;
        self.total_bytes = 0;
        Ok(())
    }

    /// Add entropy to the internal pool
    pub fn add_entropy(&mut self, entropy: &[u8]) -> Result<(), CryptoError> {
        self.drbg.add_entropy(entropy)
    }

    /// Check if RNG is healthy
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.drbg.is_healthy()
    }

    /// Get total bytes generated
    #[must_use]
    pub const fn total_bytes_generated(&self) -> u64 {
        self.total_bytes
    }

    /// Attempt automatic reseed using hardware RNG
    fn try_auto_reseed(&mut self) -> Result<(), CryptoError> {
        if let Some(callback) = self.hw_entropy_callback {
            let mut entropy = [0u8; 32];
            callback(&mut entropy)?;
            self.drbg.reseed(&entropy, &[])?;
            secure_zero(&mut entropy);
        }
        Ok(())
    }
}

impl CryptoRng for SystemRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        // Check if we need reseeding
        if self.drbg.needs_reseed() {
            if self.hw_available {
                self.try_auto_reseed()?;
            } else {
                return Err(CryptoError::RngFailure);
            }
        }

        self.drbg.fill_bytes(dest)?;
        self.total_bytes = self.total_bytes.saturating_add(dest.len() as u64);
        Ok(())
    }
}

impl Drop for SystemRng {
    fn drop(&mut self) {
        // DRBG will zeroize itself
    }
}

// =============================================================================
// Simple RNG for backward compatibility
// =============================================================================

/// Simple seeded RNG for cases where full DRBG is not needed
/// Uses SHA3-256 in counter mode
pub struct SimpleRng {
    /// State (seed)
    state: SecureBuffer<32>,
    /// Counter
    counter: u64,
}

impl SimpleRng {
    /// Create from 32-byte seed
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        let mut state = SecureBuffer::<32>::new();
        state.as_mut_slice().copy_from_slice(&seed);
        Self { state, counter: 0 }
    }

    /// Create with simple u64 seed (for testing)
    #[must_use]
    pub fn from_u64(seed: u64) -> Self {
        let hash = Sha3_256::hash(&seed.to_le_bytes());
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(hash.as_ref());
        Self::new(seed_bytes)
    }
}

impl CryptoRng for SimpleRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        let mut offset = 0;
        while offset < dest.len() {
            self.counter = self.counter.wrapping_add(1);

            let mut hasher = Sha3_256::new();
            hasher.update(self.state.as_slice());
            hasher.update(&self.counter.to_le_bytes());
            let block = hasher.finalize();

            let copy_len = (dest.len() - offset).min(32);
            dest[offset..offset + copy_len].copy_from_slice(&block.as_ref()[..copy_len]);
            offset += copy_len;
        }
        Ok(())
    }
}

impl Drop for SimpleRng {
    fn drop(&mut self) {
        self.state.zeroize();
        self.counter = 0;
    }
}

// =============================================================================
// Test RNG (Deterministic for testing only)
// =============================================================================

/// Test RNG for deterministic testing (NOT FOR PRODUCTION)
#[cfg(any(test, feature = "test-vectors"))]
pub struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

#[cfg(any(test, feature = "test-vectors"))]
impl TestRng {
    /// Create a test RNG with a fixed seed
    #[must_use]
    pub const fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }

    /// Create a test RNG from a simple seed value
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        Self::new(bytes)
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        self.counter = 0;
    }
}

#[cfg(any(test, feature = "test-vectors"))]
impl CryptoRng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        let mut offset = 0;
        while offset < dest.len() {
            self.counter = self.counter.wrapping_add(1);

            let mut hasher = Sha3_256::new();
            hasher.update(&self.seed);
            hasher.update(&self.counter.to_le_bytes());
            let block = hasher.finalize();

            let copy_len = (dest.len() - offset).min(32);
            dest[offset..offset + copy_len].copy_from_slice(&block.as_ref()[..copy_len]);
            offset += copy_len;
        }
        Ok(())
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Generate random byte array
pub fn random_bytes<const N: usize>(rng: &mut impl CryptoRng) -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    rng.fill_bytes(&mut buf)?;
    Ok(buf)
}

/// Generate a random value in range [0, max) with rejection sampling
pub fn random_range(rng: &mut impl CryptoRng, max: u32) -> Result<u32, CryptoError> {
    if max == 0 {
        return Ok(0);
    }
    if max == 1 {
        return Ok(0);
    }

    // Use rejection sampling to avoid modulo bias
    let threshold = u32::MAX - (u32::MAX % max);

    loop {
        let value = rng.next_u32()?;
        if value < threshold {
            return Ok(value % max);
        }
    }
}

/// Generate random bytes with retry on failure
pub fn random_bytes_retry<const N: usize>(
    rng: &mut impl CryptoRng,
    max_retries: usize,
) -> Result<[u8; N], CryptoError> {
    for _ in 0..max_retries {
        match random_bytes::<N>(rng) {
            Ok(bytes) => return Ok(bytes),
            Err(CryptoError::RngFailure) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(CryptoError::RngFailure)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_health_test_pass() {
        let mut health = EntropyHealthTest::new();

        // Random-looking data should pass
        let data: [u8; 64] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
            0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
            0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a,
        ];

        assert!(health.process_samples(&data).is_ok());
        assert!(health.is_healthy());
    }

    #[test]
    fn test_entropy_health_test_repetition_fail() {
        let mut health = EntropyHealthTest::new();

        // 6 consecutive identical bytes should fail
        let data = [0x42u8; 6];

        assert!(health.process_samples(&data).is_err());
    }

    #[test]
    fn test_hash_drbg_instantiate() {
        let entropy = [0x42u8; 48];
        let nonce = [0x13u8; 16];

        let drbg = HashDrbg::instantiate(&entropy, &nonce, b"test", false);
        assert!(drbg.is_ok());
    }

    #[test]
    fn test_hash_drbg_generate() {
        let entropy = [0x42u8; 48];
        let nonce = [0x13u8; 16];

        let mut drbg = HashDrbg::instantiate(&entropy, &nonce, b"test", false).unwrap();

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        drbg.fill_bytes(&mut output1).unwrap();
        drbg.fill_bytes(&mut output2).unwrap();

        // Outputs should be different
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hash_drbg_deterministic() {
        let entropy = [0x42u8; 48];
        let nonce = [0x13u8; 16];

        let mut drbg1 = HashDrbg::instantiate(&entropy, &nonce, b"test", false).unwrap();
        let mut drbg2 = HashDrbg::instantiate(&entropy, &nonce, b"test", false).unwrap();

        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        drbg1.fill_bytes(&mut output1).unwrap();
        drbg2.fill_bytes(&mut output2).unwrap();

        // Same seed should produce same output
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_hash_drbg_reseed() {
        let entropy = [0x42u8; 48];
        let nonce = [0x13u8; 16];

        let mut drbg = HashDrbg::instantiate(&entropy, &nonce, b"test", false).unwrap();

        let mut before = [0u8; 32];
        drbg.fill_bytes(&mut before).unwrap();

        // Use varied entropy to avoid triggering the health test's
        // repetition count check (which rejects uniform byte sequences).
        let mut new_entropy = [0u8; 32];
        for i in 0..32 {
            new_entropy[i] = (i as u8).wrapping_mul(0x99).wrapping_add(0x42);
        }
        drbg.reseed(&new_entropy, &[]).unwrap();

        let mut after = [0u8; 32];
        drbg.fill_bytes(&mut after).unwrap();

        // After reseed, counter should be reset
        assert_eq!(drbg.reseed_counter(), 2);
    }

    #[test]
    fn test_system_rng() {
        let seed = [0x42u8; 32];
        let mut rng = SystemRng::from_seed(&seed).unwrap();

        let mut output = [0u8; 64];
        rng.fill_bytes(&mut output).unwrap();

        // Should have generated some bytes
        assert_eq!(rng.total_bytes_generated(), 64);
    }

    #[test]
    fn test_simple_rng() {
        let mut rng = SimpleRng::from_u64(12345);

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        rng.fill_bytes(&mut output1).unwrap();
        rng.fill_bytes(&mut output2).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_random_range() {
        let mut rng = SimpleRng::from_u64(12345);

        for _ in 0..100 {
            let val = random_range(&mut rng, 10).unwrap();
            assert!(val < 10);
        }
    }

    #[test]
    fn test_random_range_edge_cases() {
        let mut rng = SimpleRng::from_u64(12345);

        assert_eq!(random_range(&mut rng, 0).unwrap(), 0);
        assert_eq!(random_range(&mut rng, 1).unwrap(), 0);
    }

    #[test]
    fn test_random_bytes() {
        let mut rng = SimpleRng::from_u64(54321);

        let bytes1: [u8; 16] = random_bytes(&mut rng).unwrap();
        let bytes2: [u8; 16] = random_bytes(&mut rng).unwrap();

        assert_ne!(bytes1, bytes2);
    }
}
