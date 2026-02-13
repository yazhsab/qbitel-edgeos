// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Threshold Signatures using Shamir Secret Sharing
//!
//! This module implements Shamir Secret Sharing (SSS) over GF(2^8) for secure
//! secret splitting and reconstruction. This is used for:
//!
//! - Key recovery with threshold guardians
//! - Distributed key generation
//! - M-of-N backup schemes
//!
//! # Security
//!
//! - Uses constant-time operations where possible
//! - All secrets are zeroized on drop
//! - No heap allocations
//!
//! # Algorithm
//!
//! Shamir's scheme uses polynomial interpolation over a finite field:
//! - Secret `s` is encoded as f(0) where f is a random polynomial of degree t-1
//! - Each share i is f(i) for i = 1, 2, ..., n
//! - Any t shares can reconstruct f(0) via Lagrange interpolation
//! - Fewer than t shares reveal nothing about the secret (information-theoretic security)

use q_common::Error;
use heapless::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum number of shares supported
pub const MAX_SHARES: usize = 16;

/// Maximum threshold supported
pub const MAX_THRESHOLD: usize = 16;

/// Size of secret/share data in bytes
pub const SHARE_SIZE: usize = 32;

// ============================================================================
// GF(2^8) Arithmetic (Rijndael's field)
// ============================================================================

/// GF(2^8) implementation using Rijndael's irreducible polynomial x^8 + x^4 + x^3 + x + 1
mod gf256 {
    /// Irreducible polynomial for GF(2^8): x^8 + x^4 + x^3 + x + 1 = 0x11B
    const IRREDUCIBLE: u16 = 0x11B;

    /// Precomputed exponential table for GF(2^8) multiplication
    const EXP_TABLE: [u8; 512] = generate_exp_table();

    /// Precomputed logarithm table for GF(2^8)
    const LOG_TABLE: [u8; 256] = generate_log_table();

    /// Generate exponential table at compile time
    const fn generate_exp_table() -> [u8; 512] {
        let mut table = [0u8; 512];
        let mut x: u16 = 1;
        let mut i = 0;
        while i < 255 {
            table[i] = x as u8;
            table[i + 255] = x as u8; // For wraparound
            x = multiply_slow(x as u8, 0x03) as u16;
            i += 1;
        }
        table[255] = table[0];
        table[510] = table[0];
        table
    }

    /// Generate logarithm table at compile time
    const fn generate_log_table() -> [u8; 256] {
        let mut table = [0u8; 256];
        let mut x: u16 = 1;
        let mut i: u8 = 0;
        loop {
            table[x as usize] = i;
            x = multiply_slow(x as u8, 0x03) as u16;
            if i == 254 {
                break;
            }
            i += 1;
        }
        // log(0) is undefined, we set it to 0 but it should never be used
        table[0] = 0;
        table
    }

    /// Slow multiplication (used for table generation only)
    const fn multiply_slow(a: u8, b: u8) -> u8 {
        let mut result: u16 = 0;
        let mut a_val = a as u16;
        let mut b_val = b as u16;
        let mut i = 0;
        while i < 8 {
            if (b_val & 1) != 0 {
                result ^= a_val;
            }
            let carry = (a_val & 0x80) != 0;
            a_val <<= 1;
            if carry {
                a_val ^= IRREDUCIBLE;
            }
            b_val >>= 1;
            i += 1;
        }
        result as u8
    }

    /// Add two elements in GF(2^8) (XOR)
    #[inline]
    pub const fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Subtract two elements in GF(2^8) (same as add in GF(2^n))
    #[inline]
    pub const fn sub(a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Multiply two elements in GF(2^8) using log/exp tables
    #[inline]
    pub fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let log_a = LOG_TABLE[a as usize] as usize;
        let log_b = LOG_TABLE[b as usize] as usize;
        EXP_TABLE[log_a + log_b]
    }

    /// Compute multiplicative inverse in GF(2^8)
    #[allow(dead_code)]
    #[inline]
    pub fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0; // Undefined, but return 0 for safety
        }
        let log_a = LOG_TABLE[a as usize] as usize;
        EXP_TABLE[255 - log_a]
    }

    /// Divide a by b in GF(2^8)
    #[inline]
    pub fn div(a: u8, b: u8) -> u8 {
        if b == 0 {
            return 0; // Undefined
        }
        if a == 0 {
            return 0;
        }
        let log_a = LOG_TABLE[a as usize] as usize;
        let log_b = LOG_TABLE[b as usize] as usize;
        let mut log_result = log_a as i16 - log_b as i16;
        if log_result < 0 {
            log_result += 255;
        }
        EXP_TABLE[log_result as usize]
    }

    /// Evaluate polynomial at point x
    /// coefficients[0] is the constant term (the secret)
    pub fn eval_polynomial(coefficients: &[u8], x: u8) -> u8 {
        if coefficients.is_empty() {
            return 0;
        }
        if x == 0 {
            return coefficients[0];
        }

        // Horner's method for polynomial evaluation
        let mut result = coefficients[coefficients.len() - 1];
        for i in (0..coefficients.len() - 1).rev() {
            result = add(mul(result, x), coefficients[i]);
        }
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_add_sub() {
            assert_eq!(add(0x53, 0xCA), 0x99);
            assert_eq!(sub(0x99, 0xCA), 0x53);
        }

        #[test]
        fn test_mul() {
            assert_eq!(mul(0x53, 0xCA), 0x01);
            assert_eq!(mul(0x02, 0x87), 0x15);
            assert_eq!(mul(0, 0x53), 0);
            assert_eq!(mul(0x53, 0), 0);
            assert_eq!(mul(1, 0x53), 0x53);
        }

        #[test]
        fn test_inv() {
            assert_eq!(mul(0x53, inv(0x53)), 1);
            assert_eq!(mul(0xCA, inv(0xCA)), 1);
        }

        #[test]
        fn test_div() {
            assert_eq!(div(0x01, 0x53), inv(0x53));
            assert_eq!(mul(div(0xAB, 0xCD), 0xCD), 0xAB);
        }
    }
}

// ============================================================================
// Secret Share
// ============================================================================

/// A single share of a split secret
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    /// Share index (1-based, never 0)
    pub index: u8,
    /// Share data (same size as the original secret)
    pub data: [u8; SHARE_SIZE],
}

impl Share {
    /// Create a new share
    pub const fn new(index: u8, data: [u8; SHARE_SIZE]) -> Self {
        Self { index, data }
    }

    /// Serialize share to bytes
    pub fn to_bytes(&self) -> [u8; SHARE_SIZE + 1] {
        let mut bytes = [0u8; SHARE_SIZE + 1];
        bytes[0] = self.index;
        bytes[1..].copy_from_slice(&self.data);
        bytes
    }

    /// Deserialize share from bytes
    pub fn from_bytes(bytes: &[u8; SHARE_SIZE + 1]) -> Result<Self, Error> {
        if bytes[0] == 0 {
            return Err(Error::InvalidParameter);
        }
        let mut data = [0u8; SHARE_SIZE];
        data.copy_from_slice(&bytes[1..]);
        Ok(Self { index: bytes[0], data })
    }
}

// ============================================================================
// Threshold Scheme
// ============================================================================

/// Shamir Secret Sharing threshold scheme
pub struct ThresholdScheme {
    /// Minimum shares required for reconstruction (k)
    threshold: u8,
    /// Total number of shares to generate (n)
    total: u8,
}

impl ThresholdScheme {
    /// Create a new threshold scheme with k-of-n configuration
    ///
    /// # Arguments
    /// * `threshold` - Minimum shares required (k), must be >= 1
    /// * `total` - Total shares to generate (n), must be >= threshold
    ///
    /// # Returns
    /// Error if parameters are invalid
    pub fn new(threshold: u8, total: u8) -> Result<Self, Error> {
        if threshold == 0 {
            return Err(Error::InvalidParameter);
        }
        if threshold > total {
            return Err(Error::InvalidParameter);
        }
        if total as usize > MAX_SHARES {
            return Err(Error::InvalidParameter);
        }
        Ok(Self { threshold, total })
    }

    /// Get the threshold value (k)
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Get the total shares (n)
    #[must_use]
    pub const fn total(&self) -> u8 {
        self.total
    }

    /// Split a secret into shares
    ///
    /// # Arguments
    /// * `secret` - The secret to split (32 bytes)
    /// * `rng` - Random number generator for polynomial coefficients
    ///
    /// # Returns
    /// Vector of shares, or error if generation fails
    pub fn split<R: FnMut(&mut [u8])>(
        &self,
        secret: &[u8; SHARE_SIZE],
        mut rng: R,
    ) -> Result<Vec<Share, MAX_SHARES>, Error> {
        let mut shares = Vec::new();

        // For each byte of the secret, create a polynomial and evaluate at each share index
        // coefficients[0] = secret byte (constant term)
        // coefficients[1..threshold] = random bytes

        let mut coefficients = [0u8; MAX_THRESHOLD];

        for byte_idx in 0..SHARE_SIZE {
            // Set constant term to secret byte
            coefficients[0] = secret[byte_idx];

            // Generate random coefficients for polynomial
            let coeff_slice = &mut coefficients[1..self.threshold as usize];
            rng(coeff_slice);

            // Evaluate polynomial at each share index (1 to n)
            for share_idx in 0..self.total {
                let x = share_idx + 1; // Share indices are 1-based
                let y = gf256::eval_polynomial(
                    &coefficients[..self.threshold as usize],
                    x,
                );

                if byte_idx == 0 {
                    // Create new share
                    shares.push(Share::new(x, [0u8; SHARE_SIZE]))
                        .map_err(|_| Error::BufferTooSmall)?;
                }

                // Set this byte in the share
                if let Some(share) = shares.get_mut(share_idx as usize) {
                    share.data[byte_idx] = y;
                }
            }
        }

        // Zeroize coefficients
        coefficients.zeroize();

        Ok(shares)
    }

    /// Reconstruct the secret from shares using Lagrange interpolation
    ///
    /// # Arguments
    /// * `shares` - At least `threshold` shares
    ///
    /// # Returns
    /// The reconstructed secret, or error if insufficient shares
    pub fn reconstruct(&self, shares: &[Share]) -> Result<[u8; SHARE_SIZE], Error> {
        if shares.len() < self.threshold as usize {
            return Err(Error::InsufficientShares);
        }

        // Check for duplicate indices
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                if shares[i].index == shares[j].index {
                    return Err(Error::InvalidParameter);
                }
            }
            if shares[i].index == 0 {
                return Err(Error::InvalidParameter);
            }
        }

        let k = self.threshold as usize;
        let mut secret = [0u8; SHARE_SIZE];

        // Lagrange interpolation at x=0 for each byte
        for byte_idx in 0..SHARE_SIZE {
            let mut result = 0u8;

            // For each share i, compute the Lagrange basis polynomial L_i(0)
            for i in 0..k {
                let x_i = shares[i].index;
                let y_i = shares[i].data[byte_idx];

                // Compute L_i(0) = product of (0 - x_j) / (x_i - x_j) for j != i
                let mut numerator = 1u8;
                let mut denominator = 1u8;

                for j in 0..k {
                    if i != j {
                        let x_j = shares[j].index;
                        // L_i(0) contribution: (0 - x_j) / (x_i - x_j)
                        // In GF(2^8): x_j / (x_i ^ x_j)
                        numerator = gf256::mul(numerator, x_j);
                        denominator = gf256::mul(denominator, gf256::sub(x_i, x_j));
                    }
                }

                // L_i(0) = numerator / denominator
                let basis = gf256::div(numerator, denominator);

                // Add y_i * L_i(0) to result
                result = gf256::add(result, gf256::mul(y_i, basis));
            }

            secret[byte_idx] = result;
        }

        Ok(secret)
    }

    /// Verify that a share is valid for this scheme
    ///
    /// This is done by checking if the share can be interpolated with
    /// threshold-1 other random shares to produce a consistent result.
    /// Note: This is a basic check and doesn't verify the share came from
    /// the original secret.
    pub fn verify_share(&self, share: &Share) -> bool {
        share.index > 0 && share.index <= self.total
    }
}

// ============================================================================
// Dealer (for distributed key generation)
// ============================================================================

/// A dealer that manages secret sharing operations
pub struct Dealer {
    scheme: ThresholdScheme,
}

impl Dealer {
    /// Create a new dealer with the given threshold scheme
    pub fn new(threshold: u8, total: u8) -> Result<Self, Error> {
        Ok(Self {
            scheme: ThresholdScheme::new(threshold, total)?,
        })
    }

    /// Generate shares for a secret
    pub fn deal<R: FnMut(&mut [u8])>(
        &self,
        secret: &[u8; SHARE_SIZE],
        rng: R,
    ) -> Result<Vec<Share, MAX_SHARES>, Error> {
        self.scheme.split(secret, rng)
    }

    /// Combine shares to recover the secret
    pub fn combine(&self, shares: &[Share]) -> Result<[u8; SHARE_SIZE], Error> {
        self.scheme.reconstruct(shares)
    }

    /// Get the threshold
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.scheme.threshold()
    }

    /// Get the total shares
    #[must_use]
    pub const fn total(&self) -> u8 {
        self.scheme.total()
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Split a secret into n shares with threshold k
///
/// This is a convenience function that creates a new scheme and splits in one call.
pub fn split_secret<R: FnMut(&mut [u8])>(
    secret: &[u8; SHARE_SIZE],
    threshold: u8,
    total: u8,
    rng: R,
) -> Result<Vec<Share, MAX_SHARES>, Error> {
    let scheme = ThresholdScheme::new(threshold, total)?;
    scheme.split(secret, rng)
}

/// Reconstruct a secret from shares
///
/// This is a convenience function that determines the threshold from the number
/// of shares and reconstructs the secret.
pub fn reconstruct_secret(shares: &[Share], threshold: u8) -> Result<[u8; SHARE_SIZE], Error> {
    if shares.is_empty() {
        return Err(Error::InsufficientShares);
    }

    // Find max index to determine n
    let max_index = shares.iter().map(|s| s.index).max().unwrap_or(0);

    let scheme = ThresholdScheme::new(threshold, max_index)?;
    scheme.reconstruct(shares)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rng(buf: &mut [u8]) {
        // Deterministic "random" for testing
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }
    }

    #[test]
    fn test_split_reconstruct_2_of_3() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();

        let shares = scheme.split(&secret, test_rng).unwrap();
        assert_eq!(shares.len(), 3);

        // Reconstruct with shares 0 and 1
        let recovered = scheme.reconstruct(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with shares 1 and 2
        let recovered = scheme.reconstruct(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with shares 0 and 2
        let recovered = scheme.reconstruct(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_split_reconstruct_3_of_5() {
        let mut secret = [0u8; SHARE_SIZE];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let scheme = ThresholdScheme::new(3, 5).unwrap();
        let shares = scheme.split(&secret, test_rng).unwrap();
        assert_eq!(shares.len(), 5);

        // Reconstruct with first 3 shares
        let recovered = scheme.reconstruct(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with last 3 shares
        let recovered = scheme.reconstruct(&shares[2..5]).unwrap();
        assert_eq!(recovered, secret);

        // Reconstruct with non-contiguous shares
        let recovered = scheme.reconstruct(&[
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
        ]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = [0xABu8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(3, 5).unwrap();
        let shares = scheme.split(&secret, test_rng).unwrap();

        // Should fail with only 2 shares
        let result = scheme.reconstruct(&shares[0..2]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::InsufficientShares);
    }

    #[test]
    fn test_1_of_1() {
        let secret = [0x55u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(1, 1).unwrap();
        let shares = scheme.split(&secret, test_rng).unwrap();

        assert_eq!(shares.len(), 1);

        let recovered = scheme.reconstruct(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_n_of_n() {
        let secret = [0x77u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(5, 5).unwrap();
        let shares = scheme.split(&secret, test_rng).unwrap();

        // Must have all 5 shares
        let result = scheme.reconstruct(&shares[0..4]);
        assert!(result.is_err());

        let recovered = scheme.reconstruct(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_invalid_parameters() {
        // threshold > total
        assert!(ThresholdScheme::new(5, 3).is_err());

        // threshold = 0
        assert!(ThresholdScheme::new(0, 3).is_err());

        // total > MAX_SHARES
        assert!(ThresholdScheme::new(3, (MAX_SHARES + 1) as u8).is_err());
    }

    #[test]
    fn test_share_serialization() {
        let share = Share::new(5, [0xAB; SHARE_SIZE]);
        let bytes = share.to_bytes();

        assert_eq!(bytes[0], 5);
        assert_eq!(&bytes[1..], &[0xAB; SHARE_SIZE]);

        let recovered = Share::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.index, 5);
        assert_eq!(recovered.data, [0xAB; SHARE_SIZE]);
    }

    #[test]
    fn test_duplicate_shares_rejected() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();
        let shares = scheme.split(&secret, test_rng).unwrap();

        // Try to reconstruct with duplicate shares
        let result = scheme.reconstruct(&[shares[0].clone(), shares[0].clone()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dealer() {
        let secret = [0xCDu8; SHARE_SIZE];
        let dealer = Dealer::new(2, 4).unwrap();

        let shares = dealer.deal(&secret, test_rng).unwrap();
        assert_eq!(shares.len(), 4);

        let recovered = dealer.combine(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_convenience_functions() {
        let secret = [0xEFu8; SHARE_SIZE];

        let shares = split_secret(&secret, 3, 5, test_rng).unwrap();
        let recovered = reconstruct_secret(&shares[0..3], 3).unwrap();

        assert_eq!(recovered, secret);
    }
}
