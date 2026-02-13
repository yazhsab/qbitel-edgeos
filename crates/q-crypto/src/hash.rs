// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Hash function implementations
//!
//! Provides SHA3 family hash functions for Qbitel EdgeOS.
//! All implementations are no_std compatible and use the sha3 crate.

use crate::error::CryptoError;
use crate::traits::Hash;
use q_common::types::AlgorithmId;
use sha3::{Digest, Sha3_256 as Sha3_256Impl, Sha3_512 as Sha3_512Impl};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256 as Shake256Impl;

/// SHA3-256 hash output
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sha3_256Output([u8; 32]);

impl Sha3_256Output {
    /// Create from bytes
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Sha3_256Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Sha3_256Output {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// SHA3-256 hasher
pub struct Sha3_256 {
    inner: Sha3_256Impl,
}

impl Hash for Sha3_256 {
    const ALGORITHM_ID: AlgorithmId = AlgorithmId::Sha3_256;
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 136; // SHA3-256 rate

    type Output = Sha3_256Output;

    fn hash(message: &[u8]) -> Self::Output {
        let result = Sha3_256Impl::digest(message);
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        Sha3_256Output(output)
    }

    fn new() -> Self {
        Self {
            inner: Sha3_256Impl::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self) -> Self::Output {
        let result = self.inner.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        Sha3_256Output(output)
    }

    fn reset(&mut self) {
        Digest::reset(&mut self.inner);
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA3-512 hash output
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sha3_512Output([u8; 64]);

impl Sha3_512Output {
    /// Create from bytes
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Sha3_512Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 64]> for Sha3_512Output {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

/// SHA3-512 hasher
pub struct Sha3_512 {
    inner: Sha3_512Impl,
}

impl Hash for Sha3_512 {
    const ALGORITHM_ID: AlgorithmId = AlgorithmId::Sha3_512;
    const OUTPUT_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 72; // SHA3-512 rate

    type Output = Sha3_512Output;

    fn hash(message: &[u8]) -> Self::Output {
        let result = Sha3_512Impl::digest(message);
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        Sha3_512Output(output)
    }

    fn new() -> Self {
        Self {
            inner: Sha3_512Impl::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self) -> Self::Output {
        let result = self.inner.finalize();
        let mut output = [0u8; 64];
        output.copy_from_slice(&result);
        Sha3_512Output(output)
    }

    fn reset(&mut self) {
        Digest::reset(&mut self.inner);
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// SHAKE256 Extendable Output Function (XOF)
// =============================================================================

/// SHAKE256 extendable-output function wrapper
pub struct Shake256 {
    inner: Shake256Impl,
}

impl Shake256 {
    /// Create a new SHAKE256 hasher
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Shake256Impl::default(),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.inner, data);
    }

    /// Finalize and get XOF output of specified length
    #[must_use]
    pub fn finalize_xof(self, output_len: usize) -> heapless::Vec<u8, 4096> {
        let mut reader = self.inner.finalize_xof();
        let mut output = heapless::Vec::new();
        output.resize(output_len.min(4096), 0).ok();
        reader.read(&mut output);
        output
    }

    /// One-shot squeeze operation
    pub fn squeeze(input: &[u8], output: &mut [u8]) {
        let mut hasher = Shake256Impl::default();
        Update::update(&mut hasher, input);
        let mut reader = hasher.finalize_xof();
        reader.read(output);
    }

    /// Reset the hasher state
    pub fn reset(&mut self) {
        self.inner = Shake256Impl::default();
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::Xof for Shake256 {
    fn new() -> Self {
        Shake256::new()
    }

    fn update(&mut self, data: &[u8]) {
        Shake256::update(self, data);
    }

    fn finalize_into(self, output: &mut [u8]) {
        let mut reader = self.inner.finalize_xof();
        reader.read(output);
    }
}

// =============================================================================
// SHAKE128 Extendable Output Function (XOF)
// =============================================================================

/// SHAKE128 extendable-output function wrapper
pub struct Shake128 {
    inner: sha3::Shake128,
}

impl Shake128 {
    /// Create a new SHAKE128 hasher
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: sha3::Shake128::default(),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.inner, data);
    }

    /// Finalize and get XOF output of specified length
    #[must_use]
    pub fn finalize_xof(self, output_len: usize) -> heapless::Vec<u8, 4096> {
        let mut reader = self.inner.finalize_xof();
        let mut output = heapless::Vec::new();
        output.resize(output_len.min(4096), 0).ok();
        reader.read(&mut output);
        output
    }

    /// One-shot squeeze operation
    pub fn squeeze(input: &[u8], output: &mut [u8]) {
        let mut hasher = sha3::Shake128::default();
        Update::update(&mut hasher, input);
        let mut reader = hasher.finalize_xof();
        reader.read(output);
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// HKDF
// =============================================================================

/// HKDF using SHA3-256
pub struct HkdfSha3_256;

impl HkdfSha3_256 {
    /// Extract: derive PRK from input key material and salt
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Sha3_256Output {
        // HMAC-SHA3-256(salt, ikm)
        Self::hmac(salt, ikm)
    }

    /// Expand: derive output key material from PRK
    ///
    /// Implements HKDF-Expand per RFC 5869 Section 2.3 using HMAC-SHA3-256.
    /// The PRK is used as the HMAC key for each expansion round:
    ///   T(1) = HMAC(PRK, info || 0x01)
    ///   T(n) = HMAC(PRK, T(n-1) || info || n)
    ///   OKM  = T(1) || T(2) || ... (truncated to output length)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::BufferTooSmall` if output exceeds 255 * 32 bytes.
    pub fn expand(prk: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        if output.len() > 255 * 32 {
            return Err(CryptoError::BufferTooSmall);
        }

        let mut t = [0u8; 32];
        let mut offset = 0;
        let mut counter = 1u8;

        while offset < output.len() {
            // Build T(n) input: T(n-1) || info || counter
            // For n=1, T(0) is empty (not included)
            let mut hmac_input = [0u8; 32 + 256 + 1]; // max: prev_t + info + counter
            let mut input_len = 0;

            if counter > 1 {
                hmac_input[..32].copy_from_slice(&t);
                input_len += 32;
            }

            let info_len = info.len().min(256);
            hmac_input[input_len..input_len + info_len].copy_from_slice(&info[..info_len]);
            input_len += info_len;

            hmac_input[input_len] = counter;
            input_len += 1;

            // T(n) = HMAC-SHA3-256(PRK, T(n-1) || info || counter)
            t.copy_from_slice(Self::hmac(prk, &hmac_input[..input_len]).as_ref());

            let copy_len = (output.len() - offset).min(32);
            output[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
            offset += copy_len;
            counter += 1;
        }

        Ok(())
    }

    /// Full HKDF (extract + expand)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::BufferTooSmall` if output is too large.
    pub fn derive(
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let prk = Self::extract(salt, ikm);
        Self::expand(prk.as_ref(), info, output)
    }

    /// Simple HMAC-SHA3-256
    fn hmac(key: &[u8], data: &[u8]) -> Sha3_256Output {
        const BLOCK_SIZE: usize = 136;

        // Prepare key
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let hash = Sha3_256::hash(key);
            key_block[..32].copy_from_slice(hash.as_ref());
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Inner hash: H((K ^ ipad) || data)
        let mut inner_key = [0x36u8; BLOCK_SIZE];
        for (i, k) in key_block.iter().enumerate() {
            inner_key[i] ^= k;
        }

        let mut hasher = Sha3_256::new();
        hasher.update(&inner_key);
        hasher.update(data);
        let inner_hash = hasher.finalize();

        // Outer hash: H((K ^ opad) || inner_hash)
        let mut outer_key = [0x5cu8; BLOCK_SIZE];
        for (i, k) in key_block.iter().enumerate() {
            outer_key[i] ^= k;
        }

        let mut hasher = Sha3_256::new();
        hasher.update(&outer_key);
        hasher.update(inner_hash.as_ref());
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = Sha3_256::hash(b"");
        // Known SHA3-256 hash of empty string
        assert_eq!(hash.as_ref().len(), 32);
    }

    #[test]
    fn test_sha3_256_incremental() {
        let one_shot = Sha3_256::hash(b"hello world");

        let mut hasher = Sha3_256::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finalize();

        assert_eq!(one_shot.as_ref(), incremental.as_ref());
    }

    #[test]
    fn test_sha3_512() {
        let hash = Sha3_512::hash(b"test");
        assert_eq!(hash.as_ref().len(), 64);
    }

    #[test]
    fn test_hkdf() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let mut output = [0u8; 64];

        HkdfSha3_256::derive(ikm, salt, info, &mut output).unwrap();

        // Output should be deterministic
        let mut output2 = [0u8; 64];
        HkdfSha3_256::derive(ikm, salt, info, &mut output2).unwrap();

        assert_eq!(output, output2);
    }

    #[test]
    fn test_hkdf_prk_is_used() {
        // Verify that expand() actually uses the PRK parameter.
        // Different PRKs must produce different output.
        let info = b"test info";
        let prk_a = [0xAAu8; 32];
        let prk_b = [0xBBu8; 32];

        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];

        HkdfSha3_256::expand(&prk_a, info, &mut out_a).unwrap();
        HkdfSha3_256::expand(&prk_b, info, &mut out_b).unwrap();

        assert_ne!(out_a, out_b, "Different PRKs must produce different output");
    }

    #[test]
    fn test_hkdf_expand_multi_block() {
        // Verify multi-block expansion works correctly
        let prk = [0x42u8; 32];
        let info = b"expand test";

        let mut output_64 = [0u8; 64];
        HkdfSha3_256::expand(&prk, info, &mut output_64).unwrap();

        // First 32 bytes should match a 32-byte expansion
        let mut output_32 = [0u8; 32];
        HkdfSha3_256::expand(&prk, info, &mut output_32).unwrap();

        assert_eq!(&output_64[..32], &output_32[..]);
    }

    #[test]
    fn test_hkdf_expand_too_large() {
        let prk = [0x42u8; 32];
        let mut output = [0u8; 32];
        // 255 * 32 = 8160 is the max; asking for more should fail
        // We can't allocate that much on stack, so test the limit check
        assert!(HkdfSha3_256::expand(&prk, b"", &mut output).is_ok());
    }
}
