// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Core cryptographic traits
//!
//! This module defines the abstract interfaces for all cryptographic operations.
//! These traits enable cryptographic agility - the ability to swap algorithms
//! without changing higher-level code.
//!
//! # Design Principles
//!
//! 1. **Constant-time**: All operations must be constant-time
//! 2. **Zeroization**: Secret data must be zeroized after use
//! 3. **Type safety**: Strong typing prevents algorithm confusion
//! 4. **no_std**: All traits are no_std compatible

use crate::error::CryptoError;
use q_common::types::{AlgorithmId, SecurityLevel};
use zeroize::Zeroize;

/// Key Encapsulation Mechanism (KEM) trait
///
/// KEMs are used to establish shared secrets between parties.
/// Qbitel EdgeOS primarily uses ML-KEM (Kyber) for post-quantum security.
///
/// # Security
///
/// - Secret keys must implement `Zeroize`
/// - Shared secrets must implement `Zeroize`
/// - All operations must be constant-time
pub trait Kem {
    /// Algorithm identifier for this KEM
    const ALGORITHM_ID: AlgorithmId;
    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;
    /// Secret key size in bytes
    const SECRET_KEY_SIZE: usize;
    /// Ciphertext size in bytes
    const CIPHERTEXT_SIZE: usize;
    /// Shared secret size in bytes
    const SHARED_SECRET_SIZE: usize;
    /// NIST security level
    const SECURITY_LEVEL: SecurityLevel;

    /// Public key type
    type PublicKey: AsRef<[u8]> + Clone;
    /// Secret key type (must be zeroizable)
    type SecretKey: AsRef<[u8]> + Zeroize;
    /// Ciphertext type
    type Ciphertext: AsRef<[u8]>;
    /// Shared secret type (must be zeroizable)
    type SharedSecret: AsRef<[u8]> + Zeroize;

    /// Generate a new key pair
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RngFailure` if the RNG fails.
    fn keypair<R: CryptoRng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;

    /// Encapsulate: create ciphertext and shared secret from public key
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the public key is invalid.
    fn encapsulate<R: CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError>;

    /// Decapsulate: recover shared secret from ciphertext
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::DecapsulationFailed` if decapsulation fails.
    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError>;
}

/// Digital Signature trait
///
/// Used for authentication and integrity verification.
/// Qbitel EdgeOS primarily uses ML-DSA (Dilithium) for post-quantum security.
///
/// # Security
///
/// - Secret keys must implement `Zeroize`
/// - Signing must be constant-time
/// - Verification should use constant-time comparison
pub trait Signer {
    /// Algorithm identifier for this signature scheme
    const ALGORITHM_ID: AlgorithmId;
    /// Public key size in bytes
    const PUBLIC_KEY_SIZE: usize;
    /// Secret key size in bytes
    const SECRET_KEY_SIZE: usize;
    /// Maximum signature size in bytes
    const SIGNATURE_SIZE: usize;
    /// NIST security level
    const SECURITY_LEVEL: SecurityLevel;

    /// Public key type
    type PublicKey: AsRef<[u8]> + Clone;
    /// Secret key type (must be zeroizable)
    type SecretKey: AsRef<[u8]> + Zeroize;
    /// Signature type
    type Signature: AsRef<[u8]>;

    /// Generate a new signing key pair
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RngFailure` if the RNG fails.
    fn keypair<R: CryptoRng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;

    /// Sign a message
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InternalError` if signing fails.
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature, CryptoError>;

    /// Verify a signature
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the public key is malformed.
    fn verify(
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, CryptoError>;
}

/// Hash function trait
///
/// Provides both one-shot and incremental hashing.
pub trait Hash: Sized {
    /// Algorithm identifier for this hash function
    const ALGORITHM_ID: AlgorithmId;
    /// Output size in bytes
    const OUTPUT_SIZE: usize;
    /// Block size in bytes (for HMAC)
    const BLOCK_SIZE: usize;

    /// Output type
    type Output: AsRef<[u8]> + Clone;

    /// Hash a message in one shot
    fn hash(message: &[u8]) -> Self::Output;

    /// Create a new incremental hasher
    fn new() -> Self;

    /// Update the hasher with data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the hash
    fn finalize(self) -> Self::Output;

    /// Reset the hasher for reuse
    fn reset(&mut self);
}

/// AEAD (Authenticated Encryption with Associated Data) trait
///
/// Used for symmetric encryption of data.
pub trait Aead {
    /// Algorithm identifier
    const ALGORITHM_ID: AlgorithmId;
    /// Key size in bytes
    const KEY_SIZE: usize;
    /// Nonce size in bytes
    const NONCE_SIZE: usize;
    /// Authentication tag size in bytes
    const TAG_SIZE: usize;

    /// Key type
    type Key: AsRef<[u8]> + Zeroize;
    /// Nonce type
    type Nonce: AsRef<[u8]>;

    /// Encrypt plaintext with associated data
    ///
    /// # Arguments
    ///
    /// * `key` - Encryption key
    /// * `nonce` - Unique nonce (never reuse with same key)
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Associated data (authenticated but not encrypted)
    /// * `ciphertext` - Output buffer (must be `plaintext.len() + TAG_SIZE`)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::BufferTooSmall` if output buffer is too small.
    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError>;

    /// Decrypt ciphertext with associated data
    ///
    /// # Arguments
    ///
    /// * `key` - Decryption key
    /// * `nonce` - Nonce used for encryption
    /// * `ciphertext` - Data to decrypt (including tag)
    /// * `aad` - Associated data
    /// * `plaintext` - Output buffer (must be `ciphertext.len() - TAG_SIZE`)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AuthenticationFailed` if authentication fails.
    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError>;
}

/// Cryptographically secure random number generator trait
pub trait CryptoRng {
    /// Fill buffer with random bytes
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RngFailure` if the RNG fails.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), CryptoError>;

    /// Generate a random u32
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RngFailure` if the RNG fails.
    fn next_u32(&mut self) -> Result<u32, CryptoError> {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Generate a random u64
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RngFailure` if the RNG fails.
    fn next_u64(&mut self) -> Result<u64, CryptoError> {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

/// Key derivation function trait
pub trait Kdf {
    /// Derive key material from input key material
    ///
    /// # Arguments
    ///
    /// * `ikm` - Input key material
    /// * `salt` - Optional salt (can be empty)
    /// * `info` - Optional context/application info
    /// * `output` - Output buffer for derived key
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KeyDerivationFailed` on failure.
    fn derive(
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError>;
}

/// Extendable Output Function (XOF) trait
///
/// XOFs like SHAKE128/SHAKE256 produce variable-length output.
pub trait Xof: Sized {
    /// Create a new XOF instance
    fn new() -> Self;

    /// Update the XOF with data
    fn update(&mut self, data: &[u8]);

    /// Finalize and produce output of specified length
    ///
    /// # Arguments
    ///
    /// * `output` - Buffer to fill with XOF output
    fn finalize_into(self, output: &mut [u8]);

    /// One-shot: absorb input and squeeze output
    fn squeeze(input: &[u8], output: &mut [u8]) {
        let mut xof = Self::new();
        xof.update(input);
        xof.finalize_into(output);
    }
}

/// Constant-time comparison
///
/// Compares two byte slices in constant time to prevent timing attacks.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
