// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! AEAD (Authenticated Encryption with Associated Data) for Qbitel EdgeOS
//!
//! This module provides production-quality authenticated encryption using:
//!
//! - **AES-256-GCM**: NIST approved, hardware acceleration on many platforms
//! - **ChaCha20-Poly1305**: Constant-time without hardware support
//!
//! # Security Features
//!
//! - Constant-time implementations (using RustCrypto crates)
//! - Nonce misuse resistance utilities
//! - Key wrapping for secure key storage
//! - Streaming mode for large data
//!
//! # Nonce Management
//!
//! **CRITICAL**: Never reuse a nonce with the same key. This module provides:
//! - `NonceSequence`: Counter-based nonce generation
//! - `SyntheticNonce`: Derive nonces from message content (SIV-like)
//!
//! # Example
//!
//! ```ignore
//! use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce, NonceSequence};
//! use q_crypto::traits::Aead;
//!
//! let key = Aes256Key::new([0u8; 32]);
//! let mut nonce_gen = NonceSequence::new([0u8; 4]);
//! let nonce = nonce_gen.next();
//!
//! let plaintext = b"secret message";
//! let mut ciphertext = [0u8; 64];
//! let len = Aes256Gcm::encrypt(&key, &nonce, plaintext, b"", &mut ciphertext)?;
//! ```

use crate::error::CryptoError;
use crate::traits::Aead;
use crate::hash::Sha3_256;
use crate::traits::Hash;
use crate::zeroize_utils::secure_zero;
use q_common::types::AlgorithmId;
use zeroize::{Zeroize, ZeroizeOnDrop};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm as Aes256GcmImpl, Nonce,
};

use chacha20poly1305::ChaCha20Poly1305 as ChaCha20Poly1305Cipher;

// =============================================================================
// AES-256-GCM Implementation
// =============================================================================

/// AES-256-GCM key (32 bytes)
///
/// This type wraps a 256-bit key and ensures it is securely zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Aes256Key([u8; 32]);

impl Aes256Key {
    /// Create a new key from bytes
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    ///
    /// Returns `None` if slice length is not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Generate a random key
    pub fn generate<R: crate::traits::CryptoRng>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl AsRef<[u8]> for Aes256Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// AES-GCM nonce (12 bytes / 96 bits)
///
/// **CRITICAL**: Never reuse a nonce with the same key.
/// Use `NonceSequence` for safe nonce generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AesGcmNonce([u8; 12]);

impl AesGcmNonce {
    /// Create a new nonce from bytes
    #[must_use]
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    ///
    /// Returns `None` if slice length is not exactly 12 bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 12 {
            return None;
        }
        let mut bytes = [0u8; 12];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Create a zero nonce (use only for counter-based schemes)
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 12])
    }

    /// Increment nonce by 1 (for counter mode)
    pub fn increment(&mut self) {
        for byte in self.0.iter_mut().rev() {
            let (new_val, overflow) = byte.overflowing_add(1);
            *byte = new_val;
            if !overflow {
                break;
            }
        }
    }
}

impl AsRef<[u8]> for AesGcmNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// AES-256-GCM AEAD implementation
///
/// Provides authenticated encryption using AES-256 in Galois/Counter Mode.
/// This is a NIST-approved algorithm suitable for protecting sensitive data.
///
/// # Security Properties
///
/// - **Confidentiality**: 256-bit security level
/// - **Authenticity**: 128-bit authentication tag
/// - **Performance**: Hardware acceleration on modern CPUs (AES-NI)
pub struct Aes256Gcm;

impl Aead for Aes256Gcm {
    const ALGORITHM_ID: AlgorithmId = AlgorithmId::Aes256Gcm;
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    type Key = Aes256Key;
    type Nonce = AesGcmNonce;

    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let required_len = plaintext.len() + Self::TAG_SIZE;
        if ciphertext.len() < required_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Copy plaintext to output buffer
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);

        // Create cipher instance
        let cipher = Aes256GcmImpl::new_from_slice(&key.0)
            .map_err(|_| CryptoError::InvalidKey)?;

        let gcm_nonce = Nonce::from_slice(&nonce.0);

        // Encrypt in place
        let tag = cipher
            .encrypt_in_place_detached(gcm_nonce, aad, &mut ciphertext[..plaintext.len()])
            .map_err(|_| CryptoError::InternalError)?;

        // Append tag
        ciphertext[plaintext.len()..required_len].copy_from_slice(&tag);

        Ok(required_len)
    }

    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if ciphertext.len() < Self::TAG_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        let plaintext_len = ciphertext.len() - Self::TAG_SIZE;
        if plaintext.len() < plaintext_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Create cipher instance
        let cipher = Aes256GcmImpl::new_from_slice(&key.0)
            .map_err(|_| CryptoError::InvalidKey)?;

        let gcm_nonce = Nonce::from_slice(&nonce.0);

        // Copy ciphertext (without tag) to plaintext buffer
        plaintext[..plaintext_len].copy_from_slice(&ciphertext[..plaintext_len]);

        // Extract tag
        let tag = aes_gcm::Tag::from_slice(&ciphertext[plaintext_len..]);

        // Decrypt in place
        cipher
            .decrypt_in_place_detached(gcm_nonce, aad, &mut plaintext[..plaintext_len], tag)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(plaintext_len)
    }
}

impl Aes256Gcm {
    /// Encrypt with automatic nonce generation
    ///
    /// Returns (ciphertext_with_tag, nonce) where the nonce is prepended.
    /// Output format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn encrypt_with_nonce<R: crate::traits::CryptoRng>(
        key: &Aes256Key,
        rng: &mut R,
        plaintext: &[u8],
        aad: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let required_len = 12 + plaintext.len() + 16;
        if output.len() < required_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Generate random nonce
        rng.fill_bytes(&mut output[..12])?;

        // Safety: from_slice only fails if length != 12, which cannot happen here
        // since we explicitly slice exactly 12 bytes. Using ok_or for defense-in-depth.
        let nonce = AesGcmNonce::from_slice(&output[..12])
            .ok_or(CryptoError::InvalidNonce)?;

        // Encrypt
        let ct_len = Self::encrypt(key, &nonce, plaintext, aad, &mut output[12..])?;

        Ok(12 + ct_len)
    }

    /// Decrypt with embedded nonce
    ///
    /// Expects input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn decrypt_with_nonce(
        key: &Aes256Key,
        input: &[u8],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if input.len() < 12 + 16 {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Safety: from_slice only fails if length != 12, which cannot happen here
        // since we've already verified input.len() >= 28. Using ok_or for defense-in-depth.
        let nonce = AesGcmNonce::from_slice(&input[..12])
            .ok_or(CryptoError::InvalidNonce)?;
        Self::decrypt(key, &nonce, &input[12..], aad, plaintext)
    }
}

// =============================================================================
// ChaCha20-Poly1305 Implementation
// =============================================================================

/// ChaCha20-Poly1305 key (32 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChaCha20Key([u8; 32]);

impl ChaCha20Key {
    /// Create a new key from bytes
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Generate a random key
    pub fn generate<R: crate::traits::CryptoRng>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl AsRef<[u8]> for ChaCha20Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ChaCha20-Poly1305 nonce (12 bytes / 96 bits)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChaCha20Nonce([u8; 12]);

impl ChaCha20Nonce {
    /// Create a new nonce from bytes
    #[must_use]
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 12 {
            return None;
        }
        let mut bytes = [0u8; 12];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Create a zero nonce
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 12])
    }

    /// Increment nonce by 1
    pub fn increment(&mut self) {
        for byte in self.0.iter_mut().rev() {
            let (new_val, overflow) = byte.overflowing_add(1);
            *byte = new_val;
            if !overflow {
                break;
            }
        }
    }
}

impl AsRef<[u8]> for ChaCha20Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// ChaCha20-Poly1305 AEAD implementation
///
/// Provides authenticated encryption using ChaCha20 stream cipher with
/// Poly1305 authenticator. This algorithm is designed to be fast and
/// secure even without hardware acceleration.
///
/// # Security Properties
///
/// - **Confidentiality**: 256-bit security level
/// - **Authenticity**: 128-bit authentication tag
/// - **Performance**: Constant-time, no timing attacks possible
pub struct ChaCha20Poly1305Impl;

impl Aead for ChaCha20Poly1305Impl {
    const ALGORITHM_ID: AlgorithmId = AlgorithmId::ChaCha20Poly1305;
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    type Key = ChaCha20Key;
    type Nonce = ChaCha20Nonce;

    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use chacha20poly1305::aead::AeadInPlace;

        let required_len = plaintext.len() + Self::TAG_SIZE;
        if ciphertext.len() < required_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Copy plaintext to output buffer
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);

        // Create cipher instance
        let cipher = ChaCha20Poly1305Cipher::new_from_slice(&key.0)
            .map_err(|_| CryptoError::InvalidKey)?;

        let cc_nonce = chacha20poly1305::Nonce::from_slice(&nonce.0);

        // Encrypt in place
        let tag = cipher
            .encrypt_in_place_detached(cc_nonce, aad, &mut ciphertext[..plaintext.len()])
            .map_err(|_| CryptoError::InternalError)?;

        // Append tag
        ciphertext[plaintext.len()..required_len].copy_from_slice(&tag);

        Ok(required_len)
    }

    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use chacha20poly1305::aead::AeadInPlace;

        if ciphertext.len() < Self::TAG_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        let plaintext_len = ciphertext.len() - Self::TAG_SIZE;
        if plaintext.len() < plaintext_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Create cipher instance
        let cipher = ChaCha20Poly1305Cipher::new_from_slice(&key.0)
            .map_err(|_| CryptoError::InvalidKey)?;

        let cc_nonce = chacha20poly1305::Nonce::from_slice(&nonce.0);

        // Copy ciphertext (without tag) to plaintext buffer
        plaintext[..plaintext_len].copy_from_slice(&ciphertext[..plaintext_len]);

        // Extract tag
        let tag = chacha20poly1305::Tag::from_slice(&ciphertext[plaintext_len..]);

        // Decrypt in place
        cipher
            .decrypt_in_place_detached(cc_nonce, aad, &mut plaintext[..plaintext_len], tag)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(plaintext_len)
    }
}

// =============================================================================
// Nonce Management
// =============================================================================

/// Counter-based nonce sequence generator
///
/// Generates unique nonces using a counter to prevent reuse.
/// Format: prefix (4 bytes) || counter (8 bytes big-endian)
///
/// # Safety
///
/// - Each `NonceSequence` instance must use a unique prefix
/// - Counter starts at 0 and increments with each call
/// - Returns error if counter overflows (after 2^64 nonces) - key must be rotated
pub struct NonceSequence {
    /// Fixed prefix (e.g., device ID or session ID)
    prefix: [u8; 4],
    /// Current counter value
    counter: u64,
}

impl NonceSequence {
    /// Create a new nonce sequence with given prefix
    #[must_use]
    pub const fn new(prefix: [u8; 4]) -> Self {
        Self { prefix, counter: 0 }
    }

    /// Create with random prefix
    pub fn random<R: crate::traits::CryptoRng>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut prefix = [0u8; 4];
        rng.fill_bytes(&mut prefix)?;
        Ok(Self { prefix, counter: 0 })
    }

    /// Get next nonce (AES-GCM compatible)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::NonceExhausted` if counter overflows.
    /// This indicates the key has been used for 2^64 messages and MUST be rotated.
    pub fn next_aes(&mut self) -> Result<AesGcmNonce, CryptoError> {
        let nonce = self.current_aes();
        self.counter = self.counter.checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        Ok(nonce)
    }

    /// Get next nonce (ChaCha20 compatible)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::NonceExhausted` if counter overflows.
    /// This indicates the key has been used for 2^64 messages and MUST be rotated.
    pub fn next_chacha(&mut self) -> Result<ChaCha20Nonce, CryptoError> {
        let nonce = self.current_chacha();
        self.counter = self.counter.checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        Ok(nonce)
    }

    /// Get current nonce without incrementing
    #[must_use]
    pub fn current_aes(&self) -> AesGcmNonce {
        let mut bytes = [0u8; 12];
        bytes[..4].copy_from_slice(&self.prefix);
        bytes[4..].copy_from_slice(&self.counter.to_be_bytes());
        AesGcmNonce(bytes)
    }

    /// Get current nonce without incrementing
    #[must_use]
    pub fn current_chacha(&self) -> ChaCha20Nonce {
        let mut bytes = [0u8; 12];
        bytes[..4].copy_from_slice(&self.prefix);
        bytes[4..].copy_from_slice(&self.counter.to_be_bytes());
        ChaCha20Nonce(bytes)
    }

    /// Get current counter value
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Check if nonce space is nearly exhausted (> 2^63 uses)
    #[must_use]
    pub const fn is_near_exhaustion(&self) -> bool {
        self.counter > (1u64 << 63)
    }
}

// =============================================================================
// Synthetic Nonce (SIV-like construction)
// =============================================================================

/// Synthetic IV generator for nonce-misuse resistance
///
/// Derives nonces from the message and key, providing some protection
/// against nonce reuse. However, identical messages will produce
/// identical ciphertexts, leaking equality.
///
/// Use only when random nonces are impractical.
pub struct SyntheticNonce;

impl SyntheticNonce {
    /// Generate synthetic nonce from key and message
    pub fn generate(key: &[u8], message: &[u8], aad: &[u8]) -> AesGcmNonce {
        let mut hasher = Sha3_256::new();
        hasher.update(b"SIV-NONCE");
        hasher.update(key);
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);
        hasher.update(&(aad.len() as u64).to_le_bytes());
        hasher.update(aad);

        let hash = hasher.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hash.as_ref()[..12]);

        // Clear top bit to ensure counter space
        nonce[0] &= 0x7F;

        AesGcmNonce(nonce)
    }
}

// =============================================================================
// Key Wrapping (RFC 3394 / AES-KW)
// =============================================================================

/// AES Key Wrap (RFC 3394)
///
/// Wraps a key using AES-256 for secure key storage/transport.
/// Output is 8 bytes larger than input.
pub struct AesKeyWrap;

impl AesKeyWrap {
    /// Default IV per RFC 3394
    const DEFAULT_IV: u64 = 0xA6A6A6A6A6A6A6A6;

    /// Wrap a key
    ///
    /// Input key must be a multiple of 8 bytes (64 bits).
    /// Output is input.len() + 8 bytes.
    pub fn wrap(
        kek: &Aes256Key,
        key_data: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit};
        use aes_gcm::aes::Aes256;

        // Validate input
        if key_data.len() < 16 || key_data.len() % 8 != 0 {
            return Err(CryptoError::InvalidKey);
        }

        let n = key_data.len() / 8;
        let required_len = key_data.len() + 8;

        if output.len() < required_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Initialize output: A || R[1] || R[2] || ... || R[n]
        output[..8].copy_from_slice(&Self::DEFAULT_IV.to_be_bytes());
        output[8..required_len].copy_from_slice(key_data);

        let cipher = Aes256::new_from_slice(&kek.0)
            .map_err(|_| CryptoError::InvalidKey)?;

        // 6 * n iterations
        for j in 0..6 {
            for i in 0..n {
                // B = AES(K, A || R[i])
                let mut block = [0u8; 16];
                block[..8].copy_from_slice(&output[..8]);
                block[8..].copy_from_slice(&output[8 + i * 8..16 + i * 8]);

                let mut block_arr = aes_gcm::aes::Block::from(block);
                cipher.encrypt_block(&mut block_arr);

                // A = MSB(64, B) ^ t where t = (n*j)+i+1
                let t = ((n * j) + i + 1) as u64;
                let mut a = [0u8; 8];
                a.copy_from_slice(&block_arr[..8]);
                let a_val = u64::from_be_bytes(a) ^ t;
                output[..8].copy_from_slice(&a_val.to_be_bytes());

                // R[i] = LSB(64, B)
                output[8 + i * 8..16 + i * 8].copy_from_slice(&block_arr[8..]);
            }
        }

        Ok(required_len)
    }

    /// Unwrap a key
    ///
    /// Input must be at least 24 bytes (8 byte header + 16 byte minimum payload).
    /// Output is input.len() - 8 bytes.
    pub fn unwrap(
        kek: &Aes256Key,
        wrapped: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        use aes_gcm::aes::cipher::{BlockDecrypt, KeyInit};
        use aes_gcm::aes::Aes256;

        // Validate input
        if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let n = (wrapped.len() / 8) - 1;
        let key_len = wrapped.len() - 8;

        if output.len() < key_len {
            return Err(CryptoError::BufferTooSmall);
        }

        // Initialize: A = C[0], R[i] = C[i]
        let mut a = [0u8; 8];
        a.copy_from_slice(&wrapped[..8]);
        output[..key_len].copy_from_slice(&wrapped[8..]);

        let cipher = Aes256::new_from_slice(&kek.0)
            .map_err(|_| CryptoError::InvalidKey)?;

        // 6 * n iterations in reverse
        for j in (0..6).rev() {
            for i in (0..n).rev() {
                // A ^ t
                let t = ((n * j) + i + 1) as u64;
                let a_val = u64::from_be_bytes(a) ^ t;

                // B = AES^-1(K, (A ^ t) || R[i])
                let mut block = [0u8; 16];
                block[..8].copy_from_slice(&a_val.to_be_bytes());
                block[8..].copy_from_slice(&output[i * 8..(i + 1) * 8]);

                let mut block_arr = aes_gcm::aes::Block::from(block);
                cipher.decrypt_block(&mut block_arr);

                // A = MSB(64, B)
                a.copy_from_slice(&block_arr[..8]);

                // R[i] = LSB(64, B)
                output[i * 8..(i + 1) * 8].copy_from_slice(&block_arr[8..]);
            }
        }

        // Verify IV
        if u64::from_be_bytes(a) != Self::DEFAULT_IV {
            secure_zero(output);
            return Err(CryptoError::AuthenticationFailed);
        }

        Ok(key_len)
    }
}

// =============================================================================
// Streaming AEAD
// =============================================================================

/// Maximum chunk size for streaming encryption (64 KB)
pub const STREAM_CHUNK_SIZE: usize = 65536;

/// Streaming AEAD encryptor
///
/// Encrypts data in chunks with a sequence number for ordering.
/// Each chunk is independently authenticated.
pub struct StreamEncryptor {
    key: Aes256Key,
    nonce_seq: NonceSequence,
    chunk_count: u64,
}

impl StreamEncryptor {
    /// Create a new stream encryptor
    pub fn new(key: Aes256Key, prefix: [u8; 4]) -> Self {
        Self {
            key,
            nonce_seq: NonceSequence::new(prefix),
            chunk_count: 0,
        }
    }

    /// Encrypt a chunk
    ///
    /// Returns the ciphertext length (chunk.len() + 16)
    pub fn encrypt_chunk(
        &mut self,
        chunk: &[u8],
        is_last: bool,
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if chunk.len() > STREAM_CHUNK_SIZE {
            return Err(CryptoError::BufferTooSmall);
        }

        let nonce = self.nonce_seq.next_aes()?;

        // AAD includes chunk number and last flag
        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&self.chunk_count.to_be_bytes());
        aad[8] = if is_last { 1 } else { 0 };

        let len = Aes256Gcm::encrypt(&self.key, &nonce, chunk, &aad, output)?;
        self.chunk_count += 1;

        Ok(len)
    }

    /// Get number of chunks encrypted
    #[must_use]
    pub const fn chunk_count(&self) -> u64 {
        self.chunk_count
    }
}

/// Streaming AEAD decryptor
pub struct StreamDecryptor {
    key: Aes256Key,
    nonce_seq: NonceSequence,
    chunk_count: u64,
}

impl StreamDecryptor {
    /// Create a new stream decryptor
    pub fn new(key: Aes256Key, prefix: [u8; 4]) -> Self {
        Self {
            key,
            nonce_seq: NonceSequence::new(prefix),
            chunk_count: 0,
        }
    }

    /// Decrypt a chunk
    ///
    /// Returns the plaintext length
    pub fn decrypt_chunk(
        &mut self,
        chunk: &[u8],
        is_last: bool,
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let nonce = self.nonce_seq.next_aes()?;

        // AAD includes chunk number and last flag
        let mut aad = [0u8; 9];
        aad[..8].copy_from_slice(&self.chunk_count.to_be_bytes());
        aad[8] = if is_last { 1 } else { 0 };

        let len = Aes256Gcm::decrypt(&self.key, &nonce, chunk, &aad, output)?;
        self.chunk_count += 1;

        Ok(len)
    }
}

impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for StreamDecryptor {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = Aes256Key::new([0x42u8; 32]);
        let nonce = AesGcmNonce::new([0x01u8; 12]);
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let mut ciphertext = [0u8; 128];
        let ct_len = Aes256Gcm::encrypt(&key, &nonce, plaintext, aad, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 128];
        let pt_len =
            Aes256Gcm::decrypt(&key, &nonce, &ciphertext[..ct_len], aad, &mut decrypted).unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_aes256gcm_auth_failure() {
        let key = Aes256Key::new([0x42u8; 32]);
        let nonce = AesGcmNonce::new([0x01u8; 12]);
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let mut ciphertext = [0u8; 128];
        let ct_len = Aes256Gcm::encrypt(&key, &nonce, plaintext, aad, &mut ciphertext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        let mut decrypted = [0u8; 128];
        let result =
            Aes256Gcm::decrypt(&key, &nonce, &ciphertext[..ct_len], aad, &mut decrypted);

        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = ChaCha20Key::new([0x42u8; 32]);
        let nonce = ChaCha20Nonce::new([0x01u8; 12]);
        let plaintext = b"Hello, ChaCha!";
        let aad = b"aad";

        let mut ciphertext = [0u8; 128];
        let ct_len =
            ChaCha20Poly1305Impl::encrypt(&key, &nonce, plaintext, aad, &mut ciphertext).unwrap();

        let mut decrypted = [0u8; 128];
        let pt_len =
            ChaCha20Poly1305Impl::decrypt(&key, &nonce, &ciphertext[..ct_len], aad, &mut decrypted)
                .unwrap();

        assert_eq!(&decrypted[..pt_len], plaintext);
    }

    #[test]
    fn test_nonce_sequence() {
        let mut seq = NonceSequence::new([0x01, 0x02, 0x03, 0x04]);

        let n1 = seq.next_aes().unwrap();
        let n2 = seq.next_aes().unwrap();
        let n3 = seq.next_aes().unwrap();

        // Each nonce should be different
        assert_ne!(n1, n2);
        assert_ne!(n2, n3);

        // Counter should increment
        assert_eq!(seq.counter(), 3);
    }

    #[test]
    fn test_nonce_exhaustion() {
        let mut seq = NonceSequence::new([0x01, 0x02, 0x03, 0x04]);
        // Set counter to max value
        seq.counter = u64::MAX;

        // Should return NonceExhausted error
        let result = seq.next_aes();
        assert_eq!(result, Err(CryptoError::NonceExhausted));
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = AesGcmNonce::new([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]);
        nonce.increment();
        assert_eq!(nonce.0[11], 0xFF);

        nonce.increment();
        // Should wrap around
        assert_eq!(nonce.0[11], 0x00);
        assert_eq!(nonce.0[10], 0x00);
    }

    #[test]
    fn test_key_wrap_unwrap() {
        let kek = Aes256Key::new([0x42u8; 32]);
        let key_data = [0x13u8; 32]; // 256-bit key

        let mut wrapped = [0u8; 48]; // 32 + 8 + padding
        let wrap_len = AesKeyWrap::wrap(&kek, &key_data, &mut wrapped).unwrap();
        assert_eq!(wrap_len, 40);

        let mut unwrapped = [0u8; 32];
        let unwrap_len = AesKeyWrap::unwrap(&kek, &wrapped[..wrap_len], &mut unwrapped).unwrap();
        assert_eq!(unwrap_len, 32);
        assert_eq!(unwrapped, key_data);
    }

    #[test]
    fn test_key_wrap_tamper() {
        let kek = Aes256Key::new([0x42u8; 32]);
        let key_data = [0x13u8; 32];

        let mut wrapped = [0u8; 48];
        let wrap_len = AesKeyWrap::wrap(&kek, &key_data, &mut wrapped).unwrap();

        // Tamper
        wrapped[0] ^= 0x01;

        let mut unwrapped = [0u8; 32];
        let result = AesKeyWrap::unwrap(&kek, &wrapped[..wrap_len], &mut unwrapped);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_streaming_encryption() {
        let key = Aes256Key::new([0x55u8; 32]);
        let prefix = [0x01, 0x02, 0x03, 0x04];

        let mut enc = StreamEncryptor::new(key.clone(), prefix);
        let mut dec = StreamDecryptor::new(key, prefix);

        let chunk1 = b"First chunk of data";
        let chunk2 = b"Second chunk";

        let mut ct1 = [0u8; 64];
        let mut ct2 = [0u8; 64];

        let len1 = enc.encrypt_chunk(chunk1, false, &mut ct1).unwrap();
        let len2 = enc.encrypt_chunk(chunk2, true, &mut ct2).unwrap();

        let mut pt1 = [0u8; 64];
        let mut pt2 = [0u8; 64];

        let dec_len1 = dec.decrypt_chunk(&ct1[..len1], false, &mut pt1).unwrap();
        let dec_len2 = dec.decrypt_chunk(&ct2[..len2], true, &mut pt2).unwrap();

        assert_eq!(&pt1[..dec_len1], chunk1);
        assert_eq!(&pt2[..dec_len2], chunk2);
    }

    #[test]
    fn test_synthetic_nonce() {
        let key = [0x42u8; 32];
        let msg1 = b"message one";
        let msg2 = b"message two";

        let n1 = SyntheticNonce::generate(&key, msg1, b"");
        let n2 = SyntheticNonce::generate(&key, msg2, b"");
        let n3 = SyntheticNonce::generate(&key, msg1, b"");

        // Different messages should produce different nonces
        assert_ne!(n1, n2);
        // Same message should produce same nonce
        assert_eq!(n1, n3);
    }
}
