// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Cryptographic error types
//!
//! This module defines error types for all cryptographic operations.

use core::fmt;

/// Error type for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid key format or size
    InvalidKey,
    /// Signature verification failed
    InvalidSignature,
    /// Signing operation failed
    SigningFailed,
    /// Ciphertext is malformed or invalid
    InvalidCiphertext,
    /// KEM decapsulation failed
    DecapsulationFailed,
    /// Random number generator failure
    RngFailure,
    /// Buffer is too small for the operation
    BufferTooSmall,
    /// Algorithm not supported
    UnsupportedAlgorithm,
    /// AEAD authentication failed
    AuthenticationFailed,
    /// Invalid nonce
    InvalidNonce,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Nonce counter exhausted - key must be rotated
    NonceExhausted,
    /// Internal error (should not occur)
    InternalError,
}

impl CryptoError {
    /// Get error code for logging/debugging
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            Self::InvalidKey => 0x0101,
            Self::InvalidSignature => 0x0102,
            Self::SigningFailed => 0x010C,
            Self::InvalidCiphertext => 0x0103,
            Self::DecapsulationFailed => 0x0104,
            Self::RngFailure => 0x0105,
            Self::BufferTooSmall => 0x0106,
            Self::UnsupportedAlgorithm => 0x0107,
            Self::AuthenticationFailed => 0x0108,
            Self::InvalidNonce => 0x0109,
            Self::KeyDerivationFailed => 0x010A,
            Self::NonceExhausted => 0x010B,
            Self::InternalError => 0x01FF,
        }
    }

    /// Get error description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::InvalidKey => "invalid key",
            Self::InvalidSignature => "invalid signature",
            Self::SigningFailed => "signing operation failed",
            Self::InvalidCiphertext => "invalid ciphertext",
            Self::DecapsulationFailed => "decapsulation failed",
            Self::RngFailure => "RNG failure",
            Self::BufferTooSmall => "buffer too small",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::AuthenticationFailed => "authentication failed",
            Self::InvalidNonce => "invalid nonce",
            Self::KeyDerivationFailed => "key derivation failed",
            Self::NonceExhausted => "nonce counter exhausted - key rotation required",
            Self::InternalError => "internal error",
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:04X}] {}", self.code(), self.description())
    }
}

impl From<CryptoError> for q_common::Error {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::InvalidKey => Self::InvalidKey,
            CryptoError::InvalidSignature => Self::InvalidSignature,
            CryptoError::SigningFailed => Self::InternalError, // Signing failure maps to internal error
            CryptoError::InvalidCiphertext => Self::InvalidKey, // Map to closest
            CryptoError::DecapsulationFailed => Self::DecapsulationFailed,
            CryptoError::RngFailure => Self::RngFailure,
            CryptoError::BufferTooSmall => Self::BufferTooSmall,
            CryptoError::UnsupportedAlgorithm => Self::UnsupportedAlgorithm,
            CryptoError::AuthenticationFailed => Self::AeadError,
            CryptoError::InvalidNonce => Self::AeadError,
            CryptoError::KeyDerivationFailed => Self::KeyDerivationFailed,
            CryptoError::NonceExhausted => Self::AeadError, // Key rotation required
            CryptoError::InternalError => Self::InternalError,
        }
    }
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;
