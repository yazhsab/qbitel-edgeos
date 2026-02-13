// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Cryptographic Agility Layer
//!
//! This crate provides the cryptographic foundation for Qbitel EdgeOS, implementing
//! post-quantum cryptographic algorithms with a focus on:
//!
//! - **Security**: Constant-time operations, secure memory handling
//! - **Agility**: Algorithm-swappable interfaces for future-proofing
//! - **Embedded**: no_std compatible, minimal memory footprint
//!
//! # Supported Algorithms
//!
//! ## Key Encapsulation Mechanisms (KEM)
//! - ML-KEM (Kyber) 512, 768, 1024
//!
//! ## Digital Signatures
//! - ML-DSA (Dilithium) 2, 3, 5
//! - FN-DSA (Falcon) 512
//! - FN-DSA (Falcon) 1024 *(constants only — full implementation pending)*
//!
//! ## Hash Functions
//! - SHA3-256, SHA3-384, SHA3-512
//! - SHAKE128, SHAKE256
//!
//! ## AEAD
//! - AES-128-GCM, AES-256-GCM
//! - ChaCha20-Poly1305
//!
//! # Security Requirements
//!
//! All cryptographic operations in this crate:
//! - Execute in constant time (no secret-dependent branching)
//! - Zeroize sensitive data after use
//! - Never log or expose key material
//! - Use hardware RNG when available

#![no_std]
#![allow(unsafe_code)] // Required for low-level crypto operations
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_lossless)]

// Core cryptographic modules
pub mod error;
pub mod traits;
pub mod zeroize_utils;

// Finite field and polynomial arithmetic
pub mod field;
pub mod ntt;

// Random number generation
pub mod rng;

// Hash functions
pub mod hash;

// AEAD ciphers
pub mod aead;

// Post-quantum KEMs
pub mod kyber;

// Post-quantum signatures
pub mod dilithium;

// Known Answer Tests
pub mod kat;

// Post-quantum signatures - Falcon
pub mod falcon;

#[cfg(feature = "hybrid")]
pub mod hybrid;

#[cfg(feature = "classical")]
pub mod classical;

// Re-export main traits and types
pub use error::CryptoError;
pub use traits::{Aead, CryptoRng, Hash, Kem, Signer, Xof};
pub use rng::SystemRng;

// Re-export algorithm implementations
pub use hash::{Sha3_256, Sha3_512, Shake256, Shake128};
pub use aead::{Aes256Gcm, ChaCha20Poly1305Impl};

#[cfg(feature = "kyber768")]
pub use kyber::Kyber768;

#[cfg(feature = "dilithium3")]
pub use dilithium::Dilithium3;

#[cfg(feature = "falcon512")]
pub use falcon::Falcon512;
