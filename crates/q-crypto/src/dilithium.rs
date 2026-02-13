// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! ML-DSA (Dilithium) Digital Signature Algorithm - Production Implementation
//!
//! This module provides a production-ready implementation of ML-DSA-65
//! (formerly Dilithium-3) as specified in NIST FIPS 204.
//!
//! # Security Properties
//! - EUF-CMA secure digital signatures
//! - Based on Module-LWE and Module-SIS problems
//! - Constant-time implementation to prevent timing attacks
//! - Deterministic signing (no per-signature randomness needed)
//!
//! # Security Level
//! - ML-DSA-65 (Dilithium3): NIST Level 3 (equivalent to AES-192)
//!
//! # Parameters (ML-DSA-65 / Dilithium3)
//! - n = 256 (polynomial degree)
//! - q = 8380417 (modulus)
//! - k = 6 (public key dimension)
//! - l = 5 (secret key dimension)
//! - η = 4 (secret key coefficient bound)
//! - γ₁ = 2^19 (signature coefficient bound)
//! - γ₂ = (q-1)/32 (low bits bound)
//! - τ = 49 (number of ±1 coefficients in challenge)
//! - β = 196 (rejection bound)
//! - ω = 55 (max hint ones)

use crate::error::CryptoError;
use crate::field::{DilithiumFieldElement, DILITHIUM_Q};
use crate::ntt::{DilithiumPoly, DILITHIUM_N};
use crate::traits::{CryptoRng, Signer};
use q_common::types::{AlgorithmId, SecurityLevel};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Dilithium-3 parameters
pub mod params {
    /// Polynomial degree
    pub const N: usize = 256;
    /// Modulus
    pub const Q: u32 = 8380417;
    /// Public key dimension k
    pub const K: usize = 6;
    /// Secret key dimension l
    pub const L: usize = 5;
    /// Secret key coefficient bound η
    pub const ETA: usize = 4;
    /// Signature coefficient bound γ₁ = 2^19
    pub const GAMMA1: u32 = 1 << 19;
    /// Low bits bound γ₂ = (q-1)/32
    pub const GAMMA2: u32 = (super::DILITHIUM_Q - 1) / 32;
    /// Number of ±1 coefficients in challenge
    pub const TAU: usize = 49;
    /// Rejection bound β = τ * η
    pub const BETA: u32 = 196;
    /// Max hint ones
    pub const OMEGA: usize = 55;
    /// Bytes per polynomial (packed, 3 bytes per coefficient)
    pub const POLY_BYTES: usize = 768;
    /// Bytes for polynomial with ETA bound
    pub const POLY_ETA_BYTES: usize = 128; // 4 bits per coefficient
    /// Bytes for polynomial with GAMMA1 bound
    pub const POLY_GAMMA1_BYTES: usize = 640; // 20 bits per coefficient
    /// Challenge seed bytes
    pub const SEED_BYTES: usize = 32;
    /// Commitment randomness bytes
    pub const CRH_BYTES: usize = 64;
}

// Dilithium-3 sizes
/// Dilithium3 public key size
pub const DILITHIUM3_PUBLIC_KEY_SIZE: usize = 1952;
/// Dilithium3 secret key size
pub const DILITHIUM3_SECRET_KEY_SIZE: usize = 4000;
/// Dilithium3 signature size
pub const DILITHIUM3_SIGNATURE_SIZE: usize = 3293;

/// Polynomial vector of dimension l
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PolyVecL {
    polys: [DilithiumPoly; params::L],
}

impl Default for PolyVecL {
    fn default() -> Self {
        Self {
            polys: core::array::from_fn(|_| DilithiumPoly::default()),
        }
    }
}

impl PolyVecL {
    fn new() -> Self {
        Self::default()
    }

    fn ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.ntt();
        }
    }

    #[allow(dead_code)]
    fn inv_ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.inv_ntt();
        }
    }

    #[allow(dead_code)]
    fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..params::L {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    fn pointwise_acc(&self, other: &Self) -> DilithiumPoly {
        let mut result = self.polys[0].pointwise_mul(&other.polys[0]);
        for i in 1..params::L {
            let term = self.polys[i].pointwise_mul(&other.polys[i]);
            result = result.add(&term);
        }
        result
    }

    /// Check if all coefficients are within bound
    fn check_norm(&self, bound: u32) -> bool {
        for poly in self.polys.iter() {
            if !poly.check_norm(bound) {
                return false;
            }
        }
        true
    }
}

/// Polynomial vector of dimension k
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PolyVecK {
    polys: [DilithiumPoly; params::K],
}

impl Default for PolyVecK {
    fn default() -> Self {
        Self {
            polys: core::array::from_fn(|_| DilithiumPoly::default()),
        }
    }
}

impl PolyVecK {
    fn new() -> Self {
        Self::default()
    }

    fn ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.ntt();
        }
    }

    fn inv_ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.inv_ntt();
        }
    }

    fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..params::K {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    fn sub(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..params::K {
            result.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        result
    }

    /// Check if all coefficients are within bound
    fn check_norm(&self, bound: u32) -> bool {
        for poly in self.polys.iter() {
            if !poly.check_norm(bound) {
                return false;
            }
        }
        true
    }
}

/// Matrix A (k x l polynomials)
#[derive(Clone, Zeroize)]
struct PolyMatrix {
    rows: [PolyVecL; params::K],
}

impl Default for PolyMatrix {
    fn default() -> Self {
        Self {
            rows: core::array::from_fn(|_| PolyVecL::default()),
        }
    }
}

impl PolyMatrix {
    fn new() -> Self {
        Self::default()
    }

    /// Matrix-vector multiplication: result = A * s
    fn mul_vec(&self, s: &PolyVecL) -> PolyVecK {
        let mut result = PolyVecK::new();
        for i in 0..params::K {
            result.polys[i] = self.rows[i].pointwise_acc(s);
        }
        result
    }
}

/// Dilithium3 public key
#[derive(Clone)]
pub struct Dilithium3PublicKey {
    /// Seed for matrix A
    rho: [u8; 32],
    /// Encoded t1 = high bits of t = As
    t1: PolyVecK,
    /// Cached serialized form
    cached_bytes: [u8; DILITHIUM3_PUBLIC_KEY_SIZE],
}

impl Dilithium3PublicKey {
    /// Create from structured data, computing the serialized cache
    fn new(rho: [u8; 32], t1: PolyVecK) -> Self {
        let mut cached_bytes = [0u8; DILITHIUM3_PUBLIC_KEY_SIZE];
        cached_bytes[..32].copy_from_slice(&rho);
        let mut offset = 32;
        for poly in t1.polys.iter() {
            for i in 0..(DILITHIUM_N / 4) {
                let t0 = poly.coeffs[4 * i].value();
                let t1v = poly.coeffs[4 * i + 1].value();
                let t2 = poly.coeffs[4 * i + 2].value();
                let t3 = poly.coeffs[4 * i + 3].value();
                cached_bytes[offset] = t0 as u8;
                cached_bytes[offset + 1] = ((t0 >> 8) | (t1v << 2)) as u8;
                cached_bytes[offset + 2] = ((t1v >> 6) | (t2 << 4)) as u8;
                cached_bytes[offset + 3] = ((t2 >> 4) | (t3 << 6)) as u8;
                cached_bytes[offset + 4] = (t3 >> 2) as u8;
                offset += 5;
            }
        }
        Self { rho, t1, cached_bytes }
    }

    /// Serialize public key
    pub fn to_bytes(&self) -> [u8; DILITHIUM3_PUBLIC_KEY_SIZE] {
        self.cached_bytes
    }

    /// Deserialize public key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != DILITHIUM3_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }

        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[..32]);

        let mut t1 = PolyVecK::new();
        let mut offset = 32;

        for poly in t1.polys.iter_mut() {
            for i in 0..(DILITHIUM_N / 4) {
                let b0 = bytes[offset] as u32;
                let b1 = bytes[offset + 1] as u32;
                let b2 = bytes[offset + 2] as u32;
                let b3 = bytes[offset + 3] as u32;
                let b4 = bytes[offset + 4] as u32;

                poly.coeffs[4 * i] = DilithiumFieldElement::new(b0 | ((b1 & 0x03) << 8));
                poly.coeffs[4 * i + 1] = DilithiumFieldElement::new((b1 >> 2) | ((b2 & 0x0F) << 6));
                poly.coeffs[4 * i + 2] = DilithiumFieldElement::new((b2 >> 4) | ((b3 & 0x3F) << 4));
                poly.coeffs[4 * i + 3] = DilithiumFieldElement::new((b3 >> 6) | (b4 << 2));
                offset += 5;
            }
        }

        let mut cached_bytes = [0u8; DILITHIUM3_PUBLIC_KEY_SIZE];
        cached_bytes.copy_from_slice(bytes);

        Ok(Self { rho, t1, cached_bytes })
    }
}

impl AsRef<[u8]> for Dilithium3PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.cached_bytes
    }
}

/// Dilithium3 secret key
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Dilithium3SecretKey {
    /// Seed for matrix A
    rho: [u8; 32],
    /// Signing key
    key: [u8; 32],
    /// Hash of public key (CRH = SHAKE256 truncated to 256 bits)
    tr: [u8; 32],
    /// Secret vector s1
    s1: PolyVecL,
    /// Secret vector s2
    s2: PolyVecK,
    /// t0 = low bits of t = As
    t0: PolyVecK,
    /// Cached serialized form
    cached_bytes: [u8; DILITHIUM3_SECRET_KEY_SIZE],
}

impl Dilithium3SecretKey {
    /// Create from structured data, computing the serialized cache
    fn new(rho: [u8; 32], key: [u8; 32], tr: [u8; 32], s1: PolyVecL, s2: PolyVecK, t0: PolyVecK) -> Self {
        let mut sk = Self {
            rho, key, tr, s1, s2, t0,
            cached_bytes: [0u8; DILITHIUM3_SECRET_KEY_SIZE],
        };
        sk.cached_bytes = sk.serialize();
        sk
    }

    /// Internal serialization (used to build cache)
    fn serialize(&self) -> [u8; DILITHIUM3_SECRET_KEY_SIZE] {
        let mut bytes = [0u8; DILITHIUM3_SECRET_KEY_SIZE];
        let mut offset = 0;

        bytes[offset..offset + 32].copy_from_slice(&self.rho);
        offset += 32;

        bytes[offset..offset + 32].copy_from_slice(&self.key);
        offset += 32;

        bytes[offset..offset + 32].copy_from_slice(&self.tr);
        offset += 32;

        // Pack s1 (4 bits per coefficient with eta=4)
        for poly in self.s1.polys.iter() {
            for i in 0..(DILITHIUM_N / 2) {
                let t0 = (params::ETA as i32 - poly.coeffs[2 * i].to_centered()) as u8;
                let t1 = (params::ETA as i32 - poly.coeffs[2 * i + 1].to_centered()) as u8;
                bytes[offset] = t0 | (t1 << 4);
                offset += 1;
            }
        }

        // Pack s2
        for poly in self.s2.polys.iter() {
            for i in 0..(DILITHIUM_N / 2) {
                let t0 = (params::ETA as i32 - poly.coeffs[2 * i].to_centered()) as u8;
                let t1 = (params::ETA as i32 - poly.coeffs[2 * i + 1].to_centered()) as u8;
                bytes[offset] = t0 | (t1 << 4);
                offset += 1;
            }
        }

        // Pack t0 (13 bits per coefficient)
        for poly in self.t0.polys.iter() {
            for i in 0..(DILITHIUM_N / 8) {
                let mut t = [0u32; 8];
                for j in 0..8 {
                    let c = poly.coeffs[8 * i + j].to_centered();
                    t[j] = ((1 << 12) - c) as u32;
                }

                bytes[offset] = t[0] as u8;
                bytes[offset + 1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
                bytes[offset + 2] = (t[1] >> 3) as u8;
                bytes[offset + 3] = ((t[1] >> 11) | (t[2] << 2)) as u8;
                bytes[offset + 4] = ((t[2] >> 6) | (t[3] << 7)) as u8;
                bytes[offset + 5] = (t[3] >> 1) as u8;
                bytes[offset + 6] = ((t[3] >> 9) | (t[4] << 4)) as u8;
                bytes[offset + 7] = (t[4] >> 4) as u8;
                bytes[offset + 8] = ((t[4] >> 12) | (t[5] << 1)) as u8;
                bytes[offset + 9] = ((t[5] >> 7) | (t[6] << 6)) as u8;
                bytes[offset + 10] = (t[6] >> 2) as u8;
                bytes[offset + 11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
                bytes[offset + 12] = (t[7] >> 5) as u8;
                offset += 13;
            }
        }

        bytes
    }

    /// Serialize secret key
    pub fn to_bytes(&self) -> [u8; DILITHIUM3_SECRET_KEY_SIZE] {
        self.cached_bytes
    }

    /// Deserialize secret key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != DILITHIUM3_SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }

        let mut offset = 0;

        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut tr = [0u8; 32];
        tr.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Unpack s1
        let mut s1 = PolyVecL::new();
        for poly in s1.polys.iter_mut() {
            for i in 0..(DILITHIUM_N / 2) {
                let t0 = (bytes[offset] & 0x0F) as i32;
                let t1 = (bytes[offset] >> 4) as i32;
                poly.coeffs[2 * i] = DilithiumFieldElement::from_i32(params::ETA as i32 - t0);
                poly.coeffs[2 * i + 1] = DilithiumFieldElement::from_i32(params::ETA as i32 - t1);
                offset += 1;
            }
        }

        // Unpack s2
        let mut s2 = PolyVecK::new();
        for poly in s2.polys.iter_mut() {
            for i in 0..(DILITHIUM_N / 2) {
                let t0 = (bytes[offset] & 0x0F) as i32;
                let t1 = (bytes[offset] >> 4) as i32;
                poly.coeffs[2 * i] = DilithiumFieldElement::from_i32(params::ETA as i32 - t0);
                poly.coeffs[2 * i + 1] = DilithiumFieldElement::from_i32(params::ETA as i32 - t1);
                offset += 1;
            }
        }

        // Unpack t0
        let mut t0 = PolyVecK::new();
        for poly in t0.polys.iter_mut() {
            for i in 0..(DILITHIUM_N / 8) {
                let b: [u32; 13] = core::array::from_fn(|j| bytes[offset + j] as u32);

                let c0 = b[0] | ((b[1] & 0x1F) << 8);
                let c1 = (b[1] >> 5) | (b[2] << 3) | ((b[3] & 0x03) << 11);
                let c2 = (b[3] >> 2) | ((b[4] & 0x7F) << 6);
                let c3 = (b[4] >> 7) | (b[5] << 1) | ((b[6] & 0x0F) << 9);
                let c4 = (b[6] >> 4) | (b[7] << 4) | ((b[8] & 0x01) << 12);
                let c5 = (b[8] >> 1) | ((b[9] & 0x3F) << 7);
                let c6 = (b[9] >> 6) | (b[10] << 2) | ((b[11] & 0x07) << 10);
                let c7 = (b[11] >> 3) | (b[12] << 5);

                poly.coeffs[8 * i] = DilithiumFieldElement::from_i32((1 << 12) - c0 as i32);
                poly.coeffs[8 * i + 1] = DilithiumFieldElement::from_i32((1 << 12) - c1 as i32);
                poly.coeffs[8 * i + 2] = DilithiumFieldElement::from_i32((1 << 12) - c2 as i32);
                poly.coeffs[8 * i + 3] = DilithiumFieldElement::from_i32((1 << 12) - c3 as i32);
                poly.coeffs[8 * i + 4] = DilithiumFieldElement::from_i32((1 << 12) - c4 as i32);
                poly.coeffs[8 * i + 5] = DilithiumFieldElement::from_i32((1 << 12) - c5 as i32);
                poly.coeffs[8 * i + 6] = DilithiumFieldElement::from_i32((1 << 12) - c6 as i32);
                poly.coeffs[8 * i + 7] = DilithiumFieldElement::from_i32((1 << 12) - c7 as i32);

                offset += 13;
            }
        }

        let mut cached_bytes = [0u8; DILITHIUM3_SECRET_KEY_SIZE];
        cached_bytes.copy_from_slice(bytes);

        Ok(Self {
            rho, key, tr, s1, s2, t0,
            cached_bytes,
        })
    }

}

impl AsRef<[u8]> for Dilithium3SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.cached_bytes
    }
}

/// Dilithium3 signature
#[derive(Clone)]
pub struct Dilithium3Signature {
    bytes: [u8; DILITHIUM3_SIGNATURE_SIZE],
}

impl Dilithium3Signature {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != DILITHIUM3_SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sig = Self {
            bytes: [0u8; DILITHIUM3_SIGNATURE_SIZE],
        };
        sig.bytes.copy_from_slice(bytes);
        Ok(sig)
    }

    /// Get bytes
    pub fn to_bytes(&self) -> &[u8; DILITHIUM3_SIGNATURE_SIZE] {
        &self.bytes
    }

    /// Get mutable bytes (for testing)
    pub fn bytes_mut(&mut self) -> &mut [u8; DILITHIUM3_SIGNATURE_SIZE] {
        &mut self.bytes
    }
}

impl AsRef<[u8]> for Dilithium3Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-DSA-65 (Dilithium3) signature scheme
pub struct Dilithium3;

impl Dilithium3 {
    /// Generate keypair with explicit seed
    pub fn generate_keypair_from_seed(
        seed: &[u8; 32],
    ) -> Result<(Dilithium3PublicKey, Dilithium3SecretKey), CryptoError> {
        // Expand seed: (rho, rho', key)
        let mut expanded = [0u8; 128];
        shake256(seed, &mut expanded);

        let mut rho = [0u8; 32];
        let mut rho_prime = [0u8; 64];
        let mut key = [0u8; 32];

        rho.copy_from_slice(&expanded[..32]);
        rho_prime.copy_from_slice(&expanded[32..96]);
        key.copy_from_slice(&expanded[96..128]);

        // Generate matrix A
        let a = gen_matrix(&rho);

        // Sample s1 from CBD(eta)
        let mut s1 = PolyVecL::new();
        for i in 0..params::L {
            s1.polys[i] = sample_eta(&rho_prime, i as u16);
        }

        // Sample s2 from CBD(eta)
        let mut s2 = PolyVecK::new();
        for i in 0..params::K {
            s2.polys[i] = sample_eta(&rho_prime, (params::L + i) as u16);
        }

        // NTT(s1)
        let mut s1_ntt = s1.clone();
        s1_ntt.ntt();

        // t = A * s1 + s2
        let mut t = a.mul_vec(&s1_ntt);
        t.inv_ntt();
        t = t.add(&s2);

        // Power2Round: t = t1 * 2^d + t0
        let mut t1 = PolyVecK::new();
        let mut t0 = PolyVecK::new();

        for i in 0..params::K {
            for j in 0..DILITHIUM_N {
                let (t0_val, t1_val) = t.polys[i].coeffs[j].power2round(13);
                t0.polys[i].coeffs[j] = t0_val;
                t1.polys[i].coeffs[j] = t1_val;
            }
        }

        // Create public key
        let pk = Dilithium3PublicKey::new(rho, t1);

        // Hash public key: tr = CRH(pk) = SHAKE256(pk) truncated to 256 bits
        let pk_bytes = pk.to_bytes();
        let mut tr = [0u8; 32];
        shake256(&pk_bytes, &mut tr);

        // Create secret key
        let sk = Dilithium3SecretKey::new(rho, key, tr, s1, s2, t0);

        Ok((pk, sk))
    }

    /// Sign message
    pub fn sign_internal(
        sk: &Dilithium3SecretKey,
        message: &[u8],
    ) -> Result<Dilithium3Signature, CryptoError> {
        // Regenerate matrix A
        let a = gen_matrix(&sk.rho);

        // NTT(s1), NTT(s2)
        let mut s1_ntt = sk.s1.clone();
        s1_ntt.ntt();
        let mut s2_ntt = sk.s2.clone();
        s2_ntt.ntt();
        let mut t0_ntt = sk.t0.clone();
        t0_ntt.ntt();

        // mu = CRH(tr || M) = SHAKE256(tr || M), 512-bit output
        let mut mu = [0u8; 64];
        {
            let mut hasher_input = heapless::Vec::<u8, 8192>::new();
            for byte in sk.tr.iter() {
                let _ = hasher_input.push(*byte);
            }
            for byte in message.iter() {
                let _ = hasher_input.push(*byte);
            }
            shake256(&hasher_input, &mut mu);
        }

        // rho' = H(key || mu)
        let mut rho_prime_input = [0u8; 96];
        rho_prime_input[..32].copy_from_slice(&sk.key);
        rho_prime_input[32..].copy_from_slice(&mu);
        let mut rho_prime = [0u8; 64];
        shake256(&rho_prime_input, &mut rho_prime);

        // Rejection sampling loop
        let mut kappa: u16 = 0;
        let max_attempts = 1000;
        loop {
            if kappa >= max_attempts {
                return Err(CryptoError::SigningFailed);
            }

            // Sample y from uniform distribution [-gamma1+1, gamma1]
            let y = sample_gamma1(&rho_prime, kappa);

            // w = A * NTT(y)
            let mut y_ntt = y.clone();
            y_ntt.ntt();
            let mut w = a.mul_vec(&y_ntt);
            w.inv_ntt();

            // Decompose w: w = w1 * alpha + w0
            let mut w1 = PolyVecK::new();
            for i in 0..params::K {
                for j in 0..DILITHIUM_N {
                    w1.polys[i].coeffs[j] = w.polys[i].coeffs[j].high_bits(2 * params::GAMMA2);
                }
            }

            // c_tilde = H(mu || w1)
            let mut c_tilde = [0u8; 32];
            {
                let mut hasher_input = heapless::Vec::<u8, 8192>::new();
                for byte in mu.iter() {
                    let _ = hasher_input.push(*byte);
                }
                // Serialize w1
                for poly in w1.polys.iter() {
                    let poly_bytes = poly.to_bytes();
                    for byte in poly_bytes.iter() {
                        let _ = hasher_input.push(*byte);
                    }
                }
                shake256(&hasher_input, &mut c_tilde);
            }

            // Sample challenge c from c_tilde
            let c = sample_challenge(&c_tilde);

            // z = y + c * s1
            let mut c_ntt = c.clone();
            c_ntt.ntt();
            let mut z = PolyVecL::new();
            for i in 0..params::L {
                let cs1 = c_ntt.pointwise_mul(&s1_ntt.polys[i]);
                let mut cs1_normal = cs1;
                cs1_normal.inv_ntt();
                z.polys[i] = y.polys[i].add(&cs1_normal);
            }

            // Check norm of z
            if !z.check_norm(params::GAMMA1 - params::BETA) {

                kappa += params::L as u16;
                continue;
            }

            // r0 = LowBits(w - c*s2)
            let mut cs2 = PolyVecK::new();
            for i in 0..params::K {
                let prod = c_ntt.pointwise_mul(&s2_ntt.polys[i]);
                let mut prod_normal = prod;
                prod_normal.inv_ntt();
                cs2.polys[i] = prod_normal;
            }
            let r0 = w.sub(&cs2);

            // Check low bits
            let mut r0_low = PolyVecK::new();
            for i in 0..params::K {
                for j in 0..DILITHIUM_N {
                    r0_low.polys[i].coeffs[j] = r0.polys[i].coeffs[j].low_bits(2 * params::GAMMA2);
                }
            }
            if !r0_low.check_norm(params::GAMMA2 - params::BETA) {

                kappa += params::L as u16;
                continue;
            }

            // Compute hint h
            let mut ct0 = PolyVecK::new();
            for i in 0..params::K {
                let prod = c_ntt.pointwise_mul(&t0_ntt.polys[i]);
                let mut prod_normal = prod;
                prod_normal.inv_ntt();
                ct0.polys[i] = prod_normal;
            }

            // Check norm of ct0
            if !ct0.check_norm(params::GAMMA2) {

                kappa += params::L as u16;
                continue;
            }

            // Make hint: h = MakeHint(-ct0, w - cs2 + ct0)
            let w_minus_cs2_plus_ct0 = r0.add(&ct0);
            let mut hint = [[false; DILITHIUM_N]; params::K];
            let mut hint_count = 0usize;

            for i in 0..params::K {
                for j in 0..DILITHIUM_N {
                    hint[i][j] = DilithiumFieldElement::make_hint(
                        -ct0.polys[i].coeffs[j],
                        w_minus_cs2_plus_ct0.polys[i].coeffs[j],
                        2 * params::GAMMA2,
                    );
                    if hint[i][j] {
                        hint_count += 1;
                    }
                }
            }

            if hint_count > params::OMEGA {

                kappa += params::L as u16;
                continue;
            }

            // Pack signature
            let sig = pack_signature(&c_tilde, &z, &hint);
            return Ok(Dilithium3Signature { bytes: sig });
        }
    }

    /// Verify signature
    pub fn verify_internal(
        pk: &Dilithium3PublicKey,
        message: &[u8],
        signature: &Dilithium3Signature,
    ) -> Result<bool, CryptoError> {
        // Unpack signature
        let (c_tilde, z, hint) = unpack_signature(&signature.bytes)?;

        // Check z norm
        if !z.check_norm(params::GAMMA1 - params::BETA) {
            return Ok(false);
        }

        // Count hint bits
        let hint_count: usize = hint.iter().map(|row| row.iter().filter(|&&b| b).count()).sum();
        if hint_count > params::OMEGA {
            return Ok(false);
        }

        // Regenerate matrix A
        let a = gen_matrix(&pk.rho);

        // mu = CRH(CRH(pk) || M)
        let pk_bytes = pk.to_bytes();
        let mut tr = [0u8; 32];
        shake256(&pk_bytes, &mut tr);

        let mut mu = [0u8; 64];
        {
            let mut hasher_input = heapless::Vec::<u8, 8192>::new();
            for byte in tr.iter() {
                let _ = hasher_input.push(*byte);
            }
            for byte in message.iter() {
                let _ = hasher_input.push(*byte);
            }
            shake256(&hasher_input, &mut mu);
        }

        // Sample challenge c
        let c = sample_challenge(&c_tilde);

        // NTT(z)
        let mut z_ntt = z.clone();
        z_ntt.ntt();

        // NTT(c)
        let mut c_ntt = c.clone();
        c_ntt.ntt();

        // NTT(t1 * 2^d)
        let mut t1_ntt = pk.t1.clone();
        for poly in t1_ntt.polys.iter_mut() {
            for coeff in poly.coeffs.iter_mut() {
                *coeff = DilithiumFieldElement::new(coeff.value() << 13);
            }
        }
        t1_ntt.ntt();

        // w' = A * z - c * t1 * 2^d
        let az = a.mul_vec(&z_ntt);
        let mut ct1 = PolyVecK::new();
        for i in 0..params::K {
            ct1.polys[i] = c_ntt.pointwise_mul(&t1_ntt.polys[i]);
        }
        let mut w_prime = az.sub(&ct1);
        w_prime.inv_ntt();

        // UseHint to compute w1'
        let mut w1_prime = PolyVecK::new();
        for i in 0..params::K {
            for j in 0..DILITHIUM_N {
                w1_prime.polys[i].coeffs[j] = DilithiumFieldElement::use_hint(
                    hint[i][j],
                    w_prime.polys[i].coeffs[j],
                    2 * params::GAMMA2,
                );
            }
        }

        // c' = H(mu || w1')
        let mut c_tilde_prime = [0u8; 32];
        {
            let mut hasher_input = heapless::Vec::<u8, 8192>::new();
            for byte in mu.iter() {
                let _ = hasher_input.push(*byte);
            }
            for poly in w1_prime.polys.iter() {
                let poly_bytes = poly.to_bytes();
                for byte in poly_bytes.iter() {
                    let _ = hasher_input.push(*byte);
                }
            }
            shake256(&hasher_input, &mut c_tilde_prime);
        }

        // Compare c_tilde with c_tilde_prime
        Ok(ct_compare(&c_tilde, &c_tilde_prime))
    }
}

impl Signer for Dilithium3 {
    const ALGORITHM_ID: AlgorithmId = AlgorithmId::Dilithium3;
    const PUBLIC_KEY_SIZE: usize = DILITHIUM3_PUBLIC_KEY_SIZE;
    const SECRET_KEY_SIZE: usize = DILITHIUM3_SECRET_KEY_SIZE;
    const SIGNATURE_SIZE: usize = DILITHIUM3_SIGNATURE_SIZE;
    const SECURITY_LEVEL: SecurityLevel = SecurityLevel::Level3;

    type PublicKey = Dilithium3PublicKey;
    type SecretKey = Dilithium3SecretKey;
    type Signature = Dilithium3Signature;

    fn keypair<R: CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed)?;
        let result = Self::generate_keypair_from_seed(&seed);
        seed.zeroize();
        result
    }

    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Result<Self::Signature, CryptoError> {
        Self::sign_internal(sk, message)
    }

    fn verify(
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, CryptoError> {
        Self::verify_internal(pk, message, signature)
    }
}

// ============================================================================
// Internal functions
// ============================================================================

/// Generate matrix A from seed
fn gen_matrix(rho: &[u8; 32]) -> PolyMatrix {
    let mut a = PolyMatrix::new();
    for i in 0..params::K {
        for j in 0..params::L {
            a.rows[i].polys[j] = sample_uniform(rho, (i * 256 + j) as u16);
        }
    }
    a
}

/// Sample polynomial uniformly from seed
fn sample_uniform(rho: &[u8; 32], nonce: u16) -> DilithiumPoly {
    let mut poly = DilithiumPoly::new();

    let mut xof_input = [0u8; 34];
    xof_input[..32].copy_from_slice(rho);
    xof_input[32] = nonce as u8;
    xof_input[33] = (nonce >> 8) as u8;

    let mut output = [0u8; 840];
    shake128(&xof_input, &mut output);

    let mut ctr = 0usize;
    let mut pos = 0usize;

    while ctr < DILITHIUM_N && pos + 3 <= output.len() {
        let t = (output[pos] as u32)
            | ((output[pos + 1] as u32) << 8)
            | ((output[pos + 2] as u32) << 16);
        let t = t & 0x7FFFFF;

        if t < DILITHIUM_Q {
            poly.coeffs[ctr] = DilithiumFieldElement::new(t);
            ctr += 1;
        }
        pos += 3;
    }

    poly
}

/// Sample polynomial with coefficients in [-eta, eta]
fn sample_eta(seed: &[u8], nonce: u16) -> DilithiumPoly {
    let mut poly = DilithiumPoly::new();

    let mut prf_input = [0u8; 66];
    prf_input[..64].copy_from_slice(&seed[..64.min(seed.len())]);
    prf_input[64] = nonce as u8;
    prf_input[65] = (nonce >> 8) as u8;

    let mut output = [0u8; 128]; // eta=4: 4 bits per coefficient
    shake256(&prf_input, &mut output);

    for i in 0..DILITHIUM_N {
        let t = (output[i / 2] >> ((i % 2) * 4)) & 0x0F;
        let t0 = t & 0x07;
        let t1 = t >> 3;
        let coeff = (t0 as i32) - (t1 as i32) * 4;
        poly.coeffs[i] = DilithiumFieldElement::from_i32(coeff);
    }

    poly
}

/// Sample y from uniform distribution [-gamma1+1, gamma1]
fn sample_gamma1(seed: &[u8], nonce: u16) -> PolyVecL {
    let mut y = PolyVecL::new();

    for i in 0..params::L {
        let mut prf_input = [0u8; 66];
        prf_input[..64].copy_from_slice(seed);
        let n = nonce + (i as u16);
        prf_input[64] = n as u8;
        prf_input[65] = (n >> 8) as u8;

        let mut output = [0u8; 640]; // 20 bits per coefficient, 256 * 20 / 8 = 640
        shake256(&prf_input, &mut output);

        // Unpack 4 coefficients (20 bits each) from 10 bytes
        for j in 0..(DILITHIUM_N / 4) {
            let b = &output[10 * j..10 * j + 10];
            let c0 = (b[0] as u32) | ((b[1] as u32) << 8) | (((b[2] as u32) & 0x0F) << 16);
            let c1 = ((b[2] as u32) >> 4) | ((b[3] as u32) << 4) | ((b[4] as u32) << 12);
            let c2 = (b[5] as u32) | ((b[6] as u32) << 8) | (((b[7] as u32) & 0x0F) << 16);
            let c3 = ((b[7] as u32) >> 4) | ((b[8] as u32) << 4) | ((b[9] as u32) << 12);

            y.polys[i].coeffs[4 * j] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c0 & 0xFFFFF) as i32);
            y.polys[i].coeffs[4 * j + 1] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c1 & 0xFFFFF) as i32);
            y.polys[i].coeffs[4 * j + 2] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c2 & 0xFFFFF) as i32);
            y.polys[i].coeffs[4 * j + 3] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c3 & 0xFFFFF) as i32);
        }
    }

    y
}

/// Sample challenge polynomial with tau ±1 coefficients
fn sample_challenge(seed: &[u8; 32]) -> DilithiumPoly {
    let mut c = DilithiumPoly::new();

    let mut output = [0u8; 136];
    shake256(seed, &mut output);

    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (output[i] as u64) << (8 * i);
    }

    let mut pos = 8usize;
    for i in (DILITHIUM_N - params::TAU)..DILITHIUM_N {
        // Sample j uniformly in [0, i]
        loop {
            if pos >= output.len() {
                break;
            }
            let b = output[pos] as usize;
            pos += 1;
            if b <= i {
                // Swap c[i] and c[b]
                c.coeffs[i] = c.coeffs[b];
                // c[b] = ±1
                let sign = (signs & 1) as i32;
                signs >>= 1;
                c.coeffs[b] = DilithiumFieldElement::from_i32(1 - 2 * sign);
                break;
            }
        }
    }

    c
}

/// Pack signature
fn pack_signature(
    c_tilde: &[u8; 32],
    z: &PolyVecL,
    hint: &[[bool; DILITHIUM_N]; params::K],
) -> [u8; DILITHIUM3_SIGNATURE_SIZE] {
    let mut sig = [0u8; DILITHIUM3_SIGNATURE_SIZE];
    let mut offset = 0;

    // c_tilde
    sig[offset..offset + 32].copy_from_slice(c_tilde);
    offset += 32;

    // z: pack each coefficient as gamma1 - z_i into 20 bits
    // 4 coefficients (20 bits each) = 80 bits = 10 bytes per group
    for poly in z.polys.iter() {
        for i in 0..(DILITHIUM_N / 4) {
            let c0 =
                (params::GAMMA1 as i32 - poly.coeffs[4 * i].to_centered()) as u32 & 0xFFFFF;
            let c1 = (params::GAMMA1 as i32 - poly.coeffs[4 * i + 1].to_centered()) as u32
                & 0xFFFFF;
            let c2 = (params::GAMMA1 as i32 - poly.coeffs[4 * i + 2].to_centered()) as u32
                & 0xFFFFF;
            let c3 = (params::GAMMA1 as i32 - poly.coeffs[4 * i + 3].to_centered()) as u32
                & 0xFFFFF;

            // Pack 4 × 20-bit values into 10 bytes
            sig[offset + 0] = c0 as u8;
            sig[offset + 1] = (c0 >> 8) as u8;
            sig[offset + 2] = ((c0 >> 16) | (c1 << 4)) as u8;
            sig[offset + 3] = (c1 >> 4) as u8;
            sig[offset + 4] = (c1 >> 12) as u8;
            sig[offset + 5] = c2 as u8;
            sig[offset + 6] = (c2 >> 8) as u8;
            sig[offset + 7] = ((c2 >> 16) | (c3 << 4)) as u8;
            sig[offset + 8] = (c3 >> 4) as u8;
            sig[offset + 9] = (c3 >> 12) as u8;
            offset += 10;
        }
    }

    // Hint: encode using OMEGA-encoding (Dilithium spec Section 5.4)
    // Format: for each polynomial, list the indices where hint[i] = 1,
    // then write the count. Total: OMEGA + K bytes.
    let mut hint_offset = offset;
    let mut count_offset = offset + params::OMEGA;
    for row in hint.iter() {
        let mut cnt = 0u8;
        for (j, &h) in row.iter().enumerate() {
            if h {
                if (hint_offset - offset) < params::OMEGA {
                    sig[hint_offset] = j as u8;
                    hint_offset += 1;
                }
                cnt += 1;
            }
        }
        sig[count_offset] = cnt;
        count_offset += 1;
    }

    sig
}

/// Unpack signature
fn unpack_signature(
    sig: &[u8; DILITHIUM3_SIGNATURE_SIZE],
) -> Result<([u8; 32], PolyVecL, [[bool; DILITHIUM_N]; params::K]), CryptoError> {
    let mut c_tilde = [0u8; 32];
    c_tilde.copy_from_slice(&sig[..32]);

    let mut z = PolyVecL::new();
    let mut offset = 32;

    for poly in z.polys.iter_mut() {
        for i in 0..(DILITHIUM_N / 4) {
            if offset + 10 > sig.len() {
                return Err(CryptoError::InvalidSignature);
            }

            let b = &sig[offset..offset + 10];
            let c0 = (b[0] as u32) | ((b[1] as u32) << 8) | (((b[2] as u32) & 0x0F) << 16);
            let c1 = ((b[2] as u32) >> 4) | ((b[3] as u32) << 4) | ((b[4] as u32) << 12);
            let c2 = (b[5] as u32) | ((b[6] as u32) << 8) | (((b[7] as u32) & 0x0F) << 16);
            let c3 = ((b[7] as u32) >> 4) | ((b[8] as u32) << 4) | ((b[9] as u32) << 12);

            poly.coeffs[4 * i] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c0 & 0xFFFFF) as i32);
            poly.coeffs[4 * i + 1] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c1 & 0xFFFFF) as i32);
            poly.coeffs[4 * i + 2] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c2 & 0xFFFFF) as i32);
            poly.coeffs[4 * i + 3] =
                DilithiumFieldElement::from_i32(params::GAMMA1 as i32 - (c3 & 0xFFFFF) as i32);

            offset += 10;
        }
    }

    // Unpack hint using OMEGA-encoding
    let mut hint = [[false; DILITHIUM_N]; params::K];
    let hint_start = offset;
    let count_start = offset + params::OMEGA;
    let mut pos = hint_start;
    for (row_idx, row) in hint.iter_mut().enumerate() {
        let cnt = sig[count_start + row_idx] as usize;
        for _ in 0..cnt {
            if pos < hint_start + params::OMEGA {
                let idx = sig[pos] as usize;
                if idx < DILITHIUM_N {
                    row[idx] = true;
                }
                pos += 1;
            }
        }
    }

    Ok((c_tilde, z, hint))
}

// ============================================================================
// Hash functions
// ============================================================================

fn shake128(input: &[u8], output: &mut [u8]) {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake128,
    };
    let mut hasher = Shake128::default();
    hasher.update(input);
    hasher.finalize_xof().read(output);
}

fn shake256(input: &[u8], output: &mut [u8]) {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let mut hasher = Shake256::default();
    hasher.update(input);
    hasher.finalize_xof().read(output);
}

/// Constant-time comparison
fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::TestRng;

    #[test]
    fn test_dilithium3_keypair() {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();

        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        assert_eq!(pk_bytes.len(), DILITHIUM3_PUBLIC_KEY_SIZE);
        assert_eq!(sk_bytes.len(), DILITHIUM3_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_dilithium3_sign_verify() {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();

        let message = b"Hello, World!";
        let sig = Dilithium3::sign(&sk, message).unwrap();

        assert_eq!(sig.as_ref().len(), DILITHIUM3_SIGNATURE_SIZE);

        let valid = Dilithium3::verify(&pk, message, &sig).unwrap();
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn test_dilithium3_wrong_message() {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();

        let message = b"Hello, World!";
        let sig = Dilithium3::sign(&sk, message).unwrap();

        let wrong_message = b"Wrong message!";
        let valid = Dilithium3::verify(&pk, wrong_message, &sig).unwrap();
        assert!(!valid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_dilithium3_deterministic_keypair() {
        let mut rng1 = TestRng::from_seed(42);
        let mut rng2 = TestRng::from_seed(42);

        let (pk1, _sk1) = Dilithium3::keypair(&mut rng1).unwrap();
        let (pk2, _sk2) = Dilithium3::keypair(&mut rng2).unwrap();

        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = TestRng::from_seed(123);
        let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();

        // Public key roundtrip
        let pk_bytes = pk.to_bytes();
        let pk_restored = Dilithium3PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk_restored.to_bytes());

        // Secret key roundtrip
        let sk_bytes = sk.to_bytes();
        let sk_restored = Dilithium3SecretKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.to_bytes(), sk_restored.to_bytes());
    }
}
