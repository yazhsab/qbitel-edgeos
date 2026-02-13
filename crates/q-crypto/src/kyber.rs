// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! ML-KEM (Kyber) Key Encapsulation Mechanism - Production Implementation
//!
//! This module provides a production-ready implementation of ML-KEM-768
//! (formerly Kyber-768) as specified in NIST FIPS 203.
//!
//! # Security Properties
//! - IND-CCA2 secure key encapsulation
//! - Based on Module-LWE problem
//! - Constant-time implementation to prevent timing attacks
//! - Implicit rejection for invalid ciphertexts
//!
//! # Security Level
//! - ML-KEM-768: NIST Level 3 (equivalent to AES-192)
//!
//! # Parameters (ML-KEM-768)
//! - n = 256 (polynomial degree)
//! - k = 3 (module dimension)
//! - q = 3329 (modulus)
//! - η₁ = 2 (noise parameter for key generation)
//! - η₂ = 2 (noise parameter for encryption)
//! - du = 10 (compression bits for ciphertext u)
//! - dv = 4 (compression bits for ciphertext v)

use crate::error::CryptoError;
use crate::field::{KyberFieldElement, KYBER_Q};
use crate::ntt::{KyberPoly, KYBER_N};
use crate::traits::{CryptoRng, Kem};
use q_common::types::{AlgorithmId, SecurityLevel};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Kyber-768 parameters
pub mod params {
    /// Security parameter k (module dimension)
    pub const K: usize = 3;
    /// Polynomial degree
    pub const N: usize = 256;
    /// Modulus
    pub const Q: u16 = 3329;
    /// Noise parameter η₁ for key generation
    pub const ETA1: usize = 2;
    /// Noise parameter η₂ for encryption
    pub const ETA2: usize = 2;
    /// Compression bits for u
    pub const DU: u32 = 10;
    /// Compression bits for v
    pub const DV: u32 = 4;
    /// Bytes for polynomial (12 bits per coefficient)
    pub const POLY_BYTES: usize = 384;
    /// Bytes for compressed polynomial (10 bits)
    pub const POLY_COMPRESSED_BYTES_DU: usize = 320;
    /// Bytes for compressed polynomial (4 bits)
    pub const POLY_COMPRESSED_BYTES_DV: usize = 128;
}

// Kyber-768 sizes
/// Kyber-768 public key size: k * POLY_BYTES + 32
pub const KYBER768_PUBLIC_KEY_SIZE: usize = params::K * params::POLY_BYTES + 32; // 1184
/// Kyber-768 secret key size: k * POLY_BYTES + public_key_size + 32 + 32
pub const KYBER768_SECRET_KEY_SIZE: usize =
    params::K * params::POLY_BYTES + KYBER768_PUBLIC_KEY_SIZE + 32 + 32; // 2400
/// Kyber-768 ciphertext size: k * compressed_u + compressed_v
pub const KYBER768_CIPHERTEXT_SIZE: usize =
    params::K * params::POLY_COMPRESSED_BYTES_DU + params::POLY_COMPRESSED_BYTES_DV; // 1088
/// Kyber-768 shared secret size
pub const KYBER768_SHARED_SECRET_SIZE: usize = 32;

/// Polynomial vector (k polynomials)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PolyVec {
    polys: [KyberPoly; params::K],
}

impl Default for PolyVec {
    fn default() -> Self {
        Self {
            polys: core::array::from_fn(|_| KyberPoly::default()),
        }
    }
}

impl PolyVec {
    /// Create new zero vector
    fn new() -> Self {
        Self::default()
    }

    /// Apply NTT to all polynomials
    fn ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.ntt();
        }
    }

    /// Apply inverse NTT to all polynomials
    fn inv_ntt(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.inv_ntt();
        }
    }

    /// Add two polynomial vectors
    fn add(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for i in 0..params::K {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    /// Pointwise multiply and accumulate (inner product)
    fn pointwise_acc(&self, other: &Self) -> KyberPoly {
        let mut result = self.polys[0].pointwise_mul(&other.polys[0]);
        for i in 1..params::K {
            let term = self.polys[i].pointwise_mul(&other.polys[i]);
            result = result.add(&term);
        }
        result
    }

    /// Serialize to bytes
    fn to_bytes(&self) -> [u8; params::K * params::POLY_BYTES] {
        let mut bytes = [0u8; params::K * params::POLY_BYTES];
        for i in 0..params::K {
            let poly_bytes = self.polys[i].to_bytes();
            bytes[i * params::POLY_BYTES..(i + 1) * params::POLY_BYTES]
                .copy_from_slice(&poly_bytes);
        }
        bytes
    }

    /// Deserialize from bytes
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut result = Self::new();
        for i in 0..params::K {
            let mut poly_bytes = [0u8; params::POLY_BYTES];
            poly_bytes.copy_from_slice(&bytes[i * params::POLY_BYTES..(i + 1) * params::POLY_BYTES]);
            result.polys[i] = KyberPoly::from_bytes(&poly_bytes);
        }
        result
    }

    /// Compress with du bits per coefficient
    fn compress_du(&self) -> [u8; params::K * params::POLY_COMPRESSED_BYTES_DU] {
        let mut bytes = [0u8; params::K * params::POLY_COMPRESSED_BYTES_DU];
        for i in 0..params::K {
            let (compressed, len) = compress_poly(&self.polys[i], params::DU);
            bytes[i * params::POLY_COMPRESSED_BYTES_DU..(i + 1) * params::POLY_COMPRESSED_BYTES_DU]
                .copy_from_slice(&compressed[..len]);
        }
        bytes
    }

    /// Decompress with du bits per coefficient
    fn decompress_du(bytes: &[u8]) -> Self {
        let mut result = Self::new();
        for i in 0..params::K {
            result.polys[i] = decompress_poly(
                &bytes[i * params::POLY_COMPRESSED_BYTES_DU
                    ..(i + 1) * params::POLY_COMPRESSED_BYTES_DU],
                params::DU,
            );
        }
        result
    }
}

/// Polynomial matrix (k x k)
#[derive(Clone, Zeroize)]
struct PolyMatrix {
    rows: [PolyVec; params::K],
}

impl Default for PolyMatrix {
    fn default() -> Self {
        Self {
            rows: core::array::from_fn(|_| PolyVec::default()),
        }
    }
}

impl PolyMatrix {
    /// Create new zero matrix
    fn new() -> Self {
        Self::default()
    }

    /// Matrix-vector multiplication: result = A * s
    fn mul_vec(&self, s: &PolyVec) -> PolyVec {
        let mut result = PolyVec::new();
        for i in 0..params::K {
            result.polys[i] = self.rows[i].pointwise_acc(s);
        }
        result
    }
}

/// Kyber-768 public key
#[derive(Clone)]
pub struct Kyber768PublicKey {
    /// Encoded public vector t = As + e (NTT domain)
    t: PolyVec,
    /// Seed for matrix A
    rho: [u8; 32],
    /// Cached serialized form
    cached_bytes: [u8; KYBER768_PUBLIC_KEY_SIZE],
}

impl Kyber768PublicKey {
    /// Create from structured data, computing the serialized cache
    fn new(t: PolyVec, rho: [u8; 32]) -> Self {
        let mut cached_bytes = [0u8; KYBER768_PUBLIC_KEY_SIZE];
        let t_bytes = t.to_bytes();
        cached_bytes[..params::K * params::POLY_BYTES].copy_from_slice(&t_bytes);
        cached_bytes[params::K * params::POLY_BYTES..].copy_from_slice(&rho);
        Self { t, rho, cached_bytes }
    }

    /// Serialize public key
    pub fn to_bytes(&self) -> [u8; KYBER768_PUBLIC_KEY_SIZE] {
        self.cached_bytes
    }

    /// Deserialize public key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KYBER768_PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let t = PolyVec::from_bytes(&bytes[..params::K * params::POLY_BYTES]);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[params::K * params::POLY_BYTES..]);
        let mut cached_bytes = [0u8; KYBER768_PUBLIC_KEY_SIZE];
        cached_bytes.copy_from_slice(bytes);
        Ok(Self { t, rho, cached_bytes })
    }
}

impl AsRef<[u8]> for Kyber768PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.cached_bytes
    }
}

/// Kyber-768 secret key (CCA format)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Kyber768SecretKey {
    /// Secret vector s (NTT domain)
    s: PolyVec,
    /// Public key (for re-encryption)
    t: PolyVec,
    /// Seed rho for matrix A
    rho: [u8; 32],
    /// Hash of public key H(pk)
    h_pk: [u8; 32],
    /// Implicit rejection secret
    z: [u8; 32],
    /// Cached serialized form
    cached_bytes: [u8; KYBER768_SECRET_KEY_SIZE],
}

impl Kyber768SecretKey {
    /// Create from structured data, computing the serialized cache
    fn new(s: PolyVec, t: PolyVec, rho: [u8; 32], h_pk: [u8; 32], z: [u8; 32]) -> Self {
        let mut cached_bytes = [0u8; KYBER768_SECRET_KEY_SIZE];
        let mut offset = 0;
        let s_bytes = s.to_bytes();
        cached_bytes[offset..offset + params::K * params::POLY_BYTES].copy_from_slice(&s_bytes);
        offset += params::K * params::POLY_BYTES;
        let t_bytes = t.to_bytes();
        cached_bytes[offset..offset + params::K * params::POLY_BYTES].copy_from_slice(&t_bytes);
        offset += params::K * params::POLY_BYTES;
        cached_bytes[offset..offset + 32].copy_from_slice(&rho);
        offset += 32;
        cached_bytes[offset..offset + 32].copy_from_slice(&h_pk);
        offset += 32;
        cached_bytes[offset..offset + 32].copy_from_slice(&z);
        Self { s, t, rho, h_pk, z, cached_bytes }
    }

    /// Serialize secret key
    pub fn to_bytes(&self) -> [u8; KYBER768_SECRET_KEY_SIZE] {
        self.cached_bytes
    }

    /// Deserialize secret key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KYBER768_SECRET_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }

        let mut offset = 0;

        let s = PolyVec::from_bytes(&bytes[offset..offset + params::K * params::POLY_BYTES]);
        offset += params::K * params::POLY_BYTES;

        let t = PolyVec::from_bytes(&bytes[offset..offset + params::K * params::POLY_BYTES]);
        offset += params::K * params::POLY_BYTES;

        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut h_pk = [0u8; 32];
        h_pk.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut z = [0u8; 32];
        z.copy_from_slice(&bytes[offset..offset + 32]);

        let mut cached_bytes = [0u8; KYBER768_SECRET_KEY_SIZE];
        cached_bytes.copy_from_slice(bytes);

        Ok(Self { s, t, rho, h_pk, z, cached_bytes })
    }

    /// Get public key from secret key
    pub fn public_key(&self) -> Kyber768PublicKey {
        Kyber768PublicKey::new(self.t.clone(), self.rho)
    }
}

impl AsRef<[u8]> for Kyber768SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.cached_bytes
    }
}

/// Kyber-768 ciphertext
#[derive(Clone)]
pub struct Kyber768Ciphertext {
    bytes: [u8; KYBER768_CIPHERTEXT_SIZE],
}

impl Kyber768Ciphertext {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KYBER768_CIPHERTEXT_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }
        let mut ct = Self {
            bytes: [0u8; KYBER768_CIPHERTEXT_SIZE],
        };
        ct.bytes.copy_from_slice(bytes);
        Ok(ct)
    }
}

impl AsRef<[u8]> for Kyber768Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Kyber-768 shared secret
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Kyber768SharedSecret {
    bytes: [u8; KYBER768_SHARED_SECRET_SIZE],
}

impl Kyber768SharedSecret {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KYBER768_SHARED_SECRET_SIZE {
            return Err(CryptoError::InternalError);
        }
        let mut ss = Self {
            bytes: [0u8; KYBER768_SHARED_SECRET_SIZE],
        };
        ss.bytes.copy_from_slice(bytes);
        Ok(ss)
    }
}

impl AsRef<[u8]> for Kyber768SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-KEM-768 implementation
pub struct Kyber768;

impl Kyber768 {
    /// Generate keypair with explicit seed
    pub fn generate_keypair_from_seed(
        seed: &[u8; 64],
    ) -> Result<(Kyber768PublicKey, Kyber768SecretKey), CryptoError> {
        // Split seed: d for key generation, z for implicit rejection
        let (d, z) = seed.split_at(32);

        // G(d) = (rho, sigma)
        let mut g_output = [0u8; 64];
        sha3_512(d, &mut g_output);
        let (rho, sigma) = g_output.split_at(32);

        let mut rho_arr = [0u8; 32];
        rho_arr.copy_from_slice(rho);

        // Generate matrix A from rho
        let a = gen_matrix(&rho_arr, false);

        // Sample s ~ CBD(eta1)
        let mut s = PolyVec::new();
        for i in 0..params::K {
            s.polys[i] = sample_cbd(sigma, i as u8, params::ETA1);
        }

        // Sample e ~ CBD(eta1)
        let mut e = PolyVec::new();
        for i in 0..params::K {
            e.polys[i] = sample_cbd(sigma, (params::K + i) as u8, params::ETA1);
        }

        // NTT(s), NTT(e)
        s.ntt();
        e.ntt();

        // t = A * s + e (all in NTT domain)
        let mut t = a.mul_vec(&s);
        t = t.add(&e);

        // Reduce coefficients
        for poly in t.polys.iter_mut() {
            poly.reduce();
        }

        // Create public key
        let pk = Kyber768PublicKey::new(t.clone(), rho_arr);

        // H(pk)
        let pk_bytes = pk.to_bytes();
        let mut h_pk = [0u8; 32];
        sha3_256(&pk_bytes, &mut h_pk);

        // Create secret key
        let mut z_arr = [0u8; 32];
        z_arr.copy_from_slice(z);

        let sk = Kyber768SecretKey::new(s, t, rho_arr, h_pk, z_arr);

        // Zeroize intermediate values
        g_output.zeroize();

        Ok((pk, sk))
    }

    /// Encapsulate with explicit randomness
    pub fn encapsulate_with_randomness(
        pk: &Kyber768PublicKey,
        randomness: &[u8; 32],
    ) -> Result<(Kyber768Ciphertext, Kyber768SharedSecret), CryptoError> {
        // m = H(randomness)
        let mut m = [0u8; 32];
        sha3_256(randomness, &mut m);

        // (K_bar, r) = G(m || H(pk))
        let pk_bytes = pk.to_bytes();
        let mut h_pk = [0u8; 32];
        sha3_256(&pk_bytes, &mut h_pk);

        let mut g_input = [0u8; 64];
        g_input[..32].copy_from_slice(&m);
        g_input[32..].copy_from_slice(&h_pk);

        let mut kr = [0u8; 64];
        sha3_512(&g_input, &mut kr);

        let k_bar = &kr[..32];
        let r = &kr[32..];

        // Encrypt: ct = Enc(pk, m, r)
        let ct_bytes = encrypt_cpa(pk, &m, r);
        let ct = Kyber768Ciphertext { bytes: ct_bytes };

        // K = KDF(K_bar || H(ct))
        let mut h_ct = [0u8; 32];
        sha3_256(&ct.bytes, &mut h_ct);

        let mut kdf_input = [0u8; 64];
        kdf_input[..32].copy_from_slice(k_bar);
        kdf_input[32..].copy_from_slice(&h_ct);

        let mut ss_bytes = [0u8; 32];
        shake256(&kdf_input, &mut ss_bytes);

        let ss = Kyber768SharedSecret { bytes: ss_bytes };

        // Zeroize intermediates
        m.zeroize();
        g_input.zeroize();
        kr.zeroize();

        Ok((ct, ss))
    }

    /// Decapsulate ciphertext
    pub fn decapsulate_internal(
        sk: &Kyber768SecretKey,
        ct: &Kyber768Ciphertext,
    ) -> Result<Kyber768SharedSecret, CryptoError> {
        // m' = Dec(sk, ct)
        let m_prime = decrypt_cpa(sk, &ct.bytes);

        // (K_bar', r') = G(m' || H(pk))
        let mut g_input = [0u8; 64];
        g_input[..32].copy_from_slice(&m_prime);
        g_input[32..].copy_from_slice(&sk.h_pk);

        let mut kr_prime = [0u8; 64];
        sha3_512(&g_input, &mut kr_prime);

        let k_bar_prime = &kr_prime[..32];
        let r_prime = &kr_prime[32..];

        // ct' = Enc(pk, m', r')
        let pk = sk.public_key();
        let ct_prime = encrypt_cpa(&pk, &m_prime, r_prime);

        // Constant-time comparison
        let valid = ct_compare(&ct.bytes, &ct_prime);

        // H(ct)
        let mut h_ct = [0u8; 32];
        sha3_256(&ct.bytes, &mut h_ct);

        // K = KDF(K_bar' || H(ct)) if valid
        // K = KDF(z || H(ct)) if invalid (implicit rejection)
        let mut kdf_input = [0u8; 64];
        for i in 0..32 {
            kdf_input[i] = ct_select(sk.z[i], k_bar_prime[i], valid);
        }
        kdf_input[32..].copy_from_slice(&h_ct);

        let mut ss_bytes = [0u8; 32];
        shake256(&kdf_input, &mut ss_bytes);

        let ss = Kyber768SharedSecret { bytes: ss_bytes };

        // Zeroize intermediates
        g_input.zeroize();
        kr_prime.zeroize();

        Ok(ss)
    }
}

impl Kem for Kyber768 {
    const ALGORITHM_ID: AlgorithmId = AlgorithmId::Kyber768;
    const PUBLIC_KEY_SIZE: usize = KYBER768_PUBLIC_KEY_SIZE;
    const SECRET_KEY_SIZE: usize = KYBER768_SECRET_KEY_SIZE;
    const CIPHERTEXT_SIZE: usize = KYBER768_CIPHERTEXT_SIZE;
    const SHARED_SECRET_SIZE: usize = KYBER768_SHARED_SECRET_SIZE;
    const SECURITY_LEVEL: SecurityLevel = SecurityLevel::Level3;

    type PublicKey = Kyber768PublicKey;
    type SecretKey = Kyber768SecretKey;
    type Ciphertext = Kyber768Ciphertext;
    type SharedSecret = Kyber768SharedSecret;

    fn keypair<R: CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError> {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed)?;
        let result = Self::generate_keypair_from_seed(&seed);
        seed.zeroize();
        result
    }

    fn encapsulate<R: CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError> {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness)?;
        let result = Self::encapsulate_with_randomness(pk, &randomness);
        randomness.zeroize();
        result
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError> {
        Self::decapsulate_internal(sk, ct)
    }
}

// ============================================================================
// Internal functions
// ============================================================================

/// Generate matrix A from seed
fn gen_matrix(rho: &[u8; 32], transposed: bool) -> PolyMatrix {
    let mut a = PolyMatrix::new();
    for i in 0..params::K {
        for j in 0..params::K {
            let (row, col) = if transposed { (j, i) } else { (i, j) };
            a.rows[i].polys[j] = sample_ntt(rho, row as u8, col as u8);
        }
    }
    a
}

/// Sample polynomial uniformly from XOF
fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> KyberPoly {
    let mut poly = KyberPoly::new();

    // Absorb rho || i || j
    let mut xof_input = [0u8; 34];
    xof_input[..32].copy_from_slice(rho);
    xof_input[32] = i;
    xof_input[33] = j;

    // Generate enough bytes for rejection sampling
    let mut output = [0u8; 672];
    shake128(&xof_input, &mut output);

    let mut ctr = 0usize;
    let mut pos = 0usize;

    while ctr < KYBER_N && pos + 3 <= output.len() {
        let d1 = ((output[pos] as u16) | ((output[pos + 1] as u16) << 8)) & 0x0FFF;
        let d2 = ((output[pos + 1] as u16 >> 4) | ((output[pos + 2] as u16) << 4)) & 0x0FFF;

        if d1 < KYBER_Q {
            poly.coeffs[ctr] = KyberFieldElement::new(d1);
            ctr += 1;
        }
        if ctr < KYBER_N && d2 < KYBER_Q {
            poly.coeffs[ctr] = KyberFieldElement::new(d2);
            ctr += 1;
        }
        pos += 3;
    }

    poly
}

/// Sample polynomial from centered binomial distribution
fn sample_cbd(seed: &[u8], nonce: u8, eta: usize) -> KyberPoly {
    let mut poly = KyberPoly::new();

    // PRF(seed, nonce)
    let mut prf_input = [0u8; 33];
    let len = seed.len().min(32);
    prf_input[..len].copy_from_slice(&seed[..len]);
    prf_input[32] = nonce;

    let output_len = 64 * eta;
    let mut output = [0u8; 128]; // eta=2: 128 bytes
    shake256(&prf_input[..33], &mut output[..output_len]);

    // CBD_eta sampling
    for i in 0..KYBER_N {
        let mut a = 0i16;
        let mut b = 0i16;

        for j in 0..eta {
            let byte_idx = (2 * i * eta + j) / 8;
            let bit_idx = (2 * i * eta + j) % 8;
            a += ((output[byte_idx] >> bit_idx) & 1) as i16;

            let byte_idx2 = (2 * i * eta + eta + j) / 8;
            let bit_idx2 = (2 * i * eta + eta + j) % 8;
            b += ((output[byte_idx2] >> bit_idx2) & 1) as i16;
        }

        poly.coeffs[i] = KyberFieldElement::from_i16(a - b);
    }

    poly
}

/// CPA encryption
fn encrypt_cpa(pk: &Kyber768PublicKey, m: &[u8; 32], r: &[u8]) -> [u8; KYBER768_CIPHERTEXT_SIZE] {
    // A^T from rho
    let a_t = gen_matrix(&pk.rho, true);

    // r ~ CBD(eta1)
    let mut r_vec = PolyVec::new();
    for i in 0..params::K {
        r_vec.polys[i] = sample_cbd(r, i as u8, params::ETA1);
    }

    // e1 ~ CBD(eta2)
    let mut e1 = PolyVec::new();
    for i in 0..params::K {
        e1.polys[i] = sample_cbd(r, (params::K + i) as u8, params::ETA2);
    }

    // e2 ~ CBD(eta2)
    let e2 = sample_cbd(r, (2 * params::K) as u8, params::ETA2);

    // NTT(r)
    r_vec.ntt();

    // u = NTT^-1(A^T * r) + e1
    let mut u = a_t.mul_vec(&r_vec);
    u.inv_ntt();
    u = u.add(&e1);

    // v = NTT^-1(t^T * r) + e2 + Decode(m)
    let mut v = pk.t.pointwise_acc(&r_vec);
    v.inv_ntt();
    v = v.add(&e2);

    // Add message
    let m_poly = decode_message(m);
    v = v.add(&m_poly);

    // Compress and serialize
    let mut ct = [0u8; KYBER768_CIPHERTEXT_SIZE];
    let u_compressed = u.compress_du();
    ct[..params::K * params::POLY_COMPRESSED_BYTES_DU].copy_from_slice(&u_compressed);

    let (v_compressed, v_len) = compress_poly(&v, params::DV);
    ct[params::K * params::POLY_COMPRESSED_BYTES_DU..].copy_from_slice(&v_compressed[..v_len]);

    ct
}

/// CPA decryption
fn decrypt_cpa(sk: &Kyber768SecretKey, ct: &[u8]) -> [u8; 32] {
    // Decompress u
    let u = PolyVec::decompress_du(&ct[..params::K * params::POLY_COMPRESSED_BYTES_DU]);

    // Decompress v
    let v = decompress_poly(
        &ct[params::K * params::POLY_COMPRESSED_BYTES_DU..],
        params::DV,
    );

    // m = v - NTT^-1(s^T * NTT(u))
    let mut u_ntt = u.clone();
    u_ntt.ntt();

    let mut su = sk.s.pointwise_acc(&u_ntt);
    su.inv_ntt();

    let m_poly = v.sub(&su);

    encode_message(&m_poly)
}

/// Decode 32-byte message to polynomial
fn decode_message(m: &[u8; 32]) -> KyberPoly {
    let mut poly = KyberPoly::new();
    for i in 0..32 {
        for j in 0..8 {
            let bit = (m[i] >> j) & 1;
            // 0 -> 0, 1 -> (q+1)/2 = 1665
            poly.coeffs[8 * i + j] = KyberFieldElement::new(if bit == 1 { 1665 } else { 0 });
        }
    }
    poly
}

/// Encode polynomial to 32-byte message
fn encode_message(poly: &KyberPoly) -> [u8; 32] {
    let mut m = [0u8; 32];
    for i in 0..32 {
        for j in 0..8 {
            // Compress to 1 bit: round((c * 2) / q)
            let c = poly.coeffs[8 * i + j].value() as u32;
            let bit = ((c * 2 + KYBER_Q as u32 / 2) / KYBER_Q as u32) & 1;
            m[i] |= (bit as u8) << j;
        }
    }
    m
}

/// Compress polynomial with d bits per coefficient
/// Returns a 320-byte buffer and actual length (128 for d=4, 320 for d=10)
fn compress_poly(poly: &KyberPoly, d: u32) -> ([u8; 320], usize) {
    let mut bytes = [0u8; 320];

    if d == 4 {
        // 256 * 4 / 8 = 128 bytes
        for i in 0..128 {
            let c0 = poly.coeffs[2 * i].compress(4);
            let c1 = poly.coeffs[2 * i + 1].compress(4);
            bytes[i] = (c0 | (c1 << 4)) as u8;
        }
        (bytes, 128)
    } else if d == 10 {
        // 256 * 10 / 8 = 320 bytes
        // Pack 4 coefficients (10 bits each) into 5 bytes
        for i in 0..64 {
            let c0 = poly.coeffs[4 * i].compress(10);
            let c1 = poly.coeffs[4 * i + 1].compress(10);
            let c2 = poly.coeffs[4 * i + 2].compress(10);
            let c3 = poly.coeffs[4 * i + 3].compress(10);

            bytes[5 * i] = c0 as u8;
            bytes[5 * i + 1] = ((c0 >> 8) | (c1 << 2)) as u8;
            bytes[5 * i + 2] = ((c1 >> 6) | (c2 << 4)) as u8;
            bytes[5 * i + 3] = ((c2 >> 4) | (c3 << 6)) as u8;
            bytes[5 * i + 4] = (c3 >> 2) as u8;
        }
        (bytes, 320)
    } else {
        (bytes, 0)
    }
}

/// Decompress polynomial from d bits per coefficient
fn decompress_poly(bytes: &[u8], d: u32) -> KyberPoly {
    let mut poly = KyberPoly::new();

    if d == 4 {
        for i in 0..128 {
            poly.coeffs[2 * i] = KyberFieldElement::decompress((bytes[i] & 0x0F) as u16, 4);
            poly.coeffs[2 * i + 1] = KyberFieldElement::decompress((bytes[i] >> 4) as u16, 4);
        }
    } else if d == 10 {
        // 5 bytes -> 4 coefficients
        for i in 0..64 {
            let b0 = bytes[5 * i] as u16;
            let b1 = bytes[5 * i + 1] as u16;
            let b2 = bytes[5 * i + 2] as u16;
            let b3 = bytes[5 * i + 3] as u16;
            let b4 = bytes[5 * i + 4] as u16;

            poly.coeffs[4 * i] = KyberFieldElement::decompress(b0 | ((b1 & 0x03) << 8), 10);
            poly.coeffs[4 * i + 1] =
                KyberFieldElement::decompress((b1 >> 2) | ((b2 & 0x0F) << 6), 10);
            poly.coeffs[4 * i + 2] =
                KyberFieldElement::decompress((b2 >> 4) | ((b3 & 0x3F) << 4), 10);
            poly.coeffs[4 * i + 3] = KyberFieldElement::decompress((b3 >> 6) | (b4 << 2), 10);
        }
    }

    poly
}

// ============================================================================
// Hash functions (using SHA3)
// ============================================================================

fn sha3_256(input: &[u8], output: &mut [u8; 32]) {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    output.copy_from_slice(&hasher.finalize());
}

fn sha3_512(input: &[u8], output: &mut [u8; 64]) {
    use sha3::{Digest, Sha3_512};
    let mut hasher = Sha3_512::new();
    hasher.update(input);
    output.copy_from_slice(&hasher.finalize());
}

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

// ============================================================================
// Constant-time utilities
// ============================================================================

/// Constant-time byte array comparison
fn ct_compare(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Returns 1 if equal, 0 otherwise
    (1u8).wrapping_sub((diff | diff.wrapping_neg()) >> 7)
}

/// Constant-time select: returns b if condition==1, a if condition==0
fn ct_select(a: u8, b: u8, condition: u8) -> u8 {
    let mask = condition.wrapping_neg();
    (a & !mask) | (b & mask)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::TestRng;

    #[test]
    fn test_kyber768_keypair() {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();

        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        assert_eq!(pk_bytes.len(), KYBER768_PUBLIC_KEY_SIZE);
        assert_eq!(sk_bytes.len(), KYBER768_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_kyber768_encaps_decaps() {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();

        let (ct, ss1) = Kyber768::encapsulate(&pk, &mut rng).unwrap();
        let ss2 = Kyber768::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss1.as_ref(), ss2.as_ref(), "Shared secrets must match");
    }

    #[test]
    fn test_kyber768_deterministic() {
        let mut rng1 = TestRng::from_seed(42);
        let mut rng2 = TestRng::from_seed(42);

        let (pk1, _sk1) = Kyber768::keypair(&mut rng1).unwrap();
        let (pk2, _sk2) = Kyber768::keypair(&mut rng2).unwrap();

        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn test_kyber768_wrong_ciphertext() {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();

        let (mut ct, ss1) = Kyber768::encapsulate(&pk, &mut rng).unwrap();

        // Corrupt ciphertext
        ct.bytes[0] ^= 0xFF;

        let ss2 = Kyber768::decapsulate(&sk, &ct).unwrap();

        // Shared secrets should NOT match (implicit rejection)
        assert_ne!(ss1.as_ref(), ss2.as_ref());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = TestRng::from_seed(123);
        let (pk, sk) = Kyber768::keypair(&mut rng).unwrap();

        // Public key roundtrip
        let pk_bytes = pk.to_bytes();
        let pk_restored = Kyber768PublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk_restored.to_bytes());

        // Secret key roundtrip
        let sk_bytes = sk.to_bytes();
        let sk_restored = Kyber768SecretKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.to_bytes(), sk_restored.to_bytes());
    }
}
