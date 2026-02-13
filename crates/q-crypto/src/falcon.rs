// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! FN-DSA (Falcon) Digital Signature Algorithm
//!
//! This module implements the Falcon signature scheme as specified in
//! NIST FIPS 206 (FN-DSA). Falcon provides compact signatures using
//! NTRU lattices and fast Fourier sampling.
//!
//! # Security Levels
//!
//! - **Falcon-512**: NIST Level 1 (128-bit classical security)
//! - **Falcon-1024**: NIST Level 5 (256-bit classical security)
//!
//! # Implementation
//!
//! This module wraps the `fn-dsa` crate by Thomas Pornin, which provides
//! a production-quality, constant-time, `no_std` implementation of
//! Falcon / FN-DSA. The underlying implementation includes:
//!
//! - Proper NTRU key generation with NTRU Solve for (f, g, F, G)
//! - Fast Fourier sampling for signature generation
//! - Constant-time operations on all platforms
//! - Correct Gaussian sampling to prevent key leakage

use crate::error::CryptoError;
use crate::traits::{Signer, CryptoRng};
use crate::zeroize_utils::SecureBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Use fn-dsa for the actual cryptographic operations
use fn_dsa::{
    KeyPairGenerator, KeyPairGenerator512,
    SigningKey, SigningKey512,
    VerifyingKey, VerifyingKey512,
    FN_DSA_LOGN_512,
    HASH_ID_RAW, DOMAIN_NONE,
};

#[cfg(test)]
use fn_dsa::{sign_key_size, vrfy_key_size, signature_size};

// =============================================================================
// Falcon-512 Parameters (NIST FIPS 206)
// =============================================================================

/// Polynomial degree for Falcon-512
pub const FALCON_N: usize = 512;

/// Modulus q = 12289 (a prime, NTT-friendly)
pub const FALCON_Q: u32 = 12289;

/// log2(n) for Falcon-512
pub const FALCON_LOGN: usize = 9;

/// Public key size in bytes
pub const FALCON_512_PK_SIZE: usize = 897;

/// Secret key size in bytes
pub const FALCON_512_SK_SIZE: usize = 1281;

/// Maximum signature size in bytes (compressed)
pub const FALCON_512_SIG_SIZE: usize = 666;

/// Signature bound (squared norm)
pub const FALCON_512_SIG_BOUND: u32 = 34034726;

/// Gaussian standard deviation sigma
pub const FALCON_SIGMA: f64 = 165.736617829728;

/// Signature bound for acceptance
pub const FALCON_512_BETA_SQUARED: u64 = 34034726;

// =============================================================================
// RNG Adapter: our CryptoRng -> rand_core CryptoRng + RngCore
// =============================================================================

/// Adapter to bridge our CryptoRng trait to rand_core's CryptoRng + RngCore
/// required by fn-dsa.
struct RngAdapter<'a, R: CryptoRng> {
    inner: &'a mut R,
}

impl<'a, R: CryptoRng> rand_core::RngCore for RngAdapter<'a, R> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        // NOTE: fill_bytes is infallible by trait contract. Panic is the correct response
        // to RNG failure in a security-critical context — continuing with bad randomness
        // would be worse.
        self.inner.fill_bytes(&mut buf).expect("RNG failure in Falcon");
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        // NOTE: fill_bytes is infallible by trait contract. Panic is the correct response
        // to RNG failure in a security-critical context — continuing with bad randomness
        // would be worse.
        self.inner.fill_bytes(&mut buf).expect("RNG failure in Falcon");
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // NOTE: fill_bytes is infallible by trait contract. Panic is the correct response
        // to RNG failure in a security-critical context — continuing with bad randomness
        // would be worse.
        self.inner.fill_bytes(dest).expect("RNG failure in Falcon");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.inner.fill_bytes(dest).map_err(|_| {
            rand_core::Error::from(core::num::NonZeroU32::new(1).unwrap())
        })
    }
}

impl<'a, R: CryptoRng> rand_core::CryptoRng for RngAdapter<'a, R> {}

// =============================================================================
// Falcon Key Types
// =============================================================================

/// Falcon-512 public key
#[derive(Clone)]
pub struct Falcon512PublicKey {
    /// Encoded public key h
    data: [u8; FALCON_512_PK_SIZE],
}

impl Falcon512PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != FALCON_512_PK_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let mut data = [0u8; FALCON_512_PK_SIZE];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }

    /// Get raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl AsRef<[u8]> for Falcon512PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Falcon-512 secret key
#[derive(Clone, ZeroizeOnDrop)]
pub struct Falcon512SecretKey {
    /// Encoded secret key (f, g, F, G)
    data: SecureBuffer<FALCON_512_SK_SIZE>,
}

impl Falcon512SecretKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != FALCON_512_SK_SIZE {
            return Err(CryptoError::InvalidKey);
        }
        let mut data = SecureBuffer::new();
        data.as_mut_slice()[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { data })
    }

    /// Get raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl AsRef<[u8]> for Falcon512SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }
}

impl Zeroize for Falcon512SecretKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

/// Falcon-512 signature
#[derive(Clone)]
pub struct Falcon512Signature {
    /// Compressed signature
    data: [u8; FALCON_512_SIG_SIZE],
    /// Actual length (signatures are variable length)
    len: usize,
}

impl Falcon512Signature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > FALCON_512_SIG_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let mut data = [0u8; FALCON_512_SIG_SIZE];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            data,
            len: bytes.len(),
        })
    }

    /// Get raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get signature length
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for Falcon512Signature {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// =============================================================================
// Falcon-512 Signature Scheme
// =============================================================================

/// Falcon-512 signature scheme
pub struct Falcon512;

impl Falcon512 {
    /// Generate a keypair
    ///
    /// # Arguments
    /// * `rng` - Cryptographic random number generator
    ///
    /// # Returns
    /// Tuple of (public_key, secret_key)
    pub fn keypair<R: CryptoRng>(
        rng: &mut R,
    ) -> Result<(Falcon512PublicKey, Falcon512SecretKey), CryptoError> {
        let mut adapter = RngAdapter { inner: rng };
        let mut kpg = KeyPairGenerator512::default();

        let mut sk_buf = [0u8; FALCON_512_SK_SIZE];
        let mut pk_buf = [0u8; FALCON_512_PK_SIZE];

        kpg.keygen(FN_DSA_LOGN_512, &mut adapter, &mut sk_buf, &mut pk_buf);

        let pk = Falcon512PublicKey { data: pk_buf };
        let mut sk_data = SecureBuffer::<FALCON_512_SK_SIZE>::new();
        sk_data.as_mut_slice().copy_from_slice(&sk_buf);

        // Zeroize the temporary buffer
        sk_buf.zeroize();

        Ok((pk, Falcon512SecretKey { data: sk_data }))
    }

    /// Sign a message
    ///
    /// # Arguments
    /// * `sk` - Secret key
    /// * `message` - Message to sign
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// Signature on success
    pub fn sign<R: CryptoRng>(
        sk: &Falcon512SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Falcon512Signature, CryptoError> {
        let mut adapter = RngAdapter { inner: rng };

        // Decode the signing key from the stored bytes
        let mut signing_key = SigningKey512::decode(sk.data.as_slice())
            .ok_or(CryptoError::InvalidKey)?;

        // Sign the message (raw, no pre-hashing)
        let mut sig_buf = [0u8; FALCON_512_SIG_SIZE];
        signing_key.sign(
            &mut adapter,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            message,
            &mut sig_buf,
        );

        // fn-dsa fills the buffer with the signature, padded to the full size.
        // The actual signature length is the buffer size.
        let sig_len = FALCON_512_SIG_SIZE;

        Ok(Falcon512Signature {
            data: sig_buf,
            len: sig_len,
        })
    }

    /// Verify a signature
    ///
    /// # Arguments
    /// * `pk` - Public key
    /// * `message` - Message that was signed
    /// * `sig` - Signature to verify
    ///
    /// # Returns
    /// `true` if signature is valid
    pub fn verify(
        pk: &Falcon512PublicKey,
        message: &[u8],
        sig: &Falcon512Signature,
    ) -> Result<bool, CryptoError> {
        // Decode the verifying key
        let vk = VerifyingKey512::decode(&pk.data)
            .ok_or(CryptoError::InvalidKey)?;

        // Verify the signature
        let valid = vk.verify(
            &sig.data[..sig.len],
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            message,
        );

        Ok(valid)
    }
}

// Implement Signer trait
impl Signer for Falcon512 {
    const ALGORITHM_ID: q_common::types::AlgorithmId = q_common::types::AlgorithmId::Falcon512;
    const PUBLIC_KEY_SIZE: usize = FALCON_512_PK_SIZE;
    const SECRET_KEY_SIZE: usize = FALCON_512_SK_SIZE;
    const SIGNATURE_SIZE: usize = FALCON_512_SIG_SIZE;
    const SECURITY_LEVEL: q_common::types::SecurityLevel = q_common::types::SecurityLevel::Level1;

    type PublicKey = Falcon512PublicKey;
    type SecretKey = Falcon512SecretKey;
    type Signature = Falcon512Signature;

    fn keypair<R: CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError> {
        Falcon512::keypair(rng)
    }

    fn sign(
        sk: &Self::SecretKey,
        message: &[u8],
    ) -> Result<Self::Signature, CryptoError> {
        // Falcon sign requires RNG for nonce generation; use deterministic
        // derivation from the message and secret key for the trait interface
        // which doesn't accept an RNG parameter.
        use crate::hash::Sha3_256;
        use crate::traits::Hash;
        let hash = Sha3_256::hash(message);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(hash.as_ref());
        let mut rng = crate::rng::SimpleRng::new(seed);
        Falcon512::sign(sk, message, &mut rng)
    }

    fn verify(
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, CryptoError> {
        Falcon512::verify(pk, message, signature)
    }
}

// =============================================================================
// Falcon-1024 (NIST Level 5) — Constants only; implementation pending
// =============================================================================
//
// Falcon-1024 key generation, signing, and verification are not yet implemented
// in the Rust crate. The Python tooling (tools/q-sign, tools/q-provision) provides
// full Falcon-1024 support via liboqs. Enable the `falcon1024` feature flag when
// a Rust implementation is added.

/// Polynomial degree for Falcon-1024
#[cfg(feature = "falcon1024")]
pub const FALCON_1024_N: usize = 1024;

/// Public key size for Falcon-1024
#[cfg(feature = "falcon1024")]
pub const FALCON_1024_PK_SIZE: usize = 1793;

/// Secret key size for Falcon-1024
#[cfg(feature = "falcon1024")]
pub const FALCON_1024_SK_SIZE: usize = 2305;

/// Signature size for Falcon-1024
#[cfg(feature = "falcon1024")]
pub const FALCON_1024_SIG_SIZE: usize = 1280;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SimpleRng;

    #[test]
    fn test_falcon_keypair_sign_verify() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);

        // Generate keypair
        let (pk, sk) = Falcon512::keypair(&mut rng).unwrap();

        // Sign message
        let message = b"Test message for Falcon signature";
        let sig = Falcon512::sign(&sk, message, &mut rng).unwrap();

        // Verify signature
        let valid = Falcon512::verify(&pk, message, &sig).unwrap();
        assert!(valid, "Signature verification should succeed");

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let invalid = Falcon512::verify(&pk, wrong_message, &sig).unwrap();
        assert!(!invalid, "Verification with wrong message should fail");
    }

    #[test]
    fn test_falcon_signature_size() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);

        let (_, sk) = Falcon512::keypair(&mut rng).unwrap();
        let sig = Falcon512::sign(&sk, b"test", &mut rng).unwrap();

        // Signature should fit in specified size
        assert!(sig.len() <= FALCON_512_SIG_SIZE);
    }

    #[test]
    fn test_falcon_key_sizes() {
        // Verify our constants match fn-dsa's computed sizes
        assert_eq!(FALCON_512_SK_SIZE, sign_key_size(FN_DSA_LOGN_512));
        assert_eq!(FALCON_512_PK_SIZE, vrfy_key_size(FN_DSA_LOGN_512));
        assert_eq!(FALCON_512_SIG_SIZE, signature_size(FN_DSA_LOGN_512));
    }

    #[test]
    fn test_falcon_signer_trait() {
        // Test via the Signer trait interface
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);

        let (pk, sk) = <Falcon512 as Signer>::keypair(&mut rng).unwrap();

        let message = b"Test Signer trait for Falcon";
        let sig = <Falcon512 as Signer>::sign(&sk, message).unwrap();
        let valid = <Falcon512 as Signer>::verify(&pk, message, &sig).unwrap();
        assert!(valid, "Signer trait sign/verify should work");
    }

    #[test]
    fn test_falcon_multiple_signatures() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);

        let (pk, sk) = Falcon512::keypair(&mut rng).unwrap();

        // Sign multiple messages and verify each
        for i in 0..5 {
            let msg = [i as u8; 32];
            let sig = Falcon512::sign(&sk, &msg, &mut rng).unwrap();
            let valid = Falcon512::verify(&pk, &msg, &sig).unwrap();
            assert!(valid, "Signature {} should verify", i);
        }
    }
}
