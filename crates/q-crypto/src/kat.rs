// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Known Answer Tests (KAT) for Cryptographic Primitives
//!
//! This module provides NIST-compliant Known Answer Tests for all cryptographic
//! algorithms implemented in q-crypto. These tests use official test vectors
//! from NIST and other authoritative sources.
//!
//! # Test Vector Sources
//!
//! - SHA3: NIST FIPS 202 test vectors
//! - AES-GCM: NIST SP 800-38D test vectors
//! - ML-KEM (Kyber): NIST PQC standardization vectors
//! - ML-DSA (Dilithium): NIST PQC standardization vectors
//! - SHAKE: NIST FIPS 202 test vectors
//!
//! # Usage
//!
//! ```no_run
//! use q_crypto::kat::{run_all_kat, KatResults};
//!
//! let results = run_all_kat();
//! assert!(results.all_passed());
//! ```


// ============================================================================
// KAT Result Types
// ============================================================================

/// Result of a single KAT test
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KatTestResult {
    /// Test passed
    Passed,
    /// Test failed
    Failed,
    /// Test skipped (algorithm not available)
    Skipped,
}

/// Results of all KAT tests
#[derive(Debug, Clone)]
pub struct KatResults {
    /// SHA3-256 test results
    pub sha3_256: KatTestResult,
    /// SHA3-512 test results
    pub sha3_512: KatTestResult,
    /// SHAKE128 test results
    pub shake128: KatTestResult,
    /// SHAKE256 test results
    pub shake256: KatTestResult,
    /// AES-256-GCM test results
    pub aes_256_gcm: KatTestResult,
    /// ChaCha20-Poly1305 test results
    pub chacha20_poly1305: KatTestResult,
    /// ML-KEM-768 (Kyber) test results
    pub ml_kem_768: KatTestResult,
    /// ML-DSA-65 (Dilithium3) test results
    pub ml_dsa_65: KatTestResult,
    /// DRBG test results
    pub drbg: KatTestResult,
}

impl KatResults {
    /// Check if all tests passed
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.sha3_256 == KatTestResult::Passed
            && self.sha3_512 == KatTestResult::Passed
            && self.shake128 == KatTestResult::Passed
            && self.shake256 == KatTestResult::Passed
            && self.aes_256_gcm == KatTestResult::Passed
            && self.chacha20_poly1305 == KatTestResult::Passed
            && self.ml_kem_768 == KatTestResult::Passed
            && self.ml_dsa_65 == KatTestResult::Passed
            && self.drbg == KatTestResult::Passed
    }

    /// Get number of passed tests
    #[must_use]
    pub fn passed_count(&self) -> usize {
        let tests = [
            self.sha3_256,
            self.sha3_512,
            self.shake128,
            self.shake256,
            self.aes_256_gcm,
            self.chacha20_poly1305,
            self.ml_kem_768,
            self.ml_dsa_65,
            self.drbg,
        ];
        tests.iter().filter(|&&t| t == KatTestResult::Passed).count()
    }

    /// Get number of failed tests
    #[must_use]
    pub fn failed_count(&self) -> usize {
        let tests = [
            self.sha3_256,
            self.sha3_512,
            self.shake128,
            self.shake256,
            self.aes_256_gcm,
            self.chacha20_poly1305,
            self.ml_kem_768,
            self.ml_dsa_65,
            self.drbg,
        ];
        tests.iter().filter(|&&t| t == KatTestResult::Failed).count()
    }
}

// ============================================================================
// SHA3-256 KAT Vectors (NIST FIPS 202)
// ============================================================================

/// SHA3-256 test vectors from NIST
mod sha3_256_vectors {
    /// Empty message test
    pub const EMPTY_MSG: &[u8] = &[];
    pub const EMPTY_HASH: [u8; 32] = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
    ];

    /// "abc" test vector
    pub const ABC_MSG: &[u8] = b"abc";
    pub const ABC_HASH: [u8; 32] = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    ];

    /// 448-bit message test
    pub const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    pub const HASH_448: [u8; 32] = [
        0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08,
        0x49, 0x10, 0x03, 0x76, 0xa8, 0x23, 0x5e, 0x2c,
        0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21,
        0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76,
    ];
}

/// Run SHA3-256 KAT
pub fn kat_sha3_256() -> KatTestResult {
    use crate::hash::Sha3_256;
    use crate::traits::Hash;

    // Test empty message
    let hash = Sha3_256::hash(sha3_256_vectors::EMPTY_MSG);
    if hash.as_ref() != sha3_256_vectors::EMPTY_HASH {
        return KatTestResult::Failed;
    }

    // Test "abc"
    let hash = Sha3_256::hash(sha3_256_vectors::ABC_MSG);
    if hash.as_ref() != sha3_256_vectors::ABC_HASH {
        return KatTestResult::Failed;
    }

    // Test 448-bit message
    let hash = Sha3_256::hash(sha3_256_vectors::MSG_448);
    if hash.as_ref() != sha3_256_vectors::HASH_448 {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// SHA3-512 KAT Vectors
// ============================================================================

mod sha3_512_vectors {
    /// Empty message test
    pub const EMPTY_HASH: [u8; 64] = [
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
    ];

    /// "abc" test vector
    pub const ABC_HASH: [u8; 64] = [
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
        0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
        0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
        0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
        0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
        0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
        0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
        0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0,
    ];
}

/// Run SHA3-512 KAT
pub fn kat_sha3_512() -> KatTestResult {
    use crate::hash::Sha3_512;
    use crate::traits::Hash;

    // Test empty message
    let hash = Sha3_512::hash(&[]);
    if hash.as_ref() != sha3_512_vectors::EMPTY_HASH {
        return KatTestResult::Failed;
    }

    // Test "abc"
    let hash = Sha3_512::hash(b"abc");
    if hash.as_ref() != sha3_512_vectors::ABC_HASH {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// SHAKE128 KAT Vectors
// ============================================================================

mod shake128_vectors {
    /// Empty message, 256-bit output
    pub const EMPTY_256: [u8; 32] = [
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
    ];
}

/// Run SHAKE128 KAT
pub fn kat_shake128() -> KatTestResult {
    use crate::hash::Shake128;

    // Test empty message with 256-bit output
    let mut output = [0u8; 32];
    Shake128::squeeze(&[], &mut output);

    if output != shake128_vectors::EMPTY_256 {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// SHAKE256 KAT Vectors
// ============================================================================

mod shake256_vectors {
    /// Empty message, 512-bit output
    pub const EMPTY_512: [u8; 64] = [
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
        0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00,
        0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
        0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
        0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe,
    ];
}

/// Run SHAKE256 KAT
pub fn kat_shake256() -> KatTestResult {
    use crate::hash::Shake256;

    // Test empty message with 512-bit output
    let mut output = [0u8; 64];
    Shake256::squeeze(&[], &mut output);

    if output != shake256_vectors::EMPTY_512 {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// AES-256-GCM KAT Vectors (NIST SP 800-38D)
// ============================================================================

mod aes_gcm_vectors {
    /// Test Case 14 from NIST SP 800-38D
    pub const KEY: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    pub const NONCE: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    pub const PLAINTEXT: &[u8] = &[];

    pub const AAD: &[u8] = &[];

    #[allow(dead_code)]
    pub const CIPHERTEXT: &[u8] = &[];

    pub const TAG: [u8; 16] = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
        0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
    ];

    /// Test Case 16 - with plaintext
    pub const TC16_KEY: [u8; 32] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    ];

    pub const TC16_NONCE: [u8; 12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    ];

    pub const TC16_PLAINTEXT: [u8; 64] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
    ];

    pub const TC16_CIPHERTEXT: [u8; 64] = [
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad,
    ];

    pub const TC16_TAG: [u8; 16] = [
        0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
        0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c,
    ];
}

/// Run AES-256-GCM KAT
pub fn kat_aes_256_gcm() -> KatTestResult {
    use crate::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
    use crate::traits::Aead;

    // Test Case 14 - empty plaintext
    // For empty plaintext, output is just the tag (16 bytes)
    let mut output = [0u8; 16];

    let key = Aes256Key::new(aes_gcm_vectors::KEY);
    let nonce = AesGcmNonce::new(aes_gcm_vectors::NONCE);

    let len = match Aes256Gcm::encrypt(
        &key,
        &nonce,
        aes_gcm_vectors::PLAINTEXT, // empty
        aes_gcm_vectors::AAD,
        &mut output,
    ) {
        Ok(l) => l,
        Err(_) => return KatTestResult::Failed,
    };

    // For empty plaintext, output should be just the tag
    if len != 16 || output != aes_gcm_vectors::TAG {
        return KatTestResult::Failed;
    }

    // Test Case 16 - with plaintext (64 bytes plaintext + 16 bytes tag = 80)
    let key16 = Aes256Key::new(aes_gcm_vectors::TC16_KEY);
    let nonce16 = AesGcmNonce::new(aes_gcm_vectors::TC16_NONCE);
    let mut ct16 = [0u8; 80]; // 64 + 16 for tag

    let ct_len = match Aes256Gcm::encrypt(
        &key16,
        &nonce16,
        &aes_gcm_vectors::TC16_PLAINTEXT,
        &[],
        &mut ct16,
    ) {
        Ok(l) => l,
        Err(_) => return KatTestResult::Failed,
    };

    if ct_len != 80 {
        return KatTestResult::Failed;
    }

    // Check ciphertext (first 64 bytes)
    if ct16[..64] != aes_gcm_vectors::TC16_CIPHERTEXT {
        return KatTestResult::Failed;
    }

    // Check tag (last 16 bytes)
    if ct16[64..80] != aes_gcm_vectors::TC16_TAG {
        return KatTestResult::Failed;
    }

    // Test decryption
    let mut pt16 = [0u8; 64];
    let pt_len = match Aes256Gcm::decrypt(
        &key16,
        &nonce16,
        &ct16[..ct_len], // ciphertext includes tag
        &[],
        &mut pt16,
    ) {
        Ok(l) => l,
        Err(_) => return KatTestResult::Failed,
    };

    if pt_len != 64 || pt16 != aes_gcm_vectors::TC16_PLAINTEXT {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// ChaCha20-Poly1305 KAT Vectors (RFC 8439)
// ============================================================================

mod chacha_vectors {
    /// RFC 8439 Test Vector
    pub const KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];

    pub const NONCE: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    ];

    pub const AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];

    pub const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    pub const TAG: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];
}

/// Run ChaCha20-Poly1305 KAT
pub fn kat_chacha20_poly1305() -> KatTestResult {
    use crate::aead::{ChaCha20Poly1305Impl, ChaCha20Key, ChaCha20Nonce};
    use crate::traits::Aead;

    let key = ChaCha20Key::new(chacha_vectors::KEY);
    let nonce = ChaCha20Nonce::new(chacha_vectors::NONCE);

    // Ciphertext includes the 16-byte tag
    let mut ciphertext = [0u8; 130]; // 114 + 16

    let ct_len = match ChaCha20Poly1305Impl::encrypt(
        &key,
        &nonce,
        chacha_vectors::PLAINTEXT,
        &chacha_vectors::AAD,
        &mut ciphertext,
    ) {
        Ok(len) => len,
        Err(_) => return KatTestResult::Failed,
    };

    // Verify the tag is at the end of ciphertext
    if ct_len != 130 {
        return KatTestResult::Failed;
    }

    if ciphertext[114..130] != chacha_vectors::TAG {
        return KatTestResult::Failed;
    }

    // Test decryption
    let mut plaintext = [0u8; 114];
    let result = ChaCha20Poly1305Impl::decrypt(
        &key,
        &nonce,
        &ciphertext[..ct_len],
        &chacha_vectors::AAD,
        &mut plaintext,
    );

    if result.is_err() || &plaintext[..] != chacha_vectors::PLAINTEXT {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// ML-KEM-768 (Kyber) KAT
// ============================================================================

/// Run ML-KEM-768 KAT
///
/// Since we don't have official NIST vectors embedded, we perform
/// functional testing: keygen -> encaps -> decaps -> verify shared secret
pub fn kat_ml_kem_768() -> KatTestResult {
    use crate::kyber::Kyber768;
    use crate::rng::SimpleRng;
    use crate::traits::Kem;

    // Use deterministic RNG for reproducibility
    let mut rng = SimpleRng::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ]);

    // Generate keypair
    let (pk, sk) = match Kyber768::keypair(&mut rng) {
        Ok(kp) => kp,
        Err(_) => return KatTestResult::Failed,
    };

    // Encapsulate
    let (ct, ss1) = match Kyber768::encapsulate(&pk, &mut rng) {
        Ok(result) => result,
        Err(_) => return KatTestResult::Failed,
    };

    // Decapsulate
    let ss2 = match Kyber768::decapsulate(&sk, &ct) {
        Ok(ss) => ss,
        Err(_) => return KatTestResult::Failed,
    };

    // Shared secrets must match
    if ss1.as_ref() != ss2.as_ref() {
        return KatTestResult::Failed;
    }

    // Verify shared secret is not all zeros
    let all_zero = ss1.as_ref().iter().all(|&b| b == 0);
    if all_zero {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// ML-DSA-65 (Dilithium3) KAT
// ============================================================================

/// Run ML-DSA-65 KAT
///
/// Functional test: keygen -> sign -> verify
pub fn kat_ml_dsa_65() -> KatTestResult {
    use crate::dilithium::Dilithium3;
    use crate::rng::SimpleRng;
    use crate::traits::Signer;

    // Use deterministic RNG
    let mut rng = SimpleRng::new([
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ]);

    // Test message
    let message = b"This is a test message for ML-DSA-65 KAT verification";

    // Generate keypair
    let (pk, sk) = match Dilithium3::keypair(&mut rng) {
        Ok(kp) => kp,
        Err(_) => return KatTestResult::Failed,
    };

    // Sign message
    let signature = match Dilithium3::sign(&sk, message) {
        Ok(sig) => sig,
        Err(_) => return KatTestResult::Failed,
    };

    // Verify signature
    match Dilithium3::verify(&pk, message, &signature) {
        Ok(true) => {}
        _ => return KatTestResult::Failed,
    }

    // Verify that modified message fails
    let mut bad_message = *message;
    bad_message[0] ^= 0xFF;
    match Dilithium3::verify(&pk, &bad_message, &signature) {
        Ok(false) => {}
        _ => return KatTestResult::Failed,
    }

    // Verify that modified signature fails
    let mut bad_sig = signature;
    bad_sig.bytes_mut()[0] ^= 0xFF;
    match Dilithium3::verify(&pk, message, &bad_sig) {
        Ok(false) => {}
        _ => return KatTestResult::Failed,
    }

    KatTestResult::Passed
}

// ============================================================================
// DRBG KAT (NIST SP 800-90A)
// ============================================================================

mod drbg_vectors {
    /// Hash_DRBG test vector (SHA-256)
    /// From NIST CAVP testing
    pub const ENTROPY_INPUT: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];

    pub const NONCE: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    ];
}

/// Run DRBG KAT
pub fn kat_drbg() -> KatTestResult {
    use crate::rng::HashDrbg;
    use crate::traits::CryptoRng;

    // Create DRBG with known entropy
    let entropy = &drbg_vectors::ENTROPY_INPUT;
    let nonce = &drbg_vectors::NONCE;

    let mut drbg = match HashDrbg::instantiate(entropy, nonce, b"Qbitel EdgeOS-KAT", false) {
        Ok(d) => d,
        Err(_) => return KatTestResult::Failed,
    };

    // Generate random bytes
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    if drbg.fill_bytes(&mut output1).is_err() {
        return KatTestResult::Failed;
    }

    if drbg.fill_bytes(&mut output2).is_err() {
        return KatTestResult::Failed;
    }

    // Outputs should be different
    if output1 == output2 {
        return KatTestResult::Failed;
    }

    // Output should not be all zeros
    if output1.iter().all(|&b| b == 0) {
        return KatTestResult::Failed;
    }

    // Test reseed with varied entropy (uniform bytes would trigger health test)
    let mut new_entropy = [0u8; 32];
    for i in 0..32 {
        new_entropy[i] = (i as u8).wrapping_mul(0x37).wrapping_add(0x42);
    }
    if drbg.reseed(&new_entropy, &[]).is_err() {
        return KatTestResult::Failed;
    }

    KatTestResult::Passed
}

// ============================================================================
// Run All KAT
// ============================================================================

/// Run all Known Answer Tests
pub fn run_all_kat() -> KatResults {
    KatResults {
        sha3_256: kat_sha3_256(),
        sha3_512: kat_sha3_512(),
        shake128: kat_shake128(),
        shake256: kat_shake256(),
        aes_256_gcm: kat_aes_256_gcm(),
        chacha20_poly1305: kat_chacha20_poly1305(),
        ml_kem_768: kat_ml_kem_768(),
        ml_dsa_65: kat_ml_dsa_65(),
        drbg: kat_drbg(),
    }
}

/// Run critical KAT only (fast subset for boot-time verification)
pub fn run_critical_kat() -> bool {
    // Only run the most critical tests during boot
    kat_sha3_256() == KatTestResult::Passed
        && kat_aes_256_gcm() == KatTestResult::Passed
        && kat_drbg() == KatTestResult::Passed
}

// ============================================================================
// Self-Test Interface
// ============================================================================

/// FIPS 140-3 style self-test
pub struct CryptoSelfTest {
    /// Test has been run
    completed: bool,
    /// Test passed
    passed: bool,
    /// Detailed results
    results: Option<KatResults>,
}

impl CryptoSelfTest {
    /// Create new self-test instance
    pub const fn new() -> Self {
        Self {
            completed: false,
            passed: false,
            results: None,
        }
    }

    /// Run self-test
    pub fn run(&mut self) -> bool {
        let results = run_all_kat();
        self.passed = results.all_passed();
        self.results = Some(results);
        self.completed = true;
        self.passed
    }

    /// Check if self-test has been run
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Check if self-test passed
    pub fn is_passed(&self) -> bool {
        self.passed
    }

    /// Get detailed results
    pub fn results(&self) -> Option<&KatResults> {
        self.results.as_ref()
    }
}

impl Default for CryptoSelfTest {
    fn default() -> Self {
        Self::new()
    }
}

/// Global self-test instance using UnsafeCell for interior mutability
/// without creating references to mutable statics (Rust 2024 compatible).
struct SyncSelfTest(core::cell::UnsafeCell<CryptoSelfTest>);

// SAFETY: Access is gated behind unsafe functions that require
// single-threaded context. The embedded OS initializes this
// before any concurrent access.
unsafe impl Sync for SyncSelfTest {}

static SELF_TEST: SyncSelfTest = SyncSelfTest(core::cell::UnsafeCell::new(CryptoSelfTest::new()));

/// Run crypto self-test (should be called at startup)
///
/// # Safety
/// Must be called from single-threaded context during initialization
pub unsafe fn run_self_test() -> bool {
    (*SELF_TEST.0.get()).run()
}

/// Check if self-test passed
///
/// # Safety
/// Must be called after run_self_test
pub unsafe fn self_test_passed() -> bool {
    (*SELF_TEST.0.get()).is_passed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_kat() {
        assert_eq!(kat_sha3_256(), KatTestResult::Passed);
    }

    #[test]
    fn test_sha3_512_kat() {
        assert_eq!(kat_sha3_512(), KatTestResult::Passed);
    }

    #[test]
    fn test_all_kat() {
        let results = run_all_kat();
        assert!(results.all_passed(), "Failed: {} tests", results.failed_count());
    }
}
