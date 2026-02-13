// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Performance benchmarks for Qbitel EdgeOS cryptographic operations
//!
//! Run with: cargo bench --package q-crypto

#![feature(test)]

extern crate test;

use test::Bencher;

// Note: These benchmarks require the "std" feature or a benchmark harness
// In no_std environment, use criterion with custom setup

/// Benchmark SHA3-256 hashing
#[bench]
fn bench_sha3_256_1kb(b: &mut Bencher) {
    let data = vec![0u8; 1024];
    b.iter(|| {
        // In production: use q_crypto::hash::sha3_256(&data)
        let mut hasher = sha3::Sha3_256::new();
        sha3::Digest::update(&mut hasher, &data);
        sha3::Digest::finalize(hasher)
    });
}

#[bench]
fn bench_sha3_256_64kb(b: &mut Bencher) {
    let data = vec![0u8; 65536];
    b.iter(|| {
        let mut hasher = sha3::Sha3_256::new();
        sha3::Digest::update(&mut hasher, &data);
        sha3::Digest::finalize(hasher)
    });
}

/// Benchmark AES-256-GCM encryption
#[bench]
fn bench_aes_gcm_encrypt_1kb(b: &mut Bencher) {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;

    let key = GenericArray::from_slice(&[0u8; 32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let plaintext = vec![0u8; 1024];

    b.iter(|| {
        cipher.encrypt(nonce, plaintext.as_slice()).unwrap()
    });
}

#[bench]
fn bench_aes_gcm_decrypt_1kb(b: &mut Bencher) {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;

    let key = GenericArray::from_slice(&[0u8; 32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    let plaintext = vec![0u8; 1024];
    let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();

    b.iter(|| {
        cipher.decrypt(nonce, ciphertext.as_slice()).unwrap()
    });
}

/// Benchmark HKDF key derivation
#[bench]
fn bench_hkdf_derive_key(b: &mut Bencher) {
    let ikm = [0u8; 32];
    let salt = [0u8; 32];
    let info = b"benchmark key derivation";

    b.iter(|| {
        // Simulate HKDF-SHA3-256
        let mut hasher = sha3::Sha3_256::new();
        sha3::Digest::update(&mut hasher, &salt);
        sha3::Digest::update(&mut hasher, &ikm);
        sha3::Digest::update(&mut hasher, info);
        sha3::Digest::finalize(hasher)
    });
}

/// Benchmark constant-time comparison
#[bench]
fn bench_constant_time_eq_32(b: &mut Bencher) {
    let a = [0xAAu8; 32];
    let b_data = [0xAAu8; 32];

    b.iter(|| {
        // Constant-time comparison
        let mut result = 0u8;
        for i in 0..32 {
            result |= a[i] ^ b_data[i];
        }
        result == 0
    });
}

/// Benchmark zeroization
#[bench]
fn bench_zeroize_256_bytes(b: &mut Bencher) {
    b.iter(|| {
        let mut data = [0xFFu8; 256];
        // Volatile write to prevent optimization
        for byte in data.iter_mut() {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        data
    });
}

// Note: PQC benchmarks (Kyber, Dilithium) require the actual implementations
// These would be added when running with the full crypto library

#[cfg(feature = "pqc")]
mod pqc_benchmarks {
    use super::*;

    #[bench]
    fn bench_kyber768_keygen(b: &mut Bencher) {
        // Requires actual Kyber implementation
        b.iter(|| {
            // q_crypto::kyber::Kyber768::keypair()
        });
    }

    #[bench]
    fn bench_kyber768_encaps(b: &mut Bencher) {
        b.iter(|| {
            // q_crypto::kyber::Kyber768::encapsulate(&public_key)
        });
    }

    #[bench]
    fn bench_kyber768_decaps(b: &mut Bencher) {
        b.iter(|| {
            // q_crypto::kyber::Kyber768::decapsulate(&ciphertext, &secret_key)
        });
    }

    #[bench]
    fn bench_dilithium3_keygen(b: &mut Bencher) {
        b.iter(|| {
            // q_crypto::dilithium::Dilithium3::keypair()
        });
    }

    #[bench]
    fn bench_dilithium3_sign(b: &mut Bencher) {
        let message = vec![0u8; 256];
        b.iter(|| {
            // q_crypto::dilithium::Dilithium3::sign(&message, &secret_key)
        });
    }

    #[bench]
    fn bench_dilithium3_verify(b: &mut Bencher) {
        let message = vec![0u8; 256];
        b.iter(|| {
            // q_crypto::dilithium::Dilithium3::verify(&message, &signature, &public_key)
        });
    }
}
