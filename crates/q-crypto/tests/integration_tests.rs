// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Integration tests for q-crypto
//!
//! These tests exercise the actual cryptographic implementations end-to-end,
//! including cross-module interactions, KAT vectors, and security properties.

mod hash_tests {
    use q_crypto::hash::Sha3_256;
    use q_crypto::traits::Hash;

    #[test]
    fn test_sha3_256_empty_input() {
        // NIST KAT: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let expected = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];

        let result = Sha3_256::hash(&[]);
        assert_eq!(result.as_ref(), &expected);
    }

    #[test]
    fn test_sha3_256_abc() {
        // NIST KAT: SHA3-256("abc")
        let expected = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];

        let result = Sha3_256::hash(b"abc");
        assert_eq!(result.as_ref(), &expected);
    }

    #[test]
    fn test_sha3_256_incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";

        let oneshot = Sha3_256::hash(data);

        let mut hasher = Sha3_256::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..25]);
        hasher.update(&data[25..]);
        let incremental = hasher.finalize();

        assert_eq!(oneshot.as_ref(), incremental.as_ref());
    }

    #[test]
    fn test_sha3_256_different_inputs_different_outputs() {
        let h1 = Sha3_256::hash(b"input1");
        let h2 = Sha3_256::hash(b"input2");
        assert_ne!(h1.as_ref(), h2.as_ref());
    }

    #[test]
    fn test_sha3_256_single_bit_avalanche() {
        // Changing one bit should change ~50% of output bits
        let mut data_a = [0u8; 32];
        let mut data_b = [0u8; 32];
        data_b[0] = 1; // Single bit difference

        let h1 = Sha3_256::hash(&data_a);
        let h2 = Sha3_256::hash(&data_b);

        let mut differing_bits = 0u32;
        for (a, b) in h1.as_ref().iter().zip(h2.as_ref().iter()) {
            differing_bits += (a ^ b).count_ones();
        }

        // Should differ in roughly 128 of 256 bits (±40 for randomness)
        assert!(differing_bits > 80, "Avalanche too low: {differing_bits} bits differ");
        assert!(differing_bits < 180, "Avalanche too high: {differing_bits} bits differ");
    }
}

mod aead_tests {
    use q_crypto::aead::Aes256Gcm;
    use q_crypto::traits::Aead;

    #[test]
    fn test_aes256gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello Qbitel EdgeOS!";
        let aad = b"additional data";

        let cipher = Aes256Gcm::new(&key);

        let mut ciphertext_buf = [0u8; 256];
        let ct_len = cipher.encrypt(&nonce, plaintext, aad, &mut ciphertext_buf)
            .expect("encryption should succeed");

        // Ciphertext should be plaintext_len + 16 (GCM tag)
        assert_eq!(ct_len, plaintext.len() + 16);

        let mut decrypted_buf = [0u8; 256];
        let pt_len = cipher.decrypt(&nonce, &ciphertext_buf[..ct_len], aad, &mut decrypted_buf)
            .expect("decryption should succeed");

        assert_eq!(&decrypted_buf[..pt_len], plaintext);
    }

    #[test]
    fn test_aes256gcm_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"sensitive data";
        let aad = b"";

        let cipher = Aes256Gcm::new(&key);

        let mut ciphertext_buf = [0u8; 256];
        let ct_len = cipher.encrypt(&nonce, plaintext, aad, &mut ciphertext_buf)
            .expect("encryption should succeed");

        // Tamper with ciphertext
        ciphertext_buf[0] ^= 0xFF;

        let mut decrypted_buf = [0u8; 256];
        let result = cipher.decrypt(&nonce, &ciphertext_buf[..ct_len], aad, &mut decrypted_buf);
        assert!(result.is_err(), "Decryption of tampered ciphertext should fail");
    }

    #[test]
    fn test_aes256gcm_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret";

        let cipher1 = Aes256Gcm::new(&key1);
        let cipher2 = Aes256Gcm::new(&key2);

        let mut ciphertext_buf = [0u8; 256];
        let ct_len = cipher1.encrypt(&nonce, plaintext, b"", &mut ciphertext_buf)
            .expect("encryption should succeed");

        let mut decrypted_buf = [0u8; 256];
        let result = cipher2.decrypt(&nonce, &ciphertext_buf[..ct_len], b"", &mut decrypted_buf);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_aes256gcm_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"data";

        let cipher = Aes256Gcm::new(&key);

        let mut ciphertext_buf = [0u8; 256];
        let ct_len = cipher.encrypt(&nonce, plaintext, b"correct aad", &mut ciphertext_buf)
            .expect("encryption should succeed");

        let mut decrypted_buf = [0u8; 256];
        let result = cipher.decrypt(&nonce, &ciphertext_buf[..ct_len], b"wrong aad", &mut decrypted_buf);
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }
}

mod kyber_tests {
    use q_crypto::kyber::{Kyber768, Kyber768PublicKey, Kyber768SecretKey};
    use q_crypto::traits::Kem;
    use q_crypto::rng::TestRng;

    #[test]
    fn test_kyber768_keygen_encaps_decaps() {
        let mut rng = TestRng::new([0x42u8; 32]);

        let (pk, sk) = Kyber768::keygen(&mut rng).expect("keygen should succeed");

        let (ciphertext, shared_secret_enc) = Kyber768::encapsulate(&pk, &mut rng)
            .expect("encapsulation should succeed");

        let shared_secret_dec = Kyber768::decapsulate(&sk, &ciphertext)
            .expect("decapsulation should succeed");

        assert_eq!(
            shared_secret_enc.as_ref(),
            shared_secret_dec.as_ref(),
            "Shared secrets must match after encaps/decaps"
        );
    }

    #[test]
    fn test_kyber768_wrong_ciphertext_gives_different_secret() {
        let mut rng = TestRng::new([0x42u8; 32]);

        let (pk, sk) = Kyber768::keygen(&mut rng).expect("keygen should succeed");
        let (mut ciphertext, shared_secret_enc) = Kyber768::encapsulate(&pk, &mut rng)
            .expect("encapsulation should succeed");

        // Corrupt the ciphertext
        ciphertext.as_mut()[0] ^= 0xFF;

        let shared_secret_dec = Kyber768::decapsulate(&sk, &ciphertext)
            .expect("decapsulation should succeed (implicit rejection)");

        // ML-KEM uses implicit rejection: wrong ciphertext produces a
        // pseudorandom shared secret, not an error
        assert_ne!(
            shared_secret_enc.as_ref(),
            shared_secret_dec.as_ref(),
            "Corrupted ciphertext must produce different shared secret"
        );
    }

    #[test]
    fn test_kyber768_different_keypairs_different_secrets() {
        let mut rng1 = TestRng::new([0x01u8; 32]);
        let mut rng2 = TestRng::new([0x02u8; 32]);

        let (pk1, _sk1) = Kyber768::keygen(&mut rng1).expect("keygen 1");
        let (pk2, _sk2) = Kyber768::keygen(&mut rng2).expect("keygen 2");

        let mut rng3 = TestRng::new([0x03u8; 32]);
        let (_, ss1) = Kyber768::encapsulate(&pk1, &mut rng3).expect("encaps 1");

        let mut rng4 = TestRng::new([0x03u8; 32]);
        let (_, ss2) = Kyber768::encapsulate(&pk2, &mut rng4).expect("encaps 2");

        assert_ne!(ss1.as_ref(), ss2.as_ref(), "Different keys should produce different secrets");
    }

    #[test]
    fn test_kyber768_key_serialization_roundtrip() {
        let mut rng = TestRng::new([0x55u8; 32]);
        let (pk, sk) = Kyber768::keygen(&mut rng).expect("keygen");

        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();

        let pk_restored = Kyber768PublicKey::from_bytes(pk_bytes).expect("pk deserialize");
        let sk_restored = Kyber768SecretKey::from_bytes(sk_bytes).expect("sk deserialize");

        // Encaps with restored key, decaps with restored key
        let mut rng2 = TestRng::new([0x66u8; 32]);
        let (ct, ss_enc) = Kyber768::encapsulate(&pk_restored, &mut rng2).expect("encaps");
        let ss_dec = Kyber768::decapsulate(&sk_restored, &ct).expect("decaps");

        assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
    }
}

mod dilithium_tests {
    use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3SecretKey};
    use q_crypto::traits::Signer;
    use q_crypto::rng::TestRng;

    #[test]
    fn test_dilithium3_sign_verify() {
        let mut rng = TestRng::new([0x42u8; 32]);
        let (pk, sk) = Dilithium3::keygen(&mut rng).expect("keygen");

        let message = b"Qbitel EdgeOS firmware v1.0.0";
        let signature = Dilithium3::sign(&sk, message).expect("sign");

        let valid = Dilithium3::verify(&pk, message, &signature).expect("verify");
        assert!(valid, "Valid signature should verify");
    }

    #[test]
    fn test_dilithium3_wrong_message_fails() {
        let mut rng = TestRng::new([0x42u8; 32]);
        let (pk, sk) = Dilithium3::keygen(&mut rng).expect("keygen");

        let signature = Dilithium3::sign(&sk, b"correct message").expect("sign");

        let valid = Dilithium3::verify(&pk, b"wrong message", &signature).expect("verify");
        assert!(!valid, "Signature should not verify for wrong message");
    }

    #[test]
    fn test_dilithium3_wrong_key_fails() {
        let mut rng1 = TestRng::new([0x01u8; 32]);
        let mut rng2 = TestRng::new([0x02u8; 32]);

        let (_pk1, sk1) = Dilithium3::keygen(&mut rng1).expect("keygen 1");
        let (pk2, _sk2) = Dilithium3::keygen(&mut rng2).expect("keygen 2");

        let message = b"signed by key 1";
        let signature = Dilithium3::sign(&sk1, message).expect("sign");

        let valid = Dilithium3::verify(&pk2, message, &signature).expect("verify");
        assert!(!valid, "Signature should not verify with wrong public key");
    }

    #[test]
    fn test_dilithium3_deterministic_signatures() {
        let mut rng = TestRng::new([0x42u8; 32]);
        let (_pk, sk) = Dilithium3::keygen(&mut rng).expect("keygen");

        let message = b"deterministic test";
        let sig1 = Dilithium3::sign(&sk, message).expect("sign 1");
        let sig2 = Dilithium3::sign(&sk, message).expect("sign 2");

        // Dilithium uses deterministic signing (no randomness in sign)
        assert_eq!(sig1.as_bytes(), sig2.as_bytes(), "Signatures should be deterministic");
    }

    #[test]
    fn test_dilithium3_key_serialization_roundtrip() {
        let mut rng = TestRng::new([0x77u8; 32]);
        let (pk, sk) = Dilithium3::keygen(&mut rng).expect("keygen");

        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();

        let pk_restored = Dilithium3PublicKey::from_bytes(pk_bytes).expect("pk from bytes");
        let sk_restored = Dilithium3SecretKey::from_bytes(sk_bytes).expect("sk from bytes");

        let message = b"serialization roundtrip test";
        let sig = Dilithium3::sign(&sk_restored, message).expect("sign with restored key");
        let valid = Dilithium3::verify(&pk_restored, message, &sig).expect("verify with restored key");
        assert!(valid);
    }

    #[test]
    fn test_dilithium3_empty_message() {
        let mut rng = TestRng::new([0x42u8; 32]);
        let (pk, sk) = Dilithium3::keygen(&mut rng).expect("keygen");

        let signature = Dilithium3::sign(&sk, b"").expect("sign empty");
        let valid = Dilithium3::verify(&pk, b"", &signature).expect("verify empty");
        assert!(valid, "Should handle empty messages");
    }

    #[test]
    fn test_dilithium3_large_message() {
        let mut rng = TestRng::new([0x42u8; 32]);
        let (pk, sk) = Dilithium3::keygen(&mut rng).expect("keygen");

        let large_msg = vec![0xAB; 10_000];
        let signature = Dilithium3::sign(&sk, &large_msg).expect("sign large");
        let valid = Dilithium3::verify(&pk, &large_msg, &signature).expect("verify large");
        assert!(valid, "Should handle large messages");
    }
}

mod zeroize_tests {
    use q_crypto::zeroize_utils::{secure_zero, constant_time_compare};

    #[test]
    fn test_secure_zero_clears_memory() {
        let mut buf = [0xFFu8; 64];
        secure_zero(&mut buf);
        assert!(buf.iter().all(|&b| b == 0), "Buffer should be all zeros after secure_zero");
    }

    #[test]
    fn test_constant_time_compare_equal() {
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let b = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let b = [1u8, 2, 3, 4, 5, 6, 7, 9]; // Last byte different
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!constant_time_compare(&a, &b));
    }
}

mod kat_tests {
    use q_crypto::kat;

    #[test]
    fn test_sha3_256_kat() {
        let result = kat::kat_sha3_256();
        assert!(result.passed, "SHA3-256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_aes_256_gcm_kat() {
        let result = kat::kat_aes_256_gcm();
        assert!(result.passed, "AES-256-GCM KAT failed: {:?}", result);
    }

    #[test]
    fn test_all_kat() {
        let results = kat::run_all_kat();
        assert!(results.all_passed(), "Not all KAT passed: {:?}", results);
    }

    #[test]
    fn test_critical_kat() {
        let results = kat::run_critical_kat();
        assert!(results.all_passed(), "Critical KAT failed: {:?}", results);
    }
}

mod cross_module_tests {
    use q_crypto::hash::Sha3_256;
    use q_crypto::traits::Hash;
    use q_crypto::dilithium::Dilithium3;
    use q_crypto::traits::Signer;
    use q_crypto::rng::TestRng;

    #[test]
    fn test_sign_hash_of_data() {
        // Typical firmware verification flow: hash data, then sign the hash
        let firmware = [0xABu8; 1024];
        let firmware_hash = Sha3_256::hash(&firmware);

        let mut rng = TestRng::new([0x42u8; 32]);
        let (pk, sk) = Dilithium3::keygen(&mut rng).expect("keygen");

        let signature = Dilithium3::sign(&sk, firmware_hash.as_ref()).expect("sign hash");
        let valid = Dilithium3::verify(&pk, firmware_hash.as_ref(), &signature).expect("verify");
        assert!(valid, "Signature over hash should verify");

        // Tampered firmware should fail
        let mut tampered = [0xABu8; 1024];
        tampered[500] = 0x00;
        let tampered_hash = Sha3_256::hash(&tampered);

        let valid = Dilithium3::verify(&pk, tampered_hash.as_ref(), &signature).expect("verify tampered");
        assert!(!valid, "Signature should fail for tampered firmware hash");
    }
}
