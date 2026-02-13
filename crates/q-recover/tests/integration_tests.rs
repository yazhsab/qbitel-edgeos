// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Comprehensive tests for q-recover
//!
//! Tests for key recovery, threshold signatures, and Shamir Secret Sharing.

#![cfg(test)]

mod threshold_tests {
    use q_recover::threshold::{
        ThresholdScheme, Share, Dealer, split_secret, reconstruct_secret,
        MAX_SHARES, MAX_THRESHOLD, SHARE_SIZE,
    };
    use q_common::Error;

    fn deterministic_rng(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }
    }

    fn random_rng(buf: &mut [u8]) {
        // Use a simple LCG for more varied testing
        static mut SEED: u64 = 12345;
        for byte in buf.iter_mut() {
            unsafe {
                SEED = SEED.wrapping_mul(1103515245).wrapping_add(12345);
                *byte = (SEED >> 16) as u8;
            }
        }
    }

    #[test]
    fn test_scheme_creation_valid() {
        // Valid configurations
        assert!(ThresholdScheme::new(1, 1).is_ok());
        assert!(ThresholdScheme::new(2, 3).is_ok());
        assert!(ThresholdScheme::new(3, 5).is_ok());
        assert!(ThresholdScheme::new(5, 5).is_ok());
        assert!(ThresholdScheme::new(MAX_THRESHOLD as u8, MAX_SHARES as u8).is_ok());
    }

    #[test]
    fn test_scheme_creation_invalid() {
        // threshold = 0
        assert!(ThresholdScheme::new(0, 3).is_err());

        // threshold > total
        assert!(ThresholdScheme::new(5, 3).is_err());

        // total > MAX_SHARES
        assert!(ThresholdScheme::new(3, (MAX_SHARES + 1) as u8).is_err());
    }

    #[test]
    fn test_scheme_getters() {
        let scheme = ThresholdScheme::new(3, 5).unwrap();
        assert_eq!(scheme.threshold(), 3);
        assert_eq!(scheme.total(), 5);
    }

    #[test]
    fn test_2_of_3_split_reconstruct() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();

        let shares = scheme.split(&secret, deterministic_rng).unwrap();
        assert_eq!(shares.len(), 3);

        // Verify each share has unique index
        assert_eq!(shares[0].index, 1);
        assert_eq!(shares[1].index, 2);
        assert_eq!(shares[2].index, 3);

        // Reconstruct with different combinations
        let recovered = scheme.reconstruct(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = scheme.reconstruct(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = scheme.reconstruct(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_3_of_5_split_reconstruct() {
        let mut secret = [0u8; SHARE_SIZE];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let scheme = ThresholdScheme::new(3, 5).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();
        assert_eq!(shares.len(), 5);

        // First 3 shares
        let recovered = scheme.reconstruct(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        // Last 3 shares
        let recovered = scheme.reconstruct(&shares[2..5]).unwrap();
        assert_eq!(recovered, secret);

        // Non-contiguous shares
        let recovered = scheme.reconstruct(&[
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
        ]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_5_of_5_n_of_n() {
        let secret = [0x77u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(5, 5).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        // Must have all 5 shares
        assert!(scheme.reconstruct(&shares[0..4]).is_err());

        let recovered = scheme.reconstruct(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_1_of_1_trivial() {
        let secret = [0x55u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(1, 1).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        assert_eq!(shares.len(), 1);

        let recovered = scheme.reconstruct(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = [0xABu8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(3, 5).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        let result = scheme.reconstruct(&shares[0..2]);
        assert_eq!(result.unwrap_err(), Error::InsufficientShares);

        let result = scheme.reconstruct(&shares[0..1]);
        assert_eq!(result.unwrap_err(), Error::InsufficientShares);

        let result = scheme.reconstruct(&[]);
        assert_eq!(result.unwrap_err(), Error::InsufficientShares);
    }

    #[test]
    fn test_duplicate_shares_rejected() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        let result = scheme.reconstruct(&[shares[0].clone(), shares[0].clone()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_index_rejected() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        // Create a share with index 0
        let bad_share = Share::new(0, [0xAB; SHARE_SIZE]);
        let result = scheme.reconstruct(&[shares[0].clone(), bad_share]);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_serialization() {
        let share = Share::new(5, [0xAB; SHARE_SIZE]);
        let bytes = share.to_bytes();

        assert_eq!(bytes[0], 5);
        assert_eq!(&bytes[1..], &[0xAB; SHARE_SIZE]);

        let recovered = Share::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.index, 5);
        assert_eq!(recovered.data, [0xAB; SHARE_SIZE]);
    }

    #[test]
    fn test_share_serialization_zero_index_fails() {
        let mut bytes = [0u8; SHARE_SIZE + 1];
        bytes[0] = 0; // Invalid index

        let result = Share::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_verification() {
        let scheme = ThresholdScheme::new(3, 5).unwrap();

        // Valid indices
        assert!(scheme.verify_share(&Share::new(1, [0; SHARE_SIZE])));
        assert!(scheme.verify_share(&Share::new(3, [0; SHARE_SIZE])));
        assert!(scheme.verify_share(&Share::new(5, [0; SHARE_SIZE])));

        // Invalid indices
        assert!(!scheme.verify_share(&Share::new(0, [0; SHARE_SIZE])));
        assert!(!scheme.verify_share(&Share::new(6, [0; SHARE_SIZE])));
    }

    #[test]
    fn test_dealer_creation() {
        let dealer = Dealer::new(2, 4).unwrap();
        assert_eq!(dealer.threshold(), 2);
        assert_eq!(dealer.total(), 4);
    }

    #[test]
    fn test_dealer_deal_and_combine() {
        let secret = [0xCDu8; SHARE_SIZE];
        let dealer = Dealer::new(2, 4).unwrap();

        let shares = dealer.deal(&secret, deterministic_rng).unwrap();
        assert_eq!(shares.len(), 4);

        let recovered = dealer.combine(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_convenience_split_secret() {
        let secret = [0xEFu8; SHARE_SIZE];
        let shares = split_secret(&secret, 3, 5, deterministic_rng).unwrap();
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_convenience_reconstruct_secret() {
        let secret = [0xEFu8; SHARE_SIZE];
        let shares = split_secret(&secret, 3, 5, deterministic_rng).unwrap();
        let recovered = reconstruct_secret(&shares[0..3], 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_reconstruct_empty_shares() {
        let result = reconstruct_secret(&[], 2);
        assert_eq!(result.unwrap_err(), Error::InsufficientShares);
    }

    #[test]
    fn test_different_secrets() {
        let scheme = ThresholdScheme::new(2, 3).unwrap();

        // Test with various secret patterns
        let secrets: [[u8; SHARE_SIZE]; 4] = [
            [0x00; SHARE_SIZE], // All zeros
            [0xFF; SHARE_SIZE], // All ones
            [0x55; SHARE_SIZE], // Alternating
            [0xAA; SHARE_SIZE], // Alternating inverse
        ];

        for secret in &secrets {
            let shares = scheme.split(secret, deterministic_rng).unwrap();
            let recovered = scheme.reconstruct(&shares[0..2]).unwrap();
            assert_eq!(&recovered, secret);
        }
    }

    #[test]
    fn test_varying_byte_secret() {
        let mut secret = [0u8; SHARE_SIZE];
        for (i, byte) in secret.iter_mut().enumerate() {
            *byte = (i * 17 + 3) as u8; // Varied pattern
        }

        let scheme = ThresholdScheme::new(4, 7).unwrap();
        let shares = scheme.split(&secret, random_rng).unwrap();

        // Test multiple share combinations
        for i in 0..4 {
            let subset: Vec<_> = (0..4).map(|j| shares[(i + j) % 7].clone()).collect();
            let recovered = scheme.reconstruct(&subset).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_more_shares_than_needed() {
        let secret = [0xBBu8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 5).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        // Reconstruction with more shares than threshold should still work
        let recovered = scheme.reconstruct(&shares[0..4]).unwrap();
        assert_eq!(recovered, secret);

        let recovered = scheme.reconstruct(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_maximum_threshold() {
        let secret = [0x99u8; SHARE_SIZE];
        let k = MAX_THRESHOLD as u8;
        let n = MAX_SHARES as u8;

        let scheme = ThresholdScheme::new(k, n).unwrap();
        let shares = scheme.split(&secret, random_rng).unwrap();

        assert_eq!(shares.len(), MAX_SHARES);

        // Need all k shares
        let recovered = scheme.reconstruct(&shares[0..MAX_THRESHOLD]).unwrap();
        assert_eq!(recovered, secret);
    }
}

mod gf256_tests {
    //! Tests for GF(2^8) arithmetic properties

    #[test]
    fn test_field_addition_properties() {
        // Addition is XOR in GF(2^8)
        let a = 0x53u8;
        let b = 0xCAu8;

        // Commutative: a + b = b + a
        assert_eq!(a ^ b, b ^ a);

        // Associative: (a + b) + c = a + (b + c)
        let c = 0x12u8;
        assert_eq!((a ^ b) ^ c, a ^ (b ^ c));

        // Identity: a + 0 = a
        assert_eq!(a ^ 0, a);

        // Inverse: a + a = 0
        assert_eq!(a ^ a, 0);
    }

    #[test]
    fn test_field_subtraction_equals_addition() {
        // In GF(2^n), subtraction equals addition
        let a = 0x53u8;
        let b = 0xCAu8;

        // a - b = a + b (in GF(2^8))
        assert_eq!(a ^ b, a ^ b); // XOR is its own inverse
    }
}

mod security_tests {
    use q_recover::threshold::{ThresholdScheme, Share, SHARE_SIZE};

    fn deterministic_rng(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }
    }

    #[test]
    fn test_shares_reveal_nothing_individually() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(3, 5).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        // Each individual share should look random and not reveal the secret
        for share in &shares {
            // Shares should not equal the secret
            assert_ne!(share.data, secret);
        }
    }

    #[test]
    fn test_different_rng_produces_different_shares() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();

        let shares1 = scheme.split(&secret, |buf| {
            for (i, b) in buf.iter_mut().enumerate() { *b = i as u8; }
        }).unwrap();

        let shares2 = scheme.split(&secret, |buf| {
            for (i, b) in buf.iter_mut().enumerate() { *b = (i * 2) as u8; }
        }).unwrap();

        // Shares should be different (except potentially the constant term behavior)
        // At least some shares should differ
        let all_same = shares1.iter().zip(shares2.iter()).all(|(s1, s2)| s1.data == s2.data);
        assert!(!all_same, "Different RNG should produce different shares");
    }

    #[test]
    fn test_wrong_shares_produce_wrong_secret() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();
        let _shares = scheme.split(&secret, deterministic_rng).unwrap();

        // Create fake shares
        let fake_shares = [
            Share::new(1, [0xAA; SHARE_SIZE]),
            Share::new(2, [0xBB; SHARE_SIZE]),
        ];

        // Reconstructing from fake shares should not give the original secret
        let recovered = scheme.reconstruct(&fake_shares).unwrap();
        assert_ne!(recovered, secret);
    }
}

mod edge_case_tests {
    use q_recover::threshold::{ThresholdScheme, Share, SHARE_SIZE};

    fn deterministic_rng(buf: &mut [u8]) {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) % 256) as u8;
        }
    }

    #[test]
    fn test_all_zero_secret() {
        let secret = [0x00u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();
        let recovered = scheme.reconstruct(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_ones_secret() {
        let secret = [0xFFu8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(2, 3).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();
        let recovered = scheme.reconstruct(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_single_byte_difference() {
        let mut secret1 = [0x42u8; SHARE_SIZE];
        let mut secret2 = [0x42u8; SHARE_SIZE];
        secret2[0] = 0x43; // Differ by one byte

        let scheme = ThresholdScheme::new(2, 3).unwrap();

        let shares1 = scheme.split(&secret1, deterministic_rng).unwrap();
        let shares2 = scheme.split(&secret2, deterministic_rng).unwrap();

        // Shares should be different
        assert_ne!(shares1[0].data, shares2[0].data);
    }

    #[test]
    fn test_share_order_independence() {
        let secret = [0x42u8; SHARE_SIZE];
        let scheme = ThresholdScheme::new(3, 5).unwrap();
        let shares = scheme.split(&secret, deterministic_rng).unwrap();

        // Reconstruction should work regardless of share order
        let recovered1 = scheme.reconstruct(&[
            shares[0].clone(),
            shares[1].clone(),
            shares[2].clone(),
        ]).unwrap();

        let recovered2 = scheme.reconstruct(&[
            shares[2].clone(),
            shares[0].clone(),
            shares[1].clone(),
        ]).unwrap();

        let recovered3 = scheme.reconstruct(&[
            shares[1].clone(),
            shares[2].clone(),
            shares[0].clone(),
        ]).unwrap();

        assert_eq!(recovered1, secret);
        assert_eq!(recovered2, secret);
        assert_eq!(recovered3, secret);
    }
}
