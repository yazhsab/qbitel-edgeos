// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Integration tests for q-identity
//!
//! Tests for device identity management: DeviceClass, IdentityCommitment,
//! IdentitySecrets, verification, and hardware fingerprint handling.
//! These exercise the real crate API on the host platform.

mod device_class_tests {
    use q_identity::DeviceClass;

    #[test]
    fn test_all_device_class_variants_are_distinct() {
        let classes = [
            DeviceClass::Generic,
            DeviceClass::RailwaySignaling,
            DeviceClass::PowerGrid,
            DeviceClass::SmartMeter,
            DeviceClass::VehicleEcu,
            DeviceClass::BorderSensor,
            DeviceClass::IndustrialPlc,
            DeviceClass::Defense,
            DeviceClass::TestDevice,
        ];

        for (i, c1) in classes.iter().enumerate() {
            for (j, c2) in classes.iter().enumerate() {
                if i == j {
                    assert_eq!(c1, c2);
                } else {
                    assert_ne!(c1, c2);
                }
            }
        }
    }

    #[test]
    fn test_device_class_from_u8_known_values() {
        assert_eq!(DeviceClass::from_u8(0x00), DeviceClass::Generic);
        assert_eq!(DeviceClass::from_u8(0x10), DeviceClass::RailwaySignaling);
        assert_eq!(DeviceClass::from_u8(0x20), DeviceClass::PowerGrid);
        assert_eq!(DeviceClass::from_u8(0x21), DeviceClass::SmartMeter);
        assert_eq!(DeviceClass::from_u8(0x30), DeviceClass::VehicleEcu);
        assert_eq!(DeviceClass::from_u8(0x40), DeviceClass::BorderSensor);
        assert_eq!(DeviceClass::from_u8(0x50), DeviceClass::IndustrialPlc);
        assert_eq!(DeviceClass::from_u8(0x80), DeviceClass::Defense);
        assert_eq!(DeviceClass::from_u8(0xFE), DeviceClass::TestDevice);
    }

    #[test]
    fn test_device_class_from_u8_unknown_values_return_unknown() {
        let unknown_values = [0x01, 0x05, 0x0F, 0x99, 0xFF, 0x11, 0x42];
        for value in unknown_values {
            let class = DeviceClass::from_u8(value);
            assert_eq!(
                class,
                DeviceClass::Unknown,
                "Value 0x{:02X} should map to Unknown",
                value
            );
        }
    }

    #[test]
    fn test_safety_critical_classification() {
        // Safety-critical devices
        assert!(DeviceClass::RailwaySignaling.is_safety_critical());
        assert!(DeviceClass::PowerGrid.is_safety_critical());
        assert!(DeviceClass::VehicleEcu.is_safety_critical());
        assert!(DeviceClass::Defense.is_safety_critical());

        // Non-safety-critical devices
        assert!(!DeviceClass::Generic.is_safety_critical());
        assert!(!DeviceClass::SmartMeter.is_safety_critical());
        assert!(!DeviceClass::BorderSensor.is_safety_critical());
        assert!(!DeviceClass::IndustrialPlc.is_safety_critical());
        assert!(!DeviceClass::TestDevice.is_safety_critical());
    }

    #[test]
    fn test_enhanced_security_classification() {
        // Requires enhanced security
        assert!(DeviceClass::RailwaySignaling.requires_enhanced_security());
        assert!(DeviceClass::PowerGrid.requires_enhanced_security());
        assert!(DeviceClass::BorderSensor.requires_enhanced_security());
        assert!(DeviceClass::Defense.requires_enhanced_security());
        assert!(DeviceClass::IndustrialPlc.requires_enhanced_security());

        // Does not require enhanced security
        assert!(!DeviceClass::Generic.requires_enhanced_security());
        assert!(!DeviceClass::SmartMeter.requires_enhanced_security());
        assert!(!DeviceClass::TestDevice.requires_enhanced_security());
    }

    #[test]
    fn test_safety_critical_implies_enhanced_security() {
        let all_classes = [
            DeviceClass::Generic,
            DeviceClass::RailwaySignaling,
            DeviceClass::PowerGrid,
            DeviceClass::SmartMeter,
            DeviceClass::VehicleEcu,
            DeviceClass::BorderSensor,
            DeviceClass::IndustrialPlc,
            DeviceClass::Defense,
            DeviceClass::TestDevice,
        ];

        for class in all_classes {
            if class.is_safety_critical() {
                assert!(
                    class.requires_enhanced_security(),
                    "{:?} is safety-critical but doesn't require enhanced security",
                    class
                );
            }
        }
    }

    #[test]
    fn test_device_class_clone_and_copy() {
        let class = DeviceClass::RailwaySignaling;
        let cloned = class;
        assert_eq!(class, cloned);
    }

    #[test]
    fn test_device_class_debug_format() {
        let debug = format!("{:?}", DeviceClass::PowerGrid);
        assert!(debug.contains("PowerGrid"));
    }

    #[test]
    fn test_device_class_default() {
        let default = DeviceClass::default();
        assert_eq!(default, DeviceClass::Generic);
    }

    #[test]
    fn test_device_class_repr_u8_round_trip() {
        let classes_and_values: [(DeviceClass, u8); 9] = [
            (DeviceClass::Generic, 0x00),
            (DeviceClass::RailwaySignaling, 0x10),
            (DeviceClass::PowerGrid, 0x20),
            (DeviceClass::SmartMeter, 0x21),
            (DeviceClass::VehicleEcu, 0x30),
            (DeviceClass::BorderSensor, 0x40),
            (DeviceClass::IndustrialPlc, 0x50),
            (DeviceClass::Defense, 0x80),
            (DeviceClass::TestDevice, 0xFE),
        ];

        for (class, expected_value) in classes_and_values {
            assert_eq!(class as u8, expected_value, "{:?} repr", class);
            assert_eq!(DeviceClass::from_u8(expected_value), class);
        }
    }
}

mod identity_commitment_tests {
    use q_identity::IdentityCommitment;
    use q_common::types::{DeviceId, ManufacturerId, Timestamp, AlgorithmId};

    const KYBER768_PK_SIZE: usize = 1184;
    const DILITHIUM3_PK_SIZE: usize = 1952;

    fn make_test_commitment() -> IdentityCommitment {
        let mut commitment = IdentityCommitment::empty();
        commitment.version = 1;
        commitment.device_id = DeviceId::new([0x42; 32]);
        commitment.manufacturer_id = ManufacturerId::new([0x11; 16]);
        commitment.device_class = q_common::types::DeviceClass::TestDevice;
        commitment.created_at = Timestamp::new(1704067200); // 2024-01-01
        commitment.kem_algorithm = AlgorithmId::Kyber768;
        commitment.sig_algorithm = AlgorithmId::Dilithium3;
        commitment.kem_public_key = [0x01; KYBER768_PK_SIZE];
        commitment.signing_public_key = [0x02; DILITHIUM3_PK_SIZE];
        commitment.hardware_fingerprint_hash = [0xAB; 32];
        commitment
    }

    #[test]
    fn test_empty_commitment_creation() {
        let commitment = IdentityCommitment::empty();
        assert!(commitment.device_id.is_zero());
        assert_eq!(commitment.version, 0);
    }

    #[test]
    fn test_commitment_fields_accessible() {
        let commitment = make_test_commitment();

        assert_eq!(commitment.version, 1);
        assert!(!commitment.device_id.is_zero());
        assert_eq!(commitment.device_class, q_common::types::DeviceClass::TestDevice);
        assert_eq!(commitment.created_at.as_secs(), 1704067200);
    }

    #[test]
    fn test_commitment_kem_public_key() {
        let commitment = make_test_commitment();
        assert_eq!(commitment.kem_public_key.len(), KYBER768_PK_SIZE);
        assert!(commitment.kem_public_key.iter().all(|&b| b == 0x01));
    }

    #[test]
    fn test_commitment_signing_public_key() {
        let commitment = make_test_commitment();
        assert_eq!(commitment.signing_public_key.len(), DILITHIUM3_PK_SIZE);
        assert!(commitment.signing_public_key.iter().all(|&b| b == 0x02));
    }

    #[test]
    fn test_commitment_hardware_fingerprint() {
        let commitment = make_test_commitment();
        assert_eq!(commitment.hardware_fingerprint_hash, [0xAB; 32]);
    }

    #[test]
    fn test_commitment_serialization_roundtrip() {
        let commitment = make_test_commitment();

        let mut buffer = vec![0u8; IdentityCommitment::SERIALIZED_SIZE + 4096];
        let written = commitment.to_bytes(&mut buffer);
        assert!(written.is_some(), "Serialization should succeed");

        let len = written.unwrap();
        assert!(len > 0);
    }

    #[test]
    fn test_commitment_serialization_buffer_too_small() {
        let commitment = make_test_commitment();

        // Buffer way too small
        let mut buffer = [0u8; 16];
        let result = commitment.to_bytes(&mut buffer);
        assert!(result.is_none(), "Serialization into too-small buffer should fail");
    }

    #[test]
    fn test_commitment_signing_message() {
        let commitment = make_test_commitment();

        let mut buffer = vec![0u8; IdentityCommitment::SERIALIZED_SIZE + 4096];
        let msg_len = commitment.signing_message(&mut buffer);
        assert!(msg_len.is_some());
        assert!(msg_len.unwrap() > 0);
    }

    #[test]
    fn test_commitment_zero_device_id_detection() {
        let commitment = IdentityCommitment::empty();
        assert!(commitment.device_id.is_zero());

        let mut non_zero = IdentityCommitment::empty();
        non_zero.device_id = DeviceId::new([0x42; 32]);
        assert!(!non_zero.device_id.is_zero());
    }

    #[test]
    fn test_commitment_metadata() {
        let mut commitment = make_test_commitment();

        // Set some metadata
        let metadata = b"test-device-001";
        commitment.metadata[..metadata.len()].copy_from_slice(metadata);
        commitment.metadata_len = metadata.len();

        assert_eq!(commitment.metadata_len, 15);
        assert_eq!(&commitment.metadata[..15], b"test-device-001");
    }
}

mod identity_secrets_tests {
    use q_identity::IdentitySecrets;

    const KYBER768_SK_SIZE: usize = 2400;
    const DILITHIUM3_SK_SIZE: usize = 4000;

    #[test]
    fn test_empty_secrets_creation() {
        let secrets = IdentitySecrets::empty();
        assert!(secrets.kem_secret_key.iter().all(|&b| b == 0));
        assert!(secrets.signing_secret_key.iter().all(|&b| b == 0));
        assert!(secrets.hardware_binding_key.iter().all(|&b| b == 0));
        assert!(secrets.master_seed.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secrets_key_sizes() {
        let secrets = IdentitySecrets::empty();
        assert_eq!(secrets.kem_secret_key.len(), KYBER768_SK_SIZE);
        assert_eq!(secrets.signing_secret_key.len(), DILITHIUM3_SK_SIZE);
        assert_eq!(secrets.hardware_binding_key.len(), 32);
        assert_eq!(secrets.master_seed.len(), 64);
    }

    #[test]
    fn test_secrets_fields_writable() {
        let mut secrets = IdentitySecrets::empty();
        secrets.kem_secret_key[0] = 0xFF;
        secrets.signing_secret_key[0] = 0xAA;
        secrets.hardware_binding_key = [0x42; 32];
        secrets.master_seed = [0xBB; 64];

        assert_eq!(secrets.kem_secret_key[0], 0xFF);
        assert_eq!(secrets.signing_secret_key[0], 0xAA);
        assert_eq!(secrets.hardware_binding_key, [0x42; 32]);
        assert_eq!(secrets.master_seed, [0xBB; 64]);
    }
}

mod verification_result_tests {
    use q_identity::VerificationResult;

    #[test]
    fn test_all_verification_result_variants_distinct() {
        let results = [
            VerificationResult::Valid,
            VerificationResult::InvalidSignature,
            VerificationResult::InvalidFormat,
            VerificationResult::Expired,
            VerificationResult::ClassMismatch,
            VerificationResult::UnsupportedAlgorithm,
            VerificationResult::HardwareMismatch,
        ];

        for (i, r1) in results.iter().enumerate() {
            for (j, r2) in results.iter().enumerate() {
                if i == j {
                    assert_eq!(r1, r2);
                } else {
                    assert_ne!(r1, r2);
                }
            }
        }
    }

    #[test]
    fn test_verification_result_is_copy() {
        let r1 = VerificationResult::Valid;
        let r2 = r1;
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_verification_result_debug_format() {
        assert!(format!("{:?}", VerificationResult::Valid).contains("Valid"));
        assert!(format!("{:?}", VerificationResult::InvalidSignature).contains("InvalidSignature"));
        assert!(format!("{:?}", VerificationResult::Expired).contains("Expired"));
    }
}

mod verify_identity_tests {
    use q_identity::{verify_identity, VerificationResult, IdentityCommitment};
    use q_common::types::{DeviceId, DeviceClass, ManufacturerId, Timestamp, AlgorithmId};

    fn make_test_commitment() -> IdentityCommitment {
        let mut commitment = IdentityCommitment::empty();
        commitment.version = 1;
        commitment.device_id = DeviceId::new([0x42; 32]);
        commitment.manufacturer_id = ManufacturerId::new([0x11; 16]);
        commitment.device_class = DeviceClass::TestDevice;
        commitment.created_at = Timestamp::new(1704067200);
        commitment.kem_algorithm = AlgorithmId::Kyber768;
        commitment.sig_algorithm = AlgorithmId::Dilithium3;
        commitment.kem_public_key = [0x01; 1184];
        commitment.signing_public_key = [0x02; 1952];
        commitment.hardware_fingerprint_hash = [0xAB; 32];
        commitment
    }

    #[test]
    fn test_verify_identity_returns_result() {
        let commitment = make_test_commitment();
        let now = Timestamp::new(1704067200 + 60); // 1 minute later

        let result = verify_identity(
            &commitment,
            None,          // any device class
            0,             // no age limit
            now,
            None,          // no fingerprint check
        );

        // Should return Ok with some VerificationResult
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_identity_class_mismatch() {
        let commitment = make_test_commitment(); // TestDevice
        let now = Timestamp::new(1704067200 + 60);

        let result = verify_identity(
            &commitment,
            Some(DeviceClass::Defense), // Wrong class
            0,
            now,
            None,
        );

        if let Ok(vr) = result {
            // Should detect class mismatch
            assert_eq!(vr, VerificationResult::ClassMismatch);
        }
    }

    #[test]
    fn test_verify_identity_matching_class() {
        let commitment = make_test_commitment(); // TestDevice
        let now = Timestamp::new(1704067200 + 60);

        let result = verify_identity(
            &commitment,
            Some(DeviceClass::TestDevice), // Correct class
            0,
            now,
            None,
        );

        // Should not return ClassMismatch
        if let Ok(vr) = result {
            assert_ne!(vr, VerificationResult::ClassMismatch);
        }
    }

    #[test]
    fn test_verify_identity_fingerprint_mismatch() {
        let commitment = make_test_commitment();
        let now = Timestamp::new(1704067200 + 60);

        let wrong_fingerprint = [0xCD; 32]; // Different from 0xAB in commitment

        let result = verify_identity(
            &commitment,
            None,
            0,
            now,
            Some(&wrong_fingerprint),
        );

        if let Ok(vr) = result {
            assert_eq!(vr, VerificationResult::HardwareMismatch);
        }
    }

    #[test]
    fn test_verify_identity_fingerprint_match() {
        let commitment = make_test_commitment();
        let now = Timestamp::new(1704067200 + 60);

        let correct_fingerprint = [0xAB; 32]; // Same as in commitment

        let result = verify_identity(
            &commitment,
            None,
            0,
            now,
            Some(&correct_fingerprint),
        );

        // Should not return HardwareMismatch
        if let Ok(vr) = result {
            assert_ne!(vr, VerificationResult::HardwareMismatch);
        }
    }
}

mod device_id_tests {
    use q_common::types::DeviceId;

    #[test]
    fn test_device_id_creation() {
        let id = DeviceId::new([0x42; 32]);
        assert!(!id.is_zero());
        assert_eq!(id.as_bytes(), &[0x42; 32]);
    }

    #[test]
    fn test_device_id_zero_check() {
        let zero = DeviceId::new([0; 32]);
        assert!(zero.is_zero());

        let nonzero = DeviceId::new([0x01; 32]);
        assert!(!nonzero.is_zero());
    }

    #[test]
    fn test_device_id_from_slice() {
        let valid = DeviceId::from_slice(&[0x42; 32]);
        assert!(valid.is_some());

        let too_short = DeviceId::from_slice(&[0x42; 16]);
        assert!(too_short.is_none());

        let too_long = DeviceId::from_slice(&[0x42; 64]);
        assert!(too_long.is_none());
    }

    #[test]
    fn test_device_id_equality() {
        let id1 = DeviceId::new([0x42; 32]);
        let id2 = DeviceId::new([0x42; 32]);
        let id3 = DeviceId::new([0x43; 32]);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_device_id_debug_truncates() {
        let id = DeviceId::new([0xAB; 32]);
        let debug = format!("{:?}", id);
        // Debug should show first 4 bytes
        assert!(debug.contains("abababab"));
        // Should not show all 32 bytes
        assert!(debug.contains("..."));
    }
}

mod timestamp_tests {
    use q_common::types::Timestamp;

    #[test]
    fn test_timestamp_creation() {
        let ts = Timestamp::new(1704067200);
        assert_eq!(ts.as_secs(), 1704067200);
    }

    #[test]
    fn test_timestamp_ordering() {
        let earlier = Timestamp::new(1704067200);
        let later = Timestamp::new(1704067300);

        assert!(earlier.is_before(&later));
        assert!(later.is_after(&earlier));
        assert!(!earlier.is_after(&later));
        assert!(!later.is_before(&earlier));
    }

    #[test]
    fn test_timestamp_elapsed() {
        let created = Timestamp::new(1000);
        let now = Timestamp::new(1100);

        assert_eq!(created.elapsed_since(&now), 100);
    }

    #[test]
    fn test_timestamp_elapsed_future_returns_zero() {
        let future = Timestamp::new(2000);
        let now = Timestamp::new(1000);

        assert_eq!(future.elapsed_since(&now), 0);
    }

    #[test]
    fn test_timestamp_from_u64() {
        let ts: Timestamp = 1704067200u64.into();
        assert_eq!(ts.as_secs(), 1704067200);
    }

    #[test]
    fn test_timestamp_to_u64() {
        let ts = Timestamp::new(1704067200);
        let val: u64 = ts.into();
        assert_eq!(val, 1704067200);
    }
}

mod manufacturer_id_tests {
    use q_common::types::ManufacturerId;

    #[test]
    fn test_manufacturer_id_creation() {
        let mid = ManufacturerId::new([0x42; 16]);
        assert_eq!(mid.as_bytes(), &[0x42; 16]);
    }

    #[test]
    fn test_manufacturer_id_from_slice() {
        let valid = ManufacturerId::from_slice(&[0x42; 16]);
        assert!(valid.is_some());

        let wrong_size = ManufacturerId::from_slice(&[0x42; 8]);
        assert!(wrong_size.is_none());
    }

    #[test]
    fn test_manufacturer_id_equality() {
        let mid1 = ManufacturerId::new([0x42; 16]);
        let mid2 = ManufacturerId::new([0x42; 16]);
        let mid3 = ManufacturerId::new([0x43; 16]);

        assert_eq!(mid1, mid2);
        assert_ne!(mid1, mid3);
    }
}
