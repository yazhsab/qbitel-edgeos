// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Integration tests for q-boot
//!
//! Tests for image header validation, hash verification, boot decision logic,
//! and the incremental verifier state machine. Note: tests that require
//! reading from real flash addresses are not possible on the host platform.

use q_boot::verify::{
    BootDecision, EfuseFingerprintProvider, ImageHeader, ImageType, IncrementalVerifier,
    PufProvider, VerifyError, VerifyState,
    DILITHIUM3_PUBLIC_KEY_SIZE, DILITHIUM3_SIGNATURE_SIZE,
    IMAGE_FORMAT_VERSION, KERNEL_MAGIC, BOOTLOADER_MAGIC, APPLICATION_MAGIC,
    flags,
};

/// Helper: build a valid test header with correct SHA3-256 hash
fn build_test_header(image_body: &[u8], image_type: ImageType) -> ImageHeader {
    use q_crypto::hash::Sha3_256;
    use q_crypto::traits::Hash;

    let hash = Sha3_256::hash(image_body);
    let magic = match image_type {
        ImageType::Kernel => KERNEL_MAGIC,
        ImageType::Bootloader => BOOTLOADER_MAGIC,
        ImageType::Application => APPLICATION_MAGIC,
        _ => 0xDEADBEEF,
    };

    let mut header = unsafe { core::mem::zeroed::<ImageHeader>() };
    header.magic = magic;
    header.format_version = IMAGE_FORMAT_VERSION;
    header.image_type = image_type as u8;
    header.image_size = image_body.len() as u32;
    header.load_address = 0x0800_8000;
    header.entry_offset = 0;
    header.rollback_counter = 0;
    header.image_hash.copy_from_slice(hash.as_ref());
    header
}

mod header_validation_tests {
    use super::*;

    #[test]
    fn test_valid_kernel_header() {
        let header = build_test_header(&[0u8; 1024], ImageType::Kernel);
        assert!(header.validate_fields().is_ok());
    }

    #[test]
    fn test_valid_bootloader_header() {
        let header = build_test_header(&[0u8; 512], ImageType::Bootloader);
        assert!(header.validate_fields().is_ok());
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut header = build_test_header(&[0u8; 1024], ImageType::Kernel);
        header.magic = 0xDEADBEEF;
        assert_eq!(header.validate_fields(), Err(VerifyError::InvalidMagic));
    }

    #[test]
    fn test_wrong_magic_for_type_rejected() {
        let mut header = build_test_header(&[0u8; 1024], ImageType::Kernel);
        // Set bootloader magic but kernel type
        header.magic = BOOTLOADER_MAGIC;
        assert_eq!(header.validate_fields(), Err(VerifyError::InvalidMagic));
    }

    #[test]
    fn test_zero_image_size_rejected() {
        let mut header = build_test_header(&[0u8; 1024], ImageType::Kernel);
        header.image_size = 0;
        assert_eq!(header.validate_fields(), Err(VerifyError::InvalidImageSize));
    }

    #[test]
    fn test_oversized_image_rejected() {
        let mut header = build_test_header(&[0u8; 1024], ImageType::Kernel);
        header.image_size = 5 * 1024 * 1024; // 5MB > 4MB max
        assert_eq!(header.validate_fields(), Err(VerifyError::InvalidImageSize));
    }

    #[test]
    fn test_entry_past_image_end_rejected() {
        let mut header = build_test_header(&[0u8; 1024], ImageType::Kernel);
        header.entry_offset = 2048; // Past image_size of 1024
        assert_eq!(header.validate_fields(), Err(VerifyError::InvalidEntryPoint));
    }

    #[test]
    fn test_future_format_version_rejected() {
        let mut header = build_test_header(&[0u8; 1024], ImageType::Kernel);
        header.format_version = IMAGE_FORMAT_VERSION + 1;
        assert_eq!(header.validate_fields(), Err(VerifyError::UnsupportedVersion));
    }
}

mod version_parsing_tests {
    use super::*;

    #[test]
    fn test_version_components() {
        let mut header = build_test_header(&[0u8; 64], ImageType::Kernel);
        header.version = 0x01020304; // 1.2.3.4

        let (major, minor, patch, build) = header.parse_version();
        assert_eq!((major, minor, patch, build), (1, 2, 3, 4));
    }

    #[test]
    fn test_version_max_values() {
        let mut header = build_test_header(&[0u8; 64], ImageType::Kernel);
        header.version = 0xFFFFFFFF;

        let (major, minor, patch, build) = header.parse_version();
        assert_eq!((major, minor, patch, build), (255, 255, 255, 255));
    }

    #[test]
    fn test_version_zero() {
        let mut header = build_test_header(&[0u8; 64], ImageType::Kernel);
        header.version = 0;

        let (major, minor, patch, build) = header.parse_version();
        assert_eq!((major, minor, patch, build), (0, 0, 0, 0));
    }
}

mod hash_verification_tests {
    use super::*;
    use q_crypto::hash::Sha3_256;
    use q_crypto::traits::Hash;

    #[test]
    fn test_hash_matches_image_body() {
        let body = [0xABu8; 512];
        let header = build_test_header(&body, ImageType::Kernel);

        let computed = Sha3_256::hash(&body);
        assert_eq!(computed.as_ref(), &header.image_hash);
    }

    #[test]
    fn test_corrupted_body_hash_mismatch() {
        let body = [0xABu8; 512];
        let header = build_test_header(&body, ImageType::Kernel);

        let mut corrupted = body;
        corrupted[10] = 0x00;

        let computed = Sha3_256::hash(&corrupted);
        assert_ne!(computed.as_ref(), &header.image_hash);
    }

    #[test]
    fn test_verify_kernel_hash_correct() {
        let body = [0xCDu8; 256];
        let hash = Sha3_256::hash(&body);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(hash.as_ref());

        assert!(q_boot::verify::verify_kernel_hash(&body, &expected).unwrap());
    }

    #[test]
    fn test_verify_kernel_hash_wrong() {
        let body = [0xCDu8; 256];
        let wrong_hash = [0xFF; 32];
        assert!(!q_boot::verify::verify_kernel_hash(&body, &wrong_hash).unwrap());
    }
}

mod flags_tests {
    use super::*;

    #[test]
    fn test_flag_combinations() {
        let mut header = build_test_header(&[0u8; 64], ImageType::Kernel);
        header.flags = flags::SECURE_BOOT_REQUIRED | flags::HW_BOUND;

        assert!(header.has_flag(flags::SECURE_BOOT_REQUIRED));
        assert!(header.has_flag(flags::HW_BOUND));
        assert!(!header.has_flag(flags::ENCRYPTED));
        assert!(!header.has_flag(flags::DEBUGGABLE));
        assert!(!header.has_flag(flags::HYBRID_SIGNATURE));
    }

    #[test]
    fn test_no_flags() {
        let header = build_test_header(&[0u8; 64], ImageType::Kernel);
        assert!(!header.has_flag(flags::SECURE_BOOT_REQUIRED));
        assert!(!header.has_flag(flags::ENCRYPTED));
    }
}

mod error_conversion_tests {
    use super::*;
    use q_common::Error;

    #[test]
    fn test_verify_error_to_common_error() {
        assert_eq!(Error::from(VerifyError::HashMismatch), Error::UpdateCorrupted);
        assert_eq!(Error::from(VerifyError::SignatureFailed), Error::InvalidSignature);
        assert_eq!(Error::from(VerifyError::RollbackAttempt), Error::RollbackAttempted);
        assert_eq!(Error::from(VerifyError::HardwareBindingFailed), Error::HardwareFingerprintMismatch);
        assert_eq!(Error::from(VerifyError::InvalidMagic), Error::InvalidManifest);
    }
}

mod boot_decision_tests {
    use super::*;

    #[test]
    fn test_boot_decision_primary_success() {
        let decision = BootDecision::Boot {
            entry_point: 0x0800_8000,
            slot: 0,
        };
        assert!(matches!(decision, BootDecision::Boot { slot: 0, .. }));
    }

    #[test]
    fn test_boot_decision_fallback() {
        let decision = BootDecision::Fallback {
            entry_point: 0x0810_0000,
            slot: 1,
            primary_error: VerifyError::HashMismatch,
        };
        assert!(matches!(decision, BootDecision::Fallback { slot: 1, primary_error: VerifyError::HashMismatch, .. }));
    }

    #[test]
    fn test_boot_decision_halt_preserves_errors() {
        let decision = BootDecision::Halt {
            primary_error: VerifyError::HashMismatch,
            fallback_error: VerifyError::SignatureFailed,
        };
        match decision {
            BootDecision::Halt { primary_error, fallback_error } => {
                assert_eq!(primary_error, VerifyError::HashMismatch);
                assert_eq!(fallback_error, VerifyError::SignatureFailed);
            }
            _ => panic!("Expected Halt"),
        }
    }
}

mod efuse_fingerprint_tests {
    use super::*;

    #[test]
    fn test_efuse_provider_produces_nonzero_fingerprint() {
        let provider = EfuseFingerprintProvider::from_device();
        let fp = provider.get_fingerprint().unwrap();
        assert!(fp.iter().any(|&b| b != 0), "Fingerprint should not be all zeros");
    }

    #[test]
    fn test_efuse_provider_deterministic() {
        let provider = EfuseFingerprintProvider::from_device();
        let fp1 = provider.get_fingerprint().unwrap();
        let fp2 = provider.get_fingerprint().unwrap();
        assert_eq!(fp1, fp2, "Same provider should produce same fingerprint");
    }

    #[test]
    fn test_efuse_provider_different_ids_different_fingerprints() {
        let provider_a = EfuseFingerprintProvider::new([0x11u8; 16]);
        let provider_b = EfuseFingerprintProvider::new([0x22u8; 16]);

        let fp_a = provider_a.get_fingerprint().unwrap();
        let fp_b = provider_b.get_fingerprint().unwrap();

        assert_ne!(fp_a, fp_b, "Different device IDs should produce different fingerprints");
    }
}

mod incremental_verifier_tests {
    use super::*;

    #[test]
    fn test_initial_state_is_idle() {
        let verifier = IncrementalVerifier::new(0, 0);
        assert_eq!(verifier.state(), VerifyState::Idle);
    }

    #[test]
    fn test_first_step_transitions_to_reading_header() {
        let mut verifier = IncrementalVerifier::new(0, 0);
        let done = verifier.step();
        assert!(!done);
        assert_eq!(verifier.state(), VerifyState::ReadingHeader);
    }
}

mod header_size_tests {
    use super::*;

    #[test]
    fn test_header_size_constants() {
        assert_eq!(ImageHeader::HEADER_SIZE, 128);
        assert_eq!(ImageHeader::FULL_SIZE, 128 + DILITHIUM3_SIGNATURE_SIZE);
        assert_eq!(DILITHIUM3_PUBLIC_KEY_SIZE, 1952);
        assert_eq!(DILITHIUM3_SIGNATURE_SIZE, 3293);
    }
}
