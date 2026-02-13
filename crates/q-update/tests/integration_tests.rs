// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Integration tests for q-update
//!
//! Tests for secure firmware update: manifest parsing, version comparison,
//! A/B slot management, rollback protection, and air-gapped update packages.
//! These exercise the real crate API on the host platform.

mod version_tests {
    use q_update::version::MonotonicVersion;
    use q_common::version::Version;

    #[test]
    fn test_version_creation() {
        let v = Version::new(1, 2, 3, 4);
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 2);
        assert_eq!(v.patch(), 3);
        assert_eq!(v.build(), 4);
    }

    #[test]
    fn test_version_comparison() {
        let v1_0_0 = Version::new(1, 0, 0, 0);
        let v1_0_1 = Version::new(1, 0, 1, 0);
        let v1_1_0 = Version::new(1, 1, 0, 0);
        let v2_0_0 = Version::new(2, 0, 0, 0);

        assert!(v1_0_0 < v1_0_1);
        assert!(v1_0_1 < v1_1_0);
        assert!(v1_1_0 < v2_0_0);
    }

    #[test]
    fn test_version_equality() {
        let v1 = Version::new(1, 2, 3, 0);
        let v2 = Version::new(1, 2, 3, 0);
        let v3 = Version::new(1, 2, 4, 0);

        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
    }

    #[test]
    fn test_monotonic_version_creation() {
        let version = Version::new(1, 2, 3, 0);
        let mv = MonotonicVersion::new(version, 5);

        assert_eq!(mv.version(), &version);
        assert_eq!(mv.rollback_index(), 5);
    }

    #[test]
    fn test_monotonic_version_newer_by_rollback_index() {
        let v1 = MonotonicVersion::new(Version::new(1, 0, 0, 0), 5);
        let v2 = MonotonicVersion::new(Version::new(1, 0, 0, 0), 6);

        // Same version but higher rollback index → newer
        assert!(v2.is_newer_than(&v1));
        assert!(!v1.is_newer_than(&v2));
    }

    #[test]
    fn test_monotonic_version_newer_by_version() {
        let v1 = MonotonicVersion::new(Version::new(1, 0, 0, 0), 5);
        let v2 = MonotonicVersion::new(Version::new(2, 0, 0, 0), 5);

        // Same rollback index but higher version → newer
        assert!(v2.is_newer_than(&v1));
        assert!(!v1.is_newer_than(&v2));
    }

    #[test]
    fn test_monotonic_version_same_is_not_newer() {
        let v1 = MonotonicVersion::new(Version::new(1, 0, 0, 0), 5);
        let v2 = MonotonicVersion::new(Version::new(1, 0, 0, 0), 5);

        assert!(!v1.is_newer_than(&v2));
        assert!(!v2.is_newer_than(&v1));
    }

    #[test]
    fn test_rollback_index_takes_precedence() {
        // Higher version but lower rollback index should not be newer
        let v1 = MonotonicVersion::new(Version::new(1, 0, 0, 0), 10);
        let v2 = MonotonicVersion::new(Version::new(2, 0, 0, 0), 5);

        // v2 has higher version but lower rollback index
        // Rollback index takes precedence
        assert!(v1.is_newer_than(&v2));
        assert!(!v2.is_newer_than(&v1));
    }
}

mod slot_tests {
    use q_update::slots::{Slot, SlotState};

    #[test]
    fn test_slot_variants() {
        assert_ne!(Slot::A, Slot::B);
        assert_eq!(Slot::A as u8, 0);
        assert_eq!(Slot::B as u8, 1);
    }

    #[test]
    fn test_slot_other() {
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
    }

    #[test]
    fn test_slot_other_is_involution() {
        assert_eq!(Slot::A.other().other(), Slot::A);
        assert_eq!(Slot::B.other().other(), Slot::B);
    }

    #[test]
    fn test_slot_addresses() {
        let addr_a = Slot::A.address();
        let addr_b = Slot::B.address();

        // Addresses should be non-zero and different
        assert!(addr_a > 0);
        assert!(addr_b > 0);
        assert_ne!(addr_a, addr_b);
    }

    #[test]
    fn test_slot_sizes() {
        let size_a = Slot::A.size();
        let size_b = Slot::B.size();

        // Both slots should have the same size
        assert_eq!(size_a, size_b);
        assert!(size_a > 0);
    }

    #[test]
    fn test_slot_from_u8() {
        assert_eq!(Slot::from(0u8), Slot::A);
        assert_eq!(Slot::from(1u8), Slot::B);
    }

    #[test]
    fn test_slot_state_variants_all_distinct() {
        let states = [
            SlotState::Empty,
            SlotState::Valid,
            SlotState::Pending,
            SlotState::Active,
            SlotState::Failed,
            SlotState::Invalid,
        ];

        for (i, s1) in states.iter().enumerate() {
            for (j, s2) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(s1, s2);
                } else {
                    assert_ne!(s1, s2);
                }
            }
        }
    }

    #[test]
    fn test_slot_state_bootable() {
        assert!(SlotState::Valid.is_bootable());
        assert!(SlotState::Pending.is_bootable());
        assert!(SlotState::Active.is_bootable());

        assert!(!SlotState::Empty.is_bootable());
        assert!(!SlotState::Failed.is_bootable());
        assert!(!SlotState::Invalid.is_bootable());
    }

    #[test]
    fn test_slot_state_from_u8() {
        assert_eq!(SlotState::from(0u8), SlotState::Empty);
        assert_eq!(SlotState::from(1u8), SlotState::Valid);
        assert_eq!(SlotState::from(2u8), SlotState::Pending);
        assert_eq!(SlotState::from(3u8), SlotState::Active);
        assert_eq!(SlotState::from(4u8), SlotState::Failed);
        assert_eq!(SlotState::from(255u8), SlotState::Invalid);
    }
}

mod slot_info_tests {
    use q_update::slots::{SlotInfo, SlotState};

    #[test]
    fn test_slot_info_empty() {
        let info = SlotInfo::empty();
        assert_eq!(info.get_state(), SlotState::Empty);
        assert_eq!(info.boot_attempts, 0);
        assert_eq!(info.version, 0);
    }

    #[test]
    fn test_slot_info_set_state() {
        let mut info = SlotInfo::empty();
        info.set_state(SlotState::Active);
        assert_eq!(info.get_state(), SlotState::Active);
    }

    #[test]
    fn test_slot_info_version_parsing() {
        let mut info = SlotInfo::empty();
        info.version = 0x01020304; // 1.2.3.4

        let (major, minor, patch, build) = info.parse_version();
        assert_eq!((major, minor, patch, build), (1, 2, 3, 4));
    }

    #[test]
    fn test_slot_info_version_zero() {
        let info = SlotInfo::empty();
        let (major, minor, patch, build) = info.parse_version();
        assert_eq!((major, minor, patch, build), (0, 0, 0, 0));
    }

    #[test]
    fn test_slot_info_size_constant() {
        assert_eq!(SlotInfo::SIZE, 48);
    }
}

mod slot_metadata_tests {
    use q_update::slots::{SlotMetadata, Slot, SlotState};

    #[test]
    fn test_slot_metadata_new() {
        let metadata = SlotMetadata::new();
        assert_eq!(metadata.get_selected_slot(), Slot::A);
        assert_eq!(metadata.get_slot_info(Slot::A).get_state(), SlotState::Empty);
        assert_eq!(metadata.get_slot_info(Slot::B).get_state(), SlotState::Empty);
    }

    #[test]
    fn test_slot_metadata_default() {
        let metadata = SlotMetadata::default();
        assert_eq!(metadata.get_selected_slot(), Slot::A);
    }

    #[test]
    fn test_slot_metadata_size_constant() {
        assert_eq!(SlotMetadata::SIZE, 112);
    }

    #[test]
    fn test_slot_metadata_get_slot_info_mut() {
        let mut metadata = SlotMetadata::new();

        metadata.get_slot_info_mut(Slot::A).set_state(SlotState::Active);
        metadata.get_slot_info_mut(Slot::A).version = 0x01000000;

        assert_eq!(metadata.get_slot_info(Slot::A).get_state(), SlotState::Active);
        assert_eq!(metadata.get_slot_info(Slot::A).version, 0x01000000);

        // Slot B should be unaffected
        assert_eq!(metadata.get_slot_info(Slot::B).get_state(), SlotState::Empty);
    }

    #[test]
    fn test_slot_metadata_crc_update() {
        let mut metadata = SlotMetadata::new();
        let initial_crc = metadata.crc32;

        metadata.get_slot_info_mut(Slot::A).set_state(SlotState::Active);
        metadata.update_crc();

        // CRC should change after modification
        assert_ne!(metadata.crc32, initial_crc);
    }

    #[test]
    fn test_slot_metadata_validate_after_crc_update() {
        let mut metadata = SlotMetadata::new();
        metadata.update_crc();

        // Should validate successfully with correct magic and CRC
        assert!(metadata.validate().is_ok());
    }
}

mod manifest_tests {
    use q_update::manifest::{UpdateManifest, MANIFEST_MAGIC};

    #[test]
    fn test_manifest_magic_constant() {
        // "QUPD" in ASCII
        let bytes = MANIFEST_MAGIC.to_be_bytes();
        assert_eq!(bytes[0], b'Q');
        assert_eq!(bytes[1], b'U');
        assert_eq!(bytes[2], b'P');
        assert_eq!(bytes[3], b'D');
    }

    #[test]
    fn test_manifest_header_size() {
        assert_eq!(UpdateManifest::HEADER_SIZE, 128);
    }

    #[test]
    fn test_manifest_total_size_includes_signature() {
        // Total size = header + Dilithium3 signature (3293 bytes)
        assert_eq!(
            UpdateManifest::TOTAL_SIZE,
            128 + 3293
        );
    }
}

mod rollback_tests {
    use q_update::rollback::check_rollback;

    #[test]
    fn test_rollback_upgrade_allowed() {
        let result = check_rollback(5, 6, 0);
        assert!(result.is_ok());
        assert!(result.unwrap(), "Higher rollback index should be allowed");
    }

    #[test]
    fn test_rollback_same_index_rejected() {
        let result = check_rollback(5, 5, 0);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Same rollback index should be rejected (no upgrade)"
        );
    }

    #[test]
    fn test_rollback_downgrade_rejected() {
        let result = check_rollback(5, 4, 0);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Lower rollback index should be rejected");
    }
}

mod slot_error_tests {
    use q_update::slots::SlotError;
    use q_common::Error;

    #[test]
    fn test_slot_error_variants_exist() {
        let errors = [
            SlotError::InvalidMagic,
            SlotError::CrcMismatch,
            SlotError::InvalidSlot,
            SlotError::NoBootableSlot,
            SlotError::FlashError,
            SlotError::UpdateInProgress,
            SlotError::RollbackAttempt,
            SlotError::VerificationFailed,
            SlotError::InternalError,
        ];

        // All should be convertible to common Error
        for error in errors {
            let _common: Error = error.into();
        }
    }
}

mod airgap_tests {
    use q_update::airgap::{
        AirgapPackageHeader, CustodyRole, CustodySignature,
        AirgapFlags, AIRGAP_MAGIC, PACKAGE_FORMAT_VERSION,
    };

    #[test]
    fn test_airgap_magic_constant() {
        // "QAIR" in ASCII
        let bytes = AIRGAP_MAGIC.to_be_bytes();
        assert_eq!(bytes[0], b'Q');
        assert_eq!(bytes[1], b'A');
        assert_eq!(bytes[2], b'I');
        assert_eq!(bytes[3], b'R');
    }

    #[test]
    fn test_package_format_version() {
        assert_eq!(PACKAGE_FORMAT_VERSION, 1);
    }

    #[test]
    fn test_custody_roles_all_distinct() {
        let roles = [
            CustodyRole::BuildEngineer,
            CustodyRole::SecurityReviewer,
            CustodyRole::ReleaseManager,
            CustodyRole::QualityAssurance,
            CustodyRole::DeviceAdmin,
            CustodyRole::HardwareSecurityModule,
            CustodyRole::Custom,
        ];

        for (i, r1) in roles.iter().enumerate() {
            for (j, r2) in roles.iter().enumerate() {
                if i == j {
                    assert_eq!(r1, r2);
                } else {
                    assert_ne!(r1, r2);
                }
            }
        }
    }

    #[test]
    fn test_airgap_header_creation() {
        let header = AirgapPackageHeader::new(
            0x10,           // railway device class
            1704067200,     // created_at
            1704153600,     // expires_at (24h later)
            [0x42; 32],     // target device
            [0xAB; 32],     // package hash
        );

        assert_eq!(header.magic, AIRGAP_MAGIC);
        assert_eq!(header.format_version, PACKAGE_FORMAT_VERSION);
        assert_eq!(header.device_class, 0x10);
        assert_eq!(header.created_at, 1704067200);
        assert_eq!(header.expires_at, 1704153600);
    }

    #[test]
    fn test_airgap_header_size() {
        assert_eq!(AirgapPackageHeader::SIZE, 104);
    }

    #[test]
    fn test_airgap_header_serialization_roundtrip() {
        let header = AirgapPackageHeader::new(
            0x10,
            1704067200,
            1704153600,
            [0x42; 32],
            [0xAB; 32],
        );

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), AirgapPackageHeader::SIZE);

        let parsed = AirgapPackageHeader::from_bytes(&bytes);
        assert!(parsed.is_some());

        let parsed = parsed.unwrap();
        assert_eq!(parsed.magic, AIRGAP_MAGIC);
        assert_eq!(parsed.device_class, 0x10);
        assert_eq!(parsed.created_at, 1704067200);
    }

    #[test]
    fn test_airgap_header_from_bytes_too_short() {
        let short_data = [0u8; 16];
        assert!(AirgapPackageHeader::from_bytes(&short_data).is_none());
    }

    #[test]
    fn test_airgap_flags() {
        let flags = AirgapFlags::DEVICE_BOUND | AirgapFlags::HAS_EXPIRY;
        assert!(flags.contains(AirgapFlags::DEVICE_BOUND));
        assert!(flags.contains(AirgapFlags::HAS_EXPIRY));
        assert!(!flags.contains(AirgapFlags::CRITICAL));
        assert!(!flags.contains(AirgapFlags::ENCRYPTED));
    }

    #[test]
    fn test_custody_signature_creation() {
        let sig = CustodySignature::new(
            [0x42; 32],
            CustodyRole::SecurityReviewer,
            1704067200,
            [0xAB; 3293],
        );

        assert_eq!(sig.signer_id, [0x42; 32]);
        assert_eq!(sig.role, CustodyRole::SecurityReviewer);
        assert_eq!(sig.timestamp, 1704067200);
    }
}
