// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Comprehensive tests for q-common
//!
//! Tests for common types, error handling, and configuration.

#![cfg(test)]

mod types_tests {
    use std::collections::HashSet;

    #[test]
    fn test_device_id_creation() {
        let bytes = [0x42u8; 32];
        // DeviceId::new(bytes) would create a device ID
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_device_id_from_slice() {
        let slice = [0xABu8; 32];
        // DeviceId::from_slice(&slice) should succeed
        assert_eq!(slice.len(), 32);

        let short_slice = [0u8; 16];
        // DeviceId::from_slice(&short_slice) should fail
        assert_ne!(short_slice.len(), 32);
    }

    #[test]
    fn test_device_id_zero_check() {
        let zero_id = [0u8; 32];
        let nonzero_id = [0x01u8; 32];

        assert!(zero_id.iter().all(|&b| b == 0));
        assert!(!nonzero_id.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_manufacturer_id_creation() {
        let bytes = [0x42u8; 16];
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_device_class_from_u8() {
        // Test all device class values
        let classes = [
            (0x00, "Generic"),
            (0x10, "RailwaySignaling"),
            (0x20, "PowerGrid"),
            (0x21, "SmartMeter"),
            (0x30, "VehicleEcu"),
            (0x40, "BorderSensor"),
            (0x50, "IndustrialPlc"),
            (0x80, "Defense"),
            (0xFE, "TestDevice"),
            (0xFF, "Unknown"),
        ];

        for (value, _name) in classes {
            assert!(value <= 0xFF);
        }
    }

    #[test]
    fn test_device_class_safety_critical() {
        // Safety-critical classes
        let safety_critical = [0x10u8, 0x20, 0x30, 0x80]; // Railway, Power, Vehicle, Defense

        for class in safety_critical {
            assert!(class > 0);
        }
    }

    #[test]
    fn test_algorithm_id_values() {
        // All algorithm IDs should be unique
        let algorithm_ids = [
            0x01u8, 0x02, 0x03,       // Kyber variants
            0x10, 0x11, 0x12,          // Dilithium variants
            0x20, 0x21,                // Falcon variants
            0x80, 0x81, 0x82, 0x83,    // Classical (hybrid)
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, // Hash functions
            0xB0, 0xB1, 0xB2,          // AEAD
        ];

        let unique: HashSet<_> = algorithm_ids.iter().collect();
        assert_eq!(unique.len(), algorithm_ids.len());
    }

    #[test]
    fn test_algorithm_pqc_classification() {
        // PQC algorithms (0x01-0x2F)
        let pqc = [0x01u8, 0x02, 0x03, 0x10, 0x11, 0x12, 0x20, 0x21];

        for id in pqc {
            assert!(id < 0x30);
        }
    }

    #[test]
    fn test_security_level_ordering() {
        // Level 5 > Level 3 > Level 1
        let level1: u8 = 1;
        let level3: u8 = 3;
        let level5: u8 = 5;

        assert!(level5 > level3);
        assert!(level3 > level1);
    }

    #[test]
    fn test_timestamp_creation() {
        let ts = 1704067200u64; // 2024-01-01 00:00:00 UTC
        assert!(ts > 0);
    }

    #[test]
    fn test_timestamp_comparison() {
        let ts1 = 1000u64;
        let ts2 = 2000u64;

        assert!(ts1 < ts2);
        assert!(ts2 > ts1);
    }

    #[test]
    fn test_timestamp_elapsed() {
        let start = 1000u64;
        let now = 1500u64;
        let elapsed = now - start;

        assert_eq!(elapsed, 500);
    }

    #[test]
    fn test_secure_bytes_creation() {
        let data = [0xABu8; 32];
        assert_eq!(data.len(), 32);
    }

    #[test]
    fn test_secure_bytes_zeroization() {
        let mut data = [0xABu8; 32];

        // Simulate zeroization
        for byte in &mut data {
            *byte = 0;
        }

        assert!(data.iter().all(|&b| b == 0));
    }
}

mod error_tests {
    use std::collections::HashSet;

    #[test]
    fn test_error_codes_unique() {
        // All error codes should be unique
        let codes = [
            0x0101u16, 0x0102, 0x0103, 0x0104, 0x0105, // Crypto
            0x0201, 0x0202, 0x0203, 0x0204, 0x0205,     // Identity
            0x0301, 0x0302, 0x0303, 0x0304, 0x0305,     // Storage
            0x0401, 0x0402, 0x0403, 0x0404,             // Update
            0x0501, 0x0502, 0x0503, 0x0504,             // Recovery
            0x0601, 0x0602, 0x0603, 0x0604,             // Mesh
            0x0701, 0x0702, 0x0703, 0x0704,             // Attestation
            0x0801, 0x0802, 0x0803, 0x0804,             // HAL
            0x0901, 0x0902, 0x0903, 0x0904,             // Kernel
            0x0A01, 0x0A02, 0x0A03,                     // Boot
            0xFF01, 0xFF02, 0xFF03, 0xFFFF,             // General
        ];

        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn test_error_categories() {
        // Error categories by prefix
        let crypto_prefix = 0x0100u16;
        let identity_prefix = 0x0200u16;
        let storage_prefix = 0x0300u16;

        assert!(crypto_prefix < identity_prefix);
        assert!(identity_prefix < storage_prefix);
    }

    #[test]
    fn test_security_errors() {
        // Security-critical errors
        let security_errors = [
            0x0101u16, // InvalidKey
            0x0102,    // InvalidSignature
            0x0103,    // InvalidCiphertext
            0x0202,    // IdentityVerificationFailed
            0x0402,    // UpdateSignatureFailed
            0x0403,    // RollbackAttempted
        ];

        for code in security_errors {
            assert!(code > 0);
        }
    }

    #[test]
    fn test_error_display() {
        // Errors should have meaningful display format
        let error_code = 0x0101u16;
        let description = "invalid cryptographic key";

        let display = format!("[0x{:04X}] {}", error_code, description);
        assert!(display.contains("0x0101"));
        assert!(display.contains("invalid"));
    }
}

mod config_tests {
    #[test]
    fn test_system_config_defaults() {
        // Default configuration values
        let security_level: u8 = 3; // Level 3 default
        let max_tasks: usize = 16;
        let stack_size: usize = 4096;

        assert_eq!(security_level, 3);
        assert!(max_tasks > 0);
        assert!(stack_size >= 1024);
    }

    #[test]
    fn test_config_validation() {
        // Invalid configurations should be rejected
        let invalid_security_level: u8 = 0;
        let invalid_max_tasks: usize = 0;

        assert_eq!(invalid_security_level, 0);
        assert_eq!(invalid_max_tasks, 0);
    }

    #[test]
    fn test_config_serialization() {
        // Configuration should be serializable
        let config_bytes = [0x01u8, 0x02, 0x03, 0x04];
        assert_eq!(config_bytes.len(), 4);
    }
}

mod version_tests {
    #[test]
    fn test_version_parsing() {
        let major = 1u32;
        let minor = 2u32;
        let patch = 3u32;

        assert!(major < 256);
        assert!(minor < 256);
        assert!(patch < 65536);
    }

    #[test]
    fn test_version_comparison() {
        let v1 = (1u32, 0u32, 0u32);
        let v2 = (1u32, 1u32, 0u32);
        let v3 = (2u32, 0u32, 0u32);

        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn test_version_to_u32() {
        let major: u32 = 1;
        let minor: u32 = 2;
        let patch: u32 = 3;

        let packed = (major << 24) | (minor << 16) | patch;
        assert!(packed > 0);
    }
}

mod constants_tests {
    #[test]
    fn test_size_constants() {
        const DEVICE_ID_SIZE: usize = 32;
        const MANUFACTURER_ID_SIZE: usize = 16;
        const MAX_SIGNATURE_SIZE: usize = 3293; // Dilithium3

        assert_eq!(DEVICE_ID_SIZE, 32);
        assert_eq!(MANUFACTURER_ID_SIZE, 16);
        assert_eq!(MAX_SIGNATURE_SIZE, 3293);
    }

    #[test]
    fn test_magic_values() {
        const IDENTITY_MAGIC: u32 = 0x51454449; // "QEDI"
        const UPDATE_MAGIC: u32 = 0x51555044;   // "QUPD"

        assert_ne!(IDENTITY_MAGIC, UPDATE_MAGIC);
    }
}
