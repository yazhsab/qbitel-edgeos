// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Integration tests for q-hal
//!
//! Tests for the Hardware Abstraction Layer: platform detection, error handling,
//! trait definitions, and error conversion. Hardware-specific driver tests
//! cannot run on the host — these exercise the platform-agnostic layer.

mod platform_tests {
    use q_hal::Platform;

    #[test]
    fn test_platform_detection_returns_valid_variant() {
        let platform = Platform::current();
        // On host (no features), should be Unknown
        assert!(matches!(
            platform,
            Platform::Stm32H7 | Platform::Stm32U5 | Platform::RiscV | Platform::Unknown
        ));
    }

    #[test]
    fn test_trustzone_availability_by_platform() {
        assert!(Platform::Stm32H7.has_trustzone());
        assert!(Platform::Stm32U5.has_trustzone());
        assert!(!Platform::RiscV.has_trustzone());
        assert!(!Platform::Unknown.has_trustzone());
    }

    #[test]
    fn test_pmp_availability_by_platform() {
        assert!(!Platform::Stm32H7.has_pmp());
        assert!(!Platform::Stm32U5.has_pmp());
        assert!(Platform::RiscV.has_pmp());
        assert!(!Platform::Unknown.has_pmp());
    }

    #[test]
    fn test_flash_base_addresses_per_platform() {
        assert_eq!(Platform::Stm32H7.flash_base(), 0x0800_0000);
        assert_eq!(Platform::Stm32U5.flash_base(), 0x0800_0000);
        assert_eq!(Platform::RiscV.flash_base(), 0x2000_0000);
        assert_eq!(Platform::Unknown.flash_base(), 0x0000_0000);
    }

    #[test]
    fn test_ram_base_addresses_per_platform() {
        assert_eq!(Platform::Stm32H7.ram_base(), 0x2000_0000);
        assert_eq!(Platform::Stm32U5.ram_base(), 0x2000_0000);
        assert_eq!(Platform::RiscV.ram_base(), 0x8000_0000);
        assert_eq!(Platform::Unknown.ram_base(), 0x0000_0000);
    }

    #[test]
    fn test_platform_equality_and_inequality() {
        assert_eq!(Platform::Stm32H7, Platform::Stm32H7);
        assert_ne!(Platform::Stm32H7, Platform::Stm32U5);
        assert_ne!(Platform::Stm32H7, Platform::RiscV);
        assert_ne!(Platform::RiscV, Platform::Unknown);
    }

    #[test]
    fn test_platform_is_copy() {
        let p1 = Platform::Stm32H7;
        let p2 = p1; // Copy
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_platform_debug_format() {
        let debug = format!("{:?}", Platform::Stm32H7);
        assert!(debug.contains("Stm32H7"));

        let debug = format!("{:?}", Platform::RiscV);
        assert!(debug.contains("RiscV"));
    }

    #[test]
    fn test_flash_and_ram_regions_do_not_overlap() {
        let platforms = [Platform::Stm32H7, Platform::Stm32U5, Platform::RiscV];

        for platform in platforms {
            assert_ne!(
                platform.flash_base(),
                platform.ram_base(),
                "{:?}: flash and RAM bases must not overlap",
                platform
            );
        }
    }

    #[test]
    fn test_every_real_platform_has_isolation() {
        let platforms = [Platform::Stm32H7, Platform::Stm32U5, Platform::RiscV];

        for platform in platforms {
            let has_isolation = platform.has_trustzone() || platform.has_pmp();
            assert!(
                has_isolation,
                "{:?} must have either TrustZone or PMP",
                platform
            );
        }
    }

    #[test]
    fn test_unknown_platform_has_no_security_features() {
        assert!(!Platform::Unknown.has_trustzone());
        assert!(!Platform::Unknown.has_pmp());
    }

    #[test]
    fn test_real_platforms_have_nonzero_addresses() {
        let platforms = [Platform::Stm32H7, Platform::Stm32U5, Platform::RiscV];

        for platform in platforms {
            assert!(
                platform.flash_base() > 0,
                "{:?}: flash base must be nonzero",
                platform
            );
            assert!(
                platform.ram_base() > 0,
                "{:?}: RAM base must be nonzero",
                platform
            );
        }
    }
}

mod error_tests {
    use q_hal::HalError;
    use std::collections::HashSet;

    /// All HalError variants for exhaustive testing.
    fn all_hal_errors() -> Vec<HalError> {
        vec![
            HalError::NotInitialized,
            HalError::InitFailed,
            HalError::FlashError,
            HalError::FlashLocked,
            HalError::FlashOutOfBounds,
            HalError::FlashEraseFailed,
            HalError::FlashWriteFailed,
            HalError::FlashVerifyFailed,
            HalError::FlashTimeout,
            HalError::RngError,
            HalError::TimerError,
            HalError::GpioError,
            HalError::SpiError,
            HalError::I2cError,
            HalError::UartError,
            HalError::DmaError,
            HalError::SecureStorageError,
            HalError::SecureStorageLocked,
            HalError::SecureStorageNotFound,
            HalError::TrustZoneError,
            HalError::PufError,
            HalError::PufNotAvailable,
            HalError::InvalidParameter,
            HalError::Timeout,
            HalError::Busy,
            HalError::NotSupported,
            HalError::InvalidState,
            HalError::CryptoError,
            HalError::AuthenticationFailed,
            HalError::IntegrityCheckFailed,
            HalError::InvalidOperation,
            HalError::HardwareFault,
        ]
    }

    #[test]
    fn test_all_error_codes_are_unique() {
        let errors = all_hal_errors();
        let codes: HashSet<_> = errors.iter().map(|e| e.code()).collect();
        assert_eq!(
            codes.len(),
            errors.len(),
            "All error codes must be unique"
        );
    }

    #[test]
    fn test_all_errors_in_0x08xx_range() {
        for error in all_hal_errors() {
            let code = error.code();
            assert_eq!(
                code & 0xFF00,
                0x0800,
                "Error {:?} code 0x{:04X} must be in 0x08xx range",
                error,
                code
            );
        }
    }

    #[test]
    fn test_flash_errors_in_0x081x_range() {
        let flash_errors = [
            HalError::FlashError,
            HalError::FlashLocked,
            HalError::FlashOutOfBounds,
            HalError::FlashEraseFailed,
            HalError::FlashWriteFailed,
            HalError::FlashVerifyFailed,
            HalError::FlashTimeout,
        ];

        for error in flash_errors {
            let code = error.code();
            assert!(
                code >= 0x0810 && code <= 0x081F,
                "Flash error {:?} code 0x{:04X} must be in 0x081x range",
                error,
                code
            );
        }
    }

    #[test]
    fn test_secure_storage_errors_in_0x089x_range() {
        let storage_errors = [
            HalError::SecureStorageError,
            HalError::SecureStorageLocked,
            HalError::SecureStorageNotFound,
        ];

        for error in storage_errors {
            let code = error.code();
            assert!(
                code >= 0x0890 && code <= 0x089F,
                "Secure storage error {:?} code 0x{:04X} must be in 0x089x range",
                error,
                code
            );
        }
    }

    #[test]
    fn test_specific_error_codes() {
        assert_eq!(HalError::NotInitialized.code(), 0x0801);
        assert_eq!(HalError::InitFailed.code(), 0x0802);
        assert_eq!(HalError::FlashError.code(), 0x0810);
        assert_eq!(HalError::RngError.code(), 0x0820);
        assert_eq!(HalError::TimerError.code(), 0x0830);
        assert_eq!(HalError::GpioError.code(), 0x0840);
        assert_eq!(HalError::PufError.code(), 0x08B0);
        assert_eq!(HalError::HardwareFault.code(), 0x08D0);
        assert_eq!(HalError::NotSupported.code(), 0x08FF);
    }

    #[test]
    fn test_error_descriptions_are_nonempty() {
        for error in all_hal_errors() {
            let desc = error.description();
            assert!(
                !desc.is_empty(),
                "Error {:?} must have a nonempty description",
                error
            );
        }
    }

    #[test]
    fn test_specific_error_descriptions() {
        assert_eq!(HalError::NotInitialized.description(), "not initialized");
        assert_eq!(HalError::FlashError.description(), "flash error");
        assert_eq!(HalError::RngError.description(), "RNG error");
        assert_eq!(HalError::PufError.description(), "PUF error");
        assert_eq!(HalError::Timeout.description(), "timeout");
        assert_eq!(HalError::NotSupported.description(), "not supported");
    }

    #[test]
    fn test_error_display_includes_code_and_description() {
        let error = HalError::FlashError;
        let display = format!("{}", error);
        assert!(
            display.contains("0x0810"),
            "Display should contain hex code: {}",
            display
        );
        assert!(
            display.contains("flash error"),
            "Display should contain description: {}",
            display
        );
    }

    #[test]
    fn test_error_display_format_for_all_variants() {
        for error in all_hal_errors() {
            let display = format!("{}", error);
            let code_hex = format!("0x{:04X}", error.code());
            assert!(
                display.contains(&code_hex),
                "{:?} display '{}' must contain '{}'",
                error,
                display,
                code_hex
            );
            assert!(
                display.contains(error.description()),
                "{:?} display must contain description",
                error
            );
        }
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(HalError::FlashError, HalError::FlashError);
        assert_ne!(HalError::FlashError, HalError::RngError);
    }

    #[test]
    fn test_error_is_copy() {
        let e1 = HalError::FlashError;
        let e2 = e1; // Copy
        assert_eq!(e1, e2);
    }
}

mod error_conversion_tests {
    use q_hal::HalError;
    use q_common::Error;

    #[test]
    fn test_init_errors_to_hardware_init_failed() {
        assert_eq!(Error::from(HalError::NotInitialized), Error::HardwareInitFailed);
        assert_eq!(Error::from(HalError::InitFailed), Error::HardwareInitFailed);
    }

    #[test]
    fn test_all_flash_errors_to_flash_error() {
        let flash_errors = [
            HalError::FlashError,
            HalError::FlashLocked,
            HalError::FlashOutOfBounds,
            HalError::FlashEraseFailed,
            HalError::FlashWriteFailed,
            HalError::FlashVerifyFailed,
            HalError::FlashTimeout,
        ];

        for error in flash_errors {
            assert_eq!(
                Error::from(error),
                Error::FlashError,
                "{:?} should map to FlashError",
                error
            );
        }
    }

    #[test]
    fn test_peripheral_error_conversions() {
        assert_eq!(Error::from(HalError::RngError), Error::RngFailure);
        assert_eq!(Error::from(HalError::TimerError), Error::TimerError);
        assert_eq!(Error::from(HalError::GpioError), Error::GpioError);
        assert_eq!(Error::from(HalError::SpiError), Error::SpiError);
        assert_eq!(Error::from(HalError::I2cError), Error::I2cError);
        assert_eq!(Error::from(HalError::UartError), Error::UartError);
        assert_eq!(Error::from(HalError::DmaError), Error::DmaError);
    }

    #[test]
    fn test_secure_storage_error_conversions() {
        assert_eq!(Error::from(HalError::SecureStorageError), Error::StorageLocked);
        assert_eq!(Error::from(HalError::SecureStorageLocked), Error::StorageLocked);
        assert_eq!(Error::from(HalError::SecureStorageNotFound), Error::StorageNotFound);
    }

    #[test]
    fn test_security_error_conversions() {
        assert_eq!(Error::from(HalError::TrustZoneError), Error::TrustZoneError);
        assert_eq!(Error::from(HalError::PufError), Error::PufError);
        assert_eq!(Error::from(HalError::PufNotAvailable), Error::PufError);
        assert_eq!(Error::from(HalError::CryptoError), Error::CryptoError);
        assert_eq!(Error::from(HalError::AuthenticationFailed), Error::AuthenticationFailed);
        assert_eq!(Error::from(HalError::IntegrityCheckFailed), Error::IntegrityCheckFailed);
    }

    #[test]
    fn test_generic_error_conversions() {
        assert_eq!(Error::from(HalError::InvalidParameter), Error::InvalidParameter);
        assert_eq!(Error::from(HalError::Timeout), Error::Timeout);
        assert_eq!(Error::from(HalError::Busy), Error::Busy);
        assert_eq!(Error::from(HalError::NotSupported), Error::NotImplemented);
        assert_eq!(Error::from(HalError::InvalidState), Error::InvalidState);
        assert_eq!(Error::from(HalError::InvalidOperation), Error::InvalidState);
        assert_eq!(Error::from(HalError::HardwareFault), Error::HardwareInitFailed);
    }
}

mod reset_reason_tests {
    use q_hal::ResetReason;

    #[test]
    fn test_reset_reason_variants_all_distinct() {
        let reasons = [
            ResetReason::PowerOn,
            ResetReason::Software,
            ResetReason::Watchdog,
            ResetReason::External,
            ResetReason::BrownOut,
            ResetReason::Unknown,
        ];

        for (i, r1) in reasons.iter().enumerate() {
            for (j, r2) in reasons.iter().enumerate() {
                if i == j {
                    assert_eq!(r1, r2);
                } else {
                    assert_ne!(r1, r2);
                }
            }
        }
    }

    #[test]
    fn test_reset_reason_is_copy() {
        let r1 = ResetReason::Watchdog;
        let r2 = r1; // Copy
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_reset_reason_debug_format() {
        assert!(format!("{:?}", ResetReason::PowerOn).contains("PowerOn"));
        assert!(format!("{:?}", ResetReason::Software).contains("Software"));
        assert!(format!("{:?}", ResetReason::Watchdog).contains("Watchdog"));
        assert!(format!("{:?}", ResetReason::External).contains("External"));
        assert!(format!("{:?}", ResetReason::BrownOut).contains("BrownOut"));
        assert!(format!("{:?}", ResetReason::Unknown).contains("Unknown"));
    }
}

mod trait_object_safety_tests {
    //! Verify that HAL traits have the expected associated constants and methods.
    //! These are compile-time checks — the test passes if it compiles.

    use q_hal::{FlashInterface, RngInterface, TimerInterface, SecureStorageInterface, PufInterface};
    use q_hal::error::HalResult;

    /// A mock flash implementation to verify the trait compiles correctly
    /// and all required methods can be implemented.
    struct MockFlash;

    impl FlashInterface for MockFlash {
        const PAGE_SIZE: usize = 4096;
        const TOTAL_SIZE: usize = 2 * 1024 * 1024;
        const BASE_ADDRESS: u32 = 0x0800_0000;

        fn init(&mut self) -> HalResult<()> { Ok(()) }
        fn read(&self, _address: u32, _buffer: &mut [u8]) -> HalResult<()> { Ok(()) }
        fn write(&mut self, _address: u32, _data: &[u8]) -> HalResult<()> { Ok(()) }
        fn erase_page(&mut self, _address: u32) -> HalResult<()> { Ok(()) }
        fn lock(&mut self) -> HalResult<()> { Ok(()) }
        fn unlock(&mut self) -> HalResult<()> { Ok(()) }
        fn is_locked(&self) -> bool { false }
    }

    struct MockRng;

    impl RngInterface for MockRng {
        fn init(&mut self) -> HalResult<()> { Ok(()) }
        fn fill_bytes(&mut self, buffer: &mut [u8]) -> HalResult<()> {
            for (i, b) in buffer.iter_mut().enumerate() {
                *b = (i & 0xFF) as u8;
            }
            Ok(())
        }
        fn is_ready(&self) -> bool { true }
    }

    struct MockTimer { ticks: u64 }

    impl TimerInterface for MockTimer {
        const FREQUENCY_HZ: u32 = 1_000_000;
        fn init(&mut self) -> HalResult<()> { Ok(()) }
        fn get_ticks(&self) -> u64 { self.ticks }
        fn delay_us(&self, _us: u32) { /* no-op in mock */ }
    }

    struct MockSecureStorage;

    impl SecureStorageInterface for MockSecureStorage {
        const MAX_SLOT_SIZE: usize = 256;
        const NUM_SLOTS: usize = 8;

        fn init(&mut self) -> HalResult<()> { Ok(()) }
        fn read(&self, _slot: u8, _buffer: &mut [u8]) -> HalResult<usize> { Ok(0) }
        fn write(&mut self, _slot: u8, _data: &[u8]) -> HalResult<()> { Ok(()) }
        fn is_slot_written(&self, _slot: u8) -> HalResult<bool> { Ok(false) }
        fn lock_slot(&mut self, _slot: u8) -> HalResult<()> { Ok(()) }
        fn is_slot_locked(&self, _slot: u8) -> HalResult<bool> { Ok(false) }
        fn read_uid(&self) -> HalResult<[u8; 16]> { Ok([0x42; 16]) }
    }

    struct MockPuf;

    impl PufInterface for MockPuf {
        const RESPONSE_SIZE: usize = 256;

        fn init(&mut self) -> HalResult<()> { Ok(()) }
        fn is_available(&self) -> bool { true }
        fn challenge(&mut self, _challenge: &[u8; 32]) -> HalResult<[u8; 256]> {
            Ok([0xAB; 256])
        }
        fn enroll(&mut self) -> HalResult<([u8; 32], [u8; 128])> {
            Ok(([0x01; 32], [0x02; 128]))
        }
        fn reconstruct(&mut self, _helper_data: &[u8; 128]) -> HalResult<[u8; 32]> {
            Ok([0x01; 32])
        }
    }

    #[test]
    fn test_flash_trait_implementation() {
        let mut flash = MockFlash;
        assert_eq!(MockFlash::PAGE_SIZE, 4096);
        assert_eq!(MockFlash::TOTAL_SIZE, 2 * 1024 * 1024);
        assert_eq!(MockFlash::BASE_ADDRESS, 0x0800_0000);

        assert!(flash.init().is_ok());
        assert!(!flash.is_locked());
        assert!(flash.unlock().is_ok());

        let mut buf = [0u8; 16];
        assert!(flash.read(0x0800_0000, &mut buf).is_ok());
        assert!(flash.write(0x0800_0000, &[0xFF; 16]).is_ok());
        assert!(flash.erase_page(0x0800_0000).is_ok());
        assert!(flash.lock().is_ok());
    }

    #[test]
    fn test_rng_trait_implementation() {
        let mut rng = MockRng;
        assert!(rng.init().is_ok());
        assert!(rng.is_ready());

        let mut buf = [0u8; 32];
        assert!(rng.fill_bytes(&mut buf).is_ok());

        // Default next_u32 should use fill_bytes
        let val = rng.next_u32().unwrap();
        assert!(val > 0 || val == 0); // Just verify it doesn't panic

        let val64 = rng.next_u64().unwrap();
        assert!(val64 > 0 || val64 == 0);
    }

    #[test]
    fn test_timer_trait_implementation() {
        let timer = MockTimer { ticks: 1_000_000 };
        assert_eq!(MockTimer::FREQUENCY_HZ, 1_000_000);
        assert_eq!(timer.get_ticks(), 1_000_000);

        // Default get_micros: (1_000_000 * 1_000_000) / 1_000_000 = 1_000_000 us
        assert_eq!(timer.get_micros(), 1_000_000);

        // Default get_millis: (1_000_000 * 1_000) / 1_000_000 = 1000 ms
        assert_eq!(timer.get_millis(), 1000);
    }

    #[test]
    fn test_secure_storage_trait_implementation() {
        let mut storage = MockSecureStorage;
        assert_eq!(MockSecureStorage::MAX_SLOT_SIZE, 256);
        assert_eq!(MockSecureStorage::NUM_SLOTS, 8);

        assert!(storage.init().is_ok());
        assert!(!storage.is_slot_written(0).unwrap());
        assert!(!storage.is_slot_locked(0).unwrap());

        assert!(storage.write(0, &[0x42; 32]).is_ok());
        assert!(storage.lock_slot(0).is_ok());

        let uid = storage.read_uid().unwrap();
        assert_eq!(uid, [0x42; 16]);
    }

    #[test]
    fn test_puf_trait_implementation() {
        let mut puf = MockPuf;
        assert_eq!(MockPuf::RESPONSE_SIZE, 256);

        assert!(puf.init().is_ok());
        assert!(puf.is_available());

        // Enroll
        let (fingerprint, helper_data) = puf.enroll().unwrap();
        assert_eq!(fingerprint, [0x01; 32]);
        assert_eq!(helper_data, [0x02; 128]);

        // Reconstruct
        let reconstructed = puf.reconstruct(&helper_data).unwrap();
        assert_eq!(reconstructed, fingerprint);

        // Challenge-response
        let challenge = [0xCD; 32];
        let response = puf.challenge(&challenge).unwrap();
        assert_eq!(response.len(), 256);
    }

    #[test]
    fn test_flash_default_verify_method() {
        // Verify uses the default trait implementation
        let flash = MockFlash;
        // MockFlash.read fills buffer with zeros, so verify against zeros should pass
        let expected = [0u8; 16];
        assert!(flash.verify(0x0800_0000, &expected).unwrap());
    }

    #[test]
    fn test_flash_default_erase_range_method() {
        let mut flash = MockFlash;
        // erase_range uses the default implementation that calls erase_page in a loop
        let start = 0x0800_0000;
        let end = start + (3 * MockFlash::PAGE_SIZE as u32); // 3 pages
        assert!(flash.erase_range(start, end).is_ok());
    }

    #[test]
    fn test_timer_default_delay_ms_method() {
        let timer = MockTimer { ticks: 0 };
        // delay_ms calls delay_us(ms * 1000), which is a no-op in our mock
        timer.delay_ms(100); // Should not panic
    }
}

mod hal_result_tests {
    use q_hal::HalError;
    use q_hal::error::HalResult;

    #[test]
    fn test_hal_result_ok() {
        let result: HalResult<u32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_hal_result_err() {
        let result: HalResult<u32> = Err(HalError::NotInitialized);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HalError::NotInitialized);
    }

    #[test]
    fn test_hal_result_map() {
        let result: HalResult<u32> = Ok(42);
        let mapped = result.map(|v| v * 2);
        assert_eq!(mapped.unwrap(), 84);
    }

    #[test]
    fn test_hal_result_error_propagation() {
        fn inner() -> HalResult<u32> {
            Err(HalError::Timeout)
        }

        fn outer() -> HalResult<u32> {
            let val = inner()?;
            Ok(val + 1)
        }

        let result = outer();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HalError::Timeout);
    }
}
