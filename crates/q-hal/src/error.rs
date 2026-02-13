// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! HAL error types

use core::fmt;

/// HAL error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalError {
    /// Hardware not initialized
    NotInitialized,
    /// Hardware initialization failed
    InitFailed,
    /// Flash operation failed
    FlashError,
    /// Flash is locked
    FlashLocked,
    /// Flash address out of bounds
    FlashOutOfBounds,
    /// Flash erase failed
    FlashEraseFailed,
    /// Flash write failed
    FlashWriteFailed,
    /// Flash verify failed
    FlashVerifyFailed,
    /// Flash operation timeout
    FlashTimeout,
    /// RNG failure
    RngError,
    /// Timer error
    TimerError,
    /// GPIO error
    GpioError,
    /// SPI error
    SpiError,
    /// I2C error
    I2cError,
    /// UART error
    UartError,
    /// DMA error
    DmaError,
    /// Secure storage error
    SecureStorageError,
    /// Secure storage locked
    SecureStorageLocked,
    /// Secure storage not found
    SecureStorageNotFound,
    /// TrustZone error
    TrustZoneError,
    /// PUF error
    PufError,
    /// PUF not available
    PufNotAvailable,
    /// Invalid parameter
    InvalidParameter,
    /// Operation timeout
    Timeout,
    /// Hardware busy
    Busy,
    /// Operation not supported
    NotSupported,
    /// Invalid state for operation
    InvalidState,
    /// Crypto operation failed
    CryptoError,
    /// Authentication failed
    AuthenticationFailed,
    /// Integrity check failed
    IntegrityCheckFailed,
    /// Invalid operation for current state
    InvalidOperation,
    /// Hardware fault detected
    HardwareFault,
}

impl HalError {
    /// Get error code
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            Self::NotInitialized => 0x0801,
            Self::InitFailed => 0x0802,
            Self::FlashError => 0x0810,
            Self::FlashLocked => 0x0811,
            Self::FlashOutOfBounds => 0x0812,
            Self::FlashEraseFailed => 0x0813,
            Self::FlashWriteFailed => 0x0814,
            Self::FlashVerifyFailed => 0x0815,
            Self::FlashTimeout => 0x0816,
            Self::RngError => 0x0820,
            Self::TimerError => 0x0830,
            Self::GpioError => 0x0840,
            Self::SpiError => 0x0850,
            Self::I2cError => 0x0860,
            Self::UartError => 0x0870,
            Self::DmaError => 0x0880,
            Self::SecureStorageError => 0x0890,
            Self::SecureStorageLocked => 0x0891,
            Self::SecureStorageNotFound => 0x0892,
            Self::TrustZoneError => 0x08A0,
            Self::PufError => 0x08B0,
            Self::PufNotAvailable => 0x08B1,
            Self::InvalidParameter => 0x08F0,
            Self::Timeout => 0x08F1,
            Self::Busy => 0x08F2,
            Self::NotSupported => 0x08FF,
            Self::InvalidState => 0x08F3,
            Self::CryptoError => 0x08C0,
            Self::AuthenticationFailed => 0x08C1,
            Self::IntegrityCheckFailed => 0x08C2,
            Self::InvalidOperation => 0x08F4,
            Self::HardwareFault => 0x08D0,
        }
    }

    /// Get error description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::NotInitialized => "not initialized",
            Self::InitFailed => "initialization failed",
            Self::FlashError => "flash error",
            Self::FlashLocked => "flash locked",
            Self::FlashOutOfBounds => "flash address out of bounds",
            Self::FlashEraseFailed => "flash erase failed",
            Self::FlashWriteFailed => "flash write failed",
            Self::FlashVerifyFailed => "flash verify failed",
            Self::FlashTimeout => "flash operation timeout",
            Self::RngError => "RNG error",
            Self::TimerError => "timer error",
            Self::GpioError => "GPIO error",
            Self::SpiError => "SPI error",
            Self::I2cError => "I2C error",
            Self::UartError => "UART error",
            Self::DmaError => "DMA error",
            Self::SecureStorageError => "secure storage error",
            Self::SecureStorageLocked => "secure storage locked",
            Self::SecureStorageNotFound => "secure storage not found",
            Self::TrustZoneError => "TrustZone error",
            Self::PufError => "PUF error",
            Self::PufNotAvailable => "PUF not available",
            Self::InvalidParameter => "invalid parameter",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::NotSupported => "not supported",
            Self::InvalidState => "invalid state for operation",
            Self::CryptoError => "crypto operation failed",
            Self::AuthenticationFailed => "authentication failed",
            Self::IntegrityCheckFailed => "integrity check failed",
            Self::InvalidOperation => "invalid operation for current state",
            Self::HardwareFault => "hardware fault detected",
        }
    }
}

impl fmt::Display for HalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:04X}] {}", self.code(), self.description())
    }
}

impl From<HalError> for q_common::Error {
    fn from(e: HalError) -> Self {
        match e {
            HalError::NotInitialized | HalError::InitFailed => Self::HardwareInitFailed,
            HalError::FlashError
            | HalError::FlashLocked
            | HalError::FlashOutOfBounds
            | HalError::FlashEraseFailed
            | HalError::FlashWriteFailed
            | HalError::FlashVerifyFailed
            | HalError::FlashTimeout => Self::FlashError,
            HalError::RngError => Self::RngFailure,
            HalError::TimerError => Self::TimerError,
            HalError::GpioError => Self::GpioError,
            HalError::SpiError => Self::SpiError,
            HalError::I2cError => Self::I2cError,
            HalError::UartError => Self::UartError,
            HalError::DmaError => Self::DmaError,
            HalError::SecureStorageError | HalError::SecureStorageLocked => Self::StorageLocked,
            HalError::SecureStorageNotFound => Self::StorageNotFound,
            HalError::TrustZoneError => Self::TrustZoneError,
            HalError::PufError | HalError::PufNotAvailable => Self::PufError,
            HalError::InvalidParameter => Self::InvalidParameter,
            HalError::Timeout => Self::Timeout,
            HalError::Busy => Self::Busy,
            HalError::NotSupported => Self::NotImplemented,
            HalError::InvalidState => Self::InvalidState,
            HalError::CryptoError => Self::CryptoError,
            HalError::AuthenticationFailed => Self::AuthenticationFailed,
            HalError::IntegrityCheckFailed => Self::IntegrityCheckFailed,
            HalError::InvalidOperation => Self::InvalidState,
            HalError::HardwareFault => Self::HardwareInitFailed,
        }
    }
}

/// HAL Result type
pub type HalResult<T> = Result<T, HalError>;
