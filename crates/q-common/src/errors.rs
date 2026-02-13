// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Error types for Qbitel EdgeOS
//!
//! This module defines the unified error type used throughout the system.
//! All errors are designed to be no_std compatible and provide detailed
//! error information without heap allocation.

use core::fmt;

/// Result type alias for Qbitel EdgeOS operations
pub type Result<T> = core::result::Result<T, Error>;

/// Unified error type for Qbitel EdgeOS
///
/// This enum represents all possible errors that can occur in the system.
/// Each variant contains additional context where appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // =========================================================================
    // Cryptographic Errors (0x01xx)
    // =========================================================================
    /// Invalid cryptographic key format or size
    InvalidKey,
    /// Signature verification failed
    InvalidSignature,
    /// Ciphertext is malformed or invalid
    InvalidCiphertext,
    /// KEM decapsulation failed
    DecapsulationFailed,
    /// Random number generator failure
    RngFailure,
    /// Cryptographic algorithm not supported
    UnsupportedAlgorithm,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Hash computation failed
    HashError,
    /// AEAD encryption/decryption failed
    AeadError,

    // =========================================================================
    // Identity Errors (0x02xx)
    // =========================================================================
    /// Device identity not initialized
    IdentityNotInitialized,
    /// Identity commitment verification failed
    IdentityVerificationFailed,
    /// Identity has expired
    IdentityExpired,
    /// Device class mismatch during verification
    DeviceClassMismatch,
    /// Hardware fingerprint mismatch
    HardwareFingerprintMismatch,
    /// Identity already exists (cannot re-provision)
    IdentityAlreadyExists,

    // =========================================================================
    // Storage Errors (0x03xx)
    // =========================================================================
    /// Storage read operation failed
    StorageReadFailed,
    /// Storage write operation failed
    StorageWriteFailed,
    /// Storage is full
    StorageFull,
    /// Requested item not found in storage
    StorageNotFound,
    /// Storage data is corrupted
    StorageCorrupted,
    /// Storage is locked (secure storage)
    StorageLocked,

    // =========================================================================
    // Update Errors (0x04xx)
    // =========================================================================
    /// Update manifest is invalid
    InvalidManifest,
    /// Update signature verification failed
    UpdateSignatureFailed,
    /// Version rollback attempted (blocked)
    RollbackAttempted,
    /// Update image is corrupted
    UpdateCorrupted,
    /// No update available
    NoUpdateAvailable,
    /// Update already in progress
    UpdateInProgress,
    /// Update failed to apply
    UpdateApplyFailed,
    /// Partition switch failed
    PartitionSwitchFailed,

    // =========================================================================
    // Recovery Errors (0x05xx)
    // =========================================================================
    /// Key rotation failed
    KeyRotationFailed,
    /// Insufficient threshold shares for recovery
    InsufficientShares,
    /// Recovery token is invalid
    InvalidRecoveryToken,
    /// Device is revoked
    DeviceRevoked,
    /// Recovery not available offline
    RecoveryRequiresNetwork,

    // =========================================================================
    // Mesh Networking Errors (0x06xx)
    // =========================================================================
    /// Peer discovery failed
    PeerDiscoveryFailed,
    /// Handshake failed
    HandshakeFailed,
    /// Session is invalid or expired
    InvalidSession,
    /// Message authentication failed
    MessageAuthFailed,
    /// Peer not found in mesh
    PeerNotFound,
    /// Routing failed
    RoutingFailed,
    /// Radio communication error
    RadioError,
    /// Network timeout
    NetworkTimeout,

    // =========================================================================
    // Attestation Errors (0x07xx)
    // =========================================================================
    /// Attestation evidence is invalid
    InvalidEvidence,
    /// Attestation verification failed
    AttestationFailed,
    /// Supply chain record is invalid
    SupplyChainError,
    /// Anomaly detected during attestation
    AnomalyDetected,

    // =========================================================================
    // HAL Errors (0x08xx)
    // =========================================================================
    /// Hardware initialization failed
    HardwareInitFailed,
    /// Flash operation failed
    FlashError,
    /// Timer error
    TimerError,
    /// GPIO error
    GpioError,
    /// SPI communication error
    SpiError,
    /// I2C communication error
    I2cError,
    /// UART communication error
    UartError,
    /// DMA error
    DmaError,
    /// TrustZone configuration error
    TrustZoneError,
    /// PUF error
    PufError,

    // =========================================================================
    // Kernel Errors (0x09xx)
    // =========================================================================
    /// Task creation failed
    TaskCreationFailed,
    /// Memory allocation failed
    MemoryAllocationFailed,
    /// IPC channel error
    IpcError,
    /// System call error
    SyscallError,
    /// Scheduler error
    SchedulerError,
    /// Stack overflow detected
    StackOverflow,
    /// Invalid memory access
    MemoryAccessViolation,
    /// Resource is exhausted
    ResourceExhausted,
    /// Channel is full
    ChannelFull,
    /// Channel is already in use
    ChannelInUse,
    /// Operation would block
    WouldBlock,

    // =========================================================================
    // Boot Errors (0x0Axx)
    // =========================================================================
    /// Boot verification failed
    BootVerificationFailed,
    /// Invalid boot configuration
    InvalidBootConfig,
    /// Secure boot chain broken
    SecureBootFailed,
    /// Boot timeout
    BootTimeout,

    // =========================================================================
    // General Errors (0xFFxx)
    // =========================================================================
    /// Buffer is too small for operation
    BufferTooSmall,
    /// Invalid parameter provided
    InvalidParameter,
    /// Operation timed out
    Timeout,
    /// Resource is busy
    Busy,
    /// Operation not permitted
    NotPermitted,
    /// Feature not implemented
    NotImplemented,
    /// Internal error (should not occur)
    InternalError,
    /// Invalid state for the operation
    InvalidState,
    /// Generic cryptographic operation error
    CryptoError,
    /// Authentication failed (tag mismatch, etc.)
    AuthenticationFailed,
    /// Integrity check failed (checksum, hash, etc.)
    IntegrityCheckFailed,
    /// Requested item not found
    NotFound,
    /// Not authorized for this operation
    NotAuthorized,
    /// Timestamp is invalid or expired
    TimestampInvalid,
}

impl Error {
    /// Get the error code for this error
    ///
    /// Error codes are organized by category:
    /// - 0x01xx: Cryptographic errors
    /// - 0x02xx: Identity errors
    /// - 0x03xx: Storage errors
    /// - 0x04xx: Update errors
    /// - 0x05xx: Recovery errors
    /// - 0x06xx: Mesh networking errors
    /// - 0x07xx: Attestation errors
    /// - 0x08xx: HAL errors
    /// - 0x09xx: Kernel errors
    /// - 0x0Axx: Boot errors
    /// - 0xFFxx: General errors
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            // Crypto errors (0x01xx)
            Self::InvalidKey => 0x0101,
            Self::InvalidSignature => 0x0102,
            Self::InvalidCiphertext => 0x0103,
            Self::DecapsulationFailed => 0x0104,
            Self::RngFailure => 0x0105,
            Self::UnsupportedAlgorithm => 0x0106,
            Self::KeyDerivationFailed => 0x0107,
            Self::HashError => 0x0108,
            Self::AeadError => 0x0109,

            // Identity errors (0x02xx)
            Self::IdentityNotInitialized => 0x0201,
            Self::IdentityVerificationFailed => 0x0202,
            Self::IdentityExpired => 0x0203,
            Self::DeviceClassMismatch => 0x0204,
            Self::HardwareFingerprintMismatch => 0x0205,
            Self::IdentityAlreadyExists => 0x0206,

            // Storage errors (0x03xx)
            Self::StorageReadFailed => 0x0301,
            Self::StorageWriteFailed => 0x0302,
            Self::StorageFull => 0x0303,
            Self::StorageNotFound => 0x0304,
            Self::StorageCorrupted => 0x0305,
            Self::StorageLocked => 0x0306,

            // Update errors (0x04xx)
            Self::InvalidManifest => 0x0401,
            Self::UpdateSignatureFailed => 0x0402,
            Self::RollbackAttempted => 0x0403,
            Self::UpdateCorrupted => 0x0404,
            Self::NoUpdateAvailable => 0x0405,
            Self::UpdateInProgress => 0x0406,
            Self::UpdateApplyFailed => 0x0407,
            Self::PartitionSwitchFailed => 0x0408,

            // Recovery errors (0x05xx)
            Self::KeyRotationFailed => 0x0501,
            Self::InsufficientShares => 0x0502,
            Self::InvalidRecoveryToken => 0x0503,
            Self::DeviceRevoked => 0x0504,
            Self::RecoveryRequiresNetwork => 0x0505,

            // Mesh errors (0x06xx)
            Self::PeerDiscoveryFailed => 0x0601,
            Self::HandshakeFailed => 0x0602,
            Self::InvalidSession => 0x0603,
            Self::MessageAuthFailed => 0x0604,
            Self::PeerNotFound => 0x0605,
            Self::RoutingFailed => 0x0606,
            Self::RadioError => 0x0607,
            Self::NetworkTimeout => 0x0608,

            // Attestation errors (0x07xx)
            Self::InvalidEvidence => 0x0701,
            Self::AttestationFailed => 0x0702,
            Self::SupplyChainError => 0x0703,
            Self::AnomalyDetected => 0x0704,

            // HAL errors (0x08xx)
            Self::HardwareInitFailed => 0x0801,
            Self::FlashError => 0x0802,
            Self::TimerError => 0x0803,
            Self::GpioError => 0x0804,
            Self::SpiError => 0x0805,
            Self::I2cError => 0x0806,
            Self::UartError => 0x0807,
            Self::DmaError => 0x0808,
            Self::TrustZoneError => 0x0809,
            Self::PufError => 0x080A,

            // Kernel errors (0x09xx)
            Self::TaskCreationFailed => 0x0901,
            Self::MemoryAllocationFailed => 0x0902,
            Self::IpcError => 0x0903,
            Self::SyscallError => 0x0904,
            Self::SchedulerError => 0x0905,
            Self::StackOverflow => 0x0906,
            Self::MemoryAccessViolation => 0x0907,
            Self::ResourceExhausted => 0x0908,
            Self::ChannelFull => 0x0909,
            Self::ChannelInUse => 0x090A,
            Self::WouldBlock => 0x090B,

            // Boot errors (0x0Axx)
            Self::BootVerificationFailed => 0x0A01,
            Self::InvalidBootConfig => 0x0A02,
            Self::SecureBootFailed => 0x0A03,
            Self::BootTimeout => 0x0A04,

            // General errors (0xFFxx)
            Self::BufferTooSmall => 0xFF01,
            Self::InvalidParameter => 0xFF02,
            Self::Timeout => 0xFF03,
            Self::Busy => 0xFF04,
            Self::NotPermitted => 0xFF05,
            Self::NotImplemented => 0xFF06,
            Self::InternalError => 0xFFFF,
            Self::InvalidState => 0xFF07,
            Self::CryptoError => 0xFF08,
            Self::AuthenticationFailed => 0xFF09,
            Self::IntegrityCheckFailed => 0xFF0A,
            Self::NotFound => 0xFF0B,
            Self::NotAuthorized => 0xFF0C,
            Self::TimestampInvalid => 0xFF0D,
        }
    }

    /// Check if this is a security-critical error
    #[must_use]
    pub const fn is_security_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidKey
                | Self::InvalidSignature
                | Self::InvalidCiphertext
                | Self::DecapsulationFailed
                | Self::IdentityVerificationFailed
                | Self::HardwareFingerprintMismatch
                | Self::UpdateSignatureFailed
                | Self::RollbackAttempted
                | Self::DeviceRevoked
                | Self::MessageAuthFailed
                | Self::AttestationFailed
                | Self::AnomalyDetected
                | Self::BootVerificationFailed
                | Self::SecureBootFailed
                | Self::MemoryAccessViolation
        )
    }

    /// Get a short description of the error
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::InvalidKey => "invalid cryptographic key",
            Self::InvalidSignature => "signature verification failed",
            Self::InvalidCiphertext => "invalid ciphertext",
            Self::DecapsulationFailed => "KEM decapsulation failed",
            Self::RngFailure => "RNG failure",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::KeyDerivationFailed => "key derivation failed",
            Self::HashError => "hash computation failed",
            Self::AeadError => "AEAD operation failed",
            Self::IdentityNotInitialized => "identity not initialized",
            Self::IdentityVerificationFailed => "identity verification failed",
            Self::IdentityExpired => "identity expired",
            Self::DeviceClassMismatch => "device class mismatch",
            Self::HardwareFingerprintMismatch => "hardware fingerprint mismatch",
            Self::IdentityAlreadyExists => "identity already exists",
            Self::StorageReadFailed => "storage read failed",
            Self::StorageWriteFailed => "storage write failed",
            Self::StorageFull => "storage full",
            Self::StorageNotFound => "storage item not found",
            Self::StorageCorrupted => "storage corrupted",
            Self::StorageLocked => "storage locked",
            Self::InvalidManifest => "invalid update manifest",
            Self::UpdateSignatureFailed => "update signature failed",
            Self::RollbackAttempted => "rollback attempted",
            Self::UpdateCorrupted => "update corrupted",
            Self::NoUpdateAvailable => "no update available",
            Self::UpdateInProgress => "update in progress",
            Self::UpdateApplyFailed => "update apply failed",
            Self::PartitionSwitchFailed => "partition switch failed",
            Self::KeyRotationFailed => "key rotation failed",
            Self::InsufficientShares => "insufficient threshold shares",
            Self::InvalidRecoveryToken => "invalid recovery token",
            Self::DeviceRevoked => "device revoked",
            Self::RecoveryRequiresNetwork => "recovery requires network",
            Self::PeerDiscoveryFailed => "peer discovery failed",
            Self::HandshakeFailed => "handshake failed",
            Self::InvalidSession => "invalid session",
            Self::MessageAuthFailed => "message auth failed",
            Self::PeerNotFound => "peer not found",
            Self::RoutingFailed => "routing failed",
            Self::RadioError => "radio error",
            Self::NetworkTimeout => "network timeout",
            Self::InvalidEvidence => "invalid attestation evidence",
            Self::AttestationFailed => "attestation failed",
            Self::SupplyChainError => "supply chain error",
            Self::AnomalyDetected => "anomaly detected",
            Self::HardwareInitFailed => "hardware init failed",
            Self::FlashError => "flash error",
            Self::TimerError => "timer error",
            Self::GpioError => "GPIO error",
            Self::SpiError => "SPI error",
            Self::I2cError => "I2C error",
            Self::UartError => "UART error",
            Self::DmaError => "DMA error",
            Self::TrustZoneError => "TrustZone error",
            Self::PufError => "PUF error",
            Self::TaskCreationFailed => "task creation failed",
            Self::MemoryAllocationFailed => "memory allocation failed",
            Self::IpcError => "IPC error",
            Self::SyscallError => "syscall error",
            Self::SchedulerError => "scheduler error",
            Self::StackOverflow => "stack overflow",
            Self::MemoryAccessViolation => "memory access violation",
            Self::ResourceExhausted => "resource exhausted",
            Self::ChannelFull => "channel full",
            Self::ChannelInUse => "channel in use",
            Self::WouldBlock => "would block",
            Self::BootVerificationFailed => "boot verification failed",
            Self::InvalidBootConfig => "invalid boot config",
            Self::SecureBootFailed => "secure boot failed",
            Self::BootTimeout => "boot timeout",
            Self::BufferTooSmall => "buffer too small",
            Self::InvalidParameter => "invalid parameter",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::NotPermitted => "not permitted",
            Self::NotImplemented => "not implemented",
            Self::InternalError => "internal error",
            Self::InvalidState => "invalid state",
            Self::CryptoError => "crypto error",
            Self::AuthenticationFailed => "authentication failed",
            Self::IntegrityCheckFailed => "integrity check failed",
            Self::NotFound => "not found",
            Self::NotAuthorized => "not authorized",
            Self::TimestampInvalid => "timestamp invalid",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:04X}] {}", self.code(), self.description())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "[0x{:04X}] {}", self.code(), self.description());
    }
}
