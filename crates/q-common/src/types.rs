// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Common types for Qbitel EdgeOS
//!
//! This module defines fundamental types used throughout the system,
//! including device identifiers, algorithm identifiers, and security levels.

use core::fmt;
use zeroize::Zeroize;

/// Unique device identifier (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// Size of device ID in bytes
    pub const SIZE: usize = 32;

    /// Create a new device ID from bytes
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a device ID from a slice
    ///
    /// Returns `None` if the slice length is not exactly 32 bytes.
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Get the device ID as a byte slice
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if the device ID is all zeros (invalid)
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl AsRef<[u8]> for DeviceId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...)")
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...")
    }
}

/// Manufacturer identifier (16 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManufacturerId([u8; 16]);

impl ManufacturerId {
    /// Size of manufacturer ID in bytes
    pub const SIZE: usize = 16;

    /// Create a new manufacturer ID from bytes
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Create a manufacturer ID from a slice
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 16 {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Get the manufacturer ID as bytes
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl AsRef<[u8]> for ManufacturerId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ManufacturerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManufacturerId(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Device class enumeration
///
/// Identifies the type and purpose of the device for policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DeviceClass {
    /// Generic device class
    Generic = 0x00,
    /// Railway signaling equipment (safety-critical)
    RailwaySignaling = 0x10,
    /// Power grid infrastructure
    PowerGrid = 0x20,
    /// Smart electricity meter
    SmartMeter = 0x21,
    /// Vehicle electronic control unit
    VehicleEcu = 0x30,
    /// Border surveillance sensor
    BorderSensor = 0x40,
    /// Industrial PLC
    IndustrialPlc = 0x50,
    /// Defense/military equipment
    Defense = 0x80,
    /// Test/development device
    TestDevice = 0xFE,
    /// Unknown device class
    Unknown = 0xFF,
}

impl DeviceClass {
    /// Create from raw byte value
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::Generic,
            0x10 => Self::RailwaySignaling,
            0x20 => Self::PowerGrid,
            0x21 => Self::SmartMeter,
            0x30 => Self::VehicleEcu,
            0x40 => Self::BorderSensor,
            0x50 => Self::IndustrialPlc,
            0x80 => Self::Defense,
            0xFE => Self::TestDevice,
            _ => Self::Unknown,
        }
    }

    /// Check if this is a safety-critical device class
    #[must_use]
    pub const fn is_safety_critical(&self) -> bool {
        matches!(
            self,
            Self::RailwaySignaling | Self::PowerGrid | Self::VehicleEcu | Self::Defense
        )
    }

    /// Check if this device class requires enhanced security
    #[must_use]
    pub const fn requires_enhanced_security(&self) -> bool {
        matches!(
            self,
            Self::RailwaySignaling
                | Self::PowerGrid
                | Self::BorderSensor
                | Self::Defense
                | Self::IndustrialPlc
        )
    }
}

impl Default for DeviceClass {
    fn default() -> Self {
        Self::Generic
    }
}

/// Algorithm identifiers for cryptographic agility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AlgorithmId {
    // =========================================================================
    // Key Encapsulation Mechanisms (0x01-0x0F)
    // =========================================================================
    /// ML-KEM-512 (Kyber-512)
    Kyber512 = 0x01,
    /// ML-KEM-768 (Kyber-768) - Recommended
    Kyber768 = 0x02,
    /// ML-KEM-1024 (Kyber-1024)
    Kyber1024 = 0x03,

    // =========================================================================
    // Signature Schemes - Lattice-based (0x10-0x1F)
    // =========================================================================
    /// ML-DSA-44 (Dilithium2)
    Dilithium2 = 0x10,
    /// ML-DSA-65 (Dilithium3) - Recommended
    Dilithium3 = 0x11,
    /// ML-DSA-87 (Dilithium5)
    Dilithium5 = 0x12,

    // =========================================================================
    // Signature Schemes - Hash-based (0x20-0x2F)
    // =========================================================================
    /// FN-DSA-512 (Falcon-512)
    Falcon512 = 0x20,
    /// FN-DSA-1024 (Falcon-1024) — wire-format ID reserved; Rust implementation pending
    Falcon1024 = 0x21,

    // =========================================================================
    // Classical Algorithms (0x80-0x8F) - For hybrid mode only
    // =========================================================================
    /// ECDSA with P-256 curve
    EcdsaP256 = 0x80,
    /// ECDSA with P-384 curve
    EcdsaP384 = 0x81,
    /// Ed25519 signature scheme
    Ed25519 = 0x82,
    /// X25519 key exchange
    X25519 = 0x83,

    // =========================================================================
    // Hash Functions (0xA0-0xAF)
    // =========================================================================
    /// SHA3-256
    Sha3_256 = 0xA0,
    /// SHA3-384
    Sha3_384 = 0xA1,
    /// SHA3-512
    Sha3_512 = 0xA2,
    /// SHAKE128
    Shake128 = 0xA3,
    /// SHAKE256
    Shake256 = 0xA4,

    // =========================================================================
    // AEAD Algorithms (0xB0-0xBF)
    // =========================================================================
    /// AES-128-GCM
    Aes128Gcm = 0xB0,
    /// AES-256-GCM
    Aes256Gcm = 0xB1,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 0xB2,

    // =========================================================================
    // Unknown/Reserved (0xFF)
    // =========================================================================
    /// Unknown algorithm
    Unknown = 0xFF,
}

impl AlgorithmId {
    /// Create from raw byte value
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::Kyber512,
            0x02 => Self::Kyber768,
            0x03 => Self::Kyber1024,
            0x10 => Self::Dilithium2,
            0x11 => Self::Dilithium3,
            0x12 => Self::Dilithium5,
            0x20 => Self::Falcon512,
            0x21 => Self::Falcon1024,
            0x80 => Self::EcdsaP256,
            0x81 => Self::EcdsaP384,
            0x82 => Self::Ed25519,
            0x83 => Self::X25519,
            0xA0 => Self::Sha3_256,
            0xA1 => Self::Sha3_384,
            0xA2 => Self::Sha3_512,
            0xA3 => Self::Shake128,
            0xA4 => Self::Shake256,
            0xB0 => Self::Aes128Gcm,
            0xB1 => Self::Aes256Gcm,
            0xB2 => Self::ChaCha20Poly1305,
            _ => Self::Unknown,
        }
    }

    /// Check if this is a post-quantum algorithm
    #[must_use]
    pub const fn is_post_quantum(&self) -> bool {
        matches!(
            self,
            Self::Kyber512
                | Self::Kyber768
                | Self::Kyber1024
                | Self::Dilithium2
                | Self::Dilithium3
                | Self::Dilithium5
                | Self::Falcon512
                | Self::Falcon1024
        )
    }

    /// Check if this is a KEM algorithm
    #[must_use]
    pub const fn is_kem(&self) -> bool {
        matches!(
            self,
            Self::Kyber512 | Self::Kyber768 | Self::Kyber1024 | Self::X25519
        )
    }

    /// Check if this is a signature algorithm
    #[must_use]
    pub const fn is_signature(&self) -> bool {
        matches!(
            self,
            Self::Dilithium2
                | Self::Dilithium3
                | Self::Dilithium5
                | Self::Falcon512
                | Self::Falcon1024
                | Self::EcdsaP256
                | Self::EcdsaP384
                | Self::Ed25519
        )
    }

    /// Get the security level (NIST category)
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        match self {
            Self::Kyber512 | Self::Dilithium2 | Self::Falcon512 => SecurityLevel::Level1,
            Self::Kyber768 | Self::Dilithium3 => SecurityLevel::Level3,
            Self::Kyber1024 | Self::Dilithium5 | Self::Falcon1024 => SecurityLevel::Level5,
            Self::EcdsaP256 | Self::Ed25519 | Self::X25519 | Self::Aes128Gcm => SecurityLevel::Level1,
            Self::EcdsaP384 => SecurityLevel::Level3,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => SecurityLevel::Level5,
            Self::Sha3_256 | Self::Shake128 => SecurityLevel::Level1,
            Self::Sha3_384 => SecurityLevel::Level3,
            Self::Sha3_512 | Self::Shake256 => SecurityLevel::Level5,
            Self::Unknown => SecurityLevel::Level1,
        }
    }
}

/// Security level (NIST post-quantum security categories)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SecurityLevel {
    /// Level 1: At least as hard as AES-128 (128-bit classical / 64-bit quantum)
    Level1 = 1,
    /// Level 3: At least as hard as AES-192 (192-bit classical / 96-bit quantum)
    Level3 = 3,
    /// Level 5: At least as hard as AES-256 (256-bit classical / 128-bit quantum)
    Level5 = 5,
}

impl SecurityLevel {
    /// Create from raw value
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Level1),
            3 => Some(Self::Level3),
            5 => Some(Self::Level5),
            _ => None,
        }
    }

    /// Get the minimum required security level for a device class
    #[must_use]
    pub const fn minimum_for_device_class(class: DeviceClass) -> Self {
        match class {
            DeviceClass::Defense | DeviceClass::RailwaySignaling => Self::Level5,
            DeviceClass::PowerGrid | DeviceClass::BorderSensor | DeviceClass::IndustrialPlc => {
                Self::Level3
            }
            _ => Self::Level1,
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Level3
    }
}

/// Timestamp type (Unix seconds since epoch)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Create a new timestamp
    #[must_use]
    pub const fn new(unix_seconds: u64) -> Self {
        Self(unix_seconds)
    }

    /// Get the Unix timestamp value
    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.0
    }

    /// Check if this timestamp is before another
    #[must_use]
    pub const fn is_before(&self, other: &Self) -> bool {
        self.0 < other.0
    }

    /// Check if this timestamp is after another
    #[must_use]
    pub const fn is_after(&self, other: &Self) -> bool {
        self.0 > other.0
    }

    /// Get the duration since this timestamp (returns 0 if in the future)
    #[must_use]
    pub const fn elapsed_since(&self, now: &Self) -> u64 {
        if now.0 > self.0 {
            now.0 - self.0
        } else {
            0
        }
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for u64 {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

/// A buffer that securely zeroizes its contents on drop
#[derive(Clone)]
pub struct SecureBytes<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> SecureBytes<N> {
    /// Create a new empty secure buffer
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: [0u8; N],
            len: 0,
        }
    }

    /// Create from a slice (copies data)
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() > N {
            return None;
        }
        let mut buf = Self::new();
        buf.data[..slice.len()].copy_from_slice(slice);
        buf.len = slice.len();
        Some(buf)
    }

    /// Get the data as a slice
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get the current length
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Check if empty
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the capacity
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<const N: usize> Default for SecureBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AsRef<[u8]> for SecureBytes<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> Zeroize for SecureBytes<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.len = 0;
    }
}

impl<const N: usize> Drop for SecureBytes<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
