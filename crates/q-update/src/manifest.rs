// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Update manifest definition and parsing

use q_common::version::Version;
use q_common::constants::DILITHIUM3_SIGNATURE_SIZE;

/// Update manifest magic: "QUPD"
pub const MANIFEST_MAGIC: u32 = 0x5155_5044;

/// Update manifest structure
#[derive(Clone)]
pub struct UpdateManifest {
    /// Magic number
    pub magic: u32,
    /// Manifest version
    pub manifest_version: u8,
    /// Target device class
    pub device_class: u8,
    /// Firmware version
    pub version: Version,
    /// Image size in bytes
    pub image_size: u32,
    /// SHA3-256 hash of image
    pub image_hash: [u8; 32],
    /// Minimum required version
    pub min_version: Version,
    /// Rollback index (for anti-rollback)
    pub rollback_index: u32,
    /// Flags
    pub flags: ManifestFlags,
    /// Signature over manifest fields
    pub signature: [u8; DILITHIUM3_SIGNATURE_SIZE],
}

impl UpdateManifest {
    /// Manifest header size (without signature)
    pub const HEADER_SIZE: usize = 128;
    /// Total manifest size
    pub const TOTAL_SIZE: usize = Self::HEADER_SIZE + DILITHIUM3_SIGNATURE_SIZE;

    /// Parse manifest from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::TOTAL_SIZE {
            return None;
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MANIFEST_MAGIC {
            return None;
        }

        // Parse remaining fields...
        Some(Self {
            magic,
            manifest_version: data[4],
            device_class: data[5],
            version: Version::from_bytes(&data[6..16])?,
            image_size: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            image_hash: data[20..52].try_into().ok()?,
            min_version: Version::from_bytes(&data[52..62])?,
            rollback_index: u32::from_le_bytes([data[62], data[63], data[64], data[65]]),
            flags: ManifestFlags::from_bits_truncate(data[66]),
            signature: data[Self::HEADER_SIZE..Self::TOTAL_SIZE].try_into().ok()?,
        })
    }
}

bitflags::bitflags! {
    /// Manifest flags
    #[derive(Clone, Copy, Debug)]
    pub struct ManifestFlags: u8 {
        /// Bootloader update
        const BOOTLOADER = 0x01;
        /// Kernel update
        const KERNEL = 0x02;
        /// Application update
        const APPLICATION = 0x04;
        /// Critical security update
        const CRITICAL = 0x10;
        /// Factory reset required
        const FACTORY_RESET = 0x20;
    }
}
