// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Identity commitment structure
//!
//! Defines the core identity commitment that represents a device's
//! cryptographic identity.

use q_common::types::{AlgorithmId, DeviceId, ManufacturerId, Timestamp};
use q_common::constants::{
    KYBER768_PUBLIC_KEY_SIZE, DILITHIUM3_PUBLIC_KEY_SIZE, DILITHIUM3_SIGNATURE_SIZE,
    MAX_METADATA_SIZE, IDENTITY_COMMITMENT_VERSION,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use q_common::types::DeviceClass;

/// Identity commitment - the public identity of a device
#[derive(Clone)]
pub struct IdentityCommitment {
    /// Format version
    pub version: u8,
    /// Unique device identifier (derived from hardware fingerprint)
    pub device_id: DeviceId,
    /// Manufacturer identifier
    pub manufacturer_id: ManufacturerId,
    /// Device class
    pub device_class: DeviceClass,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// KEM algorithm identifier
    pub kem_algorithm: AlgorithmId,
    /// Signing algorithm identifier
    pub sig_algorithm: AlgorithmId,
    /// KEM public key (Kyber-768)
    pub kem_public_key: [u8; KYBER768_PUBLIC_KEY_SIZE],
    /// Signing public key (Dilithium3)
    pub signing_public_key: [u8; DILITHIUM3_PUBLIC_KEY_SIZE],
    /// Hardware fingerprint hash
    pub hardware_fingerprint_hash: [u8; 32],
    /// Optional metadata
    pub metadata: [u8; MAX_METADATA_SIZE],
    /// Metadata length
    pub metadata_len: usize,
    /// Self-signature over all above fields
    pub self_signature: [u8; DILITHIUM3_SIGNATURE_SIZE],
}

impl IdentityCommitment {
    /// Serialized size of the commitment
    pub const SERIALIZED_SIZE: usize = 1 + // version
        32 + // device_id
        16 + // manufacturer_id
        1 + // device_class
        8 + // created_at
        1 + // kem_algorithm
        1 + // sig_algorithm
        KYBER768_PUBLIC_KEY_SIZE +
        DILITHIUM3_PUBLIC_KEY_SIZE +
        32 + // hardware_fingerprint_hash
        2 + // metadata_len
        MAX_METADATA_SIZE +
        DILITHIUM3_SIGNATURE_SIZE;

    /// Create an empty/uninitialized commitment
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            version: IDENTITY_COMMITMENT_VERSION,
            device_id: DeviceId::new([0u8; 32]),
            manufacturer_id: ManufacturerId::new([0u8; 16]),
            device_class: DeviceClass::Generic,
            created_at: Timestamp::new(0),
            kem_algorithm: AlgorithmId::Kyber768,
            sig_algorithm: AlgorithmId::Dilithium3,
            kem_public_key: [0u8; KYBER768_PUBLIC_KEY_SIZE],
            signing_public_key: [0u8; DILITHIUM3_PUBLIC_KEY_SIZE],
            hardware_fingerprint_hash: [0u8; 32],
            metadata: [0u8; MAX_METADATA_SIZE],
            metadata_len: 0,
            self_signature: [0u8; DILITHIUM3_SIGNATURE_SIZE],
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self, buffer: &mut [u8]) -> Option<usize> {
        if buffer.len() < Self::SERIALIZED_SIZE {
            return None;
        }

        let mut offset = 0;

        buffer[offset] = self.version;
        offset += 1;

        buffer[offset..offset + 32].copy_from_slice(self.device_id.as_bytes());
        offset += 32;

        buffer[offset..offset + 16].copy_from_slice(self.manufacturer_id.as_bytes());
        offset += 16;

        buffer[offset] = self.device_class as u8;
        offset += 1;

        buffer[offset..offset + 8].copy_from_slice(&self.created_at.as_secs().to_le_bytes());
        offset += 8;

        buffer[offset] = self.kem_algorithm as u8;
        offset += 1;

        buffer[offset] = self.sig_algorithm as u8;
        offset += 1;

        buffer[offset..offset + KYBER768_PUBLIC_KEY_SIZE].copy_from_slice(&self.kem_public_key);
        offset += KYBER768_PUBLIC_KEY_SIZE;

        buffer[offset..offset + DILITHIUM3_PUBLIC_KEY_SIZE].copy_from_slice(&self.signing_public_key);
        offset += DILITHIUM3_PUBLIC_KEY_SIZE;

        buffer[offset..offset + 32].copy_from_slice(&self.hardware_fingerprint_hash);
        offset += 32;

        buffer[offset..offset + 2].copy_from_slice(&(self.metadata_len as u16).to_le_bytes());
        offset += 2;

        buffer[offset..offset + MAX_METADATA_SIZE].copy_from_slice(&self.metadata);
        offset += MAX_METADATA_SIZE;

        buffer[offset..offset + DILITHIUM3_SIGNATURE_SIZE].copy_from_slice(&self.self_signature);
        offset += DILITHIUM3_SIGNATURE_SIZE;

        Some(offset)
    }

    /// Get the message bytes to be signed (everything except signature)
    pub fn signing_message(&self, buffer: &mut [u8]) -> Option<usize> {
        let sig_offset = Self::SERIALIZED_SIZE - DILITHIUM3_SIGNATURE_SIZE;
        if buffer.len() < sig_offset {
            return None;
        }

        self.to_bytes(buffer)?;
        Some(sig_offset)
    }
}

/// Identity secrets - private key material (never leaves device)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecrets {
    /// KEM secret key
    pub kem_secret_key: [u8; q_common::constants::KYBER768_SECRET_KEY_SIZE],
    /// Signing secret key
    pub signing_secret_key: [u8; q_common::constants::DILITHIUM3_SECRET_KEY_SIZE],
    /// Hardware binding key (derived from PUF)
    pub hardware_binding_key: [u8; 32],
    /// Master seed for key derivation
    pub master_seed: [u8; 64],
}

impl IdentitySecrets {
    /// Create uninitialized secrets (all zeros)
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            kem_secret_key: [0u8; q_common::constants::KYBER768_SECRET_KEY_SIZE],
            signing_secret_key: [0u8; q_common::constants::DILITHIUM3_SECRET_KEY_SIZE],
            hardware_binding_key: [0u8; 32],
            master_seed: [0u8; 64],
        }
    }
}
