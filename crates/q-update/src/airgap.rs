// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Air-gapped Update Support for Qbitel EdgeOS
//!
//! This module provides secure firmware update capabilities for air-gapped systems
//! that cannot connect to networks. Updates are transferred via physical media
//! (USB, SD card) or optical channels (QR codes).
//!
//! # Security Features
//!
//! - Multi-party chain of custody signatures
//! - Manifest integrity verification
//! - Image hash verification
//! - Anti-rollback protection
//! - Timestamp validation
//! - Device binding verification

use heapless::Vec;
use q_common::Error;
use q_common::constants::DILITHIUM3_SIGNATURE_SIZE;

use crate::manifest::{UpdateManifest, ManifestFlags};
use crate::verification::{verify_manifest, verify_image_hash};

/// Maximum number of custody signatures
pub const MAX_CUSTODY_SIGNATURES: usize = 8;

/// Maximum package metadata size
pub const MAX_METADATA_SIZE: usize = 512;

/// Package format version
pub const PACKAGE_FORMAT_VERSION: u8 = 1;

/// Airgap package magic: "QAIR"
pub const AIRGAP_MAGIC: u32 = 0x5141_4952;

/// Custody entry representing a signature in the chain
#[derive(Clone)]
pub struct CustodySignature {
    /// Signer identity (32-byte hash of public key)
    pub signer_id: [u8; 32],
    /// Role of the signer (e.g., "release_engineer", "security_reviewer")
    pub role: CustodyRole,
    /// Timestamp when signature was applied (Unix epoch seconds)
    pub timestamp: u64,
    /// Dilithium-3 signature over package hash + previous signatures
    pub signature: [u8; DILITHIUM3_SIGNATURE_SIZE],
}

impl CustodySignature {
    /// Create a new custody signature
    pub fn new(
        signer_id: [u8; 32],
        role: CustodyRole,
        timestamp: u64,
        signature: [u8; DILITHIUM3_SIGNATURE_SIZE],
    ) -> Self {
        Self {
            signer_id,
            role,
            timestamp,
            signature,
        }
    }

    /// Serialize for verification
    pub fn to_bytes(&self) -> [u8; 44] {
        let mut bytes = [0u8; 44];
        bytes[0..32].copy_from_slice(&self.signer_id);
        bytes[32] = self.role as u8;
        bytes[33..41].copy_from_slice(&self.timestamp.to_le_bytes());
        // Note: signature not included in chain hash to avoid recursive hashing
        bytes
    }
}

/// Custody role for chain of custody
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CustodyRole {
    /// Build engineer who created the package
    BuildEngineer = 0,
    /// Security reviewer who audited the code
    SecurityReviewer = 1,
    /// Release manager who approved the release
    ReleaseManager = 2,
    /// Quality assurance tester
    QualityAssurance = 3,
    /// Device administrator applying the update
    DeviceAdmin = 4,
    /// Hardware security module
    HardwareSecurityModule = 5,
    /// Custom role
    Custom = 255,
}

impl From<u8> for CustodyRole {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::BuildEngineer,
            1 => Self::SecurityReviewer,
            2 => Self::ReleaseManager,
            3 => Self::QualityAssurance,
            4 => Self::DeviceAdmin,
            5 => Self::HardwareSecurityModule,
            _ => Self::Custom,
        }
    }
}

/// Airgap package header
#[derive(Clone)]
pub struct AirgapPackageHeader {
    /// Magic number ("QAIR")
    pub magic: u32,
    /// Package format version
    pub format_version: u8,
    /// Header flags
    pub flags: AirgapFlags,
    /// Target device class
    pub device_class: u8,
    /// Number of custody signatures
    pub custody_count: u8,
    /// Creation timestamp (Unix epoch seconds)
    pub created_at: u64,
    /// Expiration timestamp (Unix epoch seconds, 0 = no expiry)
    pub expires_at: u64,
    /// Target device ID (32-byte hash, all zeros for any device)
    pub target_device: [u8; 32],
    /// SHA3-256 hash of manifest + image
    pub package_hash: [u8; 32],
    /// Reserved for future use
    pub reserved: [u8; 16],
}

impl AirgapPackageHeader {
    /// Header size in bytes
    pub const SIZE: usize = 104;

    /// Create a new header
    pub fn new(
        device_class: u8,
        created_at: u64,
        expires_at: u64,
        target_device: [u8; 32],
        package_hash: [u8; 32],
    ) -> Self {
        Self {
            magic: AIRGAP_MAGIC,
            format_version: PACKAGE_FORMAT_VERSION,
            flags: AirgapFlags::empty(),
            device_class,
            custody_count: 0,
            created_at,
            expires_at,
            target_device,
            package_hash,
            reserved: [0u8; 16],
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];

        bytes[0..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4] = self.format_version;
        bytes[5] = self.flags.bits();
        bytes[6] = self.device_class;
        bytes[7] = self.custody_count;
        bytes[8..16].copy_from_slice(&self.created_at.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.expires_at.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.target_device);
        bytes[56..88].copy_from_slice(&self.package_hash);
        bytes[88..104].copy_from_slice(&self.reserved);

        bytes
    }

    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != AIRGAP_MAGIC {
            return None;
        }

        Some(Self {
            magic,
            format_version: data[4],
            flags: AirgapFlags::from_bits_truncate(data[5]),
            device_class: data[6],
            custody_count: data[7],
            created_at: u64::from_le_bytes(data[8..16].try_into().ok()?),
            expires_at: u64::from_le_bytes(data[16..24].try_into().ok()?),
            target_device: data[24..56].try_into().ok()?,
            package_hash: data[56..88].try_into().ok()?,
            reserved: data[88..104].try_into().ok()?,
        })
    }
}

bitflags::bitflags! {
    /// Airgap package flags
    #[derive(Clone, Copy, Debug)]
    pub struct AirgapFlags: u8 {
        /// Package requires specific device binding
        const DEVICE_BOUND = 0x01;
        /// Package has expiration time
        const HAS_EXPIRY = 0x02;
        /// Critical security update (bypass some checks)
        const CRITICAL = 0x04;
        /// Package is compressed
        const COMPRESSED = 0x08;
        /// Package is encrypted
        const ENCRYPTED = 0x10;
        /// Requires hardware security module verification
        const HSM_REQUIRED = 0x20;
    }
}

/// Air-gapped update package
///
/// This structure represents a complete, self-contained update package
/// that can be transported via physical media to air-gapped systems.
pub struct AirgapPackage<'a> {
    /// Package header
    pub header: AirgapPackageHeader,
    /// Update manifest
    pub manifest: UpdateManifest,
    /// Firmware image
    pub image: &'a [u8],
    /// Chain of custody signatures
    pub custody_chain: Vec<CustodySignature, MAX_CUSTODY_SIGNATURES>,
}

impl<'a> AirgapPackage<'a> {
    /// Create a new airgap package
    pub fn new(
        manifest: UpdateManifest,
        image: &'a [u8],
        device_class: u8,
        created_at: u64,
    ) -> Result<Self, Error> {
        // Compute package hash
        let package_hash = Self::compute_package_hash(&manifest, image)?;

        let header = AirgapPackageHeader::new(
            device_class,
            created_at,
            0, // No expiry by default
            [0u8; 32], // Not device-bound by default
            package_hash,
        );

        Ok(Self {
            header,
            manifest,
            image,
            custody_chain: Vec::new(),
        })
    }

    /// Create with device binding
    pub fn new_device_bound(
        manifest: UpdateManifest,
        image: &'a [u8],
        device_class: u8,
        target_device: [u8; 32],
        created_at: u64,
        expires_at: u64,
    ) -> Result<Self, Error> {
        let package_hash = Self::compute_package_hash(&manifest, image)?;

        let mut header = AirgapPackageHeader::new(
            device_class,
            created_at,
            expires_at,
            target_device,
            package_hash,
        );
        header.flags |= AirgapFlags::DEVICE_BOUND;
        if expires_at > 0 {
            header.flags |= AirgapFlags::HAS_EXPIRY;
        }

        Ok(Self {
            header,
            manifest,
            image,
            custody_chain: Vec::new(),
        })
    }

    /// Compute SHA3-256 hash of manifest + image
    fn compute_package_hash(manifest: &UpdateManifest, image: &[u8]) -> Result<[u8; 32], Error> {
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;

        // Create a combined hash of manifest header and image
        let mut hasher_input = [0u8; 256];
        let manifest_bytes = crate::verification::compute_manifest_hash(manifest);
        hasher_input[0..32].copy_from_slice(&manifest_bytes);

        // Hash the image
        let image_hash = Sha3_256::hash(image);
        let mut image_hash_bytes = [0u8; 32];
        image_hash_bytes.copy_from_slice(image_hash.as_ref());
        hasher_input[32..64].copy_from_slice(&image_hash_bytes);

        // Final hash
        let output = Sha3_256::hash(&hasher_input[0..64]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(output.as_ref());

        Ok(hash)
    }

    /// Add a custody signature to the chain
    pub fn add_custody_signature(
        &mut self,
        signer_id: [u8; 32],
        role: CustodyRole,
        timestamp: u64,
        signing_key: &[u8],
    ) -> Result<(), Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3SecretKey};
        use q_crypto::traits::Signer;

        if self.custody_chain.len() >= MAX_CUSTODY_SIGNATURES {
            return Err(Error::BufferTooSmall);
        }

        // Parse signing key
        let sk = Dilithium3SecretKey::from_bytes(signing_key)
            .map_err(|_| Error::InvalidKey)?;

        // Compute message to sign: package_hash + chain_hash
        let message = self.compute_chain_message()?;

        // Sign
        let signature = Dilithium3::sign(&sk, &message)
            .map_err(|_| Error::CryptoError)?;

        let mut sig_bytes = [0u8; DILITHIUM3_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(signature.as_ref());

        let custody_sig = CustodySignature::new(signer_id, role, timestamp, sig_bytes);

        self.custody_chain.push(custody_sig)
            .map_err(|_| Error::BufferTooSmall)?;

        self.header.custody_count = self.custody_chain.len() as u8;

        Ok(())
    }

    /// Compute message for chain signature
    fn compute_chain_message(&self) -> Result<[u8; 64], Error> {
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;

        let mut message = [0u8; 64];
        message[0..32].copy_from_slice(&self.header.package_hash);

        // Hash all previous signatures
        let mut chain_data = [0u8; MAX_CUSTODY_SIGNATURES * 44];
        let mut offset = 0;
        for sig in self.custody_chain.iter() {
            let bytes = sig.to_bytes();
            chain_data[offset..offset + 44].copy_from_slice(&bytes);
            offset += 44;
        }

        let chain_hash = Sha3_256::hash(&chain_data[0..offset]);
        message[32..64].copy_from_slice(chain_hash.as_ref());

        Ok(message)
    }

    /// Verify the custody chain
    pub fn verify_custody_chain(&self, authorized_signers: &[AuthorizedSigner]) -> Result<bool, Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
        use q_crypto::traits::Signer;

        if self.custody_chain.is_empty() {
            return Ok(false);
        }

        // Verify each signature in the chain
        let mut chain_data = [0u8; MAX_CUSTODY_SIGNATURES * 44];
        let mut offset = 0;

        for (_i, custody_sig) in self.custody_chain.iter().enumerate() {
            // Find authorized signer
            let signer = authorized_signers
                .iter()
                .find(|s| s.signer_id == custody_sig.signer_id)
                .ok_or(Error::NotFound)?;

            // Check role is authorized
            if !signer.allowed_roles.iter().any(|r| *r == custody_sig.role) {
                return Ok(false);
            }

            // Compute message at this point in chain
            let mut message = [0u8; 64];
            message[0..32].copy_from_slice(&self.header.package_hash);

            use q_crypto::hash::Sha3_256;
            use q_crypto::traits::Hash;

            let chain_hash = Sha3_256::hash(&chain_data[0..offset]);
            message[32..64].copy_from_slice(chain_hash.as_ref());

            // Verify signature
            let pk = Dilithium3PublicKey::from_bytes(&signer.public_key)
                .map_err(|_| Error::InvalidKey)?;
            let sig = Dilithium3Signature::from_bytes(&custody_sig.signature)
                .map_err(|_| Error::InvalidSignature)?;

            if !Dilithium3::verify(&pk, &message, &sig).map_err(|_| Error::CryptoError)? {
                return Ok(false);
            }

            // Add this signature's metadata to chain for next verification
            let bytes = custody_sig.to_bytes();
            chain_data[offset..offset + 44].copy_from_slice(&bytes);
            offset += 44;
        }

        Ok(true)
    }

    /// Verify package integrity (manifest signature + image hash)
    pub fn verify_integrity(&self, manifest_signing_key: &[u8]) -> Result<bool, Error> {
        // Verify manifest signature
        if !verify_manifest(&self.manifest, manifest_signing_key)? {
            return Ok(false);
        }

        // Verify image hash matches manifest
        if !verify_image_hash(self.image, &self.manifest.image_hash) {
            return Ok(false);
        }

        // Verify image size matches
        if self.image.len() != self.manifest.image_size as usize {
            return Ok(false);
        }

        // Verify package hash
        let computed_hash = Self::compute_package_hash(&self.manifest, self.image)?;
        if computed_hash != self.header.package_hash {
            return Ok(false);
        }

        Ok(true)
    }

    /// Check if package is valid for the given device and time
    pub fn check_validity(
        &self,
        device_id: &[u8; 32],
        device_class: u8,
        current_time: u64,
    ) -> Result<(), Error> {
        // Check device class
        if self.header.device_class != device_class {
            return Err(Error::InvalidParameter);
        }

        // Check device binding if required
        if self.header.flags.contains(AirgapFlags::DEVICE_BOUND) {
            let zero_device = [0u8; 32];
            if self.header.target_device != zero_device
                && self.header.target_device != *device_id
            {
                return Err(Error::NotAuthorized);
            }
        }

        // Check expiration
        if self.header.flags.contains(AirgapFlags::HAS_EXPIRY) {
            if self.header.expires_at > 0 && current_time > self.header.expires_at {
                return Err(Error::TimestampInvalid);
            }
        }

        // Check not created in the future (with 5 minute tolerance)
        if self.header.created_at > current_time + 300 {
            return Err(Error::TimestampInvalid);
        }

        Ok(())
    }

    /// Perform complete verification
    pub fn verify_complete(
        &self,
        device_id: &[u8; 32],
        device_class: u8,
        current_time: u64,
        manifest_signing_key: &[u8],
        authorized_signers: &[AuthorizedSigner],
        required_roles: &[CustodyRole],
    ) -> Result<VerificationResult, Error> {
        // Check validity
        self.check_validity(device_id, device_class, current_time)?;

        // Verify integrity
        if !self.verify_integrity(manifest_signing_key)? {
            return Ok(VerificationResult {
                valid: false,
                integrity_ok: false,
                custody_ok: false,
                roles_satisfied: false,
            });
        }

        // Verify custody chain
        let custody_ok = self.verify_custody_chain(authorized_signers)?;

        // Check required roles are present
        let mut roles_satisfied = true;
        for required in required_roles {
            if !self.custody_chain.iter().any(|c| c.role == *required) {
                roles_satisfied = false;
                break;
            }
        }

        Ok(VerificationResult {
            valid: custody_ok && roles_satisfied,
            integrity_ok: true,
            custody_ok,
            roles_satisfied,
        })
    }

    /// Get the firmware image for flashing
    pub fn get_image(&self) -> &[u8] {
        self.image
    }

    /// Get the manifest
    pub fn get_manifest(&self) -> &UpdateManifest {
        &self.manifest
    }

    /// Check if this is a critical security update
    pub fn is_critical(&self) -> bool {
        self.header.flags.contains(AirgapFlags::CRITICAL) ||
        self.manifest.flags.contains(ManifestFlags::CRITICAL)
    }
}

/// Authorized signer for custody chain verification
#[derive(Clone)]
pub struct AuthorizedSigner {
    /// Signer identity (32-byte hash of public key)
    pub signer_id: [u8; 32],
    /// Signer's public key (Dilithium-3)
    pub public_key: [u8; q_common::constants::DILITHIUM3_PUBLIC_KEY_SIZE],
    /// Roles this signer is authorized for
    pub allowed_roles: Vec<CustodyRole, 8>,
}

impl AuthorizedSigner {
    /// Create new authorized signer
    pub fn new(
        signer_id: [u8; 32],
        public_key: [u8; q_common::constants::DILITHIUM3_PUBLIC_KEY_SIZE],
    ) -> Self {
        Self {
            signer_id,
            public_key,
            allowed_roles: Vec::new(),
        }
    }

    /// Add an allowed role
    pub fn add_role(&mut self, role: CustodyRole) -> Result<(), Error> {
        self.allowed_roles.push(role)
            .map_err(|_| Error::BufferTooSmall)
    }
}

/// Result of package verification
#[derive(Debug, Clone, Copy)]
pub struct VerificationResult {
    /// Overall validity
    pub valid: bool,
    /// Manifest and image integrity verified
    pub integrity_ok: bool,
    /// Custody chain verified
    pub custody_ok: bool,
    /// All required roles present
    pub roles_satisfied: bool,
}

/// Package parser for deserializing from bytes
pub struct AirgapPackageParser;

impl AirgapPackageParser {
    /// Parse package header from bytes
    pub fn parse_header(data: &[u8]) -> Option<AirgapPackageHeader> {
        AirgapPackageHeader::from_bytes(data)
    }

    /// Get expected package size from header
    pub fn expected_size(header: &AirgapPackageHeader, manifest: &UpdateManifest) -> usize {
        AirgapPackageHeader::SIZE
            + UpdateManifest::TOTAL_SIZE
            + manifest.image_size as usize
            + (header.custody_count as usize * (44 + DILITHIUM3_SIGNATURE_SIZE))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::MANIFEST_MAGIC;
    use q_common::version::Version;

    fn create_test_manifest() -> UpdateManifest {
        UpdateManifest {
            magic: MANIFEST_MAGIC,
            manifest_version: 1,
            device_class: 0x01,
            version: Version::new(2, 0, 0, 100),
            image_size: 64,
            image_hash: [0xAA; 32],
            min_version: Version::new(1, 0, 0, 0),
            rollback_index: 5,
            flags: ManifestFlags::KERNEL,
            signature: [0u8; DILITHIUM3_SIGNATURE_SIZE],
        }
    }

    #[test]
    fn test_custody_role_conversion() {
        assert_eq!(CustodyRole::from(0), CustodyRole::BuildEngineer);
        assert_eq!(CustodyRole::from(1), CustodyRole::SecurityReviewer);
        assert_eq!(CustodyRole::from(2), CustodyRole::ReleaseManager);
        assert_eq!(CustodyRole::from(100), CustodyRole::Custom);
    }

    #[test]
    fn test_airgap_header_serialization() {
        let header = AirgapPackageHeader::new(
            0x01,
            1000000,
            2000000,
            [0x42; 32],
            [0xAB; 32],
        );

        let bytes = header.to_bytes();
        let parsed = AirgapPackageHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, AIRGAP_MAGIC);
        assert_eq!(parsed.format_version, PACKAGE_FORMAT_VERSION);
        assert_eq!(parsed.device_class, 0x01);
        assert_eq!(parsed.created_at, 1000000);
        assert_eq!(parsed.expires_at, 2000000);
        assert_eq!(parsed.target_device, [0x42; 32]);
        assert_eq!(parsed.package_hash, [0xAB; 32]);
    }

    #[test]
    fn test_airgap_header_invalid_magic() {
        let mut bytes = [0u8; AirgapPackageHeader::SIZE];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        assert!(AirgapPackageHeader::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_airgap_flags() {
        let mut flags = AirgapFlags::empty();
        assert!(!flags.contains(AirgapFlags::DEVICE_BOUND));

        flags |= AirgapFlags::DEVICE_BOUND;
        flags |= AirgapFlags::HAS_EXPIRY;

        assert!(flags.contains(AirgapFlags::DEVICE_BOUND));
        assert!(flags.contains(AirgapFlags::HAS_EXPIRY));
        assert!(!flags.contains(AirgapFlags::CRITICAL));
    }

    #[test]
    fn test_package_creation() {
        let manifest = create_test_manifest();
        let image = [0xFFu8; 64];

        let package = AirgapPackage::new(
            manifest,
            &image,
            0x01,
            1000000,
        ).unwrap();

        assert_eq!(package.header.magic, AIRGAP_MAGIC);
        assert_eq!(package.header.device_class, 0x01);
        assert_eq!(package.custody_chain.len(), 0);
    }

    #[test]
    fn test_device_bound_package() {
        let manifest = create_test_manifest();
        let image = [0xFFu8; 64];
        let device_id = [0x42; 32];

        let package = AirgapPackage::new_device_bound(
            manifest,
            &image,
            0x01,
            device_id,
            1000000,
            2000000,
        ).unwrap();

        assert!(package.header.flags.contains(AirgapFlags::DEVICE_BOUND));
        assert!(package.header.flags.contains(AirgapFlags::HAS_EXPIRY));
        assert_eq!(package.header.target_device, device_id);
        assert_eq!(package.header.expires_at, 2000000);
    }

    #[test]
    fn test_custody_signature_serialization() {
        let sig = CustodySignature::new(
            [0x11; 32],
            CustodyRole::SecurityReviewer,
            1234567890,
            [0u8; DILITHIUM3_SIGNATURE_SIZE],
        );

        let bytes = sig.to_bytes();

        assert_eq!(&bytes[0..32], &[0x11; 32]);
        assert_eq!(bytes[32], CustodyRole::SecurityReviewer as u8);
    }

    #[test]
    fn test_validity_check_device_class() {
        let manifest = create_test_manifest();
        let image = [0xFFu8; 64];

        let package = AirgapPackage::new(manifest, &image, 0x01, 1000000).unwrap();
        let device_id = [0; 32];

        // Correct device class
        assert!(package.check_validity(&device_id, 0x01, 1000000).is_ok());

        // Wrong device class
        assert!(package.check_validity(&device_id, 0x02, 1000000).is_err());
    }

    #[test]
    fn test_validity_check_expiration() {
        let manifest = create_test_manifest();
        let image = [0xFFu8; 64];
        let device_id = [0x42; 32];

        let package = AirgapPackage::new_device_bound(
            manifest,
            &image,
            0x01,
            device_id,
            1000000,
            2000000, // Expires at 2000000
        ).unwrap();

        // Before expiration
        assert!(package.check_validity(&device_id, 0x01, 1500000).is_ok());

        // After expiration
        assert!(package.check_validity(&device_id, 0x01, 2500000).is_err());
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            valid: true,
            integrity_ok: true,
            custody_ok: true,
            roles_satisfied: true,
        };

        assert!(result.valid);
        assert!(result.integrity_ok);
    }

    #[test]
    fn test_authorized_signer() {
        let mut signer = AuthorizedSigner::new(
            [0x42; 32],
            [0u8; q_common::constants::DILITHIUM3_PUBLIC_KEY_SIZE],
        );

        assert!(signer.add_role(CustodyRole::BuildEngineer).is_ok());
        assert!(signer.add_role(CustodyRole::SecurityReviewer).is_ok());

        assert_eq!(signer.allowed_roles.len(), 2);
    }

    #[test]
    fn test_is_critical() {
        let mut manifest = create_test_manifest();
        let image = [0xFFu8; 64];

        // Not critical
        let package = AirgapPackage::new(manifest.clone(), &image, 0x01, 1000000).unwrap();
        assert!(!package.is_critical());

        // Critical via manifest flag
        manifest.flags |= ManifestFlags::CRITICAL;
        let package = AirgapPackage::new(manifest, &image, 0x01, 1000000).unwrap();
        assert!(package.is_critical());
    }

    #[test]
    fn test_package_parser() {
        let header = AirgapPackageHeader::new(0x01, 1000000, 0, [0; 32], [0xAB; 32]);
        let bytes = header.to_bytes();

        let parsed = AirgapPackageParser::parse_header(&bytes).unwrap();
        assert_eq!(parsed.package_hash, [0xAB; 32]);
    }
}
