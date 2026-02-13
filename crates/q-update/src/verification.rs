// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Update signature verification
//!
//! This module provides cryptographic verification of firmware update manifests
//! and image integrity using post-quantum Dilithium-3 signatures and SHA3-256 hashes.

use crate::manifest::UpdateManifest;
use q_common::Error;

/// Serialize manifest header to bytes for signature verification
///
/// The manifest header layout (128 bytes total):
/// - [0..4]:   magic (u32, little-endian)
/// - [4]:      manifest_version (u8)
/// - [5]:      device_class (u8)
/// - [6..16]:  version (10 bytes: major(2) + minor(2) + patch(2) + build(4))
/// - [16..20]: image_size (u32, little-endian)
/// - [20..52]: image_hash (32 bytes, SHA3-256)
/// - [52..62]: min_version (10 bytes)
/// - [62..66]: rollback_index (u32, little-endian)
/// - [66]:     flags (u8)
/// - [67..128]: reserved (61 bytes, zeroed)
fn serialize_manifest_header(manifest: &UpdateManifest) -> [u8; UpdateManifest::HEADER_SIZE] {
    let mut header = [0u8; UpdateManifest::HEADER_SIZE];

    // Magic number (bytes 0-3)
    header[0..4].copy_from_slice(&manifest.magic.to_le_bytes());

    // Manifest version (byte 4)
    header[4] = manifest.manifest_version;

    // Device class (byte 5)
    header[5] = manifest.device_class;

    // Firmware version (bytes 6-15)
    header[6..16].copy_from_slice(&manifest.version.to_bytes());

    // Image size (bytes 16-19)
    header[16..20].copy_from_slice(&manifest.image_size.to_le_bytes());

    // Image hash (bytes 20-51)
    header[20..52].copy_from_slice(&manifest.image_hash);

    // Minimum version (bytes 52-61)
    header[52..62].copy_from_slice(&manifest.min_version.to_bytes());

    // Rollback index (bytes 62-65)
    header[62..66].copy_from_slice(&manifest.rollback_index.to_le_bytes());

    // Flags (byte 66)
    header[66] = manifest.flags.bits();

    // Bytes 67-127 remain zero (reserved for future use)

    header
}

/// Verify update manifest signature using Dilithium-3
///
/// This function:
/// 1. Serializes the manifest header to canonical byte representation
/// 2. Verifies the Dilithium-3 signature over the header
///
/// # Arguments
///
/// * `manifest` - The update manifest to verify
/// * `signing_key` - The public key bytes (Dilithium-3 public key)
///
/// # Returns
///
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err(_)` if verification cannot be performed (invalid key format, etc.)
pub fn verify_manifest(
    manifest: &UpdateManifest,
    signing_key: &[u8],
) -> Result<bool, Error> {
    use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
    use q_crypto::traits::Signer;

    // Parse the public key
    let pk = Dilithium3PublicKey::from_bytes(signing_key)
        .map_err(|_| Error::InvalidKey)?;

    // Serialize manifest header for verification
    let header = serialize_manifest_header(manifest);

    // Parse and verify the signature
    let sig = Dilithium3Signature::from_bytes(&manifest.signature)
        .map_err(|_| Error::InvalidSignature)?;

    Dilithium3::verify(&pk, &header, &sig)
        .map_err(|_| Error::InvalidSignature)
}

/// Verify update image hash using SHA3-256
///
/// Computes the SHA3-256 hash of the image and compares it to the expected
/// hash in constant time to prevent timing attacks.
///
/// # Arguments
///
/// * `image` - The firmware image bytes
/// * `expected_hash` - The expected SHA3-256 hash (32 bytes)
///
/// # Returns
///
/// `true` if the hash matches, `false` otherwise
pub fn verify_image_hash(image: &[u8], expected_hash: &[u8; 32]) -> bool {
    use q_crypto::hash::Sha3_256;
    use q_crypto::traits::Hash;

    let actual_hash = Sha3_256::hash(image);
    q_crypto::traits::constant_time_eq(actual_hash.as_ref(), expected_hash)
}

/// Verify complete update package
///
/// Performs full verification:
/// 1. Verifies manifest signature
/// 2. Verifies image hash matches manifest
/// 3. Checks version constraints
///
/// # Arguments
///
/// * `manifest` - The update manifest
/// * `image` - The firmware image bytes
/// * `signing_key` - The public key for signature verification
/// * `current_version` - The currently installed version (for rollback check)
///
/// # Returns
///
/// * `Ok(())` if verification succeeds
/// * `Err(_)` with specific error if verification fails
pub fn verify_update_package(
    manifest: &UpdateManifest,
    image: &[u8],
    signing_key: &[u8],
    current_version: &q_common::version::Version,
) -> Result<(), Error> {
    // Step 1: Verify manifest signature
    if !verify_manifest(manifest, signing_key)? {
        return Err(Error::InvalidSignature);
    }

    // Step 2: Verify image hash
    if !verify_image_hash(image, &manifest.image_hash) {
        return Err(Error::IntegrityCheckFailed);
    }

    // Step 3: Check image size matches
    if image.len() != manifest.image_size as usize {
        return Err(Error::InvalidParameter);
    }

    // Step 4: Check version is an upgrade (anti-rollback)
    if !manifest.version.is_greater_than(current_version) {
        return Err(Error::RollbackAttempted);
    }

    // Step 5: Check minimum version compatibility
    if !current_version.is_compatible_with(&manifest.min_version) {
        return Err(Error::InvalidState);
    }

    Ok(())
}

/// Compute manifest header hash for attestation
///
/// Returns the SHA3-256 hash of the serialized manifest header.
/// This can be used to include the manifest in attestation evidence.
pub fn compute_manifest_hash(manifest: &UpdateManifest) -> [u8; 32] {
    use q_crypto::hash::Sha3_256;
    use q_crypto::traits::Hash;

    let header = serialize_manifest_header(manifest);
    let output = Sha3_256::hash(&header);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(output.as_ref());
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ManifestFlags;
    use q_common::version::Version;

    fn create_test_manifest() -> UpdateManifest {
        UpdateManifest {
            magic: crate::manifest::MANIFEST_MAGIC,
            manifest_version: 1,
            device_class: 0x01,
            version: Version::new(2, 0, 0, 100),
            image_size: 65536,
            image_hash: [0xAA; 32],
            min_version: Version::new(1, 0, 0, 0),
            rollback_index: 5,
            flags: ManifestFlags::KERNEL,
            signature: [0u8; q_common::constants::DILITHIUM3_SIGNATURE_SIZE],
        }
    }

    #[test]
    fn test_serialize_manifest_header() {
        let manifest = create_test_manifest();
        let header = serialize_manifest_header(&manifest);

        // Verify magic
        assert_eq!(
            u32::from_le_bytes([header[0], header[1], header[2], header[3]]),
            crate::manifest::MANIFEST_MAGIC
        );

        // Verify manifest version
        assert_eq!(header[4], 1);

        // Verify device class
        assert_eq!(header[5], 0x01);

        // Verify image hash position
        assert_eq!(&header[20..52], &[0xAA; 32]);

        // Verify flags
        assert_eq!(header[66], ManifestFlags::KERNEL.bits());

        // Verify header size
        assert_eq!(header.len(), UpdateManifest::HEADER_SIZE);
    }

    #[test]
    fn test_verify_image_hash() {
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;

        let image = b"test firmware image data";
        let hash_output = Sha3_256::hash(image);
        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(hash_output.as_ref());

        assert!(verify_image_hash(image, &expected_hash));

        // Wrong hash should fail
        let wrong_hash = [0xFF; 32];
        assert!(!verify_image_hash(image, &wrong_hash));
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let manifest = create_test_manifest();
        let hash1 = compute_manifest_hash(&manifest);
        let hash2 = compute_manifest_hash(&manifest);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_manifest_hash_changes_with_version() {
        let mut manifest1 = create_test_manifest();
        let mut manifest2 = create_test_manifest();

        manifest2.version = Version::new(3, 0, 0, 0);

        let hash1 = compute_manifest_hash(&manifest1);
        let hash2 = compute_manifest_hash(&manifest2);

        assert_ne!(hash1, hash2);
    }
}
