// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Device Revocation List
//!
//! Manages a signed list of revoked device IDs. The list is versioned
//! and signed with Dilithium3 (ML-DSA-65) for quantum-resistant
//! integrity verification.
//!
//! # Operations
//!
//! - **Add / Remove**: Modify the revoked set (increments version)
//! - **Sign / Verify**: Dilithium3 signature over serialized list
//! - **Serialize / Deserialize**: `to_bytes()` / `from_bytes()` for storage/network
//! - **Merge**: Accept a newer signed list from a trusted issuer

use heapless::Vec;
use q_crypto::dilithium::{
    Dilithium3, Dilithium3PublicKey, Dilithium3SecretKey,
    Dilithium3Signature, DILITHIUM3_SIGNATURE_SIZE,
};
use q_crypto::traits::Signer;

/// Maximum revoked devices in list
pub const MAX_REVOKED: usize = 256;

/// Device ID size in bytes
pub const DEVICE_ID_SIZE: usize = 32;

/// Header size: version(4) + count(4) = 8 bytes
const HEADER_SIZE: usize = 8;

/// Maximum serialized size: header + IDs + signature
pub const MAX_SERIALIZED_SIZE: usize = HEADER_SIZE + MAX_REVOKED * DEVICE_ID_SIZE + DILITHIUM3_SIGNATURE_SIZE;

/// Reason for revoking a device
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RevocationReason {
    /// Cryptographic key was compromised
    KeyCompromise = 0,
    /// Physical device was lost or stolen
    DeviceLost = 1,
    /// Device violated fleet policy
    PolicyViolation = 2,
    /// Administrative revocation
    AdminRevoke = 3,
    /// Certificate or key expired
    CertificateExpired = 4,
}

/// Revocation list errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationError {
    /// List is at capacity
    ListFull,
    /// Device not found in list
    NotFound,
    /// Signature verification failed
    InvalidSignature,
    /// Serialization/deserialization error
    SerializationError,
    /// Received list has older or equal version
    StaleVersion,
    /// Cryptographic operation failed
    CryptoError,
}

/// Signed revocation list
pub struct RevocationList {
    /// List version (monotonically increasing)
    pub version: u32,
    /// Revoked device IDs
    pub revoked: Vec<[u8; DEVICE_ID_SIZE], MAX_REVOKED>,
    /// Dilithium3 signature over (version || count || device_ids)
    pub signature: [u8; DILITHIUM3_SIGNATURE_SIZE],
    /// Whether the signature is valid/present
    signed: bool,
}

impl RevocationList {
    /// Create a new empty revocation list
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 0,
            revoked: Vec::new(),
            signature: [0u8; DILITHIUM3_SIGNATURE_SIZE],
            signed: false,
        }
    }

    /// Check if a device is revoked
    pub fn is_revoked(&self, device_id: &[u8; DEVICE_ID_SIZE]) -> bool {
        self.revoked.iter().any(|id| id == device_id)
    }

    /// Add a device to the revocation list
    ///
    /// Increments version. Signature is invalidated and must be re-signed.
    pub fn add(&mut self, device_id: [u8; DEVICE_ID_SIZE]) -> Result<(), RevocationError> {
        // Don't add duplicates
        if self.is_revoked(&device_id) {
            return Ok(());
        }

        self.revoked.push(device_id).map_err(|_| RevocationError::ListFull)?;
        self.version += 1;
        self.signed = false;
        Ok(())
    }

    /// Remove a device from the revocation list
    ///
    /// Increments version. Signature is invalidated.
    pub fn remove(&mut self, device_id: &[u8; DEVICE_ID_SIZE]) -> Result<(), RevocationError> {
        let pos = self.revoked.iter().position(|id| id == device_id)
            .ok_or(RevocationError::NotFound)?;

        self.revoked.swap_remove(pos);
        self.version += 1;
        self.signed = false;
        Ok(())
    }

    /// Number of revoked devices
    #[must_use]
    pub fn count(&self) -> usize {
        self.revoked.len()
    }

    /// Check if the list is at capacity
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.revoked.len() >= MAX_REVOKED
    }

    /// Whether the list has been signed
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// Serialize the signable content: version(4) || count(4) || device_ids
    ///
    /// This is the data that gets signed/verified.
    pub fn signed_bytes(&self) -> Vec<u8, { HEADER_SIZE + MAX_REVOKED * DEVICE_ID_SIZE }> {
        let mut buf = Vec::new();

        // Version (little-endian)
        let _ = buf.extend_from_slice(&self.version.to_le_bytes());

        // Count (little-endian)
        let count = self.revoked.len() as u32;
        let _ = buf.extend_from_slice(&count.to_le_bytes());

        // Device IDs (sorted for deterministic signing)
        let mut sorted: Vec<[u8; DEVICE_ID_SIZE], MAX_REVOKED> = Vec::new();
        for id in &self.revoked {
            let _ = sorted.push(*id);
        }
        // Simple insertion sort (small N, no alloc)
        for i in 1..sorted.len() {
            let mut j = i;
            while j > 0 && sorted[j] < sorted[j - 1] {
                sorted.swap(j, j - 1);
                j -= 1;
            }
        }

        for id in &sorted {
            let _ = buf.extend_from_slice(id);
        }

        buf
    }

    /// Sign the list with a Dilithium3 secret key
    pub fn sign(&mut self, sk: &Dilithium3SecretKey) -> Result<(), RevocationError> {
        let data = self.signed_bytes();
        let sig = <Dilithium3 as Signer>::sign(sk, &data)
            .map_err(|_| RevocationError::CryptoError)?;

        self.signature.copy_from_slice(sig.as_ref());
        self.signed = true;
        Ok(())
    }

    /// Verify the list signature against a public key
    pub fn verify_signature(&self, pk: &Dilithium3PublicKey) -> Result<bool, RevocationError> {
        if !self.signed {
            return Ok(false);
        }

        let data = self.signed_bytes();
        let sig = Dilithium3Signature::from_bytes(&self.signature)
            .map_err(|_| RevocationError::CryptoError)?;

        <Dilithium3 as Signer>::verify(pk, &data, &sig)
            .map_err(|_| RevocationError::CryptoError)
    }

    /// Serialize the full list (header + IDs + signature) to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8, MAX_SERIALIZED_SIZE>, RevocationError> {
        let mut buf = Vec::new();

        // Header
        buf.extend_from_slice(&self.version.to_le_bytes())
            .map_err(|_| RevocationError::SerializationError)?;
        let count = self.revoked.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes())
            .map_err(|_| RevocationError::SerializationError)?;

        // Device IDs
        for id in &self.revoked {
            buf.extend_from_slice(id)
                .map_err(|_| RevocationError::SerializationError)?;
        }

        // Signature
        buf.extend_from_slice(&self.signature)
            .map_err(|_| RevocationError::SerializationError)?;

        Ok(buf)
    }

    /// Deserialize a revocation list from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, RevocationError> {
        if data.len() < HEADER_SIZE + DILITHIUM3_SIGNATURE_SIZE {
            return Err(RevocationError::SerializationError);
        }

        // Parse header
        let version = u32::from_le_bytes(
            data[0..4].try_into().map_err(|_| RevocationError::SerializationError)?
        );
        let count = u32::from_le_bytes(
            data[4..8].try_into().map_err(|_| RevocationError::SerializationError)?
        ) as usize;

        if count > MAX_REVOKED {
            return Err(RevocationError::SerializationError);
        }

        let expected_len = HEADER_SIZE + count * DEVICE_ID_SIZE + DILITHIUM3_SIGNATURE_SIZE;
        if data.len() != expected_len {
            return Err(RevocationError::SerializationError);
        }

        // Parse device IDs
        let mut revoked = Vec::new();
        for i in 0..count {
            let offset = HEADER_SIZE + i * DEVICE_ID_SIZE;
            let mut id = [0u8; DEVICE_ID_SIZE];
            id.copy_from_slice(&data[offset..offset + DEVICE_ID_SIZE]);
            revoked.push(id).map_err(|_| RevocationError::SerializationError)?;
        }

        // Parse signature
        let sig_offset = HEADER_SIZE + count * DEVICE_ID_SIZE;
        let mut signature = [0u8; DILITHIUM3_SIGNATURE_SIZE];
        signature.copy_from_slice(&data[sig_offset..sig_offset + DILITHIUM3_SIGNATURE_SIZE]);

        Ok(Self {
            version,
            revoked,
            signature,
            signed: true, // Assume signed if deserialized; caller should verify
        })
    }

    /// Accept a newer signed list from a trusted issuer
    ///
    /// Verifies the new list's signature, then replaces the current list
    /// only if the new version is strictly greater.
    pub fn update_from(
        &mut self,
        new_list: &RevocationList,
        issuer_pk: &Dilithium3PublicKey,
    ) -> Result<(), RevocationError> {
        // Reject older or same version
        if new_list.version <= self.version {
            return Err(RevocationError::StaleVersion);
        }

        // Verify new list signature
        let valid = new_list.verify_signature(issuer_pk)?;
        if !valid {
            return Err(RevocationError::InvalidSignature);
        }

        // Accept the new list
        self.version = new_list.version;
        self.revoked = new_list.revoked.clone();
        self.signature = new_list.signature;
        self.signed = true;

        Ok(())
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use q_crypto::rng::SimpleRng;

    fn test_device_id(n: u8) -> [u8; DEVICE_ID_SIZE] {
        let mut id = [0u8; DEVICE_ID_SIZE];
        id[0] = n;
        id
    }

    #[test]
    fn test_new_list() {
        let list = RevocationList::new();
        assert_eq!(list.version, 0);
        assert_eq!(list.count(), 0);
        assert!(!list.is_full());
        assert!(!list.is_signed());
    }

    #[test]
    fn test_add_remove() {
        let mut list = RevocationList::new();
        let id1 = test_device_id(1);
        let id2 = test_device_id(2);

        // Add
        list.add(id1).unwrap();
        assert_eq!(list.count(), 1);
        assert_eq!(list.version, 1);
        assert!(list.is_revoked(&id1));
        assert!(!list.is_revoked(&id2));

        // Add second
        list.add(id2).unwrap();
        assert_eq!(list.count(), 2);
        assert_eq!(list.version, 2);

        // Duplicate add is no-op
        list.add(id1).unwrap();
        assert_eq!(list.count(), 2);
        assert_eq!(list.version, 2); // Version not incremented for dup

        // Remove
        list.remove(&id1).unwrap();
        assert_eq!(list.count(), 1);
        assert_eq!(list.version, 3);
        assert!(!list.is_revoked(&id1));

        // Remove non-existent
        assert_eq!(list.remove(&id1), Err(RevocationError::NotFound));
    }

    #[test]
    fn test_capacity_limit() {
        let mut list = RevocationList::new();
        for i in 0..MAX_REVOKED {
            let mut id = [0u8; DEVICE_ID_SIZE];
            id[0] = (i & 0xFF) as u8;
            id[1] = ((i >> 8) & 0xFF) as u8;
            list.add(id).unwrap();
        }
        assert!(list.is_full());

        let overflow_id = [0xFF; DEVICE_ID_SIZE];
        assert_eq!(list.add(overflow_id), Err(RevocationError::ListFull));
    }

    #[test]
    fn test_sign_verify() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);

        let (pk, sk) = <Dilithium3 as Signer>::keypair(&mut rng).unwrap();

        let mut list = RevocationList::new();
        list.add(test_device_id(1)).unwrap();
        list.add(test_device_id(2)).unwrap();

        // Sign
        list.sign(&sk).unwrap();
        assert!(list.is_signed());

        // Verify with correct key
        assert!(list.verify_signature(&pk).unwrap());

        // Verify with wrong key
        let (wrong_pk, _) = <Dilithium3 as Signer>::keypair(&mut rng).unwrap();
        assert!(!list.verify_signature(&wrong_pk).unwrap());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);
        let (pk, sk) = <Dilithium3 as Signer>::keypair(&mut rng).unwrap();

        let mut list = RevocationList::new();
        list.add(test_device_id(10)).unwrap();
        list.add(test_device_id(20)).unwrap();
        list.add(test_device_id(30)).unwrap();
        list.sign(&sk).unwrap();

        // Serialize
        let bytes = list.to_bytes().unwrap();

        // Deserialize
        let restored = RevocationList::from_bytes(&bytes).unwrap();
        assert_eq!(restored.version, list.version);
        assert_eq!(restored.count(), 3);
        assert!(restored.is_revoked(&test_device_id(10)));
        assert!(restored.is_revoked(&test_device_id(20)));
        assert!(restored.is_revoked(&test_device_id(30)));
        assert!(!restored.is_revoked(&test_device_id(99)));

        // Verify signature on restored list
        assert!(restored.verify_signature(&pk).unwrap());
    }

    #[test]
    fn test_update_from() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);
        let (pk, sk) = <Dilithium3 as Signer>::keypair(&mut rng).unwrap();

        // Old list v1
        let mut old = RevocationList::new();
        old.add(test_device_id(1)).unwrap();
        old.sign(&sk).unwrap();

        // New list v2
        let mut new_list = RevocationList::new();
        new_list.add(test_device_id(1)).unwrap();
        new_list.add(test_device_id(2)).unwrap();
        new_list.sign(&sk).unwrap();

        // Update should succeed
        old.update_from(&new_list, &pk).unwrap();
        assert_eq!(old.version, new_list.version);
        assert_eq!(old.count(), 2);
    }

    #[test]
    fn test_update_rejects_stale() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);
        let (pk, sk) = <Dilithium3 as Signer>::keypair(&mut rng).unwrap();

        let mut current = RevocationList::new();
        current.add(test_device_id(1)).unwrap();
        current.add(test_device_id(2)).unwrap();
        current.sign(&sk).unwrap();

        // Older list
        let mut stale = RevocationList::new();
        stale.add(test_device_id(1)).unwrap();
        stale.sign(&sk).unwrap();

        assert_eq!(
            current.update_from(&stale, &pk),
            Err(RevocationError::StaleVersion)
        );
    }

    #[test]
    fn test_update_rejects_invalid_signature() {
        let seed = [0x42u8; 32];
        let mut rng = SimpleRng::new(seed);
        let (pk, sk) = <Dilithium3 as Signer>::keypair(&mut rng).unwrap();
        let (_, wrong_sk) = <Dilithium3 as Signer>::keypair(&mut rng).unwrap();

        let mut current = RevocationList::new();

        // Signed with wrong key
        let mut bad = RevocationList::new();
        bad.add(test_device_id(1)).unwrap();
        bad.sign(&wrong_sk).unwrap();

        assert_eq!(
            current.update_from(&bad, &pk),
            Err(RevocationError::InvalidSignature)
        );
    }

    #[test]
    fn test_from_bytes_invalid() {
        // Too short
        assert!(matches!(
            RevocationList::from_bytes(&[0; 4]),
            Err(RevocationError::SerializationError)
        ));

        // Wrong length
        assert!(matches!(
            RevocationList::from_bytes(&[0; HEADER_SIZE + DILITHIUM3_SIGNATURE_SIZE + 1]),
            Err(RevocationError::SerializationError)
        ));
    }
}
