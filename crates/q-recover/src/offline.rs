// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Offline Recovery Support for Air-Gapped Devices
//!
//! This module provides offline recovery capabilities for devices that
//! cannot communicate with the network during recovery.
//!
//! # Features
//!
//! - Pre-generated recovery packages
//! - Encrypted share storage
//! - Chain of custody tracking
//! - Expiration-based validity

use heapless::Vec;
use q_common::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::threshold::{Share, SHARE_SIZE};
use crate::recovery::SIGNATURE_SIZE;

/// Maximum shares in an offline package
pub const MAX_OFFLINE_SHARES: usize = 16;

/// Maximum custody chain entries
pub const MAX_CUSTODY_ENTRIES: usize = 8;

/// Encrypted share for offline recovery
#[derive(Clone)]
pub struct EncryptedShare {
    /// Share index
    pub index: u8,
    /// Guardian ID who holds this share
    pub guardian_id: [u8; 32],
    /// Encrypted share data (share + AES-GCM tag)
    pub ciphertext: [u8; SHARE_SIZE + 16],
    /// Nonce used for encryption
    pub nonce: [u8; 12],
}

impl EncryptedShare {
    /// Create from plaintext share
    pub fn encrypt(
        share: &Share,
        guardian_id: [u8; 32],
        encryption_key: &[u8; 32],
        nonce: [u8; 12],
    ) -> Result<Self, Error> {
        use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
        use q_crypto::traits::Aead;

        let key = Aes256Key::new(*encryption_key);
        let n = AesGcmNonce::new(nonce);

        let share_bytes = share.to_bytes();
        let mut ciphertext = [0u8; SHARE_SIZE + 16];

        Aes256Gcm::encrypt(&key, &n, &share_bytes, &guardian_id, &mut ciphertext)
            .map_err(|_| Error::AeadError)?;

        Ok(Self {
            index: share.index,
            guardian_id,
            ciphertext,
            nonce,
        })
    }

    /// Decrypt to plaintext share
    pub fn decrypt(&self, decryption_key: &[u8; 32]) -> Result<Share, Error> {
        use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
        use q_crypto::traits::Aead;

        let key = Aes256Key::new(*decryption_key);
        let nonce = AesGcmNonce::new(self.nonce);

        let mut plaintext = [0u8; SHARE_SIZE + 1];
        Aes256Gcm::decrypt(&key, &nonce, &self.ciphertext, &self.guardian_id, &mut plaintext)
            .map_err(|_| Error::AeadError)?;

        Share::from_bytes(&plaintext)
    }
}

/// Custody chain entry (tracks who handled the package)
#[derive(Clone)]
pub struct CustodyEntry {
    /// Authority ID who signed
    pub authority_id: [u8; 32],
    /// Timestamp of custody
    pub timestamp: u64,
    /// Location hash (optional, for physical tracking)
    pub location_hash: [u8; 32],
    /// Signature over previous entry + metadata
    pub signature: [u8; SIGNATURE_SIZE],
}

impl CustodyEntry {
    /// Create a new custody entry
    pub fn new(authority_id: [u8; 32], timestamp: u64) -> Self {
        Self {
            authority_id,
            timestamp,
            location_hash: [0u8; 32],
            signature: [0u8; SIGNATURE_SIZE],
        }
    }

    /// Set location hash
    pub fn with_location(mut self, location_hash: [u8; 32]) -> Self {
        self.location_hash = location_hash;
        self
    }

    /// Get signing bytes
    pub fn signing_bytes(&self, prev_hash: &[u8; 32]) -> [u8; 104] {
        let mut bytes = [0u8; 104];
        bytes[0..32].copy_from_slice(prev_hash);
        bytes[32..64].copy_from_slice(&self.authority_id);
        bytes[64..72].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes[72..104].copy_from_slice(&self.location_hash);
        bytes
    }

    /// Sign the entry
    pub fn sign(&mut self, secret_key: &[u8], prev_hash: &[u8; 32]) -> Result<(), Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3SecretKey};
        use q_crypto::traits::Signer;

        let sk = Dilithium3SecretKey::from_bytes(secret_key)
            .map_err(|_| Error::InvalidKey)?;

        let msg = self.signing_bytes(prev_hash);
        let sig = Dilithium3::sign(&sk, &msg)
            .map_err(|_| Error::CryptoError)?;

        self.signature.copy_from_slice(sig.as_ref());
        Ok(())
    }

    /// Verify the entry
    pub fn verify(&self, public_key: &[u8], prev_hash: &[u8; 32]) -> Result<bool, Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
        use q_crypto::traits::Signer;

        let pk = Dilithium3PublicKey::from_bytes(public_key)
            .map_err(|_| Error::InvalidKey)?;

        let sig = Dilithium3Signature::from_bytes(&self.signature)
            .map_err(|_| Error::InvalidSignature)?;

        let msg = self.signing_bytes(prev_hash);
        Dilithium3::verify(&pk, &msg, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Offline recovery package header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OfflinePackageHeader {
    /// Magic number "QORP"
    pub magic: [u8; 4],
    /// Package version
    pub version: u8,
    /// Threshold required
    pub threshold: u8,
    /// Total shares in package
    pub share_count: u8,
    /// Number of custody entries
    pub custody_count: u8,
    /// Device ID this package is for
    pub device_id: [u8; 32],
    /// Package creation time
    pub created_at: u64,
    /// Package expiration time
    pub expires_at: u64,
    /// Hash of the new identity commitment
    pub new_commitment_hash: [u8; 32],
}

impl OfflinePackageHeader {
    /// Magic bytes
    pub const MAGIC: [u8; 4] = *b"QORP";

    /// Create new header
    pub fn new(
        device_id: [u8; 32],
        threshold: u8,
        share_count: u8,
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            magic: Self::MAGIC,
            version: 1,
            threshold,
            share_count,
            custody_count: 0,
            device_id,
            created_at,
            expires_at,
            new_commitment_hash: [0u8; 32],
        }
    }

    /// Validate header
    pub fn validate(&self) -> Result<(), Error> {
        if self.magic != Self::MAGIC {
            return Err(Error::InvalidParameter);
        }
        if self.version != 1 {
            return Err(Error::InvalidParameter);
        }
        if self.threshold == 0 || self.threshold > self.share_count {
            return Err(Error::InvalidParameter);
        }
        Ok(())
    }
}

/// Complete offline recovery package
pub struct OfflineRecoveryPackage {
    /// Package header
    pub header: OfflinePackageHeader,
    /// Encrypted shares
    pub shares: Vec<EncryptedShare, MAX_OFFLINE_SHARES>,
    /// New identity commitment (encrypted)
    pub new_commitment: [u8; 256],
    /// Custody chain
    pub custody_chain: Vec<CustodyEntry, MAX_CUSTODY_ENTRIES>,
    /// Package signature (by recovery authority)
    pub authority_signature: [u8; SIGNATURE_SIZE],
}

impl OfflineRecoveryPackage {
    /// Create a new offline recovery package
    pub fn create(
        device_id: [u8; 32],
        plaintext_shares: &[Share],
        threshold: u8,
        encryption_key: &[u8; 32],
        new_commitment: &[u8],
        created_at: u64,
        validity_duration: u64,
    ) -> Result<Self, Error> {
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;

        if plaintext_shares.is_empty() || plaintext_shares.len() > MAX_OFFLINE_SHARES {
            return Err(Error::InvalidParameter);
        }

        let expires_at = created_at + validity_duration;

        let mut header = OfflinePackageHeader::new(
            device_id,
            threshold,
            plaintext_shares.len() as u8,
            created_at,
            expires_at,
        );

        // Hash the new commitment
        if !new_commitment.is_empty() {
            let hash = Sha3_256::hash(new_commitment);
            header.new_commitment_hash.copy_from_slice(hash.as_ref());
        }

        // Encrypt shares
        let mut encrypted_shares = Vec::new();
        for (idx, share) in plaintext_shares.iter().enumerate() {
            // Generate unique nonce per share
            let mut nonce = [0u8; 12];
            nonce[0..4].copy_from_slice(&device_id[0..4]);
            nonce[4..8].copy_from_slice(&(idx as u32).to_le_bytes());
            nonce[8..12].copy_from_slice(&created_at.to_le_bytes()[0..4]);

            let mut guardian_id = [0u8; 32];
            guardian_id[0] = share.index;

            let encrypted = EncryptedShare::encrypt(share, guardian_id, encryption_key, nonce)?;
            encrypted_shares.push(encrypted)
                .map_err(|_| Error::BufferTooSmall)?;
        }

        // Encrypt commitment with AES-256-GCM
        let mut encrypted_commitment = [0u8; 256];
        let commitment_len = new_commitment.len().min(240); // leave room for 16-byte tag
        if commitment_len > 0 {
            use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
            use q_crypto::traits::Aead;

            let key = Aes256Key::new(*encryption_key);
            // Derive a unique nonce for commitment encryption from device_id + timestamp
            let mut commitment_nonce = [0u8; 12];
            commitment_nonce[0..4].copy_from_slice(&device_id[0..4]);
            commitment_nonce[4..12].copy_from_slice(&created_at.to_le_bytes());

            let aad = b"q-edge-offline-commitment";
            let ct_len = Aes256Gcm::encrypt(
                &key,
                &AesGcmNonce::new(commitment_nonce),
                &new_commitment[..commitment_len],
                aad,
                &mut encrypted_commitment,
            ).map_err(|_| Error::AeadError)?;

            // Store actual ciphertext length in first byte of remaining space
            // (ct_len = commitment_len + 16 for tag)
            let _ = ct_len;
        }

        Ok(Self {
            header,
            shares: encrypted_shares,
            new_commitment: encrypted_commitment,
            custody_chain: Vec::new(),
            authority_signature: [0u8; SIGNATURE_SIZE],
        })
    }

    /// Sign the package with authority key
    pub fn sign(&mut self, authority_key: &[u8]) -> Result<(), Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3SecretKey};
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::{Hash, Signer};

        let sk = Dilithium3SecretKey::from_bytes(authority_key)
            .map_err(|_| Error::InvalidKey)?;

        // Hash the header + share metadata
        let mut hasher = Sha3_256::new();

        // Add header bytes
        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                &self.header as *const _ as *const u8,
                core::mem::size_of::<OfflinePackageHeader>(),
            )
        };
        hasher.update(header_bytes);

        // Add share ciphertexts
        for share in self.shares.iter() {
            hasher.update(&share.ciphertext);
        }

        let hash = hasher.finalize();
        let sig = Dilithium3::sign(&sk, hash.as_ref())
            .map_err(|_| Error::CryptoError)?;

        self.authority_signature.copy_from_slice(sig.as_ref());
        Ok(())
    }

    /// Verify package signature
    pub fn verify(&self, authority_public_key: &[u8]) -> Result<bool, Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::{Hash, Signer};

        let pk = Dilithium3PublicKey::from_bytes(authority_public_key)
            .map_err(|_| Error::InvalidKey)?;

        // Reconstruct the hash
        let mut hasher = Sha3_256::new();

        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                &self.header as *const _ as *const u8,
                core::mem::size_of::<OfflinePackageHeader>(),
            )
        };
        hasher.update(header_bytes);

        for share in self.shares.iter() {
            hasher.update(&share.ciphertext);
        }

        let hash = hasher.finalize();

        let sig = Dilithium3Signature::from_bytes(&self.authority_signature)
            .map_err(|_| Error::InvalidSignature)?;

        Dilithium3::verify(&pk, hash.as_ref(), &sig)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Check if package has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.header.expires_at
    }

    /// Add a custody entry
    pub fn add_custody_entry(&mut self, entry: CustodyEntry) -> Result<(), Error> {
        self.custody_chain.push(entry)
            .map_err(|_| Error::BufferTooSmall)?;
        self.header.custody_count = self.custody_chain.len() as u8;
        Ok(())
    }

    /// Apply offline recovery on device
    pub fn apply(
        &self,
        decryption_key: &[u8; 32],
        current_time: u64,
    ) -> Result<RecoveryResult, Error> {
        use crate::threshold::ThresholdScheme;

        // Validate header
        self.header.validate()?;

        // Check expiration
        if self.is_expired(current_time) {
            return Err(Error::IdentityExpired);
        }

        // Decrypt shares
        let mut shares = Vec::<Share, MAX_OFFLINE_SHARES>::new();
        for encrypted in self.shares.iter() {
            let share = encrypted.decrypt(decryption_key)?;
            shares.push(share).map_err(|_| Error::BufferTooSmall)?;
        }

        // Verify we have enough shares
        if shares.len() < self.header.threshold as usize {
            return Err(Error::InsufficientShares);
        }

        // Reconstruct secret
        let scheme = ThresholdScheme::new(
            self.header.threshold,
            self.header.share_count,
        )?;

        let secret = scheme.reconstruct(&shares)?;

        // Decrypt the commitment using AES-256-GCM
        let mut decrypted_commitment = [0u8; 256];
        let commitment_has_data = self.new_commitment.iter().any(|&b| b != 0);
        if commitment_has_data {
            use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
            use q_crypto::traits::Aead;

            let key = Aes256Key::new(*decryption_key);
            // Reconstruct the same nonce used during encryption
            let mut commitment_nonce = [0u8; 12];
            commitment_nonce[0..4].copy_from_slice(&self.header.device_id[0..4]);
            commitment_nonce[4..12].copy_from_slice(&self.header.created_at.to_le_bytes());

            let aad = b"q-edge-offline-commitment";
            let _pt_len = Aes256Gcm::decrypt(
                &key,
                &AesGcmNonce::new(commitment_nonce),
                &self.new_commitment,
                aad,
                &mut decrypted_commitment,
            ).map_err(|_| Error::AeadError)?;
        }

        Ok(RecoveryResult {
            device_id: self.header.device_id,
            recovered_secret: secret,
            new_commitment: decrypted_commitment,
        })
    }
}

/// Result of offline recovery
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryResult {
    /// Device ID
    #[zeroize(skip)]
    pub device_id: [u8; 32],
    /// Recovered secret
    pub recovered_secret: [u8; SHARE_SIZE],
    /// New identity commitment
    #[zeroize(skip)]
    pub new_commitment: [u8; 256],
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::ThresholdScheme;

    #[test]
    fn test_offline_package_header() {
        let device_id = [0x42u8; 32];
        let header = OfflinePackageHeader::new(device_id, 3, 5, 1000, 2000);

        assert_eq!(header.magic, OfflinePackageHeader::MAGIC);
        assert_eq!(header.version, 1);
        assert_eq!(header.threshold, 3);
        assert_eq!(header.share_count, 5);
        assert!(header.validate().is_ok());
    }

    #[test]
    fn test_invalid_header() {
        let device_id = [0x42u8; 32];

        // Threshold > share_count
        let header = OfflinePackageHeader::new(device_id, 6, 5, 1000, 2000);
        assert!(header.validate().is_err());

        // Zero threshold
        let header = OfflinePackageHeader::new(device_id, 0, 5, 1000, 2000);
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_encrypted_share_roundtrip() {
        let share = Share {
            index: 1,
            data: [0x42u8; SHARE_SIZE],
        };

        let guardian_id = [0xAAu8; 32];
        let key = [0xBBu8; 32];
        let nonce = [0xCCu8; 12];

        let encrypted = EncryptedShare::encrypt(&share, guardian_id, &key, nonce).unwrap();
        let decrypted = encrypted.decrypt(&key).unwrap();

        assert_eq!(decrypted.index, share.index);
        assert_eq!(decrypted.data, share.data);
    }

    #[test]
    fn test_custody_entry() {
        let entry = CustodyEntry::new([0x42u8; 32], 1234567890)
            .with_location([0xAAu8; 32]);

        assert_eq!(entry.authority_id, [0x42u8; 32]);
        assert_eq!(entry.timestamp, 1234567890);
        assert_eq!(entry.location_hash, [0xAAu8; 32]);
    }

    #[test]
    fn test_package_expiration() {
        let device_id = [0x42u8; 32];
        let scheme = ThresholdScheme::new(2, 3).unwrap();
        let secret = [0x42u8; SHARE_SIZE];
        let mut counter = 0u64;
        let rng = |dest: &mut [u8]| {
            for byte in dest.iter_mut() {
                counter = counter.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (counter >> 33) as u8;
            }
        };
        let shares = scheme.split(&secret, rng).unwrap();

        let share_slice: alloc::vec::Vec<Share> = shares.into_iter().collect();
        let package = OfflineRecoveryPackage::create(
            device_id,
            &share_slice,
            2,
            &[0xAAu8; 32],
            b"test commitment",
            1000,
            1000, // Valid for 1000 seconds
        ).unwrap();

        // Not expired at creation
        assert!(!package.is_expired(1000));

        // Not expired before end
        assert!(!package.is_expired(1999));

        // Expired after end
        assert!(package.is_expired(2001));
    }
}

extern crate alloc;
