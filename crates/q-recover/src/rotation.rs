// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Key Rotation for Qbitel EdgeOS
//!
//! This module implements secure key rotation that allows devices to update
//! their cryptographic keys in the field without requiring physical recall.
//!
//! # Key Rotation Process
//!
//! 1. **Initiate**: Generate new key pairs (Kyber KEM + Dilithium signatures)
//! 2. **Certify**: New keys are signed by the old keys (self-certification)
//! 3. **Notify**: Send rotation notification to management server
//! 4. **Confirm**: Wait for server acknowledgment
//! 5. **Commit**: Activate new keys and increment epoch
//!
//! # Security Properties
//!
//! - Old keys are securely erased after rotation
//! - Epoch counter prevents replay attacks
//! - Self-certification ensures key continuity
//! - Rollback protection via monotonic epoch

use q_common::Error;
use q_crypto::kyber::{
    Kyber768, Kyber768PublicKey, Kyber768SecretKey,
    KYBER768_PUBLIC_KEY_SIZE, KYBER768_SECRET_KEY_SIZE,
};
use q_crypto::dilithium::{
    Dilithium3, Dilithium3PublicKey, Dilithium3SecretKey, Dilithium3Signature,
    DILITHIUM3_PUBLIC_KEY_SIZE, DILITHIUM3_SECRET_KEY_SIZE, DILITHIUM3_SIGNATURE_SIZE as SIG_SIZE,
};
use q_crypto::traits::{Kem, Signer, CryptoRng};
use q_crypto::hash::Sha3_256;
use q_crypto::traits::Hash;
use heapless::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key sizes (re-exported from q-crypto for convenience)
pub const KYBER768_SECRET_SIZE: usize = KYBER768_SECRET_KEY_SIZE;
/// ML-KEM-768 public key size in bytes
pub const KYBER768_PUBLIC_SIZE: usize = KYBER768_PUBLIC_KEY_SIZE;
/// ML-DSA-65 secret key size in bytes
pub const DILITHIUM3_SECRET_SIZE: usize = DILITHIUM3_SECRET_KEY_SIZE;
/// ML-DSA-65 public key size in bytes
pub const DILITHIUM3_PUBLIC_SIZE: usize = DILITHIUM3_PUBLIC_KEY_SIZE;
/// ML-DSA-65 signature size in bytes
pub const DILITHIUM3_SIGNATURE_SIZE: usize = SIG_SIZE;

/// Key rotation state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationState {
    /// No rotation in progress
    Idle,
    /// New keys generated, awaiting certification
    Initiated,
    /// Keys certified, awaiting server acknowledgment
    Pending,
    /// Ready to commit (server acknowledged)
    Ready,
    /// Rotation failed
    Failed,
}

/// Pending keys during rotation
#[derive(Zeroize, ZeroizeOnDrop)]
struct PendingKeyMaterial {
    /// New KEM secret key
    kem_secret: [u8; KYBER768_SECRET_SIZE],
    /// New KEM public key
    kem_public: [u8; KYBER768_PUBLIC_SIZE],
    /// New signing secret key
    signing_secret: [u8; DILITHIUM3_SECRET_SIZE],
    /// New signing public key
    signing_public: [u8; DILITHIUM3_PUBLIC_SIZE],
    /// Self-certification signature (old key signs new public keys)
    certification: [u8; DILITHIUM3_SIGNATURE_SIZE],
}

/// Key rotation certificate
///
/// This structure contains the new public keys and a signature
/// from the old keys certifying the rotation.
#[derive(Clone)]
pub struct RotationCertificate {
    /// Key epoch after rotation
    pub new_epoch: u32,
    /// New KEM public key
    pub new_kem_public: [u8; KYBER768_PUBLIC_SIZE],
    /// New signing public key
    pub new_signing_public: [u8; DILITHIUM3_PUBLIC_SIZE],
    /// Timestamp of rotation initiation
    pub timestamp: u64,
    /// Device ID
    pub device_id: [u8; 32],
    /// Certification signature (old key signing new keys)
    pub signature: [u8; DILITHIUM3_SIGNATURE_SIZE],
}

impl RotationCertificate {
    /// Serialize certificate to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8, 4096> {
        let mut bytes = Vec::new();
        let _ = bytes.extend_from_slice(&self.new_epoch.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.new_kem_public);
        let _ = bytes.extend_from_slice(&self.new_signing_public);
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.device_id);
        let _ = bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Get the bytes that are signed (everything except the signature itself)
    pub fn signed_bytes(&self) -> Vec<u8, 4096> {
        let mut bytes = Vec::new();
        let _ = bytes.extend_from_slice(&self.new_epoch.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.new_kem_public);
        let _ = bytes.extend_from_slice(&self.new_signing_public);
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        let _ = bytes.extend_from_slice(&self.device_id);
        bytes
    }

    /// Verify certificate signature using old public key
    pub fn verify(&self, old_signing_public: &[u8]) -> Result<bool, Error> {
        let pk = Dilithium3PublicKey::from_bytes(old_signing_public)
            .map_err(|_| Error::InvalidKey)?;
        let sig = Dilithium3Signature::from_bytes(&self.signature)
            .map_err(|_| Error::InvalidSignature)?;

        let signed_data = self.signed_bytes();
        Dilithium3::verify(&pk, &signed_data, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Key rotation manager
///
/// Manages the lifecycle of cryptographic key rotation including
/// generation, certification, and commitment of new keys.
pub struct KeyRotation {
    /// Current key epoch (monotonically increasing)
    pub epoch: u32,
    /// Device identifier
    device_id: [u8; 32],
    /// Current rotation state
    state: RotationState,
    /// Pending new keys (only during rotation)
    pending_keys: Option<PendingKeyMaterial>,
    /// Timestamp of last rotation
    last_rotation: u64,
    /// Minimum time between rotations (in seconds)
    min_rotation_interval: u64,
}

impl KeyRotation {
    /// Create new rotation manager
    #[must_use]
    pub const fn new() -> Self {
        Self {
            epoch: 0,
            device_id: [0u8; 32],
            state: RotationState::Idle,
            pending_keys: None,
            last_rotation: 0,
            min_rotation_interval: 3600, // 1 hour minimum between rotations
        }
    }

    /// Initialize with device ID
    pub fn init(&mut self, device_id: [u8; 32], initial_epoch: u32) {
        self.device_id = device_id;
        self.epoch = initial_epoch;
    }

    /// Get current rotation state
    #[must_use]
    pub fn state(&self) -> RotationState {
        self.state
    }

    /// Get current epoch
    #[must_use]
    pub fn current_epoch(&self) -> u32 {
        self.epoch
    }

    /// Check if rotation is allowed (rate limiting)
    fn can_rotate(&self, current_time: u64) -> bool {
        if self.state != RotationState::Idle {
            return false;
        }
        current_time >= self.last_rotation + self.min_rotation_interval
    }

    /// Initiate key rotation by generating new key pairs
    ///
    /// This generates new Kyber and Dilithium key pairs and stores them
    /// as pending. The old keys are still active until commit().
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographic random number generator
    /// * `current_signing_key` - Current signing secret key (for self-certification)
    /// * `timestamp` - Current timestamp
    ///
    /// # Returns
    ///
    /// * `Ok(RotationCertificate)` - Certificate for server notification
    /// * `Err(_)` - If rotation cannot be initiated
    pub fn initiate<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        current_signing_key: &[u8],
        timestamp: u64,
    ) -> Result<RotationCertificate, Error> {
        // Check rate limiting
        if !self.can_rotate(timestamp) {
            return Err(Error::InvalidState);
        }

        // Parse current signing key for self-certification
        let current_sk = Dilithium3SecretKey::from_bytes(current_signing_key)
            .map_err(|_| Error::InvalidKey)?;

        // Generate new KEM key pair
        let (kem_pk, kem_sk): (Kyber768PublicKey, Kyber768SecretKey) = Kyber768::keypair(rng)
            .map_err(|_| Error::CryptoError)?;

        // Generate new signing key pair
        let (sig_pk, sig_sk): (Dilithium3PublicKey, Dilithium3SecretKey) = Dilithium3::keypair(rng)
            .map_err(|_| Error::CryptoError)?;

        // Prepare pending key material
        let mut pending = PendingKeyMaterial {
            kem_secret: [0u8; KYBER768_SECRET_SIZE],
            kem_public: [0u8; KYBER768_PUBLIC_SIZE],
            signing_secret: [0u8; DILITHIUM3_SECRET_SIZE],
            signing_public: [0u8; DILITHIUM3_PUBLIC_SIZE],
            certification: [0u8; DILITHIUM3_SIGNATURE_SIZE],
        };

        // Copy key material
        pending.kem_secret.copy_from_slice(&kem_sk.to_bytes());
        pending.kem_public.copy_from_slice(&kem_pk.to_bytes());
        pending.signing_secret.copy_from_slice(&sig_sk.to_bytes());
        pending.signing_public.copy_from_slice(&sig_pk.to_bytes());

        // Create self-certification: sign the new public keys with old key
        let new_epoch = self.epoch + 1;
        let mut cert_data = Vec::<u8, 4096>::new();
        let _ = cert_data.extend_from_slice(&new_epoch.to_le_bytes());
        let _ = cert_data.extend_from_slice(&pending.kem_public);
        let _ = cert_data.extend_from_slice(&pending.signing_public);
        let _ = cert_data.extend_from_slice(&timestamp.to_le_bytes());
        let _ = cert_data.extend_from_slice(&self.device_id);

        let certification_sig = Dilithium3::sign(&current_sk, &cert_data)
            .map_err(|_| Error::CryptoError)?;
        pending.certification.copy_from_slice(certification_sig.to_bytes());

        // Create certificate
        let certificate = RotationCertificate {
            new_epoch,
            new_kem_public: pending.kem_public,
            new_signing_public: pending.signing_public,
            timestamp,
            device_id: self.device_id,
            signature: pending.certification,
        };

        // Store pending keys and update state
        self.pending_keys = Some(pending);
        self.state = RotationState::Initiated;

        Ok(certificate)
    }

    /// Mark rotation as pending server acknowledgment
    pub fn mark_pending(&mut self) -> Result<(), Error> {
        if self.state != RotationState::Initiated {
            return Err(Error::InvalidState);
        }
        self.state = RotationState::Pending;
        Ok(())
    }

    /// Mark rotation as ready to commit (after server acknowledgment)
    pub fn mark_ready(&mut self) -> Result<(), Error> {
        if self.state != RotationState::Pending {
            return Err(Error::InvalidState);
        }
        self.state = RotationState::Ready;
        Ok(())
    }

    /// Commit key rotation
    ///
    /// This activates the new keys and securely erases the pending key material.
    /// After commit, the epoch is incremented and old keys should be discarded.
    ///
    /// # Arguments
    ///
    /// * `kem_secret_out` - Buffer to receive new KEM secret key
    /// * `signing_secret_out` - Buffer to receive new signing secret key
    /// * `timestamp` - Current timestamp
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success (new keys written to output buffers)
    /// * `Err(_)` if no pending rotation or invalid state
    pub fn commit(
        &mut self,
        kem_secret_out: &mut [u8; KYBER768_SECRET_SIZE],
        signing_secret_out: &mut [u8; DILITHIUM3_SECRET_SIZE],
        timestamp: u64,
    ) -> Result<(), Error> {
        if self.state != RotationState::Ready {
            return Err(Error::InvalidState);
        }

        let pending = self.pending_keys.take()
            .ok_or(Error::InvalidState)?;

        // Copy new keys to output
        kem_secret_out.copy_from_slice(&pending.kem_secret);
        signing_secret_out.copy_from_slice(&pending.signing_secret);

        // Update epoch and state
        self.epoch += 1;
        self.last_rotation = timestamp;
        self.state = RotationState::Idle;

        // pending is dropped here, triggering zeroization

        Ok(())
    }

    /// Cancel pending rotation
    pub fn cancel(&mut self) {
        // Zeroize and drop pending keys
        self.pending_keys = None;
        self.state = RotationState::Idle;
    }

    /// Get pending public keys (for server notification)
    pub fn get_pending_public_keys(&self) -> Option<([u8; KYBER768_PUBLIC_SIZE], [u8; DILITHIUM3_PUBLIC_SIZE])> {
        self.pending_keys.as_ref().map(|p| (p.kem_public, p.signing_public))
    }

    /// Verify a rotation certificate from another device
    ///
    /// This is used by servers or other devices to verify that a key rotation
    /// was properly self-certified.
    pub fn verify_certificate(
        cert: &RotationCertificate,
        old_signing_public: &[u8],
        expected_device_id: &[u8; 32],
    ) -> Result<bool, Error> {
        // Verify device ID matches
        if &cert.device_id != expected_device_id {
            return Ok(false);
        }

        // Verify signature
        cert.verify(old_signing_public)
    }

    /// Emergency key rotation (bypasses rate limiting)
    ///
    /// Use only when key compromise is suspected.
    pub fn emergency_rotate<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        current_signing_key: &[u8],
        timestamp: u64,
    ) -> Result<RotationCertificate, Error> {
        // Cancel any pending rotation
        self.cancel();

        // Force allow rotation by temporarily setting last_rotation to 0
        let saved_last = self.last_rotation;
        self.last_rotation = 0;

        let result = self.initiate(rng, current_signing_key, timestamp);

        // If failed, restore last_rotation
        if result.is_err() {
            self.last_rotation = saved_last;
        }

        result
    }
}

impl Default for KeyRotation {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute key fingerprint (SHA3-256 of public key)
pub fn key_fingerprint(public_key: &[u8]) -> [u8; 32] {
    let output = Sha3_256::hash(public_key);
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(output.as_ref());
    fingerprint
}

/// Verify key pair consistency (public key matches secret key)
pub fn verify_keypair_kem(
    secret_key: &[u8; KYBER768_SECRET_SIZE],
    public_key: &[u8; KYBER768_PUBLIC_SIZE],
) -> bool {
    // The secret key in Kyber includes the public key
    // Check if they match (public key is at offset in secret key)
    // For Kyber768, public key is embedded at bytes 1184..2368 of secret key
    if secret_key.len() >= 2368 {
        &secret_key[1184..2368] == public_key
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRng {
        counter: u64,
    }

    impl MockRng {
        fn new() -> Self {
            Self { counter: 0 }
        }
    }

    impl CryptoRng for MockRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), q_crypto::error::CryptoError> {
            for byte in dest.iter_mut() {
                self.counter = self.counter.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (self.counter >> 33) as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn test_rotation_state_machine() {
        let mut rotation = KeyRotation::new();
        assert_eq!(rotation.state(), RotationState::Idle);

        rotation.state = RotationState::Initiated;
        assert!(rotation.mark_pending().is_ok());
        assert_eq!(rotation.state(), RotationState::Pending);

        assert!(rotation.mark_ready().is_ok());
        assert_eq!(rotation.state(), RotationState::Ready);

        rotation.cancel();
        assert_eq!(rotation.state(), RotationState::Idle);
    }

    #[test]
    fn test_rotation_epoch_increment() {
        let mut rotation = KeyRotation::new();
        rotation.init([0x42; 32], 0);
        assert_eq!(rotation.current_epoch(), 0);

        // Simulate rotation
        rotation.epoch = 1;
        assert_eq!(rotation.current_epoch(), 1);
    }

    #[test]
    fn test_key_fingerprint() {
        let key1 = [0xAA; 32];
        let key2 = [0xBB; 32];

        let fp1 = key_fingerprint(&key1);
        let fp2 = key_fingerprint(&key2);

        assert_ne!(fp1, fp2);

        // Same key should produce same fingerprint
        let fp1_again = key_fingerprint(&key1);
        assert_eq!(fp1, fp1_again);
    }

    #[test]
    fn test_certificate_serialization() {
        let cert = RotationCertificate {
            new_epoch: 5,
            new_kem_public: [0xAA; KYBER768_PUBLIC_SIZE],
            new_signing_public: [0xBB; DILITHIUM3_PUBLIC_SIZE],
            timestamp: 1234567890,
            device_id: [0xCC; 32],
            signature: [0xDD; DILITHIUM3_SIGNATURE_SIZE],
        };

        let bytes = cert.to_bytes();
        assert!(bytes.len() > 0);

        // Verify epoch is at start
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            5
        );
    }
}
