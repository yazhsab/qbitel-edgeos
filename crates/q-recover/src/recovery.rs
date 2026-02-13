// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Key Recovery Protocol for Qbitel EdgeOS
//!
//! This module implements a secure key recovery protocol that enables
//! devices to recover their cryptographic keys through guardian-based
//! threshold secret sharing.
//!
//! # Protocol Overview
//!
//! 1. Device initiates recovery with a signed request
//! 2. Guardians verify the request and contribute their shares
//! 3. Coordinator collects threshold shares
//! 4. Secret is reconstructed and new keys are derived
//!
//! # Security Properties
//!
//! - Threshold security: k-of-n shares required
//! - Guardian authentication via Dilithium signatures
//! - Replay protection via nonces and timestamps
//! - Timeout-based expiry of recovery sessions

use heapless::Vec;
use q_common::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::threshold::{ThresholdScheme, Share, SHARE_SIZE};

/// Maximum number of guardians
pub const MAX_GUARDIANS: usize = 16;

/// Recovery session timeout in seconds
pub const RECOVERY_TIMEOUT_SECS: u64 = 3600; // 1 hour

/// Dilithium-3 signature size
pub const SIGNATURE_SIZE: usize = 3293;

/// Recovery token for initiating recovery
#[derive(Clone)]
pub struct RecoveryToken {
    /// Device ID requesting recovery
    pub device_id: [u8; 32],
    /// Recovery nonce (prevents replay)
    pub nonce: [u8; 16],
    /// Encrypted recovery data (optional metadata)
    pub encrypted_data: [u8; 256],
    /// Timestamp of request
    pub timestamp: u64,
    /// Device signature over the request
    pub signature: [u8; SIGNATURE_SIZE],
}

impl RecoveryToken {
    /// Create a new recovery token
    pub fn new(device_id: [u8; 32], nonce: [u8; 16], timestamp: u64) -> Self {
        Self {
            device_id,
            nonce,
            encrypted_data: [0u8; 256],
            timestamp,
            signature: [0u8; SIGNATURE_SIZE],
        }
    }

    /// Get the bytes to be signed
    pub fn signing_bytes(&self) -> [u8; 56] {
        let mut bytes = [0u8; 56];
        bytes[0..32].copy_from_slice(&self.device_id);
        bytes[32..48].copy_from_slice(&self.nonce);
        bytes[48..56].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Set the signature
    pub fn set_signature(&mut self, signature: [u8; SIGNATURE_SIZE]) {
        self.signature = signature;
    }

    /// Verify the token signature
    pub fn verify(&self, public_key: &[u8]) -> Result<bool, Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
        use q_crypto::traits::Signer;

        let pk = Dilithium3PublicKey::from_bytes(public_key)
            .map_err(|_| Error::InvalidKey)?;

        let sig = Dilithium3Signature::from_bytes(&self.signature)
            .map_err(|_| Error::InvalidSignature)?;

        let msg = self.signing_bytes();
        Dilithium3::verify(&pk, &msg, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Reason for recovery request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    /// Device key suspected compromised
    KeyCompromise = 0,
    /// Hardware failure requiring migration
    HardwareFailure = 1,
    /// Scheduled key rotation
    ScheduledRotation = 2,
    /// Administrative action
    Administrative = 3,
    /// Device lost/stolen (emergency recovery)
    DeviceLost = 4,
}

impl From<u8> for RecoveryReason {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::KeyCompromise,
            1 => Self::HardwareFailure,
            2 => Self::ScheduledRotation,
            3 => Self::Administrative,
            _ => Self::DeviceLost,
        }
    }
}

/// Recovery request from device
#[derive(Clone)]
pub struct RecoveryRequest {
    /// Device ID requesting recovery
    pub device_id: [u8; 32],
    /// Reason for recovery
    pub reason: RecoveryReason,
    /// Challenge nonce (prevents replay)
    pub challenge: [u8; 32],
    /// Timestamp of request
    pub timestamp: u64,
    /// Device signature over request
    pub signature: [u8; SIGNATURE_SIZE],
}

impl RecoveryRequest {
    /// Create a new recovery request
    pub fn new(
        device_id: [u8; 32],
        reason: RecoveryReason,
        challenge: [u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            device_id,
            reason,
            challenge,
            timestamp,
            signature: [0u8; SIGNATURE_SIZE],
        }
    }

    /// Get bytes to be signed
    pub fn signing_bytes(&self) -> [u8; 73] {
        let mut bytes = [0u8; 73];
        bytes[0..32].copy_from_slice(&self.device_id);
        bytes[32] = self.reason as u8;
        bytes[33..65].copy_from_slice(&self.challenge);
        bytes[65..73].copy_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Sign the request
    pub fn sign(&mut self, secret_key: &[u8]) -> Result<(), Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3SecretKey};
        use q_crypto::traits::Signer;

        let sk = Dilithium3SecretKey::from_bytes(secret_key)
            .map_err(|_| Error::InvalidKey)?;

        let msg = self.signing_bytes();
        let sig = Dilithium3::sign(&sk, &msg)
            .map_err(|_| Error::CryptoError)?;

        self.signature.copy_from_slice(sig.as_ref());
        Ok(())
    }

    /// Verify the request signature
    pub fn verify(&self, public_key: &[u8]) -> Result<bool, Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
        use q_crypto::traits::Signer;

        let pk = Dilithium3PublicKey::from_bytes(public_key)
            .map_err(|_| Error::InvalidKey)?;

        let sig = Dilithium3Signature::from_bytes(&self.signature)
            .map_err(|_| Error::InvalidSignature)?;

        let msg = self.signing_bytes();
        Dilithium3::verify(&pk, &msg, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Guardian share contribution
#[derive(Clone)]
pub struct GuardianContribution {
    /// Guardian identifier
    pub guardian_id: [u8; 32],
    /// Guardian's share for this recovery
    pub share: Share,
    /// Signature proving guardian authorization
    pub signature: [u8; SIGNATURE_SIZE],
    /// Timestamp of contribution
    pub timestamp: u64,
}

impl GuardianContribution {
    /// Create a new contribution
    pub fn new(guardian_id: [u8; 32], share: Share, timestamp: u64) -> Self {
        Self {
            guardian_id,
            share,
            signature: [0u8; SIGNATURE_SIZE],
            timestamp,
        }
    }

    /// Get bytes to be signed (excluding signature)
    pub fn signing_bytes(&self, device_id: &[u8; 32], challenge: &[u8; 32]) -> Vec<u8, 128> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(device_id).ok();
        bytes.extend_from_slice(challenge).ok();
        bytes.extend_from_slice(&self.guardian_id).ok();
        bytes.extend_from_slice(&self.share.to_bytes()).ok();
        bytes.extend_from_slice(&self.timestamp.to_le_bytes()).ok();
        bytes
    }

    /// Sign the contribution
    pub fn sign(&mut self, secret_key: &[u8], device_id: &[u8; 32], challenge: &[u8; 32]) -> Result<(), Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3SecretKey};
        use q_crypto::traits::Signer;

        let sk = Dilithium3SecretKey::from_bytes(secret_key)
            .map_err(|_| Error::InvalidKey)?;

        let msg = self.signing_bytes(device_id, challenge);
        let sig = Dilithium3::sign(&sk, &msg)
            .map_err(|_| Error::CryptoError)?;

        self.signature.copy_from_slice(sig.as_ref());
        Ok(())
    }

    /// Verify the contribution signature
    pub fn verify(&self, public_key: &[u8], device_id: &[u8; 32], challenge: &[u8; 32]) -> Result<bool, Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
        use q_crypto::traits::Signer;

        let pk = Dilithium3PublicKey::from_bytes(public_key)
            .map_err(|_| Error::InvalidKey)?;

        let sig = Dilithium3Signature::from_bytes(&self.signature)
            .map_err(|_| Error::InvalidSignature)?;

        let msg = self.signing_bytes(device_id, challenge);
        Dilithium3::verify(&pk, &msg, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

/// Recovery session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// Waiting for request
    Idle,
    /// Request received, collecting shares
    CollectingShares,
    /// Enough shares collected, ready to reconstruct
    ReadyToReconstruct,
    /// Recovery complete
    Complete,
    /// Recovery failed
    Failed,
    /// Recovery timed out
    TimedOut,
}

/// Recovery coordinator
///
/// Manages the collection of guardian shares and secret reconstruction.
pub struct RecoveryCoordinator {
    /// Device being recovered
    device_id: [u8; 32],
    /// Required threshold (k)
    threshold: u8,
    /// Total guardians (n)
    total_guardians: u8,
    /// Collected contributions
    contributions: Vec<GuardianContribution, MAX_GUARDIANS>,
    /// Recovery challenge
    challenge: [u8; 32],
    /// Current state
    state: RecoveryState,
    /// Session start time
    #[allow(dead_code)]
    start_time: u64,
    /// Session timeout
    timeout: u64,
    /// Recovery reason
    #[allow(dead_code)]
    reason: RecoveryReason,
}

impl RecoveryCoordinator {
    /// Create a new recovery coordinator
    pub fn new(
        device_id: [u8; 32],
        threshold: u8,
        total_guardians: u8,
        challenge: [u8; 32],
        reason: RecoveryReason,
        current_time: u64,
    ) -> Result<Self, Error> {
        if threshold == 0 || threshold > total_guardians {
            return Err(Error::InvalidParameter);
        }
        if total_guardians as usize > MAX_GUARDIANS {
            return Err(Error::InvalidParameter);
        }

        Ok(Self {
            device_id,
            threshold,
            total_guardians,
            contributions: Vec::new(),
            challenge,
            state: RecoveryState::CollectingShares,
            start_time: current_time,
            timeout: current_time + RECOVERY_TIMEOUT_SECS,
            reason,
        })
    }

    /// Get current state
    #[must_use]
    pub fn state(&self) -> RecoveryState {
        self.state
    }

    /// Get number of collected contributions
    #[must_use]
    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Get threshold required
    #[must_use]
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Get device ID
    #[must_use]
    pub fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }

    /// Get challenge
    #[must_use]
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// Check if session has timed out
    pub fn check_timeout(&mut self, current_time: u64) -> bool {
        if current_time > self.timeout {
            self.state = RecoveryState::TimedOut;
            true
        } else {
            false
        }
    }

    /// Add guardian contribution
    pub fn add_contribution(
        &mut self,
        contribution: GuardianContribution,
        guardian_public_key: &[u8],
        current_time: u64,
    ) -> Result<(), Error> {
        // Check state
        if self.state != RecoveryState::CollectingShares {
            return Err(Error::InvalidState);
        }

        // Check timeout
        if self.check_timeout(current_time) {
            return Err(Error::Timeout);
        }

        // Verify guardian signature
        if !contribution.verify(guardian_public_key, &self.device_id, &self.challenge)? {
            return Err(Error::InvalidSignature);
        }

        // Check for duplicate
        for existing in self.contributions.iter() {
            if existing.guardian_id == contribution.guardian_id {
                return Err(Error::InvalidParameter);
            }
            if existing.share.index == contribution.share.index {
                return Err(Error::InvalidParameter);
            }
        }

        // Add contribution
        self.contributions.push(contribution)
            .map_err(|_| Error::BufferTooSmall)?;

        // Check if we have enough shares
        if self.contributions.len() >= self.threshold as usize {
            self.state = RecoveryState::ReadyToReconstruct;
        }

        Ok(())
    }

    /// Reconstruct the secret from collected shares
    pub fn reconstruct(&mut self) -> Result<RecoveredSecret, Error> {
        if self.state != RecoveryState::ReadyToReconstruct {
            return Err(Error::InvalidState);
        }

        // Collect shares
        let mut shares = Vec::<Share, MAX_GUARDIANS>::new();
        for contribution in self.contributions.iter() {
            shares.push(contribution.share.clone())
                .map_err(|_| Error::BufferTooSmall)?;
        }

        // Reconstruct using threshold scheme
        let scheme = ThresholdScheme::new(self.threshold, self.total_guardians)?;
        let secret = scheme.reconstruct(&shares)?;

        self.state = RecoveryState::Complete;

        Ok(RecoveredSecret::new(secret, self.device_id))
    }

    /// Cancel the recovery session
    pub fn cancel(&mut self) {
        self.state = RecoveryState::Failed;
        self.contributions.clear();
    }

    /// Get remaining time until timeout
    pub fn remaining_time(&self, current_time: u64) -> u64 {
        if current_time >= self.timeout {
            0
        } else {
            self.timeout - current_time
        }
    }
}

/// Recovered secret with device binding
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveredSecret {
    /// The recovered secret data
    secret: [u8; SHARE_SIZE],
    /// Device ID this secret belongs to
    #[zeroize(skip)]
    device_id: [u8; 32],
}

impl RecoveredSecret {
    /// Create a new recovered secret
    fn new(secret: [u8; SHARE_SIZE], device_id: [u8; 32]) -> Self {
        Self { secret, device_id }
    }

    /// Get the secret bytes
    pub fn secret(&self) -> &[u8; SHARE_SIZE] {
        &self.secret
    }

    /// Get the device ID
    pub fn device_id(&self) -> &[u8; 32] {
        &self.device_id
    }

    /// Derive new encryption key from recovered secret
    pub fn derive_encryption_key(&self, context: &[u8]) -> Result<[u8; 32], Error> {
        use q_crypto::hash::HkdfSha3_256;

        let mut key = [0u8; 32];
        HkdfSha3_256::derive(&self.device_id, &self.secret, context, &mut key)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(key)
    }

    /// Derive new signing key from recovered secret
    pub fn derive_signing_key(&self) -> Result<[u8; 32], Error> {
        self.derive_encryption_key(b"q-edge signing key derivation v1")
    }

    /// Derive new identity seed from recovered secret
    pub fn derive_identity_seed(&self) -> Result<[u8; 64], Error> {
        use q_crypto::hash::HkdfSha3_256;

        let mut seed = [0u8; 64];
        HkdfSha3_256::derive(
            &self.device_id,
            &self.secret,
            b"q-edge identity seed derivation v1",
            &mut seed,
        ).map_err(|_| Error::KeyDerivationFailed)?;
        Ok(seed)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_coordinator_creation() {
        let device_id = [0x42u8; 32];
        let challenge = [0xAAu8; 32];

        let coord = RecoveryCoordinator::new(
            device_id,
            3,
            5,
            challenge,
            RecoveryReason::ScheduledRotation,
            1000,
        ).unwrap();

        assert_eq!(coord.state(), RecoveryState::CollectingShares);
        assert_eq!(coord.threshold(), 3);
        assert_eq!(coord.contribution_count(), 0);
    }

    #[test]
    fn test_invalid_threshold() {
        let device_id = [0x42u8; 32];
        let challenge = [0xAAu8; 32];

        // Threshold > total should fail
        let result = RecoveryCoordinator::new(
            device_id,
            6,
            5,
            challenge,
            RecoveryReason::KeyCompromise,
            1000,
        );
        assert!(result.is_err());

        // Zero threshold should fail
        let result = RecoveryCoordinator::new(
            device_id,
            0,
            5,
            challenge,
            RecoveryReason::KeyCompromise,
            1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_recovery_token() {
        let device_id = [0x42u8; 32];
        let nonce = [0xAAu8; 16];

        let token = RecoveryToken::new(device_id, nonce, 1234567890);

        assert_eq!(token.device_id, device_id);
        assert_eq!(token.nonce, nonce);
        assert_eq!(token.timestamp, 1234567890);
    }

    #[test]
    fn test_recovery_request() {
        let device_id = [0x42u8; 32];
        let challenge = [0xBBu8; 32];

        let request = RecoveryRequest::new(
            device_id,
            RecoveryReason::HardwareFailure,
            challenge,
            1234567890,
        );

        assert_eq!(request.device_id, device_id);
        assert_eq!(request.reason, RecoveryReason::HardwareFailure);
        assert_eq!(request.challenge, challenge);
    }

    #[test]
    fn test_timeout_check() {
        let device_id = [0x42u8; 32];
        let challenge = [0xAAu8; 32];

        let mut coord = RecoveryCoordinator::new(
            device_id,
            3,
            5,
            challenge,
            RecoveryReason::Administrative,
            1000,
        ).unwrap();

        // Should not be timed out initially
        assert!(!coord.check_timeout(1000));
        assert_eq!(coord.state(), RecoveryState::CollectingShares);

        // Should time out after timeout period
        assert!(coord.check_timeout(1000 + RECOVERY_TIMEOUT_SECS + 1));
        assert_eq!(coord.state(), RecoveryState::TimedOut);
    }

    #[test]
    fn test_recovered_secret() {
        let secret = [0x42u8; SHARE_SIZE];
        let device_id = [0xAAu8; 32];

        let recovered = RecoveredSecret::new(secret, device_id);

        assert_eq!(recovered.secret(), &secret);
        assert_eq!(recovered.device_id(), &device_id);

        // Test key derivation
        let key = recovered.derive_encryption_key(b"test context").unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_recovery_reason_conversion() {
        assert_eq!(RecoveryReason::from(0), RecoveryReason::KeyCompromise);
        assert_eq!(RecoveryReason::from(1), RecoveryReason::HardwareFailure);
        assert_eq!(RecoveryReason::from(2), RecoveryReason::ScheduledRotation);
        assert_eq!(RecoveryReason::from(3), RecoveryReason::Administrative);
        assert_eq!(RecoveryReason::from(255), RecoveryReason::DeviceLost);
    }
}
