// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Attestation verification
//!
//! This module provides verification of attestation evidence using
//! Dilithium-3 post-quantum signatures.

use crate::evidence::AttestationEvidence;
use q_common::Error;

/// Verification options for attestation evidence
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    /// Expected identity hash (None = accept any)
    pub expected_identity: Option<[u8; 32]>,
    /// Expected firmware hash (None = accept any)
    pub expected_firmware: Option<[u8; 32]>,
    /// Maximum allowed age of evidence in seconds (0 = no limit)
    pub max_age_secs: u64,
    /// Current timestamp for age validation
    pub current_timestamp: u64,
    /// Required PCR values (index, expected_value)
    pub required_pcrs: [(u8, Option<[u8; 32]>); 8],
    /// Require all PCRs to be non-zero
    pub require_boot_measurements: bool,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            expected_identity: None,
            expected_firmware: None,
            max_age_secs: 300, // 5 minutes default
            current_timestamp: 0,
            required_pcrs: [(0, None); 8],
            require_boot_measurements: true,
        }
    }
}

/// Result of attestation verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Evidence is valid
    Valid,
    /// Signature verification failed
    InvalidSignature,
    /// Identity hash mismatch
    IdentityMismatch,
    /// Firmware hash mismatch
    FirmwareMismatch,
    /// Evidence is too old
    Expired,
    /// PCR value mismatch
    PcrMismatch,
    /// Missing required boot measurements
    MissingMeasurements,
    /// Invalid evidence format
    InvalidFormat,
}

/// Verify attestation evidence with Dilithium-3 signature
///
/// # Arguments
/// * `evidence` - The attestation evidence to verify
/// * `public_key` - Dilithium-3 public key (1952 bytes)
/// * `options` - Verification options
///
/// # Returns
/// `Ok(VerificationStatus)` indicating the result
pub fn verify_evidence(
    evidence: &AttestationEvidence,
    public_key: &[u8],
    options: &VerificationOptions,
) -> Result<VerificationStatus, Error> {
    use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature,
                              DILITHIUM3_PUBLIC_KEY_SIZE};
    use q_crypto::traits::Signer;

    // 1. Validate public key size
    if public_key.len() != DILITHIUM3_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidKey);
    }

    // 2. Check evidence is signed
    if !evidence.is_signed() {
        return Ok(VerificationStatus::InvalidSignature);
    }

    // 3. Parse the public key
    let pk = Dilithium3PublicKey::from_bytes(public_key)
        .map_err(|_| Error::InvalidKey)?;

    // 4. Parse the signature
    let sig = Dilithium3Signature::from_bytes(&evidence.signature)
        .map_err(|_| Error::InvalidSignature)?;

    // 5. Get the signed bytes and verify signature
    let to_verify = evidence.to_signed_bytes();
    let sig_valid = Dilithium3::verify(&pk, &to_verify, &sig)
        .map_err(|_| Error::CryptoError)?;

    if !sig_valid {
        return Ok(VerificationStatus::InvalidSignature);
    }

    // 6. Check identity hash if specified
    if let Some(expected_identity) = options.expected_identity {
        if evidence.identity_hash != expected_identity {
            return Ok(VerificationStatus::IdentityMismatch);
        }
    }

    // 7. Check firmware hash if specified
    if let Some(expected_firmware) = options.expected_firmware {
        if evidence.firmware_hash != expected_firmware {
            return Ok(VerificationStatus::FirmwareMismatch);
        }
    }

    // 8. Check evidence age
    if options.max_age_secs > 0 && options.current_timestamp > 0 && evidence.timestamp > 0 {
        let age = options.current_timestamp.saturating_sub(evidence.timestamp);
        if age > options.max_age_secs {
            return Ok(VerificationStatus::Expired);
        }
    }

    // 9. Check required PCR values
    for (index, expected_value) in options.required_pcrs.iter() {
        if let Some(expected) = expected_value {
            let idx = *index as usize;
            if idx < evidence.boot_measurements.len() {
                if &evidence.boot_measurements[idx] != expected {
                    return Ok(VerificationStatus::PcrMismatch);
                }
            }
        }
    }

    // 10. Check boot measurements are present if required
    if options.require_boot_measurements {
        // At least PCR 0 (boot stages) should be non-zero
        let pcr0_zero = evidence.boot_measurements[0].iter().all(|&b| b == 0);
        if pcr0_zero {
            return Ok(VerificationStatus::MissingMeasurements);
        }
    }

    Ok(VerificationStatus::Valid)
}

/// Verify attestation evidence with identity hash (simplified API)
///
/// This is a convenience function for basic verification.
pub fn verify_evidence_simple(
    evidence: &AttestationEvidence,
    expected_identity: &[u8; 32],
    public_key: &[u8],
) -> Result<bool, Error> {
    let options = VerificationOptions {
        expected_identity: Some(*expected_identity),
        require_boot_measurements: false,
        ..Default::default()
    };

    match verify_evidence(evidence, public_key, &options)? {
        VerificationStatus::Valid => Ok(true),
        _ => Ok(false),
    }
}

/// Verify just the signature on attestation evidence
///
/// This does not validate identity, firmware, or measurements.
pub fn verify_signature_only(
    evidence: &AttestationEvidence,
    public_key: &[u8],
) -> Result<bool, Error> {
    use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature,
                              DILITHIUM3_PUBLIC_KEY_SIZE};
    use q_crypto::traits::Signer;

    if public_key.len() != DILITHIUM3_PUBLIC_KEY_SIZE {
        return Err(Error::InvalidKey);
    }

    if !evidence.is_signed() {
        return Ok(false);
    }

    let pk = Dilithium3PublicKey::from_bytes(public_key)
        .map_err(|_| Error::InvalidKey)?;

    let sig = Dilithium3Signature::from_bytes(&evidence.signature)
        .map_err(|_| Error::InvalidSignature)?;

    let to_verify = evidence.to_signed_bytes();

    Dilithium3::verify(&pk, &to_verify, &sig)
        .map_err(|_| Error::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{AttestationEvidence, SIGNATURE_SIZE};
    use q_crypto::dilithium::{Dilithium3, DILITHIUM3_PUBLIC_KEY_SIZE, DILITHIUM3_SECRET_KEY_SIZE};
    use q_crypto::traits::Signer;
    use q_crypto::rng::TestRng;

    fn create_signed_evidence() -> (AttestationEvidence, [u8; DILITHIUM3_PUBLIC_KEY_SIZE], [u8; DILITHIUM3_SECRET_KEY_SIZE]) {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();

        let identity = [0x11u8; 32];
        let firmware = [0x22u8; 32];
        let nonce = [0x33u8; 16];

        let mut evidence = AttestationEvidence::new(identity, firmware, nonce, 1000);

        // Sign the evidence
        let to_sign = evidence.to_signed_bytes();
        let signature = Dilithium3::sign(&sk, &to_sign).unwrap();

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(signature.as_ref());
        evidence.set_signature(&sig_bytes);

        (evidence, pk.to_bytes(), sk.to_bytes())
    }

    #[test]
    fn test_verify_valid_evidence() {
        let (evidence, pk, _sk) = create_signed_evidence();

        let options = VerificationOptions {
            require_boot_measurements: false,
            ..Default::default()
        };

        let result = verify_evidence(&evidence, &pk, &options).unwrap();
        assert_eq!(result, VerificationStatus::Valid);
    }

    #[test]
    fn test_verify_identity_mismatch() {
        let (evidence, pk, _sk) = create_signed_evidence();

        let options = VerificationOptions {
            expected_identity: Some([0xFFu8; 32]),
            require_boot_measurements: false,
            ..Default::default()
        };

        let result = verify_evidence(&evidence, &pk, &options).unwrap();
        assert_eq!(result, VerificationStatus::IdentityMismatch);
    }

    #[test]
    fn test_verify_wrong_key() {
        let (evidence, _pk, _sk) = create_signed_evidence();

        // Use different key
        let mut rng = TestRng::from_seed(99);
        let (wrong_pk, _) = Dilithium3::keypair(&mut rng).unwrap();

        let options = VerificationOptions {
            require_boot_measurements: false,
            ..Default::default()
        };

        let result = verify_evidence(&evidence, &wrong_pk.to_bytes(), &options).unwrap();
        assert_eq!(result, VerificationStatus::InvalidSignature);
    }

    #[test]
    fn test_verify_signature_only() {
        let (evidence, pk, _sk) = create_signed_evidence();

        let result = verify_signature_only(&evidence, &pk).unwrap();
        assert!(result);
    }
}
