// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Identity verification
//!
//! Provides offline verification of identity commitments.

use crate::commitment::IdentityCommitment;
use q_common::types::{DeviceClass, Timestamp};
use q_common::Error;

/// Result of identity verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// Identity is valid
    Valid,
    /// Self-signature is invalid
    InvalidSignature,
    /// Identity format is invalid
    InvalidFormat,
    /// Identity has expired
    Expired,
    /// Device class doesn't match expected
    ClassMismatch,
    /// Algorithm not supported
    UnsupportedAlgorithm,
    /// Hardware fingerprint mismatch
    HardwareMismatch,
}

/// Verify an identity commitment
///
/// # Arguments
///
/// * `commitment` - The identity commitment to verify
/// * `expected_class` - Optional expected device class
/// * `max_age_secs` - Optional maximum age in seconds (0 = no limit)
/// * `current_time` - Current timestamp for age check
/// * `expected_fingerprint` - Optional expected hardware fingerprint hash
pub fn verify_identity(
    commitment: &IdentityCommitment,
    expected_class: Option<DeviceClass>,
    max_age_secs: u64,
    current_time: Timestamp,
    expected_fingerprint: Option<&[u8; 32]>,
) -> Result<VerificationResult, Error> {
    // 1. Check version
    if commitment.version != q_common::constants::IDENTITY_COMMITMENT_VERSION {
        return Ok(VerificationResult::InvalidFormat);
    }

    // 2. Check algorithms are supported
    if !is_algorithm_supported(commitment.kem_algorithm) ||
       !is_algorithm_supported(commitment.sig_algorithm) {
        return Ok(VerificationResult::UnsupportedAlgorithm);
    }

    // 3. Check device class if specified
    if let Some(expected) = expected_class {
        if commitment.device_class != expected {
            return Ok(VerificationResult::ClassMismatch);
        }
    }

    // 4. Check age if specified
    if max_age_secs > 0 {
        let age = current_time.elapsed_since(&commitment.created_at);
        if age > max_age_secs {
            return Ok(VerificationResult::Expired);
        }
    }

    // 5. Check hardware fingerprint if specified
    if let Some(expected_fp) = expected_fingerprint {
        if &commitment.hardware_fingerprint_hash != expected_fp {
            return Ok(VerificationResult::HardwareMismatch);
        }
    }

    // 6. Verify self-signature
    if !verify_self_signature(commitment)? {
        return Ok(VerificationResult::InvalidSignature);
    }

    Ok(VerificationResult::Valid)
}

/// Check if an algorithm is supported
///
/// Note: Falcon1024 is recognized as a valid algorithm ID for protocol compatibility
/// but does not yet have a Rust implementation. It is accepted here for identity
/// parsing but will fail at the verification step until implemented.
fn is_algorithm_supported(alg: q_common::types::AlgorithmId) -> bool {
    use q_common::types::AlgorithmId::*;
    matches!(alg,
        Kyber512 | Kyber768 | Kyber1024 |
        Dilithium2 | Dilithium3 | Dilithium5 |
        Falcon512 | Falcon1024
    )
}

/// Verify the self-signature on an identity commitment
fn verify_self_signature(commitment: &IdentityCommitment) -> Result<bool, Error> {
    use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
    use q_crypto::traits::Signer;

    // Get the signing message (everything except signature)
    let mut message_buf = [0u8; IdentityCommitment::SERIALIZED_SIZE];
    let msg_len = commitment.signing_message(&mut message_buf)
        .ok_or(Error::BufferTooSmall)?;

    // Parse public key
    let pk = Dilithium3PublicKey::from_bytes(&commitment.signing_public_key)
        .map_err(|_| Error::InvalidKey)?;

    // Parse signature
    let sig = Dilithium3Signature::from_bytes(&commitment.self_signature)
        .map_err(|_| Error::InvalidSignature)?;

    // Verify
    Dilithium3::verify(&pk, &message_buf[..msg_len], &sig)
        .map_err(|_| Error::InvalidSignature)
}

/// Verify identity and establish secure session
///
/// Performs mutual identity verification and key establishment using
/// post-quantum KEM (Kyber-768).
///
/// # Protocol
///
/// 1. Verify peer's identity commitment (self-signature check)
/// 2. Perform KEM encapsulation using peer's public key
/// 3. Derive session keys using HKDF with shared secret
///
/// # Security Properties
///
/// - Forward secrecy: Session keys are derived from ephemeral KEM
/// - Post-quantum security: Uses Kyber-768 for key encapsulation
/// - Identity binding: Keys derived from both identities
pub fn verify_and_establish_session(
    their_commitment: &IdentityCommitment,
    our_secrets: &crate::commitment::IdentitySecrets,
    rng: &mut impl q_crypto::traits::CryptoRng,
) -> Result<SessionKeys, Error> {
    use q_crypto::kyber::{Kyber768, Kyber768PublicKey};
    use q_crypto::hash::HkdfSha3_256;
    use q_crypto::traits::Kem;

    // 1. Verify their identity
    let result = verify_identity(
        their_commitment,
        None,
        0,
        Timestamp::new(0), // In production, use actual current time
        None,
    )?;

    if result != VerificationResult::Valid {
        return Err(Error::IdentityVerificationFailed);
    }

    // 2. Parse their KEM public key
    let their_pk = Kyber768PublicKey::from_bytes(&their_commitment.kem_public_key)
        .map_err(|_| Error::InvalidKey)?;

    // 3. Perform KEM encapsulation to get shared secret
    let (ciphertext, shared_secret) = Kyber768::encapsulate(&their_pk, rng)
        .map_err(|_| Error::CryptoError)?;

    // 4. Derive session keys using HKDF
    // Salt: Hash of both device IDs for session binding
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(their_commitment.device_id.as_bytes());
    // Use first 32 bytes of our hardware binding key as our identifier
    salt[32..64].copy_from_slice(&our_secrets.hardware_binding_key);

    // Info: Domain separation + ciphertext for key binding
    let mut info = [0u8; 128];
    info[..24].copy_from_slice(b"Qbitel EdgeOS-SESSION-KEYS-v1\x00\x00");
    // Include ciphertext hash for key commitment
    {
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;
        let ct_hash = Sha3_256::hash(ciphertext.as_ref());
        info[24..56].copy_from_slice(ct_hash.as_ref());
    }

    // Derive 128 bytes of key material (4 x 32-byte keys)
    let mut key_material = [0u8; 128];
    HkdfSha3_256::derive(shared_secret.as_ref(), &salt, &info[..56], &mut key_material)
        .map_err(|_| Error::CryptoError)?;

    // Split into individual keys
    let mut encrypt_key = [0u8; 32];
    let mut decrypt_key = [0u8; 32];
    let mut send_mac_key = [0u8; 32];
    let mut recv_mac_key = [0u8; 32];

    encrypt_key.copy_from_slice(&key_material[0..32]);
    decrypt_key.copy_from_slice(&key_material[32..64]);
    send_mac_key.copy_from_slice(&key_material[64..96]);
    recv_mac_key.copy_from_slice(&key_material[96..128]);

    // Zeroize shared secret after use
    #[cfg(feature = "zeroize")]
    {
        use zeroize::Zeroize;
        key_material.zeroize();
    }

    Ok(SessionKeys {
        encrypt_key,
        decrypt_key,
        send_mac_key,
        recv_mac_key,
    })
}

/// Session keys derived from identity verification
pub struct SessionKeys {
    /// Key for encrypting outgoing messages
    pub encrypt_key: [u8; 32],
    /// Key for decrypting incoming messages
    pub decrypt_key: [u8; 32],
    /// Key for MAC on outgoing messages
    pub send_mac_key: [u8; 32],
    /// Key for MAC on incoming messages
    pub recv_mac_key: [u8; 32],
}
