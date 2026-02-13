// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Identity lifecycle management
//!
//! Handles the complete lifecycle of device identity from provisioning
//! through operational use.

use crate::commitment::{IdentityCommitment, IdentitySecrets, DeviceClass};
use crate::hardware_binding::HardwareFingerprint;
use q_common::types::{ManufacturerId, Timestamp};
use q_common::Error;
use q_crypto::traits::CryptoRng;

/// Identity lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityState {
    /// Device has no identity (factory fresh)
    Unprovisioned,
    /// Identity is being generated
    Provisioning,
    /// Identity is established and operational
    Operational,
    /// Identity has been revoked
    Revoked,
    /// Identity is being rotated
    Rotating,
}

/// Generate a new device identity
///
/// This is called during factory provisioning to create the device's
/// cryptographic identity.
pub fn generate_identity<R: CryptoRng>(
    rng: &mut R,
    fingerprint: &HardwareFingerprint,
    manufacturer_id: &ManufacturerId,
    device_class: DeviceClass,
    metadata: &[u8],
    timestamp: Timestamp,
) -> Result<(IdentityCommitment, IdentitySecrets), Error> {
    use q_crypto::kyber::Kyber768;
    use q_crypto::dilithium::Dilithium3;
    use q_crypto::traits::{Kem, Signer};
    use q_common::types::AlgorithmId;

    // Generate KEM keypair
    let (kem_pk, kem_sk) = Kyber768::keypair(rng)
        .map_err(|_| Error::RngFailure)?;

    // Generate signing keypair
    let (sig_pk, sig_sk) = Dilithium3::keypair(rng)
        .map_err(|_| Error::RngFailure)?;

    // Compute device ID from fingerprint
    let device_id = fingerprint.derive_device_id(manufacturer_id.as_bytes());

    // Generate master seed
    let mut master_seed = [0u8; 64];
    rng.fill_bytes(&mut master_seed)
        .map_err(|_| Error::RngFailure)?;

    // Derive hardware binding key
    let hardware_binding_key = fingerprint.derive_binding_key(&master_seed)?;

    // Compute fingerprint hash
    let mut fp_hash = [0u8; 32];
    {
        use q_crypto::hash::Sha3_256;
        use q_crypto::traits::Hash;
        let hash = Sha3_256::hash(fingerprint.fingerprint());
        fp_hash.copy_from_slice(hash.as_ref());
    }

    // Prepare metadata
    let mut metadata_buf = [0u8; q_common::constants::MAX_METADATA_SIZE];
    let metadata_len = metadata.len().min(q_common::constants::MAX_METADATA_SIZE);
    metadata_buf[..metadata_len].copy_from_slice(&metadata[..metadata_len]);

    // Create commitment (unsigned)
    let mut commitment = IdentityCommitment {
        version: q_common::constants::IDENTITY_COMMITMENT_VERSION,
        device_id: q_common::types::DeviceId::new(device_id),
        manufacturer_id: *manufacturer_id,
        device_class,
        created_at: timestamp,
        kem_algorithm: AlgorithmId::Kyber768,
        sig_algorithm: AlgorithmId::Dilithium3,
        kem_public_key: [0u8; q_common::constants::KYBER768_PUBLIC_KEY_SIZE],
        signing_public_key: [0u8; q_common::constants::DILITHIUM3_PUBLIC_KEY_SIZE],
        hardware_fingerprint_hash: fp_hash,
        metadata: metadata_buf,
        metadata_len,
        self_signature: [0u8; q_common::constants::DILITHIUM3_SIGNATURE_SIZE],
    };

    // Copy public keys
    commitment.kem_public_key.copy_from_slice(kem_pk.as_ref());
    commitment.signing_public_key.copy_from_slice(sig_pk.as_ref());

    // Sign the commitment
    let mut msg_buf = [0u8; IdentityCommitment::SERIALIZED_SIZE];
    let msg_len = commitment.signing_message(&mut msg_buf)
        .ok_or(Error::BufferTooSmall)?;

    let signature = Dilithium3::sign(&sig_sk, &msg_buf[..msg_len])
        .map_err(|_| Error::InvalidSignature)?;
    commitment.self_signature.copy_from_slice(signature.as_ref());

    // Create secrets
    let mut secrets = IdentitySecrets::empty();
    secrets.kem_secret_key[..kem_sk.as_ref().len()].copy_from_slice(kem_sk.as_ref());
    secrets.signing_secret_key[..sig_sk.as_ref().len()].copy_from_slice(sig_sk.as_ref());
    secrets.hardware_binding_key = hardware_binding_key;
    secrets.master_seed = master_seed;

    Ok((commitment, secrets))
}

/// Provision identity to device storage
pub fn provision_identity<S: q_hal::SecureStorageInterface>(
    storage: &mut S,
    commitment: &IdentityCommitment,
    secrets: &IdentitySecrets,
    encryption_key: &[u8; 32],
) -> Result<(), Error> {
    // Check if already provisioned
    if crate::storage::is_provisioned(storage)? {
        return Err(Error::IdentityAlreadyExists);
    }

    // Store commitment (unencrypted - public data)
    crate::storage::store_commitment(storage, commitment)?;

    // Store secrets (encrypted)
    crate::storage::store_secrets(storage, secrets, encryption_key)?;

    Ok(())
}

/// Load identity from device storage
pub fn load_identity<S: q_hal::SecureStorageInterface>(
    storage: &S,
    encryption_key: &[u8; 32],
) -> Result<(IdentityCommitment, IdentitySecrets), Error> {
    let commitment = crate::storage::load_commitment(storage)?;
    let secrets = crate::storage::load_secrets(storage, encryption_key)?;
    Ok((commitment, secrets))
}
