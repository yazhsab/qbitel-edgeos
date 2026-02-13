// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Identity storage
//!
//! Provides secure storage for identity commitments and secrets.

use crate::commitment::{IdentityCommitment, IdentitySecrets};
use q_common::Error;
use q_hal::SecureStorageInterface;

/// Storage slot assignments
pub mod slots {
    /// Identity commitment slot
    pub const COMMITMENT: u8 = 0;
    /// Encrypted secrets slot
    pub const SECRETS: u8 = 1;
    /// PUF helper data slot
    pub const HELPER_DATA: u8 = 2;
    /// Boot configuration slot
    pub const BOOT_CONFIG: u8 = 3;
}

/// Store identity commitment
pub fn store_commitment<S: SecureStorageInterface>(
    storage: &mut S,
    commitment: &IdentityCommitment,
) -> Result<(), Error> {
    let mut buffer = [0u8; IdentityCommitment::SERIALIZED_SIZE];
    let len = commitment.to_bytes(&mut buffer)
        .ok_or(Error::BufferTooSmall)?;

    storage.write(slots::COMMITMENT, &buffer[..len])
        .map_err(|_| Error::StorageWriteFailed)
}

/// Load identity commitment
///
/// Deserializes an identity commitment from secure storage.
/// The format matches the serialization in `IdentityCommitment::to_bytes()`.
pub fn load_commitment<S: SecureStorageInterface>(
    storage: &S,
) -> Result<IdentityCommitment, Error> {
    use q_common::types::{AlgorithmId, DeviceClass, DeviceId, ManufacturerId, Timestamp};
    use q_common::constants::{KYBER768_PUBLIC_KEY_SIZE, DILITHIUM3_PUBLIC_KEY_SIZE,
        DILITHIUM3_SIGNATURE_SIZE, MAX_METADATA_SIZE};

    let mut buffer = [0u8; IdentityCommitment::SERIALIZED_SIZE];
    let len = storage.read(slots::COMMITMENT, &mut buffer)
        .map_err(|_| Error::StorageReadFailed)?;

    // Minimum valid length check
    if len < 64 {
        return Err(Error::InvalidManifest);
    }

    let mut offset = 0;

    // Parse version (1 byte)
    let version = buffer[offset];
    offset += 1;

    // Parse device_id (32 bytes)
    let mut device_id_bytes = [0u8; 32];
    device_id_bytes.copy_from_slice(&buffer[offset..offset + 32]);
    let device_id = DeviceId::new(device_id_bytes);
    offset += 32;

    // Parse manufacturer_id (16 bytes)
    let mut manufacturer_id_bytes = [0u8; 16];
    manufacturer_id_bytes.copy_from_slice(&buffer[offset..offset + 16]);
    let manufacturer_id = ManufacturerId::new(manufacturer_id_bytes);
    offset += 16;

    // Parse device_class (1 byte)
    let device_class = DeviceClass::from_u8(buffer[offset]);
    offset += 1;

    // Parse created_at (8 bytes, little-endian)
    let created_at_secs = u64::from_le_bytes([
        buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3],
        buffer[offset + 4], buffer[offset + 5], buffer[offset + 6], buffer[offset + 7],
    ]);
    let created_at = Timestamp::new(created_at_secs);
    offset += 8;

    // Parse kem_algorithm (1 byte)
    let kem_algorithm = AlgorithmId::from_u8(buffer[offset]);
    offset += 1;

    // Parse sig_algorithm (1 byte)
    let sig_algorithm = AlgorithmId::from_u8(buffer[offset]);
    offset += 1;

    // Parse kem_public_key
    let mut kem_public_key = [0u8; KYBER768_PUBLIC_KEY_SIZE];
    kem_public_key.copy_from_slice(&buffer[offset..offset + KYBER768_PUBLIC_KEY_SIZE]);
    offset += KYBER768_PUBLIC_KEY_SIZE;

    // Parse signing_public_key
    let mut signing_public_key = [0u8; DILITHIUM3_PUBLIC_KEY_SIZE];
    signing_public_key.copy_from_slice(&buffer[offset..offset + DILITHIUM3_PUBLIC_KEY_SIZE]);
    offset += DILITHIUM3_PUBLIC_KEY_SIZE;

    // Parse hardware_fingerprint_hash (32 bytes)
    let mut hardware_fingerprint_hash = [0u8; 32];
    hardware_fingerprint_hash.copy_from_slice(&buffer[offset..offset + 32]);
    offset += 32;

    // Parse metadata_len (2 bytes, little-endian)
    let metadata_len = u16::from_le_bytes([buffer[offset], buffer[offset + 1]]) as usize;
    offset += 2;

    // Parse metadata
    let mut metadata = [0u8; MAX_METADATA_SIZE];
    metadata.copy_from_slice(&buffer[offset..offset + MAX_METADATA_SIZE]);
    offset += MAX_METADATA_SIZE;

    // Parse self_signature
    let mut self_signature = [0u8; DILITHIUM3_SIGNATURE_SIZE];
    self_signature.copy_from_slice(&buffer[offset..offset + DILITHIUM3_SIGNATURE_SIZE]);

    Ok(IdentityCommitment {
        version,
        device_id,
        manufacturer_id,
        device_class,
        created_at,
        kem_algorithm,
        sig_algorithm,
        kem_public_key,
        signing_public_key,
        hardware_fingerprint_hash,
        metadata,
        metadata_len,
        self_signature,
    })
}

/// Store encrypted identity secrets
///
/// Uses a random nonce for AES-256-GCM encryption. The nonce is prepended
/// to the ciphertext so it can be recovered during decryption.
///
/// Storage format: [NONCE:12][CIPHERTEXT+TAG:N]
pub fn store_secrets<S: SecureStorageInterface>(
    storage: &mut S,
    secrets: &IdentitySecrets,
    encryption_key: &[u8; 32],
    rng: &mut impl FnMut(&mut [u8]),
) -> Result<(), Error> {
    use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
    use q_crypto::traits::Aead;

    // Serialize secrets
    let mut plaintext = [0u8; 8192];
    let pt_len = serialize_secrets(secrets, &mut plaintext)?;

    // Generate random nonce (CRITICAL: never reuse with same key)
    let mut nonce_bytes = [0u8; 12];
    rng(&mut nonce_bytes);
    let nonce = AesGcmNonce::new(nonce_bytes);
    let key = Aes256Key::new(*encryption_key);

    // Encrypt
    let mut ciphertext = [0u8; 8208]; // plaintext + tag
    let ct_len = Aes256Gcm::encrypt(
        &key,
        &nonce,
        &plaintext[..pt_len],
        &[slots::SECRETS],
        &mut ciphertext,
    ).map_err(|_| Error::AeadError)?;

    // Prepend nonce to ciphertext for storage: [NONCE:12][CT+TAG:N]
    let total_len = 12 + ct_len;
    let mut output = [0u8; 12 + 8208];
    output[..12].copy_from_slice(&nonce_bytes);
    output[12..total_len].copy_from_slice(&ciphertext[..ct_len]);

    // Store nonce + encrypted secrets
    storage.write(slots::SECRETS, &output[..total_len])
        .map_err(|_| Error::StorageWriteFailed)
}

/// Load and decrypt identity secrets
///
/// Reads the nonce prepended to the ciphertext during storage.
///
/// Expected storage format: [NONCE:12][CIPHERTEXT+TAG:N]
pub fn load_secrets<S: SecureStorageInterface>(
    storage: &S,
    encryption_key: &[u8; 32],
) -> Result<IdentitySecrets, Error> {
    use q_crypto::aead::{Aes256Gcm, Aes256Key, AesGcmNonce};
    use q_crypto::traits::Aead;

    // Read nonce + encrypted secrets
    let mut raw = [0u8; 12 + 8208];
    let raw_len = storage.read(slots::SECRETS, &mut raw)
        .map_err(|_| Error::StorageReadFailed)?;

    // Minimum: 12 (nonce) + 16 (AES-GCM tag) = 28 bytes
    if raw_len < 28 {
        return Err(Error::InvalidParameter);
    }

    // Extract nonce from first 12 bytes
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&raw[..12]);
    let nonce = AesGcmNonce::new(nonce_bytes);
    let key = Aes256Key::new(*encryption_key);

    // Ciphertext follows the nonce
    let ct_len = raw_len - 12;

    // Decrypt
    let mut plaintext = [0u8; 8192];
    let pt_len = Aes256Gcm::decrypt(
        &key,
        &nonce,
        &raw[12..12 + ct_len],
        &[slots::SECRETS],
        &mut plaintext,
    ).map_err(|_| Error::AeadError)?;

    // Deserialize secrets
    deserialize_secrets(&plaintext[..pt_len])
}

/// Serialize secrets to bytes
fn serialize_secrets(secrets: &IdentitySecrets, buffer: &mut [u8]) -> Result<usize, Error> {
    let total_len = secrets.kem_secret_key.len() +
        secrets.signing_secret_key.len() +
        secrets.hardware_binding_key.len() +
        secrets.master_seed.len();

    if buffer.len() < total_len {
        return Err(Error::BufferTooSmall);
    }

    let mut offset = 0;
    buffer[offset..offset + secrets.kem_secret_key.len()].copy_from_slice(&secrets.kem_secret_key);
    offset += secrets.kem_secret_key.len();

    buffer[offset..offset + secrets.signing_secret_key.len()].copy_from_slice(&secrets.signing_secret_key);
    offset += secrets.signing_secret_key.len();

    buffer[offset..offset + 32].copy_from_slice(&secrets.hardware_binding_key);
    offset += 32;

    buffer[offset..offset + 64].copy_from_slice(&secrets.master_seed);
    offset += 64;

    Ok(offset)
}

/// Deserialize secrets from bytes
///
/// Parses identity secrets from a byte buffer.
/// Format matches `serialize_secrets`:
/// - kem_secret_key (KYBER768_SECRET_KEY_SIZE bytes)
/// - signing_secret_key (DILITHIUM3_SECRET_KEY_SIZE bytes)
/// - hardware_binding_key (32 bytes)
/// - master_seed (64 bytes)
fn deserialize_secrets(data: &[u8]) -> Result<IdentitySecrets, Error> {
    use q_common::constants::{KYBER768_SECRET_KEY_SIZE, DILITHIUM3_SECRET_KEY_SIZE};

    let expected_len = KYBER768_SECRET_KEY_SIZE + DILITHIUM3_SECRET_KEY_SIZE + 32 + 64;
    if data.len() < expected_len {
        return Err(Error::InvalidParameter);
    }

    let mut offset = 0;

    // Parse KEM secret key
    let mut kem_secret_key = [0u8; KYBER768_SECRET_KEY_SIZE];
    kem_secret_key.copy_from_slice(&data[offset..offset + KYBER768_SECRET_KEY_SIZE]);
    offset += KYBER768_SECRET_KEY_SIZE;

    // Parse signing secret key
    let mut signing_secret_key = [0u8; DILITHIUM3_SECRET_KEY_SIZE];
    signing_secret_key.copy_from_slice(&data[offset..offset + DILITHIUM3_SECRET_KEY_SIZE]);
    offset += DILITHIUM3_SECRET_KEY_SIZE;

    // Parse hardware binding key
    let mut hardware_binding_key = [0u8; 32];
    hardware_binding_key.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // Parse master seed
    let mut master_seed = [0u8; 64];
    master_seed.copy_from_slice(&data[offset..offset + 64]);

    Ok(IdentitySecrets {
        kem_secret_key,
        signing_secret_key,
        hardware_binding_key,
        master_seed,
    })
}

/// Check if identity is provisioned
pub fn is_provisioned<S: SecureStorageInterface>(storage: &S) -> Result<bool, Error> {
    storage.is_slot_written(slots::COMMITMENT)
        .map_err(|_| Error::StorageReadFailed)
}
