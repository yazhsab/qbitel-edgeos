// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Hardware binding for device identity
//!
//! Provides hardware-based identity anchoring using PUF or eFUSE.

use q_common::Error;
use q_crypto::hash::{Sha3_256, HkdfSha3_256};
use q_crypto::traits::Hash;

/// Hardware fingerprint structure
pub struct HardwareFingerprint {
    /// Stable fingerprint (32 bytes)
    fingerprint: [u8; 32],
    /// Helper data for PUF reconstruction
    helper_data: [u8; 128],
    /// Whether this was derived from PUF (true) or eFUSE (false)
    from_puf: bool,
}

impl HardwareFingerprint {
    /// Create from PUF enrollment
    pub fn from_puf(fingerprint: [u8; 32], helper_data: [u8; 128]) -> Self {
        Self {
            fingerprint,
            helper_data,
            from_puf: true,
        }
    }

    /// Create from eFUSE UID
    pub fn from_efuse_uid(uid: &[u8; 16]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Qbitel EdgeOS-EFUSE-FINGERPRINT-v1");
        hasher.update(uid);
        let hash = hasher.finalize();

        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(hash.as_ref());

        Self {
            fingerprint,
            helper_data: [0u8; 128],
            from_puf: false,
        }
    }

    /// Get the fingerprint
    #[must_use]
    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Get helper data (for PUF reconstruction)
    #[must_use]
    pub fn helper_data(&self) -> &[u8; 128] {
        &self.helper_data
    }

    /// Check if derived from PUF
    #[must_use]
    pub const fn is_from_puf(&self) -> bool {
        self.from_puf
    }

    /// Derive device ID from fingerprint and manufacturer ID
    pub fn derive_device_id(&self, manufacturer_id: &[u8; 16]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"Qbitel EdgeOS-DEVICE-ID-v1");
        hasher.update(&self.fingerprint);
        hasher.update(manufacturer_id);

        let hash = hasher.finalize();
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(hash.as_ref());
        device_id
    }

    /// Derive hardware binding key for encrypting secrets
    pub fn derive_binding_key(&self, master_seed: &[u8; 64]) -> Result<[u8; 32], Error> {
        let mut key = [0u8; 32];
        HkdfSha3_256::derive(
            &self.fingerprint,
            master_seed,
            b"Qbitel EdgeOS-HW-BINDING-v1",
            &mut key,
        ).map_err(|_| Error::KeyDerivationFailed)?;
        Ok(key)
    }
}

/// Enroll device identity using hardware binding
pub fn enroll_device<P: q_hal::PufInterface, S: q_hal::SecureStorageInterface>(
    puf: Option<&mut P>,
    storage: &S,
    _manufacturer_id: &[u8; 16],
) -> Result<HardwareFingerprint, Error> {
    // Try PUF first if available
    if let Some(puf) = puf {
        if puf.is_available() {
            let (fingerprint, helper_data) = puf.enroll()
                .map_err(|_| Error::PufError)?;
            return Ok(HardwareFingerprint::from_puf(fingerprint, helper_data));
        }
    }

    // Fall back to eFUSE UID
    let uid = storage.read_uid().map_err(|_| Error::StorageReadFailed)?;
    Ok(HardwareFingerprint::from_efuse_uid(&uid))
}

/// Reconstruct hardware fingerprint at runtime
pub fn reconstruct_fingerprint<P: q_hal::PufInterface, S: q_hal::SecureStorageInterface>(
    puf: Option<&mut P>,
    storage: &S,
    helper_data: &[u8; 128],
    from_puf: bool,
) -> Result<HardwareFingerprint, Error> {
    if from_puf {
        let puf = puf.ok_or(Error::PufError)?;
        let fingerprint = puf.reconstruct(helper_data)
            .map_err(|_| Error::PufError)?;
        Ok(HardwareFingerprint::from_puf(fingerprint, *helper_data))
    } else {
        let uid = storage.read_uid().map_err(|_| Error::StorageReadFailed)?;
        Ok(HardwareFingerprint::from_efuse_uid(&uid))
    }
}
