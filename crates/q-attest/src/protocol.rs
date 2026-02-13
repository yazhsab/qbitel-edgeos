// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Remote Attestation Protocol
//!
//! This module implements the remote attestation protocol for Qbitel EdgeOS.
//! It enables a verifier to remotely verify the integrity and identity
//! of a device using post-quantum cryptography.
//!
//! # Protocol Overview
//!
//! ```text
//! Verifier                                    Prover (Device)
//!    |                                              |
//!    |------------ AttestationRequest ------------>|
//!    |            (nonce, scope, policy)           |
//!    |                                              |
//!    |                                   Collect measurements
//!    |                                   Generate evidence
//!    |                                   Sign with attestation key
//!    |                                              |
//!    |<----------- AttestationResponse ------------|
//!    |            (evidence, signature)            |
//!    |                                              |
//!    | Verify signature                            |
//!    | Check measurements                          |
//!    | Evaluate policy                             |
//!    |                                              |
//!    |------------ AttestationResult ------------->|
//!    |            (accepted/rejected)              |
//!    |                                              |
//! ```

use q_common::Error;
use heapless::Vec;

use crate::evidence::{AttestationEvidence, EvidenceCollector, BootStage, SIGNATURE_SIZE};

/// Maximum size of attestation request
pub const MAX_REQUEST_SIZE: usize = 256;

/// Maximum size of attestation response
pub const MAX_RESPONSE_SIZE: usize = 4096;

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

// ============================================================================
// Attestation Scope
// ============================================================================

/// Scope of attestation (what to include in evidence)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttestationScope {
    /// Basic: identity + firmware hash only
    Basic = 0x01,
    /// Standard: include boot measurements
    Standard = 0x02,
    /// Full: include all PCRs and claims
    Full = 0x03,
    /// Custom: specific PCR selection
    Custom = 0xFF,
}

impl Default for AttestationScope {
    fn default() -> Self {
        Self::Standard
    }
}

impl TryFrom<u8> for AttestationScope {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Basic),
            0x02 => Ok(Self::Standard),
            0x03 => Ok(Self::Full),
            0xFF => Ok(Self::Custom),
            _ => Err(Error::InvalidParameter),
        }
    }
}

// ============================================================================
// Attestation Request
// ============================================================================

/// Attestation request from verifier
#[derive(Debug, Clone)]
pub struct AttestationRequest {
    /// Protocol version
    pub version: u8,
    /// Request type
    pub request_type: RequestType,
    /// Challenge nonce (16 bytes)
    pub nonce: [u8; 16],
    /// Attestation scope
    pub scope: AttestationScope,
    /// PCR selection mask (for custom scope)
    pub pcr_mask: u8,
    /// Expected firmware hash (optional, for verification)
    pub expected_firmware_hash: Option<[u8; 32]>,
    /// Request timestamp
    pub timestamp: u64,
}

/// Request type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestType {
    /// Standard attestation
    Attest = 0x01,
    /// Get device info only (no signature)
    GetInfo = 0x02,
    /// Attestation with PCR quote
    Quote = 0x03,
    /// Mutual attestation
    Mutual = 0x04,
}

impl Default for RequestType {
    fn default() -> Self {
        Self::Attest
    }
}

impl AttestationRequest {
    /// Create a new attestation request
    pub fn new(nonce: [u8; 16]) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_type: RequestType::Attest,
            nonce,
            scope: AttestationScope::Standard,
            pcr_mask: 0xFF,
            expected_firmware_hash: None,
            timestamp: 0,
        }
    }

    /// Set scope
    pub fn with_scope(mut self, scope: AttestationScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set PCR mask (for custom scope)
    pub fn with_pcr_mask(mut self, mask: u8) -> Self {
        self.pcr_mask = mask;
        self
    }

    /// Set expected firmware hash
    pub fn with_expected_hash(mut self, hash: [u8; 32]) -> Self {
        self.expected_firmware_hash = Some(hash);
        self
    }

    /// Parse request from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 20 {
            return Err(Error::BufferTooSmall);
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(Error::InvalidState);
        }

        let request_type = match data[1] {
            0x01 => RequestType::Attest,
            0x02 => RequestType::GetInfo,
            0x03 => RequestType::Quote,
            0x04 => RequestType::Mutual,
            _ => return Err(Error::InvalidParameter),
        };

        let scope = AttestationScope::try_from(data[2])?;
        let pcr_mask = data[3];

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[4..20]);

        let timestamp = if data.len() >= 28 {
            u64::from_le_bytes([
                data[20], data[21], data[22], data[23],
                data[24], data[25], data[26], data[27],
            ])
        } else {
            0
        };

        let expected_firmware_hash = if data.len() >= 60 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[28..60]);
            if hash != [0u8; 32] {
                Some(hash)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            version,
            request_type,
            nonce,
            scope,
            pcr_mask,
            expected_firmware_hash,
            timestamp,
        })
    }

    /// Serialize request to bytes
    pub fn to_bytes(&self) -> Vec<u8, MAX_REQUEST_SIZE> {
        let mut bytes = Vec::new();

        let _ = bytes.push(self.version);
        let _ = bytes.push(self.request_type as u8);
        let _ = bytes.push(self.scope as u8);
        let _ = bytes.push(self.pcr_mask);
        let _ = bytes.extend_from_slice(&self.nonce);
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        if let Some(hash) = self.expected_firmware_hash {
            let _ = bytes.extend_from_slice(&hash);
        }

        bytes
    }
}

// ============================================================================
// Attestation Response
// ============================================================================

/// Response status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    /// Success
    Ok = 0x00,
    /// Request denied
    Denied = 0x01,
    /// Invalid request
    InvalidRequest = 0x02,
    /// Internal error
    InternalError = 0x03,
    /// Busy
    Busy = 0x04,
    /// Unsupported scope
    UnsupportedScope = 0x05,
}

/// Attestation response from prover
#[derive(Debug)]
pub struct AttestationResponse {
    /// Protocol version
    pub version: u8,
    /// Response status
    pub status: ResponseStatus,
    /// Echo of request nonce
    pub nonce: [u8; 16],
    /// Attestation evidence
    pub evidence: AttestationEvidence,
}

impl AttestationResponse {
    /// Create a new response
    pub fn new(nonce: [u8; 16], evidence: AttestationEvidence) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status: ResponseStatus::Ok,
            nonce,
            evidence,
        }
    }

    /// Create an error response
    pub fn error(nonce: [u8; 16], status: ResponseStatus) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            status,
            nonce,
            evidence: AttestationEvidence::new([0u8; 32], [0u8; 32], nonce, 0),
        }
    }

    /// Serialize response to bytes
    pub fn to_bytes(&self) -> Vec<u8, MAX_RESPONSE_SIZE> {
        let mut bytes = Vec::new();

        let _ = bytes.push(self.version);
        let _ = bytes.push(self.status as u8);
        let _ = bytes.extend_from_slice(&self.nonce);

        // Add serialized evidence
        let evidence_bytes = self.evidence.serialize();
        let _ = bytes.extend_from_slice(&evidence_bytes);

        bytes
    }
}

// ============================================================================
// Attestation Result
// ============================================================================

/// Verification result from verifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// Attestation accepted
    Accepted,
    /// Signature invalid
    InvalidSignature,
    /// Nonce mismatch
    NonceMismatch,
    /// Firmware hash mismatch
    FirmwareMismatch,
    /// Policy violation
    PolicyViolation,
    /// Expired timestamp
    Expired,
    /// Revoked identity
    Revoked,
}

/// Attestation result message
#[derive(Debug, Clone)]
pub struct AttestationResult {
    /// Result code
    pub result: VerificationResult,
    /// Session token (if accepted)
    pub session_token: Option<[u8; 32]>,
    /// Validity period in seconds (if accepted)
    pub validity_seconds: u32,
    /// Additional info
    pub info: Vec<u8, 64>,
}

impl AttestationResult {
    /// Create accepted result
    pub fn accepted(session_token: [u8; 32], validity_seconds: u32) -> Self {
        Self {
            result: VerificationResult::Accepted,
            session_token: Some(session_token),
            validity_seconds,
            info: Vec::new(),
        }
    }

    /// Create rejected result
    pub fn rejected(reason: VerificationResult) -> Self {
        Self {
            result: reason,
            session_token: None,
            validity_seconds: 0,
            info: Vec::new(),
        }
    }

    /// Add info to result
    pub fn with_info(mut self, info: &[u8]) -> Self {
        let _ = self.info.extend_from_slice(info);
        self
    }
}

// ============================================================================
// Attestation Handler (Prover Side)
// ============================================================================

/// Attestation handler for prover (device)
pub struct AttestationHandler {
    /// Evidence collector
    collector: EvidenceCollector,
    /// Attestation signing secret key (Dilithium-3)
    signing_key: Option<[u8; q_crypto::dilithium::DILITHIUM3_SECRET_KEY_SIZE]>,
    /// Handler initialized
    initialized: bool,
    /// Attestation counter
    attestation_count: u32,
}

impl AttestationHandler {
    /// Create a new attestation handler
    pub const fn new() -> Self {
        Self {
            collector: EvidenceCollector::new(),
            signing_key: None,
            initialized: false,
            attestation_count: 0,
        }
    }

    /// Initialize handler with device identity
    ///
    /// # Arguments
    /// * `identity_hash` - 32-byte hash of device identity commitment
    /// * `firmware_hash` - 32-byte hash of running firmware
    /// * `signing_key` - Dilithium-3 secret key (4000 bytes)
    pub fn init(
        &mut self,
        identity_hash: [u8; 32],
        firmware_hash: [u8; 32],
        signing_key: [u8; q_crypto::dilithium::DILITHIUM3_SECRET_KEY_SIZE],
    ) {
        self.collector.init(identity_hash, firmware_hash);
        self.signing_key = Some(signing_key);
        self.initialized = true;
    }

    /// Record boot measurement
    pub fn measure_boot(&mut self, stage: BootStage) -> Result<(), Error> {
        self.collector.measure_boot_stage(stage)
    }

    /// Record firmware measurement
    pub fn measure_firmware(&mut self, id: u8, hash: &[u8; 32]) -> Result<(), Error> {
        self.collector.measure_firmware(id, hash)
    }

    /// Record configuration measurement
    pub fn measure_config(&mut self, id: u8, hash: &[u8; 32]) -> Result<(), Error> {
        self.collector.measure_config(id, hash)
    }

    /// Handle attestation request
    pub fn handle_request(
        &mut self,
        request: &AttestationRequest,
        timestamp: u64,
    ) -> Result<AttestationResponse, Error> {
        if !self.initialized {
            return Ok(AttestationResponse::error(
                request.nonce,
                ResponseStatus::InternalError,
            ));
        }

        // Generate evidence
        let mut evidence = self.collector.generate_evidence(request.nonce, timestamp);

        // Add standard claims based on scope
        match request.scope {
            AttestationScope::Full => {
                // Add all claims
                evidence.add_firmware_version(0, 1, 0)?;
                evidence.add_secure_boot_status(true, true)?;
                evidence.add_debug_status(false)?;
                evidence.add_rollback_counter(self.attestation_count)?;
            }
            AttestationScope::Standard => {
                // Add basic claims
                evidence.add_firmware_version(0, 1, 0)?;
                evidence.add_secure_boot_status(true, true)?;
            }
            AttestationScope::Basic => {
                // No additional claims
            }
            AttestationScope::Custom => {
                // Claims based on PCR mask
                evidence.add_firmware_version(0, 1, 0)?;
            }
        }

        // Sign evidence
        self.sign_evidence(&mut evidence)?;

        self.attestation_count = self.attestation_count.saturating_add(1);

        Ok(AttestationResponse::new(request.nonce, evidence))
    }

    /// Sign evidence with attestation key using Dilithium-3
    ///
    /// Uses ML-DSA-65 (Dilithium-3) for post-quantum secure signatures.
    fn sign_evidence(&self, evidence: &mut AttestationEvidence) -> Result<(), Error> {
        use q_crypto::dilithium::{Dilithium3, Dilithium3SecretKey};
        use q_crypto::traits::Signer;

        let signing_key_bytes = self.signing_key.ok_or(Error::InvalidState)?;

        // Parse the secret key from bytes
        let sk = Dilithium3SecretKey::from_bytes(&signing_key_bytes)
            .map_err(|_| Error::InvalidKey)?;

        // Get bytes to sign
        let to_sign = evidence.to_signed_bytes();

        // Sign using Dilithium-3
        let signature = Dilithium3::sign(&sk, &to_sign)
            .map_err(|_| Error::CryptoError)?;

        // Copy signature bytes to evidence
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(signature.as_ref());
        evidence.set_signature(&sig_bytes);

        Ok(())
    }
}

impl Default for AttestationHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Attestation Verifier
// ============================================================================

/// Verification policy
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Require specific firmware hash
    pub required_firmware_hash: Option<[u8; 32]>,
    /// Require secure boot
    pub require_secure_boot: bool,
    /// Reject if debug enabled
    pub reject_debug: bool,
    /// Maximum allowed timestamp age (seconds)
    pub max_timestamp_age: u32,
    /// Minimum rollback counter
    pub min_rollback_counter: u32,
    /// Required PCR values (index, value)
    pub required_pcrs: Vec<(u8, [u8; 32]), 8>,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            required_firmware_hash: None,
            require_secure_boot: true,
            reject_debug: true,
            max_timestamp_age: 300, // 5 minutes
            min_rollback_counter: 0,
            required_pcrs: Vec::new(),
        }
    }
}

/// Attestation verifier
pub struct AttestationVerifier {
    /// Verification policy
    policy: VerificationPolicy,
    /// Trusted identity hashes
    trusted_identities: Vec<[u8; 32], 16>,
    /// Trusted public keys (identity hash -> public key bytes)
    trusted_public_keys: Vec<([u8; 32], [u8; q_crypto::dilithium::DILITHIUM3_PUBLIC_KEY_SIZE]), 16>,
    /// Current timestamp (for validation)
    current_time: u64,
}

impl AttestationVerifier {
    /// Create a new verifier with default policy
    pub fn new() -> Self {
        Self {
            policy: VerificationPolicy::default(),
            trusted_identities: Vec::new(),
            trusted_public_keys: Vec::new(),
            current_time: 0,
        }
    }

    /// Set verification policy
    pub fn set_policy(&mut self, policy: VerificationPolicy) {
        self.policy = policy;
    }

    /// Add trusted identity
    pub fn add_trusted_identity(&mut self, identity_hash: [u8; 32]) -> Result<(), Error> {
        self.trusted_identities
            .push(identity_hash)
            .map_err(|_| Error::BufferTooSmall)
    }

    /// Add trusted identity with public key for signature verification
    ///
    /// # Arguments
    /// * `identity_hash` - 32-byte hash of device identity
    /// * `public_key` - Dilithium-3 public key (1952 bytes)
    pub fn add_trusted_identity_with_key(
        &mut self,
        identity_hash: [u8; 32],
        public_key: [u8; q_crypto::dilithium::DILITHIUM3_PUBLIC_KEY_SIZE],
    ) -> Result<(), Error> {
        self.trusted_identities
            .push(identity_hash)
            .map_err(|_| Error::BufferTooSmall)?;
        self.trusted_public_keys
            .push((identity_hash, public_key))
            .map_err(|_| Error::BufferTooSmall)
    }

    /// Get public key for an identity hash
    fn get_public_key(&self, identity_hash: &[u8; 32]) -> Option<&[u8; q_crypto::dilithium::DILITHIUM3_PUBLIC_KEY_SIZE]> {
        self.trusted_public_keys
            .iter()
            .find(|(hash, _)| hash == identity_hash)
            .map(|(_, pk)| pk)
    }

    /// Set current time for timestamp validation
    pub fn set_current_time(&mut self, time: u64) {
        self.current_time = time;
    }

    /// Generate a new attestation request
    pub fn create_request(&self, nonce: [u8; 16], scope: AttestationScope) -> AttestationRequest {
        let mut request = AttestationRequest::new(nonce).with_scope(scope);

        if let Some(hash) = self.policy.required_firmware_hash {
            request = request.with_expected_hash(hash);
        }

        request.timestamp = self.current_time;
        request
    }

    /// Verify attestation response
    pub fn verify(&self, request: &AttestationRequest, response: &AttestationResponse) -> AttestationResult {
        // Check response status
        if response.status != ResponseStatus::Ok {
            return AttestationResult::rejected(VerificationResult::PolicyViolation);
        }

        // Verify nonce matches
        if response.nonce != request.nonce {
            return AttestationResult::rejected(VerificationResult::NonceMismatch);
        }

        // Verify evidence is signed
        if !response.evidence.is_signed() {
            return AttestationResult::rejected(VerificationResult::InvalidSignature);
        }

        // Verify signature (would use Dilithium-3 verification)
        if !self.verify_signature(&response.evidence) {
            return AttestationResult::rejected(VerificationResult::InvalidSignature);
        }

        // Check identity is trusted
        let identity_trusted = self.trusted_identities.is_empty()
            || self.trusted_identities.contains(&response.evidence.identity_hash);

        if !identity_trusted {
            return AttestationResult::rejected(VerificationResult::Revoked);
        }

        // Check firmware hash if required
        if let Some(required_hash) = self.policy.required_firmware_hash {
            if response.evidence.firmware_hash != required_hash {
                return AttestationResult::rejected(VerificationResult::FirmwareMismatch);
            }
        }

        // Check timestamp
        if self.current_time > 0 && response.evidence.timestamp > 0 {
            let age = self.current_time.saturating_sub(response.evidence.timestamp);
            if age > self.policy.max_timestamp_age as u64 {
                return AttestationResult::rejected(VerificationResult::Expired);
            }
        }

        // All checks passed
        // Generate session token
        let mut session_token = [0u8; 32];
        for (i, byte) in response.nonce.iter().enumerate() {
            session_token[i] = *byte;
            session_token[16 + i] = response.evidence.identity_hash[i];
        }

        AttestationResult::accepted(session_token, 3600) // 1 hour validity
    }

    /// Verify evidence signature using Dilithium-3
    ///
    /// Verifies the signature over the evidence using the device's
    /// registered public attestation key (ML-DSA-65).
    ///
    /// Returns `false` if no public key is registered for the identity.
    /// Signature verification MUST always be cryptographic — a missing key
    /// is a verification failure, never a pass.
    fn verify_signature(&self, evidence: &AttestationEvidence) -> bool {
        use q_crypto::dilithium::{Dilithium3, Dilithium3PublicKey, Dilithium3Signature};
        use q_crypto::traits::Signer;

        // Get the public key for this identity
        let pk_bytes = match self.get_public_key(&evidence.identity_hash) {
            Some(pk) => pk,
            None => {
                // No public key registered — REJECT.
                // Accepting unverifiable signatures would allow any device
                // to forge attestation evidence.
                return false;
            }
        };

        // Parse the public key
        let pk = match Dilithium3PublicKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Parse the signature
        let sig = match Dilithium3Signature::from_bytes(&evidence.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        // Get the signed bytes
        let to_verify = evidence.to_signed_bytes();

        // Verify using Dilithium-3
        match Dilithium3::verify(&pk, &to_verify, &sig) {
            Ok(valid) => valid,
            Err(_) => false,
        }
    }
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use q_crypto::dilithium::{Dilithium3, DILITHIUM3_SECRET_KEY_SIZE, DILITHIUM3_PUBLIC_KEY_SIZE};
    use q_crypto::traits::Signer;
    use q_crypto::rng::TestRng;

    /// Generate a test keypair for attestation
    fn generate_test_keypair() -> ([u8; DILITHIUM3_SECRET_KEY_SIZE], [u8; DILITHIUM3_PUBLIC_KEY_SIZE]) {
        let mut rng = TestRng::from_seed(42);
        let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();
        (sk.to_bytes(), pk.to_bytes())
    }

    #[test]
    fn test_request_serialization() {
        let nonce = [0x42u8; 16];
        let request = AttestationRequest::new(nonce)
            .with_scope(AttestationScope::Full);

        let bytes = request.to_bytes();
        let parsed = AttestationRequest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.nonce, nonce);
        assert_eq!(parsed.scope, AttestationScope::Full);
    }

    #[test]
    fn test_handler_initialization() {
        let (sk, _pk) = generate_test_keypair();
        let mut handler = AttestationHandler::new();
        handler.init([0x11u8; 32], [0x22u8; 32], sk);

        assert!(handler.measure_boot(BootStage::Bootloader).is_ok());
        assert!(handler.measure_firmware(0, &[0xAAu8; 32]).is_ok());
    }

    #[test]
    fn test_attestation_flow_with_dilithium() {
        // Generate keypair
        let (sk, pk) = generate_test_keypair();
        let identity_hash = [0x11u8; 32];

        // Setup handler (prover)
        let mut handler = AttestationHandler::new();
        handler.init(identity_hash, [0x22u8; 32], sk);
        handler.measure_boot(BootStage::Bootloader).unwrap();

        // Setup verifier with public key
        let mut verifier = AttestationVerifier::new();
        verifier.add_trusted_identity_with_key(identity_hash, pk).unwrap();

        // Create request
        let nonce = [0x42u8; 16];
        let request = verifier.create_request(nonce, AttestationScope::Standard);

        // Handle request
        let response = handler.handle_request(&request, 12345).unwrap();
        assert_eq!(response.status, ResponseStatus::Ok);
        assert_eq!(response.nonce, nonce);
        assert!(response.evidence.is_signed());

        // Verify response with real Dilithium-3 verification
        let result = verifier.verify(&request, &response);
        assert_eq!(result.result, VerificationResult::Accepted);
        assert!(result.session_token.is_some());
    }

    #[test]
    fn test_nonce_mismatch() {
        let (sk, _pk) = generate_test_keypair();
        let mut handler = AttestationHandler::new();
        handler.init([0x11u8; 32], [0x22u8; 32], sk);

        let verifier = AttestationVerifier::new();

        let request = AttestationRequest::new([0x42u8; 16]);
        let response = handler.handle_request(&request, 0).unwrap();

        // Tamper with request nonce
        let tampered_request = AttestationRequest::new([0xFFu8; 16]);

        let result = verifier.verify(&tampered_request, &response);
        assert_eq!(result.result, VerificationResult::NonceMismatch);
    }

    #[test]
    fn test_untrusted_identity() {
        let (sk, _pk) = generate_test_keypair();
        let mut handler = AttestationHandler::new();
        handler.init([0x11u8; 32], [0x22u8; 32], sk);

        let mut verifier = AttestationVerifier::new();
        // Add different trusted identity
        verifier.add_trusted_identity([0xFFu8; 32]).unwrap();

        let request = AttestationRequest::new([0x42u8; 16]);
        let response = handler.handle_request(&request, 0).unwrap();

        let result = verifier.verify(&request, &response);
        assert_eq!(result.result, VerificationResult::Revoked);
    }

    #[test]
    fn test_invalid_signature_wrong_key() {
        // Generate two different keypairs
        let mut rng1 = TestRng::from_seed(42);
        let mut rng2 = TestRng::from_seed(99);
        let (pk1, sk1) = Dilithium3::keypair(&mut rng1).unwrap();
        let (pk2, _sk2) = Dilithium3::keypair(&mut rng2).unwrap();

        let identity_hash = [0x11u8; 32];

        // Setup handler with sk1
        let mut handler = AttestationHandler::new();
        handler.init(identity_hash, [0x22u8; 32], sk1.to_bytes());
        handler.measure_boot(BootStage::Bootloader).unwrap();

        // Setup verifier with pk2 (different key)
        let mut verifier = AttestationVerifier::new();
        verifier.add_trusted_identity_with_key(identity_hash, pk2.to_bytes()).unwrap();

        // Create and handle request
        let nonce = [0x42u8; 16];
        let request = verifier.create_request(nonce, AttestationScope::Standard);
        let response = handler.handle_request(&request, 12345).unwrap();

        // Verification should fail because signature was made with different key
        let result = verifier.verify(&request, &response);
        assert_eq!(result.result, VerificationResult::InvalidSignature);
    }
}
