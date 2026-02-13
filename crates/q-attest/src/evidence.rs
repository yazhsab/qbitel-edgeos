// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Attestation Evidence Generation
//!
//! This module implements the evidence generation for device attestation.
//! Evidence includes measurements of device state that can be verified
//! by a remote party.
//!
//! # Evidence Components
//!
//! - **Identity**: Device identity commitment hash
//! - **Firmware**: Hash of running firmware
//! - **Boot**: Boot measurements (PCR-like)
//! - **Runtime**: Runtime integrity measurements
//! - **Configuration**: Device configuration hash
//!
//! # Protocol
//!
//! 1. Verifier sends challenge (nonce)
//! 2. Device collects measurements
//! 3. Device signs evidence with attestation key
//! 4. Device returns signed evidence
//! 5. Verifier checks signature and measurements

use q_common::Error;
use q_crypto::hash::Sha3_256;
use q_crypto::traits::Hash;
use heapless::Vec;

/// Maximum size of custom claims
pub const MAX_CLAIMS_SIZE: usize = 256;

/// Number of PCR-like measurement registers
pub const NUM_PCRS: usize = 8;

/// Dilithium-3 signature size
pub const SIGNATURE_SIZE: usize = 3293;

// ============================================================================
// Measurement Register (PCR-like)
// ============================================================================

/// Platform Configuration Register (PCR-like)
///
/// Stores cumulative hash measurements that can only be extended, not reset.
#[derive(Debug, Clone)]
pub struct MeasurementRegister {
    /// Register index
    pub index: u8,
    /// Current measurement value (SHA3-256 hash)
    pub value: [u8; 32],
    /// Number of extensions
    pub extend_count: u32,
}

impl MeasurementRegister {
    /// Create a new measurement register initialized to zeros
    pub const fn new(index: u8) -> Self {
        Self {
            index,
            value: [0u8; 32],
            extend_count: 0,
        }
    }

    /// Extend the register with new data
    ///
    /// New value = SHA3-256(current_value || SHA3-256(new_data))
    ///
    /// This follows the TPM PCR extend model where measurements are
    /// accumulated cryptographically. Once extended, the previous state
    /// cannot be recovered.
    pub fn extend(&mut self, data: &[u8]) {
        // PCR_new = H(PCR_old || H(data))
        // First hash the input data
        let data_hash = sha3_256_hash(data);

        // Concatenate current value with data hash
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&self.value);
        combined[32..].copy_from_slice(&data_hash);

        // Hash the concatenation to get new PCR value
        self.value = sha3_256_hash(&combined);
        self.extend_count = self.extend_count.saturating_add(1);
    }

    /// Reset to initial state (only allowed in special circumstances)
    pub fn reset(&mut self) {
        self.value = [0u8; 32];
        self.extend_count = 0;
    }
}

/// Cryptographic hash function using SHA3-256
///
/// This function provides the cryptographically secure hash needed for
/// PCR measurements and attestation evidence. Uses NIST-standardized
/// SHA3-256 (FIPS 202).
fn sha3_256_hash(data: &[u8]) -> [u8; 32] {
    let output = Sha3_256::hash(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(output.as_ref());
    hash
}

// ============================================================================
// Evidence Types
// ============================================================================

/// Device boot stage for measurements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootStage {
    /// Early boot (before bootloader)
    EarlyBoot = 0,
    /// Bootloader running
    Bootloader = 1,
    /// Kernel loading
    KernelLoad = 2,
    /// Kernel running
    KernelRun = 3,
    /// Application running
    Application = 4,
}

/// Attestation claim type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClaimType {
    /// Firmware version
    FirmwareVersion = 0x01,
    /// Hardware version
    HardwareVersion = 0x02,
    /// Boot mode
    BootMode = 0x03,
    /// Secure boot status
    SecureBootStatus = 0x04,
    /// Debug status
    DebugStatus = 0x05,
    /// Rollback counter
    RollbackCounter = 0x06,
    /// Device class
    DeviceClass = 0x07,
    /// Custom claim
    Custom = 0xFF,
}

/// A single attestation claim
#[derive(Debug, Clone)]
pub struct Claim {
    /// Claim type
    pub claim_type: ClaimType,
    /// Claim value (variable length)
    pub value: Vec<u8, 64>,
}

impl Claim {
    /// Create a new claim
    pub fn new(claim_type: ClaimType, value: &[u8]) -> Result<Self, Error> {
        let mut v = Vec::new();
        v.extend_from_slice(value).map_err(|_| Error::BufferTooSmall)?;
        Ok(Self { claim_type, value: v })
    }

    /// Serialize claim to bytes
    pub fn to_bytes(&self) -> Vec<u8, 66> {
        let mut bytes = Vec::new();
        let _ = bytes.push(self.claim_type as u8);
        let _ = bytes.push(self.value.len() as u8);
        let _ = bytes.extend_from_slice(&self.value);
        bytes
    }
}

// ============================================================================
// Attestation Evidence
// ============================================================================

/// Attestation evidence structure
///
/// Contains all measurements and claims that attest to device state.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    /// Protocol version
    pub version: u8,
    /// Device identity commitment hash
    pub identity_hash: [u8; 32],
    /// Firmware version hash
    pub firmware_hash: [u8; 32],
    /// Boot measurements (PCR values)
    pub boot_measurements: [[u8; 32]; NUM_PCRS],
    /// Boot measurement extend counts
    pub pcr_counts: [u32; NUM_PCRS],
    /// Timestamp (monotonic counter or RTC)
    pub timestamp: u64,
    /// Challenge nonce from verifier
    pub nonce: [u8; 16],
    /// Additional claims
    pub claims: Vec<Claim, 16>,
    /// Signature over evidence (Dilithium-3)
    pub signature: [u8; SIGNATURE_SIZE],
    /// Evidence is signed
    pub signed: bool,
}

impl AttestationEvidence {
    /// Create new evidence with given parameters
    pub fn new(
        identity_hash: [u8; 32],
        firmware_hash: [u8; 32],
        nonce: [u8; 16],
        timestamp: u64,
    ) -> Self {
        Self {
            version: 1,
            identity_hash,
            firmware_hash,
            boot_measurements: [[0u8; 32]; NUM_PCRS],
            pcr_counts: [0u32; NUM_PCRS],
            timestamp,
            nonce,
            claims: Vec::new(),
            signature: [0u8; SIGNATURE_SIZE],
            signed: false,
        }
    }

    /// Set boot measurements from PCRs
    pub fn set_boot_measurements(&mut self, pcrs: &[MeasurementRegister]) {
        for pcr in pcrs.iter().take(NUM_PCRS) {
            let idx = pcr.index as usize;
            if idx < NUM_PCRS {
                self.boot_measurements[idx] = pcr.value;
                self.pcr_counts[idx] = pcr.extend_count;
            }
        }
    }

    /// Add a claim to the evidence
    pub fn add_claim(&mut self, claim: Claim) -> Result<(), Error> {
        self.claims.push(claim).map_err(|_| Error::BufferTooSmall)
    }

    /// Add firmware version claim
    pub fn add_firmware_version(&mut self, major: u8, minor: u8, patch: u8) -> Result<(), Error> {
        let value = [major, minor, patch];
        let claim = Claim::new(ClaimType::FirmwareVersion, &value)?;
        self.add_claim(claim)
    }

    /// Add hardware version claim
    pub fn add_hardware_version(&mut self, version: u16) -> Result<(), Error> {
        let value = version.to_le_bytes();
        let claim = Claim::new(ClaimType::HardwareVersion, &value)?;
        self.add_claim(claim)
    }

    /// Add secure boot status claim
    pub fn add_secure_boot_status(&mut self, enabled: bool, verified: bool) -> Result<(), Error> {
        let value = [(enabled as u8) | ((verified as u8) << 1)];
        let claim = Claim::new(ClaimType::SecureBootStatus, &value)?;
        self.add_claim(claim)
    }

    /// Add debug status claim
    pub fn add_debug_status(&mut self, debug_enabled: bool) -> Result<(), Error> {
        let value = [debug_enabled as u8];
        let claim = Claim::new(ClaimType::DebugStatus, &value)?;
        self.add_claim(claim)
    }

    /// Add rollback counter claim
    pub fn add_rollback_counter(&mut self, counter: u32) -> Result<(), Error> {
        let value = counter.to_le_bytes();
        let claim = Claim::new(ClaimType::RollbackCounter, &value)?;
        self.add_claim(claim)
    }

    /// Get the bytes to be signed
    pub fn to_signed_bytes(&self) -> Vec<u8, 512> {
        let mut bytes = Vec::new();

        // Version
        let _ = bytes.push(self.version);

        // Identity hash
        let _ = bytes.extend_from_slice(&self.identity_hash);

        // Firmware hash
        let _ = bytes.extend_from_slice(&self.firmware_hash);

        // Boot measurements
        for pcr in &self.boot_measurements {
            let _ = bytes.extend_from_slice(pcr);
        }

        // Timestamp
        let _ = bytes.extend_from_slice(&self.timestamp.to_le_bytes());

        // Nonce
        let _ = bytes.extend_from_slice(&self.nonce);

        // Claims count
        let _ = bytes.push(self.claims.len() as u8);

        // Claims
        for claim in &self.claims {
            let claim_bytes = claim.to_bytes();
            let _ = bytes.extend_from_slice(&claim_bytes);
        }

        bytes
    }

    /// Serialize evidence to bytes
    pub fn serialize(&self) -> Vec<u8, 4096> {
        let mut bytes = Vec::new();

        // Signed portion
        let signed_bytes = self.to_signed_bytes();
        let _ = bytes.extend_from_slice(&signed_bytes);

        // Signature
        let _ = bytes.extend_from_slice(&self.signature);

        bytes
    }

    /// Set signature
    pub fn set_signature(&mut self, signature: &[u8; SIGNATURE_SIZE]) {
        self.signature = *signature;
        self.signed = true;
    }

    /// Check if evidence is signed
    pub fn is_signed(&self) -> bool {
        self.signed
    }
}

// ============================================================================
// Evidence Collector
// ============================================================================

/// Evidence collector that manages PCRs and generates evidence
pub struct EvidenceCollector {
    /// Measurement registers (PCRs)
    pcrs: [MeasurementRegister; NUM_PCRS],
    /// Current boot stage
    boot_stage: BootStage,
    /// Device identity hash (cached)
    identity_hash: [u8; 32],
    /// Firmware hash (cached)
    firmware_hash: [u8; 32],
    /// Initialized flag
    initialized: bool,
}

impl EvidenceCollector {
    /// Create a new evidence collector
    pub const fn new() -> Self {
        Self {
            pcrs: [
                MeasurementRegister::new(0),
                MeasurementRegister::new(1),
                MeasurementRegister::new(2),
                MeasurementRegister::new(3),
                MeasurementRegister::new(4),
                MeasurementRegister::new(5),
                MeasurementRegister::new(6),
                MeasurementRegister::new(7),
            ],
            boot_stage: BootStage::EarlyBoot,
            identity_hash: [0u8; 32],
            firmware_hash: [0u8; 32],
            initialized: false,
        }
    }

    /// Initialize the collector with device info
    pub fn init(&mut self, identity_hash: [u8; 32], firmware_hash: [u8; 32]) {
        self.identity_hash = identity_hash;
        self.firmware_hash = firmware_hash;
        self.initialized = true;
    }

    /// Extend a PCR with measurement data
    pub fn extend_pcr(&mut self, pcr_index: usize, data: &[u8]) -> Result<(), Error> {
        if pcr_index >= NUM_PCRS {
            return Err(Error::InvalidParameter);
        }
        self.pcrs[pcr_index].extend(data);
        Ok(())
    }

    /// Measure boot stage transition
    pub fn measure_boot_stage(&mut self, stage: BootStage) -> Result<(), Error> {
        // PCR 0 is for boot stages
        let stage_data = [stage as u8];
        self.extend_pcr(0, &stage_data)?;
        self.boot_stage = stage;
        Ok(())
    }

    /// Measure firmware component
    pub fn measure_firmware(&mut self, component_id: u8, hash: &[u8; 32]) -> Result<(), Error> {
        // PCR 1 is for firmware measurements
        let mut data = [0u8; 33];
        data[0] = component_id;
        data[1..].copy_from_slice(hash);
        self.extend_pcr(1, &data)
    }

    /// Measure configuration
    pub fn measure_config(&mut self, config_id: u8, config_hash: &[u8; 32]) -> Result<(), Error> {
        // PCR 2 is for configuration
        let mut data = [0u8; 33];
        data[0] = config_id;
        data[1..].copy_from_slice(config_hash);
        self.extend_pcr(2, &data)
    }

    /// Measure runtime event
    pub fn measure_runtime(&mut self, event_type: u8, event_data: &[u8]) -> Result<(), Error> {
        // PCR 3 is for runtime events
        let mut data = Vec::<u8, 64>::new();
        data.push(event_type).map_err(|_| Error::BufferTooSmall)?;
        data.extend_from_slice(event_data).map_err(|_| Error::BufferTooSmall)?;
        self.extend_pcr(3, &data)
    }

    /// Generate attestation evidence
    pub fn generate_evidence(&self, nonce: [u8; 16], timestamp: u64) -> AttestationEvidence {
        let mut evidence = AttestationEvidence::new(
            self.identity_hash,
            self.firmware_hash,
            nonce,
            timestamp,
        );

        evidence.set_boot_measurements(&self.pcrs);
        evidence
    }

    /// Get current PCR values
    pub fn get_pcr(&self, index: usize) -> Option<&MeasurementRegister> {
        self.pcrs.get(index)
    }

    /// Get all PCRs
    pub fn get_all_pcrs(&self) -> &[MeasurementRegister; NUM_PCRS] {
        &self.pcrs
    }

    /// Get current boot stage
    pub fn boot_stage(&self) -> BootStage {
        self.boot_stage
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Evidence Collector
// ============================================================================

/// Static evidence collector for boot-time measurements
static mut COLLECTOR: EvidenceCollector = EvidenceCollector::new();

/// Initialize the global evidence collector
pub fn init_collector(identity_hash: [u8; 32], firmware_hash: [u8; 32]) {
    unsafe {
        (*core::ptr::addr_of_mut!(COLLECTOR)).init(identity_hash, firmware_hash);
    }
}

/// Extend a PCR in the global collector
pub fn extend_pcr(pcr_index: usize, data: &[u8]) -> Result<(), Error> {
    unsafe { (*core::ptr::addr_of_mut!(COLLECTOR)).extend_pcr(pcr_index, data) }
}

/// Measure boot stage in global collector
pub fn measure_boot_stage(stage: BootStage) -> Result<(), Error> {
    unsafe { (*core::ptr::addr_of_mut!(COLLECTOR)).measure_boot_stage(stage) }
}

/// Generate evidence using global collector
pub fn generate_evidence(nonce: [u8; 16], timestamp: u64) -> AttestationEvidence {
    unsafe { (*core::ptr::addr_of!(COLLECTOR)).generate_evidence(nonce, timestamp) }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_register() {
        let mut pcr = MeasurementRegister::new(0);
        assert_eq!(pcr.value, [0u8; 32]);
        assert_eq!(pcr.extend_count, 0);

        pcr.extend(b"test data");
        assert_ne!(pcr.value, [0u8; 32]);
        assert_eq!(pcr.extend_count, 1);

        let old_value = pcr.value;
        pcr.extend(b"more data");
        assert_ne!(pcr.value, old_value);
        assert_eq!(pcr.extend_count, 2);
    }

    #[test]
    fn test_evidence_creation() {
        let identity = [0x42u8; 32];
        let firmware = [0x13u8; 32];
        let nonce = [0xAAu8; 16];

        let evidence = AttestationEvidence::new(identity, firmware, nonce, 12345);

        assert_eq!(evidence.version, 1);
        assert_eq!(evidence.identity_hash, identity);
        assert_eq!(evidence.firmware_hash, firmware);
        assert_eq!(evidence.nonce, nonce);
        assert_eq!(evidence.timestamp, 12345);
        assert!(!evidence.signed);
    }

    #[test]
    fn test_add_claims() {
        let mut evidence = AttestationEvidence::new(
            [0u8; 32],
            [0u8; 32],
            [0u8; 16],
            0,
        );

        assert!(evidence.add_firmware_version(1, 2, 3).is_ok());
        assert!(evidence.add_hardware_version(0x0100).is_ok());
        assert!(evidence.add_secure_boot_status(true, true).is_ok());
        assert!(evidence.add_debug_status(false).is_ok());
        assert!(evidence.add_rollback_counter(42).is_ok());

        assert_eq!(evidence.claims.len(), 5);
    }

    #[test]
    fn test_evidence_serialization() {
        let mut evidence = AttestationEvidence::new(
            [0x11u8; 32],
            [0x22u8; 32],
            [0x33u8; 16],
            1000,
        );

        evidence.add_firmware_version(1, 0, 0).unwrap();

        let bytes = evidence.to_signed_bytes();
        assert!(bytes.len() > 0);
    }

    #[test]
    fn test_evidence_collector() {
        let mut collector = EvidenceCollector::new();
        collector.init([0x42u8; 32], [0x13u8; 32]);

        assert!(collector.measure_boot_stage(BootStage::Bootloader).is_ok());
        assert!(collector.measure_firmware(0, &[0xAAu8; 32]).is_ok());
        assert!(collector.measure_config(0, &[0xBBu8; 32]).is_ok());

        let evidence = collector.generate_evidence([0u8; 16], 12345);
        assert_ne!(evidence.boot_measurements[0], [0u8; 32]);
        assert_ne!(evidence.boot_measurements[1], [0u8; 32]);
        assert_ne!(evidence.boot_measurements[2], [0u8; 32]);
    }

    #[test]
    fn test_claim_serialization() {
        let claim = Claim::new(ClaimType::FirmwareVersion, &[1, 2, 3]).unwrap();
        let bytes = claim.to_bytes();

        assert_eq!(bytes[0], ClaimType::FirmwareVersion as u8);
        assert_eq!(bytes[1], 3); // length
        assert_eq!(&bytes[2..5], &[1, 2, 3]);
    }
}
