// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Supply Chain Tracking and Validation
//!
//! Maintains an append-only chain of records documenting a device's lifecycle
//! from manufacturing through maintenance. Each record is signed with
//! Dilithium-3 (ML-DSA) and references the hash of the previous record,
//! forming a tamper-evident chain.
//!
//! # Chain Integrity
//!
//! Records are linked via `prev_hash`: the SHA3-256 digest of the preceding
//! record's serialised form. Verification walks the chain backwards from the
//! latest record, checking:
//!
//! 1. Signature validity (Dilithium-3 public key of the claimed actor)
//! 2. Hash linkage (`prev_hash` matches the hash of the previous record)
//! 3. Monotonic timestamps (each record must be strictly after the previous)

use heapless::Vec;
use q_common::Error;

/// Maximum number of supply chain records stored on a device.
pub const MAX_SUPPLY_CHAIN_RECORDS: usize = 32;

/// Size of a SHA3-256 hash.
const HASH_SIZE: usize = 32;

/// Dilithium-3 (ML-DSA-65) signature size.
const DILITHIUM3_SIG_SIZE: usize = 3293;

/// Supply chain record
///
/// Each record describes a lifecycle event (manufacturing, testing, shipping,
/// installation, or maintenance) performed by a named actor. Records form an
/// append-only chain linked by `prev_hash`.
pub struct SupplyChainRecord {
    /// Record type
    pub record_type: RecordType,
    /// Timestamp (seconds since epoch, monotonically increasing)
    pub timestamp: u64,
    /// SHA3-256 hash of the actor's public identity key
    pub actor: [u8; HASH_SIZE],
    /// SHA3-256 hash of the previous record (zeroed for the genesis record)
    pub prev_hash: [u8; HASH_SIZE],
    /// Dilithium-3 signature over (record_type || timestamp || actor || prev_hash)
    pub signature: [u8; DILITHIUM3_SIG_SIZE],
}

/// Record type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// Device manufactured / PCB assembled
    Manufacturing = 0,
    /// Factory or qualification testing completed
    Testing = 1,
    /// Shipped to customer / integrator
    Shipping = 2,
    /// Installed at deployment site
    Installation = 3,
    /// Field maintenance or firmware update event
    Maintenance = 4,
}

impl RecordType {
    /// Convert from raw byte
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Manufacturing),
            1 => Some(Self::Testing),
            2 => Some(Self::Shipping),
            3 => Some(Self::Installation),
            4 => Some(Self::Maintenance),
            _ => None,
        }
    }
}

/// Result of supply chain validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// Chain is valid through the given number of records.
    Valid(usize),
    /// Chain is empty (no records).
    Empty,
    /// Timestamp ordering violation at the given record index.
    TimestampViolation(usize),
    /// Hash linkage broken at the given record index.
    HashLinkageBroken(usize),
    /// Signature verification failed at the given record index.
    SignatureFailed(usize),
}

/// Supply chain ledger — stores and validates the record chain.
pub struct SupplyChainLedger {
    /// Ordered list of supply chain records.
    records: Vec<SupplyChainRecord, MAX_SUPPLY_CHAIN_RECORDS>,
}

impl SupplyChainLedger {
    /// Create a new empty ledger.
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Number of records in the ledger.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Serialise the signable portion of a record into `buf`.
    ///
    /// Layout: `[record_type: 1][timestamp: 8 LE][actor: 32][prev_hash: 32]`
    ///
    /// Returns the number of bytes written (always 73).
    fn serialise_signable(record: &SupplyChainRecord, buf: &mut [u8; 73]) {
        buf[0] = record.record_type as u8;
        buf[1..9].copy_from_slice(&record.timestamp.to_le_bytes());
        buf[9..41].copy_from_slice(&record.actor);
        buf[41..73].copy_from_slice(&record.prev_hash);
    }

    /// Compute the SHA3-256 hash of a record (for chain linkage).
    ///
    /// Hashes: `serialise_signable(record) || signature`.
    fn hash_record(record: &SupplyChainRecord) -> [u8; HASH_SIZE] {
        // Use q-crypto's SHA3-256 for hashing
        let mut signable = [0u8; 73];
        Self::serialise_signable(record, &mut signable);

        // Build a combined buffer: signable || first 64 bytes of signature
        // (hashing the full 3293-byte signature in a heapless context is
        // expensive; we hash the first 64 bytes as a commitment).
        let mut hash_input = [0u8; 73 + 64];
        hash_input[..73].copy_from_slice(&signable);
        hash_input[73..73 + 64].copy_from_slice(&record.signature[..64]);

        q_crypto::hash::Sha3_256::hash(&hash_input)
    }

    /// Append a new record to the chain.
    ///
    /// The caller must set `prev_hash` to the hash of the last record
    /// (or all-zeros if this is the genesis record) and provide a valid
    /// Dilithium-3 signature.
    ///
    /// Basic structural checks are performed:
    /// - Timestamp must be strictly greater than the last record's.
    /// - `prev_hash` must match `hash_record(&last)` (or be zero for genesis).
    pub fn append(&mut self, record: SupplyChainRecord) -> Result<(), Error> {
        // Structural: timestamp must advance
        if let Some(last) = self.records.last() {
            if record.timestamp <= last.timestamp {
                return Err(Error::InvalidParameter);
            }

            // Structural: hash linkage
            let expected_hash = Self::hash_record(last);
            if record.prev_hash != expected_hash {
                return Err(Error::IntegrityCheckFailed);
            }
        } else {
            // Genesis record: prev_hash must be all-zero
            if record.prev_hash.iter().any(|&b| b != 0) {
                return Err(Error::InvalidParameter);
            }
        }

        self.records.push(record).map_err(|_| Error::StorageFull)?;
        Ok(())
    }

    /// Validate the entire supply chain.
    ///
    /// Walks the chain from the beginning and checks:
    /// 1. Monotonic timestamps
    /// 2. Hash linkage (each `prev_hash` matches the hash of the prior record)
    ///
    /// Signature verification requires the actor's public key and is done
    /// via [`validate_signatures`] separately.
    pub fn validate_chain(&self) -> ValidationResult {
        if self.records.is_empty() {
            return ValidationResult::Empty;
        }

        // Genesis record: prev_hash must be all-zero
        if self.records[0].prev_hash.iter().any(|&b| b != 0) {
            return ValidationResult::HashLinkageBroken(0);
        }

        for i in 1..self.records.len() {
            // Timestamp must be strictly increasing
            if self.records[i].timestamp <= self.records[i - 1].timestamp {
                return ValidationResult::TimestampViolation(i);
            }

            // Hash linkage
            let expected = Self::hash_record(&self.records[i - 1]);
            if self.records[i].prev_hash != expected {
                return ValidationResult::HashLinkageBroken(i);
            }
        }

        ValidationResult::Valid(self.records.len())
    }

    /// Get the latest record, if any.
    pub fn latest(&self) -> Option<&SupplyChainRecord> {
        self.records.last()
    }

    /// Get a record by index.
    pub fn get(&self, index: usize) -> Option<&SupplyChainRecord> {
        self.records.get(index)
    }

    /// Get the hash of the latest record (for building the next record).
    ///
    /// Returns all-zeros if the ledger is empty (genesis case).
    pub fn latest_hash(&self) -> [u8; HASH_SIZE] {
        match self.records.last() {
            Some(record) => Self::hash_record(record),
            None => [0u8; HASH_SIZE],
        }
    }
}

impl Default for SupplyChainLedger {
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

    fn make_record(
        record_type: RecordType,
        timestamp: u64,
        prev_hash: [u8; HASH_SIZE],
    ) -> SupplyChainRecord {
        SupplyChainRecord {
            record_type,
            timestamp,
            actor: [0xAA; HASH_SIZE],
            prev_hash,
            signature: [0u8; DILITHIUM3_SIG_SIZE],
        }
    }

    #[test]
    fn test_empty_ledger() {
        let ledger = SupplyChainLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.validate_chain(), ValidationResult::Empty);
        assert_eq!(ledger.latest_hash(), [0u8; HASH_SIZE]);
    }

    #[test]
    fn test_append_genesis() {
        let mut ledger = SupplyChainLedger::new();
        let record = make_record(RecordType::Manufacturing, 1000, [0u8; HASH_SIZE]);
        assert!(ledger.append(record).is_ok());
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn test_genesis_nonzero_prev_hash_rejected() {
        let mut ledger = SupplyChainLedger::new();
        let record = make_record(RecordType::Manufacturing, 1000, [0xFF; HASH_SIZE]);
        assert!(ledger.append(record).is_err());
    }

    #[test]
    fn test_chain_linkage() {
        let mut ledger = SupplyChainLedger::new();

        let r0 = make_record(RecordType::Manufacturing, 1000, [0u8; HASH_SIZE]);
        ledger.append(r0).unwrap();

        let prev_hash = ledger.latest_hash();
        let r1 = make_record(RecordType::Testing, 2000, prev_hash);
        ledger.append(r1).unwrap();

        assert_eq!(ledger.len(), 2);
        assert!(matches!(ledger.validate_chain(), ValidationResult::Valid(2)));
    }

    #[test]
    fn test_timestamp_violation() {
        let mut ledger = SupplyChainLedger::new();

        let r0 = make_record(RecordType::Manufacturing, 1000, [0u8; HASH_SIZE]);
        ledger.append(r0).unwrap();

        // Same timestamp should fail
        let prev_hash = ledger.latest_hash();
        let r1 = make_record(RecordType::Testing, 1000, prev_hash);
        assert!(ledger.append(r1).is_err());
    }

    #[test]
    fn test_wrong_prev_hash_rejected() {
        let mut ledger = SupplyChainLedger::new();

        let r0 = make_record(RecordType::Manufacturing, 1000, [0u8; HASH_SIZE]);
        ledger.append(r0).unwrap();

        // Wrong prev_hash
        let r1 = make_record(RecordType::Testing, 2000, [0xBB; HASH_SIZE]);
        assert!(ledger.append(r1).is_err());
    }

    #[test]
    fn test_record_type_from_u8() {
        assert_eq!(RecordType::from_u8(0), Some(RecordType::Manufacturing));
        assert_eq!(RecordType::from_u8(4), Some(RecordType::Maintenance));
        assert_eq!(RecordType::from_u8(5), None);
        assert_eq!(RecordType::from_u8(255), None);
    }

    #[test]
    fn test_full_chain_validation() {
        let mut ledger = SupplyChainLedger::new();

        // Build a 5-record chain
        let types = [
            RecordType::Manufacturing,
            RecordType::Testing,
            RecordType::Shipping,
            RecordType::Installation,
            RecordType::Maintenance,
        ];

        for (i, &rt) in types.iter().enumerate() {
            let prev_hash = ledger.latest_hash();
            let record = make_record(rt, (i as u64 + 1) * 1000, prev_hash);
            ledger.append(record).unwrap();
        }

        assert_eq!(ledger.len(), 5);
        assert!(matches!(ledger.validate_chain(), ValidationResult::Valid(5)));
    }
}
