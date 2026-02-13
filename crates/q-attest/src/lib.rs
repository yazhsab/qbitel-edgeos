// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Q-ATTEST for Qbitel EdgeOS
//!
//! Device attestation protocol:
//!
//! - **Evidence**: Generate attestation evidence
//! - **Verification**: Verify attestation claims
//! - **Protocol**: Remote attestation protocol
//! - **Supply Chain**: Track device provenance
//! - **Runtime**: Runtime integrity monitoring
//! - **Anomaly**: Anomaly detection

#![no_std]
#![warn(missing_docs)]

pub mod evidence;
pub mod verification;
pub mod protocol;
pub mod supply_chain;
pub mod runtime;
pub mod anomaly;

pub use evidence::{AttestationEvidence, EvidenceCollector, BootStage, MeasurementRegister};
pub use protocol::{
    AttestationRequest, AttestationResponse, AttestationResult,
    AttestationHandler, AttestationVerifier, VerificationPolicy,
    AttestationScope, VerificationResult,
};
