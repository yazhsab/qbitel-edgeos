// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Q-Identity Kernel for Qbitel EdgeOS
//!
//! This crate implements the device identity management system including:
//!
//! - **Identity Commitment**: Hardware-bound device identity
//! - **Hardware Binding**: PUF/eFUSE-based identity anchoring
//! - **Verification**: Offline identity verification
//! - **Storage**: Secure identity storage
//!
//! # Architecture
//!
//! Identity is established at device provisioning and bound to hardware:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │         Identity Commitment          │
//! ├─────────────────────────────────────┤
//! │ - Device ID (32 bytes)              │
//! │ - KEM Public Key (Kyber-768)        │
//! │ - Signing Public Key (Dilithium3)   │
//! │ - Device Class                       │
//! │ - Metadata                           │
//! │ - Self-Signature                     │
//! └─────────────────────────────────────┘
//!              │
//!              ▼
//! ┌─────────────────────────────────────┐
//! │        Hardware Fingerprint          │
//! │  (PUF response or eFUSE UID hash)   │
//! └─────────────────────────────────────┘
//! ```

#![no_std]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod commitment;
pub mod hardware_binding;
pub mod verification;
pub mod storage;
pub mod lifecycle;

// Re-exports
pub use commitment::{IdentityCommitment, IdentitySecrets, DeviceClass};
pub use verification::{verify_identity, VerificationResult};
