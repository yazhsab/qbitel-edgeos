// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Q-RECOVER Framework for Qbitel EdgeOS
//!
//! Provides key rotation and recovery without device recall:
//!
//! - **Key Rotation**: Update cryptographic keys in the field
//! - **Threshold Signatures**: Shamir secret sharing for recovery
//! - **Batch Revocation**: Revoke compromised devices
//! - **Offline Recovery**: Recovery without network connectivity

#![no_std]
#![warn(missing_docs)]

pub mod rotation;
pub mod threshold;
pub mod recovery;
pub mod revocation;
pub mod offline;

pub use rotation::KeyRotation;
pub use threshold::ThresholdScheme;
