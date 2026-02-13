// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Q-Update Fabric for Qbitel EdgeOS
//!
//! Provides secure firmware update capabilities including:
//!
//! - **Manifest verification**: Signed update manifests
//! - **Version control**: Monotonic versioning with rollback protection
//! - **A/B partitioning**: Safe update application with fallback
//! - **Slot management**: Atomic slot switching with boot failure handling
//! - **Air-gapped updates**: Support for offline update application

#![no_std]
#![warn(missing_docs)]

pub mod manifest;
pub mod verification;
pub mod version;
pub mod rollback;
pub mod apply;
pub mod staged;
pub mod airgap;
pub mod slots;

pub use manifest::UpdateManifest;
pub use version::MonotonicVersion;
pub use slots::{Slot, SlotManager, SlotState, SlotStatus};
