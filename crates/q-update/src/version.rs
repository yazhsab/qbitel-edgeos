// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Monotonic versioning for rollback protection

use q_common::version::Version;

/// Monotonic version wrapper
pub struct MonotonicVersion {
    version: Version,
    rollback_index: u32,
}

impl MonotonicVersion {
    /// Create new monotonic version
    #[must_use]
    pub const fn new(version: Version, rollback_index: u32) -> Self {
        Self { version, rollback_index }
    }

    /// Check if this version is greater than another
    #[must_use]
    pub fn is_newer_than(&self, other: &Self) -> bool {
        if self.rollback_index != other.rollback_index {
            return self.rollback_index > other.rollback_index;
        }
        self.version > other.version
    }

    /// Get version
    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }

    /// Get rollback index
    #[must_use]
    pub const fn rollback_index(&self) -> u32 {
        self.rollback_index
    }
}
