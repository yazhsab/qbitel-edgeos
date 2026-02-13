// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! A/B partition management

/// Active partition slot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Slot A
    A,
    /// Slot B
    B,
}

impl Slot {
    /// Get the other slot
    #[must_use]
    pub const fn other(&self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Partition state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionState {
    /// Empty/unprovisioned
    Empty,
    /// Valid and bootable
    Valid,
    /// Marked for update
    PendingUpdate,
    /// Update applied, pending verification
    PendingVerify,
    /// Boot failed, marked invalid
    Invalid,
}
