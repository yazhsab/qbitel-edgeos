// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Rollback protection

use q_common::Error;

/// Check if version rollback is allowed
pub fn check_rollback(
    current_index: u32,
    new_index: u32,
    max_rollback: u8,
) -> Result<bool, Error> {
    if new_index >= current_index {
        // Moving forward or same version
        Ok(true)
    } else if max_rollback == 0 {
        // No rollback allowed
        Err(Error::RollbackAttempted)
    } else if current_index - new_index <= max_rollback as u32 {
        // Within allowed rollback range
        Ok(true)
    } else {
        Err(Error::RollbackAttempted)
    }
}
