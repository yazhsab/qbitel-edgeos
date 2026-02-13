// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Secure Bootloader Library
//!
//! This crate provides the secure boot functionality:
//!
//! - **Verify**: Cryptographic verification of kernel image
//! - **Load**: Secure kernel loading with memory protection
//! - **Rollback**: Anti-rollback protection
//! - **Recovery**: Recovery boot mode for failed boots
//! - **Boot Log**: Persistent boot failure logging

#![no_std]
#![warn(missing_docs)]

pub mod verify;
pub mod load;
pub mod rollback;
pub mod recovery;
pub mod boot_log;

pub use verify::{verify_kernel, verify_boot_chain, BootDecision};
pub use load::load_kernel;
pub use recovery::{should_enter_recovery, enter_recovery_mode, RecoveryReason};
pub use boot_log::{BootLog, BootLogEntry, BootStage, ErrorCategory};
