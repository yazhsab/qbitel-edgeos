// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Qbitel EdgeOS Common Library
//!
//! This crate provides common types, error definitions, configuration structures,
//! and utilities shared across all Qbitel EdgeOS components.
//!
//! # Features
//!
//! - `std`: Enable standard library support (disabled by default for embedded)
//! - `defmt`: Enable defmt logging support for embedded debugging
//!
//! # Security
//!
//! All sensitive data types implement `Zeroize` for secure memory cleanup.
//! No heap allocations are performed - all buffers use fixed-size arrays or heapless collections.

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "std")]
extern crate std;

pub mod types;
pub mod errors;
pub mod config;
pub mod log;
pub mod constants;
pub mod time;
pub mod version;

// Re-export commonly used items
pub use errors::{Error, Result};
pub use types::*;
pub use config::SystemConfig;
pub use version::Version;
