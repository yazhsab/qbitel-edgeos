// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Hardware Abstraction Layer for Qbitel EdgeOS
//!
//! This crate provides a unified hardware abstraction layer that enables
//! Qbitel EdgeOS to run on multiple target platforms:
//!
//! - **STM32H7**: ARM Cortex-M7 with TrustZone-M
//! - **STM32U5**: ARM Cortex-M33 with TrustZone-M
//! - **RISC-V**: SiFive with PMP
//!
//! # Architecture
//!
//! The HAL is structured in layers:
//!
//! 1. **Traits**: Platform-agnostic interfaces (`traits` module)
//! 2. **Drivers**: Platform-specific implementations
//! 3. **Peripherals**: Low-level peripheral access
//!
//! # Security
//!
//! - Secure storage access is protected by TrustZone/PMP
//! - RNG uses hardware TRNG when available
//! - Flash operations include integrity verification

#![no_std]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod traits;
pub mod error;

#[cfg(feature = "stm32h7")]
pub mod stm32h7;

#[cfg(feature = "stm32u5")]
pub mod stm32u5;

#[cfg(feature = "riscv")]
pub mod riscv;

// Re-export main traits
pub use traits::*;
pub use error::HalError;

/// Platform identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// STM32H7 (Cortex-M7)
    Stm32H7,
    /// STM32U5 (Cortex-M33)
    Stm32U5,
    /// RISC-V (SiFive)
    RiscV,
    /// Unknown/simulation
    Unknown,
}

impl Platform {
    /// Get the current platform
    #[must_use]
    pub const fn current() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(feature = "stm32h7")] {
                Self::Stm32H7
            } else if #[cfg(feature = "stm32u5")] {
                Self::Stm32U5
            } else if #[cfg(feature = "riscv")] {
                Self::RiscV
            } else {
                Self::Unknown
            }
        }
    }

    /// Check if TrustZone is available
    #[must_use]
    pub const fn has_trustzone(&self) -> bool {
        matches!(self, Self::Stm32H7 | Self::Stm32U5)
    }

    /// Check if PMP (Physical Memory Protection) is available
    #[must_use]
    pub const fn has_pmp(&self) -> bool {
        matches!(self, Self::RiscV)
    }

    /// Get the flash base address for this platform
    #[must_use]
    pub const fn flash_base(&self) -> u32 {
        match self {
            Self::Stm32H7 | Self::Stm32U5 => 0x0800_0000,
            Self::RiscV => 0x2000_0000,
            Self::Unknown => 0x0000_0000,
        }
    }

    /// Get the RAM base address for this platform
    #[must_use]
    pub const fn ram_base(&self) -> u32 {
        match self {
            Self::Stm32H7 | Self::Stm32U5 => 0x2000_0000,
            Self::RiscV => 0x8000_0000,
            Self::Unknown => 0x0000_0000,
        }
    }
}
