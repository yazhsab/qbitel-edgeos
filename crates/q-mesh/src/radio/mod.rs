// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Radio drivers for Q-MESH
//!
//! This module provides radio hardware abstraction for mesh networking:
//!
//! - **LoRa**: Long-range, low-power radio using SX127x chips
//! - **Radio trait**: Common interface for all radio implementations
//!
//! # Supported Hardware
//!
//! - SX1276/SX1278 LoRa transceivers (EU868, US915, AS923)
//! - SX1262 (future support planned)

pub mod lora;

pub use lora::{LoRaRadio, LoRaConfig, SpreadingFactor, Bandwidth, CodingRate, FrequencyBand};

use q_common::Error;

/// Radio interface trait for mesh networking
pub trait Radio {
    /// Initialize the radio hardware
    fn init(&mut self) -> Result<(), Error>;

    /// Send data over the radio
    fn send(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Receive data from the radio
    /// Returns the number of bytes received
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Error>;

    /// Check if the radio is currently transmitting
    fn is_transmitting(&self) -> bool;

    /// Check if data is available to receive
    fn available(&self) -> bool;

    /// Get the RSSI (Received Signal Strength Indicator) of last packet
    fn last_rssi(&self) -> i16;

    /// Get the SNR (Signal-to-Noise Ratio) of last packet
    fn last_snr(&self) -> i8;

    /// Set the radio to sleep mode
    fn sleep(&mut self) -> Result<(), Error>;

    /// Set the radio to standby mode
    fn standby(&mut self) -> Result<(), Error>;

    /// Set the radio to continuous receive mode
    fn start_receive(&mut self) -> Result<(), Error>;
}

/// Radio event for interrupt handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioEvent {
    /// Transmission complete
    TxDone,
    /// Reception complete
    RxDone,
    /// Reception timeout
    RxTimeout,
    /// CRC error on reception
    CrcError,
    /// Channel activity detected (CAD)
    CadDetected,
    /// CAD done, no activity
    CadDone,
    /// FHSS channel change
    FhssChange,
}

/// Radio state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioState {
    /// Radio is in sleep mode
    Sleep,
    /// Radio is in standby mode
    Standby,
    /// Radio is transmitting
    Tx,
    /// Radio is receiving
    Rx,
    /// Radio is doing CAD (Channel Activity Detection)
    Cad,
}

/// Channel configuration for frequency hopping
#[derive(Debug, Clone, Copy)]
pub struct ChannelConfig {
    /// Center frequency in Hz
    pub frequency: u32,
    /// Minimum frequency in Hz
    pub min_frequency: u32,
    /// Maximum frequency in Hz
    pub max_frequency: u32,
    /// Channel spacing in Hz
    pub channel_spacing: u32,
    /// Number of channels
    pub num_channels: u8,
}

impl ChannelConfig {
    /// Create configuration for EU868 band
    #[must_use]
    pub const fn eu868() -> Self {
        Self {
            frequency: 868_100_000,
            min_frequency: 863_000_000,
            max_frequency: 870_000_000,
            channel_spacing: 200_000,
            num_channels: 8,
        }
    }

    /// Create configuration for US915 band
    #[must_use]
    pub const fn us915() -> Self {
        Self {
            frequency: 915_000_000,
            min_frequency: 902_000_000,
            max_frequency: 928_000_000,
            channel_spacing: 200_000,
            num_channels: 64,
        }
    }

    /// Create configuration for AS923 band
    #[must_use]
    pub const fn as923() -> Self {
        Self {
            frequency: 923_200_000,
            min_frequency: 920_000_000,
            max_frequency: 925_000_000,
            channel_spacing: 200_000,
            num_channels: 16,
        }
    }

    /// Get frequency for a given channel number
    #[must_use]
    pub const fn channel_frequency(&self, channel: u8) -> u32 {
        if channel >= self.num_channels {
            return self.frequency;
        }
        self.min_frequency + (channel as u32) * self.channel_spacing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eu868_config() {
        let config = ChannelConfig::eu868();
        assert_eq!(config.frequency, 868_100_000);
        assert_eq!(config.num_channels, 8);
    }

    #[test]
    fn test_channel_frequency() {
        let config = ChannelConfig::eu868();
        assert_eq!(config.channel_frequency(0), 863_000_000);
        assert_eq!(config.channel_frequency(1), 863_200_000);
    }
}
